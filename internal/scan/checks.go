package scan

import (
	"fmt"
	"sort"
	"strings"
)

// Check inspects a set of resources and reports what is wrong with them. Every
// check is read-only and works the same against manifests on disk and against
// objects pulled from a live cluster, which is what keeps a pre-merge result
// comparable to what the cluster shows afterwards.
type Check func([]Resource) []Finding

// All is the registry. Order here is the order findings are reported in.
var All = []Check{
	CheckNetworkPolicies,
	CheckClusterAdmin,
	CheckPlainCredentials,
	CheckMutableTags,
	CheckPrivileged,
	CheckResourceLimits,
}

func finding(id, resource, detail string, risk Risk) Finding {
	c := Catalogue[id]
	return Finding{
		ID:       id,
		Title:    c.Title,
		Risk:     risk,
		Resource: resource,
		Detail:   detail,
		Why:      c.Why,
		Next:     c.Next,
		Controls: ControlsFor(id, ""),
	}
}

// CheckNetworkPolicies reports namespaces that hold workloads but no
// NetworkPolicy, which means everything in them can reach everything else.
func CheckNetworkPolicies(rs []Resource) []Finding {
	withWorkloads := map[string]bool{}
	withPolicy := map[string]bool{}

	for _, r := range rs {
		if len(r.Containers()) > 0 && r.Metadata.Namespace != "" {
			withWorkloads[r.Metadata.Namespace] = true
		}
		if r.Kind == "NetworkPolicy" {
			withPolicy[r.Metadata.Namespace] = true
		}
	}

	var bare []string
	for ns := range withWorkloads {
		if !withPolicy[ns] {
			bare = append(bare, ns)
		}
	}
	sort.Strings(bare)

	var out []Finding
	for _, ns := range bare {
		out = append(out, finding("SC-01", "namespace/"+ns,
			"no NetworkPolicy, so every pod here can reach every other pod in the cluster", High))
	}
	return out
}

// CheckClusterAdmin reports subjects bound to cluster-admin, excluding the
// bindings every cluster is born with.
//
// Reporting system:masters or the distribution's own control-plane identities
// is noise: it is true of every cluster, the team cannot remove it, and a
// report that opens with it reads as though the tool does not know what it is
// looking at. Those identities are named in platformSubjects, and
// PlatformSubjects lists the ones a given run left out, so the exclusion is
// visible rather than silent.
//
// A ServiceAccount in a platform namespace is a different case and is reported
// at medium: usually it is the distribution's own, but nothing stops somebody
// from adding one there, and an assessment that drops it has a blind spot in
// exactly the place an attacker would pick.
func CheckClusterAdmin(rs []Resource) []Finding {
	var out []Finding
	for _, r := range rs {
		if r.Kind != "ClusterRoleBinding" || r.RoleRef["name"] != "cluster-admin" {
			continue
		}
		for _, s := range r.Subjects {
			if isPlatformSubject(s) {
				continue
			}

			kind := strings.ToLower(s["kind"])
			name := s["name"]
			if ns := s["namespace"]; ns != "" {
				name = ns + "/" + name
			}

			detail := fmt.Sprintf("grants cluster-admin to %s %s", kind, name)
			risk := High

			if ns, ok := platformNamespaceOf(s); ok {
				risk = Medium
				detail += fmt.Sprintf(", in platform namespace %s; confirm it is the distribution's own and not something added", ns)
			}
			if group, ok := everySubjectGroup(s); ok {
				detail += ", which is " + group
			}

			out = append(out, finding("SC-06", r.Ref(), detail, risk))
		}
	}
	return out
}

// everySubjectGroup spells out what the aggregate RBAC groups actually cover.
// "grants cluster-admin to group system:serviceaccounts:build" is accurate and
// still easy to read past; a reader who does not know the group by heart needs
// to be told that it means every workload in that namespace.
func everySubjectGroup(s map[string]string) (string, bool) {
	name := s["name"]
	switch name {
	case "system:authenticated":
		return "every user and workload that can authenticate to this cluster", true
	case "system:unauthenticated", "system:anonymous":
		return "anyone who can reach the API server, authenticated or not", true
	case "system:serviceaccounts":
		return "every service account in every namespace", true
	}
	if ns := strings.TrimPrefix(name, "system:serviceaccounts:"); ns != name && ns != "" {
		return "every service account in namespace " + ns, true
	}
	return "", false
}

// platformNamespaceOf reports the platform namespace a single ServiceAccount
// subject lives in, through either the namespace field or the user form of the
// name. It is deliberately not part of isPlatformSubject: these are reported,
// at a lower risk, rather than filtered.
func platformNamespaceOf(s map[string]string) (string, bool) {
	if ns := s["namespace"]; skipNamespaces[ns] {
		return ns, true
	}
	if ns, ok := serviceAccountNamespace(s["name"]); ok && skipNamespaces[ns] {
		return ns, true
	}
	return "", false
}

// PlatformSubjects names the cluster-admin subjects CheckClusterAdmin left out,
// with the reason. A run that reports two findings while it suppressed three
// bindings has to be able to say so: the count belongs next to the findings,
// not in the tool's head.
func PlatformSubjects(rs []Resource) []Suppressed {
	var out []Suppressed
	for _, r := range rs {
		if r.Kind != "ClusterRoleBinding" || r.RoleRef["name"] != "cluster-admin" {
			continue
		}
		for _, s := range r.Subjects {
			if !isPlatformSubject(s) {
				continue
			}
			out = append(out, Suppressed{
				What:   fmt.Sprintf("%s grants cluster-admin to %s %s", r.Ref(), strings.ToLower(s["kind"]), s["name"]),
				Reason: "Kubernetes or the distribution binds this identity itself; the team cannot remove it",
			})
		}
	}
	return out
}

// platformSubjects are the identities Kubernetes and its distributions bind
// for themselves. The list is exhaustive on purpose: a `system:` prefix is not
// proof that a subject is the platform's. The aggregate groups
// (system:authenticated, system:unauthenticated, system:anonymous,
// system:serviceaccounts and system:serviceaccounts:<ns>) carry the same
// prefix, and a cluster-admin binding on one of those hands the cluster to
// every user or every workload in it -- the single worst thing this check can
// find, so it must never be filtered away.
var platformSubjects = map[string]bool{
	"system:masters":       true,
	"system:nodes":         true,
	"system:node-proxier":  true,
	"system:bootstrappers": true,
	"system:monitoring":    true,
}

// platformSubjectPrefixes cover the identities that carry a component or node
// name, which cannot be listed exhaustively.
var platformSubjectPrefixes = []string{
	"system:kube-",          // kube-controller-manager, kube-scheduler, kube-proxy
	"system:node:",          // one individual kubelet
	"system:controller:",    // the built-in controllers
	"system:bootstrappers:", // kubeadm node bootstrap
}

// isPlatformSubject reports whether a subject is Kubernetes itself or the
// distribution's control plane, rather than an identity anybody could have
// added. Living in a platform namespace is not enough: see platformNamespaceOf.
func isPlatformSubject(s map[string]string) bool {
	name := s["name"]
	if platformSubjects[name] {
		return true
	}
	for _, p := range platformSubjectPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// serviceAccountNamespace pulls the namespace out of the user form of a single
// ServiceAccount identity, system:serviceaccount:<ns>:<name>. It deliberately
// does not match system:serviceaccounts:<ns>, which is the group of every
// ServiceAccount in that namespace.
func serviceAccountNamespace(name string) (string, bool) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(name, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(name, prefix)
	ns, _, found := strings.Cut(rest, ":")
	if !found || ns == "" {
		return "", false
	}
	return ns, true
}

// CheckPlainCredentials reports ConfigMaps holding something that looks like a
// credential. ConfigMaps are not secrets, are rarely access-controlled, and are
// routinely committed to Git.
func CheckPlainCredentials(rs []Resource) []Finding {
	markers := []string{"PASSWORD", "SECRET", "TOKEN", "APIKEY", "API_KEY", "PRIVATE_KEY"}

	var out []Finding
	for _, r := range rs {
		if r.Kind != "ConfigMap" {
			continue
		}
		var hits []string
		for k := range r.Data {
			up := strings.ToUpper(k)
			for _, m := range markers {
				if strings.Contains(up, m) {
					hits = append(hits, k)
					break
				}
			}
		}
		if len(hits) > 0 {
			sort.Strings(hits)
			out = append(out, finding("SC-04", r.Ref(),
				"holds credentials in plain text: "+strings.Join(hits, ", "), High))
		}
	}
	return out
}

// CheckMutableTags reports images referenced by a tag rather than a digest.
// A tag is a pointer someone else can move; a digest is the content itself.
func CheckMutableTags(rs []Resource) []Finding {
	var out []Finding
	for _, r := range rs {
		for _, c := range r.Containers() {
			image, _ := c["image"].(string)
			if image == "" || strings.Contains(image, "@sha256:") {
				continue
			}

			risk := Medium
			detail := fmt.Sprintf("image %q is pinned to a tag, not a digest", image)
			if strings.HasSuffix(image, ":latest") || !strings.Contains(image, ":") {
				risk = High
				detail = fmt.Sprintf("image %q uses a floating tag that can change under you", image)
			}
			out = append(out, finding("SC-07", r.Ref(), detail, risk))
		}
	}
	return out
}

// CheckPrivileged reports containers that run privileged, as root, or with the
// node's filesystem mounted.
func CheckPrivileged(rs []Resource) []Finding {
	var out []Finding
	for _, r := range rs {
		for _, c := range r.Containers() {
			sc, _ := c["securityContext"].(map[string]interface{})

			if priv, ok := sc["privileged"].(bool); ok && priv {
				out = append(out, finding("SC-05", r.Ref(),
					"runs privileged, which disables nearly all container isolation", High))
			}
			if uid, ok := sc["runAsUser"].(int); ok && uid == 0 {
				out = append(out, finding("SC-05", r.Ref(), "runs as root (uid 0)", Medium))
			}
			if sc == nil {
				out = append(out, finding("SC-05", r.Ref(),
					"has no securityContext, so it runs with the image default, usually root", Medium))
			}
		}

		for _, v := range volumes(r) {
			if hp, ok := v["hostPath"].(map[string]interface{}); ok {
				out = append(out, finding("SC-05", r.Ref(),
					fmt.Sprintf("mounts the node filesystem at %v", hp["path"]), High))
			}
		}
	}
	return out
}

func volumes(r Resource) []map[string]interface{} {
	spec := r.PodSpec()
	if spec == nil {
		return nil
	}
	raw, ok := spec["volumes"].([]interface{})
	if !ok {
		return nil
	}
	var out []map[string]interface{}
	for _, v := range raw {
		if m, ok := v.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}

// CheckResourceLimits reports containers without a memory limit. A CPU limit is
// deliberately not required: it causes throttling and rarely prevents an
// outage, where an unbounded container can take the whole node down.
func CheckResourceLimits(rs []Resource) []Finding {
	var out []Finding
	for _, r := range rs {
		for _, c := range r.Containers() {
			res, _ := c["resources"].(map[string]interface{})
			limits, _ := res["limits"].(map[string]interface{})
			if _, ok := limits["memory"]; !ok {
				name, _ := c["name"].(string)
				out = append(out, finding("SC-09", r.Ref(),
					fmt.Sprintf("container %q has no memory limit", name), Low))
			}
		}
	}
	return out
}

// Run executes every check and returns the findings sorted by risk.
func Run(rs []Resource) []Finding {
	var out []Finding
	for _, c := range All {
		out = append(out, c(rs)...)
	}
	order := map[Risk]int{High: 0, Medium: 1, Low: 2}
	sort.SliceStable(out, func(i, j int) bool {
		if order[out[i].Risk] != order[out[j].Risk] {
			return order[out[i].Risk] < order[out[j].Risk]
		}
		return out[i].ID < out[j].ID
	})
	return out
}
