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
// unlimitedClusterRoles names the ClusterRoles that grant everything, so a
// binding can be judged on what the role permits rather than on what it is
// called.
//
// Only roles present in what was assessed are listed. A binding pointing at a
// role stathe never saw is left alone: calling it safe would hide a real one,
// and calling it cluster-admin would invent a finding about a role the reader
// cannot look up. Either way the honest answer is that it was not assessed.
func unlimitedClusterRoles(rs []Resource) map[string]bool {
	out := map[string]bool{}
	for _, r := range rs {
		if r.Kind != "ClusterRole" {
			continue
		}
		for _, rule := range r.Rules {
			if rule.GrantsEverything() {
				out[r.Metadata.Name] = true
				break
			}
		}
	}
	return out
}

func CheckClusterAdmin(rs []Resource) []Finding {
	unlimited := unlimitedClusterRoles(rs)

	var out []Finding
	for _, r := range rs {
		if r.Kind != "ClusterRoleBinding" {
			continue
		}

		role := r.RoleRef["name"]
		// What the binding grants, in the words the finding will use. A role
		// nobody recognises has to be explained, or the finding reads as a
		// false positive about ordinary platform plumbing and gets closed. The
		// explanation goes at the end of the sentence rather than next to the
		// role name, so the subject is not pushed behind a relative clause.
		granted, explain := "cluster-admin", ""
		if role != "cluster-admin" {
			if !unlimited[role] {
				continue
			}
			granted = "clusterrole " + role
			explain = ", and that role permits every action on every resource in every API group"
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

			detail := fmt.Sprintf("grants %s to %s %s", granted, kind, name)
			risk := High

			if ns, ok := platformNamespaceOf(s); ok {
				risk = Medium
				detail += fmt.Sprintf(", in platform namespace %s; confirm it is the distribution's own and not something added", ns)
			}
			if group, ok := everySubjectGroup(s); ok {
				detail += ", which is " + group
			}
			// Last, so the clauses about the subject stay next to the subject
			// and "that role" cannot be read as referring to the group.
			detail += explain

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
	// Sorted for the same reason the findings are: this list goes into the
	// document, and a document that reorders itself between runs cannot be
	// diffed against the previous one.
	sort.Slice(out, func(i, j int) bool { return out[i].What < out[j].What })
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
	var out []Finding
	for _, r := range rs {
		if r.Kind != "ConfigMap" {
			continue
		}
		var hits []string
		for k := range r.Data {
			if looksLikeACredentialKey(k) {
				hits = append(hits, k)
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

// credentialSuffixes are the endings of a key that holds a secret. The test is
// on the end of the name rather than anywhere in it, because the word is a
// noun there: PASSWORD, DB_PASSWORD and app.password all name a password,
// while SECRET_SCANNER_ENABLED names a feature flag.
var credentialSuffixes = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN", "APIKEY", "API_KEY",
	"PRIVATE_KEY", "ACCESS_KEY", "SECRET_KEY", "CREDENTIALS", "PASSPHRASE",
}

// notCredentials are endings that follow a credential word and turn it into
// something else: a switch, a list of names, a file path, a duration.
var notCredentials = []string{
	"ENABLED", "DISABLED", "REQUIRED", "NAME", "NAMES", "ACCOUNT", "ACCOUNTS",
	"INFO", "PATH", "FILE", "DIR", "URL", "URI", "TYPE", "PROVIDER", "REF",
	"KEYS", "COUNT", "TTL", "TIMEOUT", "EXPIRY", "ROTATION", "POLICY",
	"VERSION", "FORMAT", "LENGTH", "MIN", "MAX",
}

// looksLikeACredentialKey decides whether a ConfigMap key names a secret.
//
// SC-04 is reported at high, and a high-severity false positive is the most
// expensive output this tool produces: it is the one a client checks first, and
// the credibility of every other finding rides on it. A substring match made
// FOO_SECRET_SCANNER_ENABLED a credential. So the rule is narrower and says no
// in the cases that are demonstrably not credentials -- which does mean a key
// called SECRET_FOR_THE_DATABASE is missed. Missing one is recoverable;
// inventing one in front of a client is not.
func looksLikeACredentialKey(key string) bool {
	up := strings.ToUpper(key)

	// Separators vary by convention (DB_PASSWORD, db.password, dbPassword as
	// DBPASSWORD); normalising them means one rule instead of three.
	norm := strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(up)

	for _, no := range notCredentials {
		if strings.HasSuffix(norm, "_"+no) || norm == no {
			return false
		}
	}

	for _, suffix := range credentialSuffixes {
		if norm == suffix || strings.HasSuffix(norm, "_"+suffix) {
			return true
		}
		// No separator at all: DBPASSWORD, mysqlpassword.
		if !strings.Contains(norm, "_") && strings.HasSuffix(norm, suffix) {
			return true
		}
	}
	return false
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
			f := finding("SC-07", r.Ref(), detail, risk)
			// The image, not the workload: a handful of charts can account for
			// most of the SC-07 findings in a cluster, and the fix is per image.
			f.Cause = image
			out = append(out, f)
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

		// Every host mount on a workload becomes one finding, ranked by the
		// worst path; see hostPathFinding.
		var hostPaths []string
		for _, v := range volumes(r) {
			if hp, ok := v["hostPath"].(map[string]interface{}); ok {
				hostPaths = append(hostPaths, fmt.Sprintf("%v", hp["path"]))
			}
		}
		if f, ok := hostPathFinding(r.Ref(), hostPaths); ok {
			out = append(out, f)
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

// Run executes every check and returns the findings sorted by risk, then by ID,
// then by resource and detail.
//
// The last two are not cosmetic. Sorting only on risk and ID leaves findings
// that share both in whatever order the resources arrived in, and from a live
// cluster that is the order the API server happened to list them -- not stable
// between two runs. The ordering here is total: every field a reader can see
// takes part in it, so the same cluster produces the same document and a diff
// between two runs shows only what actually changed.
func Run(rs []Resource) []Finding {
	var out []Finding
	for _, c := range All {
		out = append(out, c(rs)...)
	}
	sortFindings(out)
	return out
}
