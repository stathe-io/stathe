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
		out = append(out, finding("NW-01", "namespace/"+ns,
			"no NetworkPolicy, so every pod here can reach every other pod in the cluster", High))
	}
	return out
}

// CheckClusterAdmin reports subjects bound to cluster-admin.
func CheckClusterAdmin(rs []Resource) []Finding {
	var out []Finding
	for _, r := range rs {
		if r.Kind != "ClusterRoleBinding" || r.RoleRef["name"] != "cluster-admin" {
			continue
		}
		for _, s := range r.Subjects {
			name := s["name"]
			if ns := s["namespace"]; ns != "" {
				name = ns + "/" + name
			}
			out = append(out, finding("NW-06", r.Ref(),
				fmt.Sprintf("grants cluster-admin to %s %s", strings.ToLower(s["kind"]), name), High))
		}
	}
	return out
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
			out = append(out, finding("NW-04", r.Ref(),
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
			out = append(out, finding("NW-07", r.Ref(), detail, risk))
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
				out = append(out, finding("NW-05", r.Ref(),
					"runs privileged, which disables nearly all container isolation", High))
			}
			if uid, ok := sc["runAsUser"].(int); ok && uid == 0 {
				out = append(out, finding("NW-05", r.Ref(), "runs as root (uid 0)", Medium))
			}
			if sc == nil {
				out = append(out, finding("NW-05", r.Ref(),
					"has no securityContext, so it runs with the image default, usually root", Medium))
			}
		}

		for _, v := range volumes(r) {
			if hp, ok := v["hostPath"].(map[string]interface{}); ok {
				out = append(out, finding("NW-05", r.Ref(),
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
				out = append(out, finding("NW-09", r.Ref(),
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
