package scan

import (
	"os"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The by-permission half of SC-06 passed every manifest test and never fired
// on a live cluster: the manifests carried the ClusterRole, the cluster read
// did not. This builds both objects the way the dynamic client hands them over
// and runs them through the same conversion LoadCluster uses, so the live path
// is tested and not only the file path.
func TestWildcardRoleIsFoundOnALiveCluster(t *testing.T) {
	role := fromUnstructured(map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]interface{}{"name": "argocd-application-controller"},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{"*"},
				"resources": []interface{}{"*"},
				"verbs":     []interface{}{"*"},
			},
		},
	}, "ClusterRole", "argocd-application-controller", "")

	binding := fromUnstructured(map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata":   map[string]interface{}{"name": "argocd-application-controller"},
		"roleRef": map[string]interface{}{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     "argocd-application-controller",
		},
		"subjects": []interface{}{
			map[string]interface{}{"kind": "ServiceAccount", "name": "argocd-application-controller", "namespace": "argocd"},
		},
	}, "ClusterRoleBinding", "argocd-application-controller", "")

	got := CheckClusterAdmin([]Resource{role, binding})
	if len(got) != 1 {
		t.Fatalf("a wildcard ClusterRole read from the cluster has to be reported, got %d findings", len(got))
	}
}

// LoadCluster reads what wanted lists; the client approves what the RBAC file
// grants. When the two drift apart, either a check silently gets nothing (the
// read is denied and lands in a stderr note) or the client approves access the
// code never uses. Both have happened in this repository's history once, so
// the comparison is a test rather than a review step.
func TestWantedMatchesTheRBACFile(t *testing.T) {
	f, err := os.ReadFile("../../cluster/readonly-rbac.yaml")
	if err != nil {
		t.Fatal(err)
	}

	var granted []string
	dec := yaml.NewDecoder(strings.NewReader(string(f)))
	for {
		var doc struct {
			Kind  string `yaml:"kind"`
			Rules []struct {
				APIGroups []string `yaml:"apiGroups"`
				Resources []string `yaml:"resources"`
				Verbs     []string `yaml:"verbs"`
			} `yaml:"rules"`
		}
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if doc.Kind != "ClusterRole" {
			continue
		}
		for _, rule := range doc.Rules {
			if len(rule.Verbs) != 1 || rule.Verbs[0] != "list" {
				t.Errorf("the RBAC file promises one verb, list; got %v on %v", rule.Verbs, rule.Resources)
			}
			for _, g := range rule.APIGroups {
				for _, r := range rule.Resources {
					granted = append(granted, g+"/"+r)
				}
			}
		}
	}

	var read []string
	for _, w := range wanted {
		read = append(read, w.gvr.Group+"/"+w.gvr.Resource)
	}

	sort.Strings(granted)
	sort.Strings(read)
	if strings.Join(granted, " ") != strings.Join(read, " ") {
		t.Errorf("the RBAC file and wanted disagree\n  granted: %v\n  read:    %v", granted, read)
	}
}

// A binding to a role stathe did not see cannot be judged, and leaving it out
// without a word is how a clean SC-06 comes out of an assessment that never
// looked. It is counted, not reported: stathe does not know what the role
// grants, so it cannot say the binding is wrong.
func TestBindingToAnUnseenRoleIsCounted(t *testing.T) {
	rs := []Resource{
		{
			Kind:     "ClusterRoleBinding",
			Metadata: Metadata{Name: "ops"},
			RoleRef:  map[string]string{"kind": "ClusterRole", "name": "ops-superuser"},
			Subjects: []map[string]string{
				{"kind": "Group", "name": "ops"},
			},
		},
	}

	if got := CheckClusterAdmin(rs); len(got) != 0 {
		t.Errorf("an unseen role is not evidence of cluster-admin, got %d findings", len(got))
	}

	left := UnseenRoles(rs)
	if len(left) != 1 {
		t.Fatalf("the binding has to be listed under NOT ASSESSED, got %d entries", len(left))
	}
	if !strings.Contains(left[0].What, "ops-superuser") {
		t.Errorf("the role has to be named so the reader can look it up, got %q", left[0].What)
	}
}

// cluster-admin itself is never in what was read from a manifest directory,
// and it does not need to be: its meaning is fixed. Listing every binding to
// it as unassessed would bury the real gaps.
func TestBindingToClusterAdminIsNotUnseen(t *testing.T) {
	rs := []Resource{
		{
			Kind:     "ClusterRoleBinding",
			Metadata: Metadata{Name: "admins"},
			RoleRef:  map[string]string{"kind": "ClusterRole", "name": "cluster-admin"},
			Subjects: []map[string]string{{"kind": "Group", "name": "admins"}},
		},
	}
	if left := UnseenRoles(rs); len(left) != 0 {
		t.Errorf("cluster-admin is judged by name, got %+v", left)
	}
}
