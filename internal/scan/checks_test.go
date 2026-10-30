package scan

import (
	"strings"
	"testing"
)

// These tests are the safety net for changing checks. Each one states a case
// in plain terms: here is a resource, here is what stathe should say about it.
//
// To add a check, copy the closest block below, change the resource and the
// expectation, and run `make test`. A failing test prints what it expected and
// what it got, so a red test tells you what to fix rather than that something
// is vaguely wrong.

// deployment builds a minimal Deployment for tests. The options are applied to
// the single container, so a test only has to state what it cares about.
func deployment(name, ns string, container map[string]interface{}) Resource {
	return Resource{
		Kind:     "Deployment",
		Metadata: Metadata{Name: name, Namespace: ns},
		Spec: map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{container},
				},
			},
		},
	}
}

// ids returns the finding IDs, so tests can assert on what was reported
// without depending on the exact wording.
func ids(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func contains(have []string, want string) bool {
	for _, h := range have {
		if h == want {
			return true
		}
	}
	return false
}

func TestNetworkPolicies(t *testing.T) {
	tests := []struct {
		name      string
		resources []Resource
		wantCount int
	}{
		{
			name: "a namespace with workloads and no policy is reported",
			resources: []Resource{
				deployment("web", "shop", map[string]interface{}{"image": "nginx@sha256:abc"}),
			},
			wantCount: 1,
		},
		{
			name: "a namespace with a policy is not reported",
			resources: []Resource{
				deployment("web", "shop", map[string]interface{}{"image": "nginx@sha256:abc"}),
				{Kind: "NetworkPolicy", Metadata: Metadata{Name: "deny", Namespace: "shop"}},
			},
			wantCount: 0,
		},
		{
			name: "a namespace with no workloads is not reported",
			resources: []Resource{
				{Kind: "ConfigMap", Metadata: Metadata{Name: "cfg", Namespace: "empty"}},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckNetworkPolicies(tt.resources)
			if len(got) != tt.wantCount {
				t.Errorf("expected %d findings, got %d: %v", tt.wantCount, len(got), ids(got))
			}
		})
	}
}

func TestClusterAdmin(t *testing.T) {
	binding := func(name string, subject map[string]string) Resource {
		return Resource{
			Kind:     "ClusterRoleBinding",
			Metadata: Metadata{Name: name},
			RoleRef:  map[string]string{"name": "cluster-admin"},
			Subjects: []map[string]string{subject},
		}
	}

	tests := []struct {
		name     string
		resource Resource
		want     bool
		wantRisk Risk
	}{
		{
			name:     "a service account someone added is reported",
			resource: binding("ci", map[string]string{"kind": "ServiceAccount", "name": "runner", "namespace": "build"}),
			want:     true,
			wantRisk: High,
		},
		{
			name:     "the built-in system:masters binding is not reported",
			resource: binding("cluster-admin", map[string]string{"kind": "Group", "name": "system:masters"}),
			want:     false,
		},
		{
			name:     "a service account in a platform namespace is reported, at medium",
			resource: binding("helm", map[string]string{"kind": "ServiceAccount", "name": "helm", "namespace": "kube-system"}),
			want:     true,
			wantRisk: Medium,
		},
		{
			name:     "the user form of a platform-namespace service account is reported, at medium",
			resource: binding("helm", map[string]string{"kind": "User", "name": "system:serviceaccount:kube-system:helm"}),
			want:     true,
			wantRisk: Medium,
		},
		{
			name:     "cluster-admin for every authenticated user is reported",
			resource: binding("oops", map[string]string{"kind": "Group", "name": "system:authenticated"}),
			want:     true,
			wantRisk: High,
		},
		{
			name:     "cluster-admin for anonymous users is reported",
			resource: binding("oops", map[string]string{"kind": "Group", "name": "system:unauthenticated"}),
			want:     true,
			wantRisk: High,
		},
		{
			name:     "cluster-admin for every service account is reported",
			resource: binding("oops", map[string]string{"kind": "Group", "name": "system:serviceaccounts"}),
			want:     true,
			wantRisk: High,
		},
		{
			name:     "cluster-admin for every service account in a namespace is reported",
			resource: binding("oops", map[string]string{"kind": "Group", "name": "system:serviceaccounts:build"}),
			want:     true,
			wantRisk: High,
		},
		{
			name:     "a node group binding is not reported",
			resource: binding("nodes", map[string]string{"kind": "Group", "name": "system:nodes"}),
			want:     false,
		},
		{
			name:     "a kube-controller-manager binding is not reported",
			resource: binding("kcm", map[string]string{"kind": "User", "name": "system:kube-controller-manager"}),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckClusterAdmin([]Resource{tt.resource})
			if (len(got) > 0) != tt.want {
				t.Fatalf("expected reported=%v, got %d findings", tt.want, len(got))
			}
			if tt.want && got[0].Risk != tt.wantRisk {
				t.Errorf("expected risk %q, got %q (%s)", tt.wantRisk, got[0].Risk, got[0].Detail)
			}

			// Whatever is not reported has to be accountable: every subject
			// ends up in exactly one of the two lists, never in neither.
			suppressed := PlatformSubjects([]Resource{tt.resource})
			if len(got)+len(suppressed) != 1 {
				t.Errorf("subject is neither reported nor accounted for: %d findings, %d suppressed",
					len(got), len(suppressed))
			}
		})
	}
}

func TestMutableTags(t *testing.T) {
	tests := []struct {
		name     string
		image    string
		want     bool
		wantRisk Risk
	}{
		{name: "a digest is fine", image: "nginx@sha256:abc123", want: false},
		{name: "latest is high risk", image: "nginx:latest", want: true, wantRisk: High},
		{name: "no tag at all is high risk", image: "nginx", want: true, wantRisk: High},
		{name: "a version tag is medium risk", image: "nginx:1.27", want: true, wantRisk: Medium},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := deployment("app", "shop", map[string]interface{}{"image": tt.image})
			got := CheckMutableTags([]Resource{d})

			if (len(got) > 0) != tt.want {
				t.Fatalf("expected reported=%v for %q, got %d findings", tt.want, tt.image, len(got))
			}
			if tt.want && got[0].Risk != tt.wantRisk {
				t.Errorf("expected risk %q for %q, got %q", tt.wantRisk, tt.image, got[0].Risk)
			}
		})
	}
}

func TestPrivileged(t *testing.T) {
	tests := []struct {
		name      string
		container map[string]interface{}
		want      bool
	}{
		{
			name: "privileged is reported",
			container: map[string]interface{}{
				"image":           "app@sha256:abc",
				"securityContext": map[string]interface{}{"privileged": true},
			},
			want: true,
		},
		{
			name: "a missing securityContext is reported",
			container: map[string]interface{}{
				"image": "app@sha256:abc",
			},
			want: true,
		},
		{
			name: "a non-root securityContext is not reported",
			container: map[string]interface{}{
				"image":           "app@sha256:abc",
				"securityContext": map[string]interface{}{"runAsNonRoot": true},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckPrivileged([]Resource{deployment("app", "shop", tt.container)})
			if (len(got) > 0) != tt.want {
				t.Errorf("expected reported=%v, got %d findings: %v", tt.want, len(got), ids(got))
			}
		})
	}
}

func TestPlainCredentials(t *testing.T) {
	tests := []struct {
		name string
		data map[string]string
		want bool
	}{
		{name: "a password is reported", data: map[string]string{"DB_PASSWORD": "x"}, want: true},
		{name: "a token is reported", data: map[string]string{"API_TOKEN": "x"}, want: true},
		{name: "ordinary configuration is not", data: map[string]string{"LOG_LEVEL": "debug"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := Resource{
				Kind:     "ConfigMap",
				Metadata: Metadata{Name: "cfg", Namespace: "shop"},
				Data:     tt.data,
			}
			got := CheckPlainCredentials([]Resource{cm})
			if (len(got) > 0) != tt.want {
				t.Errorf("expected reported=%v, got %d findings", tt.want, len(got))
			}
		})
	}
}

func TestResourceLimits(t *testing.T) {
	withLimit := map[string]interface{}{
		"name":  "app",
		"image": "app@sha256:abc",
		"resources": map[string]interface{}{
			"limits": map[string]interface{}{"memory": "256Mi"},
		},
	}
	without := map[string]interface{}{"name": "app", "image": "app@sha256:abc"}

	if got := CheckResourceLimits([]Resource{deployment("a", "shop", withLimit)}); len(got) != 0 {
		t.Errorf("a container with a memory limit should not be reported, got %d", len(got))
	}
	if got := CheckResourceLimits([]Resource{deployment("a", "shop", without)}); len(got) != 1 {
		t.Errorf("a container without a memory limit should be reported, got %d", len(got))
	}
}

// TestEveryFindingHasWording guards the report: a finding whose ID is missing
// from the catalogue would reach a client with empty "why it matters" text.
func TestEveryFindingHasWording(t *testing.T) {
	resources := []Resource{
		deployment("web", "shop", map[string]interface{}{"name": "web", "image": "nginx:latest"}),
		{Kind: "ConfigMap", Metadata: Metadata{Name: "cfg", Namespace: "shop"}, Data: map[string]string{"DB_PASSWORD": "x"}},
		{
			Kind:     "ClusterRoleBinding",
			Metadata: Metadata{Name: "ci"},
			RoleRef:  map[string]string{"name": "cluster-admin"},
			Subjects: []map[string]string{{"kind": "ServiceAccount", "name": "runner", "namespace": "build"}},
		},
	}

	for _, f := range Run(resources) {
		if f.Title == "" || f.Why == "" || f.Next == "" {
			t.Errorf("%s has no catalogue entry, so the report would show empty text", f.ID)
		}
	}
}

// TestNorthwindFindings pins what the demo cluster is supposed to produce.
//
// It matches on the finding text rather than the ID on purpose. Several
// different weaknesses report the same ID, so asserting on IDs alone would let
// someone remove the privileged container and still see a green test — which
// is exactly the kind of test that makes you trust a suite you should not.
func TestNorthwindFindings(t *testing.T) {
	resources, err := LoadDir("../../cluster/northwind")
	if err != nil {
		t.Fatalf("could not load the Northwind manifests: %v", err)
	}

	findings := Run(resources)

	// Each entry is a weakness attack.md walks a workshop through, described
	// by a phrase that must appear in the reported detail.
	required := map[string]string{
		"SC-01 no network separation":      "no NetworkPolicy",
		"SC-04 credentials in a ConfigMap": "credentials in plain text",
		"SC-05 a privileged container":     "runs privileged",
		"SC-05 the node filesystem mount":  "mounts the node filesystem",
		"SC-06 cluster-admin granted":      "grants cluster-admin",
		"SC-07 a floating image tag":       "floating tag",
		"SC-09 no memory limit":            "no memory limit",
	}

	for weakness, phrase := range required {
		if !anyDetailContains(findings, phrase) {
			t.Errorf("%s is no longer demonstrable in Northwind (nothing reported %q).\n"+
				"Northwind is supposed to stay broken: restore it, or update this test "+
				"and the matching section in cluster/attack.md.", weakness, phrase)
		}
	}
}

func anyDetailContains(fs []Finding, phrase string) bool {
	for _, f := range fs {
		if strings.Contains(f.Detail, phrase) {
			return true
		}
	}
	return false
}
