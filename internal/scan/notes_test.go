package scan

import (
	"strings"
	"testing"
)

func policy(name string, spec map[string]interface{}) Resource {
	return Resource{
		Kind:     "ValidatingAdmissionPolicy",
		Metadata: Metadata{Name: name},
		Spec:     spec,
	}
}

func TestImagePolicyIsNotedButNeverSuppressesAFinding(t *testing.T) {
	rs := []Resource{
		policy("require-digests", map[string]interface{}{
			"validations": []interface{}{
				map[string]interface{}{
					"expression": `object.spec.containers.all(c, c.image.contains("@sha256:"))`,
				},
			},
		}),
		deployment("web", "shop", map[string]interface{}{"name": "web", "image": "nginx:latest"}),
	}

	notes := ImagePolicyNotes(rs)
	if len(notes) != 1 {
		t.Fatalf("expected the policy to be noted, got %d notes", len(notes))
	}
	if !strings.Contains(notes[0], "require-digests") {
		t.Errorf("the policy has to be named so it can be read, got %q", notes[0])
	}
	if !strings.Contains(notes[0], ExceptionsFileName) {
		t.Errorf("the note has to point at the register as the way to act on it, got %q", notes[0])
	}

	// The whole point: a control stathe cannot interpret does not get to
	// silence a check. SC-07 is still reported, at the same risk.
	findings := CheckMutableTags(rs)
	if len(findings) != 1 {
		t.Fatalf("expected SC-07 to still be reported, got %d findings", len(findings))
	}
	if findings[0].Risk != High {
		t.Errorf("the risk must not be lowered by a policy stathe cannot read, got %q", findings[0].Risk)
	}
}

func TestPolicyWithoutImagesIsNotNoted(t *testing.T) {
	rs := []Resource{policy("require-labels", map[string]interface{}{
		"validations": []interface{}{
			map[string]interface{}{"expression": `has(object.metadata.labels.owner)`},
		},
	})}

	if got := ImagePolicyNotes(rs); len(got) != 0 {
		t.Errorf("expected no note for a policy unrelated to images, got %q", got)
	}
}

// Eighteen findings from three images are three decisions. The cause is what
// makes that visible, so it has to be the image rather than the workload.
func TestMutableTagFindingsCarryTheImageAsCause(t *testing.T) {
	rs := []Resource{
		deployment("a", "shop", map[string]interface{}{"name": "a", "image": "nginx:latest"}),
		deployment("b", "shop", map[string]interface{}{"name": "b", "image": "nginx:latest"}),
		deployment("c", "orders", map[string]interface{}{"name": "c", "image": "node:16-alpine"}),
	}

	byCause := map[string]int{}
	for _, f := range CheckMutableTags(rs) {
		if f.Cause == "" {
			t.Fatalf("SC-07 finding on %s has no cause; grouping by image is what makes it actionable", f.Resource)
		}
		byCause[f.Cause]++
	}

	if len(byCause) != 2 {
		t.Errorf("expected the three findings to group onto two images, got %d groups: %v", len(byCause), byCause)
	}
	if byCause["nginx:latest"] != 2 {
		t.Errorf("expected two findings on nginx:latest, got %d", byCause["nginx:latest"])
	}
}

func TestPlatformNamespacesAreRecordedAndExclusionsSayWhy(t *testing.T) {
	// Restore the package-level set, so the order tests run in cannot matter.
	defer func() { skipNamespaces = namespaceSet(defaultPlatformNamespaces) }()

	all := AddPlatformNamespaces("fleet-system", " cattle-system ", "")
	if !contains(all, "fleet-system") || !contains(all, "cattle-system") {
		t.Fatalf("expected the named namespaces to be added and trimmed, got %v", all)
	}
	if !contains(all, "kube-system") {
		t.Errorf("the defaults have to stay in the set, got %v", all)
	}

	inv := &Inventory{}
	inv.Add(Resource{Kind: "Deployment", Metadata: Metadata{Name: "fleet", Namespace: "fleet-system"}})
	inv.Add(Resource{Kind: "Deployment", Metadata: Metadata{Name: "dns", Namespace: "kube-system"}})
	inv.Add(Resource{Kind: "Deployment", Metadata: Metadata{Name: "shop", Namespace: "shop"}})

	if len(inv.Resources) != 1 {
		t.Errorf("expected only the team's own workload to be assessed, got %d", len(inv.Resources))
	}

	// The reason given has to be the real one: named on the command line is a
	// different statement from "every cluster has this".
	var declared, builtIn string
	for _, s := range inv.Skipped() {
		if strings.Contains(s.What, "fleet-system") {
			declared = s.Reason
		}
		if strings.Contains(s.What, "kube-system") {
			builtIn = s.Reason
		}
	}
	if !strings.Contains(declared, "--platform-namespaces") {
		t.Errorf("a namespace excluded by request has to say so, got %q", declared)
	}
	if strings.Contains(builtIn, "--platform-namespaces") {
		t.Errorf("kube-system is excluded by default, not by request, got %q", builtIn)
	}
}
