package baseline

import (
	"strings"
	"testing"

	"github.com/TestRebel/stathe/internal/scan"
)

func sc01(ns string) scan.Finding {
	return scan.Finding{ID: "SC-01", Risk: scan.High, Resource: "namespace/" + ns}
}

// TestOnlyCoversAssessedNamespaces guards the rule that the baseline can never
// cover ground the assessment did not walk. Generating policy for a namespace
// nobody looked at is how you take down a service you have never seen.
func TestOnlyCoversAssessedNamespaces(t *testing.T) {
	files := Generate([]scan.Finding{
		sc01("payments"),
		// Not an SC-01, so "logging" has a policy already and must not appear.
		{ID: "SC-05", Risk: scan.High, Resource: "logging/deployment/fluentd"},
	}, Options{})

	for _, f := range files {
		if strings.Contains(f.Name, "logging") {
			t.Errorf("generated %s for a namespace with no SC-01 finding", f.Name)
		}
	}
	if !hasFile(files, "enforcing/payments-network-policy.yaml") {
		t.Error("no policy generated for the namespace that needs one")
	}
}

// TestNothingToDo covers the good outcome. A client whose namespaces all have
// policies should get an empty result, not a directory of files implying work.
func TestNothingToDo(t *testing.T) {
	files := Generate([]scan.Finding{
		{ID: "SC-07", Risk: scan.Medium, Resource: "web/deployment/api"},
	}, Options{})
	if len(files) != 0 {
		t.Errorf("expected nothing to generate, got %d files", len(files))
	}
}

// TestWarnHalfNeverEnforces is the test that matters most.
//
// The whole method rests on "nothing breaks": the warn directory is described
// to the client as safe to apply during business hours. A pod-security enforce
// label slipping into those files would make that a lie and could take down a
// client's namespace. Nothing in warn/ may ever carry enforce.
func TestWarnHalfNeverEnforces(t *testing.T) {
	files := Generate([]scan.Finding{sc01("payments")}, Options{})

	for _, f := range files {
		if !strings.HasPrefix(f.Name, "warn/") {
			continue
		}
		for _, banned := range []string{
			"pod-security.kubernetes.io/enforce",
			"kind: NetworkPolicy",
		} {
			if strings.Contains(f.Content, banned) {
				t.Errorf("%s contains %q; the warn half must block nothing", f.Name, banned)
			}
		}
	}
}

// TestEnforcingHalfSaysSo is the other side: anything that does enforce has to
// announce it, because the reader decides on a change window based on that
// warning alone.
func TestEnforcingHalfSaysSo(t *testing.T) {
	files := Generate([]scan.Finding{sc01("payments")}, Options{})

	for _, f := range files {
		if !strings.HasPrefix(f.Name, "enforcing/") {
			continue
		}
		if !strings.Contains(f.Content, "ENFORCES THE MOMENT IT IS APPLIED") {
			t.Errorf("%s does not warn that it enforces on apply", f.Name)
		}
		// Rollback has to be in the file itself. Someone reading it at 23:00
		// during an incident is not going back to the README.
		if !strings.Contains(f.Content, "kubectl delete networkpolicy") {
			t.Errorf("%s does not carry its own rollback command", f.Name)
		}
		// Egress must stay untouched: a default-deny-egress policy also blocks
		// DNS, which fails like an application bug.
		if strings.Contains(f.Content, "- Egress") {
			t.Errorf("%s restricts egress; that is a later engagement", f.Name)
		}
	}
}

// TestGeneratedPoliciesAreLabelled pins the label the rollback command selects
// on. If these drift apart, the documented rollback silently deletes nothing.
func TestGeneratedPoliciesAreLabelled(t *testing.T) {
	files := Generate([]scan.Finding{sc01("payments")}, Options{})

	for _, f := range files {
		if !strings.HasPrefix(f.Name, "enforcing/") {
			continue
		}
		policies := strings.Count(f.Content, "kind: NetworkPolicy")
		labels := strings.Count(f.Content, `stathe.io/generated: "true"`)
		if policies != labels {
			t.Errorf("%s has %d policies but %d rollback labels; "+
				"the documented rollback would leave some behind",
				f.Name, policies, labels)
		}
	}
}

// TestMissingIngressIsVisible checks that an undetected ingress controller
// produces something a reader must deal with, rather than a quietly wrong
// namespace reference.
func TestMissingIngressIsVisible(t *testing.T) {
	files := Generate([]scan.Finding{sc01("payments")}, Options{})

	var policy string
	for _, f := range files {
		if strings.HasPrefix(f.Name, "enforcing/") {
			policy = f.Content
		}
	}
	if !strings.Contains(policy, "INGRESS-NAMESPACE") {
		t.Error("an undetected ingress controller should leave an obvious placeholder")
	}
	if !strings.Contains(policy, "No ingress controller was detected") {
		t.Error("the placeholder should be explained in the file")
	}
}

func hasFile(files []File, name string) bool {
	for _, f := range files {
		if f.Name == name {
			return true
		}
	}
	return false
}
