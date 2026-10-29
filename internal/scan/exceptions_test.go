package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeExceptions(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ExceptionsFileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestReasonIsRequired and TestExpiryIsRequired pin the two refusals that make
// this an accepted-risk register rather than a mute button. If either stops
// failing, a team can silence a finding with no record of who decided what, or
// forever, and the tool has quietly become part of the problem.
func TestReasonIsRequired(t *testing.T) {
	dir := writeExceptions(t, `
exceptions:
  - id: SC-09
    resource: "payments/deployment/api"
    expires: 2027-03-01
`)
	_, err := LoadExceptions(dir)
	if err == nil {
		t.Fatal("an exception with no reason was accepted")
	}
	if !strings.Contains(err.Error(), "needs a reason") {
		t.Errorf("the error should say a reason is missing, got: %v", err)
	}
}

func TestExpiryIsRequired(t *testing.T) {
	dir := writeExceptions(t, `
exceptions:
  - id: SC-09
    resource: "payments/deployment/api"
    reason: "LimitRange sets the default"
`)
	_, err := LoadExceptions(dir)
	if err == nil {
		t.Fatal("an exception with no expiry was accepted")
	}
	if !strings.Contains(err.Error(), "expires") {
		t.Errorf("the error should say an expiry is missing, got: %v", err)
	}
}

func TestMissingFileIsFine(t *testing.T) {
	got, err := LoadExceptions(t.TempDir())
	if err != nil {
		t.Fatalf("a missing register should not be an error: %v", err)
	}
	if got != nil {
		t.Errorf("expected no exceptions, got %v", got)
	}
}

func TestBadDateIsRejected(t *testing.T) {
	dir := writeExceptions(t, `
exceptions:
  - id: SC-09
    resource: "*"
    reason: "accepted"
    expires: "next march"
`)
	if _, err := LoadExceptions(dir); err == nil {
		t.Fatal("a non-date expiry was accepted")
	}
}

func fixture() []Finding {
	return []Finding{
		{ID: "SC-01", Risk: High, Resource: "namespace/payments"},
		{ID: "SC-09", Risk: Low, Resource: "payments/deployment/api"},
		{ID: "SC-09", Risk: Low, Resource: "payments/deployment/worker"},
		{ID: "SC-09", Risk: Low, Resource: "billing/deployment/api"},
	}
}

func TestPrefixMatchCoversANamespace(t *testing.T) {
	dir := writeExceptions(t, `
exceptions:
  - id: SC-09
    resource: "payments/*"
    reason: "LimitRange on the namespace sets a default"
    expires: 2099-01-01
`)
	ex, err := LoadExceptions(dir)
	if err != nil {
		t.Fatal(err)
	}

	reported, accepted, lapsed := ApplyExceptions(fixture(), ex, time.Now())

	if len(accepted) != 2 {
		t.Errorf("expected the two payments findings accepted, got %d", len(accepted))
	}
	if len(lapsed) != 0 {
		t.Errorf("nothing should have lapsed, got %d", len(lapsed))
	}
	// billing must survive: a prefix exception must not leak into another
	// namespace, which is the failure mode that hides a real finding.
	var sawBilling bool
	for _, f := range reported {
		if f.Resource == "billing/deployment/api" {
			sawBilling = true
		}
		if strings.HasPrefix(f.Resource, "payments/") && f.ID == "SC-09" {
			t.Errorf("%s should have been accepted", f.Resource)
		}
	}
	if !sawBilling {
		t.Error("the exception leaked into another namespace")
	}
}

// TestExpiredExceptionStopsSuppressing is the one that matters. An acceptance
// that has run out has to put the finding back, and say which acceptance ran
// out, so a build turning red comes with an explanation rather than a mystery.
func TestExpiredExceptionStopsSuppressing(t *testing.T) {
	dir := writeExceptions(t, `
exceptions:
  - id: SC-09
    resource: "payments/*"
    reason: "LimitRange on the namespace sets a default"
    expires: 2020-01-01
`)
	ex, err := LoadExceptions(dir)
	if err != nil {
		t.Fatal(err)
	}

	reported, accepted, lapsed := ApplyExceptions(fixture(), ex, time.Now())

	if len(accepted) != 0 {
		t.Errorf("an expired exception suppressed %d findings", len(accepted))
	}
	if len(reported) != len(fixture()) {
		t.Errorf("expected every finding reported, got %d of %d", len(reported), len(fixture()))
	}
	if len(lapsed) != 1 {
		t.Fatalf("expected one lapsed exception to report, got %d", len(lapsed))
	}
	if lapsed[0].Reason == "" {
		t.Error("the lapsed exception should carry its reason, so the reader knows what was decided")
	}
}

// TestSuppressedFindingsAreReturned guards against the quiet failure: dropping
// accepted findings on the floor instead of handing them back to be counted.
func TestSuppressedFindingsAreReturned(t *testing.T) {
	dir := writeExceptions(t, `
exceptions:
  - id: SC-09
    resource: "*"
    reason: "memory limits are set by a mutating webhook"
    expires: 2099-01-01
`)
	ex, _ := LoadExceptions(dir)
	reported, accepted, _ := ApplyExceptions(fixture(), ex, time.Now())

	if len(reported)+len(accepted) != len(fixture()) {
		t.Errorf("%d reported plus %d accepted does not account for %d findings",
			len(reported), len(accepted), len(fixture()))
	}
	for _, a := range accepted {
		if a.Exception.Reason == "" {
			t.Error("an accepted finding must carry why it was accepted")
		}
	}
}
