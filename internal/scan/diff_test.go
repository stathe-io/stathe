package scan

import (
	"encoding/json"
	"testing"
	"time"
)

func f(id, resource, detail string, risk Risk) Finding {
	return Finding{ID: id, Resource: resource, Detail: detail, Risk: risk}
}

func TestCompareSplitsFixedFromNew(t *testing.T) {
	before := Document{
		SchemaVersion: SchemaVersion,
		Stathe:        "v0.3.1",
		Findings: []Finding{
			f("SC-01", "namespace/shop", "no NetworkPolicy", High),
			f("SC-07", "shop/deployment/web", "floating tag", High),
		},
	}
	after := Document{
		SchemaVersion: SchemaVersion,
		Stathe:        "v0.3.1",
		Findings: []Finding{
			f("SC-07", "shop/deployment/web", "floating tag", High),
			f("SC-06", "clusterrolebinding/ci", "grants cluster-admin", High),
		},
	}

	d := Compare(before, after)

	if len(d.Resolved) != 1 || d.Resolved[0].ID != "SC-01" {
		t.Errorf("expected SC-01 fixed, got %+v", ids(d.Resolved))
	}
	if len(d.New) != 1 || d.New[0].ID != "SC-06" {
		t.Errorf("expected SC-06 new, got %+v", ids(d.New))
	}
	if len(d.Unchanged) != 1 || d.Unchanged[0].ID != "SC-07" {
		t.Errorf("expected SC-07 unchanged, got %+v", ids(d.Unchanged))
	}
	if d.VersionChanged {
		t.Error("the versions are the same; nothing should be flagged")
	}
}

// Two findings of the same check on the same resource are two findings. A diff
// that keyed on ID and resource alone would report both as fixed the moment
// one of them was.
func TestCompareKeepsTwoFindingsOnOneResourceApart(t *testing.T) {
	before := Document{
		SchemaVersion: SchemaVersion,
		Findings: []Finding{
			f("SC-05", "tracking/deployment/tracking", "runs privileged", High),
			f("SC-05", "tracking/deployment/tracking", "mounts the node filesystem at /", High),
		},
	}
	after := Document{
		SchemaVersion: SchemaVersion,
		Findings: []Finding{
			f("SC-05", "tracking/deployment/tracking", "mounts the node filesystem at /", High),
		},
	}

	d := Compare(before, after)

	if len(d.Resolved) != 1 {
		t.Fatalf("expected exactly one of the two SC-05 findings fixed, got %d", len(d.Resolved))
	}
	if d.Resolved[0].Detail != "runs privileged" {
		t.Errorf("the wrong one was reported as fixed: %q", d.Resolved[0].Detail)
	}
	if len(d.Unchanged) != 1 {
		t.Errorf("expected the hostPath finding to still be there, got %d unchanged", len(d.Unchanged))
	}
}

// The most flattering lie available to this tool: a finding that moved into
// .stathe.yaml counted as work done.
func TestAcceptedIsNotFixed(t *testing.T) {
	finding := f("SC-09", "shop/deployment/web", "no memory limit", Low)

	before := Document{SchemaVersion: SchemaVersion, Findings: []Finding{finding}}
	after := Document{
		SchemaVersion: SchemaVersion,
		Accepted: []AcceptedRisk{{
			Finding: finding,
			Reason:  "accepted until the capacity review",
			Expires: "2027-01-01",
		}},
	}

	d := Compare(before, after)

	if len(d.Resolved) != 0 {
		t.Errorf("an accepted finding is not a fixed finding, got %d fixed: %+v", len(d.Resolved), ids(d.Resolved))
	}
	if len(d.NewlyAccepted) != 1 {
		t.Fatalf("expected one newly accepted finding, got %d", len(d.NewlyAccepted))
	}
	if d.Fixed() != 0 {
		t.Errorf("Fixed() should count only cluster changes, got %d", d.Fixed())
	}
}

func TestExpiredAcceptanceShowsAsNoLongerAccepted(t *testing.T) {
	finding := f("SC-09", "shop/deployment/web", "no memory limit", Low)

	before := Document{
		SchemaVersion: SchemaVersion,
		Accepted:      []AcceptedRisk{{Finding: finding, Reason: "capacity review", Expires: "2026-01-01"}},
	}
	after := Document{SchemaVersion: SchemaVersion, Findings: []Finding{finding}}

	d := Compare(before, after)

	if len(d.NoLongerAccepted) != 1 {
		t.Errorf("expected the lapsed acceptance to be named, got %d", len(d.NoLongerAccepted))
	}
	if len(d.New) != 1 {
		t.Errorf("the finding is reported again, so it is new to the reported set, got %d", len(d.New))
	}
}

// A new finding can also be a check that did not exist in the earlier run. The
// diff cannot tell the difference, so it has to say so.
func TestCompareFlagsADifferentStatheVersion(t *testing.T) {
	d := Compare(
		Document{SchemaVersion: SchemaVersion, Stathe: "v0.3.0"},
		Document{SchemaVersion: SchemaVersion, Stathe: "v0.4.0"},
	)

	if !d.VersionChanged {
		t.Error("two different stathe versions have to be flagged")
	}
	if d.SchemaDowngrade {
		t.Error("both documents are current; nothing should be flagged as predating the format")
	}
}

func TestCompareFlagsALegacyFile(t *testing.T) {
	legacy, err := ParseDocument([]byte(`[{"id":"SC-01","resource":"namespace/shop","detail":"no NetworkPolicy","risk":"high"}]`))
	if err != nil {
		t.Fatalf("a bare findings array still has to be readable: %v", err)
	}
	if legacy.SchemaVersion != 1 {
		t.Errorf("expected schema version 1, got %d", legacy.SchemaVersion)
	}
	if len(legacy.Findings) != 1 {
		t.Fatalf("expected the findings to survive the parse, got %d", len(legacy.Findings))
	}

	d := Compare(legacy, Document{SchemaVersion: SchemaVersion, Stathe: "v0.3.1"})
	if !d.SchemaDowngrade {
		t.Error("a file that records nothing about its run has to be flagged as such")
	}
}

func TestDocumentRoundTrips(t *testing.T) {
	at := time.Date(2026, 10, 30, 9, 15, 0, 0, time.UTC)
	inv := &Inventory{
		Resources: make([]Resource, 70),
		Server:    "https://api.cluster.example:6443",
		Notes:     []string{"ValidatingAdmissionPolicy \"require-digests\" mentions container images."},
	}

	doc := NewDocument("v0.3.1", "production", inv, at,
		[]Finding{f("SC-01", "namespace/shop", "no NetworkPolicy", High)},
		[]Accepted{{
			Finding:   f("SC-09", "shop/deployment/web", "no memory limit", Low),
			Exception: Exception{ID: "SC-09", Resource: "shop/deployment/web", Reason: "capacity review", Expires: "2027-01-01"},
		}},
		[]Exception{{ID: "SC-07", Resource: "shop/deployment/web", Reason: "pinned next sprint", Expires: "2026-01-01"}},
		[]Suppressed{{What: "3 resources in namespace kube-system", Reason: "a platform namespace"}},
		[]string{"kube-system", "kube-public"},
	)

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("could not marshal the document: %v", err)
	}

	got, err := ParseDocument(raw)
	if err != nil {
		t.Fatalf("could not parse the document back: %v", err)
	}

	if got.SchemaVersion != SchemaVersion {
		t.Errorf("expected schema version %d, got %d", SchemaVersion, got.SchemaVersion)
	}
	if got.Stathe != "v0.3.1" || got.Source != "production" || got.ResourcesChecked != 70 {
		t.Errorf("provenance did not survive the round trip: %+v", got)
	}
	if got.Server != "https://api.cluster.example:6443" {
		t.Errorf("the API server distinguishes two clusters both called production, got %q", got.Server)
	}
	if len(got.PlatformNamespaces) != 2 || len(got.Notes) != 1 {
		t.Errorf("scope and notes did not survive the round trip: %d namespaces, %d notes",
			len(got.PlatformNamespaces), len(got.Notes))
	}
	if !got.AssessedAt.Equal(at) {
		t.Errorf("expected %s, got %s", at, got.AssessedAt)
	}
	if len(got.Findings) != 1 || len(got.Accepted) != 1 || len(got.Lapsed) != 1 || len(got.NotAssessed) != 1 {
		t.Errorf("a section was lost: %d findings, %d accepted, %d lapsed, %d not assessed",
			len(got.Findings), len(got.Accepted), len(got.Lapsed), len(got.NotAssessed))
	}
	if got.Accepted[0].Reason != "capacity review" {
		t.Errorf("the acceptance reason is the point of recording it, got %q", got.Accepted[0].Reason)
	}
}

// A document from a stathe that is newer than the one reading it cannot be
// understood, and guessing is worse than refusing.
func TestParseDocumentRefusesANewerSchema(t *testing.T) {
	raw := []byte(`{"schema_version": 99, "findings": []}`)
	if _, err := ParseDocument(raw); err == nil {
		t.Error("expected a refusal for a newer schema version")
	}
}

func TestParseDocumentRejectsSomethingElseEntirely(t *testing.T) {
	if _, err := ParseDocument([]byte(`{"hello": "world"}`)); err == nil {
		t.Error("expected an error for JSON that is neither shape")
	}
}
