package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stathe-io/stathe/internal/scan"
)

// A resource name comes from the cluster, which means it comes from whoever
// can create a resource there. The report is HTML that someone opens in a
// browser and often forwards, so a name has to survive the trip as text and
// nothing else. html/template escapes by default; this test is here so that
// stays true after someone reaches for text/template or builds a string by
// hand.
func TestReportEscapesAHostileResourceName(t *testing.T) {
	findings := []scan.Finding{{
		ID:       "SC-07",
		Title:    "Workload uses a mutable image tag",
		Risk:     scan.High,
		Resource: `shop/deployment/<script>alert("xss")</script>`,
		Detail:   `image "<img src=x onerror=alert(1)>" uses a floating tag`,
		Why:      "why",
		Next:     "next",
	}}

	var buf bytes.Buffer
	if err := Write(&buf, findings, Meta{Client: "Acme NV", Environment: "production"}, ""); err != nil {
		t.Fatalf("could not write the report: %v", err)
	}
	out := buf.String()

	for _, raw := range []string{
		"<script>alert",
		"<img src=x onerror",
	} {
		if strings.Contains(out, raw) {
			t.Errorf("the report contains %q unescaped; a resource name must never become markup", raw)
		}
	}

	// Escaped, not dropped: an assessment that silently loses part of a
	// resource name is unusable for looking the resource up.
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("the hostile name was not rendered as escaped text; it has to be visible, just inert")
	}
}

// The cover carries the claims a client reads first, and two of them are the
// ones this tool must not overstate.
func TestCoverKeepsItsDisclaimers(t *testing.T) {
	findings := []scan.Finding{{
		ID: "SC-01", Title: "No network separation", Risk: scan.High,
		Resource: "namespace/shop", Detail: "no NetworkPolicy", Why: "why", Next: "next",
	}}

	var buf bytes.Buffer
	meta := Meta{
		Client:      "Acme NV",
		Environment: "production",
		KitVersion:  "v0.3.1",
		Provenance:  "Rendered from a stathe document (schema 2) produced by stathe v0.3.1.",
	}
	if err := Write(&buf, findings, meta, ""); err != nil {
		t.Fatalf("could not write the report: %v", err)
	}
	// Whitespace-normalised: where the template happens to wrap a line is not
	// something a test should be able to fail on.
	out := strings.Join(strings.Fields(buf.String()), " ")

	for _, want := range []string{
		"read-only",        // nothing was changed
		"does not certify", // no compliance claim
		"stathe v0.3.1",    // which version produced this
		"schema 2",         // which assessment it was rendered from
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the cover no longer says %q", want)
		}
	}
}
