package scan

import (
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersion is the version of the JSON a run emits.
//
// Version 1 was a bare array of findings. It could not say which version of
// stathe produced it, what it was pointed at, what it accepted or what it left
// out -- everything a reader needs before treating the file as evidence rather
// than as output. Version 2 is an object, and the array lives under "findings".
//
// Bump this when the shape changes, never when a field is added. Readers here
// accept both versions, so a client's old file stays readable.
const SchemaVersion = 2

// Document is one assessment, in the form that gets stored, handed over and
// compared against the next one.
//
// The findings are deterministically ordered (see Run), so two assessments of
// an unchanged cluster differ only in the provenance fields: AssessedAt moves,
// and nothing else does. That is what makes a diff between two of these
// readable -- every line it shows is a line that changed in the cluster.
type Document struct {
	SchemaVersion int `json:"schema_version"`

	// Stathe is the version that produced this, which a reader needs before
	// comparing two documents: a finding can also appear because the tool
	// learned to look for it.
	Stathe     string    `json:"stathe_version"`
	AssessedAt time.Time `json:"assessed_at"`

	// Source is the context or directory that was assessed, resolved: an empty
	// --context becomes the name of the context that was actually used.
	Source string `json:"source"`

	// Server is the API server behind that context, which is what distinguishes
	// two clusters whose contexts are both called "production".
	Server string `json:"server,omitempty"`

	// KubernetesVersion matters when comparing two assessments: a finding can
	// appear because the cluster was upgraded under it.
	KubernetesVersion string `json:"kubernetes_version,omitempty"`
	ResourcesChecked  int    `json:"resources_checked"`

	// PlatformNamespaces is which namespaces this assessment held to be out of
	// scope. Two assessments are comparable only if that answer is recorded
	// rather than remembered.
	PlatformNamespaces []string `json:"platform_namespaces,omitempty"`

	// Notes are things to weigh that are neither findings nor exclusions, such
	// as a control stathe can see but cannot interpret.
	Notes []string `json:"notes,omitempty"`

	Findings []Finding `json:"findings"`

	// Accepted are the findings an exception covers. They are in the document
	// rather than dropped from it: a report that shows 17 where a run found 19
	// is the one an auditor catches.
	Accepted []AcceptedRisk `json:"accepted,omitempty"`

	// Lapsed are acceptances that ran out. The findings they used to cover are
	// back in Findings; this says why they reappeared.
	Lapsed []LapsedRisk `json:"lapsed,omitempty"`

	// NotAssessed is everything filtered out before the checks ran. A reader
	// cannot judge a count of findings without it.
	NotAssessed []Suppressed `json:"not_assessed,omitempty"`
}

// AcceptedRisk is a finding plus the acceptance that covers it, flattened for
// JSON so a pipeline does not have to understand the on-disk exception shape.
type AcceptedRisk struct {
	Finding Finding `json:"finding"`
	Reason  string  `json:"reason"`
	Expires string  `json:"expires"`
}

// LapsedRisk is an acceptance that has expired.
type LapsedRisk struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Reason   string `json:"reason"`
	Expired  string `json:"expired"`
}

// NewDocument assembles a document from what a run produced.
//
// It takes the Inventory rather than a list of resources so that everything the
// load learned -- which cluster, which API server, what it could not read, what
// it noticed -- reaches the document without each caller having to remember to
// pass it.
// notAssessed is passed in rather than taken from the Inventory: the load only
// knows what it skipped, and the checks know what they filtered. Both belong in
// the same section, so the caller that has both assembles it.
func NewDocument(version, source string, inv *Inventory, at time.Time,
	findings []Finding, accepted []Accepted, lapsed []Exception,
	notAssessed []Suppressed, platformNamespaces []string) Document {

	doc := Document{
		SchemaVersion:      SchemaVersion,
		Stathe:             version,
		AssessedAt:         at.UTC(),
		Source:             source,
		Server:             inv.Server,
		KubernetesVersion:  inv.Version,
		ResourcesChecked:   len(inv.Resources),
		PlatformNamespaces: platformNamespaces,
		Notes:              inv.Notes,
		Findings:           findings,
		NotAssessed:        notAssessed,
	}

	for _, a := range accepted {
		doc.Accepted = append(doc.Accepted, AcceptedRisk{
			Finding: a.Finding,
			Reason:  a.Exception.Reason,
			Expires: a.Exception.Expires,
		})
	}
	for _, e := range lapsed {
		doc.Lapsed = append(doc.Lapsed, LapsedRisk{
			ID:       e.ID,
			Resource: e.Resource,
			Reason:   e.Reason,
			Expired:  e.Expires,
		})
	}

	return doc
}

// ParseDocument reads either schema version.
//
// A version 1 file -- a bare array -- is still accepted, because a client may
// be comparing this quarter against a run from before the format changed. What
// it cannot do is invent the fields that format never carried: the result says
// SchemaVersion 1, and a caller that needs provenance has to say so rather
// than report a blank as a fact.
func ParseDocument(raw []byte) (Document, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err == nil && doc.SchemaVersion != 0 {
		if doc.SchemaVersion > SchemaVersion {
			return Document{}, fmt.Errorf(
				"this file is schema version %d and this stathe understands up to %d; use a newer stathe",
				doc.SchemaVersion, SchemaVersion)
		}
		return doc, nil
	}

	var findings []Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return Document{}, fmt.Errorf("this is neither a stathe document nor a findings array: %w", err)
	}
	return Document{SchemaVersion: 1, Findings: findings}, nil
}
