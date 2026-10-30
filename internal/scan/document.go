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

	// Source is the context or directory that was assessed, as it was named on
	// the command line.
	Source           string `json:"source"`
	ResourcesChecked int    `json:"resources_checked"`

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
func NewDocument(version, source string, resourcesChecked int, at time.Time,
	findings []Finding, accepted []Accepted, lapsed []Exception, notAssessed []Suppressed) Document {

	doc := Document{
		SchemaVersion:    SchemaVersion,
		Stathe:           version,
		AssessedAt:       at.UTC(),
		Source:           source,
		ResourcesChecked: resourcesChecked,
		Findings:         findings,
		NotAssessed:      notAssessed,
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
