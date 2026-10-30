package scan

import "sort"

// Diff compares two assessments of the same cluster.
//
// This is the retest. "We fixed it" is a claim; a diff against the assessment
// that found it is evidence. Both directions matter equally: a finding that
// disappeared is the work the team did, and a finding that appeared since is
// the thing nobody has looked at yet.
type Diff struct {
	// Resolved are findings in the earlier assessment and not in the later one.
	Resolved []Finding
	// New are findings in the later assessment and not in the earlier one.
	New []Finding
	// Unchanged are in both.
	Unchanged []Finding

	// NewlyAccepted and NoLongerAccepted track the register rather than the
	// cluster. A finding that moved into .stathe.yaml did not get fixed, and a
	// diff that counted it as resolved would be the most flattering lie this
	// tool could tell.
	NewlyAccepted    []Finding
	NoLongerAccepted []Finding

	// VersionChanged is true when the two assessments came from different
	// versions of stathe. It does not invalidate the diff, but it means a new
	// finding can also be a check that did not exist before, so the reader has
	// to be told.
	VersionChanged  bool
	BeforeVersion   string
	AfterVersion    string
	SchemaDowngrade bool
}

// Compare diffs two documents, earlier first.
//
// Findings are matched on ID, resource and detail together. ID and resource
// alone are not enough: one deployment can hold two SC-05 findings, and
// treating them as one would hide the one that is left after the other is
// fixed.
func Compare(before, after Document) Diff {
	d := Diff{
		BeforeVersion: before.Stathe,
		AfterVersion:  after.Stathe,

		// Only when both documents actually name a version. A file that
		// records no version is a separate and larger problem, reported as
		// SchemaDowngrade; saying "the version changed from unknown" on top of
		// that is noise.
		VersionChanged: before.Stathe != "" && after.Stathe != "" && before.Stathe != after.Stathe,

		// A version 1 file carries no provenance at all, so it cannot say
		// which stathe produced it. Comparing against one is allowed and
		// flagged, never silently treated as equivalent.
		SchemaDowngrade: before.SchemaVersion < SchemaVersion || after.SchemaVersion < SchemaVersion,
	}

	beforeFindings := index(before.Findings)
	afterFindings := index(after.Findings)

	for key, f := range beforeFindings {
		if _, ok := afterFindings[key]; ok {
			d.Unchanged = append(d.Unchanged, f)
			continue
		}
		d.Resolved = append(d.Resolved, f)
	}
	for key, f := range afterFindings {
		if _, ok := beforeFindings[key]; !ok {
			d.New = append(d.New, f)
		}
	}

	// Acceptance is compared on its own axis. A finding that is accepted in the
	// later assessment left Findings without the cluster changing, so it has to
	// show up as accepted rather than as resolved.
	beforeAccepted := indexAccepted(before.Accepted)
	afterAccepted := indexAccepted(after.Accepted)

	for key, f := range afterAccepted {
		if _, ok := beforeAccepted[key]; !ok {
			d.NewlyAccepted = append(d.NewlyAccepted, f)
			// It is not also "resolved": the risk was accepted, not removed.
			d.Resolved = drop(d.Resolved, key)
		}
	}
	for key, f := range beforeAccepted {
		if _, ok := afterAccepted[key]; !ok {
			d.NoLongerAccepted = append(d.NoLongerAccepted, f)
		}
	}

	for _, set := range []*[]Finding{
		&d.Resolved, &d.New, &d.Unchanged, &d.NewlyAccepted, &d.NoLongerAccepted,
	} {
		sortFindings(*set)
	}
	return d
}

// Fixed reports whether anything was actually fixed in the cluster, as opposed
// to accepted into the register.
func (d Diff) Fixed() int { return len(d.Resolved) }

func key(f Finding) string { return f.ID + "|" + f.Resource + "|" + f.Detail }

func index(fs []Finding) map[string]Finding {
	out := make(map[string]Finding, len(fs))
	for _, f := range fs {
		out[key(f)] = f
	}
	return out
}

func indexAccepted(as []AcceptedRisk) map[string]Finding {
	out := make(map[string]Finding, len(as))
	for _, a := range as {
		out[key(a.Finding)] = a.Finding
	}
	return out
}

func drop(fs []Finding, k string) []Finding {
	out := fs[:0]
	for _, f := range fs {
		if key(f) != k {
			out = append(out, f)
		}
	}
	return out
}

// sortFindings is the total order the whole tool reports in: risk, then ID,
// then resource, then detail. Run uses it too, which is what makes two
// assessments of an unchanged cluster produce the same document and a diff
// between them show only real changes.
func sortFindings(fs []Finding) {
	order := map[Risk]int{High: 0, Medium: 1, Low: 2}
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if order[a.Risk] != order[b.Risk] {
			return order[a.Risk] < order[b.Risk]
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		return a.Detail < b.Detail
	})
}
