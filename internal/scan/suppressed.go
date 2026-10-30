package scan

import (
	"fmt"
	"sort"
)

// Suppressed is one thing an assessment deliberately left out, with the reason
// it was left out.
//
// Every filter in this tool produces one of these. A run that narrows what it
// looked at and then prints a single number is a run nobody can check: the
// reader cannot tell a clean cluster from a quiet tool. Findings say what is
// wrong, these say what was not considered, and both are printed.
type Suppressed struct {
	// What names the thing left out the way a reader would look it up.
	What string
	// Reason is written for someone who did not choose the filter.
	Reason string
}

// Inventory is the result of a load: the resources that will be assessed, and
// what was skipped before the checks ever ran.
type Inventory struct {
	Resources []Resource

	// skippedPerNamespace counts resources dropped per namespace, so the
	// summary can say how much was left out and not merely that something was.
	skippedPerNamespace map[string]int
}

// Keep reports whether a resource belongs in the assessment, and records it as
// skipped when it does not. It is the only place the namespace filter is
// applied, so nothing can be dropped without being counted.
func (inv *Inventory) Keep(r Resource) bool {
	ns := r.Metadata.Namespace
	if !skipNamespaces[ns] {
		return true
	}
	if inv.skippedPerNamespace == nil {
		inv.skippedPerNamespace = map[string]int{}
	}
	inv.skippedPerNamespace[ns]++
	return false
}

// Add keeps a resource if it belongs in the assessment, and counts it as
// skipped otherwise.
func (inv *Inventory) Add(r Resource) {
	if inv.Keep(r) {
		inv.Resources = append(inv.Resources, r)
	}
}

// Skipped describes the namespaces the load left out, ordered by name so two
// runs read the same. The namespaces themselves are platform namespaces, but
// the team can and does put its own workloads there, which is why the count is
// reported rather than assumed to be zero-risk.
func (inv *Inventory) Skipped() []Suppressed {
	names := make([]string, 0, len(inv.skippedPerNamespace))
	for ns := range inv.skippedPerNamespace {
		names = append(names, ns)
	}
	sort.Strings(names)

	out := make([]Suppressed, 0, len(names))
	for _, ns := range names {
		out = append(out, Suppressed{
			What:   fmt.Sprintf("%d resources in namespace %s", inv.skippedPerNamespace[ns], ns),
			Reason: "a platform namespace: it belongs to the distribution rather than to the team being assessed",
		})
	}
	return out
}
