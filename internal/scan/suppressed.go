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
	What string `json:"what"`
	// Reason is written for someone who did not choose the filter.
	Reason string `json:"reason"`
}

// Inventory is the result of a load: the resources that will be assessed, and
// what was skipped before the checks ever ran.
type Inventory struct {
	Resources []Resource

	// Context and Server name the cluster this came from, resolved rather than
	// as typed: an empty --context means "the current one", and the reader has
	// to be able to see which one that turned out to be.
	Context string
	Server  string

	// Notes are things the reader needs to weigh that are not findings and not
	// exclusions -- a mitigating control stathe can see but cannot interpret,
	// for instance. They never change a risk level: stathe does not get to
	// decide that something else already handles a finding.
	Notes []string

	// skippedPerNamespace counts resources dropped per namespace, so the
	// summary can say how much was left out and not merely that something was.
	skippedPerNamespace map[string]int

	// unread are resource types the cluster would not hand over. An assessment
	// that could not read ConfigMaps found no credentials in them, and saying
	// "no findings" without saying that is the same lie as hiding one.
	unread []Suppressed

	// onlyDeclared limits the namespace filter to the namespaces somebody named
	// on the command line, leaving out the kube-* defaults. It is set for a
	// directory of manifests: those files were put there on purpose, so the
	// only reason to skip one is that the operator said so.
	onlyDeclared bool
}

// plural keeps the count readable: "1 resources" reads as a bug in the tool,
// and a reader who distrusts the output stops reading it.
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// NewInventory wraps resources that were loaded without a cluster -- from a
// directory of manifests -- so that path gets the same notes and the same
// document sections as a cluster read. Nothing is filtered: every manifest in a
// directory was put there on purpose.
func NewInventory(rs []Resource) *Inventory {
	inv := &Inventory{onlyDeclared: true}
	for _, r := range rs {
		inv.Add(r)
	}
	inv.Notes = ImagePolicyNotes(inv.Resources)
	return inv
}

// Keep reports whether a resource belongs in the assessment, and records it as
// skipped when it does not. It is the only place the namespace filter is
// applied, so nothing can be dropped without being counted.
func (inv *Inventory) Keep(r Resource) bool {
	ns := r.Metadata.Namespace

	skip := skipNamespaces[ns]
	if inv.onlyDeclared {
		skip = declaredPlatformNamespaces[ns]
	}
	if !skip {
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

	out := make([]Suppressed, 0, len(names)+len(inv.unread))
	out = append(out, inv.unread...)
	for _, ns := range names {
		reason := "declared a platform namespace with --platform-namespaces, so its " +
			"findings belong to whoever runs the platform rather than to this assessment"
		if IsDefaultPlatformNamespace(ns) {
			reason = "a namespace every cluster has for its own components, " +
				"belonging to the distribution rather than to the team being assessed"
		}
		out = append(out, Suppressed{
			What:   fmt.Sprintf("%s in namespace %s", plural(inv.skippedPerNamespace[ns], "resource"), ns),
			Reason: reason,
		})
	}
	return out
}
