package scan

import "fmt"

// Risk is the severity of a finding, judged for the environment it was found
// in rather than taken from a generic score.
type Risk string

const (
	High   Risk = "high"
	Medium Risk = "medium"
	Low    Risk = "low"
)

// Finding is one problem, tied to the resource it was found on. The wording of
// Why and Next ends up in the client report verbatim, so it is written for a
// reader who does not operate the cluster.
type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Risk     Risk   `json:"risk"`
	Resource string `json:"resource"`
	Detail   string `json:"detail"`

	// Cause is what several findings have in common when they do, such as the
	// one image eighteen workloads pull. It is what makes a list of findings
	// actionable: eighteen rows is a backlog, one image is an afternoon. Empty
	// when a finding has no shared cause beyond its own resource.
	Cause string `json:"cause,omitempty"`
	Why   string `json:"why"`
	Next  string `json:"next"`

	// Controls are the regulatory obligations this finding is evidence about.
	// They travel with the finding in JSON so a pipeline can group by article
	// without needing stathe's catalogue.
	Controls []Control `json:"controls,omitempty"`
}

func (f Finding) String() string {
	return fmt.Sprintf("%-7s %-8s %-44s %s", f.ID, f.Risk, f.Resource, f.Detail)
}

// Catalogue holds the fixed wording per finding ID.
//
// IDs are SC-nn, for stathe check. They are stable: an ID never changes
// meaning and is never reused, because a client's previous report, their
// .stathe.yaml and their ticket titles all refer to it. The numbering has
// gaps where checks are planned but not written, which is deliberate -- a
// renumbering would silently repoint every one of those references. Keeping it in one place is
// what makes two assessments comparable, and what stops the report from
// drifting into whatever phrasing seemed right that afternoon.
var Catalogue = map[string]struct {
	Title string
	Why   string
	Next  string
}{
	"SC-01": {
		Title: "No network separation between workloads",
		Why:   "A single compromised component gives an attacker a direct path to every other service, including the database.",
		Next:  "Apply a default-deny NetworkPolicy per namespace, with explicit exceptions for DNS and the ingress controller.",
	},
	"SC-04": {
		Title: "Credentials stored in plain configuration",
		Why:   "Anyone with read access to the repository or the namespace can read the password, including CI runners and backups.",
		Next:  "Move the value to a Secret backed by a vault or Sealed Secrets, and rotate it.",
	},
	"SC-05": {
		Title: "Container runs with excessive privileges",
		Why:   "A privileged container that is broken into is effectively root on the node, not just inside the container.",
		Next:  "Set runAsNonRoot, drop privileged, and add the capabilities the workload actually needs.",
	},
	// The wording covers users and groups as well as service accounts: a
	// binding on an aggregate group such as system:authenticated grants the
	// same thing to everyone at once. The meaning of SC-06 is unchanged --
	// cluster-admin held by somebody who should not hold it -- so the ID still
	// refers to what it always referred to.
	"SC-06": {
		Title: "Cluster-admin granted outside the platform's own bindings",
		Why:   "Whoever holds that identity controls the whole cluster. For a service account the token sits in every pod using it; for a group, every member has it, and the aggregate groups cover every user or every workload there is.",
		Next:  "Determine the permissions actually used, write a Role for exactly those, and remove the binding.",
	},
	"SC-07": {
		Title: "Workload uses a mutable image tag",
		Why:   "A tag can point at different software tomorrow, so a restart can silently run an untested version and you cannot prove what ran during an incident.",
		Next:  "Pin the image on digest and let Renovate propose updates.",
	},
	"SC-09": {
		Title: "Workload has no resource limits",
		Why:   "One bug or one crypto miner can consume the node and take every other workload on it down.",
		Next:  "Set a memory limit per container and a LimitRange per namespace as a default.",
	},
}
