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
	Why      string `json:"why"`
	Next     string `json:"next"`
}

func (f Finding) String() string {
	return fmt.Sprintf("%-7s %-8s %-44s %s", f.ID, f.Risk, f.Resource, f.Detail)
}

// Catalogue holds the fixed wording per finding ID. Keeping it in one place is
// what makes two assessments comparable, and what stops the report from
// drifting into whatever phrasing seemed right that afternoon.
var Catalogue = map[string]struct {
	Title string
	Why   string
	Next  string
}{
	"NW-01": {
		Title: "No network separation between workloads",
		Why:   "A single compromised component gives an attacker a direct path to every other service, including the database.",
		Next:  "Apply a default-deny NetworkPolicy per namespace, with explicit exceptions for DNS and the ingress controller.",
	},
	"NW-04": {
		Title: "Credentials stored in plain configuration",
		Why:   "Anyone with read access to the repository or the namespace can read the password, including CI runners and backups.",
		Next:  "Move the value to a Secret backed by a vault or Sealed Secrets, and rotate it.",
	},
	"NW-05": {
		Title: "Container runs with excessive privileges",
		Why:   "A privileged container that is broken into is effectively root on the node, not just inside the container.",
		Next:  "Set runAsNonRoot, drop privileged, and add the capabilities the workload actually needs.",
	},
	"NW-06": {
		Title: "Service account bound to cluster-admin",
		Why:   "The token sits in every pod using that account. Whoever reaches one of those pods controls the whole cluster.",
		Next:  "Determine the permissions actually used, write a Role for exactly those, and remove the binding.",
	},
	"NW-07": {
		Title: "Workload uses a mutable image tag",
		Why:   "A tag can point at different software tomorrow, so a restart can silently run an untested version and you cannot prove what ran during an incident.",
		Next:  "Pin the image on digest and let Renovate propose updates.",
	},
	"NW-09": {
		Title: "Workload has no resource limits",
		Why:   "One bug or one crypto miner can consume the node and take every other workload on it down.",
		Next:  "Set a memory limit per container and a LimitRange per namespace as a default.",
	},
}
