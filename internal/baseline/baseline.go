// Package baseline turns findings into the configuration that fixes them.
//
// It writes files and never touches a cluster. That is not timidity: the whole
// method rests on the client applying the change themselves, through their own
// review and their own pipeline, in their own change window. A tool that
// applies policy to a production platform on a consultant's laptop is how you
// lose the next engagement.
//
// There is one honest complication, and it shapes this package.
//
// Pod Security Admission has a warn and an audit mode. Labels in those modes
// report violations and block nothing, so they are safe to apply during
// business hours and tell you exactly what enforcement would have stopped.
//
// NetworkPolicy has no such mode. The moment a default-deny policy lands, it
// is enforcing. There is no dry run. So the two kinds of output are kept in
// separate directories with separate instructions, and the generated README
// says plainly which one can be applied this afternoon and which one needs a
// change window and someone watching the dashboards.
package baseline

import (
	"fmt"
	"sort"
	"strings"

	"github.com/stathe-io/stathe/internal/scan"
)

// File is one generated artefact, ready to be written to disk or reviewed in a
// merge request.
type File struct {
	Name    string
	Content string
}

// Options carries what cannot be derived from the findings.
type Options struct {
	// Ingress is the controller detected by preflight, for example "Traefik".
	// Empty means the ingress exception is generated with a placeholder and a
	// comment, rather than silently omitted.
	Ingress string

	// IngressNamespace is where that controller runs. Empty gets a placeholder.
	IngressNamespace string
}

// Generate produces the baseline for the namespaces that need one.
//
// Only SC-01 drives it today: the namespaces with no network separation at
// all. That is deliberate. The other findings are fixed by editing the
// workload the team already owns, and generating a patch for someone else's
// Deployment is how you end up owning their repository.
func Generate(findings []scan.Finding, opt Options) []File {
	namespaces := namespacesNeedingPolicy(findings)
	if len(namespaces) == 0 {
		return nil
	}

	if opt.IngressNamespace == "" {
		opt.IngressNamespace = "INGRESS-NAMESPACE"
	}

	var out []File
	out = append(out, File{Name: "README.md", Content: readme(namespaces, opt)})

	for _, ns := range namespaces {
		out = append(out, File{
			Name:    fmt.Sprintf("warn/%s-pod-security.yaml", ns),
			Content: podSecurity(ns),
		})
		out = append(out, File{
			Name:    fmt.Sprintf("enforcing/%s-network-policy.yaml", ns),
			Content: networkPolicies(ns, opt),
		})
	}

	return out
}

// namespacesNeedingPolicy reads the SC-01 findings rather than taking a list,
// so the baseline can only ever cover ground the assessment actually walked.
func namespacesNeedingPolicy(findings []scan.Finding) []string {
	seen := map[string]bool{}
	for _, f := range findings {
		if f.ID != "SC-01" {
			continue
		}
		// SC-01 names its resource as "namespace/<name>".
		if ns, ok := strings.CutPrefix(f.Resource, "namespace/"); ok {
			seen[ns] = true
		}
	}

	out := make([]string, 0, len(seen))
	for ns := range seen {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// podSecurity emits the labels in warn and audit only. enforce is deliberately
// absent: this file is meant to be applied on an ordinary Tuesday, and adding
// enforce here would make that untrue.
func podSecurity(ns string) string {
	return fmt.Sprintf(`# Pod Security Admission for %[1]s, reporting only.
#
# warn  surfaces a violation to whoever applies the manifest.
# audit records it in the API server audit log.
#
# Neither blocks anything. Nothing that runs today stops running when this is
# applied, which is why this file is safe during business hours.
#
# Leave it in place for a sprint and collect what it reports. Moving to
# enforcement is a separate decision that needs written approval, and the
# README explains it. It is deliberately not written here, even commented out:
# a blocking label is one keystroke away once it is in the file, and this file
# has to stay provably harmless.
apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
  labels:
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
  annotations:
    stathe.io/addresses: "SC-05"
    stathe.io/mode: "reporting only, blocks nothing"
`, ns)
}

// networkPolicies emits ingress separation only.
//
// Egress is left alone on purpose. A default-deny-egress policy also blocks
// DNS, and a namespace that cannot resolve names fails in ways that look like
// an application bug for the first twenty minutes. Egress is a second
// engagement, after the team can see what ingress separation did.
func networkPolicies(ns string, opt Options) string {
	ingressComment := "# Detected ingress controller: " + opt.Ingress
	if opt.Ingress == "" {
		ingressComment = "# No ingress controller was detected. Confirm the namespace below\n" +
			"# before applying, or delete this document if nothing external\n" +
			"# reaches this namespace."
	}

	return fmt.Sprintf(`# Network separation for %[1]s.
#
# THIS ENFORCES THE MOMENT IT IS APPLIED. NetworkPolicy has no audit mode.
#
# What it does: once any policy selects a pod, everything not explicitly
# allowed is denied. These three documents together mean that pods in %[1]s
# accept traffic from each other and from the ingress controller, and from
# nothing else.
#
# What it does not do: it does not touch egress. Pods in %[1]s can still reach
# anything they reach today, including DNS. That is intentional for a first
# step -- a default-deny-egress policy also blocks DNS and fails in ways that
# look like an application bug.
#
# Before applying:
#   1. Apply it to one non-production namespace first and leave it a day.
#   2. Know which other namespaces talk to this one. Anything not listed below
#      stops working immediately.
#   3. Have a change window and someone watching error rates.
#
# Rollback is immediate and complete:
#   kubectl delete networkpolicy -n %[1]s -l stathe.io/generated=true
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: %[1]s
  labels:
    stathe.io/generated: "true"
  annotations:
    stathe.io/addresses: "SC-01"
spec:
  # An empty podSelector selects every pod in the namespace.
  podSelector: {}
  policyTypes:
    - Ingress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: %[1]s
  labels:
    stathe.io/generated: "true"
  annotations:
    stathe.io/addresses: "SC-01"
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector: {}
---
%[2]s
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-controller
  namespace: %[1]s
  labels:
    stathe.io/generated: "true"
  annotations:
    stathe.io/addresses: "SC-01"
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              # kubernetes.io/metadata.name is set automatically by the API
              # server, so this works without labelling the namespace first.
              kubernetes.io/metadata.name: %[3]s
`, ns, ingressComment, opt.IngressNamespace)
}

func readme(namespaces []string, opt Options) string {
	var b strings.Builder

	b.WriteString("# Baseline\n\n")
	b.WriteString("Generated by `stathe baseline`. Nothing here has been applied.\n\n")
	b.WriteString("These files are meant to go through your own review and your own\n")
	b.WriteString("pipeline. They are split into two directories because the two halves\n")
	b.WriteString("carry very different risk.\n\n")

	b.WriteString("## `warn/` — safe to apply now\n\n")
	b.WriteString("Pod Security Admission labels in `warn` and `audit` mode. They report\n")
	b.WriteString("violations and block nothing. Nothing that runs today stops running.\n\n")
	b.WriteString("```sh\nkubectl apply -f warn/\n```\n\n")
	b.WriteString("Leave them for a sprint, then look at what they reported.\n\n")
	b.WriteString("### Moving to enforcement, later\n\n")
	b.WriteString("Once the warnings are clean, enforcement is one more label per\n")
	b.WriteString("namespace:\n\n")
	b.WriteString("```sh\n")
	b.WriteString("kubectl label namespace NAMESPACE \\\n")
	b.WriteString("  pod-security.kubernetes.io/enforce=baseline\n")
	b.WriteString("```\n\n")
	b.WriteString("That one **does** block: pods violating the baseline profile are\n")
	b.WriteString("refused at admission. It is a separate decision that needs written\n")
	b.WriteString("approval, which is why it is not in any generated file. Start with\n")
	b.WriteString("`baseline`, not `restricted`.\n\n")

	b.WriteString("## `enforcing/` — needs a change window\n\n")
	b.WriteString("NetworkPolicies. **These enforce the moment they are applied.**\n")
	b.WriteString("NetworkPolicy has no audit mode, so there is no way to preview this\n")
	b.WriteString("against live traffic.\n\n")
	b.WriteString("They cover ingress only. Egress is untouched, so DNS and outbound\n")
	b.WriteString("calls keep working. That is deliberate for a first step.\n\n")
	b.WriteString("Apply one namespace at a time, starting with the least critical:\n\n")
	b.WriteString("```sh\n")
	for _, ns := range namespaces {
		b.WriteString(fmt.Sprintf("kubectl apply -f enforcing/%s-network-policy.yaml\n", ns))
	}
	b.WriteString("```\n\n")
	b.WriteString("Rollback is immediate:\n\n")
	b.WriteString("```sh\nkubectl delete networkpolicy -A -l stathe.io/generated=true\n```\n\n")

	b.WriteString("## Before you apply the enforcing half\n\n")
	b.WriteString("Each policy allows traffic from the same namespace and from the\n")
	b.WriteString("ingress controller. **Anything else that talks to these namespaces\n")
	b.WriteString("stops working.** Common things that get missed:\n\n")
	b.WriteString("- Prometheus or another monitoring stack scraping metrics\n")
	b.WriteString("- A service mesh sidecar injector\n")
	b.WriteString("- Backup jobs reaching a database\n")
	b.WriteString("- Another team's namespace calling an API you forgot was shared\n\n")
	b.WriteString("Add an explicit `from:` block for each of those before applying,\n")
	b.WriteString("not after someone reports an outage.\n\n")

	b.WriteString("## Namespaces covered\n\n")
	for _, ns := range namespaces {
		b.WriteString(fmt.Sprintf("- `%s`\n", ns))
	}
	b.WriteString("\nThese are the namespaces that had no NetworkPolicy at all (SC-01).\n")

	if opt.Ingress != "" {
		b.WriteString(fmt.Sprintf("\nIngress controller detected: **%s** in `%s`.\n",
			opt.Ingress, opt.IngressNamespace))
	} else {
		b.WriteString("\nNo ingress controller was detected, so the ingress exception uses\n")
		b.WriteString("a placeholder namespace. Fill it in or delete that document.\n")
	}

	return b.String()
}
