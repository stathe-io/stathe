// Command stathe assesses a Kubernetes platform and reports what is wrong with
// it, without changing anything.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/stathe-io/stathe/internal/baseline"
	"github.com/stathe-io/stathe/internal/report"
	"github.com/stathe-io/stathe/internal/scan"
)

const usage = `stathe — Kubernetes security assessment

Usage:
  stathe check --manifests DIR    Assess manifests on disk, no cluster needed
  stathe check --context NAME     Assess a live cluster (read-only)
  stathe check                    Assess the current kubectl context
  stathe report --client NAME     Turn findings into a client-ready document
  stathe diff BEFORE.json AFTER.json
                                  Compare two assessments: what was fixed, what
                                  is new, what was accepted rather than fixed
  stathe preflight --context NAME Check access the day before an assessment
  stathe baseline --out DIR       Generate the fix as files, applying nothing
  stathe compliance               Which NIS2 measures these checks can evidence
  stathe version

Flags:
  --json              Emit findings as JSON instead of a table
  --framework NAME    Show the obligation each finding is evidence about
                      (nis2, dora, iso27001)
  --fail-on LEVEL     Exit 1 when a finding at this severity or above remains
                      (high, medium, low, none). Default none.
  --exceptions DIR    Where to look for .stathe.yaml, the accepted-risk
                      register. Each entry needs a reason and an expiry date.
  --platform-namespaces NS,NS
                      Namespaces that belong to whoever runs the platform
                      rather than to the team being assessed, on top of the
                      kube-* defaults. Their resources are left out, counted
                      and listed under NOT ASSESSED.
  --summary           One line per check, with what the findings have in
                      common, instead of one line per finding.

stathe only ever reads. It never writes to a cluster.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "check":
		os.Exit(runCheck(os.Args[2:]))
	case "report":
		os.Exit(runReport(os.Args[2:]))
	case "diff":
		os.Exit(runDiff(os.Args[2:]))
	case "compliance":
		os.Exit(runCompliance(os.Args[2:]))
	case "preflight":
		os.Exit(runPreflight(os.Args[2:]))
	case "baseline":
		os.Exit(runBaseline(os.Args[2:]))
	case "version":
		fmt.Println("stathe", version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	manifests := fs.String("manifests", "", "directory of manifests to assess")
	kubeContext := fs.String("context", "", "kubectl context to assess")
	asJSON := fs.Bool("json", false, "emit findings as JSON")
	framework := fs.String("framework", "", "annotate findings with obligations (nis2, dora, iso27001)")
	summary := fs.Bool("summary", false, "one line per check instead of one per finding")
	failOn := fs.String("fail-on", "none", "exit 1 when a finding at this severity or above remains (high, medium, low, none)")
	exceptionsDir := fs.String("exceptions", "", "directory holding .stathe.yaml (default: the manifests dir, or the working directory)")
	platformNS := fs.String("platform-namespaces", "", "comma-separated namespaces to treat as the platform's own, on top of the defaults")
	fs.Parse(args)

	// Recorded in the document, and listed under NOT ASSESSED with the reason
	// that they were named here rather than that every cluster has them.
	platformNamespaces := scan.AddPlatformNamespaces(strings.Split(*platformNS, ",")...)

	threshold, ok := failThreshold(*failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown --fail-on %q; use high, medium, low or none\n", *failOn)
		return 2
	}

	if *manifests != "" && *kubeContext != "" {
		fmt.Fprintln(os.Stderr, "use either --manifests or --context, not both")
		return 2
	}
	if *framework != "" && !scan.ValidFramework(*framework) {
		fmt.Fprintf(os.Stderr, "unknown framework %q; use nis2, dora or iso27001\n", *framework)
		return 2
	}

	var (
		inv    *scan.Inventory
		source string
		err    error
	)

	if *manifests != "" {
		source = *manifests
		// A directory is assessed exactly as given: every manifest in it was
		// put there on purpose, so there is nothing to filter and nothing to
		// report as skipped.
		var resources []scan.Resource
		resources, err = scan.LoadDir(*manifests)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not read manifests: %v\n", err)
			return 1
		}
		inv = scan.NewInventory(resources)
	} else {
		inv, err = scan.LoadCluster(*kubeContext)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not read the cluster: %v\n", err)
			return 1
		}

		// Name the cluster that was actually read, not the argument that was
		// typed. Assessing the wrong cluster is the one mistake here nobody can
		// correct afterwards, and it is the reader who has to be able to catch
		// it -- so the context and the API server are printed, and both end up
		// in the document.
		source = inv.Context
		if source == "" {
			source = "an unnamed context"
		}
		if !*asJSON {
			printClusterHeader(os.Stdout, source, inv.Server, inv.Version)
		}
	}

	resources := inv.Resources
	findings := scan.Run(resources)

	// What the assessment left out, collected before anything is printed so the
	// JSON path and the table path report the same exclusions.
	left := append(inv.Skipped(), scan.PlatformSubjects(resources)...)

	// Accepted risk is applied before anything is printed or counted, so the
	// JSON a pipeline consumes and the table a human reads agree.
	exDir := *exceptionsDir
	if exDir == "" {
		exDir = *manifests
	}
	if exDir == "" {
		exDir = "."
	}
	exceptions, err := scan.LoadExceptions(exDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	findings, accepted, lapsed := scan.ApplyExceptions(findings, exceptions, time.Now())

	if *asJSON {
		// One document, carrying the findings, what was accepted, what lapsed,
		// what was filtered out, and which version of stathe looked at what.
		// Everything a reader needs before treating the file as evidence, and
		// everything stathe diff needs to compare two of them.
		doc := scan.NewDocument(version, source, inv, time.Now(),
			findings, accepted, lapsed, left, platformNamespaces)

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			fmt.Fprintf(os.Stderr, "could not write JSON: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Printf("Assessed %d resources in %s\n\n", len(resources), source)
	if len(findings) == 0 {
		fmt.Println("No findings. That is unusual; check that the path is right.")
		// Especially here: a clean result next to a filter the reader cannot
		// see is the one claim this tool must never make by omission.
		printNotes(os.Stdout, inv.Notes)
		printLeftOut(os.Stdout, left)
		return 0
	}

	if *summary {
		// One line per check, for a platform with enough findings that the
		// full list scrolls past. The detail is still in --json and in the
		// report; this is the view you read out loud in a kickoff.
		printSummary(findings)
	} else {
		printFindings(os.Stdout, findings, *framework)
	}

	counts := map[scan.Risk]int{}
	for _, f := range findings {
		counts[f.Risk]++
	}
	fmt.Printf("\n%d findings: %d high, %d medium, %d low\n",
		len(findings), counts[scan.High], counts[scan.Medium], counts[scan.Low])

	// Accepted risk is shown, never silently dropped. A run that hides what it
	// suppressed is the one an auditor catches.
	if len(accepted) > 0 {
		fmt.Printf("\n%d accepted in %s:\n", len(accepted), scan.ExceptionsFileName)
		for _, a := range accepted {
			fmt.Printf("  %-7s %-44s %s (until %s)\n",
				a.Finding.ID, a.Finding.Resource, a.Exception.Reason, a.Exception.Expires)
		}
	}
	for _, e := range lapsed {
		fmt.Printf("\nThe acceptance of %s on %s expired on %s and no longer applies.\n",
			e.ID, e.Resource, e.Expires)
		fmt.Printf("  It was accepted because: %s\n", e.Reason)
		fmt.Println("  Renew the date after deciding again, or fix the finding.")
	}

	printNotes(os.Stdout, inv.Notes)
	printLeftOut(os.Stdout, left)

	if *summary {
		printNextSteps(os.Stdout, source, *manifests != "")
	}

	fmt.Println("\nNothing was changed. This command only reads.")

	if threshold >= 0 {
		for _, f := range findings {
			if rankOf(f.Risk) <= threshold {
				fmt.Printf("\nFailing: %s findings remain and --fail-on is %s.\n", f.Risk, *failOn)
				return 1
			}
		}
	}
	return 0
}

// printLeftOut prints what the assessment did not look at. It is not an
// appendix: the number of findings only means something next to the number of
// things that were filtered out before they could become one. Nothing is
// printed when nothing was left out, which is the honest result for a
// --manifests run.
func printLeftOut(w io.Writer, left []scan.Suppressed) {
	if len(left) == 0 {
		return
	}
	fmt.Fprintf(w, "\nNOT ASSESSED (%d, filtered before the checks ran)\n", len(left))
	for _, s := range left {
		fmt.Fprintf(w, "  %s\n", s.What)
		fmt.Fprintf(w, "      %s\n", s.Reason)
	}
}

// printClusterHeader is the same three lines for check and preflight.
//
// They were different before, which meant the go/no-go a client approved and
// the assessment that followed could not be lined up against each other -- and
// check said only "the current context", which is not something a reader can
// check. An empty field says it is unknown rather than printing a blank that
// reads as a fact.
func printClusterHeader(w io.Writer, context, server, version string) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "Context\t%s\n", nonEmpty(context))
	fmt.Fprintf(tw, "Server\t%s\n", nonEmpty(server))
	fmt.Fprintf(tw, "Version\t%s\n", nonEmpty(version))
	tw.Flush()
}

// printFindings writes the findings as a table that lines up whatever the
// resource names happen to be.
//
// The fixed-width columns it replaces were fine on the demo cluster and broke
// on the first real one: a long namespace plus a long workload name pushed the
// detail -- the part an engineer acts on -- off the right of the terminal.
//
// Findings that are the same problem on several workloads, such as one image
// reused across a chart's deployments, collapse onto one row with the
// workloads listed under it. The document keeps them separate, because each is
// evidence about its own resource and stathe diff has to be able to tell them
// apart; this is a decision about reading, not about recording.
func printFindings(w io.Writer, findings []scan.Finding, framework string) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)

	for _, g := range groupForDisplay(findings) {
		f := g.first
		resource := f.Resource
		if len(g.resources) > 1 {
			resource = plural(len(g.resources), kindOf(g.resources))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.ID, f.Risk, resource, f.Detail)

		if len(g.resources) > 1 {
			for _, r := range g.resources {
				fmt.Fprintf(tw, "\t\t\t  %s\n", r)
			}
		}

		// With a framework selected, the obligation goes on its own line.
		// Putting it in the table would widen every row by the longest
		// article reference in the set.
		if framework != "" {
			for _, c := range scan.ControlsFor(f.ID, scan.Framework(framework)) {
				fmt.Fprintf(tw, "\t\t\t%s  %s\n", c.Ref, c.Name)
			}
		}
	}
	tw.Flush()
}

// displayGroup is one row of the table: a finding, and every resource it was
// reported on with the same wording.
type displayGroup struct {
	first     scan.Finding
	resources []string
}

// groupForDisplay collects findings that say exactly the same thing about
// different resources, keeping the order Run put them in.
//
// The key is the wording rather than the cause: two findings that share an
// image but differ in what they say about it are two problems, and merging them
// would lose the half the reader needs.
func groupForDisplay(findings []scan.Finding) []displayGroup {
	var order []string
	groups := map[string]*displayGroup{}

	for _, f := range findings {
		key := f.ID + "|" + string(f.Risk) + "|" + f.Detail
		g, ok := groups[key]
		if !ok {
			g = &displayGroup{first: f}
			groups[key] = g
			order = append(order, key)
		}
		g.resources = append(g.resources, f.Resource)
	}

	out := make([]displayGroup, 0, len(order))
	for _, key := range order {
		out = append(out, *groups[key])
	}
	return out
}

// kindOf names what a group of resources are, taken from the references
// themselves so the count reads correctly: SC-01 reports namespaces and SC-06
// reports bindings, and calling either of those "workloads" is the kind of
// small wrongness that makes a reader stop trusting the rest.
func kindOf(resources []string) string {
	kind := ""
	for _, r := range resources {
		parts := strings.Split(r, "/")
		if len(parts) < 2 {
			return "resource"
		}
		// shop/deployment/web, namespace/shop, clusterrolebinding/ci: the kind
		// is always the segment before the name.
		this := parts[len(parts)-2]
		if kind == "" {
			kind = this
		}
		if this != kind {
			// A mixed group, such as a Deployment and a DaemonSet with the
			// same problem. Naming one of them would be wrong.
			return "resource"
		}
	}
	if kind == "" {
		return "resource"
	}
	return kind
}

// plural keeps a count readable: "1 workloads" reads as a bug in the tool.
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// printNotes prints what the reader has to weigh that is not a finding: a
// control stathe can see but cannot interpret, for instance. It never changes a
// risk level, and it is printed next to the findings rather than instead of
// them.
func printNotes(w io.Writer, notes []string) {
	if len(notes) == 0 {
		return
	}
	fmt.Fprintf(w, "\nNOTED (%d, neither findings nor exclusions)\n", len(notes))
	for _, n := range notes {
		fmt.Fprintf(w, "  %s\n", n)
	}
}

// printSummary collapses the findings to one line per check, keeping the
// catalogue order rather than re-sorting, so two runs are comparable at a
// glance. The count is what a reader needs first: how many of this, not which
// ones, which is the next question and a different view.
//
// Under each line it names what the findings have in common. Eighteen SC-07
// findings that all come from three images are three decisions, not eighteen,
// and a summary that stops at the number leaves the reader to work that out
// from a list it just refused to print.
func printSummary(findings []scan.Finding) {
	type row struct {
		id    string
		risk  scan.Risk
		count int

		// A check is grouped by what its findings share only when every one of
		// them shares something: SC-07 findings all name an image, while SC-05
		// findings name a host path only when that is what is wrong. Falling
		// back per finding rather than per check mixes the two.
		allHaveCause  bool
		byCause       map[string]int
		causeOrder    []string
		byResource    map[string]int
		resourceOrder []string
	}
	var order []string
	seen := map[string]*row{}

	for _, f := range findings {
		r, ok := seen[f.ID]
		if !ok {
			r = &row{
				id: f.ID, risk: f.Risk, allHaveCause: true,
				byCause:    map[string]int{},
				byResource: map[string]int{},
			}
			seen[f.ID] = r
			order = append(order, f.ID)
		}
		if rankOf(f.Risk) < rankOf(r.risk) {
			r.risk = f.Risk
		}
		r.count++

		// Both groupings are collected, and one is chosen per check below.
		// Mixing them in a single list put a bare "/" from a host mount next
		// to a workload reference, which reads as a glitch and is one.
		if f.Cause == "" {
			r.allHaveCause = false
		}
		if _, seen := r.byCause[f.Cause]; !seen {
			r.causeOrder = append(r.causeOrder, f.Cause)
		}
		r.byCause[f.Cause]++

		if _, seen := r.byResource[f.Resource]; !seen {
			r.resourceOrder = append(r.resourceOrder, f.Resource)
		}
		r.byResource[f.Resource]++
	}

	for _, id := range order {
		r := seen[id]
		c := scan.Catalogue[id]
		fmt.Printf("%-7s %-8s %2d  %s\n", r.id, r.risk, r.count, c.Title)

		groups, order := r.byResource, r.resourceOrder
		if r.allHaveCause {
			groups, order = r.byCause, r.causeOrder
		}

		// Only worth printing when grouping actually reduces the problem, and
		// only the few that carry most of it. The full list is one command away.
		if len(order) < r.count {
			sort.SliceStable(order, func(i, j int) bool {
				return groups[order[i]] > groups[order[j]]
			})
			shown := order
			if len(shown) > 3 {
				shown = shown[:3]
			}
			for _, g := range shown {
				fmt.Printf("%-17s%2d× %s\n", "", groups[g], g)
			}
			if rest := len(order) - len(shown); rest > 0 {
				fmt.Printf("%-17s    and %d more\n", "", rest)
			}
		}
	}
}

// printNextSteps closes the summary with the two commands that follow it. A
// view that deliberately withholds the detail has to say where the detail is,
// or it reads as the whole answer.
func printNextSteps(w io.Writer, source string, hasManifests bool) {
	target := "--context " + source
	if hasManifests {
		target = "--manifests " + source
	}

	// The description goes above the command rather than after it: a context
	// name or a directory path is as long as it happens to be, and a trailing
	// comment that lines up on this cluster will not line up on the next one.
	fmt.Fprintln(w, "\nNEXT")
	for _, step := range [][2]string{
		{"every finding, one per line", "stathe check " + target},
		{"the document to keep and compare against the next assessment", "stathe check " + target + " --json > findings.json"},
		{"the client-ready report", "stathe report --findings findings.json --client NAME --out report.html"},
		{"the fix as files, applying nothing", "stathe baseline " + target + " --out ./fix"},
	} {
		fmt.Fprintf(w, "\n  %s\n    %s\n", step[0], step[1])
	}
}

// failThreshold maps --fail-on onto the risk ranking. -1 means never fail,
// which stays the default: a tool that starts breaking builds the day someone
// upgrades it gets removed from the pipeline.
func failThreshold(s string) (int, bool) {
	switch s {
	case "none", "":
		return -1, true
	case "high":
		return 0, true
	case "medium":
		return 1, true
	case "low":
		return 2, true
	}
	return 0, false
}

func rankOf(r scan.Risk) int {
	switch r {
	case scan.High:
		return 0
	case scan.Medium:
		return 1
	default:
		return 2
	}
}

// version is set at build time with -ldflags. The report prints it, because a
// client needs to know which version produced a given set of findings before
// they can compare two assessments.
var version = "dev"

func runReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	in := fs.String("findings", "", "findings JSON from `stathe check --json` (default: stdin)")
	out := fs.String("out", "", "write the report here (default: stdout)")
	client := fs.String("client", "", "client name for the cover")
	env := fs.String("environment", "", "environment or cluster name")
	author := fs.String("author", "Jarno Kristelijn", "report author")
	email := fs.String("email", "info@testrebel.com", "contact address")
	framework := fs.String("framework", "", "add a regulatory mapping section (nis2, dora, iso27001)")
	fs.Parse(args)

	if *framework != "" && !scan.ValidFramework(*framework) {
		fmt.Fprintf(os.Stderr, "unknown framework %q; use nis2, dora or iso27001\n", *framework)
		return 2
	}

	var raw []byte
	var err error
	if *in == "" || *in == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(*in)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not read findings: %v\n", err)
		return 1
	}

	// Both schema versions are accepted: a client may be reporting on a file
	// produced before the format changed.
	doc, err := scan.ParseDocument(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse findings JSON: %v\n", err)
		fmt.Fprintln(os.Stderr, "expected the output of: stathe check --json")
		return 1
	}
	findings := doc.Findings
	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "no findings to report")
		return 1
	}

	if *client == "" {
		fmt.Fprintln(os.Stderr, "stathe report needs --client")
		return 2
	}

	meta := report.Meta{
		Client:      *client,
		Environment: *env,
		Author:      *author,
		Email:       *email,
		KitVersion:  version,
		Provenance:  provenanceOf(doc),
	}

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not create %s: %v\n", *out, err)
			return 1
		}
		defer f.Close()
		w = f
	}

	if err := report.Write(w, findings, meta, scan.Framework(*framework)); err != nil {
		fmt.Fprintf(os.Stderr, "could not write the report: %v\n", err)
		return 1
	}

	if *out != "" {
		fmt.Fprintf(os.Stderr, "wrote %s (%d findings)\n", *out, len(findings))
	}
	return 0
}

// provenanceOf is the sentence on the report cover that ties the document to
// the run it came from. A findings file in the old format cannot supply it, and
// says so: a reader must not take the report date for the assessment date.
func provenanceOf(doc scan.Document) string {
	if doc.SchemaVersion < 2 {
		return "Rendered from a findings file in the pre-v2 format, which records neither " +
			"the time of the assessment nor what it was pointed at. The date above is the " +
			"date of this document, not of the assessment."
	}

	s := fmt.Sprintf("Rendered from a stathe document (schema %d) produced by stathe %s on %s",
		doc.SchemaVersion, nonEmpty(doc.Stathe), doc.AssessedAt.Format("2 January 2006 at 15:04 MST"))
	if doc.Source != "" {
		s += ", against " + doc.Source
	}
	s += fmt.Sprintf(". %d resources were checked", doc.ResourcesChecked)
	if n := len(doc.NotAssessed); n > 0 {
		s += fmt.Sprintf("; %d exclusions are listed in that document", n)
	}
	return s + "."
}

// runBaseline writes the fix to disk and stops there. It never applies
// anything, which is the whole point: the client's own pipeline applies it,
// after their own review.
func runBaseline(args []string) int {
	fs := flag.NewFlagSet("baseline", flag.ExitOnError)
	manifests := fs.String("manifests", "", "directory of manifests to assess")
	kubeContext := fs.String("context", "", "kubectl context to assess")
	outDir := fs.String("out", "baseline", "directory to write the baseline into")
	ingress := fs.String("ingress-namespace", "", "namespace the ingress controller runs in")
	fs.Parse(args)

	if *manifests != "" && *kubeContext != "" {
		fmt.Fprintln(os.Stderr, "use either --manifests or --context, not both")
		return 2
	}

	var (
		resources []scan.Resource
		err       error
		opt       baseline.Options
	)

	if *manifests != "" {
		resources, err = scan.LoadDir(*manifests)
	} else {
		var inv *scan.Inventory
		inv, err = scan.LoadCluster(*kubeContext)
		if inv != nil {
			resources = inv.Resources
		}
		// Against a live cluster the ingress controller can be identified
		// rather than guessed, which decides which exception to write.
		if pre, perr := scan.Preflight(*kubeContext); perr == nil {
			opt.Ingress = pre.Platform.Ingress
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not assess: %v\n", err)
		return 1
	}

	opt.IngressNamespace = *ingress

	assessed := scan.Run(resources)
	if bad := baseline.InvalidNamespaces(assessed); len(bad) > 0 {
		fmt.Fprintf(os.Stderr, "refusing to write a baseline: not valid namespace names: %q\n", bad)
		return 1
	}

	files := baseline.Generate(assessed, opt)
	if len(files) == 0 {
		fmt.Println("Nothing to generate: every namespace already has a NetworkPolicy.")
		return 0
	}

	for _, f := range files {
		path := filepath.Join(*outDir, f.Name)
		// Second line of defence behind the namespace check: never write
		// outside the output directory, whatever a file is called.
		if rel, rerr := filepath.Rel(*outDir, path); rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			fmt.Fprintf(os.Stderr, "refusing to write %s: it is outside %s\n", path, *outDir)
			return 1
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "could not create %s: %v\n", filepath.Dir(path), err)
			return 1
		}
		if err := os.WriteFile(path, []byte(f.Content), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "could not write %s: %v\n", path, err)
			return 1
		}
		fmt.Println("wrote", path)
	}

	fmt.Printf("\n%d files in %s/. Nothing was applied.\n", len(files), *outDir)
	fmt.Printf("Read %s/README.md before applying anything in enforcing/.\n", *outDir)
	return 0
}

// runDiff compares two assessments. It is the retest: the command that turns
// "we fixed it" from a claim into something a client can put in front of an
// auditor, and the reason stathe check --json carries provenance.
func runDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	failOnNew := fs.Bool("fail-on-new", false, "exit 1 when the later assessment has findings the earlier one did not")
	files := parseInterspersed(fs, args)

	if len(files) != 2 {
		fmt.Fprintln(os.Stderr, "stathe diff needs two files: stathe diff before.json after.json")
		fmt.Fprintln(os.Stderr, "both are the output of: stathe check --json")
		return 2
	}

	before, code := readDocument(files[0])
	if code != 0 {
		return code
	}
	after, code := readDocument(files[1])
	if code != 0 {
		return code
	}

	d := scan.Compare(before, after)

	fmt.Printf("Before   %s", describe(before))
	fmt.Printf("After    %s", describe(after))
	fmt.Println()

	// Said before the numbers, not after them: a reader who takes the counts at
	// face value and finds the caveat underneath has already drawn a
	// conclusion the data does not support.
	if d.VersionChanged {
		fmt.Printf("The two assessments came from different versions of stathe (%s and %s).\n",
			nonEmpty(d.BeforeVersion), nonEmpty(d.AfterVersion))
		fmt.Println("A finding that appears here can also be a check that did not exist before,")
		fmt.Println("rather than something that changed in the cluster.")
		fmt.Println()
	}
	if d.SchemaDowngrade {
		fmt.Println("One of these files predates the stathe document format, so it carries no")
		fmt.Println("record of which version produced it or what that run left out.")
		fmt.Println()
	}

	printFindingSet("FIXED", d.Resolved)
	printFindingSet("NEW", d.New)
	printFindingSet("ACCEPTED SINCE (not fixed: the risk was accepted in .stathe.yaml)", d.NewlyAccepted)
	printFindingSet("NO LONGER ACCEPTED (the acceptance was removed or expired)", d.NoLongerAccepted)

	fmt.Printf("%d fixed, %d new, %d unchanged", len(d.Resolved), len(d.New), len(d.Unchanged))
	if len(d.NewlyAccepted) > 0 {
		fmt.Printf(", %d accepted since", len(d.NewlyAccepted))
	}
	fmt.Println()

	if len(d.Resolved) == 0 && len(d.New) == 0 && len(d.NewlyAccepted) == 0 && len(d.NoLongerAccepted) == 0 {
		fmt.Println("\nNothing changed between these two assessments.")
	}

	if *failOnNew && len(d.New) > 0 {
		fmt.Printf("\nFailing: %d findings are new and --fail-on-new is set.\n", len(d.New))
		return 1
	}
	return 0
}

// parseInterspersed parses flags that appear before, between or after the
// positional arguments, and returns the positional ones.
//
// Go's flag package stops at the first non-flag argument, so
// `stathe diff before.json after.json --fail-on-new` would otherwise fail with
// a message about the file count, which is not what is wrong. Nobody should
// have to learn where a flag is allowed to sit.
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var positional []string
	for len(args) > 0 {
		fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	return positional
}

func readDocument(path string) (scan.Document, int) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not read %s: %v\n", path, err)
		return scan.Document{}, 1
	}
	doc, err := scan.ParseDocument(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse %s: %v\n", path, err)
		return scan.Document{}, 1
	}
	return doc, 0
}

// describe names what a document was produced from. A version 1 file knows
// none of this, and says so rather than printing blanks that read as facts.
func describe(d scan.Document) string {
	if d.SchemaVersion < 2 {
		return fmt.Sprintf("%d findings, from a file that records nothing about the run\n", len(d.Findings))
	}
	return fmt.Sprintf("%s  %s  stathe %s  %d resources, %d findings\n",
		d.AssessedAt.Format("2006-01-02 15:04 MST"), nonEmpty(d.Source),
		nonEmpty(d.Stathe), d.ResourcesChecked, len(d.Findings))
}

func printFindingSet(heading string, fs []scan.Finding) {
	if len(fs) == 0 {
		return
	}
	fmt.Printf("\n%s (%d)\n", heading, len(fs))
	for _, f := range fs {
		fmt.Printf("  %s\n", f)
	}
}

func nonEmpty(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// runPreflight is the day-before check. It exits non-zero on a no-go so it can
// sit in a pipeline, and prints the missing permission rather than a generic
// failure, because the person who has to fix it is usually not in the room.
func runPreflight(args []string) int {
	fs := flag.NewFlagSet("preflight", flag.ExitOnError)
	kubeContext := fs.String("context", "", "kubectl context to check")
	fs.Parse(args)

	res, err := scan.Preflight(*kubeContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no-go: %v\n", err)
		return 1
	}

	printClusterHeader(os.Stdout, res.Context, res.Server, res.Version)
	fmt.Println()

	fmt.Println("ACCESS")
	for _, a := range res.Access {
		name := a.Resource
		if a.Group != "" {
			name = a.Resource + "." + a.Group
		}
		mark := "ok  "
		switch {
		case a.Allowed:
		case a.Optional:
			// Not a no-go: the assessment runs without it, and all that is lost
			// is a note about a control that may already apply.
			mark = "absent"
		default:
			mark = "MISSING"
		}
		fmt.Printf("  %-8s list %-36s %s\n", mark, name, a.Reason)
	}

	fmt.Println("\nPLATFORM")
	for _, row := range [][2]string{
		{"Ingress", res.Platform.Ingress},
		{"CNI", res.Platform.CNI},
		{"GitOps", res.Platform.GitOps},
	} {
		value := row[1]
		if value == "" {
			// Not an error. It means the baseline variant has to be chosen by
			// asking rather than by looking, which is worth knowing a day early.
			value = "could not tell — ask during the kickoff"
		}
		fmt.Printf("  %-9s %s\n", row[0], value)
	}

	fmt.Println()
	if !res.OK {
		fmt.Println("NO-GO. stathe check cannot read everything it needs.")
		fmt.Println("Apply cluster/readonly-rbac.yaml, or have the cluster owner grant")
		fmt.Println("list on the resources marked MISSING above, then run this again.")
		return 1
	}

	fmt.Println("GO. stathe check has everything it needs.")
	fmt.Println("Nothing was changed. This command only reads.")
	return 0
}

// runCompliance prints what these checks can and cannot evidence. The second
// half is the point: it is the difference between a tool that helps with an
// audit and a tool that pretends to pass one.
func runCompliance(args []string) int {
	fs := flag.NewFlagSet("compliance", flag.ExitOnError)
	fs.Parse(args)

	cov := scan.NIS2Coverage()

	var covered, gaps []scan.Coverage
	for _, c := range cov {
		if len(c.CheckIDs) > 0 {
			covered = append(covered, c)
		} else {
			gaps = append(gaps, c)
		}
	}

	fmt.Println("NIS2 Article 21(2) — cybersecurity risk-management measures")
	fmt.Printf("stathe %s produces configuration evidence for %d of the %d measures.\n\n",
		version, len(covered), len(cov))

	fmt.Println("EVIDENCED BY A STATHE CHECK")
	for _, c := range covered {
		fmt.Printf("  %-16s %s\n", c.Control.Ref, c.Control.Name)
		fmt.Printf("  %-16s checks: %s\n\n", "", strings.Join(c.CheckIDs, ", "))
	}

	fmt.Println("NOT EVIDENCED — these need something stathe cannot read")
	for _, c := range gaps {
		fmt.Printf("  %-16s %s\n", c.Control.Ref, c.Control.Name)
	}

	fmt.Println()
	fmt.Println("stathe reads the technical configuration of one cluster. The measures")
	fmt.Println("above with no checks are organisational: procedures, contracts, training")
	fmt.Println("and records. No scanner can evidence those, and a report that implies")
	fmt.Println("otherwise is worse than no report.")
	fmt.Println()
	fmt.Println("This is not an attestation of compliance and stathe does not issue one.")

	return 0
}
