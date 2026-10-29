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
	"strings"
	"time"

	"github.com/TestRebel/stathe/internal/baseline"
	"github.com/TestRebel/stathe/internal/report"
	"github.com/TestRebel/stathe/internal/scan"
)

const usage = `stathe — Kubernetes security assessment

Usage:
  stathe check --manifests DIR    Assess manifests on disk, no cluster needed
  stathe check --context NAME     Assess a live cluster (read-only)
  stathe check                    Assess the current kubectl context
  stathe report --client NAME     Turn findings into a client-ready document
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
	failOn := fs.String("fail-on", "none", "exit 1 when a finding at this severity or above remains (high, medium, low, none)")
	exceptionsDir := fs.String("exceptions", "", "directory holding .stathe.yaml (default: the manifests dir, or the working directory)")
	fs.Parse(args)

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
		resources []scan.Resource
		source    string
		err       error
	)

	if *manifests != "" {
		source = *manifests
		resources, err = scan.LoadDir(*manifests)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not read manifests: %v\n", err)
			return 1
		}
	} else {
		source = *kubeContext
		if source == "" {
			source = "the current context"
		}
		if !*asJSON {
			fmt.Printf("Reading %s...\n", source)
		}
		resources, err = scan.LoadCluster(*kubeContext)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not read the cluster: %v\n", err)
			return 1
		}
	}

	findings := scan.Run(resources)

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
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			fmt.Fprintf(os.Stderr, "could not write JSON: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Printf("Assessed %d resources in %s\n\n", len(resources), source)
	if len(findings) == 0 {
		fmt.Println("No findings. That is unusual; check that the path is right.")
		return 0
	}

	for _, f := range findings {
		fmt.Println(f)
		// With a framework selected, the obligation goes on its own indented
		// line. Putting it in the table would push the detail text off a
		// terminal, and the detail is the part an engineer acts on.
		if *framework != "" {
			for _, c := range scan.ControlsFor(f.ID, scan.Framework(*framework)) {
				fmt.Printf("%-16s%s  %s\n", "", c.Ref, c.Name)
			}
		}
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

	var findings []scan.Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		fmt.Fprintf(os.Stderr, "could not parse findings JSON: %v\n", err)
		fmt.Fprintln(os.Stderr, "expected the output of: stathe check --json")
		return 1
	}
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
		resources, err = scan.LoadCluster(*kubeContext)
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

	files := baseline.Generate(scan.Run(resources), opt)
	if len(files) == 0 {
		fmt.Println("Nothing to generate: every namespace already has a NetworkPolicy.")
		return 0
	}

	for _, f := range files {
		path := filepath.Join(*outDir, f.Name)
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

	fmt.Printf("Context   %s\n", res.Context)
	fmt.Printf("Server    %s\n", res.Server)
	fmt.Printf("Version   %s\n\n", res.Version)

	fmt.Println("ACCESS")
	for _, a := range res.Access {
		name := a.Resource
		if a.Group != "" {
			name = a.Resource + "." + a.Group
		}
		mark := "ok  "
		if !a.Allowed {
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
