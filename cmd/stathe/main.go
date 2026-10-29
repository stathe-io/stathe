// Command stathe assesses a Kubernetes platform and reports what is wrong with
// it, without changing anything.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/TestRebel/stathe/internal/scan"
)

const usage = `stathe — Kubernetes security assessment

Usage:
  stathe check --manifests DIR    Assess manifests on disk, no cluster needed
  stathe check --context NAME     Assess a live cluster (read-only)
  stathe check                    Assess the current kubectl context
  stathe version

Flags:
  --json    Emit findings as JSON instead of a table

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
	case "version":
		fmt.Println("stathe (development build)")
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
	fs.Parse(args)

	if *manifests != "" && *kubeContext != "" {
		fmt.Fprintln(os.Stderr, "use either --manifests or --context, not both")
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
	}

	counts := map[scan.Risk]int{}
	for _, f := range findings {
		counts[f.Risk]++
	}
	fmt.Printf("\n%d findings: %d high, %d medium, %d low\n",
		len(findings), counts[scan.High], counts[scan.Medium], counts[scan.Low])
	fmt.Println("\nNothing was changed. This command only reads.")

	return 0
}
