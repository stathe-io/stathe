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
  stathe check --manifests <dir>   Assess manifests on disk, no cluster needed
  stathe version

Flags:
  --json    Emit findings as JSON instead of a table
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
	asJSON := fs.Bool("json", false, "emit findings as JSON")
	fs.Parse(args)

	if *manifests == "" {
		fmt.Fprintln(os.Stderr, "stathe check needs --manifests <dir>")
		fmt.Fprintln(os.Stderr, "(assessing a live cluster is not implemented yet)")
		return 2
	}

	resources, err := scan.LoadDir(*manifests)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not read manifests: %v\n", err)
		return 1
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

	fmt.Printf("Assessed %d resources in %s\n\n", len(resources), *manifests)
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
