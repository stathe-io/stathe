package baseline

import (
	"strings"
	"testing"

	"github.com/stathe-io/stathe/internal/scan"
)

// TestHostileNamespaceNeverBecomesAPath pins the reason ValidNamespace exists.
// With --manifests the namespace is whatever the file says, and it is used in a
// file name. Before the check, "../../../tmp/x" produced a path outside the
// output directory, and a name with a newline added lines to the YAML.
func TestHostileNamespaceNeverBecomesAPath(t *testing.T) {
	hostile := []string{
		"../../../tmp/x",
		"payments/../../x",
		"a\nkind: ClusterRoleBinding",
		"UPPERCASE",
		"",
		strings.Repeat("a", 64),
	}

	for _, ns := range hostile {
		if ValidNamespace(ns) {
			t.Errorf("ValidNamespace(%q) = true, want false", ns)
		}

		files := Generate([]scan.Finding{sc01(ns)}, Options{})
		if len(files) != 0 {
			t.Errorf("Generate wrote %d files for namespace %q, want none", len(files), ns)
		}
		for _, f := range files {
			if strings.Contains(f.Name, "..") {
				t.Errorf("file name %q escapes the output directory", f.Name)
			}
		}

		if bad := InvalidNamespaces([]scan.Finding{sc01(ns)}); len(bad) != 1 {
			t.Errorf("InvalidNamespaces did not report %q", ns)
		}
	}
}

func TestValidNamespacesStillWork(t *testing.T) {
	for _, ns := range []string{"payments", "northwind-web", "a", "team-1", strings.Repeat("a", 63)} {
		if !ValidNamespace(ns) {
			t.Errorf("ValidNamespace(%q) = false, want true", ns)
		}
	}
}
