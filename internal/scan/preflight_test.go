package scan

import (
	"strings"
	"testing"
)

// "could not tell" reads as "this cluster has no network policy enforcement",
// and the difference decides which baseline variant gets prepared the night
// before. The version string is enough to narrow it down on the distributions
// that put their name in it.
func TestCNIInferredFromTheServerVersion(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"v1.31.4+rke2r1", "Canal"},
		{"v1.30.6+k3s1", "Flannel"},
		{"v1.30.5-gke.1443001", "GKE"},
		{"v1.30.4-eks-a737599", "VPC CNI"},
		{"v1.31.2", ""},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := cniFromDistribution(tt.version)
			if tt.want == "" {
				if got != "" {
					t.Errorf("a plain version implies nothing; got %q", got)
				}
				return
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("expected %q to be mentioned for %s, got %q", tt.want, tt.version, got)
			}

			// A guess has to read as a guess. Preparing the wrong baseline
			// because stathe sounded certain is worse than being told to ask.
			for _, hedge := range []string{"probably", "Confirm"} {
				if !strings.Contains(got, hedge) {
					t.Errorf("an inference has to say so; %q is missing from %q", hedge, got)
				}
			}
		})
	}
}
