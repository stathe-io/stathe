package scan

import (
	"fmt"
	"math/rand"
	"testing"
)

// Determinism is the property every comparison rests on. A quarterly
// assessment is evidence only if the same cluster produces the same document:
// if two runs can order the same findings differently, every diff between them
// shows work that nobody did, and the reader has no way to tell those lines
// from the real changes.
//
// The order the API server happens to return objects in is not stable, so the
// sort has to be a total order -- every field a reader can see has to take part
// in it, not just risk and ID.
func TestRunOrderDoesNotDependOnInputOrder(t *testing.T) {
	var resources []Resource
	for _, ns := range []string{"shop", "orders", "tracking"} {
		for i := 0; i < 3; i++ {
			resources = append(resources, deployment(
				fmt.Sprintf("app-%d", i), ns,
				map[string]interface{}{
					"name":  fmt.Sprintf("app-%d", i),
					"image": "nginx:latest",
				}))
		}
	}

	want := fingerprint(Run(resources))

	// A fixed seed, so a failure is reproducible rather than a once-a-month
	// mystery in CI.
	rng := rand.New(rand.NewSource(1))
	for attempt := 0; attempt < 20; attempt++ {
		shuffled := make([]Resource, len(resources))
		copy(shuffled, resources)
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})

		got := fingerprint(Run(shuffled))
		if got != want {
			t.Fatalf("the same resources in a different order produced a different report (attempt %d).\n"+
				"The findings are the same; only their order moved, which is enough to make\n"+
				"stathe diff report changes nobody made.\n\nwant:\n%s\ngot:\n%s", attempt, want, got)
		}
	}
}

// fingerprint renders the findings the way a reader sees them, so the
// comparison fails on anything visible that moved.
func fingerprint(fs []Finding) string {
	var b []byte
	for _, f := range fs {
		b = append(b, fmt.Sprintf("%s|%s|%s|%s\n", f.ID, f.Risk, f.Resource, f.Detail)...)
	}
	return string(b)
}
