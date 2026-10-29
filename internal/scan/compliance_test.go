package scan

import "testing"

// The mapping is data, and data rots quietly. A typo in an article reference
// is invisible in review and survives until a client's compliance officer
// looks it up and finds nothing there. These tests are the guard.

// TestEveryFindingIsMapped fails when a check is added to the catalogue
// without deciding what it is evidence about. That decision is the product, so
// forgetting it should break the build rather than ship an empty column.
func TestEveryFindingIsMapped(t *testing.T) {
	for id := range Catalogue {
		if len(controls[id]) == 0 {
			t.Errorf("%s is in the catalogue but maps to no obligation", id)
		}
	}
}

// TestNoMappingForUnknownFinding catches the reverse: a mapping left behind
// after a check was renamed or removed.
func TestNoMappingForUnknownFinding(t *testing.T) {
	for id := range controls {
		if _, ok := Catalogue[id]; !ok {
			t.Errorf("%s has a mapping but is not in the catalogue", id)
		}
	}
}

// TestNIS2RefsAreReal is the one that matters. Every NIS2 reference used in a
// mapping has to be one of the ten measures in Article 21(2). Without this,
// "Art. 21(2)(k)" -- which does not exist -- would print happily in a client
// report.
func TestNIS2RefsAreReal(t *testing.T) {
	valid := map[string]string{}
	for _, m := range nis2Measures {
		valid[m.Ref] = m.Name
	}

	for id, cs := range controls {
		for _, c := range cs {
			if c.Framework != NIS2 {
				continue
			}
			name, ok := valid[c.Ref]
			if !ok {
				t.Errorf("%s cites %q, which is not a measure in Article 21(2)", id, c.Ref)
				continue
			}
			// init canonicalises these from the measure list, so a mismatch
			// here means that normalisation stopped working rather than that
			// someone mistyped a title.
			if name != c.Name {
				t.Errorf("%s cites %s as %q, but the measure list calls it %q; "+
					"the init canonicalisation is not running",
					id, c.Ref, c.Name, name)
			}
		}
	}
}

// TestNIS2CoverageIsHonest pins the claim stathe makes out loud. If someone
// adds a mapping that quietly moves a measure from "not covered" to "covered",
// this test fails and forces them to confirm that the checks really do
// evidence it.
func TestNIS2CoverageIsHonest(t *testing.T) {
	cov := NIS2Coverage()
	if len(cov) != 10 {
		t.Fatalf("Article 21(2) has ten measures, coverage reported %d", len(cov))
	}

	gaps := map[string]bool{}
	for _, c := range cov {
		if len(c.CheckIDs) == 0 {
			gaps[c.Control.Ref] = true
		}
	}

	// These four are organisational. No cluster scanner can evidence them, and
	// if a future change claims otherwise it is wrong.
	for _, ref := range []string{
		"Art. 21(2)(b)", // incident handling
		"Art. 21(2)(f)", // assessing effectiveness
		"Art. 21(2)(g)", // hygiene and training
		"Art. 21(2)(j)", // MFA and secured communications
	} {
		if !gaps[ref] {
			t.Errorf("%s is now reported as evidenced by a check; "+
				"stathe reads cluster configuration and cannot evidence it", ref)
		}
	}
}

// TestControlsForFiltersByFramework guards the filter itself, since a broken
// filter would put ISO control numbers in a NIS2 report.
func TestControlsForFiltersByFramework(t *testing.T) {
	all := ControlsFor("SC-06", "")
	if len(all) == 0 {
		t.Fatal("SC-06 should map to something")
	}

	nis2 := ControlsFor("SC-06", NIS2)
	if len(nis2) == 0 {
		t.Fatal("SC-06 should map to a NIS2 measure")
	}
	for _, c := range nis2 {
		if c.Framework != NIS2 {
			t.Errorf("asked for NIS2, got a %s control: %s", c.Framework, c.Ref)
		}
	}
	if len(nis2) >= len(all) {
		t.Error("the NIS2 filter returned everything, so it is not filtering")
	}

	if got := ControlsFor("SC-99", NIS2); got != nil {
		t.Errorf("an unknown finding should map to nothing, got %v", got)
	}
}
