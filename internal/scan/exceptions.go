package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Accepted risk.
//
// Every scanner that lives in a pipeline needs a way to say "we know, and we
// have decided to live with it". Without one, the first false positive blocks
// a build permanently and the team's real fix is to delete the pipeline step.
//
// Three decisions here are deliberate, and they are the difference between a
// suppression list and an accepted-risk register.
//
// A reason is required. An exception without one is refused rather than
// honoured, because an undocumented suppression is how a risk stops existing
// on paper while still existing in the cluster.
//
// An expiry is required. Accepted risk is a decision taken in a context, and
// contexts change. When the date passes the finding comes back, loudly, with
// the reason it was accepted and the date it lapsed.
//
// Suppressed findings are counted and reported, never silently dropped. A run
// that says "19 findings, 2 accepted" is honest. A run that says "17 findings"
// is a lie by omission, and it is the one an auditor catches.

// Exception is one accepted risk, read from .stathe.yaml.
type Exception struct {
	ID       string `yaml:"id"`
	Resource string `yaml:"resource"`
	Reason   string `yaml:"reason"`
	Expires  string `yaml:"expires"`

	expiry time.Time
}

// ExceptionFile is the on-disk shape.
type ExceptionFile struct {
	Exceptions []Exception `yaml:"exceptions"`
}

// ExceptionsFileName is looked for next to the manifests, or in the working
// directory when assessing a live cluster.
const ExceptionsFileName = ".stathe.yaml"

// LoadExceptions reads the accepted-risk register. A missing file is not an
// error: most clusters have no accepted risks, and demanding an empty file
// would be noise.
//
// A malformed or incomplete entry is an error. Failing loudly here is the
// point: a typo in an exception silently un-suppresses nothing and hides a
// finding, which is the worst outcome available.
func LoadExceptions(dir string) ([]Exception, error) {
	path := filepath.Join(dir, ExceptionsFileName)

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", path, err)
	}

	var f ExceptionFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", path, err)
	}

	for i := range f.Exceptions {
		e := &f.Exceptions[i]
		where := fmt.Sprintf("%s entry %d", path, i+1)

		if e.ID == "" {
			return nil, fmt.Errorf("%s: needs an id, for example NW-09", where)
		}
		if e.Resource == "" {
			return nil, fmt.Errorf("%s (%s): needs a resource, or \"*\" for every resource", where, e.ID)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return nil, fmt.Errorf(
				"%s (%s): needs a reason.\n"+
					"An accepted risk without a recorded reason is not an accepted risk,\n"+
					"it is a hidden one. Write the sentence you would say to an auditor.",
				where, e.ID)
		}
		if e.Expires == "" {
			return nil, fmt.Errorf(
				"%s (%s): needs an expires date, for example 2027-03-01.\n"+
					"Accepted risk is a decision taken in a context, and contexts change.\n"+
					"Pick a date by which someone will look at this again.",
				where, e.ID)
		}

		t, err := time.Parse("2006-01-02", e.Expires)
		if err != nil {
			return nil, fmt.Errorf("%s (%s): expires must be YYYY-MM-DD, got %q", where, e.ID, e.Expires)
		}
		e.expiry = t
	}

	return f.Exceptions, nil
}

// matches reports whether this exception covers a finding. The resource may be
// "*" for every resource, or end in "*" to cover a namespace or a prefix.
func (e Exception) matches(f Finding) bool {
	if e.ID != f.ID {
		return false
	}
	switch {
	case e.Resource == "*":
		return true
	case strings.HasSuffix(e.Resource, "*"):
		return strings.HasPrefix(f.Resource, strings.TrimSuffix(e.Resource, "*"))
	default:
		return e.Resource == f.Resource
	}
}

// Expired reports whether the acceptance has lapsed as of now.
func (e Exception) Expired(now time.Time) bool {
	return now.After(e.expiry)
}

// Accepted pairs a finding with the exception that covers it, so the summary
// can show what was accepted and why rather than just a count.
type Accepted struct {
	Finding   Finding
	Exception Exception
}

// ApplyExceptions splits findings into those still reported and those accepted.
//
// An expired exception does not suppress. The finding returns to the reported
// set and the exception is returned in lapsed, so the caller can say which
// acceptance ran out and when, instead of a build simply turning red again
// with no explanation.
func ApplyExceptions(findings []Finding, exceptions []Exception, now time.Time) (
	reported []Finding, accepted []Accepted, lapsed []Exception,
) {
	lapsedSeen := map[string]bool{}

	for _, f := range findings {
		var cover *Exception
		for i := range exceptions {
			e := exceptions[i]
			if !e.matches(f) {
				continue
			}
			if e.Expired(now) {
				key := e.ID + "|" + e.Resource
				if !lapsedSeen[key] {
					lapsedSeen[key] = true
					lapsed = append(lapsed, e)
				}
				continue
			}
			cover = &exceptions[i]
			break
		}

		if cover != nil {
			accepted = append(accepted, Accepted{Finding: f, Exception: *cover})
			continue
		}
		reported = append(reported, f)
	}

	return reported, accepted, lapsed
}
