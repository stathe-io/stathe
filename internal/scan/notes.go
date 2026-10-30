package scan

import (
	"fmt"
	"sort"
	"strings"
)

// Notes are the things a reader has to weigh that are neither findings nor
// exclusions.
//
// The case that forced this: a cluster can already enforce image digests
// through an admission policy, which makes SC-07 true on paper and handled in
// practice. stathe can see that such a policy exists. It cannot read CEL, or
// Kyverno's policy language, or Rego, and decide what the policy actually
// permits -- so it says what it saw and leaves the judgement to the person who
// can check it. Lowering a risk on the strength of a control stathe does not
// understand would be the same mistake as hiding a finding.

// ImagePolicyNotes reports admission policies that mention container images.
//
// It deliberately does not claim the policy enforces anything. "A policy
// mentioning images exists, go and read it" is the whole claim, and it is one
// stathe can stand behind.
func ImagePolicyNotes(rs []Resource) []string {
	var names []string
	for _, r := range rs {
		if r.Kind != "ValidatingAdmissionPolicy" {
			continue
		}
		if !mentionsImages(r.Spec) {
			continue
		}
		names = append(names, r.Metadata.Name)
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)

	return []string{fmt.Sprintf(
		"ValidatingAdmissionPolicy %s mentions container images. stathe does not "+
			"interpret policy expressions, so it cannot tell whether digests are already "+
			"required. If they are, accept SC-07 in %s with that policy as the reason "+
			"rather than leaving the finding open. Kyverno, Gatekeeper and other "+
			"webhook-based engines are not read at all.",
		strings.Join(quoteAll(names), ", "), ExceptionsFileName)}
}

// mentionsImages walks a policy spec looking for the word image in any string.
// A policy is an arbitrarily nested object and the interesting text sits in CEL
// expressions, match conditions and messages, so searching the whole thing is
// both simpler and less likely to miss one than reaching for known fields.
func mentionsImages(v interface{}) bool {
	switch t := v.(type) {
	case string:
		return strings.Contains(strings.ToLower(t), "image")
	case map[string]interface{}:
		for _, inner := range t {
			if mentionsImages(inner) {
				return true
			}
		}
	case []interface{}:
		for _, inner := range t {
			if mentionsImages(inner) {
				return true
			}
		}
	}
	return false
}

func quoteAll(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, fmt.Sprintf("%q", s))
	}
	return out
}
