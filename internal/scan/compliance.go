package scan

import "sort"

// Regulatory mapping.
//
// This file exists so a finding is not only a technical fact but an answer to
// the question a compliance officer actually asks: which obligation does this
// touch? That turns `stathe report` from a list of problems into evidence
// someone can file.
//
// Two things are deliberately true of this mapping.
//
// First, it is conservative. Each entry cites the article or control the
// finding speaks to directly. Where a finding merely relates to an obligation,
// it is left out, because a mapping that claims everything proves nothing.
//
// Second, it is honest about its own limits, and `stathe compliance` prints
// those limits rather than hiding them. stathe reads the technical
// configuration of one cluster. Most of NIS2 Article 21(2) is organisational:
// incident handling, training, supplier contracts, crisis management. No
// scanner can produce evidence for those, and a tool that implies otherwise is
// selling a false sense of safety.
//
// stathe does not certify, attest or determine compliance. It produces
// evidence about configuration, which an auditor or a DPO weighs alongside
// everything else.

// Framework is a body of rules a client is held to.
type Framework string

const (
	NIS2     Framework = "nis2"
	DORA     Framework = "dora"
	ISO27001 Framework = "iso27001"
)

// Frameworks is the set stathe can map to, in the order the report prints them.
var Frameworks = []Framework{NIS2, DORA, ISO27001}

// FrameworkName is the full title, for the report where an abbreviation is not
// enough for a reader outside the engineering team.
var FrameworkName = map[Framework]string{
	NIS2:     "NIS2 — Directive (EU) 2022/2555",
	DORA:     "DORA — Regulation (EU) 2022/2554",
	ISO27001: "ISO/IEC 27001:2022, Annex A",
}

// Control is one obligation: where it lives and what it is called.
type Control struct {
	Framework Framework `json:"framework"`
	Ref       string    `json:"ref"`
	Name      string    `json:"name"`
}

// ValidFramework reports whether s names a framework stathe maps to.
func ValidFramework(s string) bool {
	for _, f := range Frameworks {
		if string(f) == s {
			return true
		}
	}
	return false
}

// nis2Measures is the full list of risk-management measures in NIS2
// Article 21(2). It is here in full, not just the parts stathe covers, because
// the coverage report is only useful if it shows the gaps too.
var nis2Measures = []Control{
	{NIS2, "Art. 21(2)(a)", "Policies on risk analysis and information system security"},
	{NIS2, "Art. 21(2)(b)", "Incident handling"},
	{NIS2, "Art. 21(2)(c)", "Business continuity, backup management and disaster recovery"},
	{NIS2, "Art. 21(2)(d)", "Supply chain security"},
	{NIS2, "Art. 21(2)(e)", "Security in acquisition, development and maintenance, including vulnerability handling"},
	{NIS2, "Art. 21(2)(f)", "Policies to assess the effectiveness of risk-management measures"},
	{NIS2, "Art. 21(2)(g)", "Basic cyber hygiene practices and cybersecurity training"},
	{NIS2, "Art. 21(2)(h)", "Policies on the use of cryptography and encryption"},
	{NIS2, "Art. 21(2)(i)", "Human resources security, access control policies and asset management"},
	{NIS2, "Art. 21(2)(j)", "Multi-factor authentication and secured communications"},
}

// controls maps a finding ID to the obligations it is evidence about.
var controls = map[string][]Control{
	"NW-01": {
		{NIS2, "Art. 21(2)(a)", "Policies on risk analysis and information system security"},
		{NIS2, "Art. 21(2)(i)", "Access control policies and asset management"},
		{DORA, "Art. 9", "Protection and prevention"},
		{ISO27001, "A.8.22", "Segregation of networks"},
		{ISO27001, "A.8.20", "Networks security"},
	},
	"NW-04": {
		{NIS2, "Art. 21(2)(h)", "Policies on the use of cryptography and encryption"},
		{NIS2, "Art. 21(2)(i)", "Access control policies and asset management"},
		{DORA, "Art. 9", "Protection and prevention"},
		{ISO27001, "A.5.17", "Authentication information"},
		{ISO27001, "A.8.24", "Use of cryptography"},
	},
	"NW-05": {
		{NIS2, "Art. 21(2)(e)", "Security in acquisition, development and maintenance"},
		{NIS2, "Art. 21(2)(i)", "Access control policies and asset management"},
		{DORA, "Art. 9", "Protection and prevention"},
		{ISO27001, "A.8.2", "Privileged access rights"},
		{ISO27001, "A.8.9", "Configuration management"},
	},
	"NW-06": {
		{NIS2, "Art. 21(2)(i)", "Access control policies and asset management"},
		{DORA, "Art. 9", "Protection and prevention"},
		{ISO27001, "A.5.15", "Access control"},
		{ISO27001, "A.5.18", "Access rights"},
		{ISO27001, "A.8.2", "Privileged access rights"},
	},
	"NW-07": {
		{NIS2, "Art. 21(2)(d)", "Supply chain security"},
		{NIS2, "Art. 21(2)(e)", "Security in acquisition, development and maintenance"},
		{DORA, "Art. 28", "ICT third-party risk: general principles"},
		{ISO27001, "A.5.21", "Managing information security in the ICT supply chain"},
		{ISO27001, "A.8.32", "Change management"},
	},
	"NW-09": {
		{NIS2, "Art. 21(2)(c)", "Business continuity, backup management and disaster recovery"},
		{DORA, "Art. 11", "Response and recovery"},
		{ISO27001, "A.8.6", "Capacity management"},
	},
}

// init makes the measure list the single source of truth for NIS2 wording.
//
// The mapping below is written by hand, and a hand-written title drifts from
// the regulation's own words the moment someone shortens one to fit a table.
// Rather than police that, every NIS2 entry takes its name from nis2Measures
// at startup, so the report and the coverage command cannot disagree and a
// client reads the article as it is actually written.
//
// A reference that is not in Article 21(2) at all would be silently left with
// its hand-written name here; TestNIS2RefsAreReal is what catches that.
func init() {
	canonical := map[string]string{}
	for _, m := range nis2Measures {
		canonical[m.Ref] = m.Name
	}
	for id, cs := range controls {
		for i, c := range cs {
			if c.Framework != NIS2 {
				continue
			}
			if name, ok := canonical[c.Ref]; ok {
				controls[id][i].Name = name
			}
		}
	}
}

// ControlsFor returns the obligations a finding is evidence about. Pass an
// empty framework for all of them.
func ControlsFor(id string, f Framework) []Control {
	all := controls[id]
	if f == "" {
		return all
	}
	var out []Control
	for _, c := range all {
		if c.Framework == f {
			out = append(out, c)
		}
	}
	return out
}

// Coverage is one obligation and the checks that speak to it. Findings is
// empty when stathe has nothing to say about it, which is the interesting case.
type Coverage struct {
	Control  Control
	CheckIDs []string
}

// NIS2Coverage walks Article 21(2) and reports, per measure, which checks
// produce evidence for it. Measures with no checks are returned too: the point
// of the command is to be straight about what still needs a human.
func NIS2Coverage() []Coverage {
	byRef := map[string][]string{}
	for id, cs := range controls {
		for _, c := range cs {
			if c.Framework != NIS2 {
				continue
			}
			byRef[c.Ref] = append(byRef[c.Ref], id)
		}
	}

	out := make([]Coverage, 0, len(nis2Measures))
	for _, m := range nis2Measures {
		ids := byRef[m.Ref]
		sort.Strings(ids)
		out = append(out, Coverage{Control: m, CheckIDs: ids})
	}
	return out
}
