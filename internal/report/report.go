// Package report turns reviewed findings into the client-facing document.
//
// The template is a copy of the house style in sample-report.html: navy and
// teal, a dark cover, KPI tiles, and one card per finding. Keeping the wording
// in the finding catalogue and the layout here means two reports from two
// different clusters read the same way.
package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"time"

	"github.com/TestRebel/stathe/internal/scan"
)

//go:embed template.html
var files embed.FS

// Meta is everything about the engagement that cannot be read from a cluster.
type Meta struct {
	Client      string
	Environment string
	Date        string
	Author      string
	Email       string
	KitVersion  string
}

// Group collects the findings that share an ID, so the report shows one card
// per issue with its affected resources listed, rather than forty near
// identical rows.
type Group struct {
	ID        string
	Title     string
	Risk      scan.Risk
	Why       string
	Next      string
	Resources []string
}

type data struct {
	Meta   Meta
	Groups []Group
	High   int
	Medium int
	Low    int
	Total  int
}

// Write renders the report as HTML.
func Write(w io.Writer, findings []scan.Finding, meta Meta) error {
	if meta.Date == "" {
		meta.Date = time.Now().Format("2 January 2006")
	}

	d := data{Meta: meta, Total: len(findings)}

	byID := map[string]*Group{}
	var order []string

	for _, f := range findings {
		switch f.Risk {
		case scan.High:
			d.High++
		case scan.Medium:
			d.Medium++
		case scan.Low:
			d.Low++
		}

		g, ok := byID[f.ID]
		if !ok {
			g = &Group{ID: f.ID, Title: f.Title, Risk: f.Risk, Why: f.Why, Next: f.Next}
			byID[f.ID] = g
			order = append(order, f.ID)
		}
		// A group takes the highest risk any of its findings carries, so a
		// single high-risk instance is not hidden behind a medium heading.
		if rank(f.Risk) < rank(g.Risk) {
			g.Risk = f.Risk
		}
		g.Resources = append(g.Resources, fmt.Sprintf("%s — %s", f.Resource, f.Detail))
	}

	sort.SliceStable(order, func(i, j int) bool {
		a, b := byID[order[i]], byID[order[j]]
		if rank(a.Risk) != rank(b.Risk) {
			return rank(a.Risk) < rank(b.Risk)
		}
		return a.ID < b.ID
	})
	for _, id := range order {
		d.Groups = append(d.Groups, *byID[id])
	}

	tmpl, err := template.ParseFS(files, "template.html")
	if err != nil {
		return fmt.Errorf("could not parse the report template: %w", err)
	}
	return tmpl.Execute(w, d)
}

func rank(r scan.Risk) int {
	switch r {
	case scan.High:
		return 0
	case scan.Medium:
		return 1
	default:
		return 2
	}
}
