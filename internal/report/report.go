// Package report renders results as text, JSON and a single-file HTML page.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/0xM44k/tracecheck/internal/hostcfg"
	"github.com/0xM44k/tracecheck/internal/verify"
)

// Schema identifies the JSON layout.
const Schema = "tracecheck/1"

// Host describes where the run happened. Hostname is empty unless asked for.
type Host struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname,omitempty"`
	Elevated bool   `json:"elevated"`
}

// Report is the full output of a verify run.
type Report struct {
	Schema      string          `json:"schema"`
	Tool        string          `json:"tool"`
	Version     string          `json:"version"`
	GeneratedAt time.Time       `json:"generated_at"`
	Host        Host            `json:"host"`
	Level       string          `json:"level"`
	Config      *hostcfg.Config `json:"config"`
	Results     []verify.Result `json:"results"`
	Summary     verify.Summary  `json:"summary"`
}

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r *Report) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(r)
}

var label = map[verify.Status]string{
	verify.Covered: "COVERED", verify.Blind: "BLIND", verify.Unverifiable: "UNVERIFIABLE",
	verify.Skipped: "SKIPPED", verify.Errored: "ERROR",
}

// Text writes a terminal summary.
func Text(w io.Writer, r *Report) {
	fmt.Fprintf(w, "tracecheck %s on %s/%s (elevated: %v), level %s\n\n", r.Version, r.Host.OS, r.Host.Arch, r.Host.Elevated, r.Level)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tTECHNIQUE\tCHECK\tSEEN IN\tPREDICTED\tLATENCY")
	for _, x := range r.Results {
		seen := "-"
		var names []string
		for _, h := range x.Hits {
			names = append(names, h.Sink)
		}
		if len(names) > 0 {
			seen = strings.Join(names, ",")
		}
		lat := "-"
		if x.LatencyMS > 0 {
			lat = fmt.Sprintf("%.1fs", float64(x.LatencyMS)/1000)
		}
		pred := string(x.Prediction)
		if x.Agreement == verify.Disagree {
			pred += " (!)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", label[x.Status], x.Technique, x.Name, seen, pred, lat)
	}
	tw.Flush()
	s := r.Summary
	fmt.Fprintf(w, "\n%d checks: %d covered, %d blind, %d unverifiable, %d skipped, %d errors; %d prediction disagreement(s)\n",
		s.Total, s.Covered, s.Blind, s.Unverifiable, s.Skipped, s.Errored, s.Disagree)
	for _, x := range r.Results {
		switch x.Status {
		case verify.Blind:
			fmt.Fprintf(w, "\nBLIND  %s %s\n  The host did not record this. %s\n", x.Technique, x.Name, x.PredictionReason)
		case verify.Skipped, verify.Errored, verify.Unverifiable:
			fmt.Fprintf(w, "\n%s  %s %s: %s\n", label[x.Status], x.Technique, x.Name, x.Detail)
		}
		if x.CleanupError != "" {
			fmt.Fprintf(w, "\nCLEANUP FAILED for %s: %s\n  Remove it by hand: nonce %s\n", x.ID, x.CleanupError, x.Nonce)
		}
		if x.Agreement == verify.Disagree {
			fmt.Fprintf(w, "\nPREDICTION WRONG  %s: predicted %s, observed %s. The configuration model missed something.\n", x.ID, x.Prediction, x.Status)
		}
	}
	if len(r.Config.Notes) > 0 {
		fmt.Fprintln(w)
		for _, n := range r.Config.Notes {
			fmt.Fprintln(w, "note:", n)
		}
	}
	if s.Blind > 0 {
		fmt.Fprintln(w, "\nRun `tracecheck rules` for the configuration that closes these gaps.")
	}
}
