package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0xM44k/tracecheck/internal/hostcfg"
	"github.com/0xM44k/tracecheck/internal/sink"
	"github.com/0xM44k/tracecheck/internal/verify"
)

func sampleReport() *Report {
	return &Report{
		Schema:      Schema,
		Tool:        "tracecheck",
		Version:     "0.1.0",
		GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Host:        Host{OS: "linux", Arch: "amd64", Elevated: true},
		Level:       "safe",
		Config:      &hostcfg.Config{OS: "linux", Notes: []string{"a note"}},
		Results: []verify.Result{
			{ID: "ok", Name: "ok check", Technique: "T1", Status: verify.Covered,
				Prediction: hostcfg.PredSeen, Agreement: verify.Agree, LatencyMS: 1500,
				Hits: []sink.Hit{{Sink: "auditd", Evidence: "x"}}},
			{ID: "bl", Name: "blind check", Technique: "T2", Status: verify.Blind,
				Prediction: hostcfg.PredSeen, Agreement: verify.Disagree, PredictionReason: "rule loaded"},
			{ID: "cl", Name: "cleanup check", Technique: "T3", Status: verify.Covered,
				Agreement: verify.Open, CleanupError: "rm failed", Nonce: "tcabc123"},
		},
		Summary: verify.Summary{Total: 3, Covered: 2, Blind: 1, Disagree: 1},
	}
}

func TestJSON_RoundTrips(t *testing.T) {
	r := sampleReport()
	var buf bytes.Buffer
	if err := JSON(&buf, r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var got Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Schema != Schema {
		t.Errorf("schema = %q", got.Schema)
	}
	if len(got.Results) != 3 {
		t.Fatalf("results = %d", len(got.Results))
	}
	if got.Summary.Covered != 2 {
		t.Errorf("summary = %+v", got.Summary)
	}
}

func TestJSON_IsIndented(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\n  \"") {
		t.Error("expected indented JSON output")
	}
}

func TestText_ContainsExpectedSections(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleReport())
	out := buf.String()

	for _, want := range []string{
		"tracecheck 0.1.0 on linux/amd64",
		"COVERED", "BLIND",
		"ok check", "blind check",
		"3 checks: 2 covered, 1 blind",
		"1 prediction disagreement(s)",
		"BLIND  T2 blind check",
		"rule loaded",
		"CLEANUP FAILED for cl: rm failed",
		"nonce tcabc123",
		"PREDICTION WRONG  bl: predicted expected-seen, observed blind",
		"note: a note",
		"tracecheck rules",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected text report to contain %q; full output:\n%s", want, out)
		}
	}
}

func TestText_LatencyFormatting(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleReport())
	if !strings.Contains(buf.String(), "1.5s") {
		t.Errorf("expected formatted latency '1.5s', got:\n%s", buf.String())
	}
}

func TestText_NoRulesHintWhenNothingBlind(t *testing.T) {
	r := sampleReport()
	r.Results = []verify.Result{{ID: "ok", Status: verify.Covered}}
	r.Summary = verify.Summary{Total: 1, Covered: 1}
	var buf bytes.Buffer
	Text(&buf, r)
	if strings.Contains(buf.String(), "tracecheck rules") {
		t.Error("did not expect the rules hint when nothing is blind")
	}
}

func TestText_NoHitsShowsDash(t *testing.T) {
	r := &Report{
		Version: "0.1.0", Host: Host{OS: "linux", Arch: "amd64"}, Level: "safe",
		Config:  &hostcfg.Config{},
		Results: []verify.Result{{ID: "x", Status: verify.Blind}},
		Summary: verify.Summary{Total: 1, Blind: 1},
	}
	var buf bytes.Buffer
	Text(&buf, r)
	lines := strings.Split(buf.String(), "\n")
	found := false
	for _, l := range lines {
		if strings.HasPrefix(l, "BLIND") && strings.Contains(l, "-") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a dash placeholder for 'seen in' when there are no hits:\n%s", buf.String())
	}
}
