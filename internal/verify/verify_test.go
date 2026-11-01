package verify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0xM44k/tracecheck/internal/canary"
	"github.com/0xM44k/tracecheck/internal/hostcfg"
	"github.com/0xM44k/tracecheck/internal/match"
	"github.com/0xM44k/tracecheck/internal/sink"
)

// fakeSink is a scriptable sink.Sink for tests.
type fakeSink struct {
	name      string
	available bool
	why       string
	hit       *sink.Hit
	queryErr  error
	queries   int
}

func (f *fakeSink) Name() string              { return f.name }
func (f *fakeSink) Available() (bool, string) { return f.available, f.why }
func (f *fakeSink) Query(_ context.Context, _ match.Spec) (*sink.Hit, error) {
	f.queries++
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return f.hit, nil
}

func testCanary(id string, run func(ctx context.Context, e *canary.Env, nonce string) (match.Spec, func() error, error)) canary.Canary {
	return canary.Canary{
		ID: id, Name: "test " + id, Technique: "T0000", Tactic: "Test", Level: canary.Safe,
		Predict: func(*hostcfg.Config) (hostcfg.Prediction, string) { return hostcfg.PredUnknown, "" },
		Run:     run,
	}
}

func TestNonce_UniqueAndFormatted(t *testing.T) {
	a, b := Nonce(), Nonce()
	if a == b {
		t.Error("expected unique nonces")
	}
	if len(a) != 12 || a[:2] != "tc" {
		t.Errorf("nonce format = %q", a)
	}
}

func TestSelect_FiltersByLevel(t *testing.T) {
	o := Options{Level: canary.Safe}
	for _, c := range Select("linux", o) {
		if c.Level != canary.Safe {
			t.Errorf("canary %s has level %v, expected only Safe to be selected", c.ID, c.Level)
		}
	}
}

func TestSelect_OnlyFilter(t *testing.T) {
	o := Options{Level: canary.Full, Only: []string{"lin-exec-shell"}}
	got := Select("linux", o)
	if len(got) != 1 || got[0].ID != "lin-exec-shell" {
		t.Fatalf("got %v", got)
	}
}

func TestSelect_OnlyIsCaseAndSpaceInsensitive(t *testing.T) {
	o := Options{Level: canary.Full, Only: []string{"  LIN-EXEC-SHELL  "}}
	got := Select("linux", o)
	if len(got) != 1 || got[0].ID != "lin-exec-shell" {
		t.Fatalf("got %v", got)
	}
}

func TestAgreement(t *testing.T) {
	cases := []struct {
		p    hostcfg.Prediction
		s    Status
		want Agreement
	}{
		{hostcfg.PredSeen, Covered, Agree},
		{hostcfg.PredBlind, Blind, Agree},
		{hostcfg.PredSeen, Blind, Disagree},
		{hostcfg.PredBlind, Covered, Disagree},
		{hostcfg.PredUnknown, Covered, Open},
		{hostcfg.PredSeen, Unverifiable, Open},
	}
	for _, c := range cases {
		if got := agreement(c.p, c.s); got != c.want {
			t.Errorf("agreement(%v,%v) = %v, want %v", c.p, c.s, got, c.want)
		}
	}
}

func runSingle(t *testing.T, c canary.Canary, sinks []sink.Sink, o Options) Result {
	t.Helper()
	cfg := &hostcfg.Config{}
	env := &canary.Env{}
	if o.Timeout == 0 {
		o.Timeout = 200 * time.Millisecond
	}
	if o.Interval == 0 {
		o.Interval = 10 * time.Millisecond
	}
	// runOne is exercised directly: canary.All() has no slot for an ad-hoc
	// test canary, and that's exactly the unit under test here.
	return runOne(context.Background(), c, cfg, sinks, env, o)
}

func TestRunOne_CoveredWhenSinkHits(t *testing.T) {
	ranCleanup := false
	c := testCanary("ok", func(ctx context.Context, e *canary.Env, nonce string) (match.Spec, func() error, error) {
		return match.Spec{Needles: []string{nonce}}, func() error { ranCleanup = true; return nil }, nil
	})
	s := &fakeSink{name: "fake", available: true, hit: &sink.Hit{Sink: "fake", Evidence: "matched"}}
	r := runSingle(t, c, []sink.Sink{s}, Options{})
	if r.Status != Covered {
		t.Fatalf("status = %v, want Covered", r.Status)
	}
	if len(r.Hits) != 1 || r.Hits[0].Evidence != "matched" {
		t.Errorf("hits = %+v", r.Hits)
	}
	if !ranCleanup {
		t.Error("expected cleanup to run")
	}
	if r.Nonce == "" {
		t.Error("expected a nonce to be recorded")
	}
}

func TestRunOne_BlindWhenNoSinkHits(t *testing.T) {
	c := testCanary("blind", func(ctx context.Context, e *canary.Env, nonce string) (match.Spec, func() error, error) {
		return match.Spec{Needles: []string{nonce}}, nil, nil
	})
	s := &fakeSink{name: "fake", available: true, hit: nil}
	r := runSingle(t, c, []sink.Sink{s}, Options{})
	if r.Status != Blind {
		t.Fatalf("status = %v, want Blind", r.Status)
	}
}

func TestRunOne_UnverifiableWhenNoUsableSink(t *testing.T) {
	c := testCanary("unver", func(ctx context.Context, e *canary.Env, nonce string) (match.Spec, func() error, error) {
		return match.Spec{Needles: []string{nonce}}, nil, nil
	})
	s := &fakeSink{name: "fake", available: false, why: "not installed"}
	r := runSingle(t, c, []sink.Sink{s}, Options{})
	if r.Status != Unverifiable {
		t.Fatalf("status = %v, want Unverifiable", r.Status)
	}
	if r.SinksUnavailable["fake"] != "not installed" {
		t.Errorf("SinksUnavailable = %v", r.SinksUnavailable)
	}
}

func TestRunOne_UnverifiableWhenAllQueriesError(t *testing.T) {
	c := testCanary("qerr", func(ctx context.Context, e *canary.Env, nonce string) (match.Spec, func() error, error) {
		return match.Spec{Needles: []string{nonce}}, nil, nil
	})
	s := &fakeSink{name: "fake", available: true, queryErr: errors.New("permission denied")}
	r := runSingle(t, c, []sink.Sink{s}, Options{Timeout: 30 * time.Millisecond, Interval: 10 * time.Millisecond})
	if r.Status != Unverifiable {
		t.Fatalf("status = %v, want Unverifiable", r.Status)
	}
}

func TestRunOne_SkippedWhenCanaryReturnsErrSkip(t *testing.T) {
	c := testCanary("skip", func(ctx context.Context, e *canary.Env, nonce string) (match.Spec, func() error, error) {
		return match.Spec{}, nil, canary.ErrSkip{Reason: "needs root"}
	})
	r := runSingle(t, c, nil, Options{})
	if r.Status != Skipped || r.Detail != "needs root" {
		t.Fatalf("r = %+v", r)
	}
}

func TestRunOne_ErroredWhenCanaryFailsWithoutSpec(t *testing.T) {
	c := testCanary("err", func(ctx context.Context, e *canary.Env, nonce string) (match.Spec, func() error, error) {
		return match.Spec{}, nil, errors.New("boom")
	})
	r := runSingle(t, c, nil, Options{})
	if r.Status != Errored {
		t.Fatalf("status = %v, want Errored", r.Status)
	}
}

func TestRunOne_CleanupErrorRecorded(t *testing.T) {
	c := testCanary("cleanuperr", func(ctx context.Context, e *canary.Env, nonce string) (match.Spec, func() error, error) {
		return match.Spec{Needles: []string{nonce}}, func() error { return errors.New("rm failed") }, nil
	})
	s := &fakeSink{name: "fake", available: true, hit: &sink.Hit{Sink: "fake", Evidence: "x"}}
	r := runSingle(t, c, []sink.Sink{s}, Options{})
	if r.CleanupError != "rm failed" {
		t.Errorf("CleanupError = %q", r.CleanupError)
	}
}

func TestRunOne_AgreementRecorded(t *testing.T) {
	c := canary.Canary{
		ID: "agree-test", Level: canary.Safe,
		Predict: func(*hostcfg.Config) (hostcfg.Prediction, string) { return hostcfg.PredSeen, "rule loaded" },
		Run: func(ctx context.Context, e *canary.Env, nonce string) (match.Spec, func() error, error) {
			return match.Spec{Needles: []string{nonce}}, nil, nil
		},
	}
	s := &fakeSink{name: "fake", available: true, hit: &sink.Hit{Sink: "fake", Evidence: "x"}}
	r := runSingle(t, c, []sink.Sink{s}, Options{})
	if r.Agreement != Agree {
		t.Errorf("Agreement = %v, want Agree (predicted seen, got covered)", r.Agreement)
	}
}

func TestApplicable_FiltersBySinkName(t *testing.T) {
	c := canary.Canary{ID: "x", Sinks: []string{"auditd"}}
	all := []sink.Sink{
		&fakeSink{name: "auditd"},
		&fakeSink{name: "journald"},
	}
	got := applicable(c, all)
	if len(got) != 1 || got[0].Name() != "auditd" {
		t.Fatalf("got %v", got)
	}
}

func TestApplicable_EmptySinksMeansAll(t *testing.T) {
	c := canary.Canary{ID: "x"}
	all := []sink.Sink{&fakeSink{name: "auditd"}, &fakeSink{name: "journald"}}
	got := applicable(c, all)
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestSummarize(t *testing.T) {
	rs := []Result{
		{Status: Covered, Agreement: Agree},
		{Status: Blind, Agreement: Disagree},
		{Status: Unverifiable, Agreement: Open},
		{Status: Skipped},
		{Status: Errored},
	}
	s := Summarize(rs)
	if s.Total != 5 || s.Covered != 1 || s.Blind != 1 || s.Unverifiable != 1 || s.Skipped != 1 || s.Errored != 1 || s.Disagree != 1 {
		t.Errorf("summary = %+v", s)
	}
}
