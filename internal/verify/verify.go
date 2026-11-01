// Package verify runs canaries and checks whether the host's telemetry recorded them.
package verify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/0xM44k/tracecheck/internal/canary"
	"github.com/0xM44k/tracecheck/internal/hostcfg"
	"github.com/0xM44k/tracecheck/internal/sink"
)

// Status of one canary.
type Status string

const (
	Covered      Status = "covered"      // the host recorded it
	Blind        Status = "blind"        // the host looked and did not record it
	Unverifiable Status = "unverifiable" // no readable telemetry source to look in
	Skipped      Status = "skipped"      // could not run here (needs root, tool missing)
	Errored      Status = "error"        // the canary itself failed
)

// Agreement between the configuration-based prediction and what happened.
type Agreement string

const (
	Agree    Agreement = "agree"
	Disagree Agreement = "disagree"
	Open     Agreement = "undetermined"
)

// Result is the outcome for one canary.
type Result struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	Technique        string             `json:"technique"`
	Tactic           string             `json:"tactic"`
	Level            string             `json:"level"`
	Description      string             `json:"description"`
	Status           Status             `json:"status"`
	Prediction       hostcfg.Prediction `json:"prediction"`
	PredictionReason string             `json:"prediction_reason,omitempty"`
	Agreement        Agreement          `json:"agreement"`
	Nonce            string             `json:"nonce,omitempty"`
	Hits             []sink.Hit         `json:"hits,omitempty"`
	SinksChecked     []string           `json:"sinks_checked,omitempty"`
	SinksUnavailable map[string]string  `json:"sinks_unavailable,omitempty"`
	LatencyMS        int64              `json:"latency_ms,omitempty"`
	Detail           string             `json:"detail,omitempty"`
	CleanupError     string             `json:"cleanup_error,omitempty"`
	Fix              canary.Fix         `json:"fix"`
}

// Summary counts results by status.
type Summary struct {
	Total        int `json:"total"`
	Covered      int `json:"covered"`
	Blind        int `json:"blind"`
	Unverifiable int `json:"unverifiable"`
	Skipped      int `json:"skipped"`
	Errored      int `json:"errored"`
	Disagree     int `json:"prediction_disagreements"`
}

// Options control a run.
type Options struct {
	Level    canary.Level
	Only     []string
	Timeout  time.Duration
	Interval time.Duration
	PID      int
	TmpDir   string
}

// Nonce returns a fresh unique marker such as tc3fa91c07de.
func Nonce() string {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "tc" + hex.EncodeToString(b)
}

// Select returns the canaries to run for these options.
func Select(goos string, o Options) []canary.Canary {
	var out []canary.Canary
	for _, c := range canary.All(goos) {
		if c.Level > o.Level {
			continue
		}
		if len(o.Only) > 0 {
			keep := false
			for _, id := range o.Only {
				if strings.EqualFold(strings.TrimSpace(id), c.ID) {
					keep = true
				}
			}
			if !keep {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func agreement(p hostcfg.Prediction, s Status) Agreement {
	switch {
	case p == hostcfg.PredSeen && s == Covered, p == hostcfg.PredBlind && s == Blind:
		return Agree
	case p == hostcfg.PredSeen && s == Blind, p == hostcfg.PredBlind && s == Covered:
		return Disagree
	}
	return Open
}

func applicable(c canary.Canary, all []sink.Sink) []sink.Sink {
	if len(c.Sinks) == 0 {
		return all
	}
	var out []sink.Sink
	for _, s := range all {
		for _, n := range c.Sinks {
			if s.Name() == n {
				out = append(out, s)
			}
		}
	}
	return out
}

// Run executes the canaries and returns one result each.
func Run(ctx context.Context, goos string, cfg *hostcfg.Config, sinks []sink.Sink, env *canary.Env, o Options) ([]Result, Summary) {
	if o.Timeout == 0 {
		o.Timeout = 12 * time.Second
	}
	if o.Interval == 0 {
		o.Interval = 500 * time.Millisecond
	}
	var results []Result
	for _, c := range Select(goos, o) {
		results = append(results, runOne(ctx, c, cfg, sinks, env, o))
	}
	return results, Summarize(results)
}

// runOne has a named return (r) because the deferred cleanup below sets
// r.CleanupError after the canary's own result is otherwise final: without a
// named return, that assignment would land on a copy made at the "return r"
// statement and never reach the caller.
func runOne(ctx context.Context, c canary.Canary, cfg *hostcfg.Config, all []sink.Sink, env *canary.Env, o Options) (r Result) {
	r = Result{ID: c.ID, Name: c.Name, Technique: c.Technique, Tactic: c.Tactic, Level: c.Level.String(),
		Description: c.Description, Fix: c.Fix, Agreement: Open}
	r.Prediction, r.PredictionReason = c.Predict(cfg)

	nonce := Nonce()
	r.Nonce = nonce
	start := time.Now()
	spec, cleanup, err := c.Run(ctx, env, nonce)
	if cleanup != nil {
		defer func() {
			if cerr := cleanup(); cerr != nil {
				r.CleanupError = cerr.Error()
			}
		}()
	}
	if reason, skip := canary.IsSkip(err); skip {
		r.Status, r.Detail = Skipped, reason
		return r
	}
	if err != nil && spec.Needles == nil {
		r.Status, r.Detail = Errored, err.Error()
		return r
	}
	spec.Since = start

	sinks := applicable(c, all)
	var usable []sink.Sink
	r.SinksUnavailable = map[string]string{}
	for _, s := range sinks {
		if ok, why := s.Available(); ok {
			usable = append(usable, s)
			r.SinksChecked = append(r.SinksChecked, s.Name())
		} else {
			r.SinksUnavailable[s.Name()] = why
		}
	}
	if len(r.SinksUnavailable) == 0 {
		r.SinksUnavailable = nil
	}
	if len(usable) == 0 {
		r.Status, r.Detail = Unverifiable, "no readable telemetry source for this check"
		r.Agreement = agreement(r.Prediction, r.Status)
		return r
	}

	deadline := time.Now().Add(o.Timeout)
	queryErrs := map[string]string{}
	for {
		for _, s := range usable {
			h, qerr := s.Query(ctx, spec)
			if qerr != nil {
				queryErrs[s.Name()] = qerr.Error()
				continue
			}
			delete(queryErrs, s.Name())
			if h != nil {
				r.Hits = append(r.Hits, *h)
			}
		}
		if len(r.Hits) > 0 || time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		time.Sleep(o.Interval)
	}
	r.LatencyMS = time.Since(start).Milliseconds()
	switch {
	case len(r.Hits) > 0:
		r.Status = Covered
	case len(queryErrs) == len(usable):
		r.Status = Unverifiable
		for k, v := range queryErrs {
			r.Detail += k + ": " + v + "; "
		}
	default:
		r.Status = Blind
	}
	r.Agreement = agreement(r.Prediction, r.Status)
	return r
}

// Summarize counts results.
func Summarize(rs []Result) Summary {
	s := Summary{Total: len(rs)}
	for _, r := range rs {
		switch r.Status {
		case Covered:
			s.Covered++
		case Blind:
			s.Blind++
		case Unverifiable:
			s.Unverifiable++
		case Skipped:
			s.Skipped++
		case Errored:
			s.Errored++
		}
		if r.Agreement == Disagree {
			s.Disagree++
		}
	}
	return s
}
