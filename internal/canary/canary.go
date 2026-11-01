// Package canary holds the harmless, reversible actions tracecheck performs to
// find out whether the host's own telemetry records them.
//
// Every canary carries a unique nonce (or the tracecheck process ID) so a hit
// can only come from the canary itself. None of them runs a payload, touches
// data that is not its own, or leaves anything behind: whatever a canary
// creates, it removes again.
package canary

import (
	"context"
	"errors"
	"sort"

	"github.com/0xM44k/tracecheck/internal/hostcfg"
	"github.com/0xM44k/tracecheck/internal/match"
	"github.com/0xM44k/tracecheck/internal/runner"
)

// Level says how much a canary touches.
type Level int

const (
	// Safe canaries only run harmless programs, open files, or make a loopback
	// connection. They change nothing on the host.
	Safe Level = iota
	// Full canaries create and then delete real configuration objects
	// (a cron file, an account, a scheduled task) and need --level full --yes.
	Full
)

func (l Level) String() string {
	if l == Safe {
		return "safe"
	}
	return "full"
}

// ErrSkip is returned by a canary that cannot run here, with the reason.
type ErrSkip struct{ Reason string }

func (e ErrSkip) Error() string { return e.Reason }

// IsSkip reports whether err is an ErrSkip and returns its reason.
func IsSkip(err error) (string, bool) {
	var s ErrSkip
	if errors.As(err, &s) {
		return s.Reason, true
	}
	return "", false
}

// Fix is the configuration that makes the host record the canary's action.
type Fix struct {
	Auditd  []string // /etc/audit/rules.d lines
	Windows []string // commands to run from an elevated prompt
	Note    string
}

// Env is what a canary may use.
type Env struct {
	R      runner.Runner
	PID    int
	TmpDir string
}

// Canary is one technique emulation.
type Canary struct {
	ID          string
	Name        string
	Technique   string
	Tactic      string
	Platform    string
	Level       Level
	Description string
	Sinks       []string // sink labels that can carry the evidence; empty = all
	Predict     func(*hostcfg.Config) (hostcfg.Prediction, string)
	Run         func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error)
	Fix         Fix
}

// All returns the canaries for a platform, ordered by ID.
func All(goos string) []Canary {
	var out []Canary
	switch goos {
	case "linux":
		out = linuxCanaries()
	case "windows":
		out = windowsCanaries()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func noCleanup() error { return nil }
