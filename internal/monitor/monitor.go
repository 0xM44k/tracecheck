// Package monitor compares successive verification runs so a host that quietly
// stops logging something (auditd stopped, a rule removed, a policy reset by
// group policy) raises an alert instead of staying silent.
package monitor

import (
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/0xM44k/tracecheck/internal/verify"
)

// Entry is the last known status of one check.
type Entry struct {
	Status verify.Status `json:"status"`
	Since  time.Time     `json:"since"`
}

// State is persisted between runs.
type State struct {
	Version int              `json:"version"`
	Updated time.Time        `json:"updated"`
	Checks  map[string]Entry `json:"checks"`
}

// Alert describes a change.
type Alert struct {
	Time   time.Time     `json:"time"`
	Kind   string        `json:"kind"` // regression, recovery
	ID     string        `json:"id"`
	Name   string        `json:"name"`
	Tech   string        `json:"technique"`
	From   verify.Status `json:"from"`
	To     verify.Status `json:"to"`
	Detail string        `json:"detail,omitempty"`
}

// Load reads state; a missing file is an empty state.
func Load(path string) (State, error) {
	s := State{Version: 1, Checks: map[string]Entry{}}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return State{Version: 1, Checks: map[string]Entry{}}, err
	}
	if s.Checks == nil {
		s.Checks = map[string]Entry{}
	}
	return s, nil
}

// Save writes state atomically.
func Save(path string, s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Compare returns the alerts for a new set of results and the next state.
// Skipped and errored checks neither alert nor overwrite the known status:
// a check that could not run says nothing about the host.
func Compare(prev State, results []verify.Result, now time.Time) ([]Alert, State) {
	next := State{Version: 1, Updated: now, Checks: map[string]Entry{}}
	for k, v := range prev.Checks {
		next.Checks[k] = v
	}
	var alerts []Alert
	for _, r := range results {
		if r.Status == verify.Skipped || r.Status == verify.Errored {
			continue
		}
		old, had := prev.Checks[r.ID]
		cur := Entry{Status: r.Status, Since: now}
		if had && old.Status == r.Status {
			cur.Since = old.Since
		}
		next.Checks[r.ID] = cur
		if !had || old.Status == r.Status {
			continue
		}
		a := Alert{Time: now.UTC(), ID: r.ID, Name: r.Name, Tech: r.Technique, From: old.Status, To: r.Status, Detail: r.Detail}
		switch {
		case old.Status == verify.Covered && r.Status != verify.Covered:
			a.Kind = "regression"
		case r.Status == verify.Covered:
			a.Kind = "recovery"
		default:
			continue
		}
		alerts = append(alerts, a)
	}
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].ID < alerts[j].ID })
	return alerts, next
}
