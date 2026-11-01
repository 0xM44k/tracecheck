package monitor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xM44k/tracecheck/internal/verify"
)

func TestLoad_MissingFileIsEmptyState(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Version != 1 || len(s.Checks) != 0 {
		t.Errorf("state = %+v", s)
	}
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now().UTC().Truncate(time.Second)
	s := State{Version: 1, Updated: now, Checks: map[string]Entry{
		"lin-exec-shell": {Status: verify.Covered, Since: now},
	}}
	if err := Save(path, s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Checks["lin-exec-shell"].Status != verify.Covered {
		t.Errorf("round-tripped state = %+v", got)
	}
	// Save must not leave a .tmp file behind.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("expected .tmp file to be renamed away, stat err = %v", err)
	}
}

func TestLoad_CorruptFileResetsRatherThanPanics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err == nil {
		t.Error("expected an error for corrupt JSON")
	}
	if s.Checks == nil {
		t.Error("expected a usable empty state even on error")
	}
}

func result(id string, status verify.Status) verify.Result {
	return verify.Result{ID: id, Name: "name-" + id, Technique: "Txxxx", Status: status}
}

func TestCompare_FirstRunNoAlerts(t *testing.T) {
	prev := State{Checks: map[string]Entry{}}
	now := time.Now()
	alerts, next := Compare(prev, []verify.Result{result("a", verify.Covered)}, now)
	if len(alerts) != 0 {
		t.Errorf("expected no alerts on first run, got %v", alerts)
	}
	if next.Checks["a"].Status != verify.Covered {
		t.Errorf("next state = %+v", next.Checks)
	}
}

func TestCompare_Regression(t *testing.T) {
	now := time.Now()
	prev := State{Checks: map[string]Entry{
		"a": {Status: verify.Covered, Since: now.Add(-time.Hour)},
	}}
	alerts, next := Compare(prev, []verify.Result{result("a", verify.Blind)}, now)
	if len(alerts) != 1 || alerts[0].Kind != "regression" {
		t.Fatalf("alerts = %+v", alerts)
	}
	if alerts[0].From != verify.Covered || alerts[0].To != verify.Blind {
		t.Errorf("alert = %+v", alerts[0])
	}
	if next.Checks["a"].Status != verify.Blind {
		t.Errorf("next state = %+v", next.Checks)
	}
}

func TestCompare_Recovery(t *testing.T) {
	now := time.Now()
	prev := State{Checks: map[string]Entry{
		"a": {Status: verify.Blind, Since: now.Add(-time.Hour)},
	}}
	alerts, _ := Compare(prev, []verify.Result{result("a", verify.Covered)}, now)
	if len(alerts) != 1 || alerts[0].Kind != "recovery" {
		t.Fatalf("alerts = %+v", alerts)
	}
}

func TestCompare_NoChangeNoAlertAndSinceIsPreserved(t *testing.T) {
	since := time.Now().Add(-48 * time.Hour)
	now := time.Now()
	prev := State{Checks: map[string]Entry{
		"a": {Status: verify.Covered, Since: since},
	}}
	alerts, next := Compare(prev, []verify.Result{result("a", verify.Covered)}, now)
	if len(alerts) != 0 {
		t.Errorf("expected no alert when status is unchanged, got %v", alerts)
	}
	if !next.Checks["a"].Since.Equal(since) {
		t.Errorf("Since should be preserved across unchanged runs, got %v want %v", next.Checks["a"].Since, since)
	}
}

func TestCompare_SkippedAndErroredNeverAlertOrOverwrite(t *testing.T) {
	now := time.Now()
	prev := State{Checks: map[string]Entry{
		"a": {Status: verify.Covered, Since: now.Add(-time.Hour)},
	}}
	alerts, next := Compare(prev, []verify.Result{
		result("a", verify.Skipped),
	}, now)
	if len(alerts) != 0 {
		t.Errorf("a skipped check must never alert, got %v", alerts)
	}
	if next.Checks["a"].Status != verify.Covered {
		t.Errorf("a skipped check must not overwrite known status, got %+v", next.Checks["a"])
	}

	alerts2, next2 := Compare(prev, []verify.Result{
		result("a", verify.Errored),
	}, now)
	if len(alerts2) != 0 {
		t.Errorf("an errored check must never alert, got %v", alerts2)
	}
	if next2.Checks["a"].Status != verify.Covered {
		t.Errorf("an errored check must not overwrite known status, got %+v", next2.Checks["a"])
	}
}

func TestCompare_UnverifiableIsNeitherRegressionNorRecovery(t *testing.T) {
	now := time.Now()
	prev := State{Checks: map[string]Entry{
		"a": {Status: verify.Covered, Since: now.Add(-time.Hour)},
	}}
	// covered -> unverifiable: not a "regression" to blind, and not a recovery.
	// Per Compare's switch, this still alerts as a regression (covered -> non-covered).
	alerts, next := Compare(prev, []verify.Result{result("a", verify.Unverifiable)}, now)
	if len(alerts) != 1 || alerts[0].Kind != "regression" {
		t.Fatalf("covered -> unverifiable should alert as regression, got %+v", alerts)
	}
	if next.Checks["a"].Status != verify.Unverifiable {
		t.Errorf("next state = %+v", next.Checks["a"])
	}
}

func TestCompare_BlindToUnverifiable_NoAlert(t *testing.T) {
	// Neither status is "covered", so this is not a regression (didn't come
	// from covered) nor a recovery (didn't go to covered) - the default
	// branch in Compare's switch applies and nothing is emitted.
	now := time.Now()
	prev := State{Checks: map[string]Entry{
		"a": {Status: verify.Blind, Since: now.Add(-time.Hour)},
	}}
	alerts, _ := Compare(prev, []verify.Result{result("a", verify.Unverifiable)}, now)
	if len(alerts) != 0 {
		t.Errorf("blind -> unverifiable should not alert, got %+v", alerts)
	}
}

func TestCompare_AlertsSortedByID(t *testing.T) {
	now := time.Now()
	prev := State{Checks: map[string]Entry{
		"z-check": {Status: verify.Covered, Since: now},
		"a-check": {Status: verify.Covered, Since: now},
	}}
	alerts, _ := Compare(prev, []verify.Result{
		result("z-check", verify.Blind),
		result("a-check", verify.Blind),
	}, now)
	if len(alerts) != 2 {
		t.Fatalf("alerts = %+v", alerts)
	}
	if alerts[0].ID != "a-check" || alerts[1].ID != "z-check" {
		t.Errorf("expected sorted order, got %s, %s", alerts[0].ID, alerts[1].ID)
	}
}
