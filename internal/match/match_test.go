package match

import (
	"strings"
	"testing"
	"time"
)

func TestVariants(t *testing.T) {
	vs := Variants("tcABCDEF0123")
	if len(vs) != 2 {
		t.Fatalf("want 2 variants, got %d", len(vs))
	}
	if vs[0] != "tcabcdef0123" {
		t.Errorf("plain variant = %q", vs[0])
	}
	wantHex := strings.ToLower(hexEncode("tcABCDEF0123"))
	if vs[1] != wantHex {
		t.Errorf("hex variant = %q, want %q", vs[1], wantHex)
	}
}

func TestGroupAudit(t *testing.T) {
	lines := []string{
		`type=SYSCALL msg=audit(1700000000.123:500): arch=c000003e syscall=59 pid=111 comm="cat"`,
		`type=PATH msg=audit(1700000000.123:500): item=0 name="/tmp/decoys/passwords.txt"`,
		`type=SYSCALL msg=audit(1700000001.456:501): arch=c000003e syscall=59 pid=222 comm="ls"`,
		`not an audit line, should be ignored`,
	}
	events := GroupAudit(lines)
	if len(events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}
	if events[0].Serial != "500" || len(events[0].Lines) != 2 {
		t.Errorf("event 0 = %+v", events[0])
	}
	if events[1].Serial != "501" || len(events[1].Lines) != 1 {
		t.Errorf("event 1 = %+v", events[1])
	}
	if !events[0].At.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("event 0 time = %v", events[0].At)
	}
}

func TestGroupAudit_SameSecondDifferentSerial(t *testing.T) {
	// Two events in the same second must stay separate (keyed by serial too).
	lines := []string{
		`msg=audit(1700000000.100:1): pid=1`,
		`msg=audit(1700000000.200:2): pid=2`,
	}
	events := GroupAudit(lines)
	if len(events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}
}

func TestAudit_NeedleMatch(t *testing.T) {
	events := []AuditEvent{
		{Serial: "1", At: time.Unix(100, 0), Lines: []string{
			`msg=audit(100.0:1): comm="sh" a1="tcdeadbeef01"`,
		}},
	}
	ev, line, ok := Audit(events, Spec{Needles: []string{"tcdeadbeef01"}})
	if !ok {
		t.Fatal("expected match")
	}
	if ev.Serial != "1" {
		t.Errorf("serial = %q", ev.Serial)
	}
	if !strings.Contains(line, "tcdeadbeef01") {
		t.Errorf("evidence line = %q", line)
	}
}

func TestAudit_NeedleHexVariant(t *testing.T) {
	// auditd hex-encodes values with unusual bytes; needle must still match.
	needle := "tc!!weird"
	hexForm := strings.ToLower(hexEncode(needle))
	events := []AuditEvent{
		{Serial: "1", At: time.Unix(100, 0), Lines: []string{
			`msg=audit(100.0:1): a1=` + hexForm,
		}},
	}
	_, _, ok := Audit(events, Spec{Needles: []string{needle}})
	if !ok {
		t.Fatal("expected hex-variant match")
	}
}

func TestAudit_PIDFilterRequired(t *testing.T) {
	events := []AuditEvent{
		{Serial: "1", At: time.Unix(100, 0), Lines: []string{
			`msg=audit(100.0:1): comm="cat" pid=999 saddr=0200007F7F000001`,
		}},
	}
	// wrong pid: no match even though needle is present
	_, _, ok := Audit(events, Spec{Needles: []string{"saddr=0200007f7f000001"}, PID: 111})
	if ok {
		t.Fatal("expected no match: pid does not agree")
	}
	// right pid: match
	_, _, ok = Audit(events, Spec{Needles: []string{"saddr=0200007f7f000001"}, PID: 999})
	if !ok {
		t.Fatal("expected match: pid agrees")
	}
}

func TestAudit_SinceFilter(t *testing.T) {
	events := []AuditEvent{
		{Serial: "1", At: time.Unix(100, 0), Lines: []string{`msg=audit(100.0:1): needle=tcold`}},
		{Serial: "2", At: time.Unix(200, 0), Lines: []string{`msg=audit(200.0:2): needle=tcold`}},
	}
	ev, _, ok := Audit(events, Spec{Needles: []string{"tcold"}, Since: time.Unix(150, 0)})
	if !ok {
		t.Fatal("expected match after Since cutoff")
	}
	if ev.Serial != "2" {
		t.Errorf("expected the later event (serial 2), got serial %q", ev.Serial)
	}
}

func TestAudit_SinceTruncatesToSecond(t *testing.T) {
	// Since with sub-second precision is truncated to the second, so an event
	// at the exact same second (but recorded with .000) should still match.
	events := []AuditEvent{
		{Serial: "1", At: time.Unix(100, 0), Lines: []string{`msg=audit(100.000:1): needle=tcx`}},
	}
	since := time.Unix(100, 500_000_000) // 100.5s
	_, _, ok := Audit(events, Spec{Needles: []string{"tcx"}, Since: since})
	if !ok {
		t.Fatal("expected Since to truncate to the second, allowing the same-second event")
	}
}

func TestAudit_NoMatch(t *testing.T) {
	events := []AuditEvent{
		{Serial: "1", At: time.Unix(100, 0), Lines: []string{`msg=audit(100.0:1): comm="ls"`}},
	}
	_, _, ok := Audit(events, Spec{Needles: []string{"tcnotthere"}})
	if ok {
		t.Fatal("expected no match")
	}
}

func TestText(t *testing.T) {
	lines := []string{"some unrelated log line", "found TCNEEDLE123 right here"}
	line, ok := Text(lines, Spec{Needles: []string{"tcneedle123"}})
	if !ok {
		t.Fatal("expected case-insensitive match")
	}
	if !strings.Contains(line, "TCNEEDLE123") {
		t.Errorf("line = %q", line)
	}
}

func TestText_NoMatch(t *testing.T) {
	_, ok := Text([]string{"nothing here"}, Spec{Needles: []string{"tcmissing"}})
	if ok {
		t.Fatal("expected no match")
	}
}

func TestWindowsText_SplitsEventsAndFiltersByID(t *testing.T) {
	out := `Event[0]:
  Log Name: Security
  Event ID: 4688
  Message: a process was created tcABC123

Event[1]:
  Log Name: Security
  Event ID: 4663
  Message: unrelated tcABC123 too
`
	// Only Event ID 4688 allowed.
	line, id, ok := WindowsText(out, Spec{Needles: []string{"tcabc123"}, EventID: []int{4688}})
	if !ok {
		t.Fatal("expected match restricted to event ID 4688")
	}
	if id != 4688 {
		t.Errorf("id = %d", id)
	}
	if !strings.Contains(strings.ToLower(line), "tcabc123") {
		t.Errorf("line = %q", line)
	}
}

func TestWindowsText_NoEventIDFilter(t *testing.T) {
	out := `Event[0]:
  Event ID: 1
  Message: hello tcxyz
`
	_, id, ok := WindowsText(out, Spec{Needles: []string{"tcxyz"}})
	if !ok || id != 1 {
		t.Fatalf("ok=%v id=%d", ok, id)
	}
}

func TestWindowsText_EventIDMismatch(t *testing.T) {
	out := `Event[0]:
  Event ID: 999
  Message: tcnope
`
	_, _, ok := WindowsText(out, Spec{Needles: []string{"tcnope"}, EventID: []int{1}})
	if ok {
		t.Fatal("expected no match: event ID not in allow-list")
	}
}

func TestTrim(t *testing.T) {
	if got := Trim("short", 10); got != "short" {
		t.Errorf("got %q", got)
	}
	long := strings.Repeat("a", 300)
	got := Trim(long, 10)
	if len([]rune(got)) != 11 { // 10 chars + ellipsis
		t.Errorf("trimmed length = %d, got %q", len([]rune(got)), got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("expected ellipsis suffix, got %q", got)
	}
}

// hexEncode mirrors encoding/hex.EncodeToString for the test above without
// importing it twice at package scope collision; trivial helper.
func hexEncode(s string) string {
	const hexdigits = "0123456789abcdef"
	b := []byte(s)
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0xf]
	}
	return string(out)
}
