// Package match decides whether a piece of host telemetry belongs to a canary.
//
// A canary is recognised by a needle (a unique string it put into a command
// line, file name or similar) and, for actions that cannot carry a needle, by
// the process ID of the tracecheck process that performed them.
package match

import (
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Spec describes what to look for.
type Spec struct {
	Needles []string  // any one of these must appear (case-insensitive)
	PID     int       // when non-zero, the same audit event must also carry pid=PID
	EventID []int     // Windows only: when set, the event ID must be one of these
	Since   time.Time // ignore telemetry older than this (zero = no limit)
}

// Variants returns the needle in the forms auditd may write it: plain, and the
// upper-case hex encoding auditd uses for values that contain unusual bytes.
func Variants(needle string) []string {
	n := strings.ToLower(needle)
	return []string{n, strings.ToLower(hex.EncodeToString([]byte(needle)))}
}

var auditHead = regexp.MustCompile(`msg=audit\((\d+)\.(\d+):(\d+)\)`)

// AuditEvent is the set of records auditd wrote for one event serial.
type AuditEvent struct {
	Serial string
	At     time.Time
	Lines  []string
}

// GroupAudit splits raw audit.log lines into events. Lines without a
// msg=audit(...) header are ignored.
func GroupAudit(lines []string) []AuditEvent {
	var out []AuditEvent
	idx := map[string]int{}
	for _, l := range lines {
		m := auditHead.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		key := m[1] + ":" + m[3]
		i, ok := idx[key]
		if !ok {
			sec, _ := strconv.ParseInt(m[1], 10, 64)
			out = append(out, AuditEvent{Serial: m[3], At: time.Unix(sec, 0)})
			i = len(out) - 1
			idx[key] = i
		}
		out[i].Lines = append(out[i].Lines, l)
	}
	return out
}

func hasPID(lines []string, pid int) bool {
	tok := "pid=" + strconv.Itoa(pid)
	for _, l := range lines {
		for _, f := range strings.Fields(l) {
			if f == tok {
				return true
			}
		}
	}
	return false
}

// Audit returns the first event that satisfies the spec, and one line of
// evidence from it.
func Audit(events []AuditEvent, s Spec) (AuditEvent, string, bool) {
	var vs []string
	for _, n := range s.Needles {
		vs = append(vs, Variants(n)...)
	}
	for _, ev := range events {
		if !s.Since.IsZero() && ev.At.Before(s.Since.Truncate(time.Second)) {
			continue
		}
		if s.PID != 0 && !hasPID(ev.Lines, s.PID) {
			continue
		}
		for _, l := range ev.Lines {
			low := strings.ToLower(l)
			for _, v := range vs {
				if v != "" && strings.Contains(low, v) {
					return ev, Trim(l, 220), true
				}
			}
		}
	}
	return AuditEvent{}, "", false
}

// Text matches free-form log text (journal, syslog files). Each line is checked.
func Text(lines []string, s Spec) (string, bool) {
	var vs []string
	for _, n := range s.Needles {
		vs = append(vs, strings.ToLower(n))
	}
	for _, l := range lines {
		low := strings.ToLower(l)
		for _, v := range vs {
			if v != "" && strings.Contains(low, v) {
				return Trim(l, 220), true
			}
		}
	}
	return "", false
}

var evHead = regexp.MustCompile(`(?m)^Event\[\d+\]`)
var evID = regexp.MustCompile(`(?m)^\s*Event ID:\s*(\d+)`)

// WindowsText splits `wevtutil qe /f:text` output into events and returns the
// first whose text contains a needle (and, if set, whose Event ID is allowed).
func WindowsText(out string, s Spec) (string, int, bool) {
	locs := evHead.FindAllStringIndex(out, -1)
	for i, loc := range locs {
		end := len(out)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := out[loc[0]:end]
		low := strings.ToLower(block)
		id := 0
		if m := evID.FindStringSubmatch(block); m != nil {
			id, _ = strconv.Atoi(m[1])
		}
		if len(s.EventID) > 0 {
			ok := false
			for _, want := range s.EventID {
				if want == id {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		for _, n := range s.Needles {
			if n != "" && strings.Contains(low, strings.ToLower(n)) {
				return Trim(firstLineWith(block, n), 220), id, true
			}
		}
	}
	return "", 0, false
}

func firstLineWith(block, needle string) string {
	ln := strings.ToLower(needle)
	for _, l := range strings.Split(block, "\n") {
		if strings.Contains(strings.ToLower(l), ln) {
			return strings.TrimSpace(l)
		}
	}
	return strings.TrimSpace(block)
}

// Trim shortens s to n runes with an ellipsis.
func Trim(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
