// Package sink reads the places a host already sends security telemetry to.
// None of them is written to by tracecheck; they are only searched.
package sink

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/0xM44k/tracecheck/internal/match"
	"github.com/0xM44k/tracecheck/internal/runner"
)

// Hit is one piece of telemetry that belongs to a canary.
type Hit struct {
	Sink     string `json:"sink"`
	Evidence string `json:"evidence"`
	EventID  int    `json:"event_id,omitempty"`
}

// Sink is one telemetry destination.
type Sink interface {
	Name() string
	Available() (bool, string)
	Query(ctx context.Context, s match.Spec) (*Hit, error)
}

// tailLines returns the lines in roughly the last max bytes of a file.
func tailLines(path string, max int64) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > max {
		if _, err := f.Seek(st.Size()-max, io.SeekStart); err != nil {
			return nil, err
		}
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	if st.Size() > max && len(lines) > 0 {
		lines = lines[1:] // first line is probably cut
	}
	return lines, nil
}

// AuditLog searches auditd's log file.
type AuditLog struct{ Path string }

func (AuditLog) Name() string { return "auditd" }

func (a AuditLog) Available() (bool, string) {
	f, err := os.Open(a.Path)
	if err != nil {
		return false, "cannot read " + a.Path + ": " + err.Error()
	}
	f.Close()
	return true, ""
}

func (a AuditLog) Query(_ context.Context, s match.Spec) (*Hit, error) {
	lines, err := tailLines(a.Path, 16<<20)
	if err != nil {
		return nil, err
	}
	if _, ev, ok := match.Audit(match.GroupAudit(lines), s); ok {
		return &Hit{Sink: a.Name(), Evidence: ev}, nil
	}
	return nil, nil
}

// Journal searches the systemd journal. The needle is never passed on the
// command line, otherwise an execve audit rule would log the search itself.
type Journal struct{ R runner.Runner }

func (Journal) Name() string { return "journald" }

func (j Journal) Available() (bool, string) {
	if !runner.Have("journalctl") {
		return false, "journalctl is not installed"
	}
	return true, ""
}

func (j Journal) Query(ctx context.Context, s match.Spec) (*Hit, error) {
	out, err := j.R.Run(ctx, "journalctl", "--no-pager", "-o", "short", "-n", "5000")
	if err != nil {
		return nil, err
	}
	if ev, ok := match.Text(strings.Split(string(out), "\n"), s); ok {
		return &Hit{Sink: j.Name(), Evidence: ev}, nil
	}
	return nil, nil
}

// SyslogFiles searches classic syslog files.
type SyslogFiles struct{ Paths []string }

func (SyslogFiles) Name() string { return "syslog" }

func (s SyslogFiles) Available() (bool, string) {
	for _, p := range s.Paths {
		if f, err := os.Open(p); err == nil {
			f.Close()
			return true, ""
		}
	}
	return false, "no readable syslog file"
}

func (s SyslogFiles) Query(_ context.Context, sp match.Spec) (*Hit, error) {
	for _, p := range s.Paths {
		lines, err := tailLines(p, 4<<20)
		if err != nil {
			continue
		}
		if ev, ok := match.Text(lines, sp); ok {
			return &Hit{Sink: s.Name(), Evidence: ev}, nil
		}
	}
	return nil, nil
}

// EventLog searches one Windows event log channel through wevtutil.
type EventLog struct {
	R       runner.Runner
	Channel string
	Label   string
}

func (e EventLog) Name() string { return e.Label }

func (e EventLog) Available() (bool, string) { return true, "" }

func (e EventLog) Query(ctx context.Context, s match.Spec) (*Hit, error) {
	out, err := e.R.Run(ctx, "wevtutil", "qe", e.Channel, "/c:400", "/rd:true", "/f:text")
	if err != nil {
		return nil, err
	}
	if ev, id, ok := match.WindowsText(string(out), s); ok {
		return &Hit{Sink: e.Name(), Evidence: ev, EventID: id}, nil
	}
	return nil, nil
}

// ForOS returns the sinks to search on this platform.
func ForOS(goos, auditLog string, r runner.Runner) []Sink {
	switch goos {
	case "linux":
		return []Sink{
			AuditLog{Path: auditLog},
			Journal{R: r},
			SyslogFiles{Paths: []string{"/var/log/syslog", "/var/log/auth.log", "/var/log/messages", "/var/log/secure"}},
		}
	case "windows":
		return []Sink{
			EventLog{R: r, Channel: "Security", Label: "Security"},
			EventLog{R: r, Channel: "Microsoft-Windows-Sysmon/Operational", Label: "Sysmon"},
			EventLog{R: r, Channel: "Microsoft-Windows-PowerShell/Operational", Label: "PowerShell"},
			EventLog{R: r, Channel: "Microsoft-Windows-TaskScheduler/Operational", Label: "TaskScheduler"},
			EventLog{R: r, Channel: "System", Label: "System"},
		}
	}
	return nil
}
