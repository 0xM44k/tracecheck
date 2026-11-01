// Package watch places decoy files and raises an alert when something touches
// them. On Linux it uses fanotify permission events, so the kernel tells
// tracecheck which process is opening the file before the open completes. That
// is what makes optional containment possible: the open can be refused.
//
// Decoys contain no real secret. They are marked as decoys inside the file so
// a person who finds one is not misled.
package watch

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Alert is one touch of a decoy.
type Alert struct {
	Time    time.Time `json:"time"`
	Decoy   string    `json:"decoy"`
	Event   string    `json:"event"` // open, modify, access
	PID     int       `json:"pid"`
	PPID    int       `json:"ppid"`
	UID     int       `json:"uid"`
	Comm    string    `json:"comm,omitempty"`
	Exe     string    `json:"exe,omitempty"`
	Cmdline string    `json:"cmdline,omitempty"`
	Chain   []string  `json:"chain,omitempty"` // ancestors, nearest first, as pid:name
	Action  string    `json:"action"`          // allowed, denied, suspended, killed
	Note    string    `json:"note,omitempty"`
}

// Options control watching.
type Options struct {
	Paths     []string
	Contain   string   // alert, deny, suspend, kill
	AllowComm []string // process names that may touch decoys silently
	Emit      func(Alert)
}

// Contain modes.
const (
	ContainAlert   = "alert"
	ContainDeny    = "deny"
	ContainSuspend = "suspend"
	ContainKill    = "kill"
)

// ValidContain reports whether s is a known mode.
func ValidContain(s string) bool {
	switch s {
	case ContainAlert, ContainDeny, ContainSuspend, ContainKill:
		return true
	}
	return false
}

type decoySpec struct {
	Name    string
	Content string
}

var decoys = []decoySpec{
	{"aws_credentials.bak", "# tracecheck decoy: not a real credential\n[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"},
	{"id_rsa.old", "# tracecheck decoy: not a real key\n-----BEGIN OPENSSH PRIVATE KEY-----\ndHJhY2VjaGVjayBkZWNveSwgbm90IGEgcmVhbCBrZXk=\n-----END OPENSSH PRIVATE KEY-----\n"},
	{"passwords.txt", "# tracecheck decoy: not real passwords\nvpn-admin: decoy-not-a-password\nbackup-db: decoy-not-a-password\n"},
	{"kubeconfig.old", "# tracecheck decoy: not a real cluster\napiVersion: v1\nkind: Config\nclusters:\n- name: decoy\n  cluster:\n    server: https://decoy.invalid:6443\nusers:\n- name: decoy\n  user:\n    token: decoy-not-a-token\n"},
	{".env.backup", "# tracecheck decoy: not real settings\nDATABASE_URL=postgres://decoy:decoy@decoy.invalid:5432/decoy\nAPI_KEY=decoy-not-a-key\n"},
}

// Deploy writes the decoy files into dir and returns their paths. Existing
// files are never overwritten.
func Deploy(dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var out []string
	for _, d := range decoys {
		p := filepath.Join(dir, d.Name)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			if os.IsExist(err) {
				if b, rerr := os.ReadFile(p); rerr == nil && strings.Contains(string(b), "tracecheck decoy") {
					out = append(out, p) // our own decoy from an earlier run
					continue
				}
				return out, fmt.Errorf("%s already exists and is not a tracecheck decoy; refusing to touch it", p)
			}
			return out, err
		}
		_, werr := f.WriteString(d.Content)
		f.Close()
		if werr != nil {
			return out, werr
		}
		out = append(out, p)
	}
	return out, nil
}

// Remove deletes decoy files that still carry the decoy marker.
func Remove(paths []string) {
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), "tracecheck decoy") {
			os.Remove(p)
		}
	}
}

// Emitter writes alerts as JSON lines to a file and a human line to out.
type Emitter struct {
	mu     sync.Mutex
	file   *os.File
	out    io.Writer
	extra  func(Alert)
	Count  int
	Denied int
}

// NewEmitter opens logPath for appending (empty = no file).
func NewEmitter(logPath string, out io.Writer, extra func(Alert)) (*Emitter, error) {
	e := &Emitter{out: out, extra: extra}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		e.file = f
	}
	return e, nil
}

// Emit records one alert.
func (e *Emitter) Emit(a Alert) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Count++
	if a.Action != "allowed" {
		e.Denied++
	}
	if e.file != nil {
		b, _ := json.Marshal(a)
		e.file.Write(append(b, '\n'))
	}
	if e.out != nil {
		fmt.Fprintf(e.out, "%s ALERT decoy=%s event=%s pid=%d uid=%d exe=%s action=%s chain=%s\n",
			a.Time.Format(time.RFC3339), filepath.Base(a.Decoy), a.Event, a.PID, a.UID, a.Exe, a.Action, strings.Join(a.Chain, " < "))
	}
	if e.extra != nil {
		e.extra(a)
	}
}

// Close closes the log file.
func (e *Emitter) Close() {
	if e.file != nil {
		e.file.Close()
	}
}
