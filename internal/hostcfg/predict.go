package hostcfg

import (
	"regexp"
	"strings"
)

// Prediction is what the configuration says should happen for one canary.
type Prediction string

const (
	PredSeen    Prediction = "expected-seen"
	PredBlind   Prediction = "expected-blind"
	PredUnknown Prediction = "unknown"
)

var (
	execRule    = regexp.MustCompile(`(?:-S\s+(?:\S*,)?(?:execve|execveat)\b|-S\s+all\b)`)
	actionRule  = regexp.MustCompile(`always,exit|exit,always`)
	permLetters = regexp.MustCompile(`-p\s+([rwxa]+)`)
	pathArg     = regexp.MustCompile(`(?:-w\s+|-F\s+(?:path|dir)=)(\S+)`)
)

// AuditLive says whether auditd can be expected to be writing to a readable log.
func (l *Linux) AuditLive() (bool, string) {
	switch {
	case l.AuditEnabled == 0:
		return false, "kernel audit is disabled"
	case l.AuditDaemonPID == 0:
		return false, "no audit daemon is attached to the kernel audit socket"
	case !l.AuditLogExists:
		return false, "audit log " + l.AuditLogPath + " does not exist (auditd not running as a daemon, or write_logs is off)"
	case !l.AuditLogReadable:
		return false, "audit log " + l.AuditLogPath + " exists but is not readable by this user"
	}
	return true, ""
}

// HasSyscallRule reports a loaded rule that logs any of the given syscalls.
func (l *Linux) HasSyscallRule(names ...string) bool {
	for _, r := range l.Rules {
		if !actionRule.MatchString(r) || strings.Contains(r, "-F exit=-") {
			continue
		}
		if strings.Contains(r, "-S all") {
			return true
		}
		for _, n := range names {
			if regexp.MustCompile(`-S\s+(?:\S*,)?` + regexp.QuoteMeta(n) + `(?:,\S*)?(?:\s|$)`).MatchString(r) {
				return true
			}
		}
	}
	return false
}

// HasWatch reports a loaded watch (or path/dir filter) covering path with the
// given permission letter ('w' write, 'a' attribute change, 'r' read).
func (l *Linux) HasWatch(path string, perm byte) bool {
	for _, r := range l.Rules {
		m := pathArg.FindStringSubmatch(r)
		if m == nil {
			continue
		}
		p := strings.TrimRight(m[1], "/")
		if p == "" || !(path == p || strings.HasPrefix(path, p+"/")) {
			continue
		}
		pm := permLetters.FindStringSubmatch(r)
		if pm == nil {
			if strings.Contains(r, "-w ") {
				return true // a bare -w watches every permission
			}
			continue
		}
		if strings.IndexByte(pm[1], perm) >= 0 {
			return true
		}
	}
	return false
}

// HasExecRule reports a rule that logs program execution.
func (l *Linux) HasExecRule() bool {
	for _, r := range l.Rules {
		if actionRule.MatchString(r) && execRule.MatchString(r) {
			return true
		}
	}
	return false
}

// Audit-policy subcategory GUIDs (Microsoft documents these in auditpol output).
const (
	GUIDProcessCreation   = "{0cce922b-69ae-11d9-bed3-505054503030}"
	GUIDUserAccountMgmt   = "{0cce9235-69ae-11d9-bed3-505054503030}"
	GUIDOtherObjectAccess = "{0cce9227-69ae-11d9-bed3-505054503030}"
	GUIDSecuritySysExt    = "{0cce9211-69ae-11d9-bed3-505054503030}"
	GUIDFileSystem        = "{0cce921d-69ae-11d9-bed3-505054503030}"
	GUIDRegistry          = "{0cce921e-69ae-11d9-bed3-505054503030}"
)

// AuditsSuccess reports whether the subcategory audits success events.
func (w *Windows) AuditsSuccess(guid, englishName string) (bool, bool) {
	if !w.AuditPolRead {
		return false, false
	}
	v, ok := w.AuditPol[guid]
	if !ok {
		v, ok = w.AuditPol["name:"+strings.ToLower(englishName)]
	}
	if !ok {
		return false, false
	}
	return strings.Contains(strings.ToLower(v), "success"), true
}
