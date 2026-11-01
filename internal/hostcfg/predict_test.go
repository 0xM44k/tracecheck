package hostcfg

import "testing"

func TestAuditLive(t *testing.T) {
	cases := []struct {
		name string
		l    Linux
		live bool
	}{
		{"disabled", Linux{AuditEnabled: 0, AuditDaemonPID: 1, AuditLogExists: true, AuditLogReadable: true}, false},
		{"no daemon", Linux{AuditEnabled: 1, AuditDaemonPID: 0, AuditLogExists: true, AuditLogReadable: true}, false},
		{"log missing", Linux{AuditEnabled: 1, AuditDaemonPID: 1, AuditLogExists: false, AuditLogReadable: true}, false},
		{"log unreadable", Linux{AuditEnabled: 1, AuditDaemonPID: 1, AuditLogExists: true, AuditLogReadable: false}, false},
		{"fully live", Linux{AuditEnabled: 1, AuditDaemonPID: 1234, AuditLogExists: true, AuditLogReadable: true}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			live, reason := c.l.AuditLive()
			if live != c.live {
				t.Errorf("live = %v, want %v (reason=%q)", live, c.live, reason)
			}
			if !live && reason == "" {
				t.Error("expected a non-empty reason when not live")
			}
		})
	}
}

func TestHasSyscallRule(t *testing.T) {
	l := &Linux{Rules: []string{
		`-a always,exit -F arch=b64 -S execve,execveat -F key=tracecheck_exec`,
	}}
	if !l.HasSyscallRule("execve") {
		t.Error("expected match for execve in a comma list")
	}
	if !l.HasSyscallRule("execveat") {
		t.Error("expected match for execveat in a comma list")
	}
	if l.HasSyscallRule("connect") {
		t.Error("expected no match for a syscall not in the rule")
	}
}

func TestHasSyscallRule_AllCovers(t *testing.T) {
	l := &Linux{Rules: []string{`-a always,exit -S all -F key=everything`}}
	if !l.HasSyscallRule("connect") {
		t.Error("-S all should match any syscall")
	}
}

func TestHasSyscallRule_ExitFilterExcluded(t *testing.T) {
	// A rule that only logs failures (exit=-EPERM etc.) should not count as
	// "this syscall is recorded" for our always-succeeding canaries.
	l := &Linux{Rules: []string{`-a always,exit -F arch=b64 -S execve -F exit=-1 -F key=denied_only`}}
	if l.HasSyscallRule("execve") {
		t.Error("expected no match: rule is filtered to failures only")
	}
}

func TestHasSyscallRule_WrongAction(t *testing.T) {
	l := &Linux{Rules: []string{`-a never,exit -S execve -F key=disabled_rule`}}
	if l.HasSyscallRule("execve") {
		t.Error("expected no match: action is never,exit")
	}
}

func TestHasWatch(t *testing.T) {
	l := &Linux{Rules: []string{`-w /etc/shadow -p r -k tracecheck_shadow`}}
	if !l.HasWatch("/etc/shadow", 'r') {
		t.Error("expected read watch to match")
	}
	if l.HasWatch("/etc/shadow", 'w') {
		t.Error("expected no write watch")
	}
}

func TestHasWatch_DirPrefix(t *testing.T) {
	l := &Linux{Rules: []string{`-w /etc/cron.d -p wa -k tracecheck_cron`}}
	if !l.HasWatch("/etc/cron.d/foo", 'w') {
		t.Error("expected a watch on the directory to cover a file inside it")
	}
	if l.HasWatch("/etc/other", 'w') {
		t.Error("expected no match for an unrelated path")
	}
}

func TestHasWatch_BareDashW(t *testing.T) {
	l := &Linux{Rules: []string{`-w /etc/passwd`}}
	if !l.HasWatch("/etc/passwd", 'x') {
		t.Error("a bare -w with no -p should be treated as watching every permission")
	}
}

func TestHasExecRule(t *testing.T) {
	l := &Linux{Rules: []string{`-a always,exit -F arch=b64 -S execve,execveat -F key=tracecheck_exec`}}
	if !l.HasExecRule() {
		t.Error("expected exec rule to be detected")
	}
	l2 := &Linux{Rules: []string{`-w /etc/shadow -p r -k x`}}
	if l2.HasExecRule() {
		t.Error("expected no exec rule for an unrelated watch")
	}
}

func TestAuditsSuccess(t *testing.T) {
	w := &Windows{
		AuditPolRead: true,
		AuditPol: map[string]string{
			GUIDProcessCreation: "Success",
		},
	}
	success, known := w.AuditsSuccess(GUIDProcessCreation, "Process Creation")
	if !success || !known {
		t.Errorf("success=%v known=%v", success, known)
	}
}

func TestAuditsSuccess_FallsBackToName(t *testing.T) {
	w := &Windows{
		AuditPolRead: true,
		AuditPol: map[string]string{
			"name:process creation": "Success and Failure",
		},
	}
	success, known := w.AuditsSuccess(GUIDProcessCreation, "Process Creation")
	if !success || !known {
		t.Errorf("success=%v known=%v", success, known)
	}
}

func TestAuditsSuccess_NotReadOrUnknown(t *testing.T) {
	w := &Windows{AuditPolRead: false}
	if success, known := w.AuditsSuccess(GUIDProcessCreation, "Process Creation"); success || known {
		t.Errorf("expected (false,false) when policy wasn't read, got (%v,%v)", success, known)
	}
	w2 := &Windows{AuditPolRead: true, AuditPol: map[string]string{}}
	if success, known := w2.AuditsSuccess(GUIDProcessCreation, "Process Creation"); success || known {
		t.Errorf("expected (false,false) for an unknown subcategory, got (%v,%v)", success, known)
	}
}
