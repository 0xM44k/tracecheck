package hostcfg

import "testing"

func TestParseAuditctlStatus(t *testing.T) {
	out := `enabled 1
failure 1
pid 1234
rate_limit 0
backlog_limit 8192
lost 3
backlog 0
backlog_wait_time 60000
backlog_wait_time_actual 0
enabled 1
`
	l := &Linux{}
	ParseAuditctlStatus(out, l)
	if l.AuditEnabled != 1 {
		t.Errorf("AuditEnabled = %d", l.AuditEnabled)
	}
	if l.AuditDaemonPID != 1234 {
		t.Errorf("AuditDaemonPID = %d", l.AuditDaemonPID)
	}
	if l.AuditLost != 3 {
		t.Errorf("AuditLost = %d", l.AuditLost)
	}
	if l.AuditBacklogLimit != 8192 {
		t.Errorf("AuditBacklogLimit = %d", l.AuditBacklogLimit)
	}
}

func TestParseAuditctlStatus_Unknown(t *testing.T) {
	l := &Linux{}
	ParseAuditctlStatus("garbage output\nnot key value pairs at all", l)
	if l.AuditEnabled != -1 {
		t.Errorf("expected -1 (unknown) when enabled is never set, got %d", l.AuditEnabled)
	}
}

func TestParseAuditRules(t *testing.T) {
	out := `-a always,exit -F arch=b64 -S execve -F key=k1
-w /etc/shadow -p r -k k2

No rules
`
	rules := ParseAuditRules(out)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d: %v", len(rules), rules)
	}
}

func TestParseAuditdConf(t *testing.T) {
	conf := "log_file = /var/log/audit/audit.log\nmax_log_file = 8\n"
	if got := ParseAuditdConf(conf); got != "/var/log/audit/audit.log" {
		t.Errorf("got %q", got)
	}
	if got := ParseAuditdConf("no log_file line here"); got != "/var/log/audit/audit.log" {
		t.Errorf("default fallback = %q", got)
	}
}

func TestParseAuditPolCSV(t *testing.T) {
	out := "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n" +
		`HOST,System,Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success,` + "\r\n"
	m := ParseAuditPolCSV(out)
	if got := m["{0cce922b-69ae-11d9-bed3-505054503030}"]; got != "Success" {
		t.Errorf("by GUID = %q, map=%v", got, m)
	}
	if got := m["name:process creation"]; got != "Success" {
		t.Errorf("by name = %q", got)
	}
}

func TestParseAuditPolCSV_HeaderSkipped(t *testing.T) {
	out := "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n"
	m := ParseAuditPolCSV(out)
	if len(m) != 0 {
		t.Errorf("expected header-only input to produce no entries, got %v", m)
	}
}

func TestSplitCSV_QuotedCommas(t *testing.T) {
	row := splitCSV(`a,"b,c",d`)
	want := []string{"a", "b,c", "d"}
	if len(row) != len(want) {
		t.Fatalf("got %v", row)
	}
	for i := range want {
		if row[i] != want[i] {
			t.Errorf("field %d = %q, want %q", i, row[i], want[i])
		}
	}
}

func TestParseRegDWORD(t *testing.T) {
	out := "HKLM\\...\\Policies\n    EnableScriptBlockLogging    REG_DWORD    0x1\n"
	v, ok := ParseRegDWORD(out)
	if !ok || v != 1 {
		t.Errorf("v=%d ok=%v", v, ok)
	}
}

func TestParseRegDWORD_Missing(t *testing.T) {
	_, ok := ParseRegDWORD("ERROR: The system was unable to find the specified registry key.")
	if ok {
		t.Error("expected not-ok for missing key")
	}
}

func TestParseWevtutilEnabled(t *testing.T) {
	out := "channel: Microsoft-Windows-Sysmon/Operational\r\nenabled: true\r\ntype: Admin\r\n"
	if !ParseWevtutilEnabled(out) {
		t.Error("expected true")
	}
	out2 := "enabled: false\r\n"
	if ParseWevtutilEnabled(out2) {
		t.Error("expected false")
	}
}

func TestParseScState(t *testing.T) {
	out := `SERVICE_NAME: Sysmon
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)`
	installed, running := ParseScState(out)
	if !installed || !running {
		t.Errorf("installed=%v running=%v", installed, running)
	}
}

func TestParseScState_NotInstalled(t *testing.T) {
	out := "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\nThe specified service does not exist as an installed service."
	installed, running := ParseScState(out)
	if installed || running {
		t.Errorf("installed=%v running=%v, want both false", installed, running)
	}
}

func TestParseScState_StoppedService(t *testing.T) {
	out := `SERVICE_NAME: foo
        STATE              : 1  STOPPED`
	installed, running := ParseScState(out)
	if !installed {
		t.Error("expected installed=true")
	}
	if running {
		t.Error("expected running=false for STOPPED service")
	}
}
