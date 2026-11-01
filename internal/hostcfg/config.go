// Package hostcfg reads, read-only, how the host is configured to log, and
// predicts from that configuration what it should record.
package hostcfg

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"
)

// Config is a snapshot of the logging-relevant settings of one host.
type Config struct {
	OS      string   `json:"os"`
	Linux   *Linux   `json:"linux,omitempty"`
	Windows *Windows `json:"windows,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// Linux holds auditd, journal and syslog settings.
type Linux struct {
	AuditctlPresent    bool     `json:"auditctl_present"`
	AuditEnabled       int      `json:"audit_enabled"` // 0 off, 1 on, 2 locked, -1 unknown
	AuditDaemonPID     int      `json:"audit_daemon_pid"`
	AuditLost          int      `json:"audit_lost"`
	AuditBacklogLimit  int      `json:"audit_backlog_limit"`
	Rules              []string `json:"audit_rules"`
	AuditLogPath       string   `json:"audit_log_path"`
	AuditLogExists     bool     `json:"audit_log_exists"`
	AuditLogReadable   bool     `json:"audit_log_readable"`
	JournalctlPresent  bool     `json:"journalctl_present"`
	JournaldPersistent bool     `json:"journald_persistent"`
	SyslogDaemon       string   `json:"syslog_daemon,omitempty"`
}

// Windows holds audit policy, PowerShell logging and Sysmon settings.
type Windows struct {
	AuditPol        map[string]string `json:"audit_policy"` // subcategory GUID (lower-case) -> setting
	AuditPolRead    bool              `json:"audit_policy_read"`
	ProcCmdLine     bool              `json:"process_creation_command_line"`
	ScriptBlock     bool              `json:"powershell_script_block_logging"`
	ModuleLogging   bool              `json:"powershell_module_logging"`
	SysmonInstalled bool              `json:"sysmon_installed"`
	SysmonRunning   bool              `json:"sysmon_running"`
	Channels        map[string]bool   `json:"event_log_channels_enabled"`
}

// ParseAuditctlStatus reads `auditctl -s` output.
func ParseAuditctlStatus(out string, l *Linux) {
	l.AuditEnabled = -1
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		n, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		switch f[0] {
		case "enabled":
			l.AuditEnabled = n
		case "pid":
			l.AuditDaemonPID = n
		case "lost":
			l.AuditLost = n
		case "backlog_limit":
			l.AuditBacklogLimit = n
		}
	}
}

// ParseAuditRules reads `auditctl -l` output into one rule per line.
func ParseAuditRules(out string) []string {
	var rules []string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "No rules") {
			continue
		}
		rules = append(rules, t)
	}
	return rules
}

var logFileLine = regexp.MustCompile(`(?m)^\s*log_file\s*=\s*(\S+)`)

// ParseAuditdConf returns log_file from auditd.conf, or the default.
func ParseAuditdConf(conf string) string {
	if m := logFileLine.FindStringSubmatch(conf); m != nil {
		return m[1]
	}
	return "/var/log/audit/audit.log"
}

// ParseAuditPolCSV reads `auditpol /get /category:* /r` and returns the
// setting per subcategory GUID (lower-case, with braces). When a row has no
// GUID the lower-cased subcategory name is used as the key instead.
func ParseAuditPolCSV(out string) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(out, "\r", "")))
	for sc.Scan() {
		row := splitCSV(sc.Text())
		if len(row) < 5 || strings.EqualFold(row[0], "Machine Name") {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(row[3]))
		if key == "" {
			key = strings.ToLower(strings.TrimSpace(row[2]))
		}
		m[key] = strings.TrimSpace(row[4])
		m["name:"+strings.ToLower(strings.TrimSpace(row[2]))] = strings.TrimSpace(row[4])
	}
	return m
}

func splitCSV(s string) []string {
	var out []string
	var cur strings.Builder
	q := false
	for _, r := range s {
		switch {
		case r == '"':
			q = !q
		case r == ',' && !q:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, cur.String())
}

var regDwordRe = regexp.MustCompile(`(?i)REG_DWORD\s+0x([0-9a-f]+)`)

// ParseRegDWORD extracts a DWORD from `reg query` output.
func ParseRegDWORD(out string) (uint64, bool) {
	m := regDwordRe.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseUint(m[1], 16, 64)
	return v, err == nil
}

// ParseWevtutilEnabled reads `wevtutil gl <channel>` and says whether it is enabled.
func ParseWevtutilEnabled(out string) bool {
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(strings.ToLower(t), "enabled:") {
			return strings.EqualFold(strings.TrimSpace(t[len("enabled:"):]), "true")
		}
	}
	return false
}

// ParseScState reads `sc query <service>` and returns installed, running.
func ParseScState(out string) (bool, bool) {
	low := strings.ToLower(out)
	if strings.Contains(low, "1060") || !strings.Contains(low, "state") {
		return false, false
	}
	return true, strings.Contains(low, "running")
}
