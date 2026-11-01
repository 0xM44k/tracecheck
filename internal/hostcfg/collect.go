package hostcfg

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xM44k/tracecheck/internal/runner"
)

// Env abstracts the few file system reads collectors need, for tests.
type Env struct {
	ReadFile func(string) ([]byte, error)
	Exists   func(string) bool
	Comms    func() []string // names of running processes (Linux)
}

// RealEnv reads the actual host.
func RealEnv() Env {
	return Env{
		ReadFile: os.ReadFile,
		Exists:   func(p string) bool { _, err := os.Stat(p); return err == nil },
		Comms: func() []string {
			var out []string
			ents, _ := filepath.Glob("/proc/[0-9]*/comm")
			for _, e := range ents {
				if b, err := os.ReadFile(e); err == nil {
					out = append(out, strings.TrimSpace(string(b)))
				}
			}
			return out
		},
	}
}

// Collect reads the configuration of the host for the given GOOS.
func Collect(ctx context.Context, r runner.Runner, env Env, goos string) *Config {
	c := &Config{OS: goos}
	switch goos {
	case "linux":
		c.Linux = collectLinux(ctx, r, env, c)
	case "windows":
		c.Windows = collectWindows(ctx, r, c)
	default:
		c.Notes = append(c.Notes, "unsupported platform "+goos+": only linux and windows are implemented")
	}
	return c
}

func collectLinux(ctx context.Context, r runner.Runner, env Env, c *Config) *Linux {
	l := &Linux{AuditEnabled: -1, AuditLogPath: "/var/log/audit/audit.log"}
	if out, err := r.Run(ctx, "auditctl", "-s"); err == nil {
		l.AuditctlPresent = true
		ParseAuditctlStatus(string(out), l)
		if rules, err := r.Run(ctx, "auditctl", "-l"); err == nil {
			l.Rules = ParseAuditRules(string(rules))
		}
	} else {
		c.Notes = append(c.Notes, "auditctl could not be run (not installed, or not root): audit state is unknown")
	}
	if b, err := env.ReadFile("/etc/audit/auditd.conf"); err == nil {
		l.AuditLogPath = ParseAuditdConf(string(b))
	}
	if _, err := os.Stat(l.AuditLogPath); err == nil {
		l.AuditLogExists = true
	}
	if f, err := os.Open(l.AuditLogPath); err == nil { // a real open: readability is what matters
		f.Close()
		l.AuditLogReadable = true
	}
	l.JournalctlPresent = runner.Have("journalctl")
	l.JournaldPersistent = env.Exists("/var/log/journal")
	for _, name := range env.Comms() {
		if name == "rsyslogd" || name == "syslog-ng" {
			l.SyslogDaemon = name
		}
	}
	return l
}

var winChannels = []string{
	"Security",
	"Microsoft-Windows-Sysmon/Operational",
	"Microsoft-Windows-PowerShell/Operational",
	"Microsoft-Windows-TaskScheduler/Operational",
	"System",
}

func regDword(ctx context.Context, r runner.Runner, key, name string) bool {
	out, err := r.Run(ctx, "reg", "query", key, "/v", name)
	if err != nil {
		return false
	}
	v, ok := ParseRegDWORD(string(out))
	return ok && v != 0
}

func collectWindows(ctx context.Context, r runner.Runner, c *Config) *Windows {
	w := &Windows{AuditPol: map[string]string{}, Channels: map[string]bool{}}
	if out, err := r.Run(ctx, "auditpol", "/get", "/category:*", "/r"); err == nil {
		w.AuditPol = ParseAuditPolCSV(string(out))
		w.AuditPolRead = len(w.AuditPol) > 0
	} else {
		c.Notes = append(c.Notes, "auditpol could not be run (needs an elevated prompt): audit policy is unknown")
	}
	w.ProcCmdLine = regDword(ctx, r, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`, "ProcessCreationIncludeCmdLine_Enabled")
	w.ScriptBlock = regDword(ctx, r, `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging")
	w.ModuleLogging = regDword(ctx, r, `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging`, "EnableModuleLogging")
	for _, svc := range []string{"Sysmon64", "Sysmon"} {
		if out, _ := r.Run(ctx, "sc", "query", svc); out != nil {
			inst, run := ParseScState(string(out))
			if inst {
				w.SysmonInstalled, w.SysmonRunning = true, run
				break
			}
		}
	}
	for _, ch := range winChannels {
		if out, err := r.Run(ctx, "wevtutil", "gl", ch); err == nil {
			w.Channels[ch] = ParseWevtutilEnabled(string(out))
		}
	}
	return w
}
