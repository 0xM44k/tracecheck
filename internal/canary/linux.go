package canary

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/0xM44k/tracecheck/internal/hostcfg"
	"github.com/0xM44k/tracecheck/internal/match"
)

func linuxPredict(l *hostcfg.Linux, ok func() bool, reason string) (hostcfg.Prediction, string) {
	if l == nil {
		return hostcfg.PredUnknown, "no Linux configuration was read"
	}
	if live, why := l.AuditLive(); !live {
		// Journal or syslog may still carry it, but the audit trail does not.
		return hostcfg.PredBlind, why
	}
	if l.AuditEnabled < 0 {
		return hostcfg.PredUnknown, "audit state could not be read"
	}
	if ok() {
		return hostcfg.PredSeen, reason
	}
	return hostcfg.PredBlind, "no loaded audit rule covers this"
}

func needRoot(what string) error {
	if os.Geteuid() != 0 {
		return ErrSkip{"needs root to " + what}
	}
	return nil
}

func writeAndRemove(path, content string) (func() error, error) {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return noCleanup, err
	}
	return func() error {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}, nil
}

func archFlags() string {
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		return "-F arch=b64"
	}
	return "-F arch=b32"
}

func linuxCanaries() []Canary {
	arch := archFlags()
	return []Canary{
		{
			ID: "lin-exec-shell", Name: "Run a shell command", Technique: "T1059.004", Tactic: "Execution",
			Platform: "linux", Level: Safe,
			Description: "Runs /bin/sh with a harmless command and the nonce as an argument.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return linuxPredict(c.Linux, func() bool { return c.Linux.HasExecRule() }, "an execve audit rule is loaded")
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				_, err := e.R.Run(ctx, "/bin/sh", "-c", "exit 0", nonce)
				return match.Spec{Needles: []string{nonce}}, noCleanup, err
			},
			Fix: Fix{Auditd: []string{"-a always,exit " + arch + " -S execve,execveat -k tracecheck_exec"},
				Note: "Logs every program execution. Add -F auid>=1000 -F auid!=-1 to limit it to real users."},
		},
		{
			ID: "lin-discovery-uname", Name: "System information discovery", Technique: "T1082", Tactic: "Discovery",
			Platform: "linux", Level: Safe,
			Description: "Runs uname with a bogus extra operand carrying the nonce (it exits with an error and prints nothing useful).",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return linuxPredict(c.Linux, func() bool { return c.Linux.HasExecRule() }, "an execve audit rule is loaded")
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				e.R.Run(ctx, "uname", "-a", nonce) // exits 1 on purpose; only the execve matters
				return match.Spec{Needles: []string{nonce}}, noCleanup, nil
			},
			Fix: Fix{Auditd: []string{"-a always,exit " + arch + " -S execve,execveat -k tracecheck_exec"}},
		},
		{
			ID: "lin-cred-shadow-read", Name: "Read the password hash file", Technique: "T1003.008", Tactic: "Credential Access",
			Platform: "linux", Level: Safe,
			Description: "Opens /etc/shadow for reading and closes it again without reading any content.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return linuxPredict(c.Linux, func() bool { return c.Linux.HasWatch("/etc/shadow", 'r') }, "a read watch on /etc/shadow is loaded")
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				f, err := os.Open("/etc/shadow") // EACCES for non-root is still an audited attempt
				if err == nil {
					f.Close()
				}
				return match.Spec{Needles: []string{"/etc/shadow"}, PID: e.PID}, noCleanup, nil
			},
			Fix: Fix{Auditd: []string{"-w /etc/shadow -p r -k tracecheck_shadow"}},
		},
		{
			ID: "lin-perm-chmod", Name: "Change a file's permissions", Technique: "T1222.002", Tactic: "Defense Evasion",
			Platform: "linux", Level: Safe,
			Description: "Creates a temporary file named with the nonce, changes its mode, deletes it.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return linuxPredict(c.Linux, func() bool {
					return c.Linux.HasSyscallRule("chmod", "fchmodat", "fchmodat2", "fchmod")
				}, "a chmod audit rule is loaded")
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				dir, err := os.MkdirTemp(e.TmpDir, "tracecheck-"+nonce+"-")
				if err != nil {
					return match.Spec{}, noCleanup, err
				}
				cleanup := func() error { return os.RemoveAll(dir) }
				p := filepath.Join(dir, "f")
				if err := os.WriteFile(p, nil, 0o600); err != nil {
					return match.Spec{}, cleanup, err
				}
				if err := os.Chmod(p, 0o640); err != nil {
					return match.Spec{}, cleanup, err
				}
				return match.Spec{Needles: []string{nonce}, PID: e.PID}, cleanup, nil
			},
			Fix: Fix{Auditd: []string{"-a always,exit " + arch + " -S chmod,fchmod,fchmodat -k tracecheck_perm"},
				Note: "fchmodat2 (Linux 6.6+) is not known to older audit userspace; add it by hand if your auditctl accepts it."},
		},
		{
			ID: "lin-net-connect", Name: "Open a network connection", Technique: "T1046", Tactic: "Discovery",
			Platform: "linux", Level: Safe,
			Description: "Connects to a closed port on 127.0.0.1 (nothing leaves the machine).",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return linuxPredict(c.Linux, func() bool { return c.Linux.HasSyscallRule("connect") }, "a connect audit rule is loaded")
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					return match.Spec{}, noCleanup, err
				}
				port := ln.Addr().(*net.TCPAddr).Port
				ln.Close() // now closed: the connect is refused
				c, derr := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
				if derr == nil {
					c.Close()
				}
				// auditd writes saddr as hex: family 0200, port, then 127.0.0.1.
				needle := fmt.Sprintf("0200%04X7F000001", port)
				return match.Spec{Needles: []string{needle}, PID: e.PID}, noCleanup, nil
			},
			Fix: Fix{Auditd: []string{"-a always,exit " + arch + " -S connect -k tracecheck_net"},
				Note: "Very noisy on busy hosts. Filter by user, exe or destination in production."},
		},
		{
			ID: "lin-persist-cron", Name: "Create a cron job file", Technique: "T1053.003", Tactic: "Persistence",
			Platform: "linux", Level: Full,
			Description: "Writes /etc/cron.d/tc-<nonce> containing only a comment, then deletes it. No job is scheduled.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return linuxPredict(c.Linux, func() bool { return c.Linux.HasWatch("/etc/cron.d/x", 'w') }, "a write watch on /etc/cron.d is loaded")
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				if err := needRoot("write /etc/cron.d"); err != nil {
					return match.Spec{}, noCleanup, err
				}
				p := "/etc/cron.d/tc-" + nonce
				cl, err := writeAndRemove(p, "# tracecheck canary, no job. Removed automatically.\n")
				return match.Spec{Needles: []string{"tc-" + nonce}}, cl, err
			},
			Fix: Fix{Auditd: []string{"-w /etc/cron.d/ -p wa -k tracecheck_cron"}},
		},
		{
			ID: "lin-persist-systemd", Name: "Create a systemd unit file", Technique: "T1543.002", Tactic: "Persistence",
			Platform: "linux", Level: Full,
			Description: "Writes a unit file that is never enabled or started, then deletes it.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return linuxPredict(c.Linux, func() bool { return c.Linux.HasWatch("/etc/systemd/system/x", 'w') }, "a write watch on /etc/systemd/system is loaded")
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				if err := needRoot("write /etc/systemd/system"); err != nil {
					return match.Spec{}, noCleanup, err
				}
				p := "/etc/systemd/system/tc-" + nonce + ".service"
				cl, err := writeAndRemove(p, "[Unit]\nDescription=tracecheck canary (never started)\n")
				return match.Spec{Needles: []string{"tc-" + nonce}}, cl, err
			},
			Fix: Fix{Auditd: []string{"-w /etc/systemd/system/ -p wa -k tracecheck_systemd"}},
		},
		{
			ID: "lin-persist-profile", Name: "Create a login-shell script", Technique: "T1546.004", Tactic: "Persistence",
			Platform: "linux", Level: Full,
			Description: "Writes /etc/profile.d/tc-<nonce>.sh containing only a comment, then deletes it.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return linuxPredict(c.Linux, func() bool { return c.Linux.HasWatch("/etc/profile.d/x", 'w') }, "a write watch on /etc/profile.d is loaded")
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				if err := needRoot("write /etc/profile.d"); err != nil {
					return match.Spec{}, noCleanup, err
				}
				p := "/etc/profile.d/tc-" + nonce + ".sh"
				cl, err := writeAndRemove(p, "# tracecheck canary, does nothing. Removed automatically.\n")
				return match.Spec{Needles: []string{"tc-" + nonce}}, cl, err
			},
			Fix: Fix{Auditd: []string{"-w /etc/profile.d/ -p wa -k tracecheck_profile"}},
		},
		{
			ID: "lin-account-create", Name: "Create a local account", Technique: "T1136.001", Tactic: "Persistence",
			Platform: "linux", Level: Full,
			Description: "Creates a system account with no home and no login shell, then deletes it.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return linuxPredict(c.Linux, func() bool { return true }, "auditd records account changes made by useradd by default")
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				if err := needRoot("create an account"); err != nil {
					return match.Spec{}, noCleanup, err
				}
				name := "tc" + strings.TrimPrefix(nonce, "tc")
				if len(name) > 30 {
					name = name[:30]
				}
				if _, err := e.R.Run(ctx, "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name); err != nil {
					return match.Spec{}, noCleanup, ErrSkip{"useradd failed: " + err.Error()}
				}
				cleanup := func() error { _, err := e.R.Run(ctx, "userdel", name); return err }
				return match.Spec{Needles: []string{name}}, cleanup, nil
			},
			Fix: Fix{Auditd: []string{"-w /etc/passwd -p wa -k tracecheck_identity", "-w /etc/shadow -p wa -k tracecheck_identity"},
				Note: "USER_ADD records come from auditd itself. If they are missing, auditd is not running or its log is not readable."},
		},
	}
}
