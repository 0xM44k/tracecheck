package canary

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"

	"github.com/0xM44k/tracecheck/internal/hostcfg"
	"github.com/0xM44k/tracecheck/internal/match"
)

func winPredict(w *hostcfg.Windows, parts ...func(*hostcfg.Windows) (bool, bool, string)) (hostcfg.Prediction, string) {
	if w == nil {
		return hostcfg.PredUnknown, "no Windows configuration was read"
	}
	unknown := false
	for _, p := range parts {
		seen, known, why := p(w)
		if seen {
			return hostcfg.PredSeen, why
		}
		if !known {
			unknown = true
		}
	}
	if unknown {
		return hostcfg.PredUnknown, "audit policy could not be read (run from an elevated prompt)"
	}
	return hostcfg.PredBlind, "no enabled setting records this"
}

func sysmonPart(w *hostcfg.Windows) (bool, bool, string) {
	return w.SysmonRunning, true, "Sysmon is running (whether it logs this depends on its configuration)"
}

func auditPart(guid, name, why string, extra func(*hostcfg.Windows) bool) func(*hostcfg.Windows) (bool, bool, string) {
	return func(w *hostcfg.Windows) (bool, bool, string) {
		ok, known := w.AuditsSuccess(guid, name)
		if ok && extra != nil && !extra(w) {
			return false, true, ""
		}
		return ok, known, why
	}
}

func randPassword() string {
	const set = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 24)
	rand.Read(b)
	for i := range b {
		b[i] = set[int(b[i])%len(set)]
	}
	return string(b) + "#1a"
}

func windowsCanaries() []Canary {
	procFix := Fix{Windows: []string{
		`auditpol /set /subcategory:"Process Creation" /success:enable`,
		`reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f`,
	}, Note: "Event 4688 with the command line. Sysmon event 1 is an alternative."}
	procPredict := func(c *hostcfg.Config) (hostcfg.Prediction, string) {
		return winPredict(c.Windows,
			auditPart(hostcfg.GUIDProcessCreation, "Process Creation", "Process Creation auditing and command-line logging are on",
				func(w *hostcfg.Windows) bool { return w.ProcCmdLine }),
			sysmonPart)
	}
	return []Canary{
		{
			ID: "win-exec-cmd", Name: "Run a command prompt command", Technique: "T1059.003", Tactic: "Execution",
			Platform: "windows", Level: Safe, Sinks: []string{"Security", "Sysmon"},
			Description: "Runs cmd.exe /c echo with the nonce.",
			Predict:     procPredict,
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				_, err := e.R.Run(ctx, "cmd.exe", "/c", "echo", nonce)
				return match.Spec{Needles: []string{nonce}, EventID: []int{4688, 1}}, noCleanup, err
			},
			Fix: procFix,
		},
		{
			ID: "win-exec-powershell", Name: "Run a PowerShell command", Technique: "T1059.001", Tactic: "Execution",
			Platform: "windows", Level: Safe, Sinks: []string{"Security", "Sysmon", "PowerShell"},
			Description: "Runs powershell.exe with Write-Output and the nonce.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return winPredict(c.Windows,
					auditPart(hostcfg.GUIDProcessCreation, "Process Creation", "Process Creation auditing and command-line logging are on",
						func(w *hostcfg.Windows) bool { return w.ProcCmdLine }),
					func(w *hostcfg.Windows) (bool, bool, string) {
						return w.ScriptBlock, true, "PowerShell script block logging is on"
					},
					sysmonPart)
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				_, err := e.R.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Write-Output "+nonce)
				return match.Spec{Needles: []string{nonce}, EventID: []int{4688, 1, 4104, 4103}}, noCleanup, err
			},
			Fix: Fix{Windows: append(append([]string{}, procFix.Windows...),
				`reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f`),
				Note: "Script block logging writes event 4104 to Microsoft-Windows-PowerShell/Operational."},
		},
		{
			ID: "win-discovery-whoami", Name: "Account discovery", Technique: "T1033", Tactic: "Discovery",
			Platform: "windows", Level: Safe, Sinks: []string{"Security", "Sysmon"},
			Description: "Runs whoami.exe with a bogus argument carrying the nonce (it prints an error).",
			Predict:     procPredict,
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				e.R.Run(ctx, "whoami.exe", nonce) // exits with an error on purpose
				return match.Spec{Needles: []string{nonce}, EventID: []int{4688, 1}}, noCleanup, nil
			},
			Fix: procFix,
		},
		{
			ID: "win-net-connect", Name: "Open a network connection", Technique: "T1046", Tactic: "Discovery",
			Platform: "windows", Level: Safe, Sinks: []string{"Sysmon", "Security"},
			Description: "Connects to a listener on 127.0.0.1 opened by tracecheck itself.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return winPredict(c.Windows, sysmonPart)
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					return match.Spec{}, noCleanup, err
				}
				port := ln.Addr().(*net.TCPAddr).Port
				go func() {
					if c, err := ln.Accept(); err == nil {
						c.Close()
					}
				}()
				if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
					c.Close()
				}
				return match.Spec{Needles: []string{fmt.Sprint(port)}, EventID: []int{3, 5156}}, func() error { return ln.Close() }, nil
			},
			Fix: Fix{Windows: []string{`auditpol /set /subcategory:"Filtering Platform Connection" /success:enable`},
				Note: "Event 5156 is very noisy. Sysmon event 3 with a filtered configuration is the usual choice."},
		},
		{
			ID: "win-persist-schtask", Name: "Create a scheduled task", Technique: "T1053.005", Tactic: "Persistence",
			Platform: "windows", Level: Full, Sinks: []string{"Security", "TaskScheduler", "Sysmon"},
			Description: "Creates a one-time task named with the nonce that runs `cmd /c exit`, then deletes it.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return winPredict(c.Windows,
					auditPart(hostcfg.GUIDOtherObjectAccess, "Other Object Access Events", "Other Object Access Events auditing is on (event 4698)", nil),
					func(w *hostcfg.Windows) (bool, bool, string) {
						return w.Channels["Microsoft-Windows-TaskScheduler/Operational"], true, "the Task Scheduler operational log is enabled"
					},
					sysmonPart)
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				name := "tc" + nonce
				if _, err := e.R.Run(ctx, "schtasks.exe", "/create", "/tn", name, "/tr", "cmd.exe /c exit", "/sc", "once", "/st", "23:59", "/f"); err != nil {
					return match.Spec{}, noCleanup, ErrSkip{"schtasks /create failed: " + err.Error()}
				}
				cleanup := func() error { _, err := e.R.Run(ctx, "schtasks.exe", "/delete", "/tn", name, "/f"); return err }
				return match.Spec{Needles: []string{name}, EventID: []int{4698, 106, 11, 12, 13}}, cleanup, nil
			},
			Fix: Fix{Windows: []string{
				`auditpol /set /subcategory:"Other Object Access Events" /success:enable`,
				`wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true`,
			}},
		},
		{
			ID: "win-account-create", Name: "Create a local account", Technique: "T1136.001", Tactic: "Persistence",
			Platform: "windows", Level: Full, Sinks: []string{"Security"},
			Description: "Creates a local user with a random password, then deletes it. The password exists for a moment and appears in the process command line.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return winPredict(c.Windows,
					auditPart(hostcfg.GUIDUserAccountMgmt, "User Account Management", "User Account Management auditing is on (event 4720)", nil))
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				name := "tc" + strings.TrimPrefix(nonce, "tc")
				if _, err := e.R.Run(ctx, "net.exe", "user", name, randPassword(), "/add"); err != nil {
					return match.Spec{}, noCleanup, ErrSkip{"net user /add failed: " + err.Error()}
				}
				cleanup := func() error { _, err := e.R.Run(ctx, "net.exe", "user", name, "/delete"); return err }
				return match.Spec{Needles: []string{name}, EventID: []int{4720}}, cleanup, nil
			},
			Fix: Fix{Windows: []string{`auditpol /set /subcategory:"User Account Management" /success:enable`}},
		},
		{
			ID: "win-persist-runkey", Name: "Add a Run-key autostart value", Technique: "T1547.001", Tactic: "Persistence",
			Platform: "windows", Level: Full, Sinks: []string{"Sysmon", "Security"},
			Description: "Adds a value under HKCU Run that runs `cmd /c exit`, then deletes it.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return winPredict(c.Windows, sysmonPart)
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				key := `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
				if _, err := e.R.Run(ctx, "reg.exe", "add", key, "/v", nonce, "/t", "REG_SZ", "/d", "cmd.exe /c exit", "/f"); err != nil {
					return match.Spec{}, noCleanup, ErrSkip{"reg add failed: " + err.Error()}
				}
				cleanup := func() error { _, err := e.R.Run(ctx, "reg.exe", "delete", key, "/v", nonce, "/f"); return err }
				return match.Spec{Needles: []string{nonce}, EventID: []int{13, 12, 4657}}, cleanup, nil
			},
			Fix: Fix{Note: "Run keys are normally logged by Sysmon registry events (12/13) with a maintained configuration. Native auditing needs a SACL on the key."},
		},
		{
			ID: "win-persist-service", Name: "Create a service", Technique: "T1543.003", Tactic: "Persistence",
			Platform: "windows", Level: Full, Sinks: []string{"System", "Security"},
			Description: "Creates a disabled service pointing at `cmd.exe /c exit`, then deletes it.",
			Predict: func(c *hostcfg.Config) (hostcfg.Prediction, string) {
				return winPredict(c.Windows, func(w *hostcfg.Windows) (bool, bool, string) {
					return true, true, "the Service Control Manager writes event 7045 to the System log by default"
				})
			},
			Run: func(ctx context.Context, e *Env, nonce string) (match.Spec, func() error, error) {
				name := "tc" + nonce
				if _, err := e.R.Run(ctx, "sc.exe", "create", name, "binPath=", "cmd.exe /c exit", "start=", "disabled"); err != nil {
					return match.Spec{}, noCleanup, ErrSkip{"sc create failed: " + err.Error()}
				}
				cleanup := func() error { _, err := e.R.Run(ctx, "sc.exe", "delete", name); return err }
				return match.Spec{Needles: []string{name}, EventID: []int{7045, 4697}}, cleanup, nil
			},
			Fix: Fix{Windows: []string{`auditpol /set /subcategory:"Security System Extension" /success:enable`}},
		},
	}
}
