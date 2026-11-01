// Command tracecheck tells you whether a Linux or Windows host really records
// the attack techniques you think it records, by performing harmless,
// reversible versions of them and looking for the evidence in the host's own
// logs. It can also place decoy files and alert, optionally containing, when
// something touches them.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/0xM44k/tracecheck/internal/canary"
	"github.com/0xM44k/tracecheck/internal/hostcfg"
	"github.com/0xM44k/tracecheck/internal/monitor"
	"github.com/0xM44k/tracecheck/internal/report"
	"github.com/0xM44k/tracecheck/internal/rules"
	"github.com/0xM44k/tracecheck/internal/runner"
	"github.com/0xM44k/tracecheck/internal/sink"
	"github.com/0xM44k/tracecheck/internal/verify"
	"github.com/0xM44k/tracecheck/internal/watch"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "0.1.0"

const usage = `tracecheck ` + "%s" + ` — does this host really log what you think it logs?

Usage:
  tracecheck list     [--level safe|full]
  tracecheck inspect  [--format text|json]
  tracecheck verify   [--level safe|full] [--yes] [--dry-run] [--only ID,ID] [--timeout 12s]
                      [--format text|json|html] [--out FILE] [--fail-on-blind] [--hostname]
  tracecheck rules    [--from report.json | --missing-only] [--only ID,ID]
  tracecheck watch    [--dir DIR] [--contain alert|deny|suspend|kill] [--allow-comm a,b]
                      [--log FILE] [--syslog] [--duration 10m] [--keep]
  tracecheck monitor  [--state FILE] [--interval 30m] [--once] [--alert-log FILE] [--only ID,ID]
  tracecheck version

verify performs real but harmless actions on this machine. 'safe' only runs
harmless programs, opens files and makes a loopback connection. 'full' also
creates and removes a cron file, a service, an account or a scheduled task and
needs --yes. Run it only on machines you are allowed to test.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, Version)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var code int
	switch cmd {
	case "version", "--version", "-v":
		fmt.Println("tracecheck", Version, runtime.GOOS+"/"+runtime.GOARCH)
	case "list":
		code = cmdList(args)
	case "inspect":
		code = cmdInspect(args)
	case "verify":
		code = cmdVerify(args)
	case "rules":
		code = cmdRules(args)
	case "watch":
		code = cmdWatch(args)
	case "monitor":
		code = cmdMonitor(args)
	case "help", "--help", "-h":
		fmt.Printf(usage, Version)
	default:
		fmt.Fprintf(os.Stderr, "tracecheck: unknown command %q\n\n", cmd)
		fmt.Fprintf(os.Stderr, usage, Version)
		code = 2
	}
	os.Exit(code)
}

func fail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "tracecheck: "+format+"\n", a...)
	return 2
}

func parseLevel(s string) (canary.Level, error) {
	switch strings.ToLower(s) {
	case "safe", "":
		return canary.Safe, nil
	case "full":
		return canary.Full, nil
	}
	return 0, fmt.Errorf("unknown level %q (use safe or full)", s)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func elevated(ctx context.Context, r runner.Runner) bool {
	if runtime.GOOS == "windows" {
		_, err := r.Run(ctx, "net", "session")
		return err == nil
	}
	return os.Geteuid() == 0
}

func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	lv := fs.String("level", "full", "safe or full")
	fs.Parse(args)
	level, err := parseLevel(*lv)
	if err != nil {
		return fail("%v", err)
	}
	for _, c := range verify.Select(runtime.GOOS, verify.Options{Level: level}) {
		fmt.Printf("%-22s %-10s %-5s %s\n    %s\n", c.ID, c.Technique, c.Level, c.Name, c.Description)
	}
	return 0
}

func cmdInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	format := fs.String("format", "text", "text or json")
	fs.Parse(args)
	ctx := context.Background()
	cfg := hostcfg.Collect(ctx, runner.Real{}, hostcfg.RealEnv(), runtime.GOOS)
	if *format == "json" {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		e.Encode(cfg)
		return 0
	}
	fmt.Printf("platform: %s (elevated: %v)\n", cfg.OS, elevated(ctx, runner.Real{}))
	if l := cfg.Linux; l != nil {
		live, why := l.AuditLive()
		fmt.Printf("kernel audit enabled: %d, daemon pid: %d, lost events: %d, backlog limit: %d\n", l.AuditEnabled, l.AuditDaemonPID, l.AuditLost, l.AuditBacklogLimit)
		fmt.Printf("audit log: %s (readable: %v)  recording expected: %v %s\n", l.AuditLogPath, l.AuditLogReadable, live, why)
		fmt.Printf("loaded audit rules: %d\n", len(l.Rules))
		for _, r := range l.Rules {
			fmt.Println("   ", r)
		}
		fmt.Printf("journald: present %v, persistent %v; syslog daemon: %q\n", l.JournalctlPresent, l.JournaldPersistent, l.SyslogDaemon)
	}
	if w := cfg.Windows; w != nil {
		fmt.Printf("audit policy read: %v (%d subcategories)\n", w.AuditPolRead, len(w.AuditPol)/2)
		fmt.Printf("process creation command line: %v, PowerShell script block logging: %v, module logging: %v\n", w.ProcCmdLine, w.ScriptBlock, w.ModuleLogging)
		fmt.Printf("Sysmon installed: %v, running: %v\n", w.SysmonInstalled, w.SysmonRunning)
		for ch, on := range w.Channels {
			fmt.Printf("channel %-45s enabled: %v\n", ch, on)
		}
	}
	for _, n := range cfg.Notes {
		fmt.Println("note:", n)
	}
	fmt.Println("\nPredicted from configuration (verify confirms these against real events):")
	for _, c := range verify.Select(runtime.GOOS, verify.Options{Level: canary.Full}) {
		p, why := c.Predict(cfg)
		fmt.Printf("  %-14s %-10s %-22s %s\n", p, c.Technique, c.ID, why)
	}
	return 0
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	lv := fs.String("level", "safe", "safe or full")
	yes := fs.Bool("yes", false, "confirm that full-level checks may create and remove real objects")
	dry := fs.Bool("dry-run", false, "print what would run and stop")
	only := fs.String("only", "", "comma-separated check IDs")
	timeout := fs.Duration("timeout", 12*time.Second, "how long to wait for each event to show up")
	format := fs.String("format", "text", "text, json or html")
	out := fs.String("out", "", "write the report to this file instead of stdout")
	failBlind := fs.Bool("fail-on-blind", false, "exit 1 if any check is blind")
	host := fs.Bool("hostname", false, "include the host name in the report")
	fs.Parse(args)

	level, err := parseLevel(*lv)
	if err != nil {
		return fail("%v", err)
	}
	opts := verify.Options{Level: level, Only: splitList(*only), Timeout: *timeout, PID: os.Getpid(), TmpDir: os.TempDir()}
	cs := verify.Select(runtime.GOOS, opts)
	if len(cs) == 0 {
		return fail("no checks match on %s", runtime.GOOS)
	}
	fmt.Fprintf(os.Stderr, "tracecheck will run %d check(s) on this machine (level %s):\n", len(cs), level)
	for _, c := range cs {
		fmt.Fprintf(os.Stderr, "  %-22s %-10s %s\n      %s\n", c.ID, c.Technique, c.Name, c.Description)
	}
	if *dry {
		return 0
	}
	if level == canary.Full && !*yes {
		return fail("level full creates and removes real objects (accounts, services, scheduled tasks, files in system folders); add --yes to confirm, or use --dry-run")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r := runner.Real{}
	cfg := hostcfg.Collect(ctx, r, hostcfg.RealEnv(), runtime.GOOS)
	var auditLog string
	if cfg.Linux != nil {
		auditLog = cfg.Linux.AuditLogPath
	}
	sinks := sink.ForOS(runtime.GOOS, auditLog, r)
	env := &canary.Env{R: r, PID: os.Getpid(), TmpDir: os.TempDir()}
	results, sum := verify.Run(ctx, runtime.GOOS, cfg, sinks, env, opts)

	rep := &report.Report{Schema: report.Schema, Tool: "tracecheck", Version: Version, GeneratedAt: time.Now().UTC(),
		Host:  report.Host{OS: runtime.GOOS, Arch: runtime.GOARCH, Elevated: elevated(ctx, r)},
		Level: level.String(), Config: cfg, Results: results, Summary: sum}
	if *host {
		rep.Host.Hostname, _ = os.Hostname()
	}
	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return fail("%v", err)
		}
		defer f.Close()
		w = f
	}
	switch *format {
	case "json":
		err = report.JSON(w, rep)
	case "html":
		err = report.HTML(w, rep)
	case "text":
		report.Text(w, rep)
	default:
		return fail("unknown format %q", *format)
	}
	if err != nil {
		return fail("%v", err)
	}
	if *out != "" {
		fmt.Fprintf(os.Stderr, "report written to %s\n", *out)
	}
	if sum.Errored > 0 {
		return 2
	}
	if *failBlind && sum.Blind > 0 {
		return 1
	}
	return 0
}

func cmdRules(args []string) int {
	fs := flag.NewFlagSet("rules", flag.ExitOnError)
	from := fs.String("from", "", "a verify --format json report; emit fixes for its blind checks")
	missing := fs.Bool("missing-only", false, "emit fixes only for checks the configuration predicts are not recorded")
	only := fs.String("only", "", "comma-separated check IDs")
	fs.Parse(args)
	cs := canary.All(runtime.GOOS)
	var want map[string]bool
	switch {
	case *from != "":
		b, err := os.ReadFile(*from)
		if err != nil {
			return fail("%v", err)
		}
		var rep report.Report
		if err := json.Unmarshal(b, &rep); err != nil {
			return fail("%s: %v", *from, err)
		}
		want = map[string]bool{}
		for _, r := range rep.Results {
			if r.Status == verify.Blind {
				want[r.ID] = true
			}
		}
	case *missing:
		cfg := hostcfg.Collect(context.Background(), runner.Real{}, hostcfg.RealEnv(), runtime.GOOS)
		want = map[string]bool{}
		for _, c := range cs {
			if p, _ := c.Predict(cfg); p != hostcfg.PredSeen {
				want[c.ID] = true
			}
		}
	}
	if *only != "" {
		sel := map[string]bool{}
		for _, id := range splitList(*only) {
			sel[strings.ToLower(id)] = true
		}
		if want == nil {
			want = map[string]bool{}
			for _, c := range cs {
				want[c.ID] = true
			}
		}
		for id := range want {
			if !sel[strings.ToLower(id)] {
				delete(want, id)
			}
		}
	}
	fmt.Print(rules.Generate(runtime.GOOS, Version, cs, want))
	return 0
}

func cmdWatch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	home, _ := os.UserHomeDir()
	dir := fs.String("dir", filepath.Join(home, ".tracecheck", "decoys"), "directory to place decoy files in")
	contain := fs.String("contain", "alert", "alert, deny (refuse the open), suspend (deny and SIGSTOP) or kill (deny and SIGKILL); Windows: alert or kill")
	allow := fs.String("allow-comm", "", "process names that may touch decoys without an alert (for example a backup agent)")
	logf := fs.String("log", "", "append alerts to this file as JSON lines")
	sys := fs.Bool("syslog", false, "also send alerts to syslog")
	dur := fs.Duration("duration", 0, "stop after this long (0 = until interrupted)")
	keep := fs.Bool("keep", false, "leave the decoy files in place on exit")
	fs.Parse(args)
	if !watch.ValidContain(*contain) {
		return fail("unknown --contain %q", *contain)
	}
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return fail("watch needs root on Linux (fanotify)")
	}
	paths, err := watch.Deploy(*dir)
	if err != nil {
		return fail("%v", err)
	}
	if !*keep {
		defer watch.Remove(paths)
	}
	var extra func(watch.Alert)
	if *sys {
		if extra, err = watch.SyslogExtra(); err != nil {
			return fail("%v", err)
		}
	}
	em, err := watch.NewEmitter(*logf, os.Stdout, extra)
	if err != nil {
		return fail("%v", err)
	}
	defer em.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *dur > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *dur)
		defer cancel()
	}
	fmt.Fprintf(os.Stderr, "watching %d decoy file(s) in %s, containment: %s. Ctrl-C to stop.\n", len(paths), *dir, *contain)
	for _, p := range paths {
		fmt.Fprintln(os.Stderr, "  ", p)
	}
	if err := watch.Run(ctx, watch.Options{Paths: paths, Contain: *contain, AllowComm: splitList(*allow), Emit: em.Emit}); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "stopped: %d alert(s), %d contained\n", em.Count, em.Denied)
	return 0
}

func cmdMonitor(args []string) int {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	state := fs.String("state", "tracecheck-state.json", "where to remember the last result of each check")
	every := fs.Duration("interval", 30*time.Minute, "time between runs")
	once := fs.Bool("once", false, "run once and exit (exit 1 if a regression was found)")
	alertLog := fs.String("alert-log", "", "append alerts to this file as JSON lines")
	only := fs.String("only", "", "comma-separated check IDs")
	timeout := fs.Duration("timeout", 12*time.Second, "how long to wait for each event")
	fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r := runner.Real{}
	opts := verify.Options{Level: canary.Safe, Only: splitList(*only), Timeout: *timeout, PID: os.Getpid(), TmpDir: os.TempDir()}
	var lf *os.File
	if *alertLog != "" {
		var err error
		if lf, err = os.OpenFile(*alertLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err != nil {
			return fail("%v", err)
		}
		defer lf.Close()
	}
	for {
		cfg := hostcfg.Collect(ctx, r, hostcfg.RealEnv(), runtime.GOOS)
		var auditLog string
		if cfg.Linux != nil {
			auditLog = cfg.Linux.AuditLogPath
		}
		env := &canary.Env{R: r, PID: os.Getpid(), TmpDir: os.TempDir()}
		results, sum := verify.Run(ctx, runtime.GOOS, cfg, sink.ForOS(runtime.GOOS, auditLog, r), env, opts)
		prev, err := monitor.Load(*state)
		if err != nil {
			return fail("reading state: %v", err)
		}
		alerts, next := monitor.Compare(prev, results, time.Now())
		for _, a := range alerts {
			fmt.Printf("%s %s %s (%s): %s -> %s\n", a.Time.Format(time.RFC3339), strings.ToUpper(a.Kind), a.ID, a.Tech, a.From, a.To)
			if lf != nil {
				b, _ := json.Marshal(a)
				lf.Write(append(b, '\n'))
			}
		}
		if err := monitor.Save(*state, next); err != nil {
			return fail("saving state: %v", err)
		}
		fmt.Printf("%s run: %d covered, %d blind, %d unverifiable, %d skipped; %d change(s)\n",
			time.Now().Format(time.RFC3339), sum.Covered, sum.Blind, sum.Unverifiable, sum.Skipped, len(alerts))
		if *once {
			for _, a := range alerts {
				if a.Kind == "regression" {
					return 1
				}
			}
			return 0
		}
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(*every):
		}
	}
}
