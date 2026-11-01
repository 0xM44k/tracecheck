//go:build windows

package watch

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/0xM44k/tracecheck/internal/runner"
)

// psQuote single-quotes s for PowerShell.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// EnableAuditing adds a success-read/write audit rule for Everyone to each
// decoy so Windows writes event 4663 when it is touched. The "File System"
// audit subcategory must also be enabled:
//
//	auditpol /set /subcategory:"File System" /success:enable
func EnableAuditing(ctx context.Context, r runner.Runner, paths []string) error {
	for _, p := range paths {
		script := "$p=" + psQuote(p) + ";$a=Get-Acl -LiteralPath $p;" +
			"$r=New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','ReadData,WriteData,AppendData','None','None','Success');" +
			"$a.AddAuditRule($r);Set-Acl -LiteralPath $p -AclObject $a"
		if _, err := r.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script); err != nil {
			return fmt.Errorf("setting audit rule on %s: %w", p, err)
		}
	}
	return nil
}

type evXML struct {
	System struct {
		RecordID int64 `xml:"EventRecordID"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

func parseEvents(raw string) []evXML {
	var out []evXML
	for _, chunk := range strings.SplitAfter(raw, "</Event>") {
		i := strings.Index(chunk, "<Event")
		if i < 0 {
			continue
		}
		var e evXML
		if xml.Unmarshal([]byte(chunk[i:]), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// Run polls the Security log for event 4663 on the decoys. Windows reports the
// access after it happens, so only "alert" and "kill" are possible here.
func Run(ctx context.Context, o Options) error {
	if o.Contain != ContainAlert && o.Contain != ContainKill {
		return fmt.Errorf("on Windows only --contain alert or kill is available (events arrive after the access)")
	}
	r := runner.Real{}
	if err := EnableAuditing(ctx, r, o.Paths); err != nil {
		return err
	}
	want := map[string]bool{}
	for _, p := range o.Paths {
		want[strings.ToLower(p)] = true
	}
	allow := map[string]bool{}
	for _, c := range o.AllowComm {
		allow[strings.ToLower(c)] = true
	}
	var last int64
	first := true
	for ctx.Err() == nil {
		out, err := r.Run(ctx, "wevtutil", "qe", "Security", "/q:*[System[(EventID=4663)]]", "/c:100", "/rd:true", "/f:xml")
		if err == nil {
			evs := parseEvents(string(out))
			for i := len(evs) - 1; i >= 0; i-- { // oldest first
				e := evs[i]
				if e.System.RecordID <= last {
					continue
				}
				last = e.System.RecordID
				if first {
					continue // history from before we started
				}
				d := map[string]string{}
				for _, kv := range e.Data {
					d[kv.Name] = kv.Value
				}
				obj := d["ObjectName"]
				if !want[strings.ToLower(obj)] {
					continue
				}
				proc := d["ProcessName"]
				base := strings.ToLower(proc[strings.LastIndexAny(proc, `\/`)+1:])
				if allow[base] {
					continue
				}
				pid64, _ := strconv.ParseInt(strings.TrimPrefix(d["ProcessId"], "0x"), 16, 64)
				a := Alert{Time: time.Now().UTC(), Decoy: obj, Event: "open", PID: int(pid64), Exe: proc, Comm: base,
					Cmdline: "user " + d["SubjectDomainName"] + `\` + d["SubjectUserName"], Action: "allowed"}
				if o.Contain == ContainKill && pid64 > 4 {
					if _, kerr := r.Run(ctx, "taskkill", "/PID", strconv.FormatInt(pid64, 10), "/F"); kerr == nil {
						a.Action = "killed"
					}
				}
				o.Emit(a)
			}
			first = false
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	return nil
}
