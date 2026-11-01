package report

import (
	"fmt"
	"html/template"
	"io"
	"strings"
)

var funcs = template.FuncMap{
	"join": strings.Join,
	"secs": func(ms int64) string {
		if ms <= 0 {
			return "–"
		}
		return fmt.Sprintf("%.1f s", float64(ms)/1000)
	},
}

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>tracecheck report</title>
<style>
:root{--bg:#f7f8fa;--fg:#14181f;--mut:#566072;--card:#fff;--line:#d9dee7;--ok:#0b7a43;--okbg:#dcf3e6;--bad:#b3261e;--badbg:#fbe3e1;--warn:#8a5a00;--warnbg:#fdf0d0;--info:#3b4a63;--infobg:#e6eaf1;--code:#eef1f6}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0e1116;--fg:#e6e9ef;--mut:#9aa4b5;--card:#161b22;--line:#2a313c;--ok:#5fd394;--okbg:#10301f;--bad:#ff8a80;--badbg:#3a1613;--warn:#f2c35d;--warnbg:#33260a;--info:#b5c0d6;--infobg:#212836;--code:#1d232d}}
:root[data-theme=dark]{--bg:#0e1116;--fg:#e6e9ef;--mut:#9aa4b5;--card:#161b22;--line:#2a313c;--ok:#5fd394;--okbg:#10301f;--bad:#ff8a80;--badbg:#3a1613;--warn:#f2c35d;--warnbg:#33260a;--info:#b5c0d6;--infobg:#212836;--code:#1d232d}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 56px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.1rem;margin:28px 0 10px}
.sub{color:var(--mut);margin:0 0 20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card b{display:block;font-size:1.6rem;line-height:1.1}.card span{color:var(--mut);font-size:.85rem}
.tools{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0 10px}
button{font:inherit;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:6px 12px;cursor:pointer}
button[aria-pressed=true]{background:var(--fg);color:var(--bg)}
button:focus-visible,summary:focus-visible{outline:2px solid #4c8dff;outline-offset:2px}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
table{width:100%;border-collapse:collapse;min-width:720px}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}
tr:last-child td{border-bottom:0}
.b{display:inline-block;padding:2px 9px;border-radius:999px;font-size:.78rem;font-weight:600}
.covered{background:var(--okbg);color:var(--ok)}.blind{background:var(--badbg);color:var(--bad)}
.unverifiable,.skipped,.error{background:var(--warnbg);color:var(--warn)}
.mut{color:var(--mut)}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85rem}
pre{background:var(--code);padding:10px 12px;border-radius:8px;overflow-x:auto;margin:6px 0}
details{margin:2px 0}summary{cursor:pointer;color:var(--info)}
.note{background:var(--infobg);color:var(--info);border-radius:8px;padding:8px 12px;margin:6px 0}
.dis{color:var(--bad);font-weight:600}
footer{color:var(--mut);margin-top:32px;font-size:.85rem}
</style></head><body><main>
<h1>tracecheck report</h1>
<p class="sub">{{.Host.OS}}/{{.Host.Arch}} · level {{.Level}} · {{.GeneratedAt.Format "2006-01-02 15:04 MST"}} · tracecheck {{.Version}}{{if not .Host.Elevated}} · <b>not elevated</b>, some checks could not run{{end}}</p>
<div class="cards" role="list">
<div class="card" role="listitem"><b>{{.Summary.Covered}}</b><span>covered</span></div>
<div class="card" role="listitem"><b>{{.Summary.Blind}}</b><span>blind</span></div>
<div class="card" role="listitem"><b>{{.Summary.Unverifiable}}</b><span>unverifiable</span></div>
<div class="card" role="listitem"><b>{{.Summary.Skipped}}</b><span>skipped</span></div>
<div class="card" role="listitem"><b>{{.Summary.Disagree}}</b><span>prediction disagreements</span></div>
</div>
<div class="tools" role="group" aria-label="Filter by status">
<button type="button" data-f="all" aria-pressed="true">All</button>
<button type="button" data-f="covered" aria-pressed="false">Covered</button>
<button type="button" data-f="blind" aria-pressed="false">Blind</button>
<button type="button" data-f="other" aria-pressed="false">Other</button>
<button type="button" id="theme" aria-pressed="false">Toggle theme</button>
</div>
<h2>Checks</h2>
<div class="scroll" role="region" aria-label="Check results" tabindex="0"><table>
<thead><tr><th>Status</th><th>Technique</th><th>Check</th><th>Seen in</th><th>Predicted</th><th>Latency</th></tr></thead><tbody>
{{range .Results}}<tr data-s="{{.Status}}">
<td><span class="b {{.Status}}">{{.Status}}</span></td>
<td><code>{{.Technique}}</code><br><span class="mut">{{.Tactic}}</span></td>
<td><b>{{.Name}}</b><br><span class="mut">{{.Description}}</span>
{{if .Detail}}<div class="note">{{.Detail}}</div>{{end}}
{{if .CleanupError}}<div class="note dis">Cleanup failed ({{.CleanupError}}). Remove by hand; marker {{.Nonce}}.</div>{{end}}
{{if or .Fix.Auditd .Fix.Windows .Fix.Note}}<details><summary>Configuration that records this</summary>
{{if .Fix.Auditd}}<pre>{{join .Fix.Auditd "\n"}}</pre>{{end}}{{if .Fix.Windows}}<pre>{{join .Fix.Windows "\n"}}</pre>{{end}}{{if .Fix.Note}}<p class="mut">{{.Fix.Note}}</p>{{end}}</details>{{end}}
{{range .Hits}}<details><summary>Evidence from {{.Sink}}</summary><pre>{{.Evidence}}</pre></details>{{end}}</td>
<td>{{range .Hits}}{{.Sink}} {{end}}{{if not .Hits}}–{{end}}</td>
<td>{{.Prediction}}{{if eq (printf "%s" .Agreement) "disagree"}} <span class="dis">(wrong)</span>{{end}}<br><span class="mut">{{.PredictionReason}}</span></td>
<td>{{secs .LatencyMS}}</td></tr>{{end}}
</tbody></table></div>
{{if .Config.Notes}}<h2>Notes</h2>{{range .Config.Notes}}<div class="note">{{.}}</div>{{end}}{{end}}
<footer>A check is "covered" only when the host's own log contained the unique marker of that check. "Blind" means it was searched for and not found within the wait window; it can also mean the log is delayed or rotated. This report is an audit aid, not a guarantee that a real intrusion would be detected.</footer>
</main>
<script>
(function(){var rows=document.querySelectorAll('tbody tr'),bs=document.querySelectorAll('[data-f]');
function f(v){rows.forEach(function(r){var s=r.getAttribute('data-s');r.hidden=!(v==='all'||s===v||(v==='other'&&s!=='covered'&&s!=='blind'))});
bs.forEach(function(b){b.setAttribute('aria-pressed',b.getAttribute('data-f')===v)})}
bs.forEach(function(b){b.addEventListener('click',function(){f(b.getAttribute('data-f'))})});
document.getElementById('theme').addEventListener('click',function(){var d=document.documentElement,c=d.getAttribute('data-theme');
var dark=c?c==='dark':matchMedia('(prefers-color-scheme: dark)').matches;d.setAttribute('data-theme',dark?'light':'dark')});})();
</script></body></html>`

var tpl = template.Must(template.New("page").Funcs(funcs).Parse(page))

// HTML writes the single-file report.
func HTML(w io.Writer, r *Report) error { return tpl.Execute(w, r) }
