package report

import (
	"fmt"
	"html/template"
	"os"
	"time"

	"vsm/internal/analyze"
	"vsm/internal/i18n"
	"vsm/internal/snapshot"
)

// htmlData is the view model passed to the HTML template.
type htmlData struct {
	R           *SessionReport
	L           map[string]string // translated UI labels
	Disclaimer  string
	FSAdded     int
	FSModified  int
	FSDeleted   int
	RegAdded    int
	RegModified int
	RegDeleted  int
	FSFootprint []snapshot.FSChange // changes inside the sandbox (the program itself)
	FSSystem    []snapshot.FSChange // changes outside the sandbox (possible OS noise)
}

// WriteHTML renders the bilingual-aware forensic report to path.
// WriteHTML формирует криминалистический отчёт по пути path.
func (r *SessionReport) WriteHTML(path string) error {
	lang := i18n.Normalize(r.Lang)
	keys := []string{
		"app.title", "app.subtitle", "section.summary", "section.process",
		"section.files", "section.registry", "section.timeline", "section.redirects",
		"label.added", "label.modified", "label.deleted", "label.pid", "label.exitcode",
		"label.duration", "label.integrity", "label.timedout", "label.yes", "label.no",
		"label.target", "label.sha256", "label.size", "label.path", "label.realpath",
		"label.envvar", "label.session", "label.generated", "label.regkey", "label.regvalue",
		"label.regtype", "label.regdata", "label.time", "label.event", "msg.nochanges",
		"section.network", "label.proto", "label.local", "label.remote", "label.state",
		"label.host", "label.service", "label.firstseen",
		"section.processes", "label.image", "label.lastseen", "label.role",
		"label.roottarget", "label.child",
		"section.verdict", "label.verdict", "label.score", "label.severity",
		"label.indicator", "label.detail",
		"section.footprint", "section.syschanges", "note.footprint", "note.syschanges",
	}
	labels := make(map[string]string, len(keys))
	for _, k := range keys {
		labels[k] = i18n.T(lang, k)
	}

	data := htmlData{R: r, L: labels, Disclaimer: i18n.T(lang, "disclaimer")}
	for _, c := range r.FSChanges {
		countChange(c.Type, &data.FSAdded, &data.FSModified, &data.FSDeleted)
		if r.InSandbox(c.Path) {
			data.FSFootprint = append(data.FSFootprint, c)
		} else {
			data.FSSystem = append(data.FSSystem, c)
		}
	}
	for _, c := range r.RegChanges {
		countChange(c.Type, &data.RegAdded, &data.RegModified, &data.RegDeleted)
	}

	tpl, err := template.New("report").Funcs(template.FuncMap{
		"humanSize": humanSize,
		"fmtTime":   func(tm time.Time) string { return tm.Format("2006-01-02 15:04:05") },
		"intended":  r.IntendedDestination,
		"t":         func(k string) string { return labels[k] },
		"sevText":   func(s analyze.Severity) string { return labels["sev."+string(s)] },
		"yesNo": func(b bool) string {
			if b {
				return labels["label.yes"]
			}
			return labels["label.no"]
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tpl.Execute(f, data)
}

func countChange(t snapshot.ChangeType, add, mod, del *int) {
	switch t {
	case snapshot.Added:
		*add++
	case snapshot.Modified:
		*mod++
	case snapshot.Deleted:
		*del++
	}
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="{{.R.Lang}}">
<head>
<meta charset="utf-8">
<title>{{t "app.title"}}</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}
 header{background:#1b6ec2;color:#fff;padding:20px 28px}
 header h1{margin:0;font-size:20px} header p{margin:6px 0 0;opacity:.9;font-size:13px}
 main{padding:20px 28px;max-width:1200px}
 h2{border-bottom:2px solid #1b6ec2;padding-bottom:6px;margin-top:34px;font-size:16px}
 table{border-collapse:collapse;width:100%;margin-top:10px;font-size:13px}
 th,td{border:1px solid #2a2f3a;padding:6px 9px;text-align:left;vertical-align:top;word-break:break-all}
 th{background:#1a1d24}
 tr:nth-child(even){background:#161922}
 .added{color:#4caf50;font-weight:600}
 .modified{color:#ffb300;font-weight:600}
 .deleted{color:#ef5350;font-weight:600}
 .cards{display:flex;gap:14px;flex-wrap:wrap;margin-top:12px}
 .card{background:#1a1d24;border:1px solid #2a2f3a;border-radius:8px;padding:14px 18px;min-width:150px}
 .card .n{font-size:24px;font-weight:700} .card .t{font-size:12px;opacity:.8}
 .mono{font-family:Consolas,monospace}
 .note{background:#332b00;border-left:4px solid #ffb300;padding:10px 14px;font-size:13px;margin-top:14px}
 .virt{color:#1b9ee0;font-size:12px}
 .pre{white-space:pre-line}
 .verdict{padding:16px 20px;border-radius:8px;margin-top:12px;font-size:15px;font-weight:600}
 .verdict-clean{background:#16321a;border-left:6px solid #4caf50}
 .verdict-suspicious{background:#352f12;border-left:6px solid #ffb300}
 .verdict-dangerous{background:#3a1a1a;border-left:6px solid #ef5350}
 .sev-high{color:#ef5350;font-weight:700}
 .sev-medium{color:#ffb300;font-weight:700}
 .sev-low{color:#42a5f5;font-weight:700}
 .sev-info{color:#9e9e9e;font-weight:700}
 footer{padding:18px 28px;font-size:12px;opacity:.6}
</style>
</head>
<body>
<header>
 <h1>{{t "app.title"}}</h1>
 <p>{{t "app.subtitle"}}</p>
</header>
<main>

 <h2>{{t "section.verdict"}}</h2>
 <div class="verdict verdict-{{.R.Analysis.Level}}">
  {{t "label.verdict"}}: {{.R.Analysis.LevelText}} &nbsp;·&nbsp; {{t "label.score"}}: {{.R.Analysis.Score}}/100
 </div>
 {{if .R.Analysis.Indicators}}
 <table>
  <tr><th>{{t "label.severity"}}</th><th>{{t "label.indicator"}}</th><th>{{t "label.detail"}}</th></tr>
  {{range .R.Analysis.Indicators}}<tr>
   <td class="sev-{{.Severity}}">{{sevText .Severity}}</td>
   <td>{{.Title}}</td>
   <td class="mono pre">{{.Detail}}</td>
  </tr>{{end}}
 </table>
 {{end}}

 <h2>{{t "section.summary"}}</h2>
 <table>
  <tr><th>{{t "label.target"}}</th><td class="mono">{{.R.Target.Path}}</td></tr>
  <tr><th>{{t "label.sha256"}}</th><td class="mono">{{.R.Target.SHA256}}</td></tr>
  <tr><th>{{t "label.size"}}</th><td>{{humanSize .R.Target.Size}}</td></tr>
  <tr><th>{{t "label.session"}}</th><td class="mono">{{.R.SessionDir}}</td></tr>
  <tr><th>{{t "label.generated"}}</th><td>{{fmtTime .R.GeneratedAt}}</td></tr>
 </table>
 <div class="cards">
  <div class="card"><div class="n added">{{.FSAdded}}</div><div class="t">{{t "label.added"}} — {{t "section.files"}}</div></div>
  <div class="card"><div class="n modified">{{.FSModified}}</div><div class="t">{{t "label.modified"}} — {{t "section.files"}}</div></div>
  <div class="card"><div class="n deleted">{{.FSDeleted}}</div><div class="t">{{t "label.deleted"}} — {{t "section.files"}}</div></div>
  <div class="card"><div class="n added">{{.RegAdded}}</div><div class="t">{{t "label.added"}} — {{t "section.registry"}}</div></div>
  <div class="card"><div class="n modified">{{.RegModified}}</div><div class="t">{{t "label.modified"}} — {{t "section.registry"}}</div></div>
  <div class="card"><div class="n deleted">{{.RegDeleted}}</div><div class="t">{{t "label.deleted"}} — {{t "section.registry"}}</div></div>
 </div>

 <h2>{{t "section.process"}}</h2>
 <table>
  <tr><th>{{t "label.pid"}}</th><td>{{.R.Process.PID}}</td></tr>
  <tr><th>{{t "label.exitcode"}}</th><td>{{.R.Process.ExitCode}}</td></tr>
  <tr><th>{{t "label.integrity"}}</th><td>{{.R.Process.IntegrityMode}}</td></tr>
  <tr><th>{{t "label.duration"}}</th><td>{{.R.Process.Duration}}</td></tr>
  <tr><th>{{t "label.timedout"}}</th><td>{{yesNo .R.Process.TimedOut}}</td></tr>
 </table>

 <h2>{{t "section.processes"}}</h2>
 {{if .R.Processes}}
 <table>
  <tr><th>#</th><th>{{t "label.pid"}}</th><th>{{t "label.role"}}</th><th>{{t "label.image"}}</th><th>{{t "label.firstseen"}}</th><th>{{t "label.lastseen"}}</th></tr>
  {{range $i, $p := .R.Processes}}<tr>
   <td>{{$i}}</td>
   <td>{{$p.PID}}</td>
   <td>{{if $p.IsRoot}}<span class="modified">{{t "label.roottarget"}}</span>{{else}}<span class="added">{{t "label.child"}}</span>{{end}}</td>
   <td class="mono">{{$p.Image}}</td>
   <td>{{fmtTime $p.FirstSeen}}</td>
   <td>{{fmtTime $p.LastSeen}}</td>
  </tr>{{end}}
 </table>
 {{else}}<p>{{t "msg.nochanges"}}</p>{{end}}

 <h2>{{t "section.redirects"}}</h2>
 <table>
  <tr><th>{{t "label.envvar"}}</th><th>{{t "label.realpath"}}</th><th>{{t "label.path"}} (sandbox)</th></tr>
  {{range .R.Redirects}}<tr><td class="mono">%{{.EnvVar}}%</td><td class="mono">{{.Real}}</td><td class="mono">{{.Virtual}}</td></tr>{{end}}
 </table>

 <h2>{{t "section.footprint"}}</h2>
 <div class="note">{{t "note.footprint"}}</div>
 {{template "fstable" .FSFootprint}}

 <h2>{{t "section.syschanges"}}</h2>
 <div class="note">{{t "note.syschanges"}}</div>
 {{template "fstable" .FSSystem}}

 <h2>{{t "section.registry"}}</h2>
 {{if .R.RegChanges}}
 <table>
  <tr><th>#</th><th>{{t "label.added"}}/{{t "label.modified"}}/{{t "label.deleted"}}</th><th>{{t "label.regkey"}}</th><th>{{t "label.regvalue"}}</th><th>{{t "label.regtype"}}</th><th>{{t "label.regdata"}}</th></tr>
  {{range $i, $c := .R.RegChanges}}<tr>
   <td>{{$i}}</td>
   <td class="{{$c.Type}}">{{$c.Type}}</td>
   <td class="mono">{{$c.KeyPath}}</td>
   <td class="mono">{{$c.ValueName}}</td>
   <td>{{if $c.After}}{{$c.After.Type}}{{else if $c.Before}}{{$c.Before.Type}}{{end}}</td>
   <td class="mono">{{if $c.After}}{{$c.After.Data}}{{else if $c.Before}}{{$c.Before.Data}}{{end}}</td>
  </tr>{{end}}
 </table>
 {{else}}<p>{{t "msg.nochanges"}}</p>{{end}}

 <h2>{{t "section.timeline"}}</h2>
 {{if .R.Timeline}}
 <table>
  <tr><th>#</th><th>{{t "label.time"}}</th><th>{{t "label.event"}}</th><th>{{t "label.path"}}</th></tr>
  {{range $i, $e := .R.Timeline}}<tr><td>{{$i}}</td><td>{{fmtTime $e.Time}}</td><td>{{$e.Op}}</td><td class="mono">{{$e.Path}}</td></tr>{{end}}
 </table>
 {{else}}<p>{{t "msg.nochanges"}}</p>{{end}}

 <h2>{{t "section.network"}}</h2>
 {{if .R.Network}}
 <table>
  <tr><th>#</th><th>{{t "label.proto"}}</th><th>{{t "label.pid"}}</th><th>{{t "label.local"}}</th><th>{{t "label.remote"}}</th><th>{{t "label.state"}}</th><th>{{t "label.host"}}</th><th>{{t "label.service"}}</th></tr>
  {{range $i, $c := .R.Network}}<tr>
   <td>{{$i}}</td>
   <td>{{$c.Proto}}</td>
   <td>{{$c.PID}}</td>
   <td class="mono">{{$c.LocalAddr}}:{{$c.LocalPort}}</td>
   <td class="mono">{{if $c.RemoteAddr}}{{$c.RemoteAddr}}:{{$c.RemotePort}}{{end}}</td>
   <td>{{$c.State}}</td>
   <td class="mono">{{$c.Host}}</td>
   <td>{{$c.Service}}</td>
  </tr>{{end}}
 </table>
 {{else}}<p>{{t "msg.nochanges"}}</p>{{end}}

 <div class="note">{{.Disclaimer}}</div>
</main>
<footer>{{.R.Tool}} {{.R.Version}}</footer>
</body>
</html>
{{define "fstable"}}
 {{if .}}
 <table>
  <tr><th>#</th><th>{{t "label.added"}}/{{t "label.modified"}}/{{t "label.deleted"}}</th><th>{{t "label.path"}}</th><th>{{t "label.size"}}</th><th>{{t "label.sha256"}}</th></tr>
  {{range $i, $c := .}}<tr>
   <td>{{$i}}</td>
   <td class="{{$c.Type}}">{{$c.Type}}</td>
   <td class="mono">{{$c.Path}}{{$d := intended $c.Path}}{{if $d}}<br><span class="virt">→ {{$d}}</span>{{end}}</td>
   <td>{{if $c.After}}{{humanSize $c.After.Size}}{{end}}</td>
   <td class="mono">{{if $c.After}}{{$c.After.SHA256}}{{end}}</td>
  </tr>{{end}}
 </table>
 {{else}}<p>{{t "msg.nochanges"}}</p>{{end}}
{{end}}`
