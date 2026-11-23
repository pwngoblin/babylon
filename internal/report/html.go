package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
)

// The HTML report is a single self-contained file: embedded CSS, inline SVG,
// no scripts and no external requests (enforced by a CSP meta tag). All scanned
// data is escaped by html/template.
//
// Extending it: the report is data-driven. Priority actions come from
// Report.Groups, host sections from Report.Hosts, and the findings appendix is
// one section per Finding.Family, so a new check or engine shows up with no
// template change. To give a family a nicer title or blurb, add it to
// familyInfo below.

// familyInfo optionally decorates a finding family. Unknown families still
// render, using their own name.
var familyInfo = map[string]struct{ Title, Blurb string }{
	"Vulnerable software (version match)": {"Vulnerable software (version match)",
		"Detected from the reported version string. Distribution backports can make these false alarms; confidence says how much to trust each."},
}

type htmlView struct {
	R        *Report
	Cards    []card
	Bar      []barSeg
	Plan     []planItem
	Families []familyView
	Hosts    []hostView
	Skipped  []SkippedItem
	Checks   []kv
	Notes    []string
}

type card struct {
	Label string
	N     int
	Class string
}

type barSeg struct {
	Label string
	N     int
	Pct   float64
	X     float64
	Class string
}

type kv struct {
	K string
	V int
}

type planItem struct {
	Rank int
	Group
	Resolves int
	Score    string
}

type familyView struct {
	Name, Blurb string
	Findings    []Finding
}

type hostView struct {
	Host
	Findings []Finding
}

func buildView(r *Report) *htmlView {
	v := &htmlView{R: r, Skipped: r.Coverage.Skipped}
	kev := 0
	for _, f := range r.Findings {
		if f.KEV {
			kev++
		}
	}
	v.Cards = append(v.Cards, card{"KEV exploited", kev, "kev"})
	total := 0
	for _, s := range sevOrder {
		total += r.Summary.FindingsBySev[s]
	}
	x := 0.0
	for _, s := range sevOrder {
		n := r.Summary.FindingsBySev[s]
		v.Cards = append(v.Cards, card{strings.ToUpper(s[:1]) + s[1:], n, s})
		if total > 0 && n > 0 {
			p := float64(n) * 100 / float64(total)
			v.Bar = append(v.Bar, barSeg{s, n, p, x, s})
			x += p
		}
	}
	for i, g := range r.Groups {
		v.Plan = append(v.Plan, planItem{Rank: i + 1, Group: g, Resolves: len(g.CVEs)})
	}
	byFam := map[string][]Finding{}
	byHost := map[string][]Finding{}
	for _, f := range r.Findings {
		fam := f.Family
		if fam == "" {
			fam = "Other findings"
		}
		byFam[fam] = append(byFam[fam], f)
		byHost[f.Host] = append(byHost[f.Host], f)
	}
	fams := make([]string, 0, len(byFam))
	for k := range byFam {
		fams = append(fams, k)
	}
	sort.Strings(fams)
	for _, k := range fams {
		fv := familyView{Name: k, Findings: byFam[k]}
		if info, ok := familyInfo[k]; ok {
			fv.Name, fv.Blurb = info.Title, info.Blurb
		}
		v.Families = append(v.Families, fv)
	}
	for _, h := range r.Hosts {
		v.Hosts = append(v.Hosts, hostView{Host: h, Findings: byHost[h.Address]})
	}
	for k, n := range r.Coverage.CheckRuns {
		v.Checks = append(v.Checks, kv{k, n})
	}
	sort.Slice(v.Checks, func(i, j int) bool { return v.Checks[i].K < v.Checks[j].K })
	if r.Summary.PossibleHidden {
		v.Notes = append(v.Notes, fmt.Sprintf("Accuracy mode %q hides %d unverified (possible) findings from this report; they remain stored and counted.", r.Scan.Accuracy, r.Summary.Possible))
	}
	if r.Summary.JobsFailed > 0 {
		v.Notes = append(v.Notes, fmt.Sprintf("%d scan job(s) failed, so coverage is incomplete. See the appendix.", r.Summary.JobsFailed))
	}
	return v
}

// WriteHTML renders the self-contained HTML report.
func WriteHTML(w io.Writer, r *Report) error {
	return htmlTpl.Execute(w, buildView(r))
}

func f1(p *float64) string {
	if p == nil {
		return "–"
	}
	return fmt.Sprintf("%.1f", *p)
}

func pct(p *float64) string {
	if p == nil {
		return "–"
	}
	return fmt.Sprintf("%.1f%%", *p*100)
}

var htmlTpl = template.Must(template.New("r").Funcs(template.FuncMap{
	"f1":    f1,
	"pct":   pct,
	"join":  strings.Join,
	"title": func(s string) string { return strings.ToUpper(s[:min(1, len(s))]) + s[min(1, len(s)):] },
	"cves": func(c []string, n int) string {
		if len(c) <= n {
			return strings.Join(c, ", ")
		}
		return fmt.Sprintf("%s, … +%d more", strings.Join(c[:n], ", "), len(c)-n)
	},
	"port": func(p int, proto string) string {
		if p == 0 {
			return ""
		}
		return fmt.Sprintf("%d/%s", p, proto)
	},
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Babylon report – scan {{.R.Scan.ID}}</title>
<style>
:root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--line:#d8dee4;--card:#f6f8fa;--crit:#8b1a1a;--high:#d1242f;--med:#d97706;--low:#2563eb;--info:#6b7280;--kev:#6d28d9}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#9198a1;--line:#30363d;--card:#161b22;--crit:#ff7b72;--high:#f85149;--med:#e3a008;--low:#58a6ff;--info:#8b949e;--kev:#b794f6}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 64px}
h1{margin:0 0 4px}h2{margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}h3{margin:20px 0 8px}
.mut{color:var(--mut)}.mono,code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;border-top:4px solid var(--info)}
.card b{display:block;font-size:26px}.card.kev{border-top-color:var(--kev)}.card.critical{border-top-color:var(--crit)}.card.high{border-top-color:var(--high)}.card.medium{border-top-color:var(--med)}.card.low{border-top-color:var(--low)}
.bar{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--line)}.bar i{display:block}
.s-critical{background:var(--crit)}.s-high{background:var(--high)}.s-medium{background:var(--med)}.s-low{background:var(--low)}.s-info{background:var(--info)}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:600;font-size:13px}
.badge{display:inline-block;padding:0 7px;border-radius:10px;font-size:12px;font-weight:600;color:#fff;background:var(--info)}
.badge.critical{background:var(--crit)}.badge.high{background:var(--high)}.badge.medium{background:var(--med)}.badge.low{background:var(--low)}.badge.kev{background:var(--kev)}
.badge.conf{background:transparent;color:var(--mut);border:1px solid var(--line)}
details{border:1px solid var(--line);border-radius:8px;margin:8px 0;background:var(--card)}summary{cursor:pointer;padding:8px 12px;list-style-position:inside}
details>div{padding:4px 14px 12px}pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;max-height:320px;overflow:auto}
.note{background:var(--card);border-left:4px solid var(--med);padding:8px 12px;margin:10px 0}
.legend span{margin-right:14px;font-size:13px}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px}
@media print{details{break-inside:avoid}details>div{display:block}body{font-size:12px}}
</style></head><body><main>
<h1>Babylon vulnerability report</h1>
<div class="mut">Scan {{.R.Scan.ID}}{{if .R.Scan.Name}} – {{.R.Scan.Name}}{{end}} · template {{.R.Scan.Template}} · status {{.R.Scan.Status}} · accuracy {{.R.Scan.Accuracy}}</div>
<div class="mut">Targets: <span class="mono">{{join .R.Scan.Targets ", "}}</span></div>
<div class="mut">{{if .R.Scan.StartedAt}}Started {{.R.Scan.StartedAt}}{{end}}{{if .R.Scan.FinishedAt}} · finished {{.R.Scan.FinishedAt}}{{end}} · generated {{.R.GeneratedAt}}</div>

<h2>Executive summary</h2>
<div>{{.R.Summary.Hosts}} host(s), {{.R.Summary.Services}} service(s). {{.R.Summary.Verified}} verified finding(s), {{.R.Summary.Possible}} possible, {{.R.Summary.Informational}} informational.</div>
{{range .Notes}}<div class="note">{{.}}</div>{{end}}
<div class="cards">{{range .Cards}}<div class="card {{.Class}}"><b>{{.N}}</b>{{.Label}}</div>{{end}}</div>
{{if .Bar}}<div class="bar" role="img" aria-label="Severity distribution">{{range .Bar}}<i class="s-{{.Class}}" style="width:{{printf "%.2f" .Pct}}%" title="{{.Label}}: {{.N}}"></i>{{end}}</div>
<div class="legend mut">{{range .Bar}}<span><i class="s-{{.Class}}"></i>{{.Label}} {{.N}}</span>{{end}}</div>{{end}}

<h2>Priority action plan</h2>
{{if .Plan}}<p class="mut">Each row is one fix that resolves several CVEs. Ordered by known exploitation (KEV), confidence, then CVSS.</p>
<table><tr><th>#</th><th>Fix</th><th>Where</th><th>Resolves</th><th>Worst</th></tr>
{{range .Plan}}<tr><td>{{.Rank}}</td><td><b>{{.Title}}</b><br>{{.Fix}}<br><span class="badge conf">{{.Confidence}}</span></td>
<td class="mono">{{.Host}}{{if .Port}}:{{.Port}}/{{.Proto}}{{end}}</td>
<td>{{.Resolves}} CVE{{if ne .Resolves 1}}s{{end}}{{if .KEVCount}} <span class="badge kev">{{.KEVCount}} KEV</span>{{end}}</td>
<td>CVSS {{f1 .MaxCVSS}}<br>EPSS {{pct .MaxEPSS}}</td></tr>
<tr><td></td><td colspan="4" class="mut mono">{{cves .CVEs 12}}</td></tr>{{end}}</table>
{{else}}<p class="mut">No multi-CVE root causes found.</p>{{end}}

<h2>Hosts</h2>
{{range .Hosts}}<details><summary><b class="mono">{{.Address}}</b>{{if .Hostnames}} ({{join .Hostnames ", "}}){{end}}{{if .OS}} · {{.OS}}{{end}} · {{len .Services}} service(s) · {{len .Findings}} finding(s)</summary><div>
{{if .Audit}}<p><b>Credentialed audit:</b> {{.Audit.Result}}{{if .Audit.OS}} · {{.Audit.OS}}{{end}}{{if .Audit.Packages}} · {{.Audit.Packages}} packages inspected{{end}}{{if .Audit.Ecosystem}} · advisories: {{.Audit.Ecosystem}}{{end}}{{if .Audit.Error}}<br><span class="mut">{{.Audit.Error}}</span>{{end}}</p>{{else}}<p class="mut">Credentialed audit: not performed (network view only).</p>{{end}}
{{if .Services}}<table><tr><th>Port</th><th>Service</th><th>Product</th><th>TLS issues</th></tr>
{{range .Services}}<tr><td class="mono">{{.Port}}/{{.Proto}}</td><td>{{.Name}}</td><td>{{.Product}} {{.Version}}</td><td>{{join .TLSWeak ", "}}</td></tr>{{end}}</table>{{end}}
{{range .Findings}}{{template "finding" .}}{{end}}
</div></details>{{else}}<p class="mut">No hosts.</p>{{end}}

<h2>Findings by family</h2>
{{range .Families}}<h3>{{.Name}} <span class="mut">({{len .Findings}})</span></h3>{{if .Blurb}}<p class="mut">{{.Blurb}}</p>{{end}}
{{range .Findings}}{{template "finding" .}}{{end}}{{else}}<p class="mut">No findings.</p>{{end}}

<h2>Scan coverage and audit trail</h2>
<p class="mut">What ran and what did not, so a quiet report can be told apart from a thin scan.</p>
{{if .Checks}}<table><tr><th>Check</th><th>Runs</th></tr>{{range .Checks}}<tr><td class="mono">{{.K}}</td><td>{{.V}}</td></tr>{{end}}</table>{{end}}
{{if .Skipped}}<h3>Skipped checks</h3><table><tr><th>Host</th><th>Check</th><th>Reason</th></tr>
{{range .Skipped}}<tr><td class="mono">{{.Host}}</td><td class="mono">{{.Check}}</td><td>{{.Reason}}</td></tr>{{end}}</table>{{end}}
{{if .R.Coverage.FailedJobs}}<h3>Failed jobs</h3><table><tr><th>Stage</th><th>Chunk</th><th>Error</th></tr>
{{range .R.Coverage.FailedJobs}}<tr><td>{{.Stage}}</td><td class="mono">{{.Chunk}}</td><td>{{.Error}}</td></tr>{{end}}</table>{{end}}
<p class="mut">Generated by Babylon. Contains sensitive scan data; handle accordingly.</p>
</main></body></html>
{{define "finding"}}<details><summary><span class="badge {{.Severity}}">{{title .Severity}}</span>
{{if .KEV}}<span class="badge kev">KEV</span>{{end}} <span class="badge conf">{{.Confidence}}</span> {{.Title}}
<span class="mut mono">{{.Host}}{{if .Port}}:{{port .Port .Proto}}{{end}}</span></summary><div>
<div class="mut">CVSS {{f1 .CVSS}} · EPSS {{pct .EPSS}} · {{.Detection}} · {{join .Engines ", "}}{{if .CVEs}} · {{join .CVEs ", "}}{{end}}</div>
{{if .Synopsis}}<p>{{.Synopsis}}</p>{{end}}{{if .Description}}<p>{{.Description}}</p>{{end}}
{{if .Remediation}}<p><b>Fix:</b> {{.Remediation}}</p>{{end}}
{{if .Evidence}}<details><summary>Evidence</summary><pre>{{.Evidence}}</pre></details>{{end}}
</div></details>{{end}}
`))
