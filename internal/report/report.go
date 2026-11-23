// Package report builds scan reports (JSON, Markdown, CSV) from stored data.
// Everything shown comes from scanned hosts and is therefore untrusted: output
// formats escape or fence it, and CSV neutralizes spreadsheet formulas.
package report

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"babylon/internal/group"
	"babylon/internal/store"
)

// SchemaVersion identifies the JSON layout for downstream tooling.
const SchemaVersion = 1

type Report struct {
	SchemaVersion int       `json:"schema_version"`
	GeneratedAt   string    `json:"generated_at"`
	Scan          ScanInfo  `json:"scan"`
	Summary       Summary   `json:"summary"`
	Hosts         []Host    `json:"hosts"`
	Findings      []Finding `json:"findings"`
	Groups        []Group   `json:"root_causes,omitempty"`
	Coverage      Coverage  `json:"coverage"`
}

type ScanInfo struct {
	ID         int64    `json:"id"`
	Name       string   `json:"name,omitempty"`
	Template   string   `json:"template"`
	Status     string   `json:"status"`
	Targets    []string `json:"targets"`
	StartedAt  string   `json:"started_at,omitempty"`
	FinishedAt string   `json:"finished_at,omitempty"`
	Accuracy   string   `json:"accuracy"`
}

type Summary struct {
	Hosts          int            `json:"hosts"`
	Services       int            `json:"services"`
	FindingsBySev  map[string]int `json:"findings_by_severity"`
	Verified       int            `json:"verified_findings"`
	Possible       int            `json:"possible_findings"`
	Informational  int            `json:"informational"`
	PossibleHidden bool           `json:"possible_hidden_by_accuracy"`
	JobsFailed     int            `json:"jobs_failed"`
	ChecksSkipped  int            `json:"checks_skipped"`
}

type Host struct {
	Address   string    `json:"address"`
	Hostnames []string  `json:"hostnames,omitempty"`
	OS        string    `json:"os,omitempty"`
	Services  []Service `json:"services"`
	Audit     *Audit    `json:"credentialed_audit,omitempty"`
}

// Audit is the outcome of a credentialed audit of the host (never any secret).
type Audit struct {
	Result    string `json:"result"` // ok | partial | failed
	OS        string `json:"os,omitempty"`
	Kernel    string `json:"kernel,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Packages  int    `json:"packages"`
	Error     string `json:"error,omitempty"`
}

type Service struct {
	Port    int      `json:"port"`
	Proto   string   `json:"proto"`
	Name    string   `json:"name,omitempty"`
	Product string   `json:"product,omitempty"`
	Version string   `json:"version,omitempty"`
	TLSWeak []string `json:"tls_issues,omitempty"`
}

type Finding struct {
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Detection   string   `json:"detection"`
	Title       string   `json:"title"`
	Host        string   `json:"host"`
	Port        int      `json:"port,omitempty"`
	Proto       string   `json:"proto,omitempty"`
	Family      string   `json:"family,omitempty"`
	CVEs        []string `json:"cve_ids,omitempty"`
	CVSS        *float64 `json:"cvss_score,omitempty"`
	EPSS        *float64 `json:"epss_score,omitempty"`
	KEV         bool     `json:"kev"`
	Product     string   `json:"product,omitempty"`
	Version     string   `json:"version,omitempty"`
	Synopsis    string   `json:"synopsis,omitempty"`
	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Engines     []string `json:"engines"`
	Possible    bool     `json:"possible"` // unverified, version-based
}

// Group is a root cause: several CVE findings from one outdated product.
type Group struct {
	Title      string   `json:"title"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Proto      string   `json:"proto"`
	Product    string   `json:"product"`
	Version    string   `json:"version"`
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"` // weakest member
	KEVCount   int      `json:"kev_count"`
	MaxCVSS    *float64 `json:"max_cvss,omitempty"`
	MaxEPSS    *float64 `json:"max_epss,omitempty"`
	CVEs       []string `json:"cve_ids"`
	Fix        string   `json:"remediation"`
}

type Coverage struct {
	FailedJobs []FailedJob    `json:"failed_jobs,omitempty"`
	Skipped    []SkippedItem  `json:"skipped_checks,omitempty"`
	CheckRuns  map[string]int `json:"check_runs"`
}

type FailedJob struct {
	Stage string `json:"stage"`
	Chunk string `json:"chunk"`
	Error string `json:"error"`
}

type SkippedItem struct {
	Host   string `json:"host"`
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// Build assembles a report for a scan. accuracy decides whether unverified
// ("possible") findings are listed; they are always counted and stored.
func Build(ctx context.Context, st *store.Store, id int64, accuracy string) (*Report, error) {
	sum, err := st.GetScanSummary(ctx, id)
	if err != nil {
		return nil, err
	}
	r := &Report{SchemaVersion: SchemaVersion, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	r.Scan = ScanInfo{ID: sum.ID, Name: sum.Name, Template: sum.Template, Status: sum.Status, Targets: sum.Targets,
		StartedAt: sum.StartedAt, FinishedAt: sum.FinishedAt, Accuracy: accuracy}
	r.Summary = Summary{Hosts: sum.Hosts, Services: sum.Services, FindingsBySev: sum.Findings, JobsFailed: sum.JobsFailed,
		PossibleHidden: accuracy == "avoid-false-alarms"}

	hosts, err := st.ListHosts(ctx, id)
	if err != nil {
		return nil, err
	}
	svcs, err := st.ListServices(ctx, id)
	if err != nil {
		return nil, err
	}
	idx := map[string]*Host{}
	for _, h := range hosts {
		if h.State != "up" {
			continue
		}
		r.Hosts = append(r.Hosts, Host{Address: h.Address, Hostnames: h.Hostnames, OS: h.OS, Services: []Service{}})
	}
	for i := range r.Hosts {
		idx[r.Hosts[i].Address] = &r.Hosts[i]
	}
	if sess, err := st.AuditSessions(ctx, id); err == nil {
		for _, a := range sess {
			if h := idx[a.Address]; h != nil {
				h.Audit = &Audit{Result: a.Result, OS: a.OSName, Kernel: a.Kernel, Ecosystem: a.Ecosystem, Packages: a.Packages, Error: a.Error}
			}
		}
	}
	for _, sv := range svcs {
		if sv.State != "open" {
			continue
		}
		if h := idx[sv.Address]; h != nil {
			h.Services = append(h.Services, Service{Port: sv.Port, Proto: sv.Proto, Name: sv.Name, Product: sv.Product, Version: sv.Version, TLSWeak: sv.TLSWeak})
		}
	}

	fs, err := st.ListFindings(ctx, id, "")
	if err != nil {
		return nil, err
	}
	var shown []store.FindingRow
	for _, f := range fs {
		possible := f.Confidence == "tentative" && f.Severity != "info"
		switch {
		case f.Severity == "info":
			r.Summary.Informational++
		case possible:
			r.Summary.Possible++
		default:
			r.Summary.Verified++
		}
		if possible && accuracy == "avoid-false-alarms" {
			continue
		}
		shown = append(shown, f)
		r.Findings = append(r.Findings, Finding{
			Severity: f.Severity, Confidence: f.Confidence, Detection: f.Detection, Title: f.Title, Host: f.Address,
			Port: f.Port, Proto: f.Proto, Family: f.Family, CVEs: f.CVEs, CVSS: f.CVSS, EPSS: f.EPSS, KEV: f.KEV, Product: f.Product, Version: f.Version, Synopsis: f.Synopsis,
			Description: f.Description, Remediation: f.Remediation, Evidence: f.Evidence, Engines: f.Engines, Possible: possible,
		})
	}

	groups, _ := group.Build(shown)
	for _, g := range groups {
		r.Groups = append(r.Groups, Group{Title: g.Title, Host: g.Address, Port: g.Port, Proto: g.Proto, Product: g.Product, Version: g.Version,
			Severity: g.Severity, Confidence: g.Confidence, KEVCount: g.KEVCount, MaxCVSS: g.MaxCVSS, MaxEPSS: g.MaxEPSS, CVEs: g.CVEs, Fix: g.Fix})
	}

	jobs, err := st.ListJobs(ctx, id)
	if err != nil {
		return nil, err
	}
	for _, j := range jobs {
		if j.State == store.JobFailed {
			r.Coverage.FailedJobs = append(r.Coverage.FailedJobs, FailedJob{Stage: j.Stage, Chunk: j.ChunkKey, Error: j.Error})
		}
	}
	runs, err := st.ListCheckRuns(ctx, id)
	if err != nil {
		return nil, err
	}
	r.Coverage.CheckRuns = map[string]int{}
	for _, c := range runs {
		r.Coverage.CheckRuns[c.State]++
		if c.State == "skipped" || c.State == "error" {
			r.Coverage.Skipped = append(r.Coverage.Skipped, SkippedItem{Host: c.Address, Check: c.CheckID, Reason: c.State + ": " + c.Reason})
		}
	}
	r.Summary.ChecksSkipped = r.Coverage.CheckRuns["skipped"]
	return r, nil
}

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

var sevOrder = []string{"critical", "high", "medium", "low", "info"}

// WriteMarkdown writes a human-readable report.
func WriteMarkdown(w io.Writer, r *Report) error {
	var b strings.Builder
	title := r.Scan.Name
	if title == "" {
		title = fmt.Sprintf("Scan %d", r.Scan.ID)
	}
	fmt.Fprintf(&b, "# Vulnerability scan report: %s\n\n", mdInline(title))
	fmt.Fprintf(&b, "- **Template:** %s\n- **Status:** %s\n- **Targets:** %s\n", mdInline(r.Scan.Template), r.Scan.Status, mdInline(strings.Join(r.Scan.Targets, ", ")))
	if r.Scan.StartedAt != "" {
		fmt.Fprintf(&b, "- **Started:** %s\n", r.Scan.StartedAt)
	}
	if r.Scan.FinishedAt != "" {
		fmt.Fprintf(&b, "- **Finished:** %s\n", r.Scan.FinishedAt)
	}
	fmt.Fprintf(&b, "- **Report generated:** %s (accuracy: %s)\n\n", r.GeneratedAt, r.Scan.Accuracy)

	b.WriteString("## Executive summary\n\n")
	fmt.Fprintf(&b, "%d live hosts and %d open services were assessed. ", r.Summary.Hosts, r.Summary.Services)
	fmt.Fprintf(&b, "%d verified findings, %d possible (unverified) findings, %d informational.\n\n", r.Summary.Verified, r.Summary.Possible, r.Summary.Informational)
	b.WriteString("| Severity | Count |\n|---|---|\n")
	for _, s := range sevOrder {
		fmt.Fprintf(&b, "| %s | %d |\n", s, r.Summary.FindingsBySev[s])
	}
	b.WriteString("\n")
	if r.Summary.PossibleHidden && r.Summary.Possible > 0 {
		fmt.Fprintf(&b, "> %d possible findings are hidden by the *avoid false alarms* setting; they remain stored.\n\n", r.Summary.Possible)
	}

	if len(r.Groups) > 0 {
		fmt.Fprintf(&b, "## Priority action plan (%d root causes)\n\n", len(r.Groups))
		b.WriteString("| Severity | Host | Root cause | KEV | Max CVSS | Confidence | Action |\n|---|---|---|---|---|---|---|\n")
		for _, g := range r.Groups {
			cvss := ""
			if g.MaxCVSS != nil {
				cvss = fmt.Sprintf("%.1f", *g.MaxCVSS)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %s | %s | %s |\n", strings.ToUpper(g.Severity), cell(fmt.Sprintf("%s:%d", g.Host, g.Port)),
				cell(g.Title), g.KEVCount, cvss, g.Confidence, cell(g.Fix))
		}
		b.WriteString("\nThe individual CVEs behind each item are listed under the findings below.\n\n")
	}

	writeSection := func(heading string, pred func(Finding) bool) {
		var list []Finding
		for _, f := range r.Findings {
			if pred(f) {
				list = append(list, f)
			}
		}
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s (%d)\n\n", heading, len(list))
		for _, f := range list {
			where := f.Host
			if f.Port != 0 {
				where = fmt.Sprintf("%s:%d/%s", f.Host, f.Port, f.Proto)
			}
			fmt.Fprintf(&b, "### [%s] %s\n\n", strings.ToUpper(f.Severity), mdInline(f.Title))
			fmt.Fprintf(&b, "- **Host:** %s\n- **Confidence:** %s (%s)\n- **Detected by:** %s\n", mdInline(where), f.Confidence, f.Detection, mdInline(strings.Join(f.Engines, ", ")))
			if len(f.CVEs) > 0 {
				fmt.Fprintf(&b, "- **CVE:** %s\n", mdInline(strings.Join(f.CVEs, ", ")))
			}
			if f.CVSS != nil {
				fmt.Fprintf(&b, "- **CVSS:** %.1f\n", *f.CVSS)
			}
			b.WriteString("\n")
			if f.Synopsis != "" {
				fmt.Fprintf(&b, "%s\n\n", mdInline(f.Synopsis))
			}
			if f.Description != "" {
				fmt.Fprintf(&b, "**Description.** %s\n\n", mdInline(f.Description))
			}
			if f.Remediation != "" {
				fmt.Fprintf(&b, "**Remediation.** %s\n\n", mdInline(f.Remediation))
			}
			if f.Evidence != "" {
				b.WriteString("**Evidence**\n\n" + fence(f.Evidence) + "\n\n")
			}
		}
	}
	writeSection("Findings", func(f Finding) bool { return f.Severity != "info" && !f.Possible })
	writeSection("Possible findings (version-based, unverified)", func(f Finding) bool { return f.Possible })
	writeSection("Informational", func(f Finding) bool { return f.Severity == "info" })

	b.WriteString("## Hosts and services\n\n")
	for _, h := range r.Hosts {
		label := h.Address
		if h.OS != "" {
			label += " (" + h.OS + ")"
		}
		fmt.Fprintf(&b, "### %s\n\n", mdInline(label))
		if a := h.Audit; a != nil {
			fmt.Fprintf(&b, "Credentialed audit: **%s**", mdInline(a.Result))
			if a.OS != "" {
				fmt.Fprintf(&b, ", %s", mdInline(a.OS))
			}
			if a.Packages > 0 {
				fmt.Fprintf(&b, ", %d packages inspected", a.Packages)
			}
			if a.Error != "" {
				fmt.Fprintf(&b, " (%s)", mdInline(a.Error))
			}
			b.WriteString("\n\n")
		}
		if len(h.Services) == 0 {
			b.WriteString("_No open services._\n\n")
			continue
		}
		b.WriteString("| Port | Service | Product / version |\n|---|---|---|\n")
		for _, s := range h.Services {
			fmt.Fprintf(&b, "| %d/%s | %s | %s |\n", s.Port, s.Proto, cell(s.Name), cell(strings.TrimSpace(s.Product+" "+s.Version)))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Coverage\n\n")
	fmt.Fprintf(&b, "Checks run: %d, skipped: %d, errored: %d.\n\n", r.Coverage.CheckRuns["ran"], r.Coverage.CheckRuns["skipped"], r.Coverage.CheckRuns["error"])
	if len(r.Coverage.FailedJobs) > 0 {
		b.WriteString("**Failed jobs** (results from these may be incomplete):\n\n")
		for _, j := range r.Coverage.FailedJobs {
			fmt.Fprintf(&b, "- %s / %s: %s\n", mdInline(j.Stage), mdInline(j.Chunk), mdInline(j.Error))
		}
		b.WriteString("\n")
	}
	if len(r.Coverage.Skipped) > 0 {
		b.WriteString("<details><summary>Skipped checks and reasons</summary>\n\n")
		b.WriteString("| Host | Check | Reason |\n|---|---|---|\n")
		for _, s := range r.Coverage.Skipped {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", cell(s.Host), cell(s.Check), cell(s.Reason))
		}
		b.WriteString("\n</details>\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// mdInline neutralizes Markdown/HTML in untrusted inline text.
func mdInline(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	r := strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]",
		"<", "&lt;", ">", "&gt;", "|", "\\|", "#", "\\#", "!", "\\!")
	return r.Replace(s)
}

func cell(s string) string { return mdInline(s) }

// fence returns s in a code fence long enough that s cannot close it.
func fence(s string) string {
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	f := strings.Repeat("`", max(3, longest+1))
	return f + "\n" + strings.ReplaceAll(s, "\r", "") + "\n" + f
}

// WriteCSV writes findings as CSV for spreadsheets. Cells that could be
// interpreted as formulas are neutralized.
func WriteCSV(w io.Writer, r *Report) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"severity", "confidence", "host", "port", "proto", "title", "cve_ids", "cvss", "epss", "kev", "product", "version", "engines", "family", "remediation"}); err != nil {
		return err
	}
	for _, f := range r.Findings { // already in priority order: KEV, confidence, CVSS, EPSS
		cvss := ""
		if f.CVSS != nil {
			cvss = fmt.Sprintf("%.1f", *f.CVSS)
		}
		epss := ""
		if f.EPSS != nil {
			epss = fmt.Sprintf("%.4f", *f.EPSS)
		}
		port := ""
		if f.Port != 0 {
			port = fmt.Sprint(f.Port)
		}
		row := []string{f.Severity, f.Confidence, f.Host, port, f.Proto, f.Title, strings.Join(f.CVEs, " "), cvss, epss,
			fmt.Sprint(f.KEV), f.Product, f.Version, strings.Join(f.Engines, "+"), f.Family, f.Remediation}
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func rank(s string) int {
	for i, v := range sevOrder {
		if v == s {
			return len(sevOrder) - i
		}
	}
	return 0
}

// csvSafe prefixes cells that spreadsheets would execute as formulas.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
