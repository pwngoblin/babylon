// Package lab measures detection quality against a known set of targets.
// A manifest lists what a scan of the lab must find (expected) and what it
// must never report (forbidden, i.e. known false positives). Evaluate turns a
// finished scan into recall and false-positive numbers so detection quality is
// measured on every release instead of guessed.
package lab

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"babylon/internal/model"
	"babylon/internal/store"
)

// Match selects findings. Every field that is set must match.
type Match struct {
	Host      string `yaml:"host"`   // address; "" = any
	Port      int    `yaml:"port"`   // 0 = any
	Proto     string `yaml:"proto"`  // "" = any
	Title     string `yaml:"title"`  // regexp on the finding title
	CVE       string `yaml:"cve"`    // finding lists this CVE
	Family    string `yaml:"family"` // exact family
	Engine    string `yaml:"engine"` // finding was reported by this engine
	MinSev    string `yaml:"min_severity"`
	Product   string `yaml:"product"` // regexp on the product
	titleRe   *regexp.Regexp
	productRe *regexp.Regexp
}

// Expectation is something a scan of the lab must report.
type Expectation struct {
	ID            string `yaml:"id"`
	Match         `yaml:",inline"`
	MinConfidence string `yaml:"min_confidence"` // tier that counts as a hit (default firm)
	Needs         string `yaml:"needs"`          // scan option required: allow-active, deep, credentialed, root
	Note          string `yaml:"note"`
}

// Forbidden is a finding that must not appear (a known false positive).
type Forbidden struct {
	ID     string `yaml:"id"`
	Match  `yaml:",inline"`
	Reason string `yaml:"reason"`
}

// Scan is how `babylon lab run` starts the scan.
type Scan struct {
	Template    string   `yaml:"template"`
	Targets     []string `yaml:"targets"`
	Ports       string   `yaml:"ports"`
	Timing      string   `yaml:"timing"`
	AllowActive bool     `yaml:"allow_active"`
	Deep        bool     `yaml:"deep"`
}

// Thresholds make Evaluate pass or fail.
type Thresholds struct {
	MinRecall    float64 `yaml:"min_recall"`    // fraction of expected findings that must be hit
	MaxForbidden int     `yaml:"max_forbidden"` // forbidden findings tolerated (normally 0)
}

// Manifest is the lab's expected-findings file.
type Manifest struct {
	Version    int           `yaml:"version"`
	Scan       Scan          `yaml:"scan"`
	Thresholds Thresholds    `yaml:"thresholds"`
	Expected   []Expectation `yaml:"expected"`
	Forbidden  []Forbidden   `yaml:"forbidden"`
}

// Load reads and validates a manifest.
func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse validates manifest YAML.
func Parse(b []byte) (*Manifest, error) {
	var m Manifest
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Version != 2 {
		return nil, fmt.Errorf("manifest: version must be 2, got %d", m.Version)
	}
	seen := map[string]bool{}
	for i := range m.Expected {
		e := &m.Expected[i]
		if e.ID == "" || seen[e.ID] {
			return nil, fmt.Errorf("manifest: expected[%d]: id missing or duplicated (%q)", i, e.ID)
		}
		seen[e.ID] = true
		if e.MinConfidence == "" {
			e.MinConfidence = model.ConfFirm
		}
		if err := e.Match.compile(); err != nil {
			return nil, fmt.Errorf("manifest: %s: %w", e.ID, err)
		}
		if e.Match.empty() {
			return nil, fmt.Errorf("manifest: %s: an expectation needs at least one match field", e.ID)
		}
	}
	for i := range m.Forbidden {
		f := &m.Forbidden[i]
		if f.ID == "" || seen[f.ID] {
			return nil, fmt.Errorf("manifest: forbidden[%d]: id missing or duplicated (%q)", i, f.ID)
		}
		seen[f.ID] = true
		if err := f.Match.compile(); err != nil {
			return nil, fmt.Errorf("manifest: %s: %w", f.ID, err)
		}
		if f.Match.empty() {
			return nil, fmt.Errorf("manifest: %s: a forbidden entry needs at least one match field", f.ID)
		}
	}
	return &m, nil
}

func (m *Match) compile() (err error) {
	if m.Title != "" {
		if m.titleRe, err = regexp.Compile("(?i)" + m.Title); err != nil {
			return fmt.Errorf("title regexp: %w", err)
		}
	}
	if m.Product != "" {
		if m.productRe, err = regexp.Compile("(?i)" + m.Product); err != nil {
			return fmt.Errorf("product regexp: %w", err)
		}
	}
	return nil
}

func (m Match) empty() bool {
	return m.Port == 0 && m.Title == "" && m.CVE == "" && m.Family == "" && m.Engine == "" && m.Product == ""
}

func (m Match) matches(f store.FindingRow) bool {
	if m.Host != "" && f.Address != m.Host {
		return false
	}
	if m.Port != 0 && f.Port != m.Port {
		return false
	}
	if m.Proto != "" && !strings.EqualFold(f.Proto, m.Proto) {
		return false
	}
	if m.titleRe != nil && !m.titleRe.MatchString(f.Title) {
		return false
	}
	if m.productRe != nil && !m.productRe.MatchString(f.Product) {
		return false
	}
	if m.Family != "" && f.Family != m.Family {
		return false
	}
	if m.CVE != "" {
		ok := false
		for _, c := range f.CVEs {
			if strings.EqualFold(c, m.CVE) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if m.Engine != "" {
		ok := false
		for _, e := range f.Engines {
			if e == m.Engine {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if m.MinSev != "" && model.SeverityRank(f.Severity) < model.SeverityRank(m.MinSev) {
		return false
	}
	return true
}

// Options tell Evaluate which optional capabilities the scan had.
type Options struct {
	Capabilities map[string]bool // allow-active, deep, credentialed, root
}

// Outcome of one expectation.
type Outcome struct {
	ID      string `json:"id"`
	Status  string `json:"status"` // hit | miss | weak | skipped
	Detail  string `json:"detail,omitempty"`
	Matched string `json:"matched,omitempty"`
}

// Report is the measured result.
type Report struct {
	Outcomes       []Outcome `json:"outcomes"`
	Expected       int       `json:"expected"` // counted (not skipped)
	Hits           int       `json:"hits"`
	Skipped        int       `json:"skipped"`
	Recall         float64   `json:"recall"`
	ForbiddenHits  []Outcome `json:"forbidden_hits"`
	Findings       int       `json:"findings"`
	Unreviewed     int       `json:"unreviewed_high"` // high/critical findings the manifest neither expects nor forbids
	UnreviewedList []string  `json:"unreviewed_high_list,omitempty"`
	Pass           bool      `json:"pass"`
	Failures       []string  `json:"failures,omitempty"`
}

// Evaluate compares a scan's findings with the manifest.
func Evaluate(m *Manifest, rows []store.FindingRow, opt Options) *Report {
	r := &Report{Findings: len(rows)}
	used := map[int64]bool{}
	for _, e := range m.Expected {
		o := Outcome{ID: e.ID}
		if e.Needs != "" && !opt.Capabilities[e.Needs] {
			o.Status, o.Detail = "skipped", "needs "+e.Needs
			r.Skipped++
			r.Outcomes = append(r.Outcomes, o)
			continue
		}
		r.Expected++
		var weakest *store.FindingRow
		hit := false
		for i := range rows {
			f := rows[i]
			if !e.Match.matches(f) {
				continue
			}
			used[f.ID] = true
			if model.ConfidenceRank(f.Confidence) >= model.ConfidenceRank(e.MinConfidence) {
				hit = true
				o.Matched = fmt.Sprintf("%s [%s]", f.Title, f.Confidence)
				break
			}
			weakest = &rows[i]
		}
		switch {
		case hit:
			o.Status = "hit"
			r.Hits++
		case weakest != nil:
			o.Status = "weak"
			o.Detail = fmt.Sprintf("found only at %s confidence (need %s): %s", weakest.Confidence, e.MinConfidence, weakest.Title)
		default:
			o.Status = "miss"
		}
		r.Outcomes = append(r.Outcomes, o)
	}
	if r.Expected > 0 {
		r.Recall = float64(r.Hits) / float64(r.Expected)
	}
	for _, f := range m.Forbidden {
		for _, row := range rows {
			if f.Match.matches(row) {
				used[row.ID] = true
				r.ForbiddenHits = append(r.ForbiddenHits, Outcome{ID: f.ID, Status: "forbidden", Detail: f.Reason, Matched: fmt.Sprintf("%s:%d %s", row.Address, row.Port, row.Title)})
				break
			}
		}
	}
	for _, row := range rows {
		if !used[row.ID] && model.SeverityRank(row.Severity) >= model.SeverityRank("high") && row.Confidence != model.ConfTentative {
			r.Unreviewed++
			r.UnreviewedList = append(r.UnreviewedList, fmt.Sprintf("%s:%d %s [%s]", row.Address, row.Port, row.Title, row.Confidence))
		}
	}
	sort.Strings(r.UnreviewedList)
	r.Pass = true
	if m.Thresholds.MinRecall > 0 && r.Recall < m.Thresholds.MinRecall {
		r.Pass = false
		r.Failures = append(r.Failures, fmt.Sprintf("recall %.0f%% is below the required %.0f%%", r.Recall*100, m.Thresholds.MinRecall*100))
	}
	if len(r.ForbiddenHits) > m.Thresholds.MaxForbidden {
		r.Pass = false
		r.Failures = append(r.Failures, fmt.Sprintf("%d forbidden finding(s) reported (allowed %d)", len(r.ForbiddenHits), m.Thresholds.MaxForbidden))
	}
	return r
}

// Text renders a report for a terminal.
func (r *Report) Text() string {
	var b strings.Builder
	for _, o := range r.Outcomes {
		sym := map[string]string{"hit": "ok  ", "miss": "MISS", "weak": "WEAK", "skipped": "skip"}[o.Status]
		fmt.Fprintf(&b, "  %s %-34s", sym, o.ID)
		switch {
		case o.Matched != "":
			fmt.Fprintf(&b, " %s", o.Matched)
		case o.Detail != "":
			fmt.Fprintf(&b, " %s", o.Detail)
		}
		b.WriteByte('\n')
	}
	for _, f := range r.ForbiddenHits {
		fmt.Fprintf(&b, "  FALSE POSITIVE %-24s %s (%s)\n", f.ID, f.Matched, f.Detail)
	}
	fmt.Fprintf(&b, "\nRecall: %d/%d = %.0f%%", r.Hits, r.Expected, r.Recall*100)
	if r.Skipped > 0 {
		fmt.Fprintf(&b, " (%d skipped: scan lacked the option)", r.Skipped)
	}
	fmt.Fprintf(&b, "\nForbidden findings: %d\nUnreviewed high/critical (neither expected nor forbidden): %d\n", len(r.ForbiddenHits), r.Unreviewed)
	for _, u := range r.UnreviewedList {
		fmt.Fprintf(&b, "    %s\n", u)
	}
	if r.Pass {
		b.WriteString("RESULT: PASS\n")
	} else {
		b.WriteString("RESULT: FAIL\n")
		for _, f := range r.Failures {
			fmt.Fprintf(&b, "    %s\n", f)
		}
	}
	return b.String()
}
