package nuclei

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"babylon/internal/correlate"
	"babylon/internal/model"
	"babylon/internal/policy"
)

// Args builds the Nuclei argv. Templates are an explicit file list chosen from
// Babylon's index (never a directory or tag expression), exclusions are
// repeated as defence in depth, and no user string reaches the command line.
// Note: `-c` is deliberately not used; combined with a long -etags list and
// -rl it made Nuclei stall ~3 minutes in testing.
func Args(cfg policy.NucleiConfig, targetsFile, templatesFile string, ratePPS int) ([]string, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("nuclei is not enabled for this template")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if ratePPS <= 0 {
		ratePPS = 100
	}
	return []string{
		"-l", targetsFile,
		"-t", templatesFile,
		"-duc", "-ni", "-silent", "-no-color", "-jsonl",
		"-timeout", "8", "-retries", "0",
		"-rl", strconv.Itoa(ratePPS),
		"-etags", strings.Join(cfg.ExcludeTags, ","),
		"-exclude-type", strings.Join(cfg.ExcludeProtocols, ","),
	}, nil
}

// Result is one parsed Nuclei match.
type Result struct {
	Finding       model.Finding
	Tags          []string // template tags (used to learn technologies)
	Informational bool
	HostPort      string // "ip:port" key for knowledge-base facts
	TemplateID    string
	CPE           string   // product CPE the template declares ("" if none)
	Extracted     []string // values extractors pulled out (often a version)
}

type rawResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string   `json:"name"`
		Tags           []string `json:"tags"`
		Description    string   `json:"description"`
		Impact         string   `json:"impact"`
		Severity       string   `json:"severity"`
		Remediation    string   `json:"remediation"`
		Classification struct {
			CVEID  []string `json:"cve-id"`
			CVSS   float64  `json:"cvss-score"`
			Metric string   `json:"cvss-metrics"`
			EPSS   float64  `json:"epss-score"`
			CPE    string   `json:"cpe"`
		} `json:"classification"`
	} `json:"info"`
	Type          string   `json:"type"`
	Host          string   `json:"host"`
	IP            string   `json:"ip"`
	Port          string   `json:"port"`
	MatchedAt     string   `json:"matched-at"`
	MatcherName   string   `json:"matcher-name"`
	ExtractorName string   `json:"extractor-name"`
	Extracted     []string `json:"extracted-results"`
	Request       string   `json:"request"`
	Response      string   `json:"response"`
}

// genericTags are never technology names.
var genericTags = map[string]bool{
	"tech": true, "detect": true, "discovery": true, "http": true, "panel": true, "exposure": true, "misconfig": true,
	"generic": true, "info": true, "vuln": true, "edb": true, "network": true, "tcp": true, "passive": true, "config": true,
	"listing": true, "setup": true, "headers": true, "waf": true, "version": true, "eol": true, "cve": true, "unauth": true,
	"favicon": true, "seo": true, "exposed": true, "login": true,
}

// ParseLine converts one JSONL line into a Result.
func ParseLine(line []byte, rawRef string) (Result, error) {
	var r rawResult
	if err := json.Unmarshal(line, &r); err != nil {
		return Result{}, fmt.Errorf("bad nuclei json: %w", err)
	}
	if r.TemplateID == "" {
		return Result{}, fmt.Errorf("nuclei result without template-id")
	}
	addr := r.IP
	if addr == "" {
		addr = r.Host
	}
	port, _ := strconv.Atoi(r.Port)
	proto := "tcp"
	if r.Type == "udp" {
		proto = "udp"
	}

	tags := make([]string, 0, len(r.Info.Tags))
	for _, t := range r.Info.Tags {
		tags = append(tags, strings.ToLower(t))
	}
	var cves []string
	for _, c := range r.Info.Classification.CVEID {
		cves = append(cves, strings.ToUpper(c))
	}

	sev := strings.ToLower(r.Info.Severity)
	if model.SeverityRank(sev) == 0 {
		sev = "info"
	}
	conf, detection := classify(tags, sev, len(cves) > 0, r.ExtractorName)

	f := model.Finding{
		Address:     addr,
		Port:        port,
		Proto:       proto,
		Title:       strings.TrimSpace(r.Info.Name),
		Family:      family(tags),
		Severity:    sev,
		CVEs:        cves,
		Synopsis:    firstSentence(r.Info.Description),
		Description: strings.TrimSpace(joinNonEmpty("\n\n", r.Info.Description, r.Info.Impact)),
		Remediation: strings.TrimSpace(r.Info.Remediation),
		Confidence:  conf,
		Detection:   detection,
		Engine:      "nuclei",
		EngineRef:   r.TemplateID,
		RawRef:      rawRef,
		Evidence:    correlate.Redact(evidence(r)),
	}
	if f.Title == "" {
		f.Title = r.TemplateID
	}
	if r.Info.Classification.CVSS > 0 {
		v := r.Info.Classification.CVSS
		f.CVSS = &v
		f.CVSSVector = r.Info.Classification.Metric
	}
	if r.Info.Classification.EPSS > 0 {
		v := r.Info.Classification.EPSS
		f.EPSS = &v
	}
	if f.Remediation != "" {
		f.Solution = "VendorFix"
	}
	f.Fingerprint = correlate.Fingerprint(addr, port, proto, cves, correlate.CheckKey("nuclei", r.TemplateID))

	return Result{
		Finding: f, Tags: tags, Informational: sev == "info",
		HostPort: addr + ":" + r.Port, TemplateID: r.TemplateID, CPE: r.Info.Classification.CPE, Extracted: r.Extracted,
	}, nil
}

// classify decides how strong a claim a template result makes. Nuclei does not
// say whether a CVE template verified behaviour or merely matched a version
// string, so this is a documented heuristic on template metadata:
//   - informational detections are observed facts            -> confirmed
//   - CVE templates tagged passive / version-extracting      -> tentative (version)
//   - other CVE templates (active matchers)                  -> firm
//   - misconfig / exposure / default-login / etc.            -> confirmed (the
//     response itself demonstrates the condition)
func classify(tags []string, sev string, hasCVE bool, extractor string) (confidence, detection string) {
	t := toSet(tags)
	switch {
	case sev == "info" && (t["tech"] || t["detect"] || t["discovery"] || t["panel"] || t["waf"]):
		return model.ConfConfirmed, "behaviour"
	case hasCVE || t["cve"]:
		if t["passive"] || t["version"] || strings.Contains(strings.ToLower(extractor), "version") {
			return model.ConfTentative, "version"
		}
		return model.ConfFirm, "behaviour"
	}
	return model.ConfConfirmed, "behaviour"
}

func family(tags []string) string {
	t := toSet(tags)
	switch {
	case t["default-login"] || t["default-logins"]:
		return "Default credentials"
	case t["cve"]:
		return "Known vulnerabilities"
	case t["tech"] || t["detect"] || t["discovery"]:
		return "Service detection"
	case t["panel"] || t["exposure"] || t["config"] || t["listing"]:
		return "Exposures"
	case t["misconfig"] || t["headers"]:
		return "Misconfiguration"
	}
	return "Web and network checks"
}

func evidence(r rawResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "matched at: %s", r.MatchedAt)
	if r.MatcherName != "" {
		fmt.Fprintf(&b, "\nmatcher: %s", r.MatcherName)
	}
	if len(r.Extracted) > 0 {
		fmt.Fprintf(&b, "\nextracted: %s", strings.Join(r.Extracted, ", "))
	}
	if r.Request != "" {
		b.WriteString("\n--- request ---\n" + correlate.Truncate(r.Request, 600))
	}
	if r.Response != "" {
		b.WriteString("\n--- response ---\n" + correlate.Truncate(r.Response, 1200))
	}
	return b.String()
}

// TechTokens returns technology names implied by an informational detection:
// the template's tags minus generic words.
func TechTokens(tags []string) []string {
	var out []string
	for _, t := range tags {
		if !genericTags[t] && !strings.HasPrefix(t, "cve") && !stopTokens[t] {
			out = append(out, t)
		}
	}
	return out
}

func firstSentence(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if i := strings.Index(s, ". "); i > 0 && i < 240 {
		return s[:i+1]
	}
	return correlate.Truncate(s, 240)
}

func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, strings.TrimSpace(p))
		}
	}
	return strings.Join(out, sep)
}
