// Package pack is Babylon's declarative check format. A pack is a YAML file of
// checks; each check either matches data the scan already collected (passive)
// or sends a small, bounded exchange to a service that was already found open
// (probe). Packs compile to native.Check, so ordering, skip reasons, coverage
// reporting, fingerprints and redaction come from the existing native runner.
//
// Safety is enforced here, not by convention: a pack can only talk to the host
// being scanned on ports the scan found open, HTTP is limited to read-only
// methods, and bytes, steps and time are capped. Regexes use Go's RE2 engine,
// so a hostile pattern cannot cause catastrophic backtracking.
package pack

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const SchemaVersion = 1

// Limits that Validate enforces on every pack, built-in or user supplied.
const (
	MaxSteps     = 8
	MaxSendBytes = 4096
	MaxReadBytes = 1 << 16
	MaxRegexLen  = 1000
	MaxPathLen   = 512
)

type File struct {
	Schema int   `yaml:"schema"`
	Checks []Def `yaml:"checks"`
}

type Def struct {
	ID         string     `yaml:"id"`
	Name       string     `yaml:"name"`
	Family     string     `yaml:"family"`
	Severity   string     `yaml:"severity"`
	Kind       string     `yaml:"kind"`      // passive | probe
	Transport  string     `yaml:"transport"` // probe only: tcp | udp | http
	Confidence string     `yaml:"confidence"`
	When       When       `yaml:"when"`
	Match      []Cond     `yaml:"match"` // passive: every condition must hold on one service
	Steps      []Step     `yaml:"steps"` // probe
	Finding    FindingDef `yaml:"finding"`
	Controls   []string   `yaml:"controls"`
	Tests      []Test     `yaml:"tests"`

	source string // file the check came from, for error messages
}

type When struct {
	Ports    []int    `yaml:"ports"`
	Services []string `yaml:"services"`
	Proto    string   `yaml:"proto"` // default tcp (http is always tcp)
}

// Cond is one passive condition: a service field (banner, product, version,
// name, extra, cpe, os, or script:<id>) must (or, with not, must not) match.
type Cond struct {
	Field string `yaml:"field"`
	Regex string `yaml:"regex"`
	Not   bool   `yaml:"not"`

	re *regexp.Regexp
}

type Step struct {
	Send    string    `yaml:"send"`     // tcp/udp payload (YAML escapes such as \r\n apply)
	SendHex string    `yaml:"send_hex"` // alternative to send, for binary protocols
	Read    int       `yaml:"read"`     // max bytes to read (default 1024)
	HTTP    *HTTPStep `yaml:"http"`
	Expect  Expect    `yaml:"expect"`
}

type HTTPStep struct {
	Method string `yaml:"method"` // GET (default), HEAD, OPTIONS
	Path   string `yaml:"path"`
	Scheme string `yaml:"scheme"` // auto (default), http, https
}

type Expect struct {
	Status int               `yaml:"status"` // 0 = do not check
	Body   string            `yaml:"body"`   // regex on the HTTP body or the tcp/udp reply; named groups become ${name}
	Not    string            `yaml:"not"`    // regex that must NOT match
	Header map[string]string `yaml:"header"` // http: header name -> regex

	body, not *regexp.Regexp
	header    map[string]*regexp.Regexp
}

type FindingDef struct {
	Title       string   `yaml:"title"`
	Synopsis    string   `yaml:"synopsis"`
	Description string   `yaml:"description"`
	Remediation string   `yaml:"remediation"`
	CVEs        []string `yaml:"cves"`
	CVSS        *float64 `yaml:"cvss"`
}

// Test is a fixture that travels with the check. `babylon checks test` serves
// the canned responses from a local mock and asserts the verdict.
type Test struct {
	Name      string            `yaml:"name"`
	Want      string            `yaml:"want"`      // finding | none
	Responses []Response        `yaml:"responses"` // probe: one per step
	Service   *FixtureService   `yaml:"service"`   // passive
	Scripts   map[string]string `yaml:"scripts"`   // passive: NSE script id -> output
}

type Response struct {
	Status int               `yaml:"status"`
	Body   string            `yaml:"body"`
	Header map[string]string `yaml:"header"`
	Data   string            `yaml:"data"` // tcp/udp reply
}

type FixtureService struct {
	Name, Product, Version, Banner, Extra, CPE, OS string
	Port                                           int
}

var (
	idRe         = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Z0-9]+){1,4}$`)
	severities   = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	confidences  = map[string]bool{"": true, "tentative": true, "firm": true, "confirmed": true}
	cveRe        = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	controlRe    = regexp.MustCompile(`^[A-Za-z0-9.+-]+:[A-Za-z0-9._()-]+$`)
	safeMethods  = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}
	passiveField = regexp.MustCompile(`^(banner|product|version|name|extra|cpe|os|script:[a-z0-9._-]+)$`)
)

// Parse decodes and validates one pack. Unknown YAML keys are errors so a typo
// cannot silently disable a safety limit or a condition.
func Parse(data []byte, source string) ([]Def, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	if f.Schema != SchemaVersion {
		return nil, fmt.Errorf("%s: schema must be %d, got %d", source, SchemaVersion, f.Schema)
	}
	if len(f.Checks) == 0 {
		return nil, fmt.Errorf("%s: no checks", source)
	}
	for i := range f.Checks {
		d := &f.Checks[i]
		d.source = source
		if err := d.validate(); err != nil {
			return nil, fmt.Errorf("%s: check %q: %w", source, d.ID, err)
		}
	}
	return f.Checks, nil
}

func compile(s string) (*regexp.Regexp, error) {
	if s == "" {
		return nil, nil
	}
	if len(s) > MaxRegexLen {
		return nil, fmt.Errorf("regex longer than %d characters", MaxRegexLen)
	}
	return regexp.Compile(s)
}

func (d *Def) validate() error {
	if !idRe.MatchString(d.ID) {
		return fmt.Errorf("id must look like BBL-HTTP-0001")
	}
	if strings.TrimSpace(d.Name) == "" || strings.TrimSpace(d.Family) == "" {
		return fmt.Errorf("name and family are required")
	}
	if !severities[d.Severity] {
		return fmt.Errorf("severity must be info, low, medium, high or critical")
	}
	if !confidences[d.Confidence] {
		return fmt.Errorf("confidence must be tentative, firm or confirmed")
	}
	f := d.Finding
	if strings.TrimSpace(f.Title) == "" || strings.TrimSpace(f.Synopsis) == "" || strings.TrimSpace(f.Remediation) == "" {
		return fmt.Errorf("finding needs title, synopsis and remediation")
	}
	for _, c := range f.CVEs {
		if !cveRe.MatchString(c) {
			return fmt.Errorf("bad CVE id %q", c)
		}
	}
	for _, c := range d.Controls {
		if !controlRe.MatchString(c) {
			return fmt.Errorf("control %q must look like NIST-800-53:AC-3", c)
		}
	}
	if d.When.Proto != "" && d.When.Proto != "tcp" && d.When.Proto != "udp" {
		return fmt.Errorf("when.proto must be tcp or udp")
	}
	if len(d.When.Ports) == 0 && len(d.When.Services) == 0 {
		return fmt.Errorf("when needs ports or services: a check must say which services it applies to")
	}
	for _, p := range d.When.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d out of range", p)
		}
	}
	switch d.Kind {
	case "passive":
		if len(d.Steps) > 0 || d.Transport != "" {
			return fmt.Errorf("a passive check sends nothing: remove steps and transport")
		}
		if len(d.Match) == 0 {
			return fmt.Errorf("a passive check needs match conditions")
		}
		for i := range d.Match {
			c := &d.Match[i]
			if !passiveField.MatchString(c.Field) {
				return fmt.Errorf("match field %q is not one of banner, product, version, name, extra, cpe, os, script:<id>", c.Field)
			}
			re, err := compile(c.Regex)
			if err != nil || re == nil {
				return fmt.Errorf("match regex for %s: %v", c.Field, orEmpty(err))
			}
			c.re = re
		}
	case "probe":
		if len(d.Match) > 0 {
			return fmt.Errorf("a probe check uses steps, not match")
		}
		if err := d.validateProbe(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("kind must be passive or probe")
	}
	return d.validateTests()
}

func orEmpty(err error) string {
	if err == nil {
		return "regex is required"
	}
	return err.Error()
}

func (d *Def) validateProbe() error {
	if d.Transport != "tcp" && d.Transport != "udp" && d.Transport != "http" {
		return fmt.Errorf("transport must be tcp, udp or http")
	}
	if d.Transport == "http" && d.When.Proto == "udp" || d.Transport == "udp" && d.When.Proto == "tcp" || d.Transport == "tcp" && d.When.Proto == "udp" {
		return fmt.Errorf("when.proto %q does not fit transport %s", d.When.Proto, d.Transport)
	}
	if n := len(d.Steps); n == 0 || n > MaxSteps {
		return fmt.Errorf("a probe needs 1 to %d steps", MaxSteps)
	}
	if d.Transport == "udp" && len(d.Steps) != 1 {
		return fmt.Errorf("a udp probe is one request and one reply")
	}
	for i := range d.Steps {
		s := &d.Steps[i]
		if err := s.validate(d.Transport); err != nil {
			return fmt.Errorf("step %d: %w", i+1, err)
		}
	}
	return nil
}

func (s *Step) validate(transport string) error {
	if s.Read < 0 || s.Read > MaxReadBytes {
		return fmt.Errorf("read must be 0 to %d", MaxReadBytes)
	}
	if s.Read == 0 {
		s.Read = 1024
		if transport == "http" {
			s.Read = MaxReadBytes
		}
	}
	switch transport {
	case "http":
		if s.Send != "" || s.SendHex != "" || s.HTTP == nil {
			return fmt.Errorf("an http step uses only the http: block")
		}
		h := s.HTTP
		if h.Method == "" {
			h.Method = "GET"
		}
		h.Method = strings.ToUpper(h.Method)
		if !safeMethods[h.Method] {
			return fmt.Errorf("http method %s is not allowed (GET, HEAD, OPTIONS only)", h.Method)
		}
		if !strings.HasPrefix(h.Path, "/") || len(h.Path) > MaxPathLen || strings.ContainsAny(h.Path, "\r\n \t") {
			return fmt.Errorf("http path must start with / and contain no spaces or line breaks")
		}
		if h.Scheme == "" {
			h.Scheme = "auto"
		}
		if h.Scheme != "auto" && h.Scheme != "http" && h.Scheme != "https" {
			return fmt.Errorf("http scheme must be auto, http or https")
		}
	default:
		if s.HTTP != nil {
			return fmt.Errorf("http: is only valid with transport http")
		}
		if s.Send != "" && s.SendHex != "" {
			return fmt.Errorf("use send or send_hex, not both")
		}
		if len(s.Send) > MaxSendBytes || len(s.SendHex) > 2*MaxSendBytes {
			return fmt.Errorf("payload longer than %d bytes", MaxSendBytes)
		}
		if _, err := s.payload(); err != nil {
			return err
		}
		if transport == "udp" && s.Send == "" && s.SendHex == "" {
			return fmt.Errorf("a udp step must send a request")
		}
	}
	return s.Expect.compile(transport)
}

func (e *Expect) compile(transport string) (err error) {
	if e.Status != 0 && (e.Status < 100 || e.Status > 599) {
		return fmt.Errorf("status %d out of range", e.Status)
	}
	if e.Status != 0 && transport != "http" {
		return fmt.Errorf("status is only valid for http")
	}
	if len(e.Header) > 0 && transport != "http" {
		return fmt.Errorf("header is only valid for http")
	}
	if e.body, err = compile(e.Body); err != nil {
		return fmt.Errorf("expect.body: %w", err)
	}
	if e.not, err = compile(e.Not); err != nil {
		return fmt.Errorf("expect.not: %w", err)
	}
	e.header = map[string]*regexp.Regexp{}
	for k, v := range e.Header {
		re, err := compile(v)
		if err != nil || re == nil {
			return fmt.Errorf("expect.header %s: %v", k, orEmpty(err))
		}
		e.header[strings.ToLower(k)] = re
	}
	if e.Status == 0 && e.body == nil && e.not == nil && len(e.header) == 0 {
		return fmt.Errorf("every step must expect something (status, body, not or header): a step that accepts any reply would report every open port")
	}
	return nil
}

func (d *Def) validateTests() error {
	if len(d.Tests) < 2 {
		return fmt.Errorf("every check needs at least two tests: one that should find it and one that should not")
	}
	var pos, neg bool
	for _, t := range d.Tests {
		if t.Name == "" {
			return fmt.Errorf("every test needs a name")
		}
		switch t.Want {
		case "finding":
			pos = true
		case "none":
			neg = true
		default:
			return fmt.Errorf("test %q: want must be finding or none", t.Name)
		}
		if d.Kind == "probe" && len(t.Responses) != len(d.Steps) {
			return fmt.Errorf("test %q: needs one response per step (%d)", t.Name, len(d.Steps))
		}
		if d.Kind == "passive" && t.Service == nil {
			return fmt.Errorf("test %q: a passive test needs a service", t.Name)
		}
	}
	if !pos || !neg {
		return fmt.Errorf("tests must include both want: finding and want: none")
	}
	return nil
}
