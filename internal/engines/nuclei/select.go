package nuclei

import (
	"sort"
	"strings"

	"babylon/internal/policy"
	"babylon/internal/store"
)

// Index is an in-memory, safety-filtered view of the template index. Templates
// that violate the active policy are removed at construction, so no later code
// path can select them.
type Index struct {
	tpls    []store.NucleiTemplate
	byTag   map[string][]int
	byProd  map[string][]int
	Removed int // templates dropped by the safety filter
}

// unsupportedProtocols never apply to network targets Babylon scans.
var unsupportedProtocols = map[string]bool{"workflow": true, "file": true, "dns": true, "whois": true}

// NewIndex applies the policy's exclusions (tags and protocols) and builds
// lookup tables.
func NewIndex(all []store.NucleiTemplate, cfg policy.NucleiConfig) *Index {
	ix := &Index{byTag: map[string][]int{}, byProd: map[string][]int{}}
	denyTag := toSet(cfg.ExcludeTags)
	denyProto := toSet(cfg.ExcludeProtocols)
	for _, t := range all {
		if hasAny(t.Tags, denyTag) || hasAnyP(t.Protocols, denyProto) || hasAnyP(t.Protocols, unsupportedProtocols) {
			ix.Removed++
			continue
		}
		i := len(ix.tpls)
		ix.tpls = append(ix.tpls, t)
		for _, tag := range t.Tags {
			ix.byTag[tag] = append(ix.byTag[tag], i)
		}
		if t.Product != "" {
			ix.byProd[normToken(t.Product)] = append(ix.byProd[normToken(t.Product)], i)
		}
	}
	return ix
}

// Len is the number of usable templates.
func (ix *Index) Len() int { return len(ix.tpls) }

// Profile bounds how broad generic (technology-independent) web checks are.
type Profile struct {
	GenericTags []string // generic web tags to run against every HTTP target
	MinSeverity string   // minimum severity for generic templates
	DetectTags  []string // tags of the cheap technology-detection phase
}

// ProfileFor returns the generic-check profile for a template name.
func ProfileFor(template string) Profile {
	switch template {
	case policy.TemplateFullUnauth, policy.TemplateCredentialed:
		return Profile{GenericTags: []string{"misconfig", "exposure", "panel"}, MinSeverity: "info", DetectTags: []string{"tech", "detect"}}
	default: // basic
		return Profile{GenericTags: []string{"misconfig", "exposure"}, MinSeverity: "medium", DetectTags: []string{"tech"}}
	}
}

// Detect returns the cheap technology-detection templates for HTTP targets
// (phase 1). These are informational and produce the facts that later phases
// use, analogous to Nessus's service-detection plugins.
func (ix *Index) Detect(p Profile) []string {
	set := map[int]bool{}
	for _, tag := range p.DetectTags {
		for _, i := range ix.byTag[tag] {
			t := ix.tpls[i]
			if has(t.Protocols, "http") && !has(t.Tags, "cve") {
				set[i] = true
			}
		}
	}
	return ix.paths(set)
}

// ForTokens returns templates relevant to detected technologies. proto is
// "http" or "net" (non-HTTP services). For http, generic misconfiguration and
// exposure checks per the profile are added. Templates already run in the
// detect phase are excluded unless includeDetect is set.
func (ix *Index) ForTokens(proto string, tokens []string, p Profile) []string {
	wantProto := func(t store.NucleiTemplate) bool {
		if proto == "http" {
			return has(t.Protocols, "http")
		}
		return has(t.Protocols, "tcp") || has(t.Protocols, "ssl")
	}
	set := map[int]bool{}
	for _, tok := range tokens {
		tok = normToken(tok)
		if tok == "" || stopTokens[tok] {
			continue
		}
		for _, i := range ix.byTag[tok] {
			if wantProto(ix.tpls[i]) {
				set[i] = true
			}
		}
		for _, i := range ix.byProd[tok] {
			if wantProto(ix.tpls[i]) {
				set[i] = true
			}
		}
	}
	if proto == "http" {
		min := severityRank(p.MinSeverity)
		for _, tag := range p.GenericTags {
			for _, i := range ix.byTag[tag] {
				t := ix.tpls[i]
				if has(t.Protocols, "http") && !has(t.Tags, "cve") && severityRank(t.Severity) >= min {
					set[i] = true
				}
			}
		}
	}
	// detect-phase templates already ran
	for _, tag := range p.DetectTags {
		for _, i := range ix.byTag[tag] {
			if !has(ix.tpls[i].Tags, "cve") {
				delete(set, i)
			}
		}
	}
	return ix.paths(set)
}

func (ix *Index) paths(set map[int]bool) []string {
	out := make([]string, 0, len(set))
	for i := range set {
		out = append(out, ix.tpls[i].Path)
	}
	sort.Strings(out)
	return out
}

// stopTokens are too generic to select templates by.
var stopTokens = map[string]bool{
	"http": true, "https": true, "ssl": true, "tcp": true, "udp": true, "tls": true, "unknown": true, "tcpwrapped": true,
	"server": true, "httpd": true, "key": true, "value": true, "store": true, "net": true, "golang": true, "protocol": true,
	"http-proxy": true, "web": true, "service": true, "daemon": true, "the": true, "and": true, "for": true, "version": true,
}

func normToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer("_", "-", " ", "-").Replace(s)
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	}
	return 1
}

func toSet(l []string) map[string]bool {
	m := make(map[string]bool, len(l))
	for _, s := range l {
		m[s] = true
	}
	return m
}

func hasAny(list []string, set map[string]bool) bool {
	for _, s := range list {
		if set[s] {
			return true
		}
	}
	return false
}

func hasAnyP(list []string, set map[string]bool) bool { return hasAny(list, set) }

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// TokensForService derives search tokens from what Nmap learned about a
// service: CPE vendor/product first (most precise), then the product's first
// word, then the service name.
func TokensForService(name, product string, cpes []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = normToken(s)
		if s != "" && !stopTokens[s] && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, c := range cpes {
		p := strings.Split(c, ":")
		var vendor, prod string
		switch {
		case len(p) >= 5 && p[1] == "2.3": // cpe:2.3:a:vendor:product:version...
			vendor, prod = p[3], p[4]
		case len(p) >= 4 && p[0] == "cpe": // cpe:/a:vendor:product:version
			vendor, prod = p[2], p[3]
		}
		add(prod)
		add(vendor)
	}
	if f := strings.Fields(strings.ToLower(product)); len(f) > 0 {
		add(f[0])
	}
	add(name)
	return out
}
