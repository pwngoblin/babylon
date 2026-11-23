// Package group performs root-cause grouping: many CVE findings that stem from
// the same outdated product on the same service collapse into one actionable
// item ("Apache httpd 2.4.49 — 12 CVEs (1 KEV)"). Individual findings are
// never altered or deleted; a group only references them.
package group

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"babylon/internal/matcher"
	"babylon/internal/model"
	"babylon/internal/pkgver"
	"babylon/internal/store"
)

// Group is one root cause with its member findings.
type Group struct {
	Address    string
	Port       int
	Proto      string
	Product    string
	Version    string
	Title      string
	Severity   string
	Confidence string // weakest member: a group is only as certain as its least certain claim
	KEVCount   int
	MaxCVSS    *float64
	MaxEPSS    *float64
	CVEs       []string
	Fix        string // consolidated remediation
	Members    []store.FindingRow
}

type key struct {
	addr    string
	port    int
	proto   string
	product string
	version string
}

var upgradeTo = regexp.MustCompile(`to (\S+) or later`)
var upgradeCmd = regexp.MustCompile(`Command: (.+)$`)

const familyPackage = "Outdated package"

// schemeOf infers the packaging system from the upgrade command, which the
// credentialed audit writes into each remediation.
func schemeOf(rem string) string {
	switch {
	case strings.Contains(rem, "apt-get"):
		return "deb"
	case strings.Contains(rem, "dnf "):
		return "rpm"
	case strings.Contains(rem, "apk upgrade"):
		return "apk"
	}
	return ""
}

// Build groups findings that share (host, port, product, version) when there
// are at least two of them. Findings without a product, and singletons, are
// returned unchanged in rest. Groups are ordered by the standard priority.
func Build(rows []store.FindingRow) (groups []Group, rest []store.FindingRow) {
	by := map[key][]store.FindingRow{}
	var order []key
	for _, r := range rows {
		if r.Product == "" || r.Version == "" {
			rest = append(rest, r)
			continue
		}
		k := key{r.Address, r.Port, r.Proto, r.Product, r.Version}
		if _, ok := by[k]; !ok {
			order = append(order, k)
		}
		by[k] = append(by[k], r)
	}
	for _, k := range order {
		m := by[k]
		if len(m) < 2 {
			rest = append(rest, m...)
			continue
		}
		groups = append(groups, build(k, m))
	}
	sort.SliceStable(groups, func(i, j int) bool { return store.PriorityLess(groups[i].asRow(), groups[j].asRow()) })
	sort.SliceStable(rest, func(i, j int) bool { return store.PriorityLess(rest[i], rest[j]) })
	return groups, rest
}

func build(k key, m []store.FindingRow) Group {
	g := Group{Address: k.addr, Port: k.port, Proto: k.proto, Product: k.product, Version: k.version, Members: m, Confidence: model.ConfConfirmed}
	cves := map[string]bool{}
	fixed, fixedCmd := "", ""
	pkgs := true
	for _, r := range m {
		if r.Family != familyPackage {
			pkgs = false
		}
		if model.SeverityRank(r.Severity) > model.SeverityRank(g.Severity) {
			g.Severity = r.Severity
		}
		if model.ConfidenceRank(r.Confidence) < model.ConfidenceRank(g.Confidence) {
			g.Confidence = r.Confidence
		}
		if r.KEV {
			g.KEVCount++
		}
		if r.CVSS != nil && (g.MaxCVSS == nil || *r.CVSS > *g.MaxCVSS) {
			v := *r.CVSS
			g.MaxCVSS = &v
		}
		if r.EPSS != nil && (g.MaxEPSS == nil || *r.EPSS > *g.MaxEPSS) {
			v := *r.EPSS
			g.MaxEPSS = &v
		}
		for _, c := range r.CVEs {
			cves[c] = true
		}
		if mm := upgradeTo.FindStringSubmatch(r.Remediation); mm != nil {
			newer := fixed == ""
			if !newer {
				if sc := schemeOf(r.Remediation); sc != "" {
					c, _ := pkgver.Compare(sc, mm[1], fixed)
					newer = c > 0
				} else {
					newer = matcher.Compare(mm[1], fixed) > 0
				}
			}
			if newer {
				fixed = mm[1]
				if c := upgradeCmd.FindStringSubmatch(r.Remediation); c != nil {
					fixedCmd = c[1]
				}
			}
		}
	}
	for c := range cves {
		g.CVEs = append(g.CVEs, c)
	}
	sort.Strings(g.CVEs)
	kev := ""
	if g.KEVCount > 0 {
		kev = fmt.Sprintf(" (%d KEV)", g.KEVCount)
	}
	g.Title = fmt.Sprintf("%s %s — %d CVEs%s", k.product, k.version, len(g.CVEs), kev)
	if pkgs && fixed != "" {
		g.Title = fmt.Sprintf("Outdated package: %s (%s -> %s)", k.product, k.version, fixed)
		g.Fix = fmt.Sprintf("Upgrade %s to %s or later; this resolves %d CVE(s)%s.", k.product, fixed, len(g.CVEs), kev)
		if fixedCmd != "" {
			g.Fix += " Run: " + fixedCmd
		}
	} else if fixed != "" {
		g.Fix = fmt.Sprintf("Upgrade %s to %s or later; this resolves all %d CVEs listed.", k.product, fixed, len(g.CVEs))
	} else {
		g.Fix = fmt.Sprintf("Upgrade %s to a currently supported release; check the vendor advisories for the %d CVEs listed.", k.product, len(g.CVEs))
	}
	return g
}

func (g Group) asRow() store.FindingRow {
	return store.FindingRow{Address: g.Address, Title: g.Title, Severity: g.Severity, Confidence: g.Confidence,
		KEV: g.KEVCount > 0, CVSS: g.MaxCVSS, EPSS: g.MaxEPSS}
}
