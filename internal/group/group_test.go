package group

import (
	"strings"
	"testing"

	"babylon/internal/store"
)

func f(v float64) *float64 { return &v }

func row(cve, sev, conf string, cvss float64, kev bool, fix string) store.FindingRow {
	return store.FindingRow{Address: "10.0.0.5", Port: 80, Proto: "tcp", Product: "Apache httpd", Version: "2.4.49",
		Title: cve, CVEs: []string{cve}, Severity: sev, Confidence: conf, CVSS: f(cvss), KEV: kev, Remediation: fix}
}

func TestGroupsSameRootCauseOnly(t *testing.T) {
	rows := []store.FindingRow{
		row("CVE-1", "high", "firm", 7.5, true, "Upgrade Apache httpd to 2.4.51 or later."),
		row("CVE-2", "critical", "tentative", 9.8, false, "Upgrade Apache httpd to 2.4.55 or later."),
		row("CVE-3", "medium", "firm", 5, false, "Upgrade Apache httpd to 2.4.9 or later."),
		{Address: "10.0.0.5", Port: 22, Proto: "tcp", Product: "OpenSSH", Version: "8.4", Title: "solo", Severity: "low", Confidence: "firm"}, // singleton
		{Address: "10.0.0.5", Port: 6379, Title: "no product", Severity: "high", Confidence: "firm"},
		{Address: "10.0.0.6", Port: 80, Proto: "tcp", Product: "Apache httpd", Version: "2.4.49", Title: "other host", Severity: "low", Confidence: "firm"},
	}
	groups, rest := Build(rows)
	if len(groups) != 1 || len(rest) != 3 {
		t.Fatalf("groups=%d rest=%d", len(groups), len(rest))
	}
	g := groups[0]
	if g.Title != "Apache httpd 2.4.49 — 3 CVEs (1 KEV)" {
		t.Errorf("title %q", g.Title)
	}
	if g.Severity != "critical" || *g.MaxCVSS != 9.8 || g.KEVCount != 1 || len(g.Members) != 3 {
		t.Errorf("%+v", g)
	}
	if g.Confidence != "tentative" {
		t.Errorf("a group is only as certain as its weakest member, got %s", g.Confidence)
	}
	if !strings.Contains(g.Fix, "2.4.55") {
		t.Errorf("fix must name the highest fixed version (and compare 2.4.9 < 2.4.55 numerically): %s", g.Fix)
	}
	if len(g.CVEs) != 3 || g.CVEs[0] != "CVE-1" {
		t.Errorf("cves %v", g.CVEs)
	}
}

func TestGroupsOrderedByPriority(t *testing.T) {
	mk := func(prod string, kev bool, cvss float64) []store.FindingRow {
		a := row("A-"+prod, "high", "firm", cvss, kev, "")
		b := row("B-"+prod, "high", "firm", cvss, kev, "")
		a.Product, b.Product, a.Port, b.Port = prod, prod, len(prod), len(prod)
		return []store.FindingRow{a, b}
	}
	var rows []store.FindingRow
	rows = append(rows, mk("low", false, 5)...)
	rows = append(rows, mk("kev", true, 3)...)
	rows = append(rows, mk("high", false, 9)...)
	groups, _ := Build(rows)
	if groups[0].Product != "kev" || groups[1].Product != "high" || groups[2].Product != "low" {
		t.Fatalf("%s %s %s", groups[0].Product, groups[1].Product, groups[2].Product)
	}
}

func TestPackageGroupUsesDistroVersionOrder(t *testing.T) {
	mk := func(cve, fix string) store.FindingRow {
		return store.FindingRow{Address: "h", Product: "openssl", Version: "3.0.2-0ubuntu1.10", Family: "Outdated package", Severity: "high",
			Confidence: "confirmed", CVEs: []string{cve},
			Remediation: "Upgrade openssl to " + fix + " or later. Command: apt-get update && apt-get install --only-upgrade libssl3 openssl"}
	}
	// 1.9 < 1.12 under dpkg rules but not under lexical order; upstream-style compare would also get 1.15 vs 1.9 wrong.
	gs, rest := Build([]store.FindingRow{mk("CVE-1", "3.0.2-0ubuntu1.9"), mk("CVE-2", "3.0.2-0ubuntu1.15"), mk("CVE-3", "3.0.2-0ubuntu1.12")})
	if len(gs) != 1 || len(rest) != 0 {
		t.Fatalf("groups=%d rest=%d", len(gs), len(rest))
	}
	g := gs[0]
	if g.Title != "Outdated package: openssl (3.0.2-0ubuntu1.10 -> 3.0.2-0ubuntu1.15)" {
		t.Errorf("title %q", g.Title)
	}
	if !strings.Contains(g.Fix, "apt-get update && apt-get install --only-upgrade libssl3 openssl") || !strings.Contains(g.Fix, "3 CVE") {
		t.Errorf("fix %q", g.Fix)
	}
}
