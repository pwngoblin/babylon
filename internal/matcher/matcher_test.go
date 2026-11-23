package matcher

import (
	"context"
	"testing"

	"babylon/internal/store"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.4.49", "2.4.51", -1},
		{"2.4.51", "2.4.51", 0},
		{"2.10.0", "2.9.9", 1}, // numeric, not lexical
		{"1.0", "1.0.0", -1},   // longer numeric tail is newer
		{"1.0rc1", "1.0", -1},  // pre-release below release
		{"1.0beta2", "1.0rc1", -1},
		{"8.4p1", "8.4", 1},    // portable patch above base
		{"8.4p1", "8.5", -1},   // but below the next release
		{"8.4-p1", "8.4p1", 0}, // NVD "version:update" form
		{"1.0.2k", "1.0.2m", -1},
		{"1.0.2a", "1.0.2", 1}, // trailing letter is a patch level, not an alpha
		{"1.0a1", "1.0", -1},   // letter+number is a pre-release
		{"v3.0.2", "3.0.2", 0},
		{"007", "7", 0},
		{"1.2.3.4.5", "1.2.3.4", 1},
		{"5.0.14", "6.0.0", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q,%q)=%d want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestCleanVersion(t *testing.T) {
	for in, want := range map[string]string{
		"8.9p1 Ubuntu 3ubuntu0.1": "8.9p1",
		"2.4.49 ((Unix))":         "2.4.49",
		"":                        "",
		"unknown":                 "",
		"Redis 5.0.14":            "5.0.14",
	} {
		if got := CleanVersion(in); got != want {
			t.Errorf("CleanVersion(%q)=%q want %q", in, got, want)
		}
	}
}

func fl(f float64) *float64 { return &f }

func seed(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	t.Cleanup(func() { st.Close() })
	recs := []store.CVERecord{
		{ID: "CVE-2021-41773", Description: "path traversal", CVSS: fl(7.5), Status: "Analyzed",
			Matches: []store.CPEMatch{{Vendor: "apache", Product: "http_server", Exact: "2.4.49"}}},
		{ID: "CVE-2021-23017", Description: "nginx resolver", CVSS: fl(7.7), Status: "Analyzed",
			Matches: []store.CPEMatch{{Vendor: "f5", Product: "nginx", StartIncl: "0.6.18", EndExcl: "1.20.1"}}},
		{ID: "CVE-2099-0001", Description: "unrelated vendor shipping a product also named nginx", CVSS: fl(1), Status: "Analyzed",
			Matches: []store.CPEMatch{{Vendor: "othervendor", Product: "nginx", Exact: "1.16.0"}}}, // two vendors => unique-vendor fallback cannot rescue a missing alias
		{ID: "CVE-2022-0543", Description: "redis lua", CVSS: fl(10), Status: "Analyzed",
			Matches: []store.CPEMatch{{Vendor: "redis", Product: "redis", StartIncl: "5.0.0", EndExcl: "5.0.15"}}},
		{ID: "CVE-2011-2523", Description: "vsftpd backdoor", CVSS: fl(9.8), Status: "Analyzed",
			Matches: []store.CPEMatch{{Vendor: "vsftpd_project", Product: "vsftpd", Exact: "2.3.4"}, {Vendor: "vsftpd_project", Product: "vsftpd", StartIncl: "3.0.0", EndIncl: "3.0.2"}}},
		{ID: "CVE-2008-2375", Description: "redhat-packaged vsftpd", CVSS: fl(5), Status: "Analyzed",
			Matches: []store.CPEMatch{{Vendor: "redhat", Product: "vsftpd", Exact: "0.0.1"}}}, // second vendor: fallback cannot hide a missing alias
		{ID: "CVE-2000-0001", Description: "every version of exotic", CVSS: fl(5), Status: "Analyzed",
			Matches: []store.CPEMatch{{Vendor: "exoticvendor", Product: "exotic"}}}, // unbounded
		{ID: "CVE-2000-0002", Description: "exotic old", CVSS: fl(5), Status: "Analyzed",
			Matches: []store.CPEMatch{{Vendor: "exoticvendor", Product: "exotic", EndExcl: "2.0"}}},
		{ID: "CVE-2023-0001", Description: "wp plugin", CVSS: fl(6), Status: "Analyzed",
			Matches: []store.CPEMatch{{Vendor: "apache", Product: "http_server", EndExcl: "9", TargetSW: "wordpress"}}},
	}
	if err := st.UpsertCVEs(context.Background(), recs, nil); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestMatchByCPEAndRange(t *testing.T) {
	st := seed(t)
	hits, stats, err := Match(context.Background(), st, Service{Port: 80, Product: "Apache httpd", Version: "2.4.49", CPEs: []string{"cpe:/a:apache:http_server:2.4.49"}})
	if err != nil || !stats.Checked {
		t.Fatal(err, stats)
	}
	if len(hits) != 1 || hits[0].CVE != "CVE-2021-41773" {
		t.Fatalf("hits=%+v (target_sw-scoped CVE must be ignored)", hits)
	}
	if hits[0].Confidence != "firm" {
		t.Errorf("upstream apache with no distro hint should be firm, got %s", hits[0].Confidence)
	}
}

func TestVendorAliasNginxAndRedis(t *testing.T) {
	st := seed(t)
	// Nmap says igor_sysoev; NVD says f5. Without the alias this returned zero in the spike.
	hits, _, err := Match(context.Background(), st, Service{Port: 80, CPEs: []string{"cpe:/a:igor_sysoev:nginx:1.16.0"}})
	if err != nil || len(hits) != 1 || hits[0].CVE != "CVE-2021-23017" || hits[0].FixedIn != "1.20.1" {
		t.Fatalf("nginx alias: %+v %v", hits, err)
	}
	hits, _, _ = Match(context.Background(), st, Service{Port: 6379, CPEs: []string{"cpe:/a:redislabs:redis:5.0.14"}})
	if len(hits) != 1 || hits[0].CVE != "CVE-2022-0543" {
		t.Fatalf("redis alias: %+v", hits)
	}
	// Nmap's real spelling (found by the live lab scan) is vsftpd:vsftpd.
	if h, _, _ := Match(context.Background(), st, Service{Port: 21, CPEs: []string{"cpe:/a:vsftpd:vsftpd:3.0.2"}}); len(h) != 1 {
		t.Fatalf("vsftpd:vsftpd alias: %+v", h)
	}
	hits, _, _ = Match(context.Background(), st, Service{Port: 21, CPEs: []string{"cpe:/a:beasts:vsftpd:3.0.2"}})
	if len(hits) != 1 || hits[0].CVE != "CVE-2011-2523" {
		t.Fatalf("vsftpd alias+range: %+v", hits)
	}
}

func TestProductOnlyFallbackAndUnbounded(t *testing.T) {
	st := seed(t)
	hits, stats, err := Match(context.Background(), st, Service{CPEs: []string{"cpe:/a:somebodyelse:exotic:1.5"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].CVE != "CVE-2000-0002" {
		t.Fatalf("hits=%+v", hits)
	}
	if stats.Unbounded != 1 {
		t.Errorf("the 'every version' range must be counted and skipped, got %d", stats.Unbounded)
	}
	if stats.AliasUsed == "" {
		t.Error("fallback must be reported")
	}
}

func TestProductNameWithoutCPE(t *testing.T) {
	st := seed(t)
	hits, _, _ := Match(context.Background(), st, Service{Product: "Redis key-value store", Version: "5.0.14"})
	if len(hits) != 1 {
		t.Fatalf("hits=%+v", hits)
	}
	if _, stats, _ := Match(context.Background(), st, Service{Product: "Redis key-value store"}); stats.Checked {
		t.Error("no version: must not claim the service was checked")
	}
}

func TestBackportConfidence(t *testing.T) {
	st := seed(t)
	base := Service{Port: 80, Product: "Apache httpd", Version: "2.4.49", CPEs: []string{"cpe:/a:apache:http_server:2.4.49"}}
	cases := []struct {
		name       string
		mod        func(*Service)
		want       string
		wantCaveat bool
	}{
		{"plain upstream", func(*Service) {}, "firm", false},
		{"ubuntu in version", func(s *Service) { s.Version = "2.4.49 (Ubuntu)" }, "tentative", true},
		{"debian in extrainfo", func(s *Service) { s.Extra = "Debian" }, "tentative", true},
		{"el8 build", func(s *Service) { s.Version = "2.4.49-1.el8" }, "tentative", true},
		{"alpine banner", func(s *Service) { s.Banner = "Server: Apache (Alpine)" }, "tentative", true},
		{"linux host, packaged product", func(s *Service) { s.OS = "Linux 5.15" }, "tentative", true},
		{"windows host", func(s *Service) { s.OS = "Microsoft Windows Server 2019" }, "firm", false},
	}
	for _, c := range cases {
		s := base
		c.mod(&s)
		hits, _, err := Match(context.Background(), st, s)
		if err != nil || len(hits) != 1 {
			t.Fatalf("%s: %v %+v", c.name, err, hits)
		}
		if hits[0].Confidence != c.want {
			t.Errorf("%s: confidence=%s want %s", c.name, hits[0].Confidence, c.want)
		}
		if (hits[0].Caveat != "") != c.wantCaveat {
			t.Errorf("%s: caveat=%q", c.name, hits[0].Caveat)
		}
		if hits[0].Confidence == "confirmed" {
			t.Errorf("%s: unauthenticated version matching must never yield confirmed", c.name)
		}
	}
}

func TestVsftpdIsNotBackportProne(t *testing.T) {
	// Spec: vsftpd/Tomcat style upstream software falls cleanly in range => firm,
	// even on a Linux host.
	if c, _ := Assess("vsftpd", "vsftpd 3.0.2", "Linux 5.4"); c != "firm" {
		t.Errorf("vsftpd on Linux = %s, want firm", c)
	}
	if c, _ := Assess("tomcat", "Apache Tomcat 9.0.1", "Linux 5.4"); c != "firm" {
		t.Errorf("tomcat on Linux = %s, want firm", c)
	}
}

func TestRangeBoundaries(t *testing.T) {
	m := store.CPEMatch{StartIncl: "1.0", EndExcl: "2.0"}
	for v, want := range map[string]bool{"0.9": false, "1.0": true, "1.9.9": true, "2.0": false, "2.0rc1": true} {
		if _, got := inRange(v, m); got != want {
			t.Errorf("[1.0,2.0) contains %s = %v want %v", v, got, want)
		}
	}
	m = store.CPEMatch{StartExcl: "1.0", EndIncl: "2.0"}
	for v, want := range map[string]bool{"1.0": false, "1.0.1": true, "2.0": true, "2.0.1": false} {
		if _, got := inRange(v, m); got != want {
			t.Errorf("(1.0,2.0] contains %s = %v want %v", v, got, want)
		}
	}
}

func TestImpreciseVersionsAreNotMatched(t *testing.T) {
	for _, v := range []string{"9.6.20 - 9.6.23 or 11.14 - 11.18", "2.2.X - 2.3.X", "2.2.X", "4", "1.x", "3.*"} {
		if ImpreciseVersion(v) == "" {
			t.Errorf("%q must be rejected", v)
		}
	}
	for _, v := range []string{"", "2.4.49", "8.4p1 Debian 5", "1.16.0", "5.0.14", "10.5.29", "4.4.30", "7.4"} {
		if why := ImpreciseVersion(v); why != "" {
			t.Errorf("%q wrongly rejected: %s", v, why)
		}
	}
	if _, st, _ := Match(context.Background(), nil, Service{Product: "Samba smbd", Version: "4", CPEs: []string{"cpe:/a:samba:samba"}}); st.Checked || st.Reason == "" {
		t.Errorf("bare major must be a visible skip: %+v", st)
	}
}
