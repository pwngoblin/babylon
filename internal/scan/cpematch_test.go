package scan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"babylon/internal/model"
	"babylon/internal/store"
)

func cpeStore(t *testing.T) (*store.Store, int64) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	c := func(v float64) *float64 { return &v }
	if err := st.UpsertCVEs(ctx, []store.CVERecord{
		{ID: "CVE-2021-41773", Description: "traversal", CVSS: c(7.5), Status: "Analyzed",
			Matches: []store.CPEMatch{{Vendor: "apache", Product: "http_server", Exact: "2.4.49"}}},
		{ID: "CVE-2021-42013", Description: "rce", CVSS: c(9.8), Status: "Analyzed",
			Matches: []store.CPEMatch{{Vendor: "apache", Product: "http_server", StartIncl: "2.4.49", EndExcl: "2.4.51"}}},
		{ID: "CVE-2011-2523", Description: "backdoor", CVSS: c(9.8), Status: "Analyzed",
			Matches: []store.CPEMatch{{Vendor: "vsftpd_project", Product: "vsftpd", Exact: "2.3.4"}}},
	}, nil); err != nil {
		t.Fatal(err)
	}
	_ = st.ReplaceKEV(ctx, []store.KEVEntry{{CVE: "CVE-2021-41773"}}, store.FeedInfo{Name: "kev"})
	id, err := st.CreateScan(ctx, "t", "basic", []string{"10.0.0.5"}, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	return st, id
}

func ingest(t *testing.T, st *store.Store, id int64, addr, os string, ports ...model.Port) {
	t.Helper()
	h := model.Host{Address: addr, State: "up", Ports: ports}
	if os != "" {
		h.OS = &model.OSGuess{Name: os, Family: "linux"}
	}
	if err := st.IngestHost(context.Background(), id, h); err != nil {
		t.Fatal(err)
	}
}

func apache(version, extra string) model.Port {
	return model.Port{Number: 80, Proto: "tcp", State: "open", Service: model.Service{
		Name: "http", Product: "Apache httpd", Version: version, ExtraInfo: extra, CPEs: []string{"cpe:/a:apache:http_server:2.4.49"}}}
}

func TestCPEMatchStageProducesEnrichedGroupedFindings(t *testing.T) {
	st, id := cpeStore(t)
	ctx := context.Background()
	ingest(t, st, id, "10.0.0.5", "", apache("2.4.49", "(Unix)"))
	all, _ := st.OpenServices(ctx, id)
	if err := matchHost(ctx, st, id, "10.0.0.5", all); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.ListFindings(ctx, id, "")
	if len(rows) != 2 {
		t.Fatalf("want 2 CVEs, got %+v", rows)
	}
	if !rows[0].KEV || rows[0].CVEs[0] != "CVE-2021-41773" {
		t.Errorf("KEV finding must sort first: %+v", rows[0])
	}
	for _, r := range rows {
		if r.Confidence != "firm" || r.Detection != "version" || r.Product != "Apache httpd" || r.Version != "2.4.49" {
			t.Errorf("%+v", r)
		}
		if r.Engines[0] != "cpematch" || !strings.Contains(r.Evidence, "NVD affected range") {
			t.Errorf("evidence/engine: %+v", r)
		}
	}
	if rows[1].Severity != "critical" || !strings.Contains(rows[1].Remediation, "2.4.51") {
		t.Errorf("severity/remediation from NVD data: %+v", rows[1])
	}
	runs, _ := st.ListCheckRuns(ctx, id)
	if len(runs) != 1 || runs[0].CheckID != "cpe-version-match" || runs[0].State != "ran" {
		t.Errorf("coverage: %+v", runs)
	}
}

func TestCPEMatchBackportedBannerNeverConfirmed(t *testing.T) {
	for name, tc := range map[string]struct{ version, extra, os string }{
		"ubuntu banner": {"2.4.49 ((Ubuntu))", "", ""},
		"debian extra":  {"2.4.49", "Debian", ""},
		"linux host":    {"2.4.49", "", "Linux 5.15"},
	} {
		st, id := cpeStore(t)
		ctx := context.Background()
		ingest(t, st, id, "10.0.0.5", tc.os, apache(tc.version, tc.extra))
		all, _ := st.OpenServices(ctx, id)
		if err := matchHost(ctx, st, id, "10.0.0.5", all); err != nil {
			t.Fatal(err)
		}
		rows, _ := st.ListFindings(ctx, id, "")
		if len(rows) == 0 {
			t.Fatalf("%s: no findings", name)
		}
		for _, r := range rows {
			if r.Confidence != "tentative" || !strings.Contains(r.Description, "backported") {
				t.Errorf("%s: %s must be tentative with a caveat: %+v", name, r.Title, r)
			}
		}
	}
}

func TestCPEMatchSkipReasonRecordedWhenNothingIdentified(t *testing.T) {
	st, id := cpeStore(t)
	ctx := context.Background()
	ingest(t, st, id, "10.0.0.5", "", model.Port{Number: 9999, Proto: "tcp", State: "open", Service: model.Service{Name: "unknown"}})
	all, _ := st.OpenServices(ctx, id)
	_ = matchHost(ctx, st, id, "10.0.0.5", all)
	runs, _ := st.ListCheckRuns(ctx, id)
	if len(runs) != 1 || runs[0].State != "skipped" || runs[0].Reason == "" {
		t.Fatalf("an unidentifiable service must be recorded as skipped, not as clean: %+v", runs)
	}
	if rows, _ := st.ListFindings(ctx, id, ""); len(rows) != 0 {
		t.Fatalf("%+v", rows)
	}
}

func TestCPEMatchPlansNothingWithoutFeed(t *testing.T) {
	db, _ := store.Open(":memory:")
	st := store.New(db)
	defer st.Close()
	id, _ := st.CreateScan(context.Background(), "t", "basic", []string{"10.0.0.5"}, map[string]any{})
	ingest(t, st, id, "10.0.0.5", "", apache("2.4.49", ""))
	jobs, err := cpeMatchStage(st).Plan(context.Background(), store.Scan{ID: id})
	if err != nil || len(jobs) != 0 {
		t.Fatalf("no CVE data: nothing to plan. %v %v", jobs, err)
	}
}

func TestWebTechVersionsFeedTheMatcher(t *testing.T) {
	st, id := cpeStore(t)
	ctx := context.Background()
	// Nmap saw only "http" with no version; a Nuclei detection template extracted the real one.
	ingest(t, st, id, "10.0.0.5", "", model.Port{Number: 8080, Proto: "tcp", State: "open", Service: model.Service{Name: "http"}})
	aid, _ := st.AssetID(ctx, "10.0.0.5")
	if err := st.MergeKBList(ctx, id, aid, webCPEKey("10.0.0.5:8080"), []string{"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}, "nuclei"); err != nil {
		t.Fatal(err)
	}
	all, _ := st.OpenServices(ctx, id)
	if err := matchHost(ctx, st, id, "10.0.0.5", all); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.ListFindings(ctx, id, "")
	if len(rows) != 2 {
		t.Fatalf("web-detected version must produce the Apache CVEs, got %+v", rows)
	}
	for _, r := range rows {
		if r.Port != 8080 || !strings.Contains(r.Evidence, "web technology detection") {
			t.Errorf("%+v", r)
		}
	}
}
