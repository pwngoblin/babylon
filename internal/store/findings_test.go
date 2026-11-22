package store

import (
	"context"
	"path/filepath"
	"testing"

	"babylon/internal/correlate"
	"babylon/internal/model"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(db)
	t.Cleanup(func() { s.Close() })
	return s
}

func TestFindingsMergeAcrossEnginesAndScans(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateScan(ctx, "a", "basic", []string{"x"}, map[string]any{})
	b, _ := s.CreateScan(ctx, "b", "basic", []string{"x"}, map[string]any{})
	cve := []string{"CVE-2021-41773"}
	fp := correlate.Fingerprint("10.0.0.5", 80, "tcp", cve, "whatever")

	// A version matcher says "tentative / medium" ...
	s1 := 6.0
	if err := s.RecordFinding(ctx, a, model.Finding{Fingerprint: fp, Address: "10.0.0.5", Port: 80, Proto: "tcp",
		Title: "Apache path traversal", Severity: "medium", CVSS: &s1, CVEs: cve, Confidence: model.ConfTentative,
		Detection: "version", Engine: "cpematch", EngineRef: "nvd", Evidence: "Apache 2.4.49"}); err != nil {
		t.Fatal(err)
	}
	// ... then Nuclei verifies it: stronger confidence, worse severity, higher CVSS.
	s2 := 7.5
	if err := s.RecordFinding(ctx, a, model.Finding{Fingerprint: fp, Address: "10.0.0.5", Port: 80, Proto: "tcp",
		Title: "Apache 2.4.49 traversal", Severity: "high", CVSS: &s2, CVEs: cve, Confidence: model.ConfConfirmed,
		Detection: "behaviour", Engine: "nuclei", EngineRef: "CVE-2021-41773", Evidence: "GET /cgi-bin/.%2e/ -> 200"}); err != nil {
		t.Fatal(err)
	}
	// A weaker re-report must not downgrade.
	if err := s.RecordFinding(ctx, a, model.Finding{Fingerprint: fp, Address: "10.0.0.5", Port: 80, Proto: "tcp",
		Title: "x", Severity: "low", Confidence: model.ConfTentative, Engine: "cpematch", EngineRef: "nvd", Evidence: "Apache 2.4.49"}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListFindings(ctx, a, "")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	r := rows[0]
	if r.Severity != "high" || r.Confidence != model.ConfConfirmed || r.Detection != "behaviour" || *r.CVSS != 7.5 ||
		len(r.Engines) != 2 || len(r.CVEs) != 1 || r.Title != "Apache path traversal" {
		t.Fatalf("merge wrong: %+v", r)
	}
	// Same finding in a second scan shares the finding row (diffing basis).
	s.RecordFinding(ctx, b, model.Finding{Fingerprint: fp, Address: "10.0.0.5", Port: 80, Proto: "tcp", Title: "t", Severity: "high",
		Confidence: model.ConfConfirmed, Engine: "nuclei", EngineRef: "CVE-2021-41773"})
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM finding`).Scan(&n)
	if n != 1 {
		t.Fatalf("finding rows=%d, want 1 shared across scans", n)
	}
	// Confidence filtering hides, never deletes.
	hi, _ := s.ListFindings(ctx, a, model.ConfConfirmed)
	all, _ := s.ListFindings(ctx, a, "")
	if len(hi) != 1 || len(all) != 1 {
		t.Fatal("filter wrong")
	}
}

func TestEvidenceAccumulatesWithoutDuplicates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id, _ := s.CreateScan(ctx, "a", "basic", []string{"x"}, map[string]any{})
	f := model.Finding{Fingerprint: "fp1", Address: "10.0.0.5", Title: "Missing headers", Severity: "info", Engine: "nuclei", EngineRef: "hdrs"}
	for _, ev := range []string{"missing: hsts", "missing: csp", "missing: hsts", "missing: csp"} {
		f.Evidence = ev
		if err := s.RecordFinding(ctx, id, f); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := s.ListFindings(ctx, id, "")
	if rows[0].Evidence != "missing: hsts\nmissing: csp" {
		t.Fatalf("evidence=%q", rows[0].Evidence)
	}
}

func TestKBAndCheckRuns(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id, _ := s.CreateScan(ctx, "a", "basic", []string{"x"}, map[string]any{})
	aid, _ := s.AssetID(ctx, "10.0.0.5")
	aid2, _ := s.AssetID(ctx, "10.0.0.5")
	if aid != aid2 {
		t.Fatal("AssetID must be stable")
	}
	s.SetKB(ctx, id, aid, "Services/redis", []int{6379}, "nmap")
	s.SetKB(ctx, id, aid, "Services/redis", []int{6379, 6380}, "nmap") // overwrite
	kb, _ := s.KB(ctx, id, aid)
	if string(kb["Services/redis"]) != "[6379,6380]" {
		t.Fatalf("kb=%v", kb)
	}
	s.RecordCheckRun(ctx, id, aid, "redis-noauth", "ran", "")
	s.RecordCheckRun(ctx, id, aid, "ftp-anon", "skipped", "no ftp service")
	c, _ := s.CheckRunCounts(ctx, id)
	if c["ran"] != 1 || c["skipped"] != 1 {
		t.Fatalf("counts=%v", c)
	}
}
