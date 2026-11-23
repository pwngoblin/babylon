package store

import (
	"context"
	"testing"

	"babylon/internal/correlate"
	"babylon/internal/model"
)

func f64(v float64) *float64 { return &v }

func TestFindingEnrichedWithKEVEPSSAndCVSS(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id, _ := s.CreateScan(ctx, "a", "basic", []string{"x"}, map[string]any{})
	_ = s.UpsertCVEs(ctx, []CVERecord{{ID: "CVE-2021-41773", CVSS: f64(7.5), Status: "Analyzed"}}, nil)
	_ = s.ReplaceKEV(ctx, []KEVEntry{{CVE: "CVE-2021-41773"}}, FeedInfo{Name: "kev"})
	_ = s.ReplaceEPSS(ctx, "2026-11-22", []EPSSEntry{{CVE: "CVE-2021-41773", Score: 0.94, Percentile: 0.99}}, FeedInfo{Name: "epss"})

	cve := []string{"CVE-2021-41773"}
	if err := s.RecordFinding(ctx, id, model.Finding{Fingerprint: correlate.Fingerprint("10.0.0.5", 80, "tcp", cve, ""),
		Address: "10.0.0.5", Port: 80, Proto: "tcp", Title: "t", Severity: "high", CVEs: cve, Confidence: model.ConfTentative,
		Detection: "version", Engine: "cpematch"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ListFindings(ctx, id, "")
	if len(rows) != 1 || !rows[0].KEV || rows[0].EPSS == nil || *rows[0].EPSS != 0.94 || rows[0].CVSS == nil || *rows[0].CVSS != 7.5 {
		t.Fatalf("%+v", rows)
	}

	// Feeds loaded AFTER the finding exists must still refresh it.
	cve2 := []string{"CVE-2020-1"}
	_ = s.RecordFinding(ctx, id, model.Finding{Fingerprint: correlate.Fingerprint("10.0.0.5", 22, "tcp", cve2, ""),
		Address: "10.0.0.5", Port: 22, Proto: "tcp", Title: "u", Severity: "low", CVEs: cve2, Engine: "cpematch"})
	_ = s.ReplaceKEV(ctx, []KEVEntry{{CVE: "CVE-2020-1"}}, FeedInfo{Name: "kev"})
	rows, _ = s.ListFindings(ctx, id, "")
	kev := map[string]bool{}
	for _, r := range rows {
		kev[r.Title] = r.KEV
	}
	if kev["t"] || !kev["u"] {
		t.Fatalf("KEV flag must follow the current catalogue: %v", kev)
	}
}

func TestVersionPlusBehaviourBecomesConfirmed(t *testing.T) {
	cve := []string{"CVE-2021-41773"}
	fp := correlate.Fingerprint("10.0.0.5", 80, "tcp", cve, "")
	version := model.Finding{Fingerprint: fp, Address: "10.0.0.5", Port: 80, Proto: "tcp", Title: "v", Severity: "high", CVEs: cve,
		Confidence: model.ConfTentative, Detection: "version", Engine: "cpematch"}
	probe := model.Finding{Fingerprint: fp, Address: "10.0.0.5", Port: 80, Proto: "tcp", Title: "p", Severity: "high", CVEs: cve,
		Confidence: model.ConfFirm, Detection: "behaviour", Engine: "nuclei", EngineRef: "CVE-2021-41773"}

	for name, order := range map[string][]model.Finding{"version first": {version, probe}, "probe first": {probe, version}} {
		s := newTestStore(t)
		ctx := context.Background()
		id, _ := s.CreateScan(ctx, "a", "basic", []string{"x"}, map[string]any{})
		for _, f := range order {
			if err := s.RecordFinding(ctx, id, f); err != nil {
				t.Fatal(err)
			}
		}
		rows, _ := s.ListFindings(ctx, id, "")
		if len(rows) != 1 || rows[0].Confidence != model.ConfConfirmed {
			t.Fatalf("%s: %+v", name, rows)
		}
	}

	// A version match alone, or two version matches, must never be confirmed.
	s := newTestStore(t)
	ctx := context.Background()
	id, _ := s.CreateScan(ctx, "a", "basic", []string{"x"}, map[string]any{})
	_ = s.RecordFinding(ctx, id, version)
	v2 := version
	v2.Engine = "cpematch2"
	_ = s.RecordFinding(ctx, id, v2)
	rows, _ := s.ListFindings(ctx, id, "")
	if rows[0].Confidence != model.ConfTentative {
		t.Fatalf("version-only evidence must stay tentative: %s", rows[0].Confidence)
	}

	// A tentative behavioural hit is not enough to confirm.
	s = newTestStore(t)
	id, _ = s.CreateScan(ctx, "a", "basic", []string{"x"}, map[string]any{})
	weak := probe
	weak.Confidence = model.ConfTentative
	_ = s.RecordFinding(ctx, id, version)
	_ = s.RecordFinding(ctx, id, weak)
	rows, _ = s.ListFindings(ctx, id, "")
	if rows[0].Confidence == model.ConfConfirmed {
		t.Fatal("a tentative probe must not confirm")
	}
}

func TestDefaultSortKEVThenConfidenceThenCVSSThenEPSS(t *testing.T) {
	rows := []FindingRow{
		{Title: "epss-high", Confidence: "firm", CVSS: f64(7), EPSS: f64(0.9), Severity: "high"},
		{Title: "epss-low", Confidence: "firm", CVSS: f64(7), EPSS: f64(0.1), Severity: "high"},
		{Title: "cvss-high", Confidence: "firm", CVSS: f64(9.8), Severity: "critical"},
		{Title: "confirmed", Confidence: "confirmed", CVSS: f64(5), Severity: "medium"},
		{Title: "kev-tentative", KEV: true, Confidence: "tentative", CVSS: f64(3), Severity: "low"},
	}
	want := []string{"kev-tentative", "confirmed", "cvss-high", "epss-high", "epss-low"}
	for i := 0; i < 3; i++ { // order must not depend on input order
		rows[0], rows[len(rows)-1-i] = rows[len(rows)-1-i], rows[0]
		got := append([]FindingRow(nil), rows...)
		for a := 1; a < len(got); a++ {
			for b := a; b > 0 && PriorityLess(got[b], got[b-1]); b-- {
				got[b], got[b-1] = got[b-1], got[b]
			}
		}
		for j, w := range want {
			if got[j].Title != w {
				t.Fatalf("pos %d = %s, want %s", j, got[j].Title, w)
			}
		}
	}
}
