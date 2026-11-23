package store

import (
	"context"
	"path/filepath"
	"testing"

	"babylon/internal/model"
)

func TestTrendsCompareLikeForLikeScansOnly(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	st := New(db)
	defer st.Close()
	ctx := context.Background()
	run := func(targets []string, status string, titles ...string) int64 {
		id, _ := st.CreateScan(ctx, "s", "basic", targets, map[string]any{})
		st.IngestHost(ctx, id, model.Host{Address: "10.0.0.5", State: "up"})
		for _, ti := range titles {
			st.RecordFinding(ctx, id, model.Finding{Fingerprint: "fp-" + ti, Address: "10.0.0.5", Title: ti, Severity: "high",
				Confidence: model.ConfConfirmed, Engine: "native", EngineRef: ti})
		}
		st.SetScanStatus(ctx, id, status)
		return id
	}
	a := run([]string{"10.0.0.5"}, ScanCompleted, "A", "B")
	run([]string{"10.0.9.9"}, ScanCompleted, "Z") // different targets: its own series
	b := run([]string{"10.0.0.5"}, ScanCompleted, "B", "C", "D")
	run([]string{"10.0.0.5"}, ScanFailed, "Q") // not completed: ignored
	c := run([]string{"10.0.0.5"}, ScanCompleted, "D")

	series, err := st.Trends(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 2 {
		t.Fatalf("want 2 series, got %d", len(series))
	}
	var s []TrendPoint
	for _, x := range series {
		if len(x.Targets) == 1 && x.Targets[0] == "10.0.0.5" {
			s = x.Points
		}
	}
	if len(s) != 3 || s[0].ScanID != a || s[1].ScanID != b || s[2].ScanID != c {
		t.Fatalf("points: %+v", s)
	}
	if s[0].New != 0 || s[0].Resolved != 0 {
		t.Errorf("first scan has nothing to compare with: %+v", s[0])
	}
	if s[1].New != 2 || s[1].Resolved != 1 { // C,D new; A resolved
		t.Errorf("second: %+v", s[1])
	}
	if s[2].New != 0 || s[2].Resolved != 2 { // B,C resolved
		t.Errorf("third: %+v", s[2])
	}
	if s[2].Findings["high"] != 1 {
		t.Errorf("counts: %+v", s[2].Findings)
	}
	last, _ := st.Trends(ctx, 2)
	for _, x := range last {
		if len(x.Targets) == 1 && x.Targets[0] == "10.0.0.5" && len(x.Points) != 2 {
			t.Errorf("limit not applied: %d", len(x.Points))
		}
	}
}

func TestPreviousScanIsTheLatestCompletedWithSameTargets(t *testing.T) {
	db, _ := Open(filepath.Join(t.TempDir(), "p.db"))
	st := New(db)
	defer st.Close()
	ctx := context.Background()
	mk := func(targets []string, status string) int64 {
		id, _ := st.CreateScan(ctx, "s", "basic", targets, map[string]any{})
		st.SetScanStatus(ctx, id, status)
		return id
	}
	a := mk([]string{"a"}, ScanCompleted)
	mk([]string{"b"}, ScanCompleted)
	mk([]string{"a"}, ScanFailed)
	c := mk([]string{"a"}, ScanCompleted)
	if p, _ := st.PreviousScan(ctx, c); p != a {
		t.Fatalf("previous of c = %d, want %d (the failed scan and other targets are skipped)", p, a)
	}
	if p, _ := st.PreviousScan(ctx, a); p != 0 {
		t.Fatalf("first of its series has no previous: %d", p)
	}
}
