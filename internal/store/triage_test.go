package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"babylon/internal/model"
)

func triageFixture(t *testing.T) (*Store, int64, int64) {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	st := New(db)
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	id, _ := st.CreateScan(ctx, "s", "basic", []string{"10.0.0.5"}, map[string]any{})
	st.IngestHost(ctx, id, model.Host{Address: "10.0.0.5", State: "up"})
	st.RecordFinding(ctx, id, model.Finding{Fingerprint: "f1", Address: "10.0.0.5", Title: "Open thing", Severity: "high", Confidence: model.ConfConfirmed, Engine: "native", EngineRef: "x"})
	st.RecordFinding(ctx, id, model.Finding{Fingerprint: "f2", Address: "10.0.0.5", Title: "Other", Severity: "low", Confidence: model.ConfConfirmed, Engine: "native", EngineRef: "y"})
	fs, _ := st.ListFindings(ctx, id, "")
	return st, id, fs[0].ID
}

func TestTriageHidesFromCountsAndExpires(t *testing.T) {
	st, scan, fid := triageFixture(t)
	ctx := context.Background()
	now := time.Now()
	before, _ := st.GetScanSummary(ctx, scan)
	if before.Findings["high"]+before.Findings["low"] != 2 {
		t.Fatalf("before: %v", before.Findings)
	}
	exp := now.Add(30 * 24 * time.Hour)
	if err := st.SetTriage(ctx, fid, TriageAcceptedRisk, "vendor patch scheduled", &exp, now); err != nil {
		t.Fatal(err)
	}
	after, _ := st.GetScanSummary(ctx, scan)
	if after.Findings["high"]+after.Findings["low"] != 1 {
		t.Fatalf("an active decision must hide the finding from the counts: %v", after.Findings)
	}
	fs, _ := st.ListFindings(ctx, scan, "")
	hidden := 0
	for _, f := range fs {
		if f.Triage != nil && f.Triage.Active {
			hidden++
		}
	}
	if hidden != 1 {
		t.Fatalf("ListFindings must expose the decision: %d", hidden)
	}
	// An expired decision stops hiding the finding (simulate by back-dating).
	if _, err := st.DB.Exec(`UPDATE triage SET expires_at=? WHERE finding_id=?`, now.Add(-time.Hour).UTC().Format(time.RFC3339), fid); err != nil {
		t.Fatal(err)
	}
	back, _ := st.GetScanSummary(ctx, scan)
	if back.Findings["high"]+back.Findings["low"] != 2 {
		t.Fatalf("an expired decision must not hide the finding: %v", back.Findings)
	}
	rows, _ := st.ListTriage(ctx, now)
	if len(rows) != 1 || rows[0].Active {
		t.Fatalf("list should show it expired: %+v", rows)
	}
}

func TestTriageRules(t *testing.T) {
	st, _, fid := triageFixture(t)
	ctx := context.Background()
	now := time.Now()
	soon := now.Add(24 * time.Hour)
	far := now.Add(400 * 24 * time.Hour)
	past := now.Add(-time.Hour)
	cases := []struct {
		name, status, reason string
		exp                  *time.Time
		fid                  int64
		want                 string
	}{
		{"no reason", TriageFalsePositive, "  ", nil, fid, "reason"},
		{"risk without expiry", TriageAcceptedRisk, "ok", nil, fid, "needs an expiry"},
		{"risk too long", TriageAcceptedRisk, "ok", &far, fid, "365"},
		{"expiry in the past", TriageFalsePositive, "ok", &past, fid, "future"},
		{"bad status", "ignored", "ok", &soon, fid, "status"},
		{"missing finding", TriageFalsePositive, "ok", nil, 9999, "not found"},
	}
	for _, c := range cases {
		err := st.SetTriage(ctx, c.fid, c.status, c.reason, c.exp, now)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", c.name, c.want, err)
		}
	}
	if err := st.SetTriage(ctx, fid, TriageFalsePositive, "scanner banner is wrong", nil, now); err != nil {
		t.Fatalf("a false positive needs no expiry: %v", err)
	}
	if err := st.RemoveTriage(ctx, fid); err != nil {
		t.Fatal(err)
	}
	if err := st.RemoveTriage(ctx, fid); err == nil {
		t.Error("removing a missing decision must fail")
	}
}

// A finding keeps its id when it reappears, so a decision survives rescans.
func TestTriageSurvivesRescan(t *testing.T) {
	st, _, fid := triageFixture(t)
	ctx := context.Background()
	now := time.Now()
	if err := st.SetTriage(ctx, fid, TriageFalsePositive, "wrong", nil, now); err != nil {
		t.Fatal(err)
	}
	id2, _ := st.CreateScan(ctx, "s2", "basic", []string{"10.0.0.5"}, map[string]any{})
	st.IngestHost(ctx, id2, model.Host{Address: "10.0.0.5", State: "up"})
	st.RecordFinding(ctx, id2, model.Finding{Fingerprint: "f1", Address: "10.0.0.5", Title: "Open thing", Severity: "high", Confidence: model.ConfConfirmed, Engine: "native", EngineRef: "x"})
	fs, _ := st.ListFindings(ctx, id2, "")
	if len(fs) != 1 || fs[0].ID != fid || fs[0].Triage == nil || !fs[0].Triage.Active {
		t.Fatalf("decision lost on rescan: %+v", fs)
	}
}
