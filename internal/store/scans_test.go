package store

import (
	"context"
	"testing"

	"babylon/internal/model"
)

func TestHistoryDiffAndDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateScan(ctx, "monday", "basic", []string{"10.0.0.0/24"}, map[string]any{})
	b, _ := s.CreateScan(ctx, "tuesday", "basic", []string{"10.0.0.0/24"}, map[string]any{})
	mk := func(fp, title, sev string) model.Finding {
		return model.Finding{Fingerprint: fp, Address: "10.0.0.5", Port: 80, Proto: "tcp", Title: title, Severity: sev, Engine: "nuclei", EngineRef: fp}
	}
	// A: persisting + fixed ; B: persisting + new
	s.RecordFinding(ctx, a, mk("persist", "Persisting", "high"))
	s.RecordFinding(ctx, a, mk("fixed", "Fixed later", "medium"))
	s.RecordFinding(ctx, b, mk("persist", "Persisting", "high"))
	s.RecordFinding(ctx, b, mk("new", "Brand new", "critical"))
	s.IngestHost(ctx, b, model.Host{Address: "10.0.0.5", State: "up", Ports: []model.Port{{Number: 80, Proto: "tcp", State: "open"}}})
	s.SetScanStatus(ctx, a, ScanCompleted)

	d, err := s.DiffScans(ctx, a, b)
	if err != nil || len(d.New) != 1 || d.New[0].Title != "Brand new" || len(d.Resolved) != 1 || d.Resolved[0].Title != "Fixed later" || len(d.Persisting) != 1 {
		t.Fatalf("diff=%+v err=%v", d, err)
	}

	list, _ := s.ListScans(ctx)
	if len(list) != 2 || list[0].ID != b || list[0].Findings["critical"] != 1 || list[0].Hosts != 1 || list[1].Status != ScanCompleted {
		t.Fatalf("list=%+v", list)
	}

	// Deleting scan A keeps what B still references, and drops findings nothing references.
	if err := s.DeleteScan(ctx, a); err != nil {
		t.Fatal(err)
	}
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM finding`).Scan(&n)
	if n != 2 { // persist + new; "fixed" was only in A
		t.Fatalf("findings after delete=%d, want 2", n)
	}
	if fb, _ := s.ListFindings(ctx, b, ""); len(fb) != 2 {
		t.Fatalf("B lost findings: %v", fb)
	}
	if err := s.DeleteScan(ctx, a); err == nil {
		t.Fatal("deleting a missing scan must error")
	}
	// Deleting B cascades its services and leaves no orphans.
	s.DeleteScan(ctx, b)
	for _, q := range []string{`SELECT COUNT(*) FROM finding`, `SELECT COUNT(*) FROM service`, `SELECT COUNT(*) FROM finding_occurrence`, `SELECT COUNT(*) FROM host_observation`} {
		s.DB.QueryRow(q).Scan(&n)
		if n != 0 {
			t.Errorf("%s = %d after deleting all scans", q, n)
		}
	}
}
