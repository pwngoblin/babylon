package store

import (
	"context"
	"path/filepath"
	"testing"

	"babylon/internal/model"
)

func TestAssetsCriticalityFragileTagsAndRanking(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	st := New(db)
	defer st.Close()
	ctx := context.Background()
	scan, _ := st.CreateScan(ctx, "s", "basic", []string{"10.0.0.0/24"}, map[string]any{})
	for _, h := range []string{"10.0.0.5", "10.0.0.6"} {
		st.IngestHost(ctx, scan, model.Host{Address: h, State: "up"})
		st.RecordFinding(ctx, scan, model.Finding{Fingerprint: "fp-" + h, Address: h, Title: "Same issue", Severity: "high",
			Confidence: model.ConfConfirmed, Engine: "native", EngineRef: "x"})
	}
	crit, tags, fr := CritCritical, []string{"db", "prod"}, true
	if err := st.UpdateAsset(ctx, "10.0.0.6", AssetUpdate{Criticality: &crit, Tags: &tags, Fragile: &fr}); err != nil {
		t.Fatal(err)
	}
	// Setting attributes before a host was ever scanned creates it.
	if err := st.UpdateAsset(ctx, "10.0.0.99", AssetUpdate{Criticality: &crit}); err != nil {
		t.Fatal(err)
	}
	// A later scan must not reset what a person set.
	st.IngestHost(ctx, scan, model.Host{Address: "10.0.0.6", State: "up", OS: &model.OSGuess{Name: "Linux"}})

	list, err := st.ListAssets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].Criticality != CritCritical {
		t.Fatalf("critical assets must sort first: %+v", list)
	}
	var a6 Asset
	for _, a := range list {
		if a.Address == "10.0.0.6" {
			a6 = a
		}
	}
	if a6.Criticality != CritCritical || !a6.Fragile || len(a6.Tags) != 2 || a6.OpenFindings["high"] != 1 {
		t.Fatalf("attributes lost or wrong: %+v", a6)
	}
	if !st.IsFragile(ctx, "10.0.0.6") || st.IsFragile(ctx, "10.0.0.5") || st.IsFragile(ctx, "nope") {
		t.Fatal("IsFragile")
	}
	fs, _ := st.ListFindings(ctx, scan, "")
	if len(fs) != 2 || fs[0].Address != "10.0.0.6" {
		t.Fatalf("the same finding on a critical asset must rank first: %+v", fs)
	}
	bad := 9
	if err := st.UpdateAsset(ctx, "10.0.0.5", AssetUpdate{Criticality: &bad}); err == nil {
		t.Fatal("out-of-range criticality accepted")
	}
	if n, err := ParseCriticality("High"); err != nil || n != CritHigh {
		t.Fatal("ParseCriticality")
	}
	if _, err := ParseCriticality("urgent"); err == nil {
		t.Fatal("unknown criticality accepted")
	}
}
