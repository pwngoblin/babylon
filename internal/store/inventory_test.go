package store

import (
	"context"
	"path/filepath"
	"testing"

	"babylon/internal/model"
)

func TestIngestIsIdempotentAndKeepsRichData(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(db)
	defer s.Close()
	ctx := context.Background()
	scanID, _ := s.CreateScan(ctx, "t", "basic", []string{"10.0.0.0/24"}, map[string]any{})

	// 1) sweep: host is up, nothing else known
	if err := s.IngestHost(ctx, scanID, model.Host{Address: "10.0.0.5", State: "up", MAC: "aa:bb"}); err != nil {
		t.Fatal(err)
	}
	// 2) port scan, ingested TWICE (a retried job)
	full := model.Host{Address: "10.0.0.5", State: "up", OS: &model.OSGuess{Name: "Linux 5", Family: "linux"},
		Hostnames: []string{"web.lab"},
		Ports: []model.Port{{Number: 443, Proto: "tcp", State: "open",
			Service: model.Service{Name: "http", Product: "nginx", Version: "1.16.0", CPEs: []string{"cpe:/a:nginx"}},
			TLS:     &model.TLS{KeyType: "rsa", KeyBits: 1024, Weak: []string{"RSA key shorter than 2048 bits (1024)"}}}}}
	for i := 0; i < 2; i++ {
		if err := s.IngestHost(ctx, scanID, full); err != nil {
			t.Fatal(err)
		}
	}
	// 3) a later sweep with no OS/MAC must not erase what we learned
	if err := s.IngestHost(ctx, scanID, model.Host{Address: "10.0.0.5", State: "up"}); err != nil {
		t.Fatal(err)
	}

	count := func(q string) (n int) { db.QueryRow(q).Scan(&n); return }
	if count(`SELECT COUNT(*) FROM asset`) != 1 || count(`SELECT COUNT(*) FROM service`) != 1 ||
		count(`SELECT COUNT(*) FROM tls_info`) != 1 || count(`SELECT COUNT(*) FROM host_observation`) != 1 {
		t.Fatal("ingest duplicated rows")
	}
	var os, mac, names string
	db.QueryRow(`SELECT os_family, mac, hostnames FROM asset`).Scan(&os, &mac, &names)
	if os != "linux" || mac != "aa:bb" || names != `["web.lab"]` {
		t.Fatalf("richer data was erased: os=%q mac=%q names=%q", os, mac, names)
	}

	live, _ := s.LiveHosts(ctx, scanID)
	if len(live) != 1 || live[0] != "10.0.0.5" {
		t.Fatalf("live=%v", live)
	}
	rows, _ := s.ListServices(ctx, scanID)
	if len(rows) != 1 || rows[0].Product != "nginx" || len(rows[0].TLSWeak) != 1 {
		t.Fatalf("rows=%+v", rows)
	}
}

func TestSameAssetAcrossScans(t *testing.T) {
	db, _ := Open(filepath.Join(t.TempDir(), "i.db"))
	s := New(db)
	defer s.Close()
	ctx := context.Background()
	a, _ := s.CreateScan(ctx, "a", "basic", []string{"x"}, map[string]any{})
	b, _ := s.CreateScan(ctx, "b", "basic", []string{"x"}, map[string]any{})
	h := model.Host{Address: "10.0.0.5", State: "up", Ports: []model.Port{{Number: 22, Proto: "tcp", State: "open"}}}
	s.IngestHost(ctx, a, h)
	s.IngestHost(ctx, b, h)
	var assets, services int
	db.QueryRow(`SELECT COUNT(*) FROM asset`).Scan(&assets)
	db.QueryRow(`SELECT COUNT(*) FROM service`).Scan(&services)
	if assets != 1 || services != 2 {
		t.Fatalf("assets=%d services=%d (asset shared, services per scan)", assets, services)
	}
}
