package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"babylon/internal/model"
	"babylon/internal/native"
	"babylon/internal/store"
)

// TestScaleSynthetic drives the real store, the native runner and the report
// builder with many synthetic hosts (no network, no Nmap) to find what slows
// down first. BABYLON_SCALE_HOSTS sets the size (default 1000; the plan's target
// is 5000). Skipped with -short.
func TestScaleSynthetic(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	hosts := 1000
	if v, err := strconv.Atoi(os.Getenv("BABYLON_SCALE_HOSTS")); err == nil && v > 0 {
		hosts = v
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "scale.db"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	defer st.Close()
	ctx := context.Background()
	scan, _ := st.CreateScan(ctx, "scale", "full_unauth", []string{"10.0.0.0/8"}, map[string]any{})

	step := func(name string, max time.Duration, fn func()) {
		t.Helper()
		start := time.Now()
		fn()
		d := time.Since(start)
		t.Logf("%-28s %8s  (%d hosts)", name, d.Round(time.Millisecond), hosts)
		if d > max {
			t.Errorf("%s took %s, over the %s budget", name, d, max)
		}
	}

	addr := func(i int) string { return fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256) }
	step("ingest hosts and services", 60*time.Second, func() {
		for i := 0; i < hosts; i++ {
			var ports []model.Port
			for _, p := range []struct {
				n    int
				name string
				prod string
				ver  string
			}{{22, "ssh", "OpenSSH", "8.4"}, {80, "http", "Apache httpd", "2.4.49"}, {443, "https", "nginx", "1.16.0"}, {3306, "mysql", "MySQL", "5.7.30"}, {6379, "redis", "Redis", "5.0.14"}} {
				ports = append(ports, model.Port{Number: p.n, Proto: "tcp", State: "open", Service: model.Service{Name: p.name, Product: p.prod, Version: p.ver}})
			}
			if err := st.IngestHost(ctx, scan, model.Host{Address: addr(i), State: "up", Ports: ports}); err != nil {
				t.Fatal(err)
			}
		}
	})

	checks := []native.Check{{ID: "scale-redis", Name: "r", Family: "Databases", Run: func(e *native.Env) []native.Finding {
		return []native.Finding{{Port: 6379, Proto: "tcp", Title: "Redis without authentication", Severity: "high", Synopsis: "s", Remediation: "r"}}
	}}}
	step("native checks + findings", 120*time.Second, func() {
		all, err := st.OpenServices(ctx, scan)
		if err != nil {
			t.Fatal(err)
		}
		byHost := map[string]*native.Env{}
		for _, s := range all {
			e := byHost[s.Address]
			if e == nil {
				e = &native.Env{Address: s.Address, AssetID: s.AssetID, Now: time.Now()}
				byHost[s.Address] = e
			}
			e.Services = append(e.Services, s)
		}
		for _, e := range byHost {
			e.KB = map[string]json.RawMessage{}
			if err := native.RunHost(ctx, st, scan, e, checks); err != nil {
				t.Fatal(err)
			}
		}
		// CVE-style findings for the same product versions on every host (what cpematch produces).
		for i := 0; i < hosts; i++ {
			for c := 0; c < 12; c++ {
				cve := fmt.Sprintf("CVE-2021-%05d", 40000+c)
				err := st.RecordFinding(ctx, scan, model.Finding{Fingerprint: fmt.Sprintf("cpe-%d-%d", i, c), Address: addr(i), Port: 80, Proto: "tcp",
					Title: "Apache httpd 2.4.49: " + cve, Severity: "high", CVEs: []string{cve}, Product: "Apache httpd", Version: "2.4.49",
					Confidence: model.ConfFirm, Engine: "cpematch", EngineRef: cve, Detection: "version"})
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	})

	var rep *Report
	step("summary + list findings", 60*time.Second, func() {
		if _, err := st.ListFindings(ctx, scan, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := st.GetScanSummary(ctx, scan); err != nil {
			t.Fatal(err)
		}
	})
	step("build report", 120*time.Second, func() {
		var err error
		if rep, err = Build(ctx, st, scan, "normal"); err != nil {
			t.Fatal(err)
		}
	})
	step("write markdown/html/json", 120*time.Second, func() {
		if err := WriteMarkdown(io.Discard, rep); err != nil {
			t.Fatal(err)
		}
		if err := WriteHTML(io.Discard, rep); err != nil {
			t.Fatal(err)
		}
		if err := WriteJSON(io.Discard, rep); err != nil {
			t.Fatal(err)
		}
	})
	step("compliance (nist-800-53)", 60*time.Second, func() {
		if err := AttachCompliance(ctx, st, rep, "nist-800-53", ""); err != nil {
			t.Fatal(err)
		}
	})
	step("list assets", 30*time.Second, func() {
		if l, err := st.ListAssets(ctx); err != nil || len(l) != hosts {
			t.Fatalf("assets: %d %v", len(l), err)
		}
	})
	step("second scan + trends + diff", 120*time.Second, func() {
		if err := st.SetScanStatus(ctx, scan, store.ScanCompleted); err != nil {
			t.Fatal(err)
		}
		scan2, _ := st.CreateScan(ctx, "scale2", "full_unauth", []string{"10.0.0.0/8"}, map[string]any{})
		for i := 0; i < hosts; i++ {
			st.IngestHost(ctx, scan2, model.Host{Address: addr(i), State: "up"})
			st.RecordFinding(ctx, scan2, model.Finding{Fingerprint: fmt.Sprintf("cpe-%d-%d", i, 0), Address: addr(i), Port: 80, Proto: "tcp",
				Title: "Apache httpd 2.4.49: CVE-2021-40000", Severity: "high", CVEs: []string{"CVE-2021-40000"}, Product: "Apache httpd", Version: "2.4.49",
				Confidence: model.ConfFirm, Engine: "cpematch", EngineRef: "CVE-2021-40000", Detection: "version"})
		}
		if err := st.SetScanStatus(ctx, scan2, store.ScanCompleted); err != nil {
			t.Fatal(err)
		}
		series, err := st.Trends(ctx, 0)
		if err != nil || len(series) != 1 || len(series[0].Points) != 2 {
			t.Fatalf("trends: %v %+v", err, series)
		}
		if p := series[0].Points[1]; p.Resolved < hosts*10 {
			t.Fatalf("resolved: %+v", p)
		}
	})
	t.Logf("report: %d hosts, %d findings, %d root causes", len(rep.Hosts), len(rep.Findings), len(rep.Groups))
}
