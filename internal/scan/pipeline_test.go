package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"babylon/internal/engines/nmap"
	"babylon/internal/orchestrator"
	"babylon/internal/policy"
	"babylon/internal/store"
)

// fakeNmap installs a stand-in `nmap` on PATH that records its argv and writes
// a fixture to the -oX path. mode "ok" copies the fixture, "fail" exits 1.
func fakeNmap(t *testing.T, scanFixture, mode string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls.log")
	scanFx, _ := filepath.Abs(scanFixture)
	sweepFx, _ := filepath.Abs("../../testdata/nmap/sweep.xml")
	// Like the real tool: a -sn sweep yields hosts only; a scan yields ports.
	script := `#!/bin/sh
echo "$@" >> "` + logPath + `"
out=""; sweep=0
for a in "$@"; do [ "$a" = "-sn" ] && sweep=1; done
while [ $# -gt 0 ]; do [ "$1" = "-oX" ] && out="$2"; shift; done
if [ "` + mode + `" = "fail" ]; then echo "nmap exploded" >&2; exit 1; fi
if [ $sweep = 1 ]; then cp "` + sweepFx + `" "$out"; else cp "` + scanFx + `" "$out"; fi
`
	if err := os.WriteFile(filepath.Join(dir, "nmap"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func setup(t *testing.T, template string) (*store.Store, int64, *policy.Resolved) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	t.Cleanup(func() { st.Close() })
	res, err := policy.Resolve(template, policy.Flags{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateScan(context.Background(), "t", template, []string{"10.0.0.0/29"}, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	return st, id, res
}

func run(t *testing.T, st *store.Store, id int64, res *policy.Resolved) orchestrator.Summary {
	t.Helper()
	o, err := orchestrator.New(st, Stages(res, st, Options{Privilege: nmap.PrivRoot}), orchestrator.Config{
		Classes: map[string]int{ClassNmap: 2, ClassNative: 2, ClassNuclei: 1}, DataDir: t.TempDir(), BackoffBase: time.Millisecond, MaxAttempts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := o.Run(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func TestSweepThenPortscanEndToEnd(t *testing.T) {
	log := fakeNmap(t, "../../testdata/nmap/tls.xml", "ok")
	st, id, res := setup(t, policy.TemplateBasic)

	sum := run(t, st, id, res)
	if sum.Status != store.ScanCompleted || sum.Counts[StageSweep][store.JobDone] != 1 || sum.Counts[StagePortscan][store.JobDone] != 1 {
		t.Fatalf("sum=%+v", sum)
	}
	// Port scan must target only hosts the sweep found up (10.0.0.5), not the down one.
	b, _ := os.ReadFile(log)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 nmap calls, got %d:\n%s", len(lines), b)
	}
	if !strings.HasPrefix(lines[0], "-sn") || !strings.HasSuffix(lines[0], "10.0.0.0/29") {
		t.Errorf("sweep call: %s", lines[0])
	}
	if !strings.HasSuffix(lines[1], " 10.0.0.5") || strings.Contains(lines[1], "10.0.0.6") || !strings.Contains(lines[1], "-sS") {
		t.Errorf("portscan call: %s", lines[1])
	}
	rows, _ := st.ListServices(context.Background(), id)
	if len(rows) != 1 || rows[0].Port != 443 || rows[0].Product != "nginx" || len(rows[0].TLSWeak) == 0 {
		t.Fatalf("services: %+v", rows)
	}
}

func TestHostDiscoveryTemplateHasNoPortscan(t *testing.T) {
	fakeNmap(t, "../../testdata/nmap/tls.xml", "ok")
	st, id, res := setup(t, policy.TemplateHostDiscovery)
	sum := run(t, st, id, res)
	if sum.Status != store.ScanCompleted || len(sum.Counts[StagePortscan]) != 0 {
		t.Fatalf("sum=%+v", sum)
	}
	if rows, _ := st.ListServices(context.Background(), id); len(rows) != 0 {
		t.Fatal("discovery must not record services")
	}
	if live, _ := st.LiveHosts(context.Background(), id); len(live) != 1 {
		t.Fatalf("live=%v", live)
	}
}

func TestNmapFailureRetriesThenPartial(t *testing.T) {
	log := fakeNmap(t, "../../testdata/nmap/tls.xml", "fail")
	st, id, res := setup(t, policy.TemplateBasic)
	sum := run(t, st, id, res)
	if sum.Status != store.ScanPartial || sum.Counts[StageSweep][store.JobFailed] != 1 {
		t.Fatalf("sum=%+v", sum)
	}
	b, _ := os.ReadFile(log)
	if n := strings.Count(string(b), "\n"); n != 2 { // MaxAttempts=2 for the sweep; no live hosts so no portscan jobs
		t.Fatalf("expected 2 attempts, got %d", n)
	}
	var msg string
	st.DB.QueryRow(`SELECT error FROM scan_job WHERE state='failed'`).Scan(&msg)
	if !strings.Contains(msg, "nmap exploded") {
		t.Fatalf("stderr not surfaced in job error: %q", msg)
	}
}

func TestMissingNmapIsPermanent(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // nothing on PATH
	st, id, res := setup(t, policy.TemplateHostDiscovery)
	o, _ := orchestrator.New(st, Stages(res, st, Options{Privilege: nmap.PrivRoot}), orchestrator.Config{
		Classes: map[string]int{ClassNmap: 1}, DataDir: t.TempDir(), MaxAttempts: 5, BackoffBase: time.Hour,
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		sum, _ := o.Run(context.Background(), id)
		if sum.Status != store.ScanPartial {
			t.Errorf("status=%s", sum.Status)
		}
	}()
	select {
	case <-done: // returned promptly: no hour-long backoff, so it was not retried
	case <-time.After(5 * time.Second):
		t.Fatal("missing tool must fail permanently, not retry with backoff")
	}
}
