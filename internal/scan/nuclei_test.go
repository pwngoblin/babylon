package scan

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"babylon/internal/model"
	"babylon/internal/orchestrator"
	"babylon/internal/policy"
	"babylon/internal/store"
)

// fakeNuclei puts a stand-in `nuclei` on PATH. It logs the targets and
// template list of every invocation into logDir and emits one canned result
// line: the detect fixture if the template list holds a detect/ template, else
// the scan fixture.
func fakeNuclei(t *testing.T) (logDir string) {
	t.Helper()
	dir := t.TempDir()
	logDir = t.TempDir()
	fx, _ := filepath.Abs("../../testdata/nuclei/results.jsonl")
	script := `#!/bin/sh
t=""; l=""; prev=""
for a in "$@"; do
  [ "$prev" = "-t" ] && t="$a"
  [ "$prev" = "-l" ] && l="$a"
  prev="$a"
done
n=$$
cp "$t" "` + logDir + `/templates-$n.txt"
cp "$l" "` + logDir + `/targets-$n.txt"
if grep -q "/detect/" "$t"; then grep '"template-id":"nginx-version"' "` + fx + `" | head -1
else grep '"template-id":"CVE-2021-30047"' "` + fx + `" | head -1; fi
`
	if err := os.WriteFile(filepath.Join(dir, "nuclei"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logDir
}

func tplEntry(path, sev string, protos, tags []string, product string) store.NucleiTemplate {
	return store.NucleiTemplate{Path: path, ID: filepath.Base(path), Severity: sev, Protocols: protos, Tags: tags, Product: product}
}

func readLists(t *testing.T, dir, prefix string) [][]string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, prefix+"-*.txt"))
	sort.Strings(files)
	var out [][]string
	for _, f := range files {
		b, _ := os.ReadFile(f)
		out = append(out, strings.Fields(string(b)))
	}
	return out
}

func TestNucleiTwoPhaseServiceAwarePipeline(t *testing.T) {
	logDir := fakeNuclei(t)
	st, id, res := setup(t, policy.TemplateBasic)
	ctx := context.Background()

	// Seed what Nmap would have found.
	host := model.Host{Address: "127.0.0.1", State: "up", Ports: []model.Port{
		{Number: 12121, Proto: "tcp", State: "open", Service: model.Service{Name: "ftp", Product: "vsftpd", Version: "3.0.2", CPEs: []string{"cpe:/a:vsftpd:vsftpd:3.0.2"}}},
		{Number: 18082, Proto: "tcp", State: "open", Service: model.Service{Name: "http", Product: "nginx", Version: "1.16.0", CPEs: []string{"cpe:/a:igor_sysoev:nginx:1.16.0"}}},
		{Number: 13000, Proto: "tcp", State: "open", Service: model.Service{Name: "unknown"}},
		{Number: 16379, Proto: "tcp", State: "open", Service: model.Service{Name: "redis", Product: "Redis key-value store"}}, // no templates in index
		{Number: 9999, Proto: "tcp", State: "open", Service: model.Service{Name: "tcpwrapped"}},
	}}
	if err := st.IngestHost(ctx, id, host); err != nil {
		t.Fatal(err)
	}
	// A synthetic template index including things that must never run.
	err := st.ReplaceNucleiIndex(ctx, "test", []store.NucleiTemplate{
		tplEntry("http/detect/nginx-version.yaml", "info", []string{"http"}, []string{"tech", "nginx"}, ""),
		tplEntry("http/cves/nginx-cve.yaml", "high", []string{"http"}, []string{"cve", "nginx"}, ""),
		tplEntry("http/mis/headers.yaml", "medium", []string{"http"}, []string{"misconfig", "headers"}, ""),
		tplEntry("network/cves/vsftpd.yaml", "high", []string{"tcp"}, []string{"cve", "ftp", "vsftpd"}, "vsftpd"),
		tplEntry("http/bad/dos-nginx.yaml", "high", []string{"http"}, []string{"dos", "nginx"}, ""),
		tplEntry("http/bad/intrusive-nginx.yaml", "high", []string{"http"}, []string{"intrusive", "nginx"}, ""),
		tplEntry("http/bad/default-login.yaml", "high", []string{"http"}, []string{"default-login", "nginx"}, ""),
		tplEntry("headless/bad.yaml", "high", []string{"headless"}, []string{"nginx"}, ""),
	})
	if err != nil {
		t.Fatal(err)
	}

	tplDir := t.TempDir()
	rt := newNucleiRuntime(st, res, Options{NucleiDir: tplDir, NucleiRate: 100, NucleiTimeout: time.Minute})
	stages := append([]orchestrator.Stage{{Name: StagePortscan, Class: ClassNmap, Plan: planN0, Handle: noop}}, rt.stages()...)
	o, err := orchestrator.New(st, stages, orchestrator.Config{
		Classes: map[string]int{ClassNmap: 1, ClassNuclei: 2}, DataDir: t.TempDir(), BackoffBase: time.Millisecond, MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := o.Run(ctx, id)
	if err != nil || sum.Status != store.ScanCompleted {
		t.Fatalf("sum=%+v err=%v", sum, err)
	}

	// Phase 1 (detect): HTTP candidates only: nginx + the unknown service; not ftp/redis/tcpwrapped.
	detTargets := readLists(t, logDir, "targets")
	detTemplates := readLists(t, logDir, "templates")
	if len(detTargets) != 3 {
		t.Fatalf("expected 3 nuclei runs (detect + 2 scan groups), got %d", len(detTargets))
	}
	var detectIdx = -1
	for i, tl := range detTemplates {
		if len(tl) == 1 && strings.HasSuffix(tl[0], "http/detect/nginx-version.yaml") {
			detectIdx = i
		}
	}
	if detectIdx < 0 {
		t.Fatalf("no detect run: %v", detTemplates)
	}
	got := strings.Join(detTargets[detectIdx], ",")
	if got != "http://127.0.0.1:13000,http://127.0.0.1:18082" {
		t.Errorf("detect targets = %s", got)
	}

	// No run, in any phase, may ever receive a denied template.
	for _, tl := range detTemplates {
		for _, p := range tl {
			for _, bad := range []string{"/bad/", "headless/"} {
				if strings.Contains(p, bad) {
					t.Errorf("denied template passed to nuclei: %s", p)
				}
			}
			if !strings.HasPrefix(p, tplDir) {
				t.Errorf("template path outside templates root: %s", p)
			}
		}
	}

	// Phase 2: nginx http group gets nginx CVE + medium+ generic checks (and not the detect template again);
	// ftp gets the network template. redis has no templates -> skipped and recorded.
	var sawHTTP, sawFTP bool
	for i, tl := range detTemplates {
		joined := strings.Join(tl, " ")
		switch {
		case strings.Contains(joined, "nginx-cve.yaml"):
			sawHTTP = true
			if !strings.Contains(joined, "headers.yaml") || strings.Contains(joined, "nginx-version.yaml") {
				t.Errorf("http scan templates wrong: %v", tl)
			}
			if !strings.Contains(strings.Join(detTargets[i], ","), "http://127.0.0.1:18082") {
				t.Errorf("http scan targets: %v", detTargets[i])
			}
		case strings.Contains(joined, "vsftpd.yaml"):
			sawFTP = true
			if strings.Join(detTargets[i], ",") != "127.0.0.1:12121" || len(tl) != 1 {
				t.Errorf("ftp run: targets=%v templates=%v", detTargets[i], tl)
			}
		}
	}
	if !sawHTTP || !sawFTP {
		t.Fatalf("missing scan runs http=%v ftp=%v", sawHTTP, sawFTP)
	}

	// KB learned nginx from the detect phase, and findings from both phases are stored.
	aid, _ := st.AssetID(ctx, "127.0.0.1")
	tech, _ := st.KBList(ctx, id, aid, "Web/127.0.0.1:18082/tech")
	if len(tech) != 1 || tech[0] != "nginx" {
		t.Errorf("KB tech = %v", tech)
	}
	rows, _ := st.ListFindings(ctx, id, "")
	titles := map[string]string{}
	for _, r := range rows {
		titles[r.Title] = r.Confidence
	}
	if titles["vsftpd < 3.0.3 - DoS"] != model.ConfTentative || titles["Nginx version detect"] != model.ConfConfirmed {
		t.Errorf("findings: %v", titles)
	}
	cr, _ := st.CheckRunCounts(ctx, id)
	// skipped and recorded for coverage: redis (no templates), tcpwrapped and 13000 (unidentified, detect found nothing)
	if cr["skipped"] != 3 {
		t.Errorf("check_run skipped = %d (%v), want 3", cr["skipped"], cr)
	}
}

func planN0(context.Context, store.Scan) ([]store.JobSpec, error) { return nil, nil }
func noop(context.Context, store.Job) error                       { return nil }

func TestNucleiMissingBinaryIsPermanentAndScanContinues(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	st, id, res := setup(t, policy.TemplateBasic)
	ctx := context.Background()
	st.IngestHost(ctx, id, model.Host{Address: "10.0.0.5", State: "up", Ports: []model.Port{
		{Number: 80, Proto: "tcp", State: "open", Service: model.Service{Name: "http", Product: "nginx"}}}})
	st.ReplaceNucleiIndex(ctx, "t", []store.NucleiTemplate{tplEntry("http/detect/x.yaml", "info", []string{"http"}, []string{"tech", "nginx"}, "")})
	rt := newNucleiRuntime(st, res, Options{NucleiDir: t.TempDir()})
	stages := append([]orchestrator.Stage{{Name: StagePortscan, Class: ClassNmap, Plan: planN0, Handle: noop}}, rt.stages()...)
	o, _ := orchestrator.New(st, stages, orchestrator.Config{Classes: map[string]int{ClassNmap: 1, ClassNuclei: 1},
		DataDir: t.TempDir(), MaxAttempts: 5, BackoffBase: time.Hour})
	done := make(chan orchestrator.Summary, 1)
	go func() { s, _ := o.Run(ctx, id); done <- s }()
	select {
	case s := <-done:
		if s.Status != store.ScanPartial {
			t.Fatalf("status=%s", s.Status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("missing nuclei must fail permanently, not back off for an hour")
	}
}

func TestNoIndexMeansNoNucleiJobsNotFailure(t *testing.T) {
	st, id, res := setup(t, policy.TemplateBasic)
	ctx := context.Background()
	st.IngestHost(ctx, id, model.Host{Address: "10.0.0.5", State: "up", Ports: []model.Port{
		{Number: 80, Proto: "tcp", State: "open", Service: model.Service{Name: "http"}}}})
	rt := newNucleiRuntime(st, res, Options{NucleiDir: t.TempDir()})
	stages := append([]orchestrator.Stage{{Name: StagePortscan, Class: ClassNmap, Plan: planN0, Handle: noop}}, rt.stages()...)
	o, _ := orchestrator.New(st, stages, orchestrator.Config{Classes: map[string]int{ClassNmap: 1, ClassNuclei: 1}, DataDir: t.TempDir()})
	sum, err := o.Run(ctx, id)
	if err != nil || sum.Status != store.ScanCompleted {
		t.Fatalf("sum=%+v err=%v", sum, err)
	}
}

func TestProductNamedRejectsMismatchedTemplateMetadata(t *testing.T) {
	if productNamed("opensuse", "vsftpd-detect vsFTPd Service - Detect") {
		t.Error("an unrelated product from bad template metadata must be rejected")
	}
	if !productNamed("nginx", "nginx-version Nginx version detect") || !productNamed("vsftpd", "vsftpd-detect vsFTPd Service - Detect") {
		t.Error("matching product names must pass")
	}
}

// stallingNuclei is a nuclei that never returns when its template list names
// hang.yaml (or always, if every is set), like the stuck processes seen in the field.
func stallingNuclei(t *testing.T, every bool) {
	t.Helper()
	dir := t.TempDir()
	fx, _ := filepath.Abs("../../testdata/nuclei/results.jsonl")
	cond := `grep -q "hang.yaml" "$t"`
	if every {
		cond = "true"
	}
	script := `#!/bin/sh
t=""; prev=""
for a in "$@"; do [ "$prev" = "-t" ] && t="$a"; prev="$a"; done
if ` + cond + `; then exec sleep 30; fi
grep '"template-id":"CVE-2021-30047"' "` + fx + `" | head -1
`
	if err := os.WriteFile(filepath.Join(dir, "nuclei"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func stallJob(t *testing.T, st *store.Store, scanID int64) store.Job {
	t.Helper()
	if err := st.IngestHost(context.Background(), scanID, model.Host{Address: "127.0.0.1", State: "up"}); err != nil {
		t.Fatal(err)
	}
	return store.Job{ScanID: scanID, Targets: []string{"http://127.0.0.1:18082"}, RawDir: t.TempDir()}
}

func TestNucleiStalledTemplateIsIsolatedSkippedAndReported(t *testing.T) {
	stallingNuclei(t, false)
	st, id, res := setup(t, policy.TemplateBasic)
	ctx := context.Background()
	rt := newNucleiRuntime(st, res, Options{NucleiDir: t.TempDir(), NucleiRate: 100, NucleiTimeout: time.Second})
	job := stallJob(t, st, id)
	tpls := []string{"http/a.yaml", "http/b.yaml", "http/hang.yaml", "http/c.yaml", "http/d.yaml"}

	start := time.Now()
	if err := rt.run(ctx, job, tpls, false); err != nil {
		t.Fatalf("one stuck template must not fail the job: %v", err)
	}
	if time.Since(start) > 20*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
	b, _ := os.ReadFile(filepath.Join(job.RawDir, "stalled-templates.txt"))
	if strings.TrimSpace(string(b)) != "http/hang.yaml" {
		t.Errorf("skipped = %q", b)
	}
	res1, _ := os.ReadFile(filepath.Join(job.RawDir, "results.jsonl"))
	if !strings.Contains(string(res1), "CVE-2021-30047") {
		t.Errorf("results from the healthy batches must be kept: %q", res1)
	}
	runs, _ := st.ListCheckRuns(ctx, id)
	found := false
	for _, r := range runs {
		if r.CheckID == "nuclei-stalled-templates" && r.State == "skipped" && strings.Contains(r.Reason, "hang.yaml") {
			found = true
		}
	}
	if !found {
		t.Errorf("the skip must be visible in coverage: %+v", runs)
	}
}

func TestNucleiThatAlwaysStallsFailsFastInsteadOfHoldingTheScan(t *testing.T) {
	stallingNuclei(t, true)
	st, id, res := setup(t, policy.TemplateBasic)
	rt := newNucleiRuntime(st, res, Options{NucleiDir: t.TempDir(), NucleiRate: 100, NucleiTimeout: time.Second})
	job := stallJob(t, st, id)
	var tpls []string
	for i := 0; i < 64; i++ {
		tpls = append(tpls, "http/t"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+".yaml")
	}
	start := time.Now()
	err := rt.run(context.Background(), job, tpls, false)
	if err == nil || !strings.Contains(err.Error(), "looks stuck") {
		t.Fatalf("want a clear 'stuck' error, got %v", err)
	}
	if !orchestrator.IsPermanent(err) {
		t.Error("retrying a stuck tool for the full timeout again is pointless: error must be permanent")
	}
	if time.Since(start) > 15*time.Second {
		t.Errorf("gave up after %s", time.Since(start))
	}
}
