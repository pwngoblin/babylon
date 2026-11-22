package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"babylon/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	t.Cleanup(func() { st.Close() })
	return st
}

func newScan(t *testing.T, st *store.Store) int64 {
	t.Helper()
	id, err := st.CreateScan(context.Background(), "t", "basic", []string{"10.0.0.0/24"}, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func planN(n int) PlanFunc {
	return func(context.Context, store.Scan) ([]store.JobSpec, error) {
		specs := make([]store.JobSpec, n)
		for i := range specs {
			specs[i] = store.JobSpec{ChunkKey: fmt.Sprintf("c%04d", i), Targets: []string{"10.0.0.1"}}
		}
		return specs, nil
	}
}

func ok(context.Context, store.Job) error { return nil }

func mustNew(t *testing.T, st *store.Store, stages []Stage, cfg Config) *Orchestrator {
	t.Helper()
	if cfg.Classes == nil {
		cfg.Classes = map[string]int{"a": 4, "b": 4}
	}
	if cfg.BackoffBase == 0 {
		cfg.BackoffBase = 5 * time.Millisecond
	}
	o, err := New(st, stages, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestDependenciesAndZeroJobStage(t *testing.T) {
	st := newStore(t)
	id := newScan(t, st)
	var mu sync.Mutex
	var order []string
	rec := func(name string) Handler {
		return func(_ context.Context, j store.Job) error {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			return nil
		}
	}
	stages := []Stage{
		{Name: "sweep", Class: "a", Plan: planN(3), Handle: rec("sweep")},
		{Name: "empty", Class: "a", DependsOn: []string{"sweep"}, Plan: planN(0), Handle: rec("empty")},
		{Name: "scan", Class: "b", DependsOn: []string{"empty"}, Plan: planN(5), Handle: rec("scan")},
		{Name: "report", Class: "a", DependsOn: []string{"scan"}, Plan: planN(1), Handle: rec("report")},
	}
	sum, err := mustNew(t, st, stages, Config{}).Run(context.Background(), id)
	if err != nil || sum.Status != store.ScanCompleted {
		t.Fatalf("status=%s err=%v", sum.Status, err)
	}
	// every sweep before any scan, every scan before report
	last := map[string]int{}
	first := map[string]int{}
	for i, n := range order {
		last[n] = i
		if _, ok := first[n]; !ok {
			first[n] = i
		}
	}
	if !(last["sweep"] < first["scan"] && last["scan"] < first["report"]) {
		t.Fatalf("dependency order violated: %v", order)
	}
	if len(order) != 9 {
		t.Fatalf("expected 9 job runs, got %d", len(order))
	}
}

func TestConcurrencyCapRespected(t *testing.T) {
	st := newStore(t)
	id := newScan(t, st)
	var cur, max int32
	h := func(context.Context, store.Job) error {
		n := atomic.AddInt32(&cur, 1)
		for {
			m := atomic.LoadInt32(&max)
			if n <= m || atomic.CompareAndSwapInt32(&max, m, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt32(&cur, -1)
		return nil
	}
	o := mustNew(t, st, []Stage{{Name: "s", Class: "a", Plan: planN(12), Handle: h}}, Config{Classes: map[string]int{"a": 3}})
	if _, err := o.Run(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if max != 3 {
		t.Fatalf("max concurrency = %d, want exactly 3", max)
	}
}

func TestRetryThenSuccess(t *testing.T) {
	st := newStore(t)
	id := newScan(t, st)
	var calls sync.Map
	h := func(_ context.Context, j store.Job) error {
		v, _ := calls.LoadOrStore(j.ChunkKey, new(int32))
		if atomic.AddInt32(v.(*int32), 1) < 3 {
			return errors.New("flaky")
		}
		return nil
	}
	o := mustNew(t, st, []Stage{{Name: "s", Class: "a", Plan: planN(4), Handle: h}}, Config{MaxAttempts: 3})
	sum, err := o.Run(context.Background(), id)
	if err != nil || sum.Status != store.ScanCompleted || sum.Counts["s"][store.JobDone] != 4 {
		t.Fatalf("sum=%+v err=%v", sum, err)
	}
}

func TestExhaustedRetriesMakePartialAndDependentsStillRun(t *testing.T) {
	st := newStore(t)
	id := newScan(t, st)
	var depRuns int32
	stages := []Stage{
		{Name: "s", Class: "a", Plan: planN(3), Handle: func(_ context.Context, j store.Job) error {
			if j.ChunkKey == "c0001" {
				return errors.New("always broken")
			}
			return nil
		}},
		{Name: "dep", Class: "b", DependsOn: []string{"s"}, Plan: planN(2), Handle: func(context.Context, store.Job) error {
			atomic.AddInt32(&depRuns, 1)
			return nil
		}},
	}
	sum, err := mustNew(t, st, stages, Config{MaxAttempts: 2}).Run(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Status != store.ScanPartial || sum.Counts["s"][store.JobFailed] != 1 || sum.Counts["s"][store.JobDone] != 2 {
		t.Fatalf("sum=%+v", sum)
	}
	if depRuns != 2 {
		t.Fatalf("dependent stage should still run, ran %d", depRuns)
	}
	var msg string
	st.DB.QueryRow(`SELECT error FROM scan_job WHERE state='failed'`).Scan(&msg)
	if msg != "always broken" {
		t.Fatalf("error not recorded: %q", msg)
	}
}

func TestPermanentErrorNotRetried(t *testing.T) {
	st := newStore(t)
	id := newScan(t, st)
	var calls int32
	h := func(context.Context, store.Job) error {
		atomic.AddInt32(&calls, 1)
		return Permanent(errors.New("tool missing"))
	}
	sum, _ := mustNew(t, st, []Stage{{Name: "s", Class: "a", Plan: planN(1), Handle: h}}, Config{MaxAttempts: 5}).Run(context.Background(), id)
	if calls != 1 || sum.Status != store.ScanPartial {
		t.Fatalf("calls=%d status=%s", calls, sum.Status)
	}
}

func TestPanicIsContained(t *testing.T) {
	st := newStore(t)
	id := newScan(t, st)
	stages := []Stage{{Name: "s", Class: "a", Plan: planN(2), Handle: func(_ context.Context, j store.Job) error {
		if j.ChunkKey == "c0000" {
			panic("boom")
		}
		return nil
	}}}
	sum, err := mustNew(t, st, stages, Config{}).Run(context.Background(), id)
	if err != nil || sum.Status != store.ScanPartial || sum.Counts["s"][store.JobDone] != 1 {
		t.Fatalf("sum=%+v err=%v", sum, err)
	}
}

func TestCancelThenResumeDoesNotRerunFinishedWork(t *testing.T) {
	st := newStore(t)
	id := newScan(t, st)
	var completed sync.Map // chunk -> completed count
	var started int32
	ctx, cancel := context.WithCancel(context.Background())
	h := func(ctx context.Context, j store.Job) error {
		if atomic.AddInt32(&started, 1) == 6 {
			cancel() // cancel mid-run
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
		v, _ := completed.LoadOrStore(j.ChunkKey, new(int32))
		atomic.AddInt32(v.(*int32), 1)
		return nil
	}
	stages := []Stage{{Name: "s", Class: "a", Plan: planN(20), Handle: h}}
	cfg := Config{Classes: map[string]int{"a": 2}}

	sum, err := mustNew(t, st, stages, cfg).Run(ctx, id)
	if err != nil || sum.Status != store.ScanCancelled {
		t.Fatalf("first run: sum=%+v err=%v", sum, err)
	}
	if n := sum.Counts["s"][store.JobRunning]; n != 0 {
		t.Fatalf("%d jobs left in running after cancel", n)
	}
	doneFirst := sum.Counts["s"][store.JobDone]
	if doneFirst == 0 || doneFirst == 20 {
		t.Fatalf("expected partial progress, done=%d", doneFirst)
	}

	sum, err = mustNew(t, st, stages, cfg).Run(context.Background(), id)
	if err != nil || sum.Status != store.ScanCompleted || sum.Counts["s"][store.JobDone] != 20 {
		t.Fatalf("resume: sum=%+v err=%v", sum, err)
	}
	completed.Range(func(k, v any) bool {
		if n := *v.(*int32); n != 1 {
			t.Errorf("chunk %v completed %d times, want exactly 1", k, n)
		}
		return true
	})
	var attempts int
	st.DB.QueryRow(`SELECT MAX(attempts) FROM scan_job`).Scan(&attempts)
	if attempts > 1 {
		t.Errorf("cancel must not charge attempts; max attempts=%d", attempts)
	}
}

func TestCrashRecoveryRequeuesRunningJobs(t *testing.T) {
	st := newStore(t)
	id := newScan(t, st)
	ctx := context.Background()
	if _, err := st.PlanStage(ctx, id, "s", []store.JobSpec{{Stage: "s", ChunkKey: "a"}, {Stage: "s", ChunkKey: "b"}}); err != nil {
		t.Fatal(err)
	}
	// Simulate a crashed process: jobs claimed (running) but never finished.
	if jobs, err := st.Claim(ctx, id, "s", 2, "dead-worker", time.Now()); err != nil || len(jobs) != 2 {
		t.Fatalf("claim: %v %v", jobs, err)
	}
	var runs int32
	h := func(context.Context, store.Job) error { atomic.AddInt32(&runs, 1); return nil }
	sum, err := mustNew(t, st, []Stage{{Name: "s", Class: "a", Plan: planN(2), Handle: h}}, Config{}).Run(ctx, id)
	if err != nil || sum.Status != store.ScanCompleted || runs != 2 {
		t.Fatalf("sum=%+v runs=%d err=%v", sum, runs, err)
	}
}

func TestPlanningIsIdempotent(t *testing.T) {
	st := newStore(t)
	id := newScan(t, st)
	ctx := context.Background()
	specs := []store.JobSpec{{ChunkKey: "a"}, {ChunkKey: "b"}}
	n1, _ := st.PlanStage(ctx, id, "s", specs)
	n2, _ := st.PlanStage(ctx, id, "s", specs)
	if n1 != 2 || n2 != 0 {
		t.Fatalf("n1=%d n2=%d", n1, n2)
	}
}

func TestStageGraphValidation(t *testing.T) {
	st := newStore(t)
	cfg := Config{Classes: map[string]int{"a": 1}}
	mk := func(name string, deps ...string) Stage {
		return Stage{Name: name, Class: "a", DependsOn: deps, Plan: planN(0), Handle: ok}
	}
	cases := map[string][]Stage{
		"cycle":       {mk("x", "y"), mk("y", "x")},
		"unknown dep": {mk("x", "nope")},
		"duplicate":   {mk("x"), mk("x")},
		"no class":    {{Name: "x", Class: "zzz", Plan: planN(0), Handle: ok}},
		"no handler":  {{Name: "x", Class: "a", Plan: planN(0)}},
	}
	for name, stages := range cases {
		if _, err := New(st, stages, cfg); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

// 3,000 jobs across two stages with high concurrency: verifies the batched
// single writer keeps up, nothing is lost, and the scan finishes.
func TestScaleThousandsOfJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped in -short mode")
	}
	st := newStore(t)
	id := newScan(t, st)
	var runs int32
	h := func(context.Context, store.Job) error { atomic.AddInt32(&runs, 1); return nil }
	stages := []Stage{
		{Name: "s1", Class: "a", Plan: planN(2000), Handle: h},
		{Name: "s2", Class: "b", DependsOn: []string{"s1"}, Plan: planN(1000), Handle: h},
	}
	start := time.Now()
	sum, err := mustNew(t, st, stages, Config{Classes: map[string]int{"a": 64, "b": 64}}).Run(context.Background(), id)
	if err != nil || sum.Status != store.ScanCompleted {
		t.Fatalf("sum=%+v err=%v", sum, err)
	}
	if runs != 3000 || sum.Counts["s1"][store.JobDone] != 2000 || sum.Counts["s2"][store.JobDone] != 1000 {
		t.Fatalf("runs=%d counts=%v", runs, sum.Counts)
	}
	t.Logf("3000 jobs in %s", time.Since(start))
}
