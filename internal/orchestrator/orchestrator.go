// Package orchestrator runs a scan as a DAG of stages. Each stage plans jobs
// (chunks of work) once its dependencies finish; jobs are claimed from SQLite,
// executed by handlers under per-resource concurrency caps, retried with
// backoff, and survive interruption: Run on an existing scan resumes it.
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"time"

	"babylon/internal/store"
)

// Handler executes one job. It must respect ctx cancellation. Returning an
// error retries the job (up to MaxAttempts) unless the error is Permanent.
type Handler func(ctx context.Context, job store.Job) error

// PlanFunc creates the jobs for a stage. It is called once, after every stage
// in DependsOn has finished, and may inspect earlier results via the store.
type PlanFunc func(ctx context.Context, scan store.Scan) ([]store.JobSpec, error)

// Stage is one node of the scan DAG.
type Stage struct {
	Name      string
	Class     string // resource class whose concurrency cap applies (e.g. "nmap")
	DependsOn []string
	Plan      PlanFunc
	Handle    Handler
}

// Config tunes execution.
type Config struct {
	Classes     map[string]int // concurrency cap per resource class (each must be > 0)
	MaxAttempts int            // per job, default 3
	BackoffBase time.Duration  // retry delay = base * 2^(attempt-1), default 2s
	DataDir     string         // raw output root; job dirs are created beneath it
	Worker      string         // identifier recorded on claimed jobs
	Logger      *slog.Logger
}

type permanent struct{ err error }

func (p permanent) Error() string { return p.err.Error() }
func (p permanent) Unwrap() error { return p.err }

// Permanent marks an error as non-retryable (e.g. a required tool is missing).
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanent{err}
}

// IsPermanent reports whether err was marked non-retryable.
func IsPermanent(err error) bool {
	var p permanent
	return errors.As(err, &p)
}

// Summary is the outcome of Run.
type Summary struct {
	Status string
	Counts store.Counts
}

type Orchestrator struct {
	st     *store.Store
	stages []Stage
	byName map[string]Stage
	cfg    Config
	log    *slog.Logger
}

// New validates the stage graph and configuration.
func New(st *store.Store, stages []Stage, cfg Config) (*Orchestrator, error) {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 2 * time.Second
	}
	if cfg.Worker == "" {
		cfg.Worker = "local"
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	by := map[string]Stage{}
	for _, s := range stages {
		if s.Name == "" || s.Plan == nil || s.Handle == nil {
			return nil, fmt.Errorf("stage %q: name, Plan and Handle are required", s.Name)
		}
		if _, dup := by[s.Name]; dup {
			return nil, fmt.Errorf("duplicate stage %q", s.Name)
		}
		if cfg.Classes[s.Class] <= 0 {
			return nil, fmt.Errorf("stage %q: class %q needs a concurrency cap > 0", s.Name, s.Class)
		}
		by[s.Name] = s
	}
	for _, s := range stages {
		for _, d := range s.DependsOn {
			if _, ok := by[d]; !ok {
				return nil, fmt.Errorf("stage %q depends on unknown stage %q", s.Name, d)
			}
		}
	}
	if err := checkAcyclic(stages); err != nil {
		return nil, err
	}
	return &Orchestrator{st: st, stages: stages, byName: by, cfg: cfg, log: log}, nil
}

func checkAcyclic(stages []Stage) error {
	deps := map[string][]string{}
	for _, s := range stages {
		deps[s.Name] = s.DependsOn
	}
	state := map[string]int{} // 0 new, 1 visiting, 2 done
	var visit func(string) error
	visit = func(n string) error {
		switch state[n] {
		case 1:
			return fmt.Errorf("stage dependency cycle through %q", n)
		case 2:
			return nil
		}
		state[n] = 1
		for _, d := range deps[n] {
			if err := visit(d); err != nil {
				return err
			}
		}
		state[n] = 2
		return nil
	}
	for _, s := range stages {
		if err := visit(s.Name); err != nil {
			return err
		}
	}
	return nil
}

type result struct {
	job store.Job
	err error
}

// Run executes (or resumes) a scan until all stages finish, ctx is cancelled,
// or an infrastructure error occurs. Job failures do not abort the scan; they
// make it `partial`.
func (o *Orchestrator) Run(ctx context.Context, scanID int64) (Summary, error) {
	// DB writes for bookkeeping must survive cancellation of ctx.
	bg := context.WithoutCancel(ctx)

	scan, err := o.st.GetScan(ctx, scanID)
	if err != nil {
		return Summary{}, err
	}
	if _, err := o.st.RequeueRunning(bg, scanID); err != nil { // crash recovery
		return Summary{}, err
	}
	if err := o.st.SetScanStatus(bg, scanID, store.ScanRunning); err != nil {
		return Summary{}, err
	}

	running := map[string]int{} // class -> in-flight
	inflight := 0
	done := make(chan result, 64)

	// fail handles an infrastructure error: a cancellation that surfaced as a
	// DB/ctx error is reported as a clean cancel, anything else as an error.
	fail := func(err error) (Summary, error) {
		o.drain(bg, ctx, done, &inflight, running)
		if ctx.Err() != nil {
			return o.finish(bg, scanID, store.ScanCancelled)
		}
		return Summary{}, err
	}

	planned, err := o.st.PlannedStages(bg, scanID)
	if err != nil {
		return Summary{}, err
	}

	for {
		counts, err := o.st.JobCounts(bg, scanID)
		if err != nil {
			return fail(err)
		}
		if ctx.Err() == nil {
			if len(planned) < len(o.stages) {
				if err := o.planReady(ctx, scan, planned, counts); err != nil {
					return fail(err)
				}
			}
			if err := o.dispatch(ctx, scanID, planned, counts, running, &inflight, done); err != nil {
				return fail(err)
			}
		}
		if ctx.Err() != nil {
			return fail(nil)
		}
		queued := false
		for _, states := range counts {
			if states[store.JobQueued] > 0 {
				queued = true
			}
		}
		if inflight == 0 && !queued {
			if len(planned) == len(o.stages) {
				break
			}
			// Nothing running or queued but stages remain unplanned: planning
			// one stage (e.g. with zero jobs) may unlock the next. Re-plan
			// immediately; the acyclic graph guarantees progress.
			continue
		}

		// Wait for a completion, a retry becoming due, or cancellation.
		var timer <-chan time.Time
		if t, ok, err := o.st.NextDue(bg, scanID, time.Now()); err == nil && ok {
			timer = time.After(time.Until(t) + time.Millisecond)
		}
		if timer == nil && inflight == 0 {
			// Queued work exists, nothing is running and no future due time was
			// found: a retry's backoff elapsed between the claim attempt and the
			// NextDue query above. Go around again instead of blocking forever.
			continue
		}
		select {
		case r := <-done:
			inflight--
			running[o.byName[r.job.Stage].Class]--
			if err := o.record(bg, ctx, r); err != nil {
				return fail(err)
			}
		case <-timer:
		case <-ctx.Done():
		}
	}

	counts, err := o.st.JobCounts(bg, scanID)
	if err != nil {
		return Summary{}, err
	}
	status := store.ScanCompleted
	for _, states := range counts {
		if states[store.JobFailed] > 0 {
			status = store.ScanPartial
		}
	}
	return o.finish(bg, scanID, status)
}

func (o *Orchestrator) finish(bg context.Context, scanID int64, status string) (Summary, error) {
	if err := o.st.SetScanStatus(bg, scanID, status); err != nil {
		return Summary{}, err
	}
	counts, err := o.st.JobCounts(bg, scanID)
	return Summary{Status: status, Counts: counts}, err
}

// planReady plans every unplanned stage whose dependencies have all finished,
// updating planned and counts in place.
func (o *Orchestrator) planReady(ctx context.Context, scan store.Scan, planned map[string]bool, counts store.Counts) error {
	for _, s := range o.stages {
		if planned[s.Name] {
			continue
		}
		ready := true
		for _, d := range s.DependsOn {
			if !planned[d] || counts[d][store.JobQueued] > 0 || counts[d][store.JobRunning] > 0 {
				ready = false
				break
			}
		}
		if !ready {
			continue
		}
		specs, err := s.Plan(ctx, scan)
		if err != nil {
			return fmt.Errorf("plan stage %s: %w", s.Name, err)
		}
		for i := range specs {
			specs[i].Stage = s.Name
		}
		n, err := o.st.PlanStage(ctx, scan.ID, s.Name, specs)
		if err != nil {
			return fmt.Errorf("plan stage %s: %w", s.Name, err)
		}
		o.log.Debug("stage planned", "stage", s.Name, "jobs", n)
		planned[s.Name] = true
		if counts[s.Name] == nil {
			counts[s.Name] = map[string]int{}
		}
		counts[s.Name][store.JobQueued] += n
	}
	return nil
}

// dispatch claims jobs up to each class's free capacity and starts handlers,
// keeping counts current. Stages with nothing queued cost no database write.
func (o *Orchestrator) dispatch(ctx context.Context, scanID int64, planned map[string]bool, counts store.Counts, running map[string]int, inflight *int, done chan<- result) error {
	for _, s := range o.stages {
		if !planned[s.Name] || counts[s.Name][store.JobQueued] == 0 {
			continue
		}
		free := o.cfg.Classes[s.Class] - running[s.Class]
		if free <= 0 {
			continue
		}
		jobs, err := o.st.Claim(ctx, scanID, s.Name, free, o.cfg.Worker, time.Now())
		if err != nil {
			return err
		}
		counts[s.Name][store.JobQueued] -= len(jobs)
		counts[s.Name][store.JobRunning] += len(jobs)
		for _, j := range jobs {
			running[s.Class]++
			*inflight++
			go o.execute(ctx, s, j, done)
		}
	}
	return nil
}

func (o *Orchestrator) execute(ctx context.Context, s Stage, j store.Job, done chan<- result) {
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = Permanent(fmt.Errorf("panic: %v\n%s", r, debug.Stack()))
			}
		}()
		if o.cfg.DataDir != "" {
			dir := filepath.Join(o.cfg.DataDir, "scans", strconv.FormatInt(j.ScanID, 10), "jobs", s.Name+"-"+j.ChunkKey)
			if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
				err = Permanent(mkErr)
				return
			}
			j.RawDir = dir
			if e := o.st.SetRawDir(context.WithoutCancel(ctx), j.ID, dir); e != nil {
				err = e
				return
			}
		}
		err = s.Handle(ctx, j)
	}()
	done <- result{job: j, err: err}
}

// record persists a job outcome: done, retry with backoff, or failed.
func (o *Orchestrator) record(bg, ctx context.Context, r result) error {
	switch {
	case r.err == nil:
		return o.st.FinishJob(bg, r.job.ID, store.JobDone, "")
	case ctx.Err() != nil:
		// Interrupted by cancellation, not a job failure: requeue without
		// charging the attempt so resume reruns it.
		return o.st.RequeueJob(bg, r.job.ID, time.Time{}, "", true)
	}
	var perm permanent
	if errors.As(r.err, &perm) || r.job.Attempts >= o.cfg.MaxAttempts {
		o.log.Warn("job failed", "stage", r.job.Stage, "chunk", r.job.ChunkKey, "attempts", r.job.Attempts, "err", r.err)
		return o.st.FinishJob(bg, r.job.ID, store.JobFailed, trunc(r.err.Error()))
	}
	delay := o.cfg.BackoffBase << uint(r.job.Attempts-1)
	o.log.Info("job retry", "stage", r.job.Stage, "chunk", r.job.ChunkKey, "attempt", r.job.Attempts, "in", delay, "err", r.err)
	return o.st.RequeueJob(bg, r.job.ID, time.Now().Add(delay), trunc(r.err.Error()), false)
}

// drain waits for in-flight handlers (they observe cancelled ctx) and records
// their outcomes, so no job is left in `running` on exit.
func (o *Orchestrator) drain(bg, ctx context.Context, done chan result, inflight *int, running map[string]int) {
	for *inflight > 0 {
		r := <-done
		*inflight--
		running[o.byName[r.job.Stage].Class]--
		if err := o.record(bg, ctx, r); err != nil {
			o.log.Error("record job outcome", "err", err)
		}
	}
}

func trunc(s string) string {
	if len(s) > 2000 {
		return s[:2000]
	}
	return s
}
