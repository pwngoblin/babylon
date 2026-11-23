package web

import (
	"context"
	"errors"
	"sync"
	"time"

	"babylon/internal/app"
	"babylon/internal/store"
)

var errBusy = errors.New("too many scans are running; wait for one to finish")

// manager runs scans in the background and tracks them so they can be
// cancelled or resumed from the UI.
type manager struct {
	app *app.App
	max int

	mu      sync.Mutex
	running map[int64]context.CancelFunc
	errs    map[int64]string
	warns   map[int64][]string
	wg      sync.WaitGroup
	closed  bool
}

func newManager(a *app.App, max int) *manager {
	if max <= 0 {
		max = 2
	}
	return &manager{app: a, max: max, running: map[int64]context.CancelFunc{}, errs: map[int64]string{}, warns: map[int64][]string{}}
}

func (m *manager) isRunning(id int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.running[id]
	return ok
}

func (m *manager) lastError(id int64) (string, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.errs[id], m.warns[id]
}

// start launches (or resumes) a scan in the background.
func (m *manager) start(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("server is shutting down")
	}
	if _, ok := m.running[id]; ok {
		return errors.New("scan is already running")
	}
	if len(m.running) >= m.max {
		return errBusy
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.running[id] = cancel
	delete(m.errs, id)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		res, err := m.app.Run(ctx, id, false)
		m.mu.Lock()
		delete(m.running, id)
		m.warns[id] = res.Warnings
		if err != nil {
			m.errs[id] = err.Error()
		}
		m.mu.Unlock()
		if err != nil {
			// A setup failure (e.g. unusable sudo) leaves the scan pending; mark it failed so it is visible.
			if sc, e := m.app.St.GetScan(context.Background(), id); e == nil && (sc.Status == store.ScanPending || sc.Status == store.ScanRunning) {
				st := store.ScanFailed
				if ctx.Err() != nil {
					st = store.ScanCancelled // cancelled before the orchestrator started: not a failure
				}
				_ = m.app.St.SetScanStatus(context.Background(), id, st)
			}
		}
	}()
	return nil
}

func (m *manager) cancel(id int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.running[id]
	if ok {
		c()
	}
	return ok
}

// shutdown cancels all scans (they become resumable) and waits for them.
func (m *manager) shutdown() {
	m.mu.Lock()
	m.closed = true
	for _, c := range m.running {
		c()
	}
	m.mu.Unlock()
	m.wg.Wait()
}

// runScheduler starts due scheduled scans once a minute until ctx ends.
func (m *manager) runScheduler(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			m.app.RunDue(ctx, now, m.start, errBusy)
		}
	}
}
