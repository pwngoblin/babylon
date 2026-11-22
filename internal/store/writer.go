package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
)

// ErrClosed is returned by Do after the writer has been closed.
var ErrClosed = errors.New("store: writer closed")

// Writer serializes all writes through one goroutine and batches concurrent
// operations into a single transaction. SQLite permits one writer at a time;
// funnelling writes here avoids lock contention ("database is locked") when
// hundreds of workers report results, and amortizes fsync cost.
//
// Each operation runs inside its own SAVEPOINT, so one failing operation is
// rolled back and reported without affecting the others in its batch.
type Writer struct {
	db       *sql.DB
	ch       chan op
	maxBatch int

	mu     sync.RWMutex // guards closed + sends on ch
	closed bool
	wg     sync.WaitGroup
}

type op struct {
	fn  func(*sql.Tx) error
	res chan error
}

// NewWriter starts the writer goroutine. maxBatch <= 0 defaults to 256.
func NewWriter(db *sql.DB, maxBatch int) *Writer {
	if maxBatch <= 0 {
		maxBatch = 256
	}
	w := &Writer{db: db, ch: make(chan op, maxBatch*2), maxBatch: maxBatch}
	w.wg.Add(1)
	go w.run()
	return w
}

// Do runs fn in a write transaction (batched with other callers) and returns
// its error. It returns only after the transaction has committed or fn failed.
func (w *Writer) Do(ctx context.Context, fn func(*sql.Tx) error) error {
	o := op{fn: fn, res: make(chan error, 1)}

	w.mu.RLock()
	if w.closed {
		w.mu.RUnlock()
		return ErrClosed
	}
	select {
	case w.ch <- o:
		w.mu.RUnlock()
	case <-ctx.Done():
		w.mu.RUnlock()
		return ctx.Err()
	}
	// Once enqueued the op will run; wait for its outcome regardless of ctx so
	// the caller never observes an ambiguous result.
	return <-o.res
}

// Close stops accepting work, flushes queued operations, and waits for exit.
func (w *Writer) Close() {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.ch)
	}
	w.mu.Unlock()
	w.wg.Wait()
}

func (w *Writer) run() {
	defer w.wg.Done()
	for first := range w.ch {
		batch := []op{first}
	drain:
		for len(batch) < w.maxBatch {
			select {
			case o, ok := <-w.ch:
				if !ok {
					break drain
				}
				batch = append(batch, o)
			default:
				break drain
			}
		}
		w.flush(batch)
	}
}

func (w *Writer) flush(batch []op) {
	tx, err := w.db.Begin()
	if err != nil {
		failAll(batch, fmt.Errorf("begin: %w", err))
		return
	}
	errs := make([]error, len(batch))
	ok := make([]bool, len(batch))
	for i, o := range batch {
		errs[i] = runInSavepoint(tx, o.fn)
		ok[i] = errs[i] == nil
	}
	if err := tx.Commit(); err != nil {
		tx.Rollback()
		for i, o := range batch {
			if ok[i] {
				o.res <- fmt.Errorf("commit: %w", err)
			} else {
				o.res <- errs[i]
			}
		}
		return
	}
	for i, o := range batch {
		o.res <- errs[i]
	}
}

func runInSavepoint(tx *sql.Tx, fn func(*sql.Tx) error) (err error) {
	if _, e := tx.Exec("SAVEPOINT op"); e != nil {
		return e
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in write op: %v", r)
		}
		if err != nil {
			tx.Exec("ROLLBACK TO op")
		}
		tx.Exec("RELEASE op")
	}()
	return fn(tx)
}

func failAll(batch []op, err error) {
	for _, o := range batch {
		o.res <- err
	}
}
