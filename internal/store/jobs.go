package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// TimeFormat is fixed-width UTC so timestamps compare correctly as strings.
const TimeFormat = "2006-01-02T15:04:05.000000Z"

func ts(t time.Time) string { return t.UTC().Format(TimeFormat) }

// Job states.
const (
	JobQueued  = "queued"
	JobRunning = "running"
	JobDone    = "done"
	JobFailed  = "failed"
	JobSkipped = "skipped"
)

// Scan statuses.
const (
	ScanPending   = "pending"
	ScanRunning   = "running"
	ScanCompleted = "completed"
	ScanPartial   = "partial"
	ScanFailed    = "failed"
	ScanCancelled = "cancelled"
)

// Store bundles the read handle and the batched writer.
type Store struct {
	DB *sql.DB
	W  *Writer
}

// New wraps an opened database with a Writer.
func New(db *sql.DB) *Store { return &Store{DB: db, W: NewWriter(db, 256)} }

// Close flushes pending writes and closes the database.
func (s *Store) Close() error {
	s.W.Close()
	return s.DB.Close()
}

type Scan struct {
	ID        int64
	Name      string
	Template  string
	Targets   []string
	Options   json.RawMessage
	Status    string
	StartedAt string
}

// JobSpec describes a job to be planned.
type JobSpec struct {
	Stage    string
	Engine   string
	ChunkKey string
	Targets  []string
	Params   map[string]string // engine-specific parameters (e.g. nuclei tags)
}

type Job struct {
	ID       int64
	ScanID   int64
	Stage    string
	Engine   string
	ChunkKey string
	Targets  []string
	Params   map[string]string
	Attempts int
	RawDir   string
}

// CreateScan inserts a pending scan and returns its id.
func (s *Store) CreateScan(ctx context.Context, name, template string, targets []string, options any) (int64, error) {
	tj, err := json.Marshal(targets)
	if err != nil {
		return 0, err
	}
	oj, err := json.Marshal(options)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.W.Do(ctx, func(tx *sql.Tx) error {
		r, err := tx.Exec(`INSERT INTO scan(name,template,targets_json,options_json,status) VALUES(?,?,?,?,?)`,
			name, template, string(tj), string(oj), ScanPending)
		if err != nil {
			return err
		}
		id, err = r.LastInsertId()
		return err
	})
	return id, err
}

func (s *Store) GetScan(ctx context.Context, id int64) (Scan, error) {
	var sc Scan
	var tj, oj string
	var name, started sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT id,name,template,targets_json,options_json,status,started_at FROM scan WHERE id=?`, id).
		Scan(&sc.ID, &name, &sc.Template, &tj, &oj, &sc.Status, &started)
	if err != nil {
		return sc, fmt.Errorf("scan %d: %w", id, err)
	}
	sc.Name, sc.StartedAt = name.String, started.String
	sc.Options = json.RawMessage(oj)
	return sc, json.Unmarshal([]byte(tj), &sc.Targets)
}

// SetScanStatus updates the status; started_at is set once on first running,
// finished_at on terminal statuses.
func (s *Store) SetScanStatus(ctx context.Context, id int64, status string) error {
	now := ts(time.Now())
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		switch status {
		case ScanRunning:
			_, err := tx.Exec(`UPDATE scan SET status=?, started_at=COALESCE(started_at,?), finished_at=NULL WHERE id=?`, status, now, id)
			return err
		case ScanCompleted, ScanPartial, ScanFailed, ScanCancelled:
			_, err := tx.Exec(`UPDATE scan SET status=?, finished_at=? WHERE id=?`, status, now, id)
			return err
		default:
			_, err := tx.Exec(`UPDATE scan SET status=? WHERE id=?`, status, id)
			return err
		}
	})
}

// PlanStage records the stage as planned and inserts its jobs, atomically and
// idempotently: if the stage was already planned, nothing changes. It returns
// the number of jobs inserted.
func (s *Store) PlanStage(ctx context.Context, scanID int64, stage string, specs []JobSpec) (int, error) {
	n := 0
	err := s.W.Do(ctx, func(tx *sql.Tx) error {
		r, err := tx.Exec(`INSERT OR IGNORE INTO scan_stage(scan_id,stage,planned_at) VALUES(?,?,?)`, scanID, stage, ts(time.Now()))
		if err != nil {
			return err
		}
		if c, _ := r.RowsAffected(); c == 0 {
			return nil // already planned
		}
		for _, sp := range specs {
			tj, err := json.Marshal(sp.Targets)
			if err != nil {
				return err
			}
			var params any
			if len(sp.Params) > 0 {
				pj, err := json.Marshal(sp.Params)
				if err != nil {
					return err
				}
				params = string(pj)
			}
			r, err := tx.Exec(`INSERT OR IGNORE INTO scan_job(scan_id,stage,engine,chunk_key,targets_json,params_json,state) VALUES(?,?,?,?,?,?,?)`,
				scanID, stage, nullable(sp.Engine), sp.ChunkKey, string(tj), params, JobQueued)
			if err != nil {
				return err
			}
			c, _ := r.RowsAffected()
			n += int(c)
		}
		return nil
	})
	return n, err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// PlannedStages returns the set of stages already planned for a scan.
func (s *Store) PlannedStages(ctx context.Context, scanID int64) (map[string]bool, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT stage FROM scan_stage WHERE scan_id=?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var st string
		if err := rows.Scan(&st); err != nil {
			return nil, err
		}
		out[st] = true
	}
	return out, rows.Err()
}

// Claim atomically moves up to n due queued jobs of a stage to running.
func (s *Store) Claim(ctx context.Context, scanID int64, stage string, n int, worker string, now time.Time) ([]Job, error) {
	if n <= 0 {
		return nil, nil
	}
	var jobs []Job
	err := s.W.Do(ctx, func(tx *sql.Tx) error {
		jobs = jobs[:0]
		rows, err := tx.Query(`SELECT id,COALESCE(engine,''),chunk_key,targets_json,attempts,params_json FROM scan_job
			WHERE scan_id=? AND stage=? AND state=? AND (not_before IS NULL OR not_before<=?)
			ORDER BY id LIMIT ?`, scanID, stage, JobQueued, ts(now), n)
		if err != nil {
			return err
		}
		for rows.Next() {
			j := Job{ScanID: scanID, Stage: stage}
			var tj string
			var pj sql.NullString
			if err := rows.Scan(&j.ID, &j.Engine, &j.ChunkKey, &tj, &j.Attempts, &pj); err != nil {
				rows.Close()
				return err
			}
			if pj.Valid {
				if err := json.Unmarshal([]byte(pj.String), &j.Params); err != nil {
					rows.Close()
					return err
				}
			}
			if err := json.Unmarshal([]byte(tj), &j.Targets); err != nil {
				rows.Close()
				return err
			}
			jobs = append(jobs, j)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for i := range jobs {
			jobs[i].Attempts++
			if _, err := tx.Exec(`UPDATE scan_job SET state=?, attempts=attempts+1, worker=?, started_at=?, finished_at=NULL, error=NULL, not_before=NULL WHERE id=?`,
				JobRunning, worker, ts(now), jobs[i].ID); err != nil {
				return err
			}
		}
		return nil
	})
	return jobs, err
}

// SetRawDir records the on-disk output directory of a job.
func (s *Store) SetRawDir(ctx context.Context, jobID int64, dir string) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE scan_job SET raw_dir=? WHERE id=?`, dir, jobID)
		return err
	})
}

// FinishJob moves a running job to a terminal state (done, failed, skipped).
func (s *Store) FinishJob(ctx context.Context, jobID int64, state, errMsg string) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE scan_job SET state=?, finished_at=?, error=? WHERE id=?`, state, ts(time.Now()), nullable(errMsg), jobID)
		return err
	})
}

// RequeueJob puts a job back in the queue. When refund is true the attempt is
// not counted (used for cancellation, which is not the job's fault).
func (s *Store) RequeueJob(ctx context.Context, jobID int64, notBefore time.Time, errMsg string, refund bool) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		var nb any
		if !notBefore.IsZero() {
			nb = ts(notBefore)
		}
		q := `UPDATE scan_job SET state=?, not_before=?, error=?, worker=NULL WHERE id=?`
		if refund {
			q = `UPDATE scan_job SET state=?, not_before=?, error=?, worker=NULL, attempts=MAX(attempts-1,0) WHERE id=?`
		}
		_, err := tx.Exec(q, JobQueued, nb, nullable(errMsg), jobID)
		return err
	})
}

// RequeueRunning resets jobs left in `running` (crash or cancel) so they rerun.
// The interrupted attempt is refunded. Returns how many jobs were reset.
func (s *Store) RequeueRunning(ctx context.Context, scanID int64) (int, error) {
	n := 0
	err := s.W.Do(ctx, func(tx *sql.Tx) error {
		r, err := tx.Exec(`UPDATE scan_job SET state=?, worker=NULL, attempts=MAX(attempts-1,0), not_before=NULL
			WHERE scan_id=? AND state=?`, JobQueued, scanID, JobRunning)
		if err != nil {
			return err
		}
		c, _ := r.RowsAffected()
		n = int(c)
		return nil
	})
	return n, err
}

// Counts is stage → state → number of jobs.
type Counts map[string]map[string]int

func (s *Store) JobCounts(ctx context.Context, scanID int64) (Counts, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT stage,state,COUNT(*) FROM scan_job WHERE scan_id=? GROUP BY stage,state`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := Counts{}
	for rows.Next() {
		var st, state string
		var n int
		if err := rows.Scan(&st, &state, &n); err != nil {
			return nil, err
		}
		if out[st] == nil {
			out[st] = map[string]int{}
		}
		out[st][state] = n
	}
	return out, rows.Err()
}

// NextDue returns the earliest not_before among queued jobs that are not yet
// claimable at now. ok is false when there is none.
func (s *Store) NextDue(ctx context.Context, scanID int64, now time.Time) (t time.Time, ok bool, err error) {
	var v sql.NullString
	err = s.DB.QueryRowContext(ctx, `SELECT MIN(not_before) FROM scan_job WHERE scan_id=? AND state=? AND not_before>?`,
		scanID, JobQueued, ts(now)).Scan(&v)
	if err != nil || !v.Valid {
		return time.Time{}, false, err
	}
	t, err = time.Parse(TimeFormat, v.String)
	return t, err == nil, err
}
