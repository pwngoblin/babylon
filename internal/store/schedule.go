package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Schedule is a recurring scan definition.
type Schedule struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Request     string `json:"request"` // app.Request as JSON
	IntervalMin int    `json:"interval_min"`
	Enabled     bool   `json:"enabled"`
	NextRun     int64  `json:"next_run"`
	LastRun     int64  `json:"last_run,omitempty"`
	LastScanID  int64  `json:"last_scan_id,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

const MinScheduleMinutes = 15

func (s *Store) CreateSchedule(ctx context.Context, name, requestJSON string, intervalMin int, firstRun time.Time) (int64, error) {
	if intervalMin < MinScheduleMinutes {
		return 0, errors.New("a schedule must repeat at most every 15 minutes")
	}
	var id int64
	err := s.W.Do(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO schedule(name, request_json, interval_min, next_run, created_at) VALUES(?,?,?,?,?)`,
			name, requestJSON, intervalMin, firstRun.Unix(), time.Now().Unix())
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

func scanSchedule(r interface{ Scan(...any) error }) (Schedule, error) {
	var s Schedule
	var en int
	var last, lastScan sql.NullInt64
	var lerr sql.NullString
	if err := r.Scan(&s.ID, &s.Name, &s.Request, &s.IntervalMin, &en, &s.NextRun, &last, &lastScan, &lerr); err != nil {
		return s, err
	}
	s.Enabled, s.LastRun, s.LastScanID, s.LastError = en == 1, last.Int64, lastScan.Int64, lerr.String
	return s, nil
}

const scheduleCols = `id, name, request_json, interval_min, enabled, next_run, last_run, last_scan_id, last_error`

func (s *Store) ListSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+scheduleCols+` FROM schedule ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// DueSchedules returns enabled schedules whose next run time has passed.
func (s *Store) DueSchedules(ctx context.Context, now time.Time) ([]Schedule, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+scheduleCols+` FROM schedule WHERE enabled=1 AND next_run<=? ORDER BY next_run`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// MarkScheduleRan records a run (scanID 0 with errMsg on failure) and moves next_run forward.
func (s *Store) MarkScheduleRan(ctx context.Context, id int64, ran time.Time, next time.Time, scanID int64, errMsg string) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE schedule SET last_run=?, next_run=?, last_scan_id=NULLIF(?,0), last_error=NULLIF(?, '') WHERE id=?`,
			ran.Unix(), next.Unix(), scanID, errMsg, id)
		return err
	})
}

func (s *Store) SetScheduleEnabled(ctx context.Context, id int64, on bool) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		v := 0
		if on {
			v = 1
		}
		res, err := tx.ExecContext(ctx, `UPDATE schedule SET enabled=? WHERE id=?`, v, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
}

func (s *Store) DeleteSchedule(ctx context.Context, id int64) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM schedule WHERE id=?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
}
