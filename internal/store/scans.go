package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// ScanSummary is one row of scan history.
type ScanSummary struct {
	ID         int64
	Name       string
	Template   string
	Status     string
	Targets    []string
	StartedAt  string
	FinishedAt string
	JobsDone   int
	JobsTotal  int
	JobsFailed int
	Hosts      int
	Services   int
	Findings   map[string]int // severity -> count
}

// ListScans returns scan history, newest first.
func (s *Store) ListScans(ctx context.Context) ([]ScanSummary, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, COALESCE(name,''), template, status, targets_json,
		COALESCE(started_at,''), COALESCE(finished_at,'') FROM scan ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	var out []ScanSummary
	for rows.Next() {
		var sm ScanSummary
		var tj string
		if err := rows.Scan(&sm.ID, &sm.Name, &sm.Template, &sm.Status, &tj, &sm.StartedAt, &sm.FinishedAt); err != nil {
			rows.Close()
			return nil, err
		}
		_ = json.Unmarshal([]byte(tj), &sm.Targets)
		out = append(out, sm)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.fillSummary(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GetScanSummary returns one scan's summary.
func (s *Store) GetScanSummary(ctx context.Context, id int64) (ScanSummary, error) {
	var sm ScanSummary
	var tj string
	err := s.DB.QueryRowContext(ctx, `SELECT id, COALESCE(name,''), template, status, targets_json,
		COALESCE(started_at,''), COALESCE(finished_at,'') FROM scan WHERE id=?`, id).
		Scan(&sm.ID, &sm.Name, &sm.Template, &sm.Status, &tj, &sm.StartedAt, &sm.FinishedAt)
	if err != nil {
		return sm, fmt.Errorf("scan %d: %w", id, err)
	}
	_ = json.Unmarshal([]byte(tj), &sm.Targets)
	return sm, s.fillSummary(ctx, &sm)
}

func (s *Store) fillSummary(ctx context.Context, sm *ScanSummary) error {
	sm.Findings = map[string]int{}
	rows, err := s.DB.QueryContext(ctx, `SELECT state, COUNT(*) FROM scan_job WHERE scan_id=? GROUP BY state`, sm.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var st string
		var n int
		rows.Scan(&st, &n)
		sm.JobsTotal += n
		switch st {
		case JobDone, JobSkipped:
			sm.JobsDone += n
		case JobFailed:
			sm.JobsFailed += n
			sm.JobsDone += n // finished, albeit unsuccessfully
		}
	}
	rows.Close()
	s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_observation WHERE scan_id=? AND state='up'`, sm.ID).Scan(&sm.Hosts)
	s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM service WHERE scan_id=? AND state='open'`, sm.ID).Scan(&sm.Services)
	// Findings with an active triage decision (accepted risk, false positive) are not counted.
	fr, err := s.DB.QueryContext(ctx, `SELECT f.severity, COUNT(*) FROM finding f
		WHERE f.id IN (SELECT finding_id FROM finding_occurrence WHERE scan_id=?) AND NOT `+activeTriageSQL+` GROUP BY f.severity`, sm.ID, nowArg())
	if err != nil {
		return err
	}
	defer fr.Close()
	for fr.Next() {
		var sev string
		var n int
		fr.Scan(&sev, &n)
		sm.Findings[sev] = n
	}
	return fr.Err()
}

// DeleteScan removes a scan and everything that belongs to it (jobs, services,
// TLS, knowledge base, occurrences, coverage). Findings that no scan still
// references are removed too; assets are kept as inventory history.
func (s *Store) DeleteScan(ctx context.Context, id int64) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		// Findings seen first in this scan survive it if later scans reference them.
		if _, err := tx.Exec(`UPDATE finding SET first_seen_scan=NULL WHERE first_seen_scan=?`, id); err != nil {
			return err
		}
		r, err := tx.Exec(`DELETE FROM scan WHERE id=?`, id)
		if err != nil {
			return err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return fmt.Errorf("scan %d: %w", id, sql.ErrNoRows)
		}
		_, err = tx.Exec(`DELETE FROM finding WHERE id NOT IN (SELECT finding_id FROM finding_occurrence)`)
		return err
	})
}

// RunningScanIDs returns scans recorded as running (used to mark scans left
// over from a crashed process as interrupted).
func (s *Store) RunningScanIDs(ctx context.Context) ([]int64, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id FROM scan WHERE status='running'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		out = append(out, id)
	}
	return out, rows.Err()
}

// HostRow is a host as observed in a scan.
type HostRow struct {
	Address   string
	Hostnames []string
	OS        string
	State     string
	AuthState string
}

// ListHosts returns hosts observed in a scan.
func (s *Store) ListHosts(ctx context.Context, scanID int64) ([]HostRow, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT a.address, a.hostnames, COALESCE(a.os_name,''), o.state, COALESCE(o.auth_status,'')
		FROM host_observation o JOIN asset a ON a.id=o.asset_id WHERE o.scan_id=? ORDER BY a.id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostRow
	for rows.Next() {
		var h HostRow
		var names string
		if err := rows.Scan(&h.Address, &names, &h.OS, &h.State, &h.AuthState); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(names), &h.Hostnames)
		out = append(out, h)
	}
	return out, rows.Err()
}

// CoverageRow is one check outcome on one host.
type CoverageRow struct {
	Address string
	CheckID string
	State   string
	Reason  string
}

// ListCheckRuns returns per-host check outcomes (ran / skipped / error).
func (s *Store) ListCheckRuns(ctx context.Context, scanID int64) ([]CoverageRow, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT a.address, c.check_id, c.state, COALESCE(c.reason,'')
		FROM check_run c JOIN asset a ON a.id=c.asset_id WHERE c.scan_id=? ORDER BY a.id, c.state, c.check_id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CoverageRow
	for rows.Next() {
		var r CoverageRow
		if err := rows.Scan(&r.Address, &r.CheckID, &r.State, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// JobRow is a job for display.
type JobRow struct {
	Stage    string
	ChunkKey string
	State    string
	Attempts int
	Error    string
	Started  string
	Finished string
	Targets  int
}

// ListJobs returns the jobs of a scan.
func (s *Store) ListJobs(ctx context.Context, scanID int64) ([]JobRow, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT stage, chunk_key, state, attempts, COALESCE(error,''), COALESCE(started_at,''),
		COALESCE(finished_at,''), json_array_length(targets_json) FROM scan_job WHERE scan_id=? ORDER BY id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JobRow
	for rows.Next() {
		var j JobRow
		if err := rows.Scan(&j.Stage, &j.ChunkKey, &j.State, &j.Attempts, &j.Error, &j.Started, &j.Finished, &j.Targets); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// ScanDiff compares two scans by finding identity.
type ScanDiff struct {
	New        []FindingRow // in B, not in A
	Resolved   []FindingRow // in A, not in B
	Persisting []FindingRow // in both (shown with B's data)
}

// DiffScans compares findings of scan a (older) to scan b (newer). "Resolved"
// means not seen in b; it is only meaningful if b covered the same hosts and
// engines (see coverage), which callers should state.
func (s *Store) DiffScans(ctx context.Context, a, b int64) (ScanDiff, error) {
	fa, err := s.ListFindings(ctx, a, "")
	if err != nil {
		return ScanDiff{}, err
	}
	fb, err := s.ListFindings(ctx, b, "")
	if err != nil {
		return ScanDiff{}, err
	}
	inA := map[int64]bool{}
	for _, f := range fa {
		inA[f.ID] = true
	}
	inB := map[int64]bool{}
	var d ScanDiff
	for _, f := range fb {
		inB[f.ID] = true
		if inA[f.ID] {
			d.Persisting = append(d.Persisting, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	for _, f := range fa {
		if !inB[f.ID] {
			d.Resolved = append(d.Resolved, f)
		}
	}
	return d, nil
}

// ScanOptionsJSON returns the raw options of a scan.
func (s *Store) ScanOptionsJSON(ctx context.Context, id int64) (string, error) {
	var o string
	err := s.DB.QueryRowContext(ctx, `SELECT options_json FROM scan WHERE id=?`, id).Scan(&o)
	return strings.TrimSpace(o), err
}
