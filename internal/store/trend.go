package store

import (
	"context"
	"database/sql"
	"sort"
	"strings"
)

// TrendPoint is one completed scan in a series of scans of the same targets.
type TrendPoint struct {
	ScanID     int64
	FinishedAt string
	Hosts      int
	Findings   map[string]int // open findings by severity (triaged ones excluded)
	New        int            // not seen in the previous scan of this series (informational findings excluded)
	Resolved   int            // seen in the previous scan, gone now
	Failed     bool           // scan had failed jobs, so New/Resolved may be skewed
}

// TrendSeries is the history of scans that had exactly the same targets.
type TrendSeries struct {
	Targets []string
	Points  []TrendPoint // oldest first
}

// Trends groups completed scans by their exact target list and compares each
// scan with the previous one in its series. Only like-for-like scans are
// compared: "resolved" is meaningless when the targets differ. limit caps the
// points per series (0 = all), keeping the most recent.
func (s *Store) Trends(ctx context.Context, limit int) ([]TrendSeries, error) {
	all, err := s.ListScans(ctx) // newest first
	if err != nil {
		return nil, err
	}
	by := map[string]*TrendSeries{}
	var order []string
	for i := len(all) - 1; i >= 0; i-- { // oldest first
		sc := all[i]
		if sc.Status != ScanCompleted {
			continue
		}
		key := strings.Join(sc.Targets, ",")
		ser := by[key]
		if ser == nil {
			ser = &TrendSeries{Targets: sc.Targets}
			by[key] = ser
			order = append(order, key)
		}
		p := TrendPoint{ScanID: sc.ID, FinishedAt: sc.FinishedAt, Hosts: sc.Hosts, Findings: sc.Findings, Failed: sc.JobsFailed > 0}
		if n := len(ser.Points); n > 0 {
			d, err := s.DiffScans(ctx, ser.Points[n-1].ScanID, sc.ID)
			if err != nil {
				return nil, err
			}
			p.New, p.Resolved = countOpen(d.New), countOpen(d.Resolved)
		}
		ser.Points = append(ser.Points, p)
	}
	var out []TrendSeries
	for _, k := range order {
		ser := *by[k]
		if limit > 0 && len(ser.Points) > limit {
			ser.Points = ser.Points[len(ser.Points)-limit:]
		}
		out = append(out, ser)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Points, out[j].Points
		return a[len(a)-1].ScanID > b[len(b)-1].ScanID // most recently scanned first
	})
	return out, nil
}

func countOpen(rows []FindingRow) int {
	n := 0
	for _, r := range rows {
		if r.Severity == "info" || (r.Triage != nil && r.Triage.Active) {
			continue
		}
		n++
	}
	return n
}

// PreviousScan returns the latest completed scan before id that had exactly the
// same targets, or 0 when there is none (id is the first of its series).
func (s *Store) PreviousScan(ctx context.Context, id int64) (int64, error) {
	var prev int64
	err := s.DB.QueryRowContext(ctx, `SELECT p.id FROM scan p, scan c
		WHERE c.id=? AND p.id<c.id AND p.targets_json=c.targets_json AND p.status=?
		ORDER BY p.id DESC LIMIT 1`, id, ScanCompleted).Scan(&prev)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return prev, err
}
