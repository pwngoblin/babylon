package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Triage statuses.
const (
	TriageAcceptedRisk  = "accepted_risk"
	TriageFalsePositive = "false_positive"
)

// MaxRiskAcceptance is the longest an accepted risk may last. Accepting a risk
// forever hides it forever; a bounded decision forces a review.
const MaxRiskAcceptance = 365 * 24 * time.Hour

// Triage is a decision about one finding.
type Triage struct {
	Status    string
	Reason    string
	CreatedAt string
	ExpiresAt string // "" = no expiry (false positives only)
	Active    bool   // false once ExpiresAt has passed: the finding counts again
}

func (t *Triage) fill(status, reason, created, expires sql.NullString, now time.Time) {
	t.Status, t.Reason, t.CreatedAt, t.ExpiresAt = status.String, reason.String, created.String, expires.String
	t.Active = true
	if t.ExpiresAt != "" {
		if exp, err := time.Parse(time.RFC3339, t.ExpiresAt); err == nil && !exp.After(now) {
			t.Active = false
		}
	}
}

// SetTriage records or replaces the decision for a finding. An accepted risk
// must expire within MaxRiskAcceptance; a false positive may have no expiry.
func (s *Store) SetTriage(ctx context.Context, findingID int64, status, reason string, expires *time.Time, now time.Time) error {
	if status != TriageAcceptedRisk && status != TriageFalsePositive {
		return fmt.Errorf("status must be %s or %s", TriageAcceptedRisk, TriageFalsePositive)
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("a reason is required")
	}
	var exp any
	if expires != nil {
		if !expires.After(now) {
			return fmt.Errorf("expiry %s is not in the future", expires.Format("2006-01-02"))
		}
		if status == TriageAcceptedRisk && expires.Sub(now) > MaxRiskAcceptance {
			return fmt.Errorf("an accepted risk can last at most 365 days")
		}
		exp = expires.UTC().Format(time.RFC3339)
	} else if status == TriageAcceptedRisk {
		return fmt.Errorf("an accepted risk needs an expiry (--expires)")
	}
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		var one int
		if err := tx.QueryRow(`SELECT 1 FROM finding WHERE id=?`, findingID).Scan(&one); err != nil {
			return fmt.Errorf("finding %d not found", findingID)
		}
		_, err := tx.Exec(`INSERT INTO triage(finding_id,status,reason,created_at,expires_at) VALUES(?,?,?,?,?)
			ON CONFLICT(finding_id) DO UPDATE SET status=excluded.status, reason=excluded.reason,
			  created_at=excluded.created_at, expires_at=excluded.expires_at`,
			findingID, status, strings.TrimSpace(reason), now.UTC().Format(time.RFC3339), exp)
		return err
	})
}

// RemoveTriage deletes a decision; the finding counts again.
func (s *Store) RemoveTriage(ctx context.Context, findingID int64) error {
	var n int64
	err := s.W.Do(ctx, func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM triage WHERE finding_id=?`, findingID)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	if err == nil && n == 0 {
		return fmt.Errorf("finding %d has no triage decision", findingID)
	}
	return err
}

// TriageRow is a decision with the finding it applies to.
type TriageRow struct {
	FindingID int64
	Address   string
	Port      int
	Title     string
	Severity  string
	Triage
}

// ListTriage returns every decision, newest first.
func (s *Store) ListTriage(ctx context.Context, now time.Time) ([]TriageRow, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT t.finding_id, a.address, COALESCE(f.port,0), f.title, f.severity,
		t.status, t.reason, t.created_at, t.expires_at
		FROM triage t JOIN finding f ON f.id=t.finding_id JOIN asset a ON a.id=f.asset_id ORDER BY t.created_at DESC, t.finding_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TriageRow
	for rows.Next() {
		var r TriageRow
		var st, rs, cr, ex sql.NullString
		if err := rows.Scan(&r.FindingID, &r.Address, &r.Port, &r.Title, &r.Severity, &st, &rs, &cr, &ex); err != nil {
			return nil, err
		}
		r.Triage.fill(st, rs, cr, ex, now)
		out = append(out, r)
	}
	return out, rows.Err()
}

// activeTriageSQL is a SQL predicate (argument: now as RFC3339) that is true when
// finding alias `f` has a triage decision that has not expired.
const activeTriageSQL = `EXISTS (SELECT 1 FROM triage t WHERE t.finding_id=f.id AND (t.expires_at IS NULL OR t.expires_at > ?))`

func nowArg() string { return time.Now().UTC().Format(time.RFC3339) }
