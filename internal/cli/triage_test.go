package cli

import (
	"testing"
	"time"
)

func TestParseExpiry(t *testing.T) {
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	if e, err := parseExpiry("", now); err != nil || e != nil {
		t.Fatalf("empty: %v %v", e, err)
	}
	if e, _ := parseExpiry("90d", now); e == nil || e.Format("2006-01-02") != "2027-02-21" {
		t.Errorf("90d: %v", e)
	}
	if e, _ := parseExpiry("2w", now); e == nil || e.Format("2006-01-02") != "2026-12-07" {
		t.Errorf("2w: %v", e)
	}
	e, err := parseExpiry("2026-12-31", now)
	if err != nil || e.Format("2006-01-02 15:04") != "2026-12-31 23:59" {
		t.Errorf("date is end of day: %v %v", e, err)
	}
	for _, bad := range []string{"soon", "90", "1y", "2026-13-01"} {
		if _, err := parseExpiry(bad, now); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
