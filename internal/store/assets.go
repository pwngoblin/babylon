package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Criticality levels for assets.
const (
	CritLow      = 1
	CritMedium   = 2 // default
	CritHigh     = 3
	CritCritical = 4
)

// CriticalityName returns the label for a level.
func CriticalityName(n int) string {
	switch n {
	case CritLow:
		return "low"
	case CritMedium:
		return "medium"
	case CritHigh:
		return "high"
	case CritCritical:
		return "critical"
	}
	return "?"
}

// ParseCriticality accepts low, medium, high, critical (or 1 to 4).
func ParseCriticality(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low", "1":
		return CritLow, nil
	case "medium", "med", "2":
		return CritMedium, nil
	case "high", "3":
		return CritHigh, nil
	case "critical", "4":
		return CritCritical, nil
	}
	return 0, fmt.Errorf("criticality must be low, medium, high or critical")
}

// Asset is a known host with the attributes a person set on it.
type Asset struct {
	ID          int64
	Address     string
	Hostnames   []string
	OS          string
	Vendor      string
	Criticality int
	Fragile     bool
	Tags        []string
	FirstSeen   string
	LastSeen    string
	// Open (not triaged away) findings in the most recent scan that included the host.
	OpenFindings map[string]int
}

// ListAssets returns every known asset with its open findings from the latest
// scan that saw it, ordered by criticality then address.
func (s *Store) ListAssets(ctx context.Context) ([]Asset, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, address, hostnames, COALESCE(os_name,''), COALESCE(vendor,''),
		criticality, fragile, tags, first_seen, last_seen FROM asset`)
	if err != nil {
		return nil, err
	}
	var out []Asset
	for rows.Next() {
		var a Asset
		var hn, tg string
		var fr int
		if err := rows.Scan(&a.ID, &a.Address, &hn, &a.OS, &a.Vendor, &a.Criticality, &fr, &tg, &a.FirstSeen, &a.LastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		_ = json.Unmarshal([]byte(hn), &a.Hostnames)
		_ = json.Unmarshal([]byte(tg), &a.Tags)
		a.Fragile = fr == 1
		out = append(out, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Open findings per asset come from the latest scan that saw each asset, in
	// two passes over the data (one query per asset took minutes at 5,000 hosts).
	latest := map[int64]int64{}
	lr, err := s.DB.QueryContext(ctx, `SELECT asset_id, MAX(scan_id) FROM host_observation GROUP BY asset_id`)
	if err != nil {
		return nil, err
	}
	for lr.Next() {
		var aid, sid int64
		if err := lr.Scan(&aid, &sid); err != nil {
			lr.Close()
			return nil, err
		}
		latest[aid] = sid
	}
	lr.Close()
	if err := lr.Err(); err != nil {
		return nil, err
	}
	type key struct{ asset, scan int64 }
	counts := map[key]map[string]int{}
	fr, err := s.DB.QueryContext(ctx, `SELECT f.asset_id, o.scan_id, f.severity, COUNT(DISTINCT f.id)
		FROM finding f JOIN finding_occurrence o ON o.finding_id=f.id
		WHERE NOT `+activeTriageSQL+` GROUP BY f.asset_id, o.scan_id, f.severity`, nowArg())
	if err != nil {
		return nil, err
	}
	for fr.Next() {
		var aid, sid int64
		var sev string
		var n int
		if err := fr.Scan(&aid, &sid, &sev, &n); err != nil {
			fr.Close()
			return nil, err
		}
		if latest[aid] != sid {
			continue
		}
		k := key{aid, sid}
		if counts[k] == nil {
			counts[k] = map[string]int{}
		}
		counts[k][sev] = n
	}
	fr.Close()
	if err := fr.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		a := &out[i]
		a.OpenFindings = map[string]int{}
		for sev, n := range counts[key{a.ID, latest[a.ID]}] {
			a.OpenFindings[sev] = n
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Criticality != out[j].Criticality {
			return out[i].Criticality > out[j].Criticality
		}
		return out[i].Address < out[j].Address
	})
	return out, nil
}

// AssetUpdate lists the attributes to change; nil fields are left alone.
type AssetUpdate struct {
	Criticality *int
	Fragile     *bool
	Tags        *[]string
}

// UpdateAsset changes attributes of an asset, creating it if the address has
// not been scanned yet (so criticality can be set before the first scan).
func (s *Store) UpdateAsset(ctx context.Context, address string, u AssetUpdate) error {
	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("address is required")
	}
	if u.Criticality != nil && (*u.Criticality < CritLow || *u.Criticality > CritCritical) {
		return fmt.Errorf("criticality out of range")
	}
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		now := ts(time.Now())
		if _, err := tx.Exec(`INSERT OR IGNORE INTO asset(address,first_seen,last_seen) VALUES(?,?,?)`, address, now, now); err != nil {
			return err
		}
		if u.Criticality != nil {
			if _, err := tx.Exec(`UPDATE asset SET criticality=? WHERE address=?`, *u.Criticality, address); err != nil {
				return err
			}
		}
		if u.Fragile != nil {
			v := 0
			if *u.Fragile {
				v = 1
			}
			if _, err := tx.Exec(`UPDATE asset SET fragile=? WHERE address=?`, v, address); err != nil {
				return err
			}
		}
		if u.Tags != nil {
			b, _ := json.Marshal(*u.Tags)
			if _, err := tx.Exec(`UPDATE asset SET tags=? WHERE address=?`, string(b), address); err != nil {
				return err
			}
		}
		return nil
	})
}

// IsFragile reports whether an address is marked fragile (unknown = false).
func (s *Store) IsFragile(ctx context.Context, address string) bool {
	var f int
	_ = s.DB.QueryRowContext(ctx, `SELECT fragile FROM asset WHERE address=?`, address).Scan(&f)
	return f == 1
}
