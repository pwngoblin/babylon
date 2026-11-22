package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// NucleiTemplate is one indexed template (see engines/nuclei.Meta).
type NucleiTemplate struct {
	Path      string
	ID        string
	Name      string
	Severity  string
	Protocols []string
	Tags      []string
	CVEs      []string
	CVSS      *float64
	Vendor    string
	Product   string
	Verified  bool
}

// ReplaceNucleiIndex atomically replaces the whole template index and records
// its freshness in feed_state.
func (s *Store) ReplaceNucleiIndex(ctx context.Context, version string, tpls []NucleiTemplate) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM nuclei_template`); err != nil {
			return err
		}
		st, err := tx.Prepare(`INSERT OR REPLACE INTO nuclei_template(path,id,name,severity,protocols,tags,cves,cvss,vendor,product,verified)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, t := range tpls {
			pj, _ := json.Marshal(nonNil(t.Protocols))
			tj, _ := json.Marshal(nonNil(t.Tags))
			cj, _ := json.Marshal(nonNil(t.CVEs))
			v := 0
			if t.Verified {
				v = 1
			}
			if _, err := st.Exec(t.Path, t.ID, nullable(t.Name), t.Severity, string(pj), string(tj), string(cj),
				nullFloat(t.CVSS), nullable(t.Vendor), nullable(t.Product), v); err != nil {
				return err
			}
		}
		_, err = tx.Exec(`INSERT INTO feed_state(name,version,fetched_at,record_count) VALUES('nuclei-templates',?,?,?)
			ON CONFLICT(name) DO UPDATE SET version=excluded.version, fetched_at=excluded.fetched_at, record_count=excluded.record_count`,
			version, ts(time.Now()), len(tpls))
		return err
	})
}

// LoadNucleiIndex reads the entire template index.
func (s *Store) LoadNucleiIndex(ctx context.Context) ([]NucleiTemplate, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT path,id,COALESCE(name,''),severity,protocols,tags,cves,cvss,COALESCE(vendor,''),COALESCE(product,''),verified FROM nuclei_template`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NucleiTemplate
	for rows.Next() {
		var t NucleiTemplate
		var pj, tj, cj string
		var cvss sql.NullFloat64
		var v int
		if err := rows.Scan(&t.Path, &t.ID, &t.Name, &t.Severity, &pj, &tj, &cj, &cvss, &t.Vendor, &t.Product, &v); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(pj), &t.Protocols)
		json.Unmarshal([]byte(tj), &t.Tags)
		json.Unmarshal([]byte(cj), &t.CVEs)
		if cvss.Valid {
			x := cvss.Float64
			t.CVSS = &x
		}
		t.Verified = v == 1
		out = append(out, t)
	}
	return out, rows.Err()
}

// FeedState returns (version, fetchedAt, count) for a feed, ok=false if absent.
func (s *Store) FeedState(ctx context.Context, name string) (version, fetched string, count int, ok bool, err error) {
	var v, f sql.NullString
	var c sql.NullInt64
	e := s.DB.QueryRowContext(ctx, `SELECT version,fetched_at,record_count FROM feed_state WHERE name=?`, name).Scan(&v, &f, &c)
	if e == sql.ErrNoRows {
		return "", "", 0, false, nil
	}
	return v.String, f.String, int(c.Int64), e == nil, e
}
