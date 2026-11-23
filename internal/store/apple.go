package store

import (
	"context"
	"database/sql"
)

// AppleRelease is one macOS security release from Apple's release index.
type AppleRelease struct {
	Major    int
	Release  string // 26.7.3
	Product  string // macOS Tahoe
	Released string // YYYY-MM-DD
	URL      string
}

// AppleFix is a CVE fixed by a macOS release.
type AppleFix struct {
	Major    int
	Release  string
	CVE      string
	Product  string
	Released string
	CVSS     *float64
}

// UpsertAppleReleases stores the release index (all macOS releases, including
// those with no published CVEs, so the newest release per line is known).
func (s *Store) UpsertAppleReleases(ctx context.Context, rel []AppleRelease) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		st, err := tx.PrepareContext(ctx, `INSERT INTO macos_release(major,release,product,released,url) VALUES(?,?,?,?,?)
			ON CONFLICT(major,release) DO UPDATE SET product=excluded.product, released=excluded.released, url=excluded.url`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, r := range rel {
			if _, err := st.ExecContext(ctx, r.Major, r.Release, r.Product, r.Released, r.URL); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpsertAppleFixes replaces the CVE list of one release and records the feed
// state for it, so unchanged releases are not downloaded again.
func (s *Store) UpsertAppleFixes(ctx context.Context, major int, release string, cves []string, feed FeedInfo) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM macos_fix WHERE major=? AND release=?`, major, release); err != nil {
			return err
		}
		st, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO macos_fix(major,release,cve) VALUES(?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, c := range cves {
			if _, err := st.ExecContext(ctx, major, release, c); err != nil {
				return err
			}
		}
		feed.Count = len(cves)
		return setFeed(tx, feed)
	})
}

// AppleReleases lists the known releases of one macOS major line (any order).
func (s *Store) AppleReleases(ctx context.Context, major int) ([]AppleRelease, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT major,release,product,COALESCE(released,''),COALESCE(url,'') FROM macos_release WHERE major=?`, major)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppleRelease
	for rows.Next() {
		var r AppleRelease
		if err := rows.Scan(&r.Major, &r.Release, &r.Product, &r.Released, &r.URL); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AppleFixesForMajor lists every stored fix of one macOS line with its CVSS (if the CVE is indexed).
func (s *Store) AppleFixesForMajor(ctx context.Context, major int) ([]AppleFix, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT f.major,f.release,f.cve,COALESCE(r.product,''),COALESCE(r.released,''),
		(SELECT c.cvss_v3 FROM cve c WHERE c.cve_id=f.cve)
		FROM macos_fix f LEFT JOIN macos_release r ON r.major=f.major AND r.release=f.release WHERE f.major=?`, major)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppleFix
	for rows.Next() {
		var f AppleFix
		var c sql.NullFloat64
		if err := rows.Scan(&f.Major, &f.Release, &f.CVE, &f.Product, &f.Released, &c); err != nil {
			return nil, err
		}
		if c.Valid {
			v := c.Float64
			f.CVSS = &v
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// CountApple returns the number of stored fixes and releases.
func (s *Store) CountApple(ctx context.Context) (fixes, releases int, err error) {
	if err = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM macos_fix`).Scan(&fixes); err != nil {
		return
	}
	err = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM macos_release`).Scan(&releases)
	return
}
