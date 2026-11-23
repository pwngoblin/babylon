package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// FeedInfo is the bookkeeping for one downloaded feed.
type FeedInfo struct {
	Name         string
	Version      string
	FetchedAt    string
	Count        int
	ETag         string
	LastModified string
	Detail       string
}

// GetFeed returns a feed's state, ok=false if it was never fetched.
func (s *Store) GetFeed(ctx context.Context, name string) (FeedInfo, bool, error) {
	var f FeedInfo
	var v, fa, et, lm, d sql.NullString
	var c sql.NullInt64
	err := s.DB.QueryRowContext(ctx, `SELECT name,version,fetched_at,record_count,etag,last_modified,detail FROM feed_state WHERE name=?`, name).
		Scan(&f.Name, &v, &fa, &c, &et, &lm, &d)
	if err == sql.ErrNoRows {
		return f, false, nil
	}
	f.Version, f.FetchedAt, f.Count, f.ETag, f.LastModified, f.Detail = v.String, fa.String, int(c.Int64), et.String, lm.String, d.String
	return f, err == nil, err
}

// ListFeeds returns every feed's state ordered by name.
func (s *Store) ListFeeds(ctx context.Context) ([]FeedInfo, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT name FROM feed_state ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	rows.Close()
	var out []FeedInfo
	for _, n := range names {
		f, ok, err := s.GetFeed(ctx, n)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, f)
		}
	}
	return out, nil
}

func setFeed(tx *sql.Tx, f FeedInfo) error {
	if f.FetchedAt == "" {
		f.FetchedAt = ts(time.Now())
	}
	_, err := tx.Exec(`INSERT INTO feed_state(name,version,fetched_at,record_count,etag,last_modified,detail) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET version=excluded.version, fetched_at=excluded.fetched_at, record_count=excluded.record_count,
		  etag=excluded.etag, last_modified=excluded.last_modified, detail=excluded.detail`,
		f.Name, nullable(f.Version), f.FetchedAt, f.Count, nullable(f.ETag), nullable(f.LastModified), nullable(f.Detail))
	return err
}

// SetFeed records a feed's state.
func (s *Store) SetFeed(ctx context.Context, f FeedInfo) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error { return setFeed(tx, f) })
}

// KEVEntry is one CISA Known Exploited Vulnerabilities record.
type KEVEntry struct {
	CVE, Vendor, Product, Name, DateAdded, DueDate, Ransomware, Notes string
}

// ReplaceKEV swaps the KEV table for a fresh catalogue in one transaction and
// refreshes the KEV flag on stored findings.
func (s *Store) ReplaceKEV(ctx context.Context, entries []KEVEntry, feed FeedInfo) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM kev`); err != nil {
			return err
		}
		st, err := tx.Prepare(`INSERT OR REPLACE INTO kev(cve_id,vendor,product,name,date_added,due_date,ransomware_use,notes) VALUES(?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, e := range entries {
			if _, err := st.Exec(strings.ToUpper(e.CVE), e.Vendor, e.Product, e.Name, e.DateAdded, e.DueDate, e.Ransomware, e.Notes); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`UPDATE finding SET kev = EXISTS(SELECT 1 FROM finding_cve fc JOIN kev k ON k.cve_id=fc.cve_id WHERE fc.finding_id=finding.id)`); err != nil {
			return err
		}
		feed.Count = len(entries)
		return setFeed(tx, feed)
	})
}

// EPSSEntry is one FIRST EPSS score.
type EPSSEntry struct {
	CVE               string
	Score, Percentile float64
}

// ReplaceEPSS swaps the EPSS table in one transaction and refreshes stored findings.
func (s *Store) ReplaceEPSS(ctx context.Context, asOf string, entries []EPSSEntry, feed FeedInfo) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM epss`); err != nil {
			return err
		}
		st, err := tx.Prepare(`INSERT OR REPLACE INTO epss(cve_id,score,percentile,as_of) VALUES(?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, e := range entries {
			if _, err := st.Exec(strings.ToUpper(e.CVE), e.Score, e.Percentile, asOf); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`UPDATE finding SET epss = (SELECT MAX(e.score) FROM finding_cve fc JOIN epss e ON e.cve_id=fc.cve_id WHERE fc.finding_id=finding.id)
			WHERE id IN (SELECT finding_id FROM finding_cve)`); err != nil {
			return err
		}
		feed.Count = len(entries)
		return setFeed(tx, feed)
	})
}

// CVERecord is one CVE with the vulnerable product ranges NVD lists for it.
type CVERecord struct {
	ID, Published, Modified, Description string
	CVSS                                 *float64
	Vector                               string
	CVSS4                                *float64
	CWE, Status                          string
	Matches                              []CPEMatch
}

// CPEMatch is one vulnerable product/version range.
type CPEMatch struct {
	Vendor, Product, TargetSW string
	Exact                     string
	StartIncl, StartExcl      string
	EndIncl, EndExcl          string
}

// UpsertCVEs stores a page of NVD records in one transaction. Matches for each
// CVE are replaced wholesale so a re-analysed CVE never keeps stale ranges.
// Rejected CVEs are removed.
func (s *Store) UpsertCVEs(ctx context.Context, recs []CVERecord, feed *FeedInfo) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		up, err := tx.Prepare(`INSERT INTO cve(cve_id,published,modified,description,cvss_v3,cvss_v3_vector,cvss_v4,cwe,vuln_status) VALUES(?,?,?,?,?,?,?,?,?)
			ON CONFLICT(cve_id) DO UPDATE SET published=excluded.published, modified=excluded.modified, description=excluded.description,
			  cvss_v3=excluded.cvss_v3, cvss_v3_vector=excluded.cvss_v3_vector, cvss_v4=excluded.cvss_v4, cwe=excluded.cwe, vuln_status=excluded.vuln_status`)
		if err != nil {
			return err
		}
		defer up.Close()
		del, err := tx.Prepare(`DELETE FROM cpe_match WHERE cve_id=? AND source='nvd'`)
		if err != nil {
			return err
		}
		defer del.Close()
		ins, err := tx.Prepare(`INSERT INTO cpe_match(source,cve_id,vendor,product,target_sw,version_exact,v_start_incl,v_start_excl,v_end_incl,v_end_excl,vulnerable)
			VALUES('nvd',?,?,?,?,?,?,?,?,?,1)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, r := range recs {
			id := strings.ToUpper(r.ID)
			if strings.EqualFold(r.Status, "Rejected") {
				if _, err := tx.Exec(`DELETE FROM cve WHERE cve_id=?`, id); err != nil {
					return err
				}
				continue
			}
			var c3, c4 any
			if r.CVSS != nil {
				c3 = *r.CVSS
			}
			if r.CVSS4 != nil {
				c4 = *r.CVSS4
			}
			if _, err := up.Exec(id, r.Published, r.Modified, r.Description, c3, nullable(r.Vector), c4, nullable(r.CWE), r.Status); err != nil {
				return err
			}
			if _, err := del.Exec(id); err != nil {
				return err
			}
			for _, m := range r.Matches {
				if _, err := ins.Exec(id, m.Vendor, m.Product, nullable(m.TargetSW), nullable(m.Exact),
					nullable(m.StartIncl), nullable(m.StartExcl), nullable(m.EndIncl), nullable(m.EndExcl)); err != nil {
					return err
				}
			}
		}
		if feed != nil {
			return setFeed(tx, *feed)
		}
		return nil
	})
}

// CountCVEs returns how many CVEs and CPE ranges are indexed.
func (s *Store) CountCVEs(ctx context.Context) (cves, ranges int, err error) {
	if err = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cve`).Scan(&cves); err != nil {
		return
	}
	err = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cpe_match`).Scan(&ranges)
	return
}

// OSVRecord is one OSV advisory.
type OSVRecord struct {
	ID, Modified, Summary, Details string
	Severity                       json.RawMessage
	Aliases                        []string
	Affected                       []OSVAffected
}

// OSVAffected is one affected package range of an advisory.
type OSVAffected struct {
	Ecosystem, Package              string
	Introduced, Fixed, LastAffected string
	Versions                        []string
}

// ReplaceOSVEcosystem swaps every advisory range of an ecosystem (and its
// "Ecosystem:release" variants) with the fresh dump, in one transaction.
func (s *Store) ReplaceOSVEcosystem(ctx context.Context, ecosystem string, recs []OSVRecord, feed FeedInfo) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM osv_affected WHERE ecosystem=? OR ecosystem LIKE ? ESCAPE '\'`, ecosystem, escapeLike(ecosystem)+`:%`); err != nil {
			return err
		}
		adv, err := tx.Prepare(`INSERT INTO osv_advisory(id,modified,summary,details,severity_json) VALUES(?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET modified=excluded.modified, summary=excluded.summary, details=excluded.details, severity_json=excluded.severity_json`)
		if err != nil {
			return err
		}
		defer adv.Close()
		al, err := tx.Prepare(`INSERT OR IGNORE INTO osv_alias(id,alias) VALUES(?,?)`)
		if err != nil {
			return err
		}
		defer al.Close()
		af, err := tx.Prepare(`INSERT INTO osv_affected(advisory_id,ecosystem,package,introduced,fixed,last_affected,versions_json) VALUES(?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer af.Close()
		for _, r := range recs {
			var sev any
			if len(r.Severity) > 0 {
				sev = string(r.Severity)
			}
			if _, err := adv.Exec(r.ID, r.Modified, r.Summary, truncate(r.Details, 4096), sev); err != nil {
				return err
			}
			for _, a := range r.Aliases {
				if _, err := al.Exec(r.ID, a); err != nil {
					return err
				}
			}
			for _, a := range r.Affected {
				var vj any
				if len(a.Versions) > 0 {
					b, _ := json.Marshal(a.Versions)
					vj = string(b)
				}
				if _, err := af.Exec(r.ID, a.Ecosystem, a.Package, nullable(a.Introduced), nullable(a.Fixed), nullable(a.LastAffected), vj); err != nil {
					return err
				}
			}
		}
		// Advisories that no longer affect anything are dropped (cascades to aliases).
		if _, err := tx.Exec(`DELETE FROM osv_advisory WHERE id NOT IN (SELECT advisory_id FROM osv_affected)`); err != nil {
			return err
		}
		feed.Count = len(recs)
		return setFeed(tx, feed)
	})
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// MatchRow is a stored vulnerable range joined with its CVE.
type MatchRow struct {
	CVE, Description, Status string
	CVSS                     *float64
	Vector                   string
	Match                    CPEMatch
}

// CPEMatches returns the vulnerable ranges indexed for a (vendor, product).
func (s *Store) CPEMatches(ctx context.Context, vendor, product string) ([]MatchRow, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT m.cve_id, COALESCE(c.description,''), COALESCE(c.vuln_status,''), c.cvss_v3, COALESCE(c.cvss_v3_vector,''),
		COALESCE(m.target_sw,''), COALESCE(m.version_exact,''), COALESCE(m.v_start_incl,''), COALESCE(m.v_start_excl,''),
		COALESCE(m.v_end_incl,''), COALESCE(m.v_end_excl,'')
		FROM cpe_match m JOIN cve c ON c.cve_id=m.cve_id WHERE m.vendor=? AND m.product=? AND m.vulnerable=1`, vendor, product)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MatchRow
	for rows.Next() {
		var r MatchRow
		var cv sql.NullFloat64
		m := &r.Match
		if err := rows.Scan(&r.CVE, &r.Description, &r.Status, &cv, &r.Vector, &m.TargetSW, &m.Exact, &m.StartIncl, &m.StartExcl, &m.EndIncl, &m.EndExcl); err != nil {
			return nil, err
		}
		if cv.Valid {
			v := cv.Float64
			r.CVSS = &v
		}
		m.Vendor, m.Product = vendor, product
		out = append(out, r)
	}
	return out, rows.Err()
}

// VendorsForProduct lists the vendors that have ranges indexed for a product name.
func (s *Store) VendorsForProduct(ctx context.Context, product string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT DISTINCT vendor FROM cpe_match WHERE product=? LIMIT 5`, product)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// PkgAdvisory is one OSV affected-range row for a package, with the CVEs the
// advisory covers.
type PkgAdvisory struct {
	Advisory, Package, Introduced, Fixed, LastAffected string
	Summary                                            string
	CVEs                                               []string
}

// OSVForPackages returns advisory ranges for the given package names within an
// ecosystem ("Debian:12" also matches variants such as "Ubuntu:22.04:LTS" via
// the ":" suffix rule, but never "Debian:121").
func (s *Store) OSVForPackages(ctx context.Context, ecoPrefix string, names []string) ([]PkgAdvisory, error) {
	var out []PkgAdvisory
	for start := 0; start < len(names); start += 200 {
		end := min(start+200, len(names))
		chunk := names[start:end]
		args := []any{ecoPrefix, escapeLike(ecoPrefix) + `:%`}
		ph := make([]string, len(chunk))
		for i, n := range chunk {
			ph[i] = "?"
			args = append(args, n)
		}
		rows, err := s.DB.QueryContext(ctx, `SELECT a.advisory_id, a.package, COALESCE(a.introduced,''), COALESCE(a.fixed,''), COALESCE(a.last_affected,''), COALESCE(v.summary,'')
			FROM osv_affected a LEFT JOIN osv_advisory v ON v.id=a.advisory_id
			WHERE (a.ecosystem=? OR a.ecosystem LIKE ? ESCAPE '\') AND a.package IN (`+strings.Join(ph, ",")+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var p PkgAdvisory
			if err := rows.Scan(&p.Advisory, &p.Package, &p.Introduced, &p.Fixed, &p.LastAffected, &p.Summary); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, p)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	// attach CVE aliases
	ids := map[string]bool{}
	for _, p := range out {
		ids[p.Advisory] = true
	}
	cves := map[string][]string{}
	idList := make([]string, 0, len(ids))
	for id := range ids {
		idList = append(idList, id)
	}
	for start := 0; start < len(idList); start += 500 {
		chunk := idList[start:min(start+500, len(idList))]
		ph := make([]string, len(chunk))
		args := make([]any, len(chunk))
		for i, id := range chunk {
			ph[i], args[i] = "?", id
		}
		rows, err := s.DB.QueryContext(ctx, `SELECT id, alias FROM osv_alias WHERE alias LIKE 'CVE-%' AND id IN (`+strings.Join(ph, ",")+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, al string
			if err := rows.Scan(&id, &al); err != nil {
				rows.Close()
				return nil, err
			}
			cves[id] = append(cves[id], al)
		}
		rows.Close()
	}
	for i := range out {
		out[i].CVEs = cves[out[i].Advisory]
	}
	return out, nil
}

// CVSSScores returns the best known CVSS v3 base score per CVE id.
func (s *Store) CVSSScores(ctx context.Context, ids []string) (map[string]float64, error) {
	out := map[string]float64{}
	for start := 0; start < len(ids); start += 500 {
		chunk := ids[start:min(start+500, len(ids))]
		ph := make([]string, len(chunk))
		args := make([]any, len(chunk))
		for i, id := range chunk {
			ph[i], args[i] = "?", id
		}
		rows, err := s.DB.QueryContext(ctx, `SELECT cve_id, cvss_v3 FROM cve WHERE cvss_v3 IS NOT NULL AND cve_id IN (`+strings.Join(ph, ",")+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var v float64
			if err := rows.Scan(&id, &v); err != nil {
				rows.Close()
				return nil, err
			}
			out[id] = v
		}
		rows.Close()
	}
	return out, nil
}

// CountOSV returns the number of indexed OSV advisories and package ranges.
func (s *Store) CountOSV(ctx context.Context) (advisories, ranges int, err error) {
	if err = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM osv_advisory`).Scan(&advisories); err != nil {
		return
	}
	err = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM osv_affected`).Scan(&ranges)
	return
}

// AllKEV returns the whole CISA KEV catalogue (a couple of thousand rows).
func (s *Store) AllKEV(ctx context.Context) ([]KEVEntry, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT cve_id, COALESCE(vendor,''), COALESCE(product,''), COALESCE(name,''), COALESCE(date_added,''), COALESCE(ransomware_use,'') FROM kev ORDER BY cve_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KEVEntry
	for rows.Next() {
		var k KEVEntry
		if err := rows.Scan(&k.CVE, &k.Vendor, &k.Product, &k.Name, &k.DateAdded, &k.Ransomware); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// AddCVEListRanges adds version ranges from cvelistV5 for CVEs that NVD has no
// ranges for. NVD data always wins: a CVE with any NVD range is skipped, and
// NVD metadata (description, CVSS) is never overwritten, only filled in when
// missing. It returns how many CVEs received ranges.
func (s *Store) AddCVEListRanges(ctx context.Context, recs []CVERecord) (int, error) {
	added := 0
	err := s.W.Do(ctx, func(tx *sql.Tx) error {
		added = 0
		up, err := tx.Prepare(`INSERT INTO cve(cve_id,published,modified,description,cvss_v3,cvss_v3_vector,vuln_status) VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(cve_id) DO UPDATE SET
			  description=COALESCE(NULLIF(cve.description,''), excluded.description),
			  cvss_v3=COALESCE(cve.cvss_v3, excluded.cvss_v3),
			  cvss_v3_vector=COALESCE(cve.cvss_v3_vector, excluded.cvss_v3_vector)`)
		if err != nil {
			return err
		}
		defer up.Close()
		ins, err := tx.Prepare(`INSERT INTO cpe_match(source,cve_id,vendor,product,target_sw,version_exact,v_start_incl,v_start_excl,v_end_incl,v_end_excl,vulnerable)
			VALUES('cvelist',?,?,?,NULL,?,?,?,?,?,1)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, r := range recs {
			id := strings.ToUpper(r.ID)
			var has int
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM cpe_match WHERE cve_id=? AND source='nvd')`, id).Scan(&has); err != nil {
				return err
			}
			if has == 1 {
				continue
			}
			var c3 any
			if r.CVSS != nil {
				c3 = *r.CVSS
			}
			if _, err := up.Exec(id, r.Published, r.Modified, r.Description, c3, nullable(r.Vector), r.Status); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM cpe_match WHERE cve_id=? AND source='cvelist'`, id); err != nil {
				return err
			}
			for _, m := range r.Matches {
				if _, err := ins.Exec(id, m.Vendor, m.Product, nullable(m.Exact), nullable(m.StartIncl), nullable(m.StartExcl), nullable(m.EndIncl), nullable(m.EndExcl)); err != nil {
					return err
				}
			}
			added++
		}
		return nil
	})
	return added, err
}

// MSRCFix is one Windows security fix: the first revision of a build that contains it.
type MSRCFix struct {
	Build    string // major.minor.build, e.g. 10.0.19045
	CVE      string
	FixedUBR int
	KB       string
	Title    string
	CVSS     *float64
	Severity string
}

// UpsertMSRC stores fixes, keeping the highest fixed revision per (build, CVE)
// because a later bulletin month may supersede an earlier fix.
func (s *Store) UpsertMSRC(ctx context.Context, fixes []MSRCFix, feed FeedInfo) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		st, err := tx.PrepareContext(ctx, `INSERT INTO msrc_fix(os_build,cve,fixed_ubr,kb,title,cvss,severity) VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(os_build,cve) DO UPDATE SET fixed_ubr=excluded.fixed_ubr, kb=excluded.kb, title=excluded.title,
			  cvss=COALESCE(excluded.cvss, cvss), severity=COALESCE(excluded.severity, severity)
			WHERE excluded.fixed_ubr > msrc_fix.fixed_ubr`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, f := range fixes {
			if _, err := st.ExecContext(ctx, f.Build, f.CVE, f.FixedUBR, f.KB, f.Title, f.CVSS, f.Severity); err != nil {
				return err
			}
		}
		return setFeed(tx, feed)
	})
}

// MSRCMissing returns the fixes a host on (build, ubr) does not yet have.
func (s *Store) MSRCMissing(ctx context.Context, build string, ubr int) ([]MSRCFix, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT os_build,cve,fixed_ubr,COALESCE(kb,''),COALESCE(title,''),cvss,COALESCE(severity,'') FROM msrc_fix WHERE os_build=? AND fixed_ubr>? ORDER BY cve`, build, ubr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MSRCFix
	for rows.Next() {
		var f MSRCFix
		var c sql.NullFloat64
		if err := rows.Scan(&f.Build, &f.CVE, &f.FixedUBR, &f.KB, &f.Title, &c, &f.Severity); err != nil {
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

// CountMSRC returns the number of stored fixes and builds covered.
func (s *Store) CountMSRC(ctx context.Context) (fixes, builds int, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT os_build) FROM msrc_fix`).Scan(&fixes, &builds)
	return
}
