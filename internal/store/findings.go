package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"babylon/internal/model"
)

// AssetID returns the id of an asset by address, creating a minimal row if the
// asset has not been seen (e.g. a finding for a host the sweep missed).
func (s *Store) AssetID(ctx context.Context, address string) (int64, error) {
	var id int64
	err := s.W.Do(ctx, func(tx *sql.Tx) error {
		var err error
		id, err = assetID(tx, address)
		return err
	})
	return id, err
}

func assetID(tx *sql.Tx, address string) (int64, error) {
	var id int64
	err := tx.QueryRow(`SELECT id FROM asset WHERE address=?`, address).Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != sql.ErrNoRows {
		return 0, err
	}
	now := ts(time.Now())
	r, err := tx.Exec(`INSERT INTO asset(address,first_seen,last_seen) VALUES(?,?,?)`, address, now, now)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

// RecordFinding stores a finding detection for a scan. Findings are global by
// fingerprint; when several engines (or repeated results from one template)
// report the same fingerprint, the finding keeps the strongest confidence and
// worst severity, CVEs are unioned, and each detection is kept as an occurrence
// with its own evidence. Idempotent for retried jobs.
func (s *Store) RecordFinding(ctx context.Context, scanID int64, f model.Finding) error {
	if f.Fingerprint == "" || f.Address == "" || f.Title == "" {
		return fmt.Errorf("finding needs fingerprint, address and title")
	}
	if f.Confidence == "" {
		f.Confidence = model.ConfFirm
	}
	if f.Detection == "" {
		f.Detection = "behaviour"
	}
	if model.SeverityRank(f.Severity) == 0 {
		f.Severity = "info"
	}
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		aid, err := assetID(tx, f.Address)
		if err != nil {
			return err
		}
		var (
			fid                      int64
			curSev, curConf, curDesc string
			curSyn, curRem, curSol   sql.NullString
			curDet                   string
			curCVSS                  sql.NullFloat64
			curVec                   sql.NullString
		)
		err = tx.QueryRow(`SELECT id,severity,confidence,COALESCE(description,''),synopsis,remediation,solution_type,cvss_score,cvss_vector,detection
			FROM finding WHERE fingerprint=?`, f.Fingerprint).Scan(&fid, &curSev, &curConf, &curDesc, &curSyn, &curRem, &curSol, &curCVSS, &curVec, &curDet)
		switch {
		case err == sql.ErrNoRows:
			r, err := tx.Exec(`INSERT INTO finding(fingerprint,asset_id,port,proto,title,family,severity,cvss_score,cvss_vector,epss,
				synopsis,description,remediation,solution_type,confidence,detection,first_seen_scan,product,version)
				VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				f.Fingerprint, aid, nullInt(f.Port), nullable(f.Proto), f.Title, nullable(f.Family), f.Severity,
				nullFloat(f.CVSS), nullable(f.CVSSVector), nullFloat(f.EPSS), nullable(f.Synopsis), nullable(f.Description),
				nullable(f.Remediation), nullable(f.Solution), f.Confidence, f.Detection, scanID, nullable(f.Product), nullable(f.Version))
			if err != nil {
				return err
			}
			if fid, err = r.LastInsertId(); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			sev, conf := curSev, curConf
			if model.SeverityRank(f.Severity) > model.SeverityRank(sev) {
				sev = f.Severity
			}
			detection := ""
			if model.ConfidenceRank(f.Confidence) > model.ConfidenceRank(conf) {
				conf, detection = f.Confidence, f.Detection
			}
			// A version-derived finding corroborated by an independent behavioural
			// check (a probe or template that saw the vulnerable behaviour) is confirmed.
			firm := model.ConfidenceRank(model.ConfFirm)
			if (curDet == "version" && f.Detection == "behaviour" && model.ConfidenceRank(f.Confidence) >= firm) ||
				(curDet == "behaviour" && f.Detection == "version" && model.ConfidenceRank(curConf) >= firm) {
				conf = model.ConfConfirmed
			}
			if f.Product != "" {
				if _, err := tx.Exec(`UPDATE finding SET product=COALESCE(product,?), version=COALESCE(version,?) WHERE id=?`, f.Product, nullable(f.Version), fid); err != nil {
					return err
				}
			}
			cvss, vec := curCVSS, curVec
			if f.CVSS != nil && (!cvss.Valid || *f.CVSS > cvss.Float64) {
				cvss, vec = sql.NullFloat64{Float64: *f.CVSS, Valid: true}, sql.NullString{String: f.CVSSVector, Valid: f.CVSSVector != ""}
			}
			keep := func(cur sql.NullString, n string) any {
				if cur.Valid && cur.String != "" {
					return cur.String
				}
				return nullable(n)
			}
			if _, err := tx.Exec(`UPDATE finding SET severity=?, confidence=?, detection=COALESCE(NULLIF(?,''),detection),
				cvss_score=?, cvss_vector=?, synopsis=?, description=?, remediation=?, solution_type=? WHERE id=?`,
				sev, conf, detection, cvss, vec, keep(curSyn, f.Synopsis),
				keep(sql.NullString{String: curDesc, Valid: curDesc != ""}, f.Description),
				keep(curRem, f.Remediation), keep(curSol, f.Solution), fid); err != nil {
				return err
			}
		}
		for _, c := range f.CVEs {
			c = strings.ToUpper(strings.TrimSpace(c))
			if c == "" {
				continue
			}
			if _, err := tx.Exec(`INSERT OR IGNORE INTO finding_cve(finding_id,cve_id) VALUES(?,?)`, fid, c); err != nil {
				return err
			}
		}
		if len(f.CVEs) > 0 { // threat-intel enrichment from the local feeds
			if _, err := tx.Exec(`UPDATE finding SET
				kev = EXISTS(SELECT 1 FROM finding_cve fc JOIN kev k ON k.cve_id=fc.cve_id WHERE fc.finding_id=finding.id),
				epss = (SELECT MAX(e.score) FROM finding_cve fc JOIN epss e ON e.cve_id=fc.cve_id WHERE fc.finding_id=finding.id),
				cvss_score = COALESCE(cvss_score, (SELECT MAX(c.cvss_v3) FROM finding_cve fc JOIN cve c ON c.cve_id=fc.cve_id WHERE fc.finding_id=finding.id))
				WHERE id=?`, fid); err != nil {
				return err
			}
		}
		_, err = tx.Exec(`INSERT INTO finding_occurrence(finding_id,scan_id,engine,engine_ref,evidence,raw_ref) VALUES(?,?,?,?,?,?)
			ON CONFLICT(finding_id,scan_id,engine,engine_ref) DO UPDATE SET
			  evidence = CASE
			    WHEN excluded.evidence IS NULL OR excluded.evidence='' THEN finding_occurrence.evidence
			    WHEN finding_occurrence.evidence IS NULL OR finding_occurrence.evidence='' THEN excluded.evidence
			    WHEN instr(finding_occurrence.evidence, excluded.evidence) > 0 THEN finding_occurrence.evidence
			    ELSE substr(finding_occurrence.evidence || char(10) || excluded.evidence, 1, 16384) END,
			  raw_ref = COALESCE(excluded.raw_ref, finding_occurrence.raw_ref)`,
			fid, scanID, f.Engine, f.EngineRef, nullable(f.Evidence), nullable(f.RawRef))
		return err
	})
}

func nullInt(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

func nullFloat(f *float64) any {
	if f == nil {
		return nil
	}
	return *f
}

// FindingRow is a finding as seen in one scan.
type FindingRow struct {
	ID          int64
	Address     string
	Port        int
	Proto       string
	Title       string
	Family      string
	Severity    string
	CVSS        *float64
	EPSS        *float64
	Product     string
	Version     string
	CVEs        []string
	KEV         bool
	Synopsis    string
	Description string
	Remediation string
	Confidence  string
	Detection   string
	Engines     []string
	Evidence    string
}

// ListFindings returns findings present in a scan, filtered to at least
// minConfidence ("" = everything is returned; nothing is ever deleted by
// filtering). Order: severity, KEV, CVSS, then host.
func (s *Store) ListFindings(ctx context.Context, scanID int64, minConfidence string) ([]FindingRow, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT f.id, a.address, COALESCE(f.port,0), COALESCE(f.proto,''), f.title, COALESCE(f.family,''),
		f.severity, f.cvss_score, f.kev, COALESCE(f.synopsis,''), COALESCE(f.description,''), COALESCE(f.remediation,''),
		f.confidence, f.detection, f.epss, COALESCE(f.product,''), COALESCE(f.version,'')
		FROM finding f JOIN asset a ON a.id=f.asset_id
		WHERE f.id IN (SELECT finding_id FROM finding_occurrence WHERE scan_id=?)`, scanID)
	if err != nil {
		return nil, err
	}
	var out []FindingRow
	for rows.Next() {
		var r FindingRow
		var cvss, epss sql.NullFloat64
		var kev int
		if err := rows.Scan(&r.ID, &r.Address, &r.Port, &r.Proto, &r.Title, &r.Family, &r.Severity, &cvss, &kev,
			&r.Synopsis, &r.Description, &r.Remediation, &r.Confidence, &r.Detection, &epss, &r.Product, &r.Version); err != nil {
			rows.Close()
			return nil, err
		}
		if cvss.Valid {
			v := cvss.Float64
			r.CVSS = &v
		}
		if epss.Valid {
			v := epss.Float64
			r.EPSS = &v
		}
		r.KEV = kev == 1
		if minConfidence == "" || model.ConfidenceRank(r.Confidence) >= model.ConfidenceRank(minConfidence) {
			out = append(out, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		cr, err := s.DB.QueryContext(ctx, `SELECT cve_id FROM finding_cve WHERE finding_id=? ORDER BY cve_id`, out[i].ID)
		if err != nil {
			return nil, err
		}
		for cr.Next() {
			var c string
			cr.Scan(&c)
			out[i].CVEs = append(out[i].CVEs, c)
		}
		cr.Close()
		or, err := s.DB.QueryContext(ctx, `SELECT engine, COALESCE(evidence,'') FROM finding_occurrence WHERE finding_id=? AND scan_id=? ORDER BY id`, out[i].ID, scanID)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		var ev []string
		for or.Next() {
			var e, evd string
			or.Scan(&e, &evd)
			if !seen[e] {
				seen[e] = true
				out[i].Engines = append(out[i].Engines, e)
			}
			if evd != "" {
				ev = append(ev, evd)
			}
		}
		or.Close()
		out[i].Evidence = strings.Join(ev, "\n")
	}
	sort.SliceStable(out, func(a, b int) bool { return PriorityLess(out[a], out[b]) })
	return out, nil
}

// SetKB records a fact about an asset for later checks (Nessus-style knowledge
// base). Values are stored as JSON.
func (s *Store) SetKB(ctx context.Context, scanID, assetID int64, key string, value any, source string) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO kb(scan_id,asset_id,key,value_json,source) VALUES(?,?,?,?,?)
			ON CONFLICT(scan_id,asset_id,key) DO UPDATE SET value_json=excluded.value_json, source=excluded.source`,
			scanID, assetID, key, string(b), source)
		return err
	})
}

// KB returns all facts for an asset in a scan.
func (s *Store) KB(ctx context.Context, scanID, assetID int64) (map[string]json.RawMessage, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT key,value_json FROM kb WHERE scan_id=? AND asset_id=?`, scanID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = json.RawMessage(v)
	}
	return out, rows.Err()
}

// RecordCheckRun notes whether a check ran, was skipped, or errored on an asset.
func (s *Store) RecordCheckRun(ctx context.Context, scanID, assetID int64, checkID, state, reason string) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO check_run(scan_id,asset_id,check_id,state,reason) VALUES(?,?,?,?,?)
			ON CONFLICT(scan_id,asset_id,check_id) DO UPDATE SET state=excluded.state, reason=excluded.reason`,
			scanID, assetID, checkID, state, nullable(reason))
		return err
	})
}

// CheckRunCounts returns state -> count for a scan (coverage summary).
func (s *Store) CheckRunCounts(ctx context.Context, scanID int64) (map[string]int, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT state,COUNT(*) FROM check_run WHERE scan_id=? GROUP BY state`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// PriorityLess orders findings for display: KEV first, then confidence,
// CVSS, EPSS; severity, host and title break ties for a stable order.
func PriorityLess(x, y FindingRow) bool {
	if x.KEV != y.KEV {
		return x.KEV
	}
	if cx, cy := model.ConfidenceRank(x.Confidence), model.ConfidenceRank(y.Confidence); cx != cy {
		return cx > cy
	}
	if vx, vy := deref(x.CVSS), deref(y.CVSS); vx != vy {
		return vx > vy
	}
	if ex, ey := deref(x.EPSS), deref(y.EPSS); ex != ey {
		return ex > ey
	}
	if sx, sy := model.SeverityRank(x.Severity), model.SeverityRank(y.Severity); sx != sy {
		return sx > sy
	}
	if x.Address != y.Address {
		return x.Address < y.Address
	}
	return x.Title < y.Title
}

func deref(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}
