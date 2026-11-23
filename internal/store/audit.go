package store

import (
	"context"
	"database/sql"
)

// AuditSession records the outcome of a credentialed audit of one host. No
// secret is ever stored: Label is the user-chosen name of the credential set.
type AuditSession struct {
	AssetID                             int64
	Address                             string
	Transport, Label                    string
	OSFamily, OSName, OSVersion, Kernel string
	Ecosystem                           string
	Result                              string // ok | partial | failed
	Error                               string
	Packages                            int
}

type PackageRow struct {
	Name, Version, Arch, SrcName, SrcVersion, Ecosystem string
}

type ConfigResult struct {
	CheckID, Result, Evidence string
}

// SaveAudit stores a host's audit session, package inventory and hardening
// results in one transaction. Re-running replaces the previous data for the
// scan and host.
func (s *Store) SaveAudit(ctx context.Context, scanID int64, a AuditSession, pkgs []PackageRow, cfg []ConfigResult) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{`DELETE FROM package WHERE scan_id=? AND asset_id=?`, `DELETE FROM config_check_result WHERE scan_id=? AND asset_id=?`,
			`DELETE FROM audit_session WHERE scan_id=? AND asset_id=?`} {
			if _, err := tx.Exec(q, scanID, a.AssetID); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`INSERT INTO audit_session(scan_id,asset_id,transport,os_family,os_name,os_version,kernel,ecosystem,result,error)
			VALUES(?,?,?,?,?,?,?,?,?,?)`, scanID, a.AssetID, orDefault(a.Transport, "ssh"), a.OSFamily, a.OSName, a.OSVersion, a.Kernel, a.Ecosystem, a.Result, truncate(a.Error, 500)); err != nil {
			return err
		}
		st, err := tx.Prepare(`INSERT OR IGNORE INTO package(scan_id,asset_id,name,version,arch,source_name,source_version,ecosystem) VALUES(?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, p := range pkgs {
			if _, err := st.Exec(scanID, a.AssetID, p.Name, p.Version, p.Arch, p.SrcName, p.SrcVersion, p.Ecosystem); err != nil {
				return err
			}
		}
		for _, c := range cfg {
			if _, err := tx.Exec(`INSERT INTO config_check_result(scan_id,asset_id,check_id,result,evidence) VALUES(?,?,?,?,?)`,
				scanID, a.AssetID, c.CheckID, c.Result, truncate(c.Evidence, 2000)); err != nil {
				return err
			}
		}
		return nil
	})
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// AuditSessions lists credentialed audit outcomes for a scan, with package counts.
func (s *Store) AuditSessions(ctx context.Context, scanID int64) ([]AuditSession, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT a.address, au.asset_id, COALESCE(au.os_name,''), COALESCE(au.os_version,''), COALESCE(au.kernel,''),
		COALESCE(au.ecosystem,''), au.result, COALESCE(au.error,''),
		(SELECT COUNT(*) FROM package p WHERE p.scan_id=au.scan_id AND p.asset_id=au.asset_id)
		FROM audit_session au JOIN asset a ON a.id=au.asset_id WHERE au.scan_id=? ORDER BY a.address`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditSession
	for rows.Next() {
		var x AuditSession
		x.Transport = "ssh"
		if err := rows.Scan(&x.Address, &x.AssetID, &x.OSName, &x.OSVersion, &x.Kernel, &x.Ecosystem, &x.Result, &x.Error, &x.Packages); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// RemoveFromScan hides findings from one scan by dropping their occurrence
// rows. The finding rows and history in other scans are untouched. Used when a
// credentialed audit proves an unauthenticated guess wrong (e.g. a banner
// version that the distribution has patched).
func (s *Store) RemoveFromScan(ctx context.Context, scanID int64, findingIDs []int64) error {
	if len(findingIDs) == 0 {
		return nil
	}
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		for _, id := range findingIDs {
			if _, err := tx.Exec(`DELETE FROM finding_occurrence WHERE scan_id=? AND finding_id=?`, scanID, id); err != nil {
				return err
			}
		}
		return nil
	})
}
