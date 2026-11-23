package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"babylon/internal/model"
)

// IngestHost records one host observation (asset, host state, services, TLS)
// for a scan in a single transaction. It is idempotent: re-ingesting the same
// host for the same scan (job retry/resume) updates rows instead of duplicating.
func (s *Store) IngestHost(ctx context.Context, scanID int64, h model.Host) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		now := ts(time.Now())
		names, _ := json.Marshal(nonNil(h.Hostnames))
		var osName, osFamily, osCPE any
		if h.OS != nil {
			osName, osFamily, osCPE = nullable(h.OS.Name), nullable(h.OS.Family), nullable(h.OS.CPE)
		}
		// COALESCE keeps richer data from earlier stages (e.g. the port scan's OS
		// guess is not erased by a later sweep that has none).
		if _, err := tx.Exec(`INSERT INTO asset(address,hostnames,mac,vendor,os_family,os_name,os_cpe,first_seen,last_seen)
			VALUES(?,?,?,?,?,?,?,?,?)
			ON CONFLICT(address) DO UPDATE SET
			  hostnames = CASE WHEN excluded.hostnames='[]' THEN asset.hostnames ELSE excluded.hostnames END,
			  mac       = COALESCE(excluded.mac, asset.mac),
			  vendor    = COALESCE(excluded.vendor, asset.vendor),
			  os_family = COALESCE(excluded.os_family, asset.os_family),
			  os_name   = COALESCE(excluded.os_name, asset.os_name),
			  os_cpe    = COALESCE(excluded.os_cpe, asset.os_cpe),
			  last_seen = excluded.last_seen`,
			h.Address, string(names), nullable(h.MAC), nullable(h.Vendor), osFamily, osName, osCPE, now, now); err != nil {
			return err
		}
		var assetID int64
		if err := tx.QueryRow(`SELECT id FROM asset WHERE address=?`, h.Address).Scan(&assetID); err != nil {
			return err
		}
		state := h.State
		if state == "" {
			state = "up"
		}
		if _, err := tx.Exec(`INSERT INTO host_observation(scan_id,asset_id,state,reason) VALUES(?,?,?,?)
			ON CONFLICT(scan_id,asset_id) DO UPDATE SET state=excluded.state, reason=COALESCE(excluded.reason, host_observation.reason)`,
			scanID, assetID, state, nullable(h.Reason)); err != nil {
			return err
		}
		for _, p := range h.Ports {
			cpes, _ := json.Marshal(nonNil(p.Service.CPEs))
			if _, err := tx.Exec(`INSERT INTO service(scan_id,asset_id,port,proto,state,name,product,version,extrainfo,tunnel,cpes,banner)
				VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
				ON CONFLICT(scan_id,asset_id,port,proto) DO UPDATE SET
				  state=excluded.state, name=excluded.name, product=excluded.product, version=excluded.version,
				  extrainfo=excluded.extrainfo, tunnel=excluded.tunnel, cpes=excluded.cpes, banner=excluded.banner`,
				scanID, assetID, p.Number, p.Proto, p.State, nullable(p.Service.Name), nullable(p.Service.Product),
				nullable(p.Service.Version), nullable(p.Service.ExtraInfo), nullable(p.Service.Tunnel), string(cpes),
				nullable(p.Service.Banner)); err != nil {
				return err
			}
			for _, sc := range p.Scripts {
				if sc.ID == "" || sc.Output == "" {
					continue
				}
				out := sc.Output
				if len(out) > 8192 {
					out = out[:8192]
				}
				vb, _ := json.Marshal(out)
				if _, err := tx.Exec(`INSERT INTO kb(scan_id,asset_id,key,value_json,source) VALUES(?,?,?,?,'nmap')
					ON CONFLICT(scan_id,asset_id,key) DO UPDATE SET value_json=excluded.value_json`,
					scanID, assetID, ScriptKey(p.Number, p.Proto, sc.ID), string(vb)); err != nil {
					return err
				}
			}
			if p.TLS == nil {
				continue
			}
			var svcID int64
			if err := tx.QueryRow(`SELECT id FROM service WHERE scan_id=? AND asset_id=? AND port=? AND proto=?`,
				scanID, assetID, p.Number, p.Proto).Scan(&svcID); err != nil {
				return err
			}
			protos, _ := json.Marshal(nonNilP(p.TLS.Protocols))
			weak, _ := json.Marshal(nonNil(p.TLS.Weak))
			sans := ""
			if len(p.TLS.SANs) > 0 {
				b, _ := json.Marshal(p.TLS.SANs)
				sans = string(b)
			}
			if _, err := tx.Exec(`INSERT INTO tls_info(service_id,subject,issuer,not_before,not_after,sig_algo,key_type,key_bits,sans,protocols_json,weak_json)
				VALUES(?,?,?,?,?,?,?,?,?,?,?)
				ON CONFLICT(service_id) DO UPDATE SET
				  subject=excluded.subject, issuer=excluded.issuer, not_before=excluded.not_before, not_after=excluded.not_after,
				  sig_algo=excluded.sig_algo, key_type=excluded.key_type, key_bits=excluded.key_bits, sans=excluded.sans,
				  protocols_json=excluded.protocols_json, weak_json=excluded.weak_json`,
				svcID, nullable(p.TLS.Subject), nullable(p.TLS.Issuer), nullable(p.TLS.NotBefore), nullable(p.TLS.NotAfter),
				nullable(p.TLS.SigAlgo), nullable(p.TLS.KeyType), p.TLS.KeyBits, nullable(sans), string(protos), string(weak)); err != nil {
				return err
			}
		}
		return nil
	})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilP(s []model.TLSProtocol) []model.TLSProtocol {
	if s == nil {
		return []model.TLSProtocol{}
	}
	return s
}

// LiveHosts returns addresses observed `up` in a scan, in stable order.
func (s *Store) LiveHosts(ctx context.Context, scanID int64) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT a.address FROM host_observation o JOIN asset a ON a.id=o.asset_id
		WHERE o.scan_id=? AND o.state='up' ORDER BY a.id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ServiceRow is a flattened service for display and reporting.
type ServiceRow struct {
	Address string
	OS      string
	Port    int
	Proto   string
	State   string
	Name    string
	Product string
	Version string
	TLSWeak []string
}

// ListServices returns open services recorded in a scan, ordered by host then port.
func (s *Store) ListServices(ctx context.Context, scanID int64) ([]ServiceRow, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT a.address, COALESCE(a.os_name,''), v.port, v.proto, v.state,
		COALESCE(v.name,''), COALESCE(v.product,''), COALESCE(v.version,''), COALESCE(t.weak_json,'[]')
		FROM service v JOIN asset a ON a.id=v.asset_id LEFT JOIN tls_info t ON t.service_id=v.id
		WHERE v.scan_id=? ORDER BY a.id, v.proto, v.port`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceRow
	for rows.Next() {
		var r ServiceRow
		var weak string
		if err := rows.Scan(&r.Address, &r.OS, &r.Port, &r.Proto, &r.State, &r.Name, &r.Product, &r.Version, &weak); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(weak), &r.TLSWeak)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ServiceInfo is an open service with the details engines need to choose checks.
type ServiceInfo struct {
	AssetID int64
	Address string
	Port    int
	Proto   string
	Name    string
	Product string
	Version string
	Tunnel  string
	CPEs    []string
	Extra   string // Nmap extrainfo (often names the distribution)
	Banner  string
	OS      string // host OS as fingerprinted ("" if unknown)
}

// OpenServices returns services in state `open` for a scan, ordered by host and port.
func (s *Store) OpenServices(ctx context.Context, scanID int64) ([]ServiceInfo, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT a.id, a.address, v.port, v.proto, COALESCE(v.name,''), COALESCE(v.product,''),
		COALESCE(v.version,''), COALESCE(v.tunnel,''), v.cpes,
		COALESCE(v.extrainfo,''), COALESCE(v.banner,''), COALESCE(a.os_name,'')
		FROM service v JOIN asset a ON a.id=v.asset_id
		WHERE v.scan_id=? AND v.state='open' ORDER BY a.id, v.proto, v.port`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceInfo
	for rows.Next() {
		var si ServiceInfo
		var cpes string
		if err := rows.Scan(&si.AssetID, &si.Address, &si.Port, &si.Proto, &si.Name, &si.Product, &si.Version, &si.Tunnel, &cpes, &si.Extra, &si.Banner, &si.OS); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(cpes), &si.CPEs)
		out = append(out, si)
	}
	return out, rows.Err()
}

// MergeKBList unions values into a JSON string-list fact (e.g. detected
// technologies for a web endpoint) without losing earlier entries.
func (s *Store) MergeKBList(ctx context.Context, scanID, assetID int64, key string, values []string, source string) error {
	return s.W.Do(ctx, func(tx *sql.Tx) error {
		var cur string
		err := tx.QueryRow(`SELECT value_json FROM kb WHERE scan_id=? AND asset_id=? AND key=?`, scanID, assetID, key).Scan(&cur)
		var list []string
		if err == nil {
			_ = json.Unmarshal([]byte(cur), &list)
		} else if err != sql.ErrNoRows {
			return err
		}
		have := map[string]bool{}
		for _, v := range list {
			have[v] = true
		}
		for _, v := range values {
			if !have[v] {
				have[v] = true
				list = append(list, v)
			}
		}
		sortStrings(list)
		b, _ := json.Marshal(list)
		_, err = tx.Exec(`INSERT INTO kb(scan_id,asset_id,key,value_json,source) VALUES(?,?,?,?,?)
			ON CONFLICT(scan_id,asset_id,key) DO UPDATE SET value_json=excluded.value_json, source=excluded.source`,
			scanID, assetID, key, string(b), source)
		return err
	})
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// KBList reads a JSON string-list fact; missing keys yield nil.
func (s *Store) KBList(ctx context.Context, scanID, assetID int64, key string) ([]string, error) {
	var v string
	err := s.DB.QueryRowContext(ctx, `SELECT value_json FROM kb WHERE scan_id=? AND asset_id=? AND key=?`, scanID, assetID, key).Scan(&v)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	return out, json.Unmarshal([]byte(v), &out)
}

// ScriptKey is the knowledge-base key holding an NSE script's output.
func ScriptKey(port int, proto, script string) string {
	return fmt.Sprintf("Script/%d/%s/%s", port, proto, script)
}

// TLSRow is stored TLS information for one service.
type TLSRow struct {
	Port     int
	Proto    string
	Subject  string
	Issuer   string
	NotAfter string
	KeyType  string
	KeyBits  int
	Weak     []string
}

// TLSForAsset returns TLS details for an asset's services in a scan.
func (s *Store) TLSForAsset(ctx context.Context, scanID, assetID int64) ([]TLSRow, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT v.port, v.proto, COALESCE(t.subject,''), COALESCE(t.issuer,''), COALESCE(t.not_after,''),
		COALESCE(t.key_type,''), COALESCE(t.key_bits,0), COALESCE(t.weak_json,'[]')
		FROM tls_info t JOIN service v ON v.id=t.service_id WHERE v.scan_id=? AND v.asset_id=? ORDER BY v.port`, scanID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TLSRow
	for rows.Next() {
		var r TLSRow
		var weak string
		if err := rows.Scan(&r.Port, &r.Proto, &r.Subject, &r.Issuer, &r.NotAfter, &r.KeyType, &r.KeyBits, &weak); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(weak), &r.Weak)
		out = append(out, r)
	}
	return out, rows.Err()
}
