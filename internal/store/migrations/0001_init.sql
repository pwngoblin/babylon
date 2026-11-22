-- Babylon schema v1 (see ARCHITECTURE.md §7)

CREATE TABLE scan (
  id INTEGER PRIMARY KEY, name TEXT,
  template TEXT NOT NULL,
  targets_json TEXT NOT NULL CHECK(json_valid(targets_json)),
  options_json TEXT NOT NULL CHECK(json_valid(options_json)),
  status TEXT NOT NULL CHECK(status IN ('pending','running','completed','partial','failed','cancelled')),
  started_at TEXT, finished_at TEXT,
  tool_versions_json TEXT, feed_versions_json TEXT
);

CREATE TABLE scan_job (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  stage TEXT NOT NULL,
  engine TEXT,
  chunk_key TEXT NOT NULL,
  targets_json TEXT NOT NULL CHECK(json_valid(targets_json)),
  state TEXT NOT NULL CHECK(state IN ('queued','running','done','failed','skipped')),
  attempts INTEGER NOT NULL DEFAULT 0, worker TEXT,
  started_at TEXT, finished_at TEXT, error TEXT, raw_dir TEXT,
  UNIQUE(scan_id, stage, chunk_key)
);
CREATE INDEX idx_job_claim ON scan_job(scan_id, state, stage);

CREATE TABLE asset (
  id INTEGER PRIMARY KEY, address TEXT NOT NULL UNIQUE,
  hostnames TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(hostnames)),
  mac TEXT, vendor TEXT, os_family TEXT, os_name TEXT, os_version TEXT, os_cpe TEXT,
  criticality INTEGER NOT NULL DEFAULT 2 CHECK(criticality BETWEEN 1 AND 4),
  fragile INTEGER NOT NULL DEFAULT 0,
  tags TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(tags)),
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);

CREATE TABLE host_observation (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES asset(id),
  state TEXT NOT NULL, reason TEXT,
  auth_status TEXT, auth_detail TEXT,
  UNIQUE(scan_id, asset_id)
);

CREATE TABLE service (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES asset(id),
  port INTEGER NOT NULL, proto TEXT NOT NULL CHECK(proto IN ('tcp','udp')),
  state TEXT NOT NULL, name TEXT, product TEXT, version TEXT, extrainfo TEXT,
  tunnel TEXT, cpes TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(cpes)), banner TEXT,
  UNIQUE(scan_id, asset_id, port, proto)
);

CREATE TABLE tls_info (
  id INTEGER PRIMARY KEY,
  service_id INTEGER NOT NULL UNIQUE REFERENCES service(id) ON DELETE CASCADE,
  subject TEXT, issuer TEXT, not_before TEXT, not_after TEXT,
  sig_algo TEXT, key_type TEXT, key_bits INTEGER, sans TEXT,
  protocols_json TEXT, weak_json TEXT
);

CREATE TABLE audit_session (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES asset(id),
  transport TEXT NOT NULL CHECK(transport IN ('ssh','winrm')),
  os_family TEXT, os_name TEXT, os_version TEXT, os_build TEXT, kernel TEXT,
  ecosystem TEXT, result TEXT NOT NULL, error TEXT,
  UNIQUE(scan_id, asset_id)
);

CREATE TABLE package (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES asset(id),
  name TEXT NOT NULL, version TEXT NOT NULL, arch TEXT,
  source_name TEXT, source_version TEXT, ecosystem TEXT NOT NULL, publisher TEXT, cpe TEXT,
  UNIQUE(scan_id, asset_id, name, arch, version)
);

CREATE TABLE os_patch (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES asset(id),
  patch_id TEXT NOT NULL, description TEXT, installed_on TEXT,
  UNIQUE(scan_id, asset_id, patch_id)
);

CREATE TABLE config_check_result (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES asset(id),
  check_id TEXT NOT NULL,
  result TEXT NOT NULL CHECK(result IN ('pass','fail','unknown','error')), evidence TEXT
);

CREATE TABLE finding (
  id INTEGER PRIMARY KEY,
  fingerprint TEXT NOT NULL UNIQUE,
  asset_id INTEGER NOT NULL REFERENCES asset(id),
  port INTEGER, proto TEXT,
  title TEXT NOT NULL, family TEXT,
  severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
  cvss_score REAL, cvss_vector TEXT,
  kev INTEGER NOT NULL DEFAULT 0, epss REAL, exploit_exists INTEGER NOT NULL DEFAULT 0,
  synopsis TEXT, description TEXT, remediation TEXT,
  solution_type TEXT,
  confidence TEXT NOT NULL DEFAULT 'firm' CHECK(confidence IN ('tentative','firm','confirmed')),
  priority REAL NOT NULL DEFAULT 0,
  first_seen_scan INTEGER REFERENCES scan(id)
);
CREATE INDEX idx_finding_asset ON finding(asset_id);

CREATE TABLE finding_cve (
  finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL, PRIMARY KEY(finding_id, cve_id)
);

CREATE TABLE remediation (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES asset(id),
  kind TEXT NOT NULL,
  subject TEXT NOT NULL, from_version TEXT, to_version TEXT, summary TEXT NOT NULL,
  cve_count INTEGER NOT NULL DEFAULT 0, max_cvss REAL,
  kev INTEGER NOT NULL DEFAULT 0, priority REAL NOT NULL DEFAULT 0
);

CREATE TABLE finding_occurrence (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL REFERENCES finding(id),
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  engine TEXT NOT NULL,
  engine_ref TEXT,
  remediation_id INTEGER REFERENCES remediation(id),
  evidence TEXT, raw_ref TEXT,
  UNIQUE(finding_id, scan_id, engine, engine_ref)
);
CREATE INDEX idx_occ_scan ON finding_occurrence(scan_id);

CREATE TABLE feed_state (name TEXT PRIMARY KEY, version TEXT, fetched_at TEXT NOT NULL, record_count INTEGER);

CREATE TABLE cve (
  cve_id TEXT PRIMARY KEY, published TEXT, modified TEXT, description TEXT,
  cvss_v3 REAL, cvss_v3_vector TEXT, cvss_v4 REAL, cwe TEXT, vuln_status TEXT
);
CREATE TABLE cpe_match (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL DEFAULT 'nvd',
  -- nvd|cvelist|vulnrichment; NVD preferred when sources overlap
  cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  vendor TEXT NOT NULL, product TEXT NOT NULL, target_sw TEXT,
  version_exact TEXT, v_start_incl TEXT, v_start_excl TEXT, v_end_incl TEXT, v_end_excl TEXT,
  vulnerable INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_cpe_vp ON cpe_match(vendor, product);

CREATE TABLE kev (
  cve_id TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT,
  date_added TEXT, due_date TEXT, ransomware_use TEXT, notes TEXT
);
CREATE TABLE epss (cve_id TEXT PRIMARY KEY, score REAL NOT NULL, percentile REAL NOT NULL, as_of TEXT NOT NULL);
CREATE TABLE exploit_ref (
  cve_id TEXT NOT NULL, source TEXT NOT NULL, ref TEXT NOT NULL,
  PRIMARY KEY(cve_id, source, ref)
);

CREATE TABLE osv_advisory (id TEXT PRIMARY KEY, modified TEXT, summary TEXT, details TEXT, severity_json TEXT, raw_json TEXT);
CREATE TABLE osv_alias (
  id TEXT NOT NULL REFERENCES osv_advisory(id) ON DELETE CASCADE,
  alias TEXT NOT NULL, PRIMARY KEY(id, alias)
);
CREATE TABLE osv_affected (
  id INTEGER PRIMARY KEY,
  advisory_id TEXT NOT NULL REFERENCES osv_advisory(id) ON DELETE CASCADE,
  ecosystem TEXT NOT NULL, package TEXT NOT NULL,
  introduced TEXT, fixed TEXT, last_affected TEXT, versions_json TEXT
);
CREATE INDEX idx_osv_pkg ON osv_affected(ecosystem, package);

CREATE TABLE msrc_advisory (
  cve_id TEXT NOT NULL, product_id TEXT NOT NULL, product_name TEXT, fixed_build TEXT, kb_id TEXT,
  superseded_by TEXT, severity TEXT, cvss_score REAL, release_date TEXT,
  PRIMARY KEY(cve_id, product_id, kb_id)
);
CREATE INDEX idx_msrc_kb ON msrc_advisory(kb_id);

CREATE TABLE apple_release (
  release_name TEXT NOT NULL, os_version_fixed TEXT NOT NULL, product TEXT NOT NULL,
  cve_id TEXT NOT NULL, component TEXT, release_date TEXT,
  PRIMARY KEY(release_name, product, cve_id)
);
