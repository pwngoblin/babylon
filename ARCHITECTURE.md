# Babylon — Architecture

Status: **draft v0.5**. Language: Go. Strategy: *a Nessus-style product layer (policy, orchestration, correlation, reporting) over open, freely redistributable detection sources, designed to maximize findings per host without destructive checks.* No dependency on the Greenbone Community Feed or Tenable content. Items tagged `[VERIFY]` are confirmed in the Phase 0 spike.

## 1. Detection strategy (no Greenbone)

Nessus/OpenVAS get coverage from a huge plugin library. Without that feed, Babylon gets coverage by **stacking seven independent, open sources** and correlating them. Each is an adapter behind one `Engine` interface.

| # | Source | Covers | Licence / cost |
|---|---|---|---|
| 1 | **Nmap** + safe NSE (`safe`, `default`, selected `vuln`; never `intrusive`, `dos`, `exploit`, `brute`) | Discovery, service/version fingerprinting, TLS, many protocol misconfigs | NPSL, run as subprocess |
| 2 | **Nuclei + nuclei-templates** (~10k: CVEs, exposures, misconfigs, tech detection, network/DNS/SSL protocols) | Web and network CVEs, admin panels, exposed services, default-credential templates (opt-in) | MIT |
| 3 | **CPE→CVE matcher** over cached NVD + cvelistV5 (CNA ranges) + CISA Vulnrichment, plus a **KEV watch** (product-level match against KEV when no version range exists) | Version-based "service X.Y is affected by CVE-…" for everything Nmap fingerprints; broadest, lowest-confidence | public domain / CC0 |
| 4 | **Babylon native checks** (YAML + Go): SSH weak algos/keys, TLS (protocol, cipher, cert, expiry, chain), SMB signing/SMBv1, SNMP default communities, anonymous FTP/NFS/SMB, unauthenticated Redis/Mongo/Elastic/Memcached/etcd/Docker API, DNS/NTP misconfig, HTTP security headers, mail relay | Misconfiguration class that CVE feeds miss | ours |
| 5 | **Credentialed collectors** (SSH, WinRM) + **OSV.dev** distro ecosystems (Debian, Ubuntu, Alpine, Red Hat/Alma/Rocky, plus language ecosystems), **MSRC** CSAF (Windows), **Apple security releases** (macOS) | Authoritative, backport-aware missing-patch detection | CC0/CC-BY/open |
| 6 | **Trivy/Grype-style filesystem and image scanning** (optional subprocess, Apache-2.0) | Containers, language lockfiles, SBOM-based checks | Apache-2.0 |
| 7 | **Enrichment**: CISA KEV, EPSS, ExploitDB/Metasploit-module *metadata* (an "exploit exists" flag; we never run exploits) | Prioritization | open |

**Excluded by decision (licence):** the Greenbone/OpenVAS feed and scanner, and any Tenable/Nessus content. No adapter, opt-in or otherwise. The Nmap `vulners` NSE script is also excluded (online API, breaks offline-first).

**Honest coverage claim:** without a NASL-class library, unauthenticated depth will trail Nessus/OpenVAS. Coverage is recovered by (a) credentialed audits, where most real-world vulnerabilities are found; (b) CPE matching to cast a wide net with explicit confidence; (c) our native misconfig library; (d) fast template updates via Nuclei. Coverage is tracked against a lab manifest every release (§12).

## 2. Principles

1. **Coverage first, safety enforced** by construction.
2. **Engines behind adapters**; all output → one normalized `Finding`.
3. **Confidence is explicit**: `confirmed` (verified by probe or authoritative advisory), `firm` (version + distro advisory), `tentative` (banner/CPE-only match). Tentative findings are shown but separated in reports.
4. **Local-first**: after `update-feeds`, scans need no outside network.
5. **No container required**: Babylon is a Go binary plus `nmap` (+ optional `nuclei`, `trivy`) on PATH. Linux and macOS first-class.
6. **Scale to 500+ hosts**: jobs, chunks, bounded pools, resume.
7. **Remote-capable**: the runner interface permits scan agents on other networks later.
8. **Subprocesses and targets are untrusted**: timeouts, caps, structured errors, no shell.

## 3. Pipeline

```
 targets + template + creds
        │
        ▼
 ┌──────────────┐ chunks ┌────────────────────────────┐
 │ 1. Policy    │───────▶│ 2. Discovery (Nmap)        │──▶ assets, services, TLS, OS, CPEs
 │ scope, safety│        │ sweep → ports/-sV → NSE    │
 │ limits,creds │        └─────────────┬──────────────┘
 └──────────────┘                      │
          ┌─────────────┬──────────────┼───────────────┬────────────────┐
          ▼             ▼              ▼               ▼                ▼
   ┌──────────┐  ┌────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
   │ 3a Nuclei│  │ 3b Native  │ │ 3c CPE→CVE  │ │ 3d Cred.    │ │ 3e Trivy    │
   │ templates│  │ checks     │ │ (NVD cache) │ │ audit OSV/  │ │ images/deps │
   │          │  │ YAML + Go  │ │ tentative   │ │ MSRC/Apple  │ │ (optional)  │
   └────┬─────┘  └─────┬──────┘ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
        └──────────────┴───────┬───────┴───────────────┴───────────────┘
                               ▼
        ┌─────────────────────────────────────────────┐
        │ 4. Correlate · cross-engine dedupe · enrich │
        │    (KEV/EPSS/exploit-exists) · root-cause   │
        │    group · prioritize · diff                │
        └───────────────────┬─────────────────────────┘
                            ▼
              HTML · Markdown · JSON · CSV · PDF · .nessus export
```

Stage 3 engines are independent and run in parallel per chunk; stage 3d runs only for hosts with credentials.

## 4. Scaling model (500+ hosts)

- `scan_job(scan_id, stage, engine, chunk_key, targets, state, attempts, worker, error)`; resume re-queues non-`done` jobs.
- Chunking: sweep ~1024 hosts; portscan/NSE ~128–256 live hosts; Nuclei via target file batches; native checks per service; credentialed audits one job per host.
- Worker pools per resource class (nmap, nuclei, native probes, SSH/WinRM); global and per-subnet rate limits.
- **Single DB writer** goroutine, batched transactions, SQLite WAL; streaming parsers (Nmap XML tokens, JSONL).
- Raw outputs on disk per job; DB references them.
- `Runner` interface: `LocalRunner` in v1; remote agent runner later (schema already has `worker`, `attempts`).
- Reports are remediation-first with collapsible per-host sections.

## 5. Repository layout

```
babylon/
├── go.mod
├── README.md  PRODUCT.md  ARCHITECTURE.md  CLAUDE.md
├── cmd/babylon/main.go
├── deploy/lab/                          # vulnerable targets (docker-compose) for E2E + coverage manifest
├── internal/
│   ├── cli/                             # scan, update-feeds, report, diff, history, doctor, creds
│   ├── config/  model/  errors/
│   ├── policy/
│   │   ├── templates.go                 # 4 Nessus-style templates → per-engine config
│   │   ├── safety.go                    # allow/deny tables for NSE categories, Nuclei tags, native checks
│   │   ├── targets.go  limits.go        # scope + public-range guard, rate limiters
│   │   └── creds.go                     # encrypted store, CIDR/tag mapping
│   ├── runner/                          # exec, orchestrator, pools, Runner interface
│   ├── engines/
│   │   ├── engine.go                    # Engine interface
│   │   ├── nmap/                        # argv, streaming XML, NSE allowlist, TLS interpretation
│   │   ├── nuclei/                      # tech→tag, JSONL, redaction
│   │   ├── cpematch/                    # CPE normalization, NVD range matching, confidence rules
│   │   ├── native/                      # check framework + built-in checks (+ YAML loader)
│   │   └── trivy/                       # optional subprocess adapter
│   ├── audit/
│   │   ├── collector.go                 # Collector interface
│   │   ├── ssh/  winrm/                 # allowlisted, read-only
│   │   ├── match/                       # osv.go  msrc.go  apple.go
│   │   └── hardening/                   # declarative packs: linux, macos, windows
│   ├── intel/
│   │   ├── feeds.go                     # update-feeds orchestrator, atomic swaps
│   │   ├── nvd.go  vulnrichment.go  kev.go  epss.go  exploitdb.go
│   │   ├── osv.go  msrc.go  apple.go  nucleitemplates.go
│   │   └── cvss.go
│   ├── correlate/                       # normalize, fingerprint, dedupe, group, score, diff
│   ├── report/                          # model, md, json, html (embed.FS)
│   └── store/                           # sqlite, migrations, queries
└── testdata/
```

**Deps:** `cobra`, `modernc.org/sqlite`, `x/crypto/ssh`, `masterzen/winrm`, `google/osv-scalibr` (version comparators/extractors), `BurntSushi/toml`, `age` (creds), stdlib `html/template`, `encoding/xml`, `log/slog`.

## 6. Key components

### 6.1 Policy and safety (non-destructive by construction)
- **Allowlist model**: each engine adapter receives configuration built *only* from allowlists in `policy/safety.go`; there is no code path that passes a user string into an argv.
  - Nmap NSE: categories `default`, `safe`, plus a curated `vuln` subset; denied: `intrusive`, `dos`, `exploit`, `brute`, `fuzzer`, `malware`.
  - Nuclei: tags allowlist per template; denied: `dos`, `fuzz`, `intrusive`, `bruteforce`, `headless`, `code`; `default-login` only with `--check-default-creds`.
  - Native checks declare `safety: read-only|probe|intrusive`; `intrusive` is not loadable.
  - Opt-ins: `--allow-active` (Full template, probe-level checks), `--check-default-creds`.
- **Test invariant:** generate configs for every template × flag combination and assert no denied tag/script/check is present.
- Fragile-asset flag → discovery-only; global and per-subnet rate caps; scan windows.
- Public-range guard: refuse non-private targets without `--i-have-authorization`; scope + operator logged.

### 6.2 Discovery (Nmap)
Sweep (`-sn`: ARP/ICMP/TCP), `-sV --version-light`, optional `-O`, `ssl-cert`/`ssl-enum-ciphers`, allowlisted NSE. Streaming XML. Produces live hosts, per-host ports, OS family and CPEs, which feed every later engine so nothing re-scans. Runs with sudo if available; otherwise connect-scan fallback with a coverage warning.

**Implementation notes (step 3).** `ssl-cert` and `ssl-enum-ciphers` are allowlisted *by name*: Nmap tags the latter `intrusive` (handshake volume, not impact), so the category denylist would otherwise silently drop TLS auditing. Each named script needs a written justification in `policy/safety.go`. UDP scanning is not implemented yet (needs raw sockets; planned as its own stage). Nmap XML passes through a sanitizer before parsing: hostile banners can embed illegal character references that make Go's strict XML decoder reject the whole document, which would let a malicious service blind the scanner (covered by a test that fails without the sanitizer). Nmap runs unprivileged by default (connect scans); `--sudo` uses `sudo -n` and `--sudo` failures are reported before any scan row is created.

### 6.3 Nuclei
Targets from service rows (URLs for HTTP(S), `host:port` for network protocols). Tech→tag mapping ∩ allowlist; pinned template commit; `-duc`, `-jsonl`, `-rl`, `-c`, `-timeout`. Evidence size-capped, secrets redacted.

### 6.4 CPE→CVE matcher (breadth engine)
- Normalize Nmap `product/version/CPE` and Nuclei tech detections to CPE 2.3.
- Match against cached NVD CPE match criteria (version ranges) plus CISA Vulnrichment CPE enrichment.
- Confidence rules: exact CPE + version in range → `tentative` (banners lie, distros backport). Confidence upgrades to `firm` when a credentialed audit shows the package unpatched, or to `confirmed` when a Nuclei/native probe verifies. Downgrades/suppresses when a credentialed audit shows the distro-fixed package is installed.
- Known high-noise products have per-product suppression/override rules.
- Reports separate "Confirmed/Firm" from "Possible (version-based)".

### 6.5 Native checks
Go interface `Check{ID, Safety, AppliesTo(Service), Run(ctx, Env)}`; `Env` exposes only read-only primitives (dial, banner, TLS handshake, SMB negotiate, SNMP get, HTTP GET/HEAD). Declarative YAML for simple matchers. Third-party extension is YAML-only (no in-process external code).

### 6.6 Credentialed audit (Linux, macOS, Windows)
```go
type Collector interface { Connect(ctx, Target, Creds) (Session, error); Collect(ctx, Session) (Inventory, error) }
type Matcher   interface { Applies(Inventory) bool; Match(ctx, Inventory) ([]RawFinding, error) }
```
| OS | Transport | Inventory (read-only) | Intel |
|---|---|---|---|
| Debian/Ubuntu | SSH | `dpkg-query`, os-release, kernel | OSV Debian/Ubuntu; source-package match; dpkg ordering |
| RHEL family | SSH | `rpm -qa --qf`, os-release | OSV Red Hat/Alma/Rocky; RPM EVR ordering |
| Alpine/containers | SSH / image tar | `apk info -v`; image layers | OSV Alpine; Trivy for images |
| macOS | SSH | `sw_vers`, `softwareupdate --history`, `brew list --versions` | Brew via OSV; OS version via Apple releases (HTML scraper + fixtures) |
| Windows | WinRM (HTTPS) | allowlisted PowerShell: build+UBR, hotfixes, installed software, Defender/firewall | MSRC CSAF: build/KB supersession; software via CPE matcher |

Rules: exact command/script allowlist; host-key verification; no sudo by default (optional allowlisted sudo per host tag); never compare upstream semver to distro-patched builds (ecosystem-native ordering + advisory `fixed` event are authoritative). Language-ecosystem dependency inspection (lockfiles on host) through osv-scalibr extractors. Hardening packs per OS (SSH daemon, firewall, perms, password policy; SMB signing, RDP NLA, Defender, lockout policy, etc.).

### 6.7 Correlation
- **Identity** = (asset, port/proto or package/KB, CVE set or check ID). Engine IDs are evidence, not identity.
- **Cross-engine dedupe**: same CVE+target from several engines → one finding, multiple occurrences; agreement raises confidence.
- **Root-cause grouping** → `remediation` ("Upgrade openssl A → B: 24 CVEs, 1 KEV").
- **Priority**: KEV → EPSS → CVSS → exploit-exists → asset criticality (one file, documented in report appendix).
- **Diff**: occurrence-set comparison; *resolved* only if the producing job completed for that asset.

**Finding identity must stay stable.** A finding's fingerprint is `hash(asset, port/proto, CVE set | canonical check key)`. The canonical-key table (`correlate.CheckKey`) merges the same non-CVE issue reported by different engines (e.g. native `redis-unauth` and Nuclei `exposed-redis`). Changing a key changes identity, so history diffs would show the old finding as resolved and the new one as new (this happened once during development, before any release). After the first release, key changes need a migration that rewrites stored fingerprints.

### 6.8 Reporting (clients/management)
One `ReportModel` → HTML (self-contained via `embed.FS`, auto-escaped, print-friendly), Markdown, JSON (versioned). Executive summary first (posture, KEV count, top remediations, coverage, trend), branding config, then technical detail with confidence-separated sections. Coverage section lists per-host: ports scanned, engines run, credentialed login status, jobs failed. Phase 3: `.nessus` v2 and generic import/export.

### 6.9 Feeds
`babylon update-feeds [--only …]`: NVD (CVE + CPE match data), CISA Vulnrichment, KEV, EPSS, ExploitDB index, OSV (selected ecosystems), MSRC, Apple releases, nuclei-templates (pinned), Trivy DB (if enabled). `feed_state` per source; atomic swap; staleness warnings. NVD is fetched via its bulk/API with throttling `[VERIFY: current NVD bulk mechanism & API key limits]`.

## 7. SQLite schema (v1)

Conventions: integer PKs, UTC ISO-8601, JSON in `TEXT` with `json_valid`, `foreign_keys=ON`, WAL.

```sql
-- ===== Scans & jobs =====
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
  stage TEXT NOT NULL,                  -- sweep|portscan|nse|nuclei|native|cpematch|audit|trivy|correlate
  engine TEXT,
  chunk_key TEXT NOT NULL,
  targets_json TEXT NOT NULL CHECK(json_valid(targets_json)),
  state TEXT NOT NULL CHECK(state IN ('queued','running','done','failed','skipped')),
  attempts INTEGER NOT NULL DEFAULT 0, worker TEXT,
  started_at TEXT, finished_at TEXT, error TEXT, raw_dir TEXT,
  not_before TEXT,                      -- retry backoff (migration 0002)
  UNIQUE(scan_id, stage, chunk_key)
);

-- migration 0002: a stage is planned once; planning is idempotent so resume never duplicates jobs
CREATE TABLE scan_stage (
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  stage TEXT NOT NULL, planned_at TEXT NOT NULL,
  PRIMARY KEY(scan_id, stage)
);
CREATE INDEX idx_job_claim ON scan_job(scan_id, state, stage);

-- ===== Assets & observations =====
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
  auth_status TEXT,                     -- none|ok|failed|partial
  auth_detail TEXT,
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

-- ===== Authenticated inventory =====
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

-- ===== Findings =====
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

CREATE TABLE finding_cve (finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
                          cve_id TEXT NOT NULL, PRIMARY KEY(finding_id, cve_id));

CREATE TABLE remediation (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES asset(id),
  kind TEXT NOT NULL,                   -- package_upgrade|os_patch|service_upgrade|config_change|mitigation
  subject TEXT NOT NULL, from_version TEXT, to_version TEXT, summary TEXT NOT NULL,
  cve_count INTEGER NOT NULL DEFAULT 0, max_cvss REAL,
  kev INTEGER NOT NULL DEFAULT 0, priority REAL NOT NULL DEFAULT 0
);

CREATE TABLE finding_occurrence (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL REFERENCES finding(id),
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  engine TEXT NOT NULL,                 -- nmap|nuclei|native|cpematch|audit|trivy
  engine_ref TEXT,                      -- template id / check id / advisory id
  remediation_id INTEGER REFERENCES remediation(id),
  evidence TEXT, raw_ref TEXT,
  UNIQUE(finding_id, scan_id, engine, engine_ref)
);
CREATE INDEX idx_occ_scan ON finding_occurrence(scan_id);

-- ===== Cached intel =====
CREATE TABLE feed_state (name TEXT PRIMARY KEY, version TEXT, fetched_at TEXT NOT NULL, record_count INTEGER);

CREATE TABLE cve (cve_id TEXT PRIMARY KEY, published TEXT, modified TEXT, description TEXT,
                  cvss_v3 REAL, cvss_v3_vector TEXT, cvss_v4 REAL, cwe TEXT, vuln_status TEXT);
CREATE TABLE cpe_match (                 -- version ranges from NVD / cvelistV5 / Vulnrichment
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL DEFAULT 'nvd',     -- nvd|cvelist|vulnrichment; NVD preferred when both exist
  cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  vendor TEXT NOT NULL, product TEXT NOT NULL, target_sw TEXT,
  version_exact TEXT, v_start_incl TEXT, v_start_excl TEXT, v_end_incl TEXT, v_end_excl TEXT,
  vulnerable INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_cpe_vp ON cpe_match(vendor, product);

CREATE TABLE kev (cve_id TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT,
                  date_added TEXT, due_date TEXT, ransomware_use TEXT, notes TEXT);
CREATE TABLE epss (cve_id TEXT PRIMARY KEY, score REAL NOT NULL, percentile REAL NOT NULL, as_of TEXT NOT NULL);
CREATE TABLE exploit_ref (cve_id TEXT NOT NULL, source TEXT NOT NULL, ref TEXT NOT NULL,   -- exploitdb|metasploit
                          PRIMARY KEY(cve_id, source, ref));

CREATE TABLE osv_advisory (id TEXT PRIMARY KEY, modified TEXT, summary TEXT, details TEXT, severity_json TEXT, raw_json TEXT);
CREATE TABLE osv_alias (id TEXT NOT NULL REFERENCES osv_advisory(id) ON DELETE CASCADE, alias TEXT NOT NULL, PRIMARY KEY(id, alias));
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
CREATE TABLE apple_release (release_name TEXT NOT NULL, os_version_fixed TEXT NOT NULL, product TEXT NOT NULL,
  cve_id TEXT NOT NULL, component TEXT, release_date TEXT, PRIMARY KEY(release_name, product, cve_id));
```

Raw engine output is on disk; credentials are never stored in the DB.

## 8. Security

- **Credentials**: age-encrypted creds file / OS keychain / ssh-agent, mapped by CIDR/tag; never in DB, logs or reports; redaction on all evidence. WinRM over HTTPS with cert validation.
- **Least privilege**: Babylon runs unprivileged; sudo only for the nmap subprocess; no daemon, no listening ports.
- **Audit log**: operator, scope, template, safety flags, tool and feed versions per scan.
- **Untrusted input**: banners/HTTP bodies/XML are attacker-influenced → escaped in reports, XML parsed without entities, evidence capped.
- **Supply chain**: Nuclei templates pinned by commit; feeds verified by checksum/signature where provided; `govulncheck` in CI.
- **Report confidentiality**: classification marking, DB and report files mode 0600, optional encrypted bundle.

## 9. Lifecycle & errors

| Situation | Behavior |
|---|---|
| Tool missing / too old | Fail fast with `babylon doctor` hint; scan runs with remaining engines and is marked `partial` if the template needs the missing one |
| Feed stale/missing | Warn (configurable hard-fail); feed age in report |
| Job timeout/crash | Retry with backoff; independent jobs continue |
| Host unreachable / auth fail | Recorded in `host_observation`; always shown in coverage |
| Ctrl-C | Cancel contexts, kill process groups, mark `cancelled`, keep data |
| Resume | `babylon scan --resume <id>` |

## 10. Implementation plan

> Status (2026-11-23): see `docs/roadmap/STATUS.md`. Built: phase 1, Linux credentialed audits, Windows WinRM + MSRC audit (not yet run on a real host), UDP stage, ~30 native checks, active API probes, cvelistV5 feed, KEV watch, timing profiles, scope allow-list, scheduler, `.nessus` export, Linux hardening baseline. Exploit availability tags (Exploit-DB, Metasploit metadata) built. Not built: macOS audit, `.nessus` import. Web-app scanning is out of scope (separate project); remote agents dropped. Also note the credentials section below describes the target design; today credentials come from env vars per scan and are never stored.

**Phase 0: Spike (≈1 week), de-risk coverage**
- Build a lab (Metasploitable-class, DVWA, several unpatched distro VMs/containers) with an **expected-findings manifest**.
- Measure what Nmap NSE + Nuclei + CPE matcher find vs. the manifest; measure CPE-match false-positive rate; confirm NVD bulk ingest `[VERIFY]` and Apple/MSRC feasibility. Output `docs/coverage-spike.md` with baseline numbers and go/no-go on each source.
- Skeleton: module, CLI, config, migrations, exec runner, `doctor`.

**Phase 1: MVP (unauthenticated end-to-end)**
1. Policy: targets, scope guard, `safety.go` + invariant tests, templates.
2. Orchestrator, job table, pools, single writer.
3. Nmap engine + ingest. 4. Nuclei adapter. 5. Native check framework + first 15–20 checks.
6. Feeds: NVD, KEV, EPSS, nuclei-templates, ExploitDB index. 7. CPE→CVE matcher with confidence rules.
8. Correlator (cross-engine dedupe, priority). 9. HTML/MD/JSON reports with exec summary + branding.
Exit: lab run meets coverage target; synthetic 500+ host run resumes after kill; safety invariants pass.

**Phase 2: Credentialed (highest coverage yield)**
- 2a creds store + SSH collector + OSV (Debian/Ubuntu, RHEL family) + root-cause grouping + hardening (Linux).
- 2b diff/trend; Alpine + containers (Trivy); language lockfiles.
- 2c macOS collector + Brew/OSV + Apple matcher + hardening.
- 2d Windows WinRM + MSRC + hardening.
- Credentialed results suppress/upgrade CPE-based tentative findings.

**Phase 3: Breadth**
More native checks (target 100+), `.nessus` import/export, remote agent runner, scheduling/UI, YAML plugin SDK docs, CIS-lite packs.

## 11. Testing

- Safety invariants: every template × flag combo → no denied NSE category/Nuclei tag/check.
- Golden-file parsers (nmap XML, nuclei JSONL, OSV/MSRC/Apple/NVD).
- Matcher tables: Debian `+deb12uN`, RHEL backports, Alpine `-rN`, Windows UBR/KB, macOS point releases; CPE range edge cases.
- Lab E2E with expected-findings manifest (coverage % and false-positive % tracked per release).
- Scale: fake-tool runs at 1k–5k hosts; memory ceiling, resume, no lost writes.
- Runner tests with fake binaries (hang, flood, crash mid-stream).
- HTML hostile-input tests.

## 12. Risks

| Risk | Mitigation |
|---|---|
| **Unauthenticated depth below Nessus/OpenVAS** | Credentialed audits as the main coverage lever; CPE breadth with confidence; native misconfig library; measured on manifest |
| CPE→CVE false positives (banners, backports) | Confidence tiers, separate report section, credentialed suppression, per-product rules |
| NVD ingestion volume/rate limits | Bulk files/incremental by `modified`, API key support, per-vendor indexing |
| Apple/MSRC intel quality | Dedicated spikes; fixtures; confidence `firm` not `confirmed` |
| Scanning breaks fragile hosts | Allowlist safety, rate limits, fragile flag, opt-ins |
| SQLite write contention at scale | Single writer, batching, WAL |
| Nmap needs root | sudo path, fallback with warning |
| Scope creep | Phase gates; engines are independent adapters |
