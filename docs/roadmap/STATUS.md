# Roadmap status (resume file)

Last updated: 2026-11-23. Latest release **v0.1.1** (github.com/pwngoblin/babylon/releases/tag/v0.1.1). Everything below is committed on `main`. Milestones 01-04 (feeds and matcher, credentialed audits, UDP/native checks/speed, HTML/PDF reports) are all done; their spec files were removed and the outcomes are in the history section. The forward-looking plan is in [ROADMAP.md](ROADMAP.md).

## At a glance

| Area | State |
|---|---|
| Discovery, ports, services, TLS (Nmap + safe NSE) | done |
| Nuclei checks (+ `--deep`), native checks, active API probes (`--allow-active`) | done |
| CPE to CVE matching (NVD + cvelistV5, KEV, EPSS, backport-aware, web tech versions, KEV product watch) | done |
| Credentialed Linux audit over SSH (OSV, config rules) | done; RHEL family unit-tested only |
| UDP stage (17 ports, needs root) | done, unit-tested only |
| Root-cause grouping, confidence tiers, priority sort | done |
| Reports: MD, JSON, CSV, HTML, PDF | done |
| Web UI, usable without the CLI for unauthenticated scans (loopback, token, CSRF, sortable findings, compare, export) | done |
| Scope allow-list (`~/.babylon/scope.txt`) | done |
| Timing profiles (standard, fast-lan, polite) | done |
| Windows build | compiles, never run |
| Windows credentialed audit (WinRM + MSRC, 15 rules) | done; tested against a fake host only |
| Native infrastructure checks (~30: network services, SNMP, TLS, DB, Docker, Windows unauth) | done; mock-tested only |
| Linux hardening baseline (~30 rules incl. Docker) | done |
| Scheduler (`babylon serve` + Schedules page) | done |
| `.nessus` export | done (import not built) |
| Exploit availability tags (Exploit-DB, Metasploit metadata; `update-feeds --only exploitdb,metasploit`) | done; unit-tested; live feeds download and parse (33,568 Exploit-DB + 2,733 Metasploit CVE links) |
| macOS credentialed audit (patch level from Apple releases, end-of-support, 9 MAC rules) | done; settings parse checked against a real Mac, patch matching against the live Apple feed; not yet run over SSH against a Mac |
| Ground-truth lab (`babylon lab`, 28 services) | done; 19/19 measurable expectations, 0 false positives |
| CI, signed releases, SBOM | done (v0.1.1) |
| Homebrew vulnerability matching, triage, asset inventory | not built (see ROADMAP.md) |
| Web-app scanning (DAST) | out of scope, separate project |

## Added after the M01-M04 work (2026-11-23)
- Findings table sorting in the web UI (click a header: natural order, reverse, default).
- Scope allow-list: `internal/app/scope.go`. If `scope.txt` exists, targets outside it are refused; a malformed file refuses everything.
- Nuclei targets drop default ports (`http://host`, not `http://host:80`).
- UI fix: a pending scan returned `jobs: null` and crashed the page; server now sends `[]` and the page tolerates it.
- Bug fix: cancelling a scan before the orchestrator started marked it `failed`; now `cancelled` (also fixed a flaky `TestConcurrentScanLimit`).
- Quality check on the lab (127.0.0.1 only, 7 services, full_unauth + allow-active, fast-lan): 314 findings in 2m18s. Found Apache 2.4.49 (88 CVEs incl. CVE-2021-41773), OpenSSH 8.4 (39), nginx 1.16.0 (10), Redis 5.0.14 (23) + unauthenticated access, vsftpd, DVWA setup page. Misses: SQLi/XSS in DVWA and Juice Shop (no web-app mode).
- Release v0.1.0: binaries for macOS arm64/amd64, Linux amd64/arm64, Windows amd64 + SHA256SUMS. Only macOS arm64 was run.
- Not run: govulncheck, staticcheck, gosec (not installed on the dev machine).

## Infrastructure checks (2026-11-23, after v0.1.0)
All native, mock-tested, read-only. Probe-level ones need `--allow-active`.
- Network services (pushed): Consul, Docker registry, YARN, Solr, Jupyter, Kibana, Prometheus, Kubernetes API anonymous, MQTT anonymous, ZooKeeper, rsync modules.
- Windows (unauthenticated): out-of-support Windows versions from SMB (date-based), MS17-010 via `smb-vuln-ms17-010` (new allowlisted NSE script, checked against nmap categories), RDP legacy security / no NLA via `rdp-enum-encryption`, WinRM on HTTP. Native findings can now carry CVE ids. Not built: WinRM credentialed audit (no Windows lab to test against).
- SNMP: direct UDP probe (no root needed) with SNMPv2c GET of sysDescr/sysObjectID/sysName using only `public`; encoding checked against the standard capture. Skipped when Nmap's snmp-info already reported it.
- TLS: direct handshake per protocol version (1.0-1.3) plus certificate checks: deprecated versions, no modern version, expiring in 30 days, SHA-1/MD5 signature, RSA under 2048.
- Databases: MySQL/MariaDB greeting (version end-of-life by vendor lifecycle date, no TLS), PostgreSQL SSLRequest (no TLS). No logins attempted.
- Containers (credentialed SSH audit): new allowlisted `docker info`/`ps`/`inspect` command and rules DOCKER-001..005 (privileged, docker.sock mount, host namespaces/paths, dangerous capabilities, running as root). Output format verified against the real local Docker daemon. Unknown when Docker is absent or inaccessible.
- Not run live: the network-service, SNMP, TLS and DB probes were tested against mocks only (the lab has none of those services except TLS-less web).

## Nessus parity pass (2026-11-23)
- `.nessus` (NessusClientData_v2) export: CLI `--format nessus`, web "Export .nessus". Babylon plugin ids are 9,000,000+ (never real Tenable ids). Test checks well-formed XML and stripping of illegal characters. Import not built.
- Hardening baseline: 15 more Linux rules (accounts, password policy, legacy services, /tmp, permissions, network sysctl, ASLR, SSH extras, logging, time sync, automatic updates); new allowlisted read-only commands; unknown never passes. Live-checked on the Ubuntu lab container.
- Scheduler: `schedule` table (migration 6), `babylon serve` runs due scans every minute, API `/api/schedules`, "Schedules" page and a Repeat choice on New scan. Scope file and concurrency limits apply to scheduled runs. Credentialed scans cannot be scheduled.
- Windows credentialed audit (WinRM, NTLM with message encryption): `update-feeds --only msrc` downloads Microsoft bulletins (12 months by default; 12,319 fixes across 66 builds parsed from the real October 2026 file). The host's build and update revision are compared with the first fixed revision per CVE; findings group into "Missing Windows updates". 15 rules WIN-001..015 (SMBv1, signing, firewall, Defender, NLA, UAC, WDigest, LM level, Guest, password policy, admins, LLMNR, update age, end of support). Fixed read-only PowerShell allowlist enforced in code. Tested with a fake host, not a real Windows machine: the WinRM transport (`audit/winrm.go`) has never connected to one.
- Not built: `.nessus` import, macOS patch audit, per-control compliance report section.

## Exploit availability (2026-11-23)
Feeds `exploitdb` (files_exploits.csv) and `metasploit` (modules_metadata_base.json, exploit modules only) store CVE-to-exploit ids in `exploit_ref` (migration 8; table existed from 0001). Findings carry `exploit_sources`, refreshed on every feed update and on record. Ranking: KEV, confidence, public exploit, CVSS, EPSS. Shown in the web UI (badge), HTML/MD/CSV/JSON (`public_exploits`) and `.nessus` (`exploit_available`, `exploit_framework_metasploit`). Metadata only, no exploit code is downloaded. 

## Protocol probes (2026-11-23)
New in `internal/native/proto.go`, all read-only and `--allow-active`, mock-tested only: LDAP anonymous bind plus a one-entry base read of the first naming context (`ldap-anonymous`), TFTP read request for a nonexistent file (`tftp-open`), NTP mode 6 READVAR (`ntp-mode6`), IPMI 2.0 Open Session with cipher suite 3 (hash disclosure, CVE-2013-4786) and cipher suite 0 (`ipmi-cipher-zero`; no authentication exchange follows), Erlang EPMD names request (`epmd-exposed`). UDP probes run directly (no root needed). Not built: SMB null sessions, IKE aggressive mode, RabbitMQ.

## macOS audit (2026-11-23)
Feed `apple` (`update-feeds --only apple`, `--apple-months` default 24): reads Apple's security releases index and one article per macOS release, stores CVEs fixed per release (`macos_release`, `macos_fix`, migration 9; the older unused `apple_release` table from 0001 was left alone). Live: 5 major lines, 3,700+ fixes. The credentialed SSH audit now detects Macs (`uname` Darwin), collects `sw_vers` plus read-only security settings (SIP, Gatekeeper, FileVault, application firewall and stealth mode, software update and login window defaults; all allowlisted, tested read-only), then: (1) every CVE fixed by a newer release in the host's major line becomes a confirmed `Missing patch (macOS)` finding grouped as "Missing macOS updates: macOS Tahoe (26.6 -> 26.7.3)"; (2) a line with no Apple release for 12 months gets an `Unsupported software` finding; (3) rules MAC-001..009 plus the SSH rules (Linux-only rules are not run on a Mac). Missing Apple data is a visible skip. Limits: a host older than the downloaded window gets a partial list; Homebrew packages are inventoried only (not matched); `sshd -T` and some settings may need a privileged account (reported as unknown).

## Ground-truth lab and bug sweep (2026-11-23)
`babylon lab up|run|check` and `deploy/lab/manifest.yaml` (version 2: expected, forbidden, needs). 28 containers on 127.0.0.1 (standard ports where a probe needs them). First full scan scored 58% recall with Nuclei stalled and 125 unreviewed high findings; after fixing the bugs it exposed (see CHANGELOG), the same lab scores 19/19 (100%) on the expectations that do not need Nuclei, 0 forbidden findings, 59 unreviewed highs (CVE matches on lab software). Not measured on this machine: 6 Nuclei-dependent expectations (Nuclei v3.11.1 stalls here, see docs/known-issues.md) and TFTP (Docker Desktop for Mac drops replies from a new source port). `govulncheck` and `staticcheck` clean. CI and release workflows run on GitHub (Linux, macOS pass; Windows test job fails on test-harness issues, non-blocking, see known-issues.md); v0.1.1 released with SBOM, checksums and a sigstore signature.

## Check packs (2026-11-23, plan track T1, first slice)
`internal/pack`: declarative YAML checks (schema 1) compiled to `native.Check`, so skip reasons, coverage, fingerprints and redaction come from the existing runner. Kinds: `passive` (matches banner, product, version or NSE output already collected) and `probe` (tcp, udp or http against services found open; needs `--allow-active`). Limits are enforced at load: no write HTTP methods, bounded steps, bytes and time, mandatory scope, every step must expect something, RE2 regexes, unknown keys rejected. Every check carries a positive and a negative fixture; `babylon checks test` serves them from a local mock. `babylon checks list|validate|test`. Built-in packs are embedded (`internal/pack/builtin`, 22 checks: management-interface exposure, legacy services, SSDP/mDNS, end-of-life and backdoored versions); user packs go in `~/.babylon/checks/` and a malformed one fails the scan instead of being ignored. Checked end to end through a real scan. Pack controls feed the compliance report below. 42 pack checks now. Scope rule: infrastructure only; web-app content discovery stays in the Wire project.

## Compliance report (2026-11-23, plan track T2)
`internal/compliance`: every Go check, audit rule (Linux, macOS, Windows) and pack check maps to NIST SP 800-53 controls; a coarse crosswalk adds PCI DSS 4.0 requirements and ISO 27001:2022 Annex A controls (a few checks map directly where the crosswalk is too coarse). `babylon scans export <id> --compliance nist-800-53|pci-dss-4|iso-27001` (and `?compliance=` in the web export) adds a per-control section to JSON, Markdown and HTML: fail (a mapped check produced a finding), pass (a mapped check ran and found nothing), not assessed (nothing ran, with the reasons). Computed from the check runs and findings a scan already stores, so it works on old scans. Checks that ran but map to nothing are listed, not hidden. A test fails if a mapped check disappears or a new check is left unmapped. The mapping is Babylon's own and labelled as an evidence aid, not an assessment; CIS benchmark text and numbering are not used.

## Operations: triage, assets, trends (2026-11-23, plan track T6)
- Triage (`babylon triage add|list|remove`, migration 10): mark a finding accepted-risk (needs an expiry, at most 365 days) or false-positive (no expiry needed), with a required reason. Decisions are keyed by the finding's stable id, so they carry over to later scans. Active decisions hide the finding from counts, summaries and the findings list and list it under "Triaged findings"; once a decision expires the finding returns with a note. Finding ids are shown in `scans show`, Markdown and JSON.
- Assets (`babylon assets list|set`): criticality (low to critical), a fragile flag and tags, stored on the asset and kept across scans; can be set before a host is first scanned. Criticality ranks a finding right after KEV. Fragile hosts get no active probes (native probe checks and Nuclei requests are skipped, with the reason in coverage); Nmap still scans them.
- Trends (`babylon trend`, `GET /api/trends`): open findings per severity per scan, plus new and resolved against the previous scan, grouped by identical target lists (different targets are never compared). Triaged and informational findings are not counted.
- Notifications (`internal/notify`, `babylon notify test`): with `~/.babylon/notify.yaml` (webhook URL, slack or json format, min severity, KEV always notifies), a finished scan posts only what is new since the previous scan of the same targets: below-threshold, informational, tentative-guess and triaged findings are left out, nothing is sent for a quiet scan, and the first scan of a target set is a baseline. The file must be chmod 600 (it holds a secret URL); errors never print the URL. Works for CLI, web and scheduled scans. Not built: email.
- Not built: web UI pages for these (CLI and API only).

## Scale harness (2026-11-23, plan track T5, first slice)
`internal/report/scale_test.go` (skipped with `-short`; `BABYLON_SCALE_HOSTS=5000` sets the size) drives the real store, native runner, report builder, compliance, assets and trends with synthetic hosts and no engines. It found two real bottlenecks, both fixed: `ListFindings` ran two queries per finding (14.8 s for 13,000 findings, now 46 ms; 65,000 findings take 0.25 s) and `ListAssets` ran slow queries per host (2 min 20 s at 5,000 hosts, now 49 ms). At 5,000 hosts and 65,000 findings the whole run takes about 14 s. What this does not cover: Nmap and Nuclei at that scale, the orchestrator under real load, and the web UI rendering a huge findings table.

## Database audits (2026-11-23, plan track T4, first slice)
`internal/dbaudit` plus the `dbaudit` stage: with `--db-user`, `--db-password-env` (and `--db-name`, `--db-label`) a credentialed scan logs in to PostgreSQL and MySQL/MariaDB services it found and evaluates 15 rules (PG-001..008, MY-001..007): TLS, password hashing, pg_hba trust and any-address rules, superuser and password-less accounts, logging, anonymous and remote-privileged accounts, local_infile, secure_file_priv, general log. Read-only by construction: fixed SELECT/SHOW statements (a test fails on anything else), run in a read-only transaction. The audit refuses to send the password over an unencrypted connection unless `--db-allow-plaintext` is given; errors never contain the password. A rule whose facts are unreadable (missing privilege) is skipped with a reason, never passed. Verified against the real lab servers (PostgreSQL 11, MariaDB 10.5), end to end through a scan and into the compliance report. Limits: one credential set per scan (the same user and password are tried on every database found, so mixed estates need one scan per credential), no Oracle/SQL Server/MongoDB, no per-database object checks, MariaDB account locking is detected only for server-internal accounts.

## SMB guest access (2026-11-23)
Native check `smb-guest-access` (`--allow-active`, `internal/native/smbguest.go`, go-smb2): logs in to 445/tcp with a random non-existent user name and an empty password; a granted session means the server maps unknown users to guest. It lists share names, skips hidden ones (`$`), and counts root entries on each share (never reads file contents, never writes). High when a share is readable, medium when only the session is granted. Verified against the lab Samba container (guest share `pub`) through a real scan; lab manifest expects it. Limit: the library cannot open anonymous (null) sessions, so Windows `RestrictAnonymous` null-session enumeration is not tested.

## Network device config audit (2026-11-23, plan track T4)
`babylon config-audit <file> --host NAME [--type cisco-ios]` (`internal/netaudit`): parses an exported Cisco IOS/IOS-XE running-config (indentation-based blocks) and evaluates 13 hardening rules IOS-001..013: Telnet on vty, cleartext and type 7 passwords, enable password/weak secret, default or RW SNMP communities, plain HTTP server, SSH v2, vty access-class and idle timeout, AAA, remote logging, NTP and timestamps, legacy small services and source routing, CDP, login banner. Nothing is sent to the device. Result is stored as a completed `config_audit` scan, so reports, `--compliance`, triage, assets and `babylon trend` work on it; re-auditing a fixed config shows the findings as resolved. Secrets are redacted from evidence. A rule whose section is missing from the config (for example no vty lines) is unknown, not a pass. Tested on a weak and a hardened sample config (all rules fail and all pass respectively). Not verified against exports from real devices, so rule coverage of unusual syntax is unknown. Not built: collecting the config over SSH, Juniper, Fortinet, Palo Alto, other IOS-like platforms (NX-OS, IOS-XR) are untested.

## Standing rules
- Scan only hosts the user names. Lab containers are on 127.0.0.1. Never sweep a subnet.
- No Greenbone/OpenVAS or Tenable content. Non-destructive checks only. Credentials come from env vars per scan and are never stored.

## History (older milestone notes)

## Milestone 01: feeds + CPE→CVE matcher: DONE except browser check + commit

### Done (code written, compiles, `go build ./...` ok)
- `internal/store/migrations/0005_intel.sql`: feed_state etag/last_modified/detail, finding.product/version, indexes. `db_test.go` expects user_version 5.
- `internal/store/intel.go`: GetFeed/ListFeeds/SetFeed, ReplaceKEV, ReplaceEPSS, UpsertCVEs, ReplaceOSVEcosystem, CPEMatches, VendorsForProduct, CountCVEs.
- `internal/intel/`: `fetch.go` (conditional GET + retry), `kev.go`, `epss.go`, `cpe.go`, `nvd.go` (ParseNVDPage + resumable SyncNVD, incremental by lastMod), `osv.go` (ParseOSV, ParseOSVZip, SyncOSV), `sync.go` (SyncKEV/SyncEPSS).
- `internal/matcher/`: `version.go` (Compare, CleanVersion), `alias.go` (Nmap→NVD vendor aliases, product-name fallback), `backport.go` (Assess: distro marker / Linux+distro-packaged product → tentative + caveat; never confirmed), `match.go`; `matcher_test.go` passes with -race.
- `internal/scan/cpematch.go`: stage `cpematch` (after portscan; wired in `pipeline.go` when `Template.CPEMatch`); records check_run `cpe-version-match`; findings per CVE, Engine `cpematch`, Detection `version`.
- `internal/store/findings.go`: RecordFinding stores product/version, enriches kev/epss/cvss from feeds, version+behaviour corroboration → `confirmed`; `FindingRow` has EPSS/Product/Version; `PriorityLess` sort = KEV, confidence, CVSS, EPSS.
- `internal/store/inventory.go`: ServiceInfo gained Extra/Banner/OS.
- `internal/app/app.go`: warns when no CVE data indexed.
- `internal/cli/feeds.go`: update-feeds now handles nuclei-templates, kev, epss, nvd, osv; flags `--only --osv-ecosystems --nvd-pages --status --no-download`; NVD key via env `NVD_API_KEY`.
- Live data loaded into `~/.babylon/babylon.db`: KEV 1790, EPSS 411k. A full NVD sync was started in background (`/tmp/babylon-bin update-feeds --only nvd`, log `/tmp/nvd-sync.log`, ~25 min keyless, resumable: just rerun the same command if it died).

### Also done since the first save
- Tests written and green (`go test -short -race ./...` all packages): intel parsers + Sync* via httptest (ETag 304, retry, resume, incremental windows, empty-dump refusal), store enrichment / confirmed-merge / sort, matcher, cpematch stage, group. Mutation-checked: backport rule, vendor alias, confirmed rule each make a test fail when removed.
- `internal/group`: root-cause grouping (host, port, product, version; ≥2 members). Wired into CLI summary (`internal/cli/scan.go`), report JSON `root_causes` + Markdown "Priority action plan", CSV (epss/product/version columns, priority order), and web UI findings tab (`rootCauses()` in `app.js`, expandable, KEV/EPSS badges).

### Live acceptance (done, 2026-11-22)
Full NVD sync finished (411,297 CVEs, 2.5M ranges). Lab scan with `babylon scan 127.0.0.1 --ports 18081,18082,16379,12121,12222`: Apache 2.4.49 → 88 CVEs (3 KEV), OpenSSH 8.4 → 35, nginx 1.16.0 → 10, Redis 5.0.14 → 20, vsftpd 3.0.2 → 2, all grouped, firm (no distro banner, unprivileged so no OS), with CVSS/KEV/fix version. Backported banners are tentative + caveat (unit tests). The live scan found one miss (Nmap names vsftpd `vsftpd:vsftpd`, NVD `vsftpd_project`); alias added with test.

### Remaining for M01 (small)
1. (done: UI checked in the browser)
2. (done: committed and released in v0.1.0)
3. Optional: record feed versions in `scan.feed_versions_json`; KEV-watch and cvelistV5 not built.

Known gaps / honest notes: NVD CPE coverage of 2026 CVEs is poor (cvelistV5/Vulnrichment merge not built); unbounded "all versions" NVD entries are skipped and counted; OSV data is ingested but not used for matching until M02; NVD ingest is per-page transactions (resumable), KEV/EPSS/OSV are single transactions.

## Milestone 02: credentialed Linux audits (SSH): DONE for Linux (2026-11-23); macOS/Windows not done
Done and tested (`go test -short -race ./...` green):
- `internal/pkgver`: dpkg, rpm, apk comparators; table cases cross-checked against real `dpkg --compare-versions`, `apk version -t`, `rpm.vercmp` in Docker (no mismatches).
- `internal/audit`: `ssh.go` (x/crypto/ssh; strict known_hosts by default, `--trust-new-hosts` pins on first use, changed key always rejected; command allowlist enforced in code; 10s per command), `facts.go` parsers, `collect.go` (16 read-only commands), `osvmatch.go` (per-distro rules, lowest fix per CVE, unfixed advisories counted not reported), `rules.go` (SSH-001..004, PERM-001, FW-001, KERN-001, SVC-001; unknown ≠ pass). In-process SSH server tests for host-key policy.
- `internal/scan/audit.go`: stage `audit` after cpematch; findings family "Outdated package" (confirmed, host-level, one per source package+CVE) and "Local configuration"; supersedes unauthenticated banner guesses when the product is an installed package (tentative+caveat, or banner version == package upstream version); failures recorded per host without secrets; `audit_session`, `package`, `config_check_result`, check_run per rule.
- `internal/group`: package groups titled "Outdated package: X (old -> new)" with the apt/dnf/apk command, using distro version order.
- CLI: `--ssh-user --ssh-key --ssh-password-env --ssh-passphrase-env --ssh-port --ssh-label --known-hosts --trust-new-hosts`. Credentials never persisted (only label). Web UI refuses credentialed scans.
- Report: per-host credentialed-audit status (JSON `credentialed_audit`, Markdown, HTML).
- OSV parser fix: Debian/Ubuntu put CVE ids in `upstream`/`related`, now stored as aliases (needed re-download).
Live acceptance (Docker lab: `babylon-ssh-ubuntu` 12301 ubuntu:20.04, `babylon-ssh-debian` 12302 debian:12, `babylon-ssh-alpine` 12303 alpine:3.17; user `audit`/`labpass123`): Alpine result equals `apk upgrade --simulate` exactly (musl, openssl 3.0.15-r0→3.0.19-r0, openssh not flagged); Ubuntu glibc CVE-2025-4802 matches `apt list --upgradable` security pocket; Debian 12 clean. Banner guess "OpenSSH 9.1 — 34 CVEs" on Alpine was superseded.
Gaps: macOS (sw_vers/brew collected but no advisory source), Windows/WinRM, RHEL-family not live-tested (unit tests only), sudo for root-only data (sshd -T, firewall, ss -p) not supported, no web UI credential entry, no key-auth live test, OSV Ubuntu pockets (ESM/Pro) not matched, kernel package CVEs depend on OSV quality.

## Milestone 03: UDP + native checks + speed: DONE (2026-11-23)
UDP stage, native checks and speed profiles are all built; see "Do all" pass and "Infrastructure checks" above. The TODO line below is historical.
Done: `internal/policy/timing.go` profiles `standard` (unchanged defaults), `fast-lan` (-T4, 1 retry, rtt 400ms/100ms, script-timeout 15s, 2x packet rate, Nuclei 300 rps; private targets only, enforced in `app.Create`), `polite` (-T2, 3 retries, 120s scripts, 40% rate, Nuclei 25 rps). CLI `--timing`, web request field `timing`, persisted in scan flags so resume keeps it. Tests: nmap argv per profile, unknown name rejected, lastAddr.
Measured on the 5-port lab scan (127.0.0.1, unprivileged): standard 57.9s, fast-lan 42.4s, identical 158 findings. Where the time goes: -sV ~11s fixed, NSE ssl-cert/ssl-enum-ciphers hang ~30s on non-TLS ports (STARTTLS probes on ftp/redis), other scripts ~15s. An extra `ssl-enum-ciphers.timeout` arg lost a script result, so it was not adopted.
Historical TODO (since done, except the TLS-script guard): targeted UDP stage (15 ports), ~20 native checks with mock-listener tests, a smarter TLS-script guard (only run ssl-* where TLS is plausible) to cut the remaining time.

## Detection breadth work (2026-11-23)
- `--deep`: run every policy-allowed Nuclei template per service (not only tech-matched). Lab: 4m40s vs 1m20s, 307 vs 301 findings. Denied tags/protocols still excluded (tested).
- Web technology versions: Nuclei detect templates that extract a version + declare a product (CPE or index metadata, product must appear in template id/title) are stored in KB `Web/ip:port/cpe` and matched against NVD like Nmap versions (cpematch now waits for nuclei-detect). Test added.
- README rewritten short (install, use, what it does).
- Ideas not built yet: cvelistV5/Vulnrichment merge (2026 CVE CPE gap), exploit availability (ExploitDB/Metasploit metadata), KEV-product watch, retire.js-style JS library versions, favicon/header/meta-generator fingerprints, trivy for lockfiles on audited hosts, more native checks.

## "Do all" pass (2026-11-23, committed)
- Security fixes: Chrome sandbox kept for PDF (opt-out env BABYLON_PDF_NO_SANDBOX=1), 4 GiB cap per feed download, SSH first-use key fingerprint printed, `BABYLON_<TOOL>` absolute-path override for nmap/nuclei/etc.
- Windows builds (runner split into proc_unix.go / proc_windows.go, taskkill). Not run on Windows yet.
- Scale: scan chunk 128 -> 16 hosts, per-host timeout from timing profile (fast-lan 8m). Cause of the 44-host stall was one giant job; fix is unverified at scale (only loopback may be scanned).
- New detection: `--deep` Nuclei; web versions -> CVE matcher; KEV product watch (tentative, product known, version unknown); UDP stage (17 ports, needs root/sudo, skip reason recorded otherwise); native probes (Docker API, Kubelet x2, Elasticsearch, CouchDB, etcd, HSTS) only with --allow-active, mock-server tests; cvelistV5 feed (`update-feeds --only cvelist`, NVD always wins): 62,342 CVEs gained ranges, lab 301 -> 310 findings.
- Not done at that time: Windows credentialed audit (since built), macOS advisories, web-app (DAST) mode, exploit-availability tags, Windows live test.

## Milestone 04: HTML/PDF reports: v0.1 DONE (2026-11-23)
`internal/report/html.go` (self-contained, CSP meta, no JS, data-driven: sections come from Groups/Hosts/Family, so new finding types need no template change; optional `familyInfo` for titles), `pdf.go` (Chrome/Chromium/weasyprint), `doctor` reports PDF renderer, CLI `scans export --format html|pdf`, web `Export HTML` button + `?format=html`. Test: escaping + no external refs. TODO: per-host credentialed-audit status block (after M02), richer coverage appendix.

