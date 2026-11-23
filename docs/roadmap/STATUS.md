# Roadmap status (resume file)

Last updated: 2026-11-23. Nothing below is committed yet (working tree has uncommitted changes on `main`, last commit f5736cf).

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
1. Browser-check the new UI section (Playwright) on scan with grouped findings.
2. Commit and push (nothing is committed yet).
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

## Milestone 03: UDP + native checks + speed: speed profiles DONE (2026-11-23); UDP and new native checks NOT STARTED
Done: `internal/policy/timing.go` profiles `standard` (unchanged defaults), `fast-lan` (-T4, 1 retry, rtt 400ms/100ms, script-timeout 15s, 2x packet rate, Nuclei 300 rps; private targets only, enforced in `app.Create`), `polite` (-T2, 3 retries, 120s scripts, 40% rate, Nuclei 25 rps). CLI `--timing`, web request field `timing`, persisted in scan flags so resume keeps it. Tests: nmap argv per profile, unknown name rejected, lastAddr.
Measured on the 5-port lab scan (127.0.0.1, unprivileged): standard 57.9s, fast-lan 42.4s, identical 158 findings. Where the time goes: -sV ~11s fixed, NSE ssl-cert/ssl-enum-ciphers hang ~30s on non-TLS ports (STARTTLS probes on ftp/redis), other scripts ~15s. An extra `ssl-enum-ciphers.timeout` arg lost a script result, so it was not adopted.
TODO next: targeted UDP stage (15 ports), ~20 native checks with mock-listener tests, a smarter TLS-script guard (only run ssl-* where TLS is plausible) to cut the remaining time.

## Detection breadth work (2026-11-23)
- `--deep`: run every policy-allowed Nuclei template per service (not only tech-matched). Lab: 4m40s vs 1m20s, 307 vs 301 findings. Denied tags/protocols still excluded (tested).
- Web technology versions: Nuclei detect templates that extract a version + declare a product (CPE or index metadata, product must appear in template id/title) are stored in KB `Web/ip:port/cpe` and matched against NVD like Nmap versions (cpematch now waits for nuclei-detect). Test added.
- README rewritten short (install, use, what it does).
- Ideas not built yet: cvelistV5/Vulnrichment merge (2026 CVE CPE gap), exploit availability (ExploitDB/Metasploit metadata), KEV-product watch, retire.js-style JS library versions, favicon/header/meta-generator fingerprints, trivy for lockfiles on audited hosts, more native checks.

## "Do all" pass (2026-11-23, uncommitted)
- Security fixes: Chrome sandbox kept for PDF (opt-out env BABYLON_PDF_NO_SANDBOX=1), 4 GiB cap per feed download, SSH first-use key fingerprint printed, `BABYLON_<TOOL>` absolute-path override for nmap/nuclei/etc.
- Windows builds (runner split into proc_unix.go / proc_windows.go, taskkill). Not run on Windows yet.
- Scale: scan chunk 128 -> 16 hosts, per-host timeout from timing profile (fast-lan 8m). Cause of the 44-host stall was one giant job; fix is unverified at scale (only loopback may be scanned).
- New detection: `--deep` Nuclei; web versions -> CVE matcher; KEV product watch (tentative, product known, version unknown); UDP stage (17 ports, needs root/sudo, skip reason recorded otherwise); native probes (Docker API, Kubelet x2, Elasticsearch, CouchDB, etcd, HSTS) only with --allow-active, mock-server tests; cvelistV5 feed (`update-feeds --only cvelist`, NVD always wins): 62,342 CVEs gained ranges, lab 301 -> 310 findings.
- Not done: Windows credentialed audit (WinRM), macOS advisories, web-app (DAST) mode, exploit-availability tags, Windows live test.

## Milestone 04: HTML/PDF reports: v0.1 DONE (2026-11-23)
`internal/report/html.go` (self-contained, CSP meta, no JS, data-driven: sections come from Groups/Hosts/Family, so new finding types need no template change; optional `familyInfo` for titles), `pdf.go` (Chrome/Chromium/weasyprint), `doctor` reports PDF renderer, CLI `scans export --format html|pdf`, web `Export HTML` button + `?format=html`. Test: escaping + no external refs. TODO: per-host credentialed-audit status block (after M02), richer coverage appendix.
(original spec below)
Self-contained html/template report, Export HTML button, PDF via chrome/weasyprint detected in `doctor`. See `milestone04.md`.
