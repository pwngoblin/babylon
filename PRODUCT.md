# Babylon — Product Plan

Status: **draft v0.5**. Direction: *Nessus-style workflow and reports, maximizing vulnerabilities found per host using only open, freely redistributable detection sources.* No Greenbone feed, no Tenable content, no container required.

## 1. One-liner

Babylon is a local-first, open-source vulnerability scanner with Nessus-style scan policies and client-ready reports, built on Nmap, Nuclei, NVD/OSV/MSRC data, and its own native checks and credentialed audits.

## 2. Problem and wedge

Nessus is closed and licensed. OpenVAS has depth but a heavy stack and a feed with its own terms. Raw Nmap/Nuclei give noisy output without prioritization, history, or client-ready reporting.

**Babylon's wedge:**
- **Breadth by stacking**: Nmap/NSE + Nuclei + CPE→CVE matching + native misconfig checks + credentialed audits, correlated into one picture.
- **Honest confidence**: confirmed / firm / tentative, so version-guess findings never masquerade as verified ones.
- **Signal**: cross-engine dedupe, root-cause grouping ("upgrade X, fix 24 CVEs"), KEV + EPSS + CVSS prioritization.
- **Nessus-like workflow**: templates, credentials by CIDR/tag, history, diffs, resumable scans.
- **Delivery**: one Go binary + `nmap`/`nuclei` on PATH; management-grade HTML report.

Where we're weaker (stated plainly): unauthenticated plugin depth versus Nessus. Credentialed scanning is where Babylon matches or beats it.

## 3. Users

| Persona | Need |
|---|---|
| **Sysadmin / home-lab / small IT** (primary) | Scan up to 500+ hosts, see as many real issues as possible, get a prioritized fix list |
| **Report readers: clients, management** | Executive summary, top actions, branded printable report |
| Consultants / DevOps | Baselines, JSON output, CI use |

## 4. Goals and non-goals

### Goals
1. **Maximize true findings per host** without destructive checks.
2. **Credentialed audits** on Linux, macOS and Windows as the main coverage lever.
3. **Trust**: evidence and confidence on every finding; coverage and auth-failure reporting so "no findings" never reads as "secure".
4. **Nessus workflow parity**: policies, history, diffs, resume.
5. **Safe by construction**: allowlist-built engine configs; denied categories unreachable; tests prove it.
6. **Scale to 500+ hosts**.
7. **Local-first**, offline after `update-feeds`.
8. **Client-ready reports** in the MVP.

### Non-goals (v1)
- Greenbone/OpenVAS feed or scanner, and Tenable/Nessus content (licence; excluded entirely, no opt-in adapter).
- Exploitation, DoS, destructive checks, fuzzing.
- Multi-tenant console/RBAC.
- Compliance attestation (CIS-lite checks only).
- Deep DAST/web crawling beyond Nuclei (a separate project).

## 5. Journeys

```
babylon update-feeds                      # NVD, KEV, EPSS, OSV, MSRC, Apple, nuclei-templates
babylon scan 10.0.0.0/22 --template basic
babylon scan hosts.txt --template credentialed --creds creds.toml
babylon scan --resume 42
babylon diff last~1 last
babylon report --format html,md,json --brand acme.toml
```

## 6. Templates

| Template | Runs | Creds | Safety posture |
|---|---|---|---|
| Host Discovery | Nmap sweep | no | minimal |
| Basic Network Scan | Nmap + safe NSE + Nuclei safe tags + native checks + CPE→CVE | no | non-destructive |
| Full Unauthenticated | + all TCP, UDP top, broader Nuclei, probe-level native checks (`--allow-active`) | no | rate-limited, opt-in |
| Credentialed Patch & Config Audit | Basic + SSH/WinRM audit + OSV/MSRC/Apple + hardening (+ Trivy for images) | yes | read-only |

Always denied: DoS, destructive, intrusive NSE/Nuclei categories. Default-credential checks need `--check-default-creds`.

## 7. Scope by phase

> Status (2026-11-23): Phase 1, the Linux and Windows credentialed audits, scheduler, UI and `.nessus` export are built (v0.1.0 plus later commits). Windows audit is not yet run against a real host; macOS audit is not built. Next steps are in `docs/roadmap/ROADMAP.md`.

- **Phase 0 (spike)**: lab + expected-findings manifest; measure coverage and CPE false-positive rate per source; go/no-go per source.
- **Phase 1 (MVP)**: policy/safety, scalable orchestrator, Nmap + Nuclei + native checks + CPE→CVE, feeds, correlation/dedupe, **HTML/MD/JSON reports with exec summary + branding**.
- **Phase 2**: credentialed audits (Linux → containers/Alpine → macOS → Windows), root-cause grouping, diff/trend, hardening packs.
- **Phase 3**: 100+ native checks, `.nessus` import/export, remote agents, scheduler/UI, plugin SDK docs.

## 8. Success metrics

- **Coverage (headline)**: ≥ 75% of the expected-findings manifest on unauthenticated lab scans; ≥ 95% of known missing package updates on credentialed Linux scans. Tracked per release.
- **Precision**: ≥ 90% of Confirmed/Firm High/Critical are true positives; tentative findings are labeled and counted separately.
- **Safety**: zero lab-target crashes under Basic and credentialed; safety-invariant test passes in CI.
- **Scale**: 500-host Basic scan completes in bounded memory and resumes after kill.
- **Time to first report** ≤ 15 min from clean install (NVD ingest dominates).
- **Offline**: full scan with the network disabled after update.
- **Report quality**: a non-technical reader names the top 5 actions from page 1.

## 9. Decisions log

| # | Decision |
|---|---|
| D1 | Primary user: sysadmin / home lab; report audience: clients/management |
| D2 | Language: Go |
| D3 | **No Greenbone feed, no Tenable content.** Coverage from Nmap/NSE, Nuclei, NVD CPE→CVE, native checks, credentialed audits (OSV/MSRC/Apple), optional Trivy |
| D4 | **No container/Linux-engine requirement**; macOS and Linux first-class. OpenVAS/Greenbone excluded for licence reasons (no adapter) |
| D5 | Safety model: **non-destructive** (not "passive only"); allowlist-built configs; active probes and default-credential checks are opt-in; CLAUDE.md updated to match |
| D6 | Confidence tiers (confirmed/firm/tentative); version-only matches are tentative and reported separately |
| D7 | Nmap may use sudo; connect-scan fallback with coverage warning |
| D8 | Scale 500+: jobs/chunking/resume/pools/single-writer in MVP; remote agents later |
| D9 | Credentialed: Linux/macOS via SSH, Windows via WinRM; no sudo on targets by default (optional allowlisted sudo per tag) |
| D10 | Credentials: age-encrypted file / keychain / ssh-agent, mapped by CIDR/tag |
| D11 | Priority: KEV → EPSS → CVSS → exploit-exists → asset criticality |
| D12 | Asset criticality via tag/CSV import, default medium, in MVP |
| D13 | Public-range guard on by default |
| D14 | Distribution: release binaries + Homebrew tap; `nmap` required, `nuclei` required for web/CVE templates, `trivy` optional; PDF via print-to-PDF |
| D15 | Licence: Apache-2.0 for Babylon (Nmap/Nuclei/Trivy are separate subprocesses) |
| D16 | Name stays "Babylon" |

## 10. Items to confirm

All resolved; nothing blocks Phase 0.
1. Greenbone: excluded for licence reasons, no adapter.
2. Nmap `vulners` NSE: excluded (online API breaks offline-first); the CPE→CVE matcher replaces it.
3. Active checks: probe-level checks run only in the Full template, behind `--allow-active` plus a scope confirmation. Basic never runs them.

## 11. Risks (product)

| Risk | Response |
|---|---|
| Unauthenticated depth below Nessus | Credentialed audits, CPE breadth, native checks, measured on manifest |
| Tentative findings create noise | Confidence tiers, separate section, credentialed suppression |
| Scanning breaks fragile hosts | Safe defaults, fragile tag, rate limits, opt-ins |
| Scope explosion | Phase gates; independent engine adapters |
| Authorization misuse | Public-range guard, scope logging, authorization flag |
