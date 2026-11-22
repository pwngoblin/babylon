# Phase 0 — Coverage Spike

Status: **first measurement pass complete** (2026-11-22). Single lab on loopback, 7 targets, 12 manifest entries after corrections. Treat numbers as directional, not statistically meaningful.

## Method
Lab: `deploy/lab/docker-compose.yml` (127.0.0.1 only). Each source run separately; raw output in `testdata/spike/`.
- **Nmap**: `-sV --version-light` + NSE `(default or safe or vuln) and not (intrusive or dos or exploit or brute or fuzzer or malware or external)`.
- **Nuclei** v3.11.1, 14,225 templates, safe exclusions (`dos,fuzz,intrusive,bruteforce,default-login`, no headless/code/js).
- **CPE→CVE prototype**: NVD API 2.0 `cpeName` + `isVulnerable` for each CPE Nmap reported; cross-checked with CISA KEV.

## Manifest corrections the lab forced
- `CVE-2021-41773/42013`: default `httpd:2.4.49` returns 403 on the traversal path → **not exploitable in this config**. Version-based `tentative` is the honest ceiling; a probe-based "confirmed" would be wrong.
- `ftp-anonymous-login`: image rejects anonymous login (530). Entry removed; needs a different image.
- Nmap sees Juice Shop as `unknown` (needs HTTP probing, i.e. Nuclei).

## Results by manifest entry (12 entries)

| Entry | Nmap/NSE | Nuclei | CPE→CVE | Union |
|---|---|---|---|---|
| CVE-2021-41773 (tentative) | – | – | ✅ | ✅ |
| CVE-2021-42013 (tentative) | – | – | ✅ | ✅ |
| apache version disclosure | ✅ | ✅ `apache-detect` | – | ✅ |
| redis unauthenticated | ✅ `redis-info` | ❌ missed | – | ✅ |
| CVE-2019-20372 nginx (tentative) | – | – | ✅ | ✅ |
| nginx version disclosure | ✅ | ✅ `nginx-version`, `nginx-eol` | – | ✅ |
| DVWA default login | – | not run (opt-in) | – | ❌ untested |
| DVWA config/phpinfo exposure | – | ✅ `configuration-listing` | – | ✅ |
| Juice Shop detected | ❌ `unknown` | ✅ | – | ✅ |
| Missing security headers | ✅ (script errored on one) | ✅ | – | ✅ |
| SSH weak algorithms | raw list only, no judgement | – | – | ❌ needs native check |
| OpenSSH 8.4 version CVEs (tentative) | – | – | ✅ (38) | ✅ |

**Union: 10/12 = 83%** (target ≥ 75%). Per source: Nmap/NSE 4/12, Nuclei 6/12, CPE 4/12. No single source exceeds 50%, so stacking is justified. Nuclei also found extras: `CVE-2021-30047` and `CVE-2015-1419` (vsftpd), `dvwa-setup` (high), `prometheus-metrics` (medium).

## Precision and noise
- **NSE false positive**: `http-vuln-cve2011-3192` reported VULNERABLE on **nginx** (an Apache-only CVE). Curated `vuln` scripts need a product guard (run only when Nmap identified the matching product), not a blanket `vuln` category.
- **Nuclei duplicates**: 66 raw results → 24 unique (host, template); `http-missing-security-headers` alone emitted 38 rows. Dedupe/grouping is mandatory, not polish.
- **CPE→CVE volume**: 158 tentative CVEs across 5 services (Apache 88, OpenSSH 38, Redis 20, nginx 10, vsftpd 2). 4 are in KEV. Without confidence tiering and grouping this would swamp a report; with them it's a "possible" section. True/false split of the 158 is **not measured** (no ground truth); needs per-product sampling.
- **KEV enrichment works**: 1,790 KEV entries joined cleanly to NVD results (e.g. CVE-2021-41773, CVE-2021-42013 flagged).

## Findings that change the design
1. **CPE vendor aliasing is required.** Nmap's CPEs missed NVD for nginx (`igor_sysoev` → NVD uses `f5`) and Redis (`redislabs` → NVD uses `redis`): both returned **0 results** until the vendor was remapped. Need a curated Nmap→NVD vendor/product alias table, with a test.
2. **Nuclei must be tech-filtered per host.** Unfiltered 14k templates × 7 targets ran 15+ min and yielded 3 findings before I stopped it. Even a broad tag union took >10 min. MVP: map each service's detected tech to a narrow tag set (or use Nuclei's tech-aware automatic scan) and measure again.
3. **Nuclei misses protocol-level misconfig** such as Redis no-auth that NSE caught; native checks are needed for that class.
4. **SSH weak-algorithm judgement** needs our own interpretation layer; NSE only lists algorithms.
5. **"Confirmed" must mean verified.** Two CVEs that look critical by version are not exploitable in the default image; the confidence model (tentative/firm/confirmed) is correct and is already in the schema.

## Not yet measured
- Precision of the 158 CPE findings; MSRC and Apple feed feasibility; Trivy on an image; DVWA default-login (opt-in path); a lab with Debian/Alpine OS packages for credentialed coverage.
- Nuclei time with proper per-host tag narrowing.

## Addendum: NVD bulk ingest spike (same day)
Sampled 3 of ~216 pages (2,000 CVEs each; indexes 0, 200000, 420000), ingested into the real schema, extrapolated. Rough, 3-page sample.

| Metric | Result |
|---|---|
| NVD size | 430,493 CVEs, 216 pages × 2,000 |
| Download | ~1.5 GB JSON (4–10 MB/page). Unauthenticated API ≈ 5 req/30 s → ~22 min full sync; with a free API key ≈ 50 req/30 s → ~2 min `[VERIFY limits]`. Incremental via `lastModStartDate` |
| Parse + ingest | ~0.4 min for the full set (Python prototype; Go will be at least as fast) |
| SQLite | ~2.1M `cpe_match` rows, ~400 MB |
| Query `(vendor, product)` | 0.02 ms (indexed) |
| cvelistV5 (CVE.org) | full release 671 MB zip; daily delta only 0.7 MB |

**Critical finding: NVD CPE coverage of recent CVEs is poor.** `configurations` present: 92% (1988–2000), 87% (2022), **16% (2026)**. Of 2,000 sampled 2026 CVEs, 979 are `Deferred` and 495 `Awaiting Analysis`. A matcher built only on NVD is blind to most CVEs from the last months, which are the ones most likely to matter.

**Design response (applied to ARCHITECTURE.md):**
1. Add **cvelistV5** (CVE.org) as a second CPE/range source: CNA-supplied `affected` product/version data, incremental via the 0.7 MB deltas. Merge into `cpe_match` with a `source` column and prefer NVD where both exist.
2. Keep **CISA Vulnrichment** CPE enrichment as a third source `[VERIFY coverage]`.
3. Add a **KEV watch** path: KEV carries vendor/product, so a detected product matching a KEV entry is surfaced as `tentative` even when no version range exists.
4. Rely on **Nuclei** for fresh CVEs (templates land within days), which is another reason it stays core.
5. Report feed age and the **share of CVEs with usable ranges**, so "no CPE findings" is never mistaken for "no vulnerabilities".

## Go / no-go
| Source | Decision |
|---|---|
| Nmap + curated NSE | **Go**, with per-product guards and a curated script list (no blanket `vuln`) |
| Nuclei | **Go**, only with per-host tech tag narrowing |
| CPE→CVE | **Go** as `tentative` breadth source, with alias table + grouping + separate report section |
| Native checks | **Go**: first targets are Redis/Memcached/Mongo no-auth, FTP anon, SSH algorithm judgement, security headers |
| NVD bulk ingest | **Go** (cheap), but **insufficient alone** → add cvelistV5 + KEV watch |
| MSRC / Apple | **Open**, spike before Phase 2d |

## Phase 0 engineering deliverables
Go module, `babylon doctor`, SQLite store + migrations (schema v1), subprocess runner with tests, lab + manifest, this measurement pass.
