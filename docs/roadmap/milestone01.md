# Milestone 01: Offline Threat Intel Feeds & Confidence-Aware CPE→CVE Matcher

## Goal
Close the unauthenticated version-detection gap by building an offline vulnerability intelligence store (`update-feeds`) and a conservative CPE→CVE matching engine enriched with **CISA KEV** and **EPSS** prioritization, strictly respecting Babylon's `tentative` / `firm` / `confirmed` confidence model.

## 1. Feed Ingestion (`babylon update-feeds`)
Extend `update-feeds` to download, verify, and index local SQLite tables (with incremental/ETag caching so updates are fast):
- **CISA KEV (Known Exploited Vulnerabilities):** Fetch CISA's official JSON feed. Store `cve_id`, `vendor`, `product`, `date_added`, `due_date`, `ransomware_use`, `notes`.
- **FIRST EPSS (Exploit Prediction Scoring System):** Fetch daily EPSS CSV/JSON scores. Store `cve_id`, `epss_score` (0.0–1.0), `percentile`.
- **OSV.dev Ecosystem Dumps:** Download zipped JSON dumps for major Linux ecosystems (`Debian`, `Ubuntu`, `Alpine`, `Rocky Linux`, `AlmaLinux`) and core open-source packages (`PyPI`, `npm`, `Go`). Store normalized affected package/version ranges and fixed versions in SQLite with indexed lookups.
- **NVD CPE/CVE Dictionary (for unauthenticated service banners):** Maintain a compact local index mapping `(cpe_vendor, cpe_product)` to CVE records (`cve_id`, `cvss_v3_score`, `cvss_vector`, `version_start_including`, `version_end_excluding`, `summary`).

## 2. CPE→CVE Matching Engine (`internal/matcher`)
- **Input:** Normalized CPE 2.3 strings and parsed service banners from the per-host Knowledge Base (produced by Nmap `-sV` and Nuclei tech-detection).
- **Version Comparison:** Implement proper semantic/upstream version comparison (handling major/minor/patch/prerelease tokens cleanly).
- **Confidence & Backport Safeguards (CRITICAL):**
  - If the detected banner comes from a Linux distribution known to backport security fixes (e.g., banner contains `Ubuntu`, `Debian`, `el8`, `el9`, `Alpine`) and the scan is **unauthenticated**, mark the resulting CVE finding as **`tentative`** and append an explicit caveat: *"Banner version may include vendor backported patches; verify with a credentialed scan."*
  - If the software is upstream/unbackported (e.g., network appliance firmware, standalone Windows binary, Apache Tomcat, vsftpd) and falls cleanly inside a vulnerable range, mark as **`firm`**.
  - If an active Nuclei template or native check confirms the same CVE, upgrade the merged finding to **`confirmed`**.
- **Prioritization Scoring:** Attach `cvss_score`, `epss_score`, and `is_kev` (boolean) to every finding. Sort default CLI/UI views by: `is_kev DESC, confidence DESC, cvss_score DESC, epss_score DESC`.

## 3. Root-Cause Grouping
- In the correlator/reporting layer, group multiple CVE findings sharing the same `(host_id, port, cpe_product, detected_version)` into a **Grouped Finding** (`"Apache HTTP Server 2.4.49 — 12 CVEs (1 KEV)"`) while preserving individual CVE records in SQLite and allowing expansion in the UI and exports.

## Acceptance Criteria
1. `babylon update-feeds` populates NVD/OSV, KEV, and EPSS tables cleanly into SQLite within a single batched transaction.
2. Scanning an unpatched service in the Docker lab produces `firm` or `tentative` CPE-matched CVEs enriched with CVSS, EPSS, and KEV flags.
3. Backported distro banners never produce `confirmed` findings from unauthenticated version matching alone.
4. Race detector tests (`go test -race ./...`) pass for feed updates, version matching, and root-cause grouping.