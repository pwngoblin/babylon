# Milestone 04: Self-Contained HTML/PDF Reports & Coverage Transparency

## Goal
Deliver executive- and client-ready single-file HTML (and optional PDF) reports that showcase Babylon's root-cause grouping, KEV/EPSS prioritization, and check-coverage transparency.

## 1. Self-Contained HTML Report Generator (`babylon scans export --format html`)
- Build using Go's `html/template` with **100% embedded CSS and inline SVG charts** (zero CDN calls, zero external JS, works completely offline).
- **Report Structure:**
  1. **Executive Summary:** Scan metadata (target scope, profile, duration, timestamps), risk posture summary cards (`KEV Exploited`, `Critical`, `High`, `Medium`, `Low`, `Info`), and severity distribution bar.
  2. **Priority Action Plan (Root-Cause Grouped):** Top remediation items ranked by `KEV > Confidence > CVSS`, showing exact upgrade/fix actions and how many individual CVEs each action resolves.
  3. **Host-by-Host Breakdown:** Discovered OS, open TCP/UDP ports, detected technologies, credentialed audit status, and grouped findings with collapsible raw evidence (`request/response`, `package version`, `config snippet`).
  4. **Scan Coverage & Audit Trail Appendix:** Summary of executed vs. skipped native checks (with skip reasons) and confidence filter applied (`--accuracy`), proving thoroughness like a commercial Nessus report.
- Add an **Export HTML** button directly into the local Web UI (`babylon serve`).

## 2. Optional PDF Export (`--format pdf`)
- If headless Chrome/Chromium or `weasyprint` is available on `PATH` (detected via `babylon doctor`), render the generated HTML report to clean paginated PDF with print-friendly `@media print` CSS rules. If unavailable, return a clear message pointing to `--format html`.

## Acceptance Criteria
1. `babylon scans export <id> --format html` outputs a standalone `.html` file that renders cleanly offline with zero external network requests.
2. Grouped findings expand cleanly to show underlying CVE IDs, CVSS/EPSS scores, KEV badges, and raw technical evidence.
3. `babylon doctor` reports whether optional PDF rendering dependencies are available.