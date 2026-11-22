# Project: Babylon — Open-Source Nessus Alternative

## Objective
Design and build **Babylon**, a lightweight, local-first vulnerability and configuration scanner that replicates the core functionality, scanning workflow, and reporting capabilities of **Nessus** using only open, free, and locally runnable data sources and detection engines.

## Core Architecture & Pipeline (Nessus Feature Parity)

### 1. Input & Policy Layer (Scan Profiles)
- Replicate Nessus scan policies by accepting target definitions (CIDR ranges, IP lists, hostnames, and optional SSH/WinRM credentials) alongside configurable scan templates (`Host Discovery`, `Basic Network Scan`, `Full Unauthenticated Scan`, `Credentialed Patch & Config Audit`).
- Enforce configurable rate limits, concurrency caps, and safe-check guardrails so scans do not overwhelm local networks or fragile endpoints.

### 2. Discovery & Service Fingerprinting Stage
- Wrap **Nmap** (via XML output parsing) to replicate Nessus's host discovery and port/service enumeration:
  - Live host discovery (ARP, ICMP echo, TCP SYN/ACK).
  - TCP/UDP port scanning and service/version banner fingerprinting (`-sV`).
  - TLS/SSL cipher suite and certificate auditing (via NSE scripts such as `ssl-enum-ciphers` and `ssl-cert`).
- Normalize discovered hosts, open ports, detected services, CPEs, and TLS metadata into a structured local state store (SQLite).

### 3. Unauthenticated Vulnerability & Misconfiguration Stage
- Feed discovered HTTP/HTTPS endpoints and network services into **Nuclei** (using the open-source `nuclei-templates` repository) filtered by detected technologies and protocols to replicate Nessus's network/web plugin checks (known CVEs, exposed admin interfaces, default credentials, and protocol misconfigurations).
- Support custom YAML/Python plugin modules for internal infrastructure checks (e.g., SMB signing status, anonymous shares, weak SSH algorithms).

### 4. Authenticated Host & Package Audit Stage (Credentialed Scans)
- Replicate Nessus's credentialed local security checks via read-only SSH (Linux/macOS) or WinRM (Windows) sessions:
  - Collect installed OS packages, kernel versions, and key security configurations.
  - Cross-reference installed package versions against **OSV.dev** and **CISA KEV** offline/cached JSON databases to detect unpatched vulnerabilities accurately (accounting for distro-specific backported package versions rather than naive upstream version matching).
  - Run baseline hardening/compliance checks (e.g., SSH daemon settings, firewall state, file permissions, password policies).

### 5. Deduplication, Correlation & Reporting Layer
- Aggregate raw outputs from Nmap, Nuclei, and authenticated package checks into a unified Nessus-style finding schema (`host`, `port/protocol`, `plugin_name`, `cve_ids`, `cvss_score`, `kev_status`, `synopsis`, `description`, `evidence`, `remediation`).
- **Root-Cause Grouping:** Deduplicate noisy findings by grouping multiple CVEs tied to the same outdated package or service into a single actionable remediation item (e.g., *"Upgrade OpenSSL from X to Y to resolve 24 CVEs"*).
- Export clean, structured reports in **Markdown**, **JSON**, and **HTML** formats, sorted by exploitability (CISA KEV + CVSS) and asset criticality.

## Technical Constraints & Stack Preferences
- **CLI / Package Name:** `babylon`
- **Language:** Go (decided; see ARCHITECTURE.md) with clean modular separation (`discovery/`, `scanners/`, `intel/`, `correlate/`, `report/`).
- **Storage:** Local SQLite database for scan history, diffing between runs (new vs. resolved findings), and cached vulnerability feeds.
- **Offline/Local-First:** Cache OSV.dev, CISA KEV, and Nuclei templates locally with a single `babylon update-feeds` command so scans run cleanly without external SaaS dependencies.
- **Safety:** Non-destructive checks only—no DoS, destructive, fuzzing, or exploitation modules. Read-only active probes (banner/version/config checks) are allowed; anything more intrusive (default-credential checks, intrusive Nuclei/NSE categories) is opt-in behind explicit flags and a scope confirmation. Denied categories must be unreachable by construction and covered by tests.
- **Detection sources:** Nmap (+ safe NSE), Nuclei templates, Babylon native plugins, NVD CPE→CVE matching, and credentialed audits against OSV/MSRC/Apple data. Do **not** depend on the Greenbone Community Feed or Tenable/Nessus content (licence; no OpenVAS adapter, opt-in or otherwise).

## Deliverables Requested
1. Propose the exact repository directory structure and SQLite schema for `babylon`.
2. Provide a clean, modular implementation plan starting with the MVP (Nmap XML ingestion + Nuclei orchestration + SQLite deduplication + Markdown/JSON report generator), followed by Phase 2 (authenticated SSH package auditing against cached OSV.dev data and scan diffing).
3. Write the core orchestration and data-model code cleanly with proper error handling, timeouts, and subprocess management.
