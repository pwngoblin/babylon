# Changelog

## Unreleased

### Added
- Check packs: declarative YAML checks (passive and probe) with built-in and user packs, per-check test fixtures and `babylon checks list|validate|test`. 22 built-in pack checks.
- Compliance report: `scans export --compliance nist-800-53|pci-dss-4|iso-27001` adds a per-control pass/fail/not-assessed section (JSON, Markdown, HTML, web export). Every check and audit rule is mapped.
- 20 more pack checks (management interfaces, STARTTLS/TLS-less mail and FTP, JDWP, RMI, r-services, more end-of-life versions).
- Triage workflow: `babylon triage` marks findings accepted-risk (with expiry) or false-positive, carried across scans and shown in reports.
- Asset inventory: `babylon assets` sets criticality (ranks findings), fragile (no active probes) and tags.
- `babylon trend` and `/api/trends`: findings over time with new and resolved per scan.
- Webhook notifications for new findings only (`~/.babylon/notify.yaml`, `babylon notify test`).
- Synthetic scale test (5,000 hosts, 65,000 findings); fixed two slow queries it exposed (findings listing and the asset list).
- Credentialed PostgreSQL and MySQL/MariaDB audits (`--db-user`, `--db-password-env`): 15 read-only rules, refuses plaintext logins by default.
- SMB guest-access check: detects servers that grant a session to unknown users and lists readable shares (read-only).
- `babylon config-audit`: offline Cisco IOS/IOS-XE hardening audit of an exported config (13 rules), stored as a scan so compliance, triage and trends work.
- Web UI: Assets, Trends and Triage pages and a triage form on each finding.
- `docs/roadmap/PLAN.md`: plan for closing the gap to Nessus.

## 0.1.1

Everything since v0.1.0.

**Added**
- Exploit availability tags (Exploit-DB, Metasploit metadata; no exploit code) used in ranking, reports and `.nessus`.
- macOS credentialed audit over SSH: missing updates from Apple security releases, end-of-support, 9 hardening rules.
- Native probes: LDAP anonymous bind, TFTP, NTP mode 6, IPMI cipher suites, Erlang EPMD.
- Ground-truth lab: `babylon lab up|run|check` scores a scan against `deploy/lab/manifest.yaml` (recall and false positives).
- 17 more real lab services (databases, brokers, LDAP, SNMP, SMB, TFTP, rsync, Consul) and four credentialed-audit hosts.
- `babylon doctor` Nuclei self-test; CI (build, vet, race tests on Linux/macOS/Windows, `govulncheck`, `staticcheck`) and a signed, SBOM-carrying release workflow.

**Fixed (found by the lab)**
- SMB signing and SMBv1 checks never ran: Nmap host-level script results were not read.
- SSH weak-algorithm check never fired: Nmap only reports algorithm counts unless verbose; names are now read from its tables.
- Memcached check required a "version" line that real output does not contain.
- A check reporting two findings on one port (for example end-of-life MariaDB without TLS) merged them into one.
- TFTP probe dropped real server replies (they come from a new source port).
- Nmap version ranges and wildcards (`9.6.20 - 9.6.23 or 11.14 - 11.18`, `2.2.X`, `4`) were matched as a precise version, producing wrong CVEs.
- Nuclei could hold a scan for 45 minutes when it stalls; now batched with deadlines, bisected, and capped (see docs/known-issues.md).

**Measured.** Lab recall on non-Nuclei checks: 19/19 expected findings, 0 forbidden findings. Nuclei-dependent expectations (6) are
not measured on the development machine because Nuclei stalls there. See docs/roadmap/STATUS.md.

**Experimental (never run against a real host).** Windows WinRM audit, UDP stage, RHEL-family audit, macOS audit over SSH.
