# Changelog

## 0.2.0-beta (unreleased)

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
