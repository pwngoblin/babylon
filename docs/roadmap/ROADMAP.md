# Roadmap

What is built is in [STATUS.md](STATUS.md). This file is what to build next, ordered by how much it improves the scanner for real use. No dates: pick from the top.

Rule for every item: non-destructive by default, opt-in flags for anything intrusive, tests with a mock target, no Greenbone/Tenable content.

## Tier 1: find more real vulnerabilities

1. **Web-app scan mode (DAST-lite).** Biggest known miss: DVWA and Juice Shop SQLi/XSS are not found today.
   - Crawler (same host only, depth and request caps, respects the scope file).
   - Passive checks on every response: cookie flags, CORS, missing headers, error leaks, secrets in JS, directory listings, exposed files.
   - JS library versions (retire.js-style) feed the CVE matcher.
   - `--allow-active` checks with harmless canaries: reflected input, error-based SQLi signals, open redirect, path traversal read of a known file. No writes, no data extraction.
   - Optional login (form or token from env) so authenticated pages are covered.
2. **Exploit availability.** Tag findings with ExploitDB, Metasploit module and public-PoC info (metadata only, no exploit code), and use it in ranking next to KEV and EPSS. Biggest help for "fix this first".
3. **Windows credentialed audit**: built (WinRM, MSRC patches, 15 rules) but untested against a real Windows host. Next: run it on a Windows VM, add software-vs-CVE matching and more rules. WinRM (HTTPS, cert checked), installed KBs and software against MSRC data, plus registry/service hardening rules. Same pattern as the SSH audit.
4. **More native checks (target 100).** First batch done (see STATUS.md: network services, Windows unauthenticated, SNMP, TLS, MySQL/Postgres, Docker audit). Still open: SMB signing and null sessions, LDAP signing, SNMP default community (read only), SSH weak algorithms and old protocol, TLS certificate expiry and weak ciphers as proper findings, exposed databases and message brokers (Mongo, Memcached, RabbitMQ, MQTT), NTP/DNS misconfig. Each with a mock-listener test.
5. **Containers and lockfiles on audited hosts.** Run Trivy-style matching on images and `package-lock`/`go.sum`/`requirements.txt` found over SSH.
6. **macOS audit.** Patch level and Homebrew packages against advisory data, plus hardening checks.

## Tier 2: fewer false alarms, more trust

7. **Ground-truth lab with expected findings.** A manifest per lab container; a test command prints recall and false-positive rate. Run it before each release so detection quality is measured, not guessed.
8. **Distro-aware banner matching.** When the banner shows a distro build (for example `OpenSSH 8.9p1 Ubuntu-3ubuntu0.6`), look up that distro's tracker instead of upstream NVD ranges. Cuts the largest class of false positives.
9. **Better OS and service identification.** Use TLS certificates, HTTP favicons and headers, SSH key types and SMB info to fill in unknown services (Juice Shop shows as "unknown" today).
10. **Triage workflow.** Mark a finding as accepted risk or false positive with a reason and an expiry; it stays hidden in later scans and reappears when it expires.
11. **Verify steps.** For findings with a safe confirming probe, run it and promote the finding from `tentative` to `confirmed`.

## Tier 3: daily use

12. **Scheduler and trends.** Run saved scans on a schedule; dashboard with new/resolved findings over time and per-asset risk.
13. **Asset inventory.** Tags, owner, criticality; risk score uses criticality.
14. **Credentials in the UI.** Enter SSH or WinRM credentials per scan in the browser, held in memory only.
15. **Notifications and integrations.** Webhook/email on new critical or KEV finding; export to SARIF, Jira/GitHub issues, `.nessus` import/export.
16. **Compliance packs.** CIS-lite hardening sets for Linux and Windows with pass/fail/unknown per control.
17. **Remote scan agents.** Run scans from another network segment and collect results centrally.

## Tier 4: engineering health

18. **CI and releases.** GitHub Actions for build, test (Linux, macOS, Windows), `govulncheck`, `staticcheck`, and tagged releases with checksums, SBOM and signatures.
19. **Run on Windows and Linux for real.** Windows has never been executed; RHEL-family audits and the UDP stage are unit-tested only.
20. **Scale proof.** A simulated 500+ host run that is killed and resumed, to confirm the 16-host chunk and host-timeout fixes.
21. **Fuzz the parsers.** Nmap XML, Nuclei JSON, OSV, NVD and SSH output parsers take untrusted input.
22. **Feed health.** `doctor` warns when feeds are stale; record feed versions in each scan so old reports can be explained.
23. **Faster scans.** Only run `ssl-*` scripts where TLS is plausible (they hang about 30 s on non-TLS ports today); smarter template selection.
24. **Backup and export of the database.** One command to back up or move `~/.babylon`.

## Not planned
Exploitation, brute forcing by default, denial-of-service checks, any use of Greenbone or Tenable content.
