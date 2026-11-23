# Roadmap

What is built is in [STATUS.md](STATUS.md). This file is what to build next, in order. No dates: pick from the top.

Rule for every item: non-destructive by default, opt-in flags for anything intrusive, tests with a mock target, no Greenbone/Tenable content.

## Next

1. **More native checks (target 100; ~36 done).** Still open: SMB null sessions and share listing (needs an SMB client), LDAP signing requirement, IKE aggressive mode (needs a valid group id, not reliably detectable blind), RabbitMQ/AMQP checks, more databases and brokers (Cassandra, Kafka, Hadoop HDFS), DNS zone transfer, SSDP/UPnP, printers (JetDirect/IPP). Each with a mock-listener test.
2. **macOS audit: Homebrew packages.** Patch level and hardening are done. Still open: match installed Homebrew formulae against advisory data (no OSV ecosystem exists; needs a CPE-style match with a confidence tier).
3. **Notifications and integrations.** Webhook/email on new critical or KEV finding; export to SARIF, Jira/GitHub issues; `.nessus` import (export is built).
4. **CI and releases.** GitHub Actions for build and test (Linux, macOS, Windows), `govulncheck`, `staticcheck`, and tagged releases with checksums, SBOM and signatures.
5. **Feed health and database backup.** `doctor` warns when feeds are stale; record feed versions in each scan; one command to back up or move `~/.babylon`.
6. **Faster scans.** Only run `ssl-*` scripts where TLS is plausible (they hang about 30 s on non-TLS ports today); smarter template selection.
7. **Containers and lockfiles on audited hosts.** Trivy-style matching on images and `package-lock`/`go.sum`/`requirements.txt` found over SSH.

## Later
- Run on Windows and Linux for real. Windows (binary and WinRM audit) has never been executed; RHEL-family audits, the UDP stage and the native probes are unit/mock-tested only.

## Not planned (decided)
- Web-app scanning (DAST): lives in another project.
- Exploitation, brute forcing by default, denial-of-service checks, any use of Greenbone or Tenable content.
- Dropped for now: Windows audit live testing and software-vs-CVE matching, probe tests against real services, ground-truth lab, distro-aware banner matching, better service identification, triage and verify steps, asset inventory, credentials in the UI, trends dashboard, per-control compliance report, remote agents, scale proof, parser fuzzing.
