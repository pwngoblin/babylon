# Roadmap

What is built is in [STATUS.md](STATUS.md). The plan for closing the gap to Nessus (tracks, order, architecture) is in [PLAN.md](PLAN.md). This file is what to build next, in order. No dates: pick from the top.

Rule for every item: non-destructive by default, opt-in flags for anything intrusive, tests with a mock target, no Greenbone/Tenable content.

## Next

1. **Grow the check packs to 100+ checks** (plan track T1; 42 pack checks and 46 Go checks exist). Infrastructure services only; each with fixtures.
2. **Active Directory.** True anonymous (null) SMB sessions (the SMB library only supports guest logins), LDAP signing and AD hardening need credentials. (SMB guest access and share listing are built.)
3. **More integrations.** Email, SARIF export, Jira/GitHub issues; `.nessus` import (export and webhook are built).
4. **Credentialed breadth** (plan track T4): collect device configs over SSH, Juniper/Fortinet/Palo Alto rule sets (a Cisco IOS file audit is built), per-engine database credentials, SQL Server/Oracle/MongoDB. (PostgreSQL and MySQL/MariaDB audits are built.)
5. **Proof and scale** (plan track T5): synthetic 5,000-host scale test, real-host matrix (Windows, Rocky, macOS over SSH, home LAN).
6. **Distro-aware banner matching.** Fewer tentative guesses on backported banners without credentials.
7. **Device identification and a home-network mode.** Name the device (router, camera, NAS), UPnP/ONVIF/RTSP checks, plain-language report. Needs discussion first.
8. **More native checks.** IKE aggressive mode, RabbitMQ/AMQP, Cassandra, DNS zone transfer, printers (JetDirect/IPP).
9. **macOS audit: Homebrew packages.** Match installed Homebrew formulae against advisory data (no OSV ecosystem exists; needs a CPE-style match with a confidence tier).
10. **Feed health and database backup.** `doctor` warns when feeds are stale; record feed versions in each scan; one command to back up or move `~/.babylon`.
11. **Faster scans.** Only run `ssl-*` scripts where TLS is plausible (they hang about 30 s on non-TLS ports today); smarter template selection.
12. **Containers and lockfiles on audited hosts.** Trivy-style matching on images and `package-lock`/`go.sum`/`requirements.txt` found over SSH.

## Later
- Windows CI: fix the shell-script test fakes, the 30 s process-group kill and the pin-file permission check (docs/known-issues.md).
- Re-measure the 6 Nuclei-dependent lab expectations and TFTP on a machine where Nuclei does not stall.
- Run on Windows and Linux for real. Windows (binary and WinRM audit) has never been executed; RHEL-family audits, the UDP stage and the native probes are unit/mock-tested only.

## Not planned (decided)
- Web-app scanning (DAST): lives in another project.
- Exploitation, brute forcing by default, denial-of-service checks, any use of Greenbone or Tenable content.
- Dropped for now: remote agents, scale proof, parser fuzzing, per-control compliance report, credentials in the UI, better service identification (beyond the lab-driven fixes).
