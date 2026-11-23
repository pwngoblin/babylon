# Babylon

A free vulnerability scanner for your own network. Latest release: [v0.1.1](https://github.com/pwngoblin/babylon/releases/latest) (binaries for macOS, Linux and Windows, with checksums, SBOM and signature). Think Nessus, but open source, runs on your laptop, and keeps everything local.

Point it at IPs or a subnet. It finds hosts, open ports and software versions, looks up known vulnerabilities, and gives you a report that says what to fix first.

## Install

Download a binary from the releases page, or build from source. You need Go 1.27+, [nmap](https://nmap.org) and [nuclei](https://github.com/projectdiscovery/nuclei). `trivy` is optional.

```
git clone https://github.com/pwngoblin/babylon
cd babylon
go build -o babylon ./cmd/babylon
./babylon doctor          # checks your tools
./babylon update-feeds    # downloads vulnerability data (first run is slow, ~30 min)
```

## Use

**No command line needed for scanning:** run `./babylon serve`, open the link it prints, and start, watch, compare and export scans from the browser. It only listens on your own machine. (Credentialed SSH scans are still CLI-only for now.)

Or use the CLI:

```
./babylon scan 192.168.1.0/24                 # scan a network
./babylon scan 10.0.0.5 --timing fast-lan     # quicker, for local networks
./babylon scan 10.0.0.5 --deep                # run every safe check (finds more, much slower)
./babylon serve                               # web UI (open the link it prints)
./babylon scans list                          # past scans
./babylon scans export 3 --format html -o report.html    # also: md, json, csv, pdf
```

Scan a Linux server **with a login** for much better results (finds missing patches exactly, plus config problems):

```
export PW='your-ssh-password'
./babylon scan 10.0.0.5 -t credentialed --ssh-user audit --ssh-password-env PW --trust-new-hosts
```

Scan a **Windows** host over WinRM (missing Microsoft updates plus security settings):

```
./babylon update-feeds --only msrc            # Microsoft fix data (about 30 MB per month)
export WPW='your-windows-password'
./babylon scan 10.0.0.8 -t credentialed --winrm-user scanner --winrm-password-env WPW --winrm-insecure-tls
```

Add your own checks as YAML in `~/.babylon/checks/` (`babylon checks validate`, `babylon checks test`; see `internal/pack/builtin` for examples).

Keep track over time: `babylon trend` shows new and resolved findings per scan. `babylon triage add 42 --status accepted-risk --reason "patch window" --expires 90d` hides a finding until it expires. `babylon assets set 10.0.0.5 --criticality high` ranks that host's findings higher; `--fragile` stops active probes against it.

Get told only about change: put a webhook in `~/.babylon/notify.yaml` (see `babylon notify test`) and scheduled scans post just the new findings.

Compliance view: `scans export 3 --compliance pci-dss-4` adds a per-control section (also `nist-800-53`, `iso-27001`). The mapping is Babylon's own, an evidence aid and not an assessment.

Audit a **database** (PostgreSQL, MySQL/MariaDB) with a read-only login:

```
export DBPW='the-password'
./babylon scan 10.0.0.20 -t credentialed --db-user auditor --db-password-env DBPW
```

The audit refuses to send the password without TLS unless you add `--db-allow-plaintext`.

Other outputs: `scans export 3 --format nessus -o scan.nessus` gives a `.nessus` file. Schedules: pick "Repeat" when you start a scan in the web UI.

## What it does

- **Finds** hosts, ports, services and TLS problems (Nmap).
- **Checks** web apps and services for known CVEs and misconfigurations (Nuclei plus its own checks).
- **Matches** software versions to CVEs (NVD), and marks how sure it is: `confirmed`, `firm` or `tentative`.
- **Logs in over SSH** (read-only) to compare installed packages with distro advisories (OSV) and run about 30 hardening checks (accounts, services, network and kernel settings, Docker).
- **Logs in to a Mac over SSH** (read-only) to find missing macOS updates (Apple security releases) and check 9 security settings. Run `update-feeds --only apple` first.
- **Logs in to PostgreSQL and MySQL/MariaDB** (read-only) to check TLS, authentication and account settings (15 rules).
- **Logs in to Windows over WinRM** (read-only) to find missing Microsoft updates (MSRC data) and check 15 security settings.
- **Ranks** results by actively exploited (CISA KEV), public exploit availability (Exploit-DB, Metasploit; metadata only), severity and exploit likelihood (EPSS).
- **Shows** results in a local web UI with filters and sortable columns.
- **Groups** results: "upgrade OpenSSL, fixes 24 CVEs" instead of 24 separate rows.

## Good to know

- Safe by default: no exploits, no denial-of-service. Intrusive checks need explicit flags.
- Public IP addresses are refused unless you add `--i-have-authorization`. Only scan what you own or may test.
- Want a hard limit? Put allowed IPs/CIDRs (one per line) in `~/.babylon/scope.txt`. Babylon then refuses to scan anything outside that list.
- Everything is stored in `~/.babylon/babylon.db`. Passwords are never saved.
- It does not use Nessus or OpenVAS/Greenbone vulnerability content (licensing), so it will not match them on every check.
- Beta. What is verified on real systems and what is not:

  | Area | State |
  |---|---|
  | Network scan, native checks (~36), CVE matching | measured on a 28-service lab: 19/19 expected findings, 0 false positives (`babylon lab run`) |
  | Linux audit over SSH (Debian, Ubuntu, Alpine) | verified against real containers |
  | Nuclei web/CVE templates | **stalls on some machines** (`babylon doctor` tells you); see [known issues](docs/known-issues.md) |
  | Windows (WinRM), macOS (SSH), RHEL-family audits, UDP stage | **experimental**: tested against fakes and mocks, not real hosts |

More detail: [ARCHITECTURE.md](ARCHITECTURE.md) · [status](docs/roadmap/STATUS.md) · [roadmap](docs/roadmap/ROADMAP.md) · [known issues](docs/known-issues.md) · [changelog](CHANGELOG.md) · License: Apache-2.0
