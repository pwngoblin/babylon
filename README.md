# Babylon

A free vulnerability scanner for your own network. Think Nessus, but open source, runs on your laptop, and keeps everything local.

Point it at IPs or a subnet. It finds hosts, open ports and software versions, looks up known vulnerabilities, and gives you a report that says what to fix first.

## Install

You need Go 1.27+, [nmap](https://nmap.org) and [nuclei](https://github.com/projectdiscovery/nuclei). `trivy` is optional.

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

## What it does

- **Finds** hosts, ports, services and TLS problems (Nmap).
- **Checks** web apps and services for known CVEs and misconfigurations (Nuclei plus its own checks).
- **Matches** software versions to CVEs (NVD), and marks how sure it is: `confirmed`, `firm` or `tentative`.
- **Logs in over SSH** (read-only) to compare installed packages with distro advisories (OSV) and check settings like `sshd_config`.
- **Ranks** results by actively exploited (CISA KEV), severity and exploit likelihood (EPSS).
- **Shows** results in a local web UI with filters and sortable columns.
- **Groups** results: "upgrade OpenSSL, fixes 24 CVEs" instead of 24 separate rows.

## Good to know

- Safe by default: no exploits, no denial-of-service. Intrusive checks need explicit flags.
- Public IP addresses are refused unless you add `--i-have-authorization`. Only scan what you own or may test.
- Want a hard limit? Put allowed IPs/CIDRs (one per line) in `~/.babylon/scope.txt`. Babylon then refuses to scan anything outside that list.
- Everything is stored in `~/.babylon/babylon.db`. Passwords are never saved.
- It does not use Nessus or OpenVAS/Greenbone vulnerability content (licensing), so it will not match them on every check.
- Early software. Expect rough edges.

More detail: [ARCHITECTURE.md](ARCHITECTURE.md) · [status](docs/roadmap/STATUS.md) · [roadmap](docs/roadmap/ROADMAP.md) · License: Apache-2.0
