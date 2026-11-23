# Milestone 02: Credentialed Linux & macOS Audits (SSH Package & Hardening Engine)

## Goal
Implement agentless, read-only SSH credentialed scanning—the single highest-value capability in Nessus—to detect unpatched OS packages (with zero backport false positives via OSV.dev) and local configuration/hardening weaknesses.

## 1. Credential Profile & Vault Handling
- Support SSH authentication via private key path (with optional passphrase) or password passed via CLI flags / scan profile JSON (never persisted in plaintext in scan history tables; store only a reference/label).
- Enforce strict **read-only** command execution over native Go SSH (`golang.org/x/crypto/ssh`), with per-command timeouts (10s) and clean session teardown.

## 2. Host Fact Collector (Writes to Per-Host Knowledge Base)
When SSH credentials are attached to a target/scan profile, run a lightweight, deterministic collection phase before checks:
- **OS Identification:** Parse `/etc/os-release` (`ID`, `VERSION_ID`, `VERSION_CODENAME`) and `uname -srm`.
- **Installed Package Inventory:**
  - Debian/Ubuntu: `dpkg-query -W -f='${Package}\t${Version}\t${Status}\n'` (filter `install ok installed`).
  - RHEL/Alma/Rocky/Fedora: `rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n'`.
  - Alpine: `apk info -v`.
  - macOS: `sw_vers` + `brew list --versions` (if present).
- **System & Security Config Snapshots:**
  - Effective SSH daemon config (`sshd -T` fallback to `/etc/ssh/sshd_config`).
  - Firewall status (`ufw status`, `firewall-cmd --state`, `iptables -L -n`).
  - Listening sockets (`ss -tulpn` or `netstat -an`) to detect internal-only services bound to `127.0.0.1` or internal interfaces.
  - Sensitive file permissions (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, authorized_keys).
  - Running containers/runtimes (`docker info` / rootless podman if present).

## 3. Distro-Aware Package CVE Matching (`OSV.dev`)
- Match collected `(ecosystem, package_name, exact_distro_version)` against the local OSV SQLite index using proper distribution version comparison (`dpkg` epoch/upstream/debian_revision rules, `rpm` EVR rules, `apk` version rules).
- Mark matched unpatched packages as **`confirmed`** (since package versions are authoritative) and auto-suppress any earlier unauthenticated `tentative` banner guesses for the same service on that host.
- **Root-Cause Package Grouping:** Roll up all CVEs for a single outdated package into one actionable remediation card:
  - Title: `Outdated package: openssl (3.0.2-0ubuntu1.10 -> 3.0.2-0ubuntu1.15)`
  - Summary: Resolves N CVEs (Highest CVSS, KEV count, exact `apt/dnf/apk` upgrade command).

## 4. Local Hardening / Compliance Checks (CIS-Inspired Baseline)
Implement modular YAML or Go audit rules evaluated against the collected host facts:
- `SSH-001`: `PermitRootLogin` enabled (`yes` or `without-password` without restriction).
- `SSH-002`: `PasswordAuthentication yes` enabled alongside weak ciphers/MACs.
- `SSH-003`: `PermitEmptyPasswords yes` or `X11Forwarding yes`.
- `PERM-001`: World-writable `/etc/passwd` or overly permissive `/etc/shadow`.
- `FW-001`: Host firewall inactive/disabled with non-loopback listening services.
- `KERN-001`: Unprotected sysctl parameters (`net.ipv4.ip_forward=1` on non-router, `kernel.dmesg_restrict=0`).
- `SVC-001`: Unauthenticated internal services exposed on `0.0.0.0` (e.g., Docker socket/TCP API, Redis, databases).

## Acceptance Criteria
1. Credentialed scan against an Ubuntu/Debian/Alpine Docker container accurately enumerates all installed packages and flags known unpatched CVEs as `confirmed` with zero false positives on patched packages.
2. Root-cause grouping collapses multi-CVE packages into single remediation items in both CLI and Web UI.
3. Hardening checks flag weak `sshd_config` and file permission issues with clear evidence snippets and remediation commands.