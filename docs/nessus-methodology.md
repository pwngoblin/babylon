# How Nessus finds vulnerabilities, and how Babylon implements the same ideas

Research date: 2026-11-22. Sources are Tenable's public documentation and blog posts (linked below). Nessus's plugin source is proprietary, so internals beyond what Tenable documents are marked **[general knowledge]** and should be treated as informed assumptions. Babylon copies the *method*, never Tenable content.

## 1. The mechanism

### 1.1 Phases
A scan is a pipeline, not one big probe. Per Tenable's ["Phases of a vulnerability scan"](https://connect.tenable.com/kb/tenable-connect-support/phases-of-a-vulnerability-scan/110111):

1. **Host discovery.** Ping each target (plugin 10180) and decide whether it is alive. Dead hosts are skipped.
2. **Port scanning.** Port-scanner plugins (TCP connect, SYN, UDP, and credentialed netstat variants) enumerate open ports.
3. **Service detection.** Plugins such as 22964 probe each open port and identify the actual protocol/application, regardless of port number.
4. **Vulnerability checks.** Thousands of plugins run, but only those *relevant* to what phases 1-3 found.
5. **Local (credentialed) checks**, if credentials work.

### 1.2 Plugins, dependencies and the knowledge base
Plugins are small programs (NASL, [overview](https://docs.tenable.com/nessus/10_12/Content/AboutNessusPlugins.htm)) with a metadata header: unique ID, version, family, CVE/CPE references, severity, **dependencies** and **required ports/keys**. Example from Tenable's docs: a patch-check plugin declares `script_dependencies("smb_hotfixes.nasl", ...)` and `script_require_ports(139, 445, ...)`, and Tenable's plugin pages list every plugin's *dependents*.

The glue is a per-host **knowledge base (KB)**: earlier plugins record facts (open ports, detected service per port, OS, banners, "credentialed checks possible"), and later plugins read them. A plugin runs only if the KB says its precondition holds. This is why Nessus is both fast (no HTTP checks against a non-HTTP port) and accurate (checks are service-aware, not port-number-aware). **[general knowledge for KB mechanics; dependencies/required-ports are documented.]**

### 1.3 Plugin categories and safe checks
Each plugin has a category (INIT, SETTINGS, GATHER_INFO, ATTACK, MIXED_ATTACK, DENIAL, DESTRUCTIVE_ATTACK, KILL_HOST, FLOOD, ...). With **Safe Checks** enabled, the DENIAL, DESTRUCTIVE_ATTACK, KILL_HOST and FLOOD categories are disabled ([source](https://connect.tenable.com/kb/tenable-connect-support/phases-of-a-vulnerability-scan/110111)). Categories also give an execution order: setup, then information gathering, then probes.

### 1.4 Remote checks: version inference vs. behaviour
Unauthenticated plugins either (a) **infer** a vulnerability from a banner/version, or (b) **observe behaviour** (send a request, check the response). Banner inference breaks on distributions that **backport** fixes without changing the version string. Tenable's informational plugins ([FTP 39519](https://www.tenable.com/plugins/nessus/39519), [SSH 39520](https://www.tenable.com/plugins/nessus/39520), [WWW 39521](https://www.tenable.com/plugins/nessus/39521), [PHP 84574](https://www.tenable.com/plugins/nessus/84574)) state that banner-based checks are *disabled* when backporting is detected, to avoid false positives. Tenable also describes a backport mapping that translates distro banners to real patched versions ([blog](https://www.tenable.com/blog/advantages-of-running-both-network-authenticated-nessus-scans)).

### 1.5 Report accuracy and thoroughness
Historically "Report paranoia" (Avoid false alarms / Normal / Paranoid); in current versions "Report accuracy": *Avoid potential false alarms* (do not report if any uncertainty) vs *Show potential false alarms* ([Assessment settings](https://docs.tenable.com/nessus/Content/AssessmentSettings.htm)). Separate switches control **thorough tests** (plugins "work harder", off by default, more intrusive), **CGI scanning** and **generic web-application tests** (off by default).

### 1.6 Credentialed (local) checks
With SSH/SMB/WinRM credentials Nessus asks the host itself: it retrieves the OS-native package/patch inventory (rpm, dpkg, ...) and compares it with advisory data, which "overcomes false positives caused by back-ported security fixes" ([docs](https://docs.tenable.com/nessus/10_9/Content/NessusCredentialedChecks.htm), [blog](https://tenable.com/blog/linuxunix-patch-auditing-using-nessus)). Plugin 19506 reports whether credentialed checks actually ran, so a failed login is visible instead of silently yielding "no findings". Coverage depends on the account's privileges.

## 2. Mapping to Babylon

| Nessus mechanism | Babylon implementation | Status |
|---|---|---|
| Phases: discovery → ports → service detection → checks | Stage DAG: `sweep → portscan → (nuclei, native) → correlate` | sweep, portscan done; nuclei/native in progress |
| Per-host **knowledge base** | `kb` table (scan, asset, key → JSON, source). Engines write facts (services, OS, TLS, banners); checks read them | in progress |
| Plugin metadata: family, severity, dependencies, required ports | `native.Check` interface: ID, Family, Category, Safety, `Requires` (KB keys / service match), `DependsOn` (check IDs) | in progress |
| Dependency ordering | Topological sort of checks per host; a check whose dependency did not run or failed is skipped and recorded | in progress |
| Service-aware execution (not port-number-aware) | Checks match on detected service/product, not port; Nuclei targets and tags derive from detected services | in progress |
| Categories and Safe Checks | Policy allow/deny tables; `Safety` per check; denied levels unreachable and tested | done (policy), extended to checks |
| Banner inference vs behaviour | Every finding records *how* it was derived. Behavioural verification → `confirmed`; banner/version-only → `tentative` | in progress |
| Backport suppression | Banner version findings on distro-patched software (Debian/Ubuntu/RHEL markers in banner, `+deb`, `el7`, ...) are downgraded/annotated; credentialed audit overrides | planned with CPE matcher |
| Report accuracy | `accuracy` scan setting (`avoid_false_alarms`, `normal`, `show_all`) filters by confidence **at presentation time**; everything is stored | in progress |
| Thorough tests / generic web tests | Opt-in flags (`--thorough`, `--allow-active`), off by default | planned |
| Credentialed checks + "did it run" | `host_observation.auth_status`; reports list hosts where credentialed checks failed | schema ready, Phase 2 |
| Plugin families | `finding.family` (e.g. "Web Servers", "Misconfiguration", "Service detection") | in progress |
| Coverage transparency | Report lists per-host: ports scanned, engines run, checks skipped and why | planned |

## 3. Design consequences

1. **Run only what is relevant.** The spike showed unfiltered Nuclei takes 15+ minutes for 3 findings. Nessus solves this with dependencies and service awareness; Babylon does the same via KB-driven tag selection.
2. **Never store less than you found.** Accuracy settings filter the *view*, so a user can switch from "avoid false alarms" to "show all" without rescanning.
3. **Confidence is part of the finding.** A banner match and a verified behaviour are different claims and are reported differently.
4. **Be loud about blind spots.** Skipped checks, failed logins and unreachable engines are first-class results.

## Sources
- Tenable, [About Nessus Plugins](https://docs.tenable.com/nessus/10_12/Content/AboutNessusPlugins.htm)
- Tenable, [Phases of a vulnerability scan](https://connect.tenable.com/kb/tenable-connect-support/phases-of-a-vulnerability-scan/110111)
- Tenable, [Assessment Scan Settings](https://docs.tenable.com/nessus/Content/AssessmentSettings.htm)
- Tenable, [Credentialed Checks](https://docs.tenable.com/nessus/10_9/Content/NessusCredentialedChecks.htm)
- Tenable, [Advantages of running both network and authenticated scans](https://www.tenable.com/blog/advantages-of-running-both-network-authenticated-nessus-scans)
- Tenable, [Linux/UNIX patch auditing using Nessus](https://tenable.com/blog/linuxunix-patch-auditing-using-nessus)
- Tenable, [Using Nessus thorough checks](https://www.tenable.com/blog/using-nessus-thorough-checks-for-in-depth-audits)
- Tenable plugin pages: [39519](https://www.tenable.com/plugins/nessus/39519), [39520](https://www.tenable.com/plugins/nessus/39520), [39521](https://www.tenable.com/plugins/nessus/39521), [84574](https://www.tenable.com/plugins/nessus/84574)
