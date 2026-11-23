# Plan: closing the gap to Nessus

Written 2026-11-23. Honest starting point: about a third of Nessus's value. The workflow and prioritisation are close. The gaps are check breadth, credentialed depth outside Linux, compliance, scale and proof on real hosts.

## What Nessus is made of, and what we do about each part

| Nessus strength | Babylon gap | Open-data answer | Track |
|---|---|---|---|
| ~200k plugins | ~36 native checks, Nuclei, NVD matching | Declarative check packs anyone can write and test; vendor advisories (CSAF) | T1, T3 |
| Compliance audits (CIS, DISA, PCI) | ~30 rules, no control mapping, no per-control report | Map rules to NIST 800-53, PCI DSS 4.0, ISO 27001 controls; per-control report; STIG-style checks as packs | T2 |
| Credentialed depth (Windows, DBs, network gear) | Linux good; Windows/macOS unproven; no DB or device audits | Read-only DB audits (PostgreSQL, MySQL), network-device config audits over SSH | T4 |
| Scale and trust | one host plus a 28-container lab; Nuclei stalls here | Synthetic scale harness, real-host verification matrix, Nuclei version guard | T5 |
| Operations (assets, triage, trends, notifications) | none | Inventory, criticality, triage with expiry, trend view, webhooks | T6 |

## Rules for all tracks
1. Nothing counts as done until the lab or a real host measures it. Each track has an exit test.
2. Safety is enforced in code, not by convention: nothing above probe level can load; denied behaviour is unreachable and tested.
3. Every new check carries its own positive and negative test fixture.
4. Scope: infrastructure only. Web-application testing (crawling, fuzzing, content discovery such as `.git`/`.env` hunting, injection checks) belongs to the separate Wire project. The pack `http` transport sends fixed GET/HEAD/OPTIONS paths to management interfaces and services, with no crawling, parameters or payloads, and checks that read like web-app testing are not added.
5. No Greenbone or Tenable content. Controls are our own mapping and are labelled as such. CIS benchmark text and numbering are not copied.

## Tracks, in order

### T1. Check packs (the breadth multiplier) — building now
Checks become data. A pack is a YAML file of checks, each with its own test fixtures. This turns "write Go for every check" into "write 20 lines of YAML", which is how Nessus reached its size.
- Kinds: `passive` (matches data the scan already has: banner, product, version, NSE output; no traffic) and `probe` (tcp, udp or http exchanges against a service already found open; needs `--allow-active`).
- Hard limits in code: only the scanned host and its open ports, GET/HEAD/OPTIONS only for http, bounded bytes, steps and time, nothing above probe level.
- Built-in packs are embedded in the binary. Users add packs in `~/.babylon/checks/`. `babylon checks list|validate|test` validates schema and runs every fixture.
- Exit: 60+ pack checks, every one with passing fixtures; total checks above 100.

### T2. Compliance
- Every check and audit rule can carry `controls:` (framework:id).
- Scan option `--compliance nist-800-53|pci-dss-4|iso-27001`, and a per-control report section: pass, fail, not assessed, with the evidence.
- Exit: a credentialed scan of a lab host produces a per-control report; unmapped rules are listed, not hidden.

### T6. Operations (asset inventory, triage, trends, notifications)
Already agreed; moved up because inventory is needed by the home-network and change-detection uses.
- Exit: scheduled scan emails or posts only new and reopened findings; accepted risk expires.

### T4. Credentialed breadth
- Databases: PostgreSQL and MySQL read-only audits (version, auth settings, TLS, exposed roles).
- Network devices: Cisco IOS, Juniper, Fortinet config audits over SSH.
- Exit: each verified against a real container or device config sample.

### T3. Advisory breadth
- CSAF ingestion (open vendor advisories) for products where NVD CPE data is poor.
- Exit: lab appliance sample gets a vendor-advisory finding that NVD matching missed.

### T5. Proof and scale (continuous)
- Scale harness: synthetic 5,000-host scan through the real orchestrator and store with fake engines. Find the first thing that breaks.
- Real-host matrix: Windows, Rocky/RHEL, macOS over SSH, a home LAN. Results go in the README table.
- Nuclei: version compatibility guard in `doctor`, and a documented known-good version.

## Progress (2026-11-23)

| Track | State |
|---|---|
| T1 check packs | engine, `babylon checks`, 42 pack checks built; target 60+ pack checks (100+ total) not reached: 88 total |
| T2 compliance | built: NIST 800-53, PCI DSS 4.0, ISO 27001 per-control report; every check mapped |
| T6 operations | built: triage with expiry, asset criticality and fragile flag, trends, webhook notifications; web UI pages built; email not built |
| T4 credentialed breadth | PostgreSQL and MySQL/MariaDB audits built and verified on real servers; Cisco IOS config-file audit built (sample configs only); SSH collection and other vendors not built |
| T3 vendor advisories (CSAF) | not started |
| T5 proof and scale | synthetic 5,000-host store/report test passes (two slow queries fixed); real-host matrix and engine-level scale not done |

## Architecture additions

```
YAML packs (embedded + ~/.babylon/checks)
        |  parse + validate (schema, limits, regexes compile)
        v
 internal/pack ---- compile ----> native.Check { Safety, Needs, Run }
        |                                  |
        | fixtures (tests:)                v
        v                         existing native runner:
 `babylon checks test`            dependency order, skip reasons, findings,
 (mock server per fixture)        check_run rows, fingerprints, redaction
```

The pack layer compiles to the existing `native.Check`, so ordering, skip reasons, coverage reporting, fingerprints and redaction need no new code. Later tracks reuse it: audit rules get the same `controls:` field, and T4 audits plug into the same check-run reporting.

### Pack format (schema 1)
```yaml
schema: 1
checks:
  - id: BBL-HTTP-0001            # unique, upper case
    name: Short plugin name
    family: Web Servers
    severity: high               # info|low|medium|high|critical
    kind: probe                  # passive | probe
    when: { ports: [8080], services: [http] }   # either matches
    transport: http              # tcp | udp | http (probe only)
    steps:
      - http: { method: GET, path: /admin, tls: auto }
        expect: { status: 200, body: "Admin Console" }
    finding:
      title: ...
      synopsis: ...
      description: ...
      remediation: ...
      cves: []
    controls: ["NIST-800-53:CM-7"]
    tests:
      - name: exposed
        responses: [{ status: 200, body: "<title>Admin Console</title>" }]
        want: finding
      - name: patched
        responses: [{ status: 403, body: "" }]
        want: none
```
