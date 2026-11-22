# Babylon

A local-first, open-source vulnerability and configuration scanner with Nessus-style scan policies and client-ready reports, built entirely on open data and tools.

> **Status: pre-alpha (Phase 0 complete, Phase 1 in progress).** There is no usable scanner yet. What exists: the project skeleton, a safe subprocess runner, the SQLite schema with a batched single-writer, the policy/safety layer, a resumable job orchestrator, the Nmap engine with a hardened XML parser, a working `babylon scan` that finds real vulnerabilities (Nmap + Nuclei + built-in checks, merged across engines), a template index, and a measured coverage spike. See [Roadmap](#roadmap).

## What it will be

One command from targets to a prioritized report:

```
babylon update-feeds
babylon scan 10.0.0.0/22 --template basic
babylon scan hosts.txt --template credentialed --creds creds.toml
babylon report --format html,md,json
```

**Detection sources** (all open, all local after `update-feeds`):

| Source | Role |
|---|---|
| Nmap + curated safe NSE | discovery, fingerprinting, TLS |
| Nuclei + nuclei-templates | web/network CVEs, exposures, misconfigurations |
| CPE→CVE matcher (NVD, cvelistV5, CISA Vulnrichment, KEV watch) | broad, lower-confidence version-based findings |
| Native checks (Go + YAML) | misconfigurations CVE feeds miss (no-auth Redis, SSH algorithms, ...) |
| Credentialed audits (SSH / WinRM) with OSV, MSRC, Apple data | authoritative, backport-aware missing-patch detection for Linux, macOS, Windows |
| CISA KEV, EPSS | prioritization |

**What makes it different**
- **Honest confidence:** every finding is `confirmed`, `firm` or `tentative`. A version-only match never masquerades as a verified one.
- **Root-cause grouping:** "upgrade OpenSSL, fixes 24 CVEs" instead of 24 rows.
- **Safe by construction:** engine configs are built only from allowlists; denied categories are unreachable and covered by tests.
- **Built for scale:** chunked, resumable scans designed for 500+ hosts.
- **Client-ready reports:** self-contained HTML with an executive summary and branding.

It does **not** use the Greenbone/OpenVAS feed or any Tenable/Nessus content (licensing), so unauthenticated plugin depth will trail those products. Credentialed scanning is where most coverage comes from. See [docs/coverage-spike.md](docs/coverage-spike.md) for measured numbers.

## Try what exists

Requires Go 1.27+, and `nmap` and `nuclei` on your PATH (`trivy` optional).

```
go build -o babylon ./cmd/babylon
./babylon doctor
./babylon update-feeds                       # download + index Nuclei templates
./babylon scan 192.168.1.0/24 -t basic        # discovery, ports, services, TLS, vulnerabilities
./babylon scan --resume 3                    # resume an interrupted scan
go test ./...          # add -short to skip the 3,000-job scale test
```

### Test lab (optional)

`deploy/lab/` has deliberately vulnerable containers for measuring coverage. They bind to `127.0.0.1` only.

```
docker compose -f deploy/lab/docker-compose.yml up -d
```

**Never expose the lab to a network.**

## Documentation

- [PRODUCT.md](PRODUCT.md): goals, non-goals, templates, decisions log
- [ARCHITECTURE.md](ARCHITECTURE.md): pipeline, engines, SQLite schema, safety model, risks
- [docs/nessus-methodology.md](docs/nessus-methodology.md): researched how Nessus finds vulnerabilities and how Babylon maps to it
- [docs/coverage-spike.md](docs/coverage-spike.md): Phase 0 measurements and what they changed
- [CLAUDE.md](CLAUDE.md): project brief used to guide development

## Roadmap

1. **Phase 0 (done):** skeleton, runner, schema, lab, coverage and NVD-ingest spikes.
2. **Phase 1 (in progress):** policy and safety (done), orchestrator with chunking, retries and resume (done), Nmap engine and `babylon scan` (done), Nuclei engine with service-aware template selection (done), native Nessus-style checks (done), CPE matcher, feeds, correlation, HTML/Markdown/JSON reports.
3. **Phase 2:** credentialed audits (Linux, containers, macOS, Windows), root-cause grouping, scan diffing, hardening checks.
4. **Phase 3:** more native checks, `.nessus` import/export, remote agents, scheduling.

## Responsible use

Scan only systems you own or are explicitly authorized to test. Babylon refuses public address ranges unless you pass an explicit authorization flag, runs non-destructive checks only, and keeps anything more intrusive behind opt-in flags. You are responsible for how you use it.

## License

[Apache-2.0](LICENSE). Nmap, Nuclei and Trivy are separate programs invoked as subprocesses under their own licences.
