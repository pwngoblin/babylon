# Known issues

## Nuclei stalls on some machines

**Symptom.** A scan sits in the `nuclei-detect` or `nuclei-scan` stage for a long time, or `babylon doctor` reports
`nuclei self-test: FAIL ... did not complete`. Running `nuclei` by hand with three or more templates against any
local web server never exits, uses almost no CPU, and prints nothing.

**What is known (Nuclei v3.11.1, macOS arm64, Go 1.27).**
- It is the Nuclei process, not Babylon, Docker or the target: it reproduces against a plain Python web server.
- One or two templates finish in milliseconds; three or more stall. Concurrency, rate limit, scan strategy,
  resolver, clustering, retry and memory-guard options make no difference. A fresh `HOME` and a clean environment
  make no difference.
- A goroutine dump (`kill -QUIT`) shows the engine waiting on a worker group whose workers no longer exist, so this
  looks like a defect inside Nuclei's work pool rather than slow requests.

**What Babylon does about it.**
- Templates run in batches of 100 with a deadline each. A batch that stalls is split until the stuck template is
  isolated and skipped; skipped templates are listed in the scan coverage (`nuclei-stalled-templates`).
- After four stalls in a row the job fails with a clear message instead of holding the scan for 45 minutes.
- `babylon doctor` runs a short self-test and fails when Nuclei cannot finish a 12-template run.

**What you can try.** Scans on the same machine and Nuclei version completed earlier the same day, so the trigger is
not yet understood. Try a different Nuclei release (untested here) or another machine. Everything that does not use Nuclei (Nmap, native checks, CVE matching, credentialed audits,
reports) is unaffected.

## Windows

The first real Windows run (GitHub Actions, 2026-11-23) built the binary and ran most unit tests, but several tests fail there:
- Many pipeline, Nuclei and web tests use `#!/bin/sh` scripts as stand-ins for `nmap` and `nuclei`; those cannot run on Windows.
  This is a test-harness limit, not a product defect, but it means Windows behaviour of the scan pipeline is unverified.
- `TestTimeoutKillsProcessGroup`: killing a process group took 30 s on Windows. This may be a real defect in the
  `taskkill` path and needs checking on a Windows host.
- `TestSSHHostKeyPolicyAndRun`: the pinned-host-key file permission check does not hold on Windows file modes.

The Windows CI job is therefore non-blocking, and Windows remains experimental.
