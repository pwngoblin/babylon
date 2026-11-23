package scan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"babylon/internal/audit"
	"babylon/internal/correlate"
	"babylon/internal/matcher"
	"babylon/internal/model"
	"babylon/internal/orchestrator"
	"babylon/internal/store"
)

const (
	StageAudit  = "audit"
	auditHostTO = 3 * time.Minute

	checkSSHAudit = "ssh-audit"
	checkPkgAudit = "ssh-package-audit"
)

// AuditConfig carries in-memory credentials for the credentialed stage. Creds
// are never persisted; Label is the only part recorded with the scan.
type AuditConfig struct {
	Creds    audit.Creds
	HostKeys audit.HostKeyPolicy
	// Connect opens a session to a host; nil uses SSH. Tests inject a fake.
	Connect func(ctx context.Context, host string) (audit.Runner, func(), error)
}

func (c *AuditConfig) connect(ctx context.Context, host string) (audit.Runner, func(), error) {
	if c.Connect != nil {
		return c.Connect(ctx, host)
	}
	s, err := audit.Dial(ctx, host, c.Creds, c.HostKeys)
	if err != nil {
		return nil, nil, err
	}
	return s, func() { s.Close() }, nil
}

func (c *AuditConfig) port() int {
	if c.Creds.Port != 0 {
		return c.Creds.Port
	}
	return 22
}

// auditStage runs the credentialed host audit: fact collection, authoritative
// package matching against OSV, and hardening rules. It runs after version
// matching so it can replace unverified banner guesses.
func auditStage(st *store.Store, cfg *AuditConfig, deps []string) orchestrator.Stage {
	return orchestrator.Stage{
		Name:      StageAudit,
		Class:     ClassNative,
		DependsOn: deps,
		Plan: func(ctx context.Context, sc store.Scan) ([]store.JobSpec, error) {
			svcs, err := st.OpenServices(ctx, sc.ID)
			if err != nil {
				return nil, err
			}
			live, err := st.LiveHosts(ctx, sc.ID)
			if err != nil {
				return nil, err
			}
			hasSSH := map[string]bool{}
			for _, s := range svcs {
				if s.Proto == "tcp" && s.Port == cfg.port() {
					hasSSH[s.Address] = true
				}
			}
			var hosts []string
			for _, h := range live {
				if hasSSH[h] {
					hosts = append(hosts, h)
					continue
				}
				if id, err := st.AssetID(ctx, h); err == nil {
					_ = st.RecordCheckRun(ctx, sc.ID, id, checkSSHAudit, "skipped", fmt.Sprintf("no open SSH service on port %d", cfg.port()))
				}
			}
			return chunkSpecs(hosts, 2, "audit", nil), nil
		},
		Handle: func(ctx context.Context, job store.Job) error {
			bg := context.WithoutCancel(ctx)
			for _, addr := range job.Targets {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				hctx, cancel := context.WithTimeout(ctx, auditHostTO)
				err := auditHost(hctx, bg, st, cfg, job.ScanID, addr)
				cancel()
				if err != nil {
					return fmt.Errorf("auditing %s: %w", addr, err)
				}
			}
			return nil
		},
	}
}

// auditHost audits one host. Host-side failures (auth, timeouts) are recorded
// as the host's audit result and do not fail the scan; only local storage
// errors are returned.
func auditHost(ctx, bg context.Context, st *store.Store, cfg *AuditConfig, scanID int64, addr string) error {
	assetID, err := st.AssetID(bg, addr)
	if err != nil {
		return err
	}
	fail := func(msg string) error {
		if err := st.SaveAudit(bg, scanID, store.AuditSession{AssetID: assetID, Result: "failed", Error: msg}, nil, nil); err != nil {
			return err
		}
		return st.RecordCheckRun(bg, scanID, assetID, checkSSHAudit, "error", msg)
	}
	run, closeFn, err := cfg.connect(ctx, addr)
	if err != nil {
		return fail(sanitizeErr(err, cfg.Creds))
	}
	defer closeFn()
	facts, err := audit.Collect(ctx, run)
	if err != nil {
		return fail(sanitizeErr(err, cfg.Creds))
	}

	eco, _ := facts.OS.Ecosystem()
	pkgs := make([]store.PackageRow, 0, len(facts.Packages))
	for _, p := range facts.Packages {
		pkgs = append(pkgs, store.PackageRow{Name: p.Name, Version: p.Version, Arch: p.Arch, SrcName: p.SrcName, SrcVersion: p.SrcVersion, Ecosystem: eco})
	}
	_ = st.SetKB(bg, scanID, assetID, "audit.credential", map[string]string{"label": cfg.Creds.Label, "user": cfg.Creds.User, "transport": "ssh"}, "audit")
	_ = st.SetKB(bg, scanID, assetID, "os.release", map[string]string{"id": facts.OS.ID, "version": facts.OS.VersionID, "codename": facts.OS.Codename, "kernel": facts.OS.Kernel}, "audit")
	if err := st.RecordCheckRun(bg, scanID, assetID, checkSSHAudit, "ran", strings.Join(facts.Errors, "; ")); err != nil {
		return err
	}

	// Package vulnerabilities.
	vulns, mstats, err := audit.MatchPackages(bg, st, facts)
	if err != nil {
		return err
	}
	if mstats.Unsupported != "" {
		if err := st.RecordCheckRun(bg, scanID, assetID, checkPkgAudit, "skipped", mstats.Unsupported); err != nil {
			return err
		}
	} else {
		reason := ""
		if mstats.Unfixed > 0 {
			reason = fmt.Sprintf("%d advisories without a vendor fix were not reported", mstats.Unfixed)
		}
		if n, _, _ := st.CountOSV(bg); n == 0 {
			reason = "no OSV data indexed (run: babylon update-feeds --only osv): results are incomplete"
		}
		for _, f := range packageFindings(bg, st, addr, vulns) {
			if err := st.RecordFinding(bg, scanID, f); err != nil {
				return err
			}
		}
		if err := st.RecordCheckRun(bg, scanID, assetID, checkPkgAudit, "ran", reason); err != nil {
			return err
		}
		if err := supersedeBannerGuesses(bg, st, scanID, addr, facts); err != nil {
			return err
		}
	}

	// Hardening rules.
	var cfgRes []store.ConfigResult
	for _, r := range audit.Rules {
		res := r.Eval(facts)
		switch res.Status {
		case audit.Unknown:
			cfgRes = append(cfgRes, store.ConfigResult{CheckID: r.ID, Result: "unknown", Evidence: res.Reason})
			if err := st.RecordCheckRun(bg, scanID, assetID, r.ID, "skipped", res.Reason); err != nil {
				return err
			}
			continue
		case audit.Fail:
			cfgRes = append(cfgRes, store.ConfigResult{CheckID: r.ID, Result: "fail", Evidence: res.Evidence})
			if err := st.RecordFinding(bg, scanID, ruleFinding(addr, r, res)); err != nil {
				return err
			}
		default:
			cfgRes = append(cfgRes, store.ConfigResult{CheckID: r.ID, Result: "pass", Evidence: res.Evidence})
		}
		if err := st.RecordCheckRun(bg, scanID, assetID, r.ID, "ran", ""); err != nil {
			return err
		}
	}

	result := "ok"
	if len(facts.Errors) > 0 || len(facts.Packages) == 0 {
		result = "partial"
	}
	return st.SaveAudit(bg, scanID, store.AuditSession{
		AssetID: assetID, Label: cfg.Creds.Label, OSFamily: facts.OS.ID, OSName: facts.OS.Pretty, OSVersion: facts.OS.VersionID,
		Kernel: facts.OS.Kernel, Ecosystem: eco, Result: result, Error: strings.Join(facts.Errors, "; "),
	}, pkgs, cfgRes)
}

// sanitizeErr keeps secrets out of stored error text.
func sanitizeErr(err error, c audit.Creds) string {
	s := err.Error()
	for _, secret := range []string{c.Password, c.Passphrase} {
		if len(secret) >= 3 {
			s = strings.ReplaceAll(s, secret, "***")
		}
	}
	return s
}

func installCmd(scheme string, bins []string) string {
	list := strings.Join(bins, " ")
	switch scheme {
	case "deb":
		return "apt-get update && apt-get install --only-upgrade " + list
	case "rpm":
		return "dnf upgrade " + list
	case "apk":
		return "apk upgrade " + list
	}
	return ""
}

// packageFindings turns package matches into one finding per (source package,
// CVE). Binary packages built from the same source collapse together and are
// listed in the upgrade command.
func packageFindings(ctx context.Context, st *store.Store, addr string, vulns []audit.PkgVuln) []model.Finding {
	type key struct{ src, ver, id string }
	type agg struct {
		v    audit.PkgVuln
		bins map[string]bool
	}
	by := map[key]*agg{}
	srcBins := map[string]map[string]bool{}
	var order []key
	var cveIDs []string
	for _, v := range vulns {
		id := v.CVE
		if id == "" {
			id = v.Advisory
		} else {
			cveIDs = append(cveIDs, v.CVE)
		}
		k := key{v.SrcName, v.Installed, id}
		a := by[k]
		if a == nil {
			a = &agg{v: v, bins: map[string]bool{}}
			by[k] = a
			order = append(order, k)
		}
		a.bins[v.Package.Name] = true
		sk := v.SrcName + "|" + v.Installed
		if srcBins[sk] == nil {
			srcBins[sk] = map[string]bool{}
		}
		srcBins[sk][v.Package.Name] = true
	}
	scores, _ := st.CVSSScores(ctx, cveIDs)
	var out []model.Finding
	for _, k := range order {
		a := by[k]
		v := a.v
		var bins []string
		for b := range srcBins[v.SrcName+"|"+v.Installed] {
			bins = append(bins, b)
		}
		sort.Strings(bins)
		var cvss *float64
		sev := "medium"
		var cves []string
		if v.CVE != "" {
			cves = []string{v.CVE}
			if s, ok := scores[v.CVE]; ok {
				cvss = &s
				sev = severityFromCVSS(cvss)
			}
		}
		label := v.CVE
		if label == "" {
			label = v.Advisory
		}
		out = append(out, model.Finding{
			// Identity includes the source package so two packages affected by one CVE stay separate.
			Fingerprint: correlate.Fingerprint(addr, 0, "pkg:"+v.SrcName, cves, "pkg:"+v.Advisory),
			Address:     addr,
			Title:       fmt.Sprintf("%s: %s %s", label, v.SrcName, v.Installed),
			Family:      "Outdated package",
			Severity:    sev, CVSS: cvss, CVEs: cves,
			Synopsis:    fmt.Sprintf("Installed package %s %s is older than the vendor-fixed version %s.", v.SrcName, v.Installed, v.Fixed),
			Description: strings.TrimSpace(v.Summary),
			Remediation: fmt.Sprintf("Upgrade %s to %s or later. Command: %s", v.SrcName, v.Fixed, installCmd(v.Scheme, bins)),
			Solution:    "VendorFix",
			Confidence:  model.ConfConfirmed, Detection: "version", Engine: "audit", EngineRef: "osv:" + v.Advisory,
			Evidence: fmt.Sprintf("Installed %s %s (packages: %s)\nFixed in %s per %s (%s)\nVersion comparison used %s rules, so distribution backports are honoured.",
				v.SrcName, v.Installed, strings.Join(bins, ", "), v.Fixed, v.Advisory, v.Ecosystem, v.Scheme),
			Product: v.SrcName, Version: v.Installed,
		})
	}
	return out
}

func ruleFinding(addr string, r audit.Rule, res audit.Result) model.Finding {
	return model.Finding{
		Fingerprint: correlate.Fingerprint(addr, 0, "", nil, "audit:"+r.ID),
		Address:     addr, Title: r.Title, Family: "Local configuration", Severity: r.Severity,
		Synopsis: r.Synopsis, Remediation: res.Remediation,
		Confidence: model.ConfConfirmed, Detection: "config", Engine: "audit", EngineRef: r.ID,
		Evidence: res.Evidence,
	}
}

// productPackages maps a banner product name to installed-package name prefixes.
var productPackages = map[string][]string{
	"apache httpd": {"apache2", "httpd"}, "apache": {"apache2", "httpd"}, "openssh": {"openssh"},
	"nginx": {"nginx"}, "openssl": {"openssl", "libssl"}, "proftpd": {"proftpd"}, "vsftpd": {"vsftpd"},
	"mysql": {"mysql"}, "mariadb": {"mariadb"}, "postgresql": {"postgresql"}, "redis": {"redis"}, "bind": {"bind"},
	"exim": {"exim"}, "postfix": {"postfix"}, "dovecot": {"dovecot"}, "samba": {"samba"}, "php": {"php"},
}

// packagesForProduct returns installed packages that provide a banner product.
func packagesForProduct(product string, facts *audit.Facts) []audit.Package {
	p := strings.ToLower(strings.TrimSpace(product))
	prefixes := productPackages[p]
	if len(prefixes) == 0 {
		if f := strings.Fields(p); len(f) > 0 {
			prefixes = []string{f[0]}
		}
	}
	var out []audit.Package
	for _, pk := range facts.Packages {
		for _, pre := range prefixes {
			if strings.HasPrefix(strings.ToLower(pk.Name), pre) || strings.HasPrefix(strings.ToLower(pk.SrcName), pre) {
				out = append(out, pk)
				break
			}
		}
	}
	return out
}

// upstreamOf reduces a distro package version to its upstream part in a form
// comparable with a service banner: "1:8.9p1-3ubuntu0.13" and "9.1_p1-r4" become
// "8.9p1" and "9.1p1".
func upstreamOf(v string) string {
	v = strings.ToLower(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.IndexAny(v, "-+~"); i >= 0 {
		v = v[:i]
	}
	return strings.ReplaceAll(v, "_", "")
}

// bannerMatchesPackage reports whether the version a service announced is the
// upstream version of one of the packages, i.e. the running service is
// (almost certainly) the packaged build.
func bannerMatchesPackage(bannerVersion string, pkgs []audit.Package) bool {
	bv := strings.ToLower(strings.TrimSpace(bannerVersion))
	if bv == "" {
		return false
	}
	for _, pk := range pkgs {
		if up := upstreamOf(pk.SrcVersion); up != "" && strings.HasPrefix(up, bv) {
			return true
		}
	}
	return false
}

// supersedeBannerGuesses removes unauthenticated version guesses for software
// the audit has verified through the package database: guesses carrying the
// backport caveat, and guesses whose version is the installed package's own
// upstream version.
// The package audit is authoritative: if the CVE applies it is reported there
// as confirmed; if the distribution patched it, the guess was a false alarm.
func supersedeBannerGuesses(ctx context.Context, st *store.Store, scanID int64, addr string, facts *audit.Facts) error {
	rows, err := st.ListFindings(ctx, scanID, "")
	if err != nil {
		return err
	}
	var drop []int64
	for _, r := range rows {
		if r.Address != addr || r.Confidence == model.ConfConfirmed {
			continue
		}
		isCPE := false
		for _, e := range r.Engines {
			if e == "cpematch" {
				isCPE = true
			}
		}
		if !isCPE {
			continue
		}
		pkgs := packagesForProduct(r.Product, facts)
		if len(pkgs) == 0 {
			continue // not installed from a package: the guess stands
		}
		caveat := r.Confidence == model.ConfTentative && strings.Contains(r.Description, matcher.CaveatBackport)
		if caveat || bannerMatchesPackage(r.Version, pkgs) {
			drop = append(drop, r.ID)
		}
	}
	return st.RemoveFromScan(ctx, scanID, drop)
}
