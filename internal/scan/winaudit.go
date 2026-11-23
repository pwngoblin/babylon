package scan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"babylon/internal/audit"
	"babylon/internal/correlate"
	"babylon/internal/model"
	"babylon/internal/orchestrator"
	"babylon/internal/store"
	"babylon/internal/winrel"
)

const (
	StageWinAudit = "winaudit"

	checkWinAudit = "winrm-audit"
	checkWinPatch = "winrm-patch-audit"

	familyWinPatch = "Missing patch (Windows)"
)

// WinAuditConfig carries in-memory WinRM credentials. Never persisted.
type WinAuditConfig struct {
	Creds audit.WinCreds
	// Connect opens a session; nil uses WinRM. Tests inject a fake.
	Connect func(ctx context.Context, host string) (audit.Runner, func(), error)
	Now     func() time.Time
}

func (c *WinAuditConfig) connect(ctx context.Context, host string) (audit.Runner, func(), error) {
	if c.Connect != nil {
		return c.Connect(ctx, host)
	}
	s, err := audit.DialWinRM(ctx, host, c.Creds)
	if err != nil {
		return nil, nil, err
	}
	return s, s.Close, nil
}

func (c *WinAuditConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// winAuditStage audits Windows hosts that expose WinRM, comparing the build
// against Microsoft's fix data and evaluating hardening rules.
func winAuditStage(st *store.Store, cfg *WinAuditConfig, deps []string) orchestrator.Stage {
	return orchestrator.Stage{
		Name:      StageWinAudit,
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
			has := map[string]bool{}
			for _, s := range svcs {
				if s.Proto == "tcp" && (s.Port == cfg.portWanted() || s.Port == 5985 || s.Port == 5986) {
					has[s.Address] = true
				}
			}
			var hosts []string
			for _, h := range live {
				if has[h] {
					hosts = append(hosts, h)
				} else if id, err := st.AssetID(ctx, h); err == nil {
					_ = st.RecordCheckRun(ctx, sc.ID, id, checkWinAudit, "skipped", "no open WinRM service (5985/5986)")
				}
			}
			return chunkSpecs(hosts, 2, "winaudit", nil), nil
		},
		Handle: func(ctx context.Context, job store.Job) error {
			bg := context.WithoutCancel(ctx)
			for _, addr := range job.Targets {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				hctx, cancel := context.WithTimeout(ctx, auditHostTO)
				err := winAuditHost(hctx, bg, st, cfg, job.ScanID, addr)
				cancel()
				if err != nil {
					return fmt.Errorf("auditing %s: %w", addr, err)
				}
			}
			return nil
		},
	}
}

func (c *WinAuditConfig) portWanted() int {
	if c.Creds.Port != 0 {
		return c.Creds.Port
	}
	return 0
}

func winAuditHost(ctx, bg context.Context, st *store.Store, cfg *WinAuditConfig, scanID int64, addr string) error {
	assetID, err := st.AssetID(bg, addr)
	if err != nil {
		return err
	}
	fail := func(msg string) error {
		if err := st.SaveAudit(bg, scanID, store.AuditSession{AssetID: assetID, Transport: "winrm", Result: "failed", Error: msg, OSFamily: "windows"}, nil, nil); err != nil {
			return err
		}
		return st.RecordCheckRun(bg, scanID, assetID, checkWinAudit, "error", msg)
	}
	run, closeFn, err := cfg.connect(ctx, addr)
	if err != nil {
		return fail(sanitizeWinErr(err, cfg.Creds))
	}
	defer closeFn()
	facts, err := audit.CollectWindows(ctx, run, cfg.now())
	if err != nil {
		return fail(sanitizeWinErr(err, cfg.Creds))
	}
	_ = st.SetKB(bg, scanID, assetID, "audit.credential", map[string]string{"label": cfg.Creds.Label, "user": cfg.Creds.User, "transport": "winrm"}, "audit")
	_ = st.SetKB(bg, scanID, assetID, "os.release", map[string]string{"id": "windows", "version": facts.FullVersion(), "caption": facts.Caption}, "audit")
	if err := st.RecordCheckRun(bg, scanID, assetID, checkWinAudit, "ran", strings.Join(facts.Errors, "; ")); err != nil {
		return err
	}

	// Missing updates.
	fixes, stats, err := audit.MatchWindowsUpdates(bg, st, facts)
	if err != nil {
		return err
	}
	if stats.Unsupported != "" {
		if err := st.RecordCheckRun(bg, scanID, assetID, checkWinPatch, "skipped", stats.Unsupported); err != nil {
			return err
		}
	} else {
		for _, f := range winPatchFindings(addr, facts, fixes) {
			if err := st.RecordFinding(bg, scanID, f); err != nil {
				return err
			}
		}
		if err := st.RecordCheckRun(bg, scanID, assetID, checkWinPatch, "ran", ""); err != nil {
			return err
		}
	}

	// Hardening rules.
	var cfgRes []store.ConfigResult
	for _, r := range audit.WinRules {
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
			if err := st.RecordFinding(bg, scanID, winRuleFinding(addr, r, res)); err != nil {
				return err
			}
		default:
			cfgRes = append(cfgRes, store.ConfigResult{CheckID: r.ID, Result: "pass", Evidence: res.Evidence})
		}
		if err := st.RecordCheckRun(bg, scanID, assetID, r.ID, "ran", ""); err != nil {
			return err
		}
	}

	pkgs := make([]store.PackageRow, 0, len(facts.Software))
	for _, s := range facts.Software {
		pkgs = append(pkgs, store.PackageRow{Name: s.Name, Version: s.Version, SrcName: s.Name, SrcVersion: s.Version, Ecosystem: "windows"})
	}
	result := "ok"
	if len(facts.Errors) > 0 {
		result = "partial"
	}
	return st.SaveAudit(bg, scanID, store.AuditSession{
		AssetID: assetID, Transport: "winrm", Label: cfg.Creds.Label, OSFamily: "windows", OSName: facts.Caption, OSVersion: facts.FullVersion(),
		Kernel: facts.FullVersion(), Ecosystem: "windows", Result: result, Error: strings.Join(facts.Errors, "; "),
	}, pkgs, cfgRes)
}

func sanitizeWinErr(err error, c audit.WinCreds) string {
	s := err.Error()
	if len(c.Password) >= 3 {
		s = strings.ReplaceAll(s, c.Password, "***")
	}
	return s
}

// winPatchFindings makes one finding per missing CVE fix. They share product and
// version so root-cause grouping collapses them into "install the latest update".
func winPatchFindings(addr string, f *audit.WinFacts, fixes []store.MSRCFix) []model.Finding {
	product := "Windows " + f.BuildKey()
	if rel := winrel.Lookup(f.Caption); rel != nil {
		product = rel.Name + " (" + f.BuildKey() + ")"
	}
	var out []model.Finding
	for _, x := range fixes {
		sev := x.Severity
		if sev == "" {
			sev = severityFromCVSS(x.CVSS)
		}
		fixedVer := fmt.Sprintf("%s.%d", x.Build, x.FixedUBR)
		kb := x.KB
		out = append(out, model.Finding{
			Fingerprint: correlate.Fingerprint(addr, 0, "win:"+x.Build, []string{x.CVE}, "win:"+x.CVE),
			Address:     addr,
			Title:       fmt.Sprintf("%s: %s", x.CVE, x.Title),
			Family:      familyWinPatch, Severity: sev, CVSS: x.CVSS, CVEs: []string{x.CVE},
			Synopsis:    fmt.Sprintf("The host is missing the Microsoft security update that fixes %s.", x.CVE),
			Description: x.Title,
			Remediation: fmt.Sprintf("Install Windows update KB%s, which brings the host to %s or later. Windows Update, WSUS or your patch tool can deploy it.", kb, fixedVer),
			Solution:    "VendorFix", Confidence: model.ConfConfirmed, Detection: "version", Engine: "audit", EngineRef: "msrc:" + x.CVE,
			Evidence: fmt.Sprintf("Installed build %s; Microsoft fixed this in %s (KB%s).", f.FullVersion(), fixedVer, kb),
			Product:  product, Version: f.FullVersion(),
		})
	}
	return out
}

func winRuleFinding(addr string, r audit.WinRule, res audit.Result) model.Finding {
	return model.Finding{
		Fingerprint: correlate.Fingerprint(addr, 0, "", nil, "audit:"+r.ID),
		Address:     addr, Title: r.Title, Family: "Local configuration", Severity: r.Severity,
		Synopsis: r.Synopsis, Remediation: res.Remediation,
		Confidence: model.ConfConfirmed, Detection: "config", Engine: "audit", EngineRef: r.ID,
		Evidence: res.Evidence,
	}
}
