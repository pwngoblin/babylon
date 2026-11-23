// Package app is the shared application layer used by both the CLI and the web
// UI: validating and persisting scan requests, and executing scans.
package app

import (
	"babylon/internal/audit"
	"babylon/internal/dbaudit"
	"babylon/internal/notify"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"babylon/internal/engines/nmap"
	"babylon/internal/orchestrator"
	"babylon/internal/policy"
	"babylon/internal/runner"
	"babylon/internal/scan"
	"babylon/internal/store"
)

// Accuracy settings (Nessus "report accuracy").
const (
	AccuracyNormal = "normal"
	AccuracyAvoid  = "avoid-false-alarms"
)

// App owns the data directory and database.
type App struct {
	Home string
	St   *store.Store
	// AllowSudo lets scans use `sudo -n nmap` for raw-socket scans when the
	// process is not root. It is decided by whoever starts the process, never
	// by a (possibly remote) scan request.
	AllowSudo bool
	// SSH holds credentials for credentialed scans. They live in memory for
	// this process only, are set by the local operator (never by a web
	// request), and are never written to the database.
	SSH *audit.Creds
	// Win holds WinRM credentials (same rules as SSH: memory only, never stored).
	Win *audit.WinCreds
	// DB holds database credentials (PostgreSQL, MySQL/MariaDB), same rules: memory only.
	DB       *dbaudit.Creds
	HostKeys audit.HostKeyPolicy
}

// Open opens (creating if needed) the data directory and database.
func Open(home string) (*App, error) {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	db, err := store.Open(filepath.Join(home, "babylon.db"))
	if err != nil {
		return nil, err
	}
	return &App{Home: home, St: store.New(db)}, nil
}

func (a *App) Close() error { return a.St.Close() }

// NucleiDir is where the Nuclei templates checkout lives.
func (a *App) NucleiDir() string { return filepath.Join(a.Home, "nuclei-templates") }

// Request describes a scan to create.
type Request struct {
	Name              string   `json:"name"`
	Template          string   `json:"template"`
	Targets           []string `json:"targets"`
	Ports             string   `json:"ports"`
	Accuracy          string   `json:"accuracy"`
	AllowActive       bool     `json:"allow_active"`
	CheckDefaultCreds bool     `json:"check_default_creds"`
	Authorized        bool     `json:"authorized"` // allow public address ranges
	Sudo              bool     `json:"sudo"`
	Workers           int      `json:"workers"`
	NucleiWorkers     int      `json:"nuclei_workers"`
	Deep              bool     `json:"deep"`
	Timing            string   `json:"timing"` // standard (default), fast-lan, polite
	Deny              []string `json:"deny"`
	MaxHosts          uint64   `json:"max_hosts"`
}

// persisted is stored in scan.options_json so a resume reproduces the run.
type persisted struct {
	Flags         policy.Flags `json:"flags"`
	Workers       int          `json:"workers"`
	NucleiWorkers int          `json:"nuclei_workers"`
	Sudo          bool         `json:"sudo"`
	Accuracy      string       `json:"accuracy"`
	Ports         string       `json:"ports,omitempty"`
	Authorized    bool         `json:"authorized,omitempty"`
	SSHLabel      string       `json:"ssh_label,omitempty"` // name of the credential set; the secret itself is never stored
}

// Create validates a request against policy (scope guard, template/flag rules,
// port syntax), then persists a pending scan. Nothing is sent to the network.
func (a *App) Create(ctx context.Context, req Request) (int64, error) {
	if req.Template == "" {
		req.Template = policy.TemplateBasic
	}
	if req.Accuracy == "" {
		req.Accuracy = AccuracyNormal
	}
	if req.Accuracy != AccuracyNormal && req.Accuracy != AccuracyAvoid {
		return 0, fmt.Errorf("invalid accuracy %q (%s or %s)", req.Accuracy, AccuracyNormal, AccuracyAvoid)
	}
	if err := nmap.ValidPorts(req.Ports); err != nil {
		return 0, err
	}
	flags := policy.Flags{AllowActive: req.AllowActive, CheckDefaultCreds: req.CheckDefaultCreds, Timing: req.Timing, Deep: req.Deep}
	res, err := policy.Resolve(req.Template, flags)
	if err != nil {
		return 0, err
	}
	if res.Template.RequiresCreds && a.SSH == nil && a.Win == nil && a.DB == nil {
		return 0, fmt.Errorf("template %q needs credentials: pass --ssh-user (Linux), --winrm-user (Windows) and/or --db-user (PostgreSQL, MySQL/MariaDB) with the matching password or key from the environment (CLI only; credentials are never stored)", req.Template)
	}
	parsed, err := policy.ParseTargets(req.Targets)
	if err != nil {
		return 0, err
	}
	guard := policy.Guard{AllowPublic: req.Authorized, MaxHosts: req.MaxHosts}
	for _, d := range req.Deny {
		p, err := netip.ParsePrefix(d)
		if err != nil {
			return 0, fmt.Errorf("invalid deny range %q: %w", d, err)
		}
		guard.Deny = append(guard.Deny, p)
	}
	resolved, err := guard.Check(ctx, parsed)
	if err != nil {
		return 0, err
	}
	{
		var ps []netip.Prefix
		for _, t := range resolved {
			ps = append(ps, t.Prefix)
		}
		if err := checkScope(a.Home, ps); err != nil {
			return 0, err
		}
	}
	targets := make([]string, 0, len(resolved))
	for _, t := range resolved {
		targets = append(targets, prefixString(t.Prefix))
		if res.Timing.PrivateOnly && !(policy.IsPrivate(t.Prefix.Addr()) && policy.IsPrivate(lastAddr(t.Prefix))) {
			return 0, fmt.Errorf("timing profile %q is only for private networks; %s is not private (use standard or polite)", res.Timing.Name, prefixString(t.Prefix))
		}
	}
	if req.Workers <= 0 {
		req.Workers = 2
	}
	if req.NucleiWorkers <= 0 {
		req.NucleiWorkers = 2
	}
	po := persisted{Flags: flags, Workers: req.Workers, NucleiWorkers: req.NucleiWorkers,
		Sudo: req.Sudo && a.AllowSudo, Accuracy: req.Accuracy, Ports: req.Ports, Authorized: req.Authorized}
	if a.SSH != nil {
		po.SSHLabel = a.SSH.Label
	} else if a.Win != nil {
		po.SSHLabel = a.Win.Label
	} else if a.DB != nil {
		po.SSHLabel = a.DB.Label
	}
	return a.St.CreateScan(ctx, req.Name, req.Template, targets, po)
}

func prefixString(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.String()
}

// Result is the outcome of executing a scan.
type Result struct {
	Summary   orchestrator.Summary
	Warnings  []string
	Accuracy  string
	Privilege nmap.Privilege
}

// Run executes (or resumes) a scan to completion, cancellation or error.
func (a *App) Run(ctx context.Context, id int64, forceSudo bool) (Result, error) {
	var out Result
	sc, err := a.St.GetScan(ctx, id)
	if err != nil {
		return out, err
	}
	var po persisted
	if err := json.Unmarshal(sc.Options, &po); err != nil {
		return out, fmt.Errorf("scan %d has unreadable options: %w", id, err)
	}
	res, err := policy.Resolve(sc.Template, po.Flags)
	if err != nil {
		return out, err
	}
	out.Accuracy = po.Accuracy
	if out.Accuracy == "" {
		out.Accuracy = AccuracyNormal
	}

	// Privilege is detected before any database mutation so a failure here
	// leaves the scan untouched.
	priv, err := a.detectPrivilege(ctx, po.Sudo || forceSudo)
	if err != nil {
		return out, err
	}
	out.Privilege = priv
	if !priv.Raw() {
		out.Warnings = append(out.Warnings, "running unprivileged: using TCP connect scans, no ARP/OS detection (use --sudo or run as root for full fidelity)")
	}
	if po.Authorized {
		out.Warnings = append(out.Warnings, "public-range guard disabled by authorization flag; make sure you are authorized to scan these targets")
	}

	sopt := scan.Options{Privilege: priv, Ports: po.Ports}
	if res.Template.Audit {
		if a.SSH == nil && a.Win == nil && a.DB == nil {
			return out, fmt.Errorf("scan %d is a credentialed scan: supply the credentials again (--ssh-user, --winrm-user or --db-user, with passwords from the environment); they are never stored", id)
		}
		if a.SSH != nil {
			sopt.Audit = &scan.AuditConfig{Creds: *a.SSH, HostKeys: a.HostKeys}
		}
		if a.DB != nil {
			sopt.DBAudit = &scan.DBAuditConfig{Creds: *a.DB}
		}
		if a.Win != nil {
			sopt.WinAudit = &scan.WinAuditConfig{Creds: *a.Win}
			if n, _, _ := a.St.CountMSRC(ctx); n == 0 {
				out.Warnings = append(out.Warnings, "no Microsoft security data indexed; Windows missing-patch matching will be skipped (run: babylon update-feeds --only msrc)")
			}
		}
		if n, _, _ := a.St.CountOSV(ctx); n == 0 {
			out.Warnings = append(out.Warnings, "no OSV package data indexed; package vulnerability matching will report nothing (run: babylon update-feeds --only osv)")
		}
	}
	sopt.PackDir = filepath.Join(a.Home, "checks")
	if res.Template.Nuclei && res.Template.Ports != "" {
		if _, _, n, ok, _ := a.St.FeedState(ctx, "nuclei-templates"); ok && n > 0 {
			sopt.NucleiDir = a.NucleiDir()
		} else {
			out.Warnings = append(out.Warnings, "no Nuclei templates indexed; web/CVE template checks will be skipped (run: babylon update-feeds)")
		}
	}
	if res.Template.CPEMatch && res.Template.Ports != "" {
		if n, _, _ := a.St.CountCVEs(ctx); n == 0 {
			out.Warnings = append(out.Warnings, "no vulnerability data indexed; version-based CVE matching will be skipped (run: babylon update-feeds)")
		}
	}
	workers, nworkers := po.Workers, po.NucleiWorkers
	if workers <= 0 {
		workers = 2
	}
	if nworkers <= 0 {
		nworkers = 2
	}
	orch, err := orchestrator.New(a.St, scan.Stages(res, a.St, sopt), orchestrator.Config{
		Classes: map[string]int{scan.ClassNmap: workers, scan.ClassNuclei: nworkers, scan.ClassNative: 4},
		DataDir: a.Home,
	})
	if err != nil {
		return out, err
	}
	out.Summary, err = orch.Run(ctx, id)
	if err == nil {
		if nerr := a.notifyChange(ctx, id); nerr != nil {
			out.Warnings = append(out.Warnings, "notification not sent: "+nerr.Error())
		}
	}
	return out, err
}

// detectPrivilege decides how nmap may run.
func (a *App) detectPrivilege(ctx context.Context, wantSudo bool) (nmap.Privilege, error) {
	if os.Geteuid() == 0 {
		return nmap.PrivRoot, nil
	}
	if !wantSudo || !a.AllowSudo {
		return nmap.PrivNone, nil
	}
	// sudo -n never prompts: it succeeds only with a cached ticket or NOPASSWD rule.
	if _, err := runner.Run(ctx, runner.Spec{Tool: "sudo", Args: []string{"-n", "true"}, Timeout: 10 * time.Second}); err != nil {
		return nmap.PrivNone, fmt.Errorf("sudo requested but `sudo -n` is not usable (run `sudo -v` first, or configure NOPASSWD for nmap): %w", err)
	}
	return nmap.PrivSudo, nil
}

// PreflightPrivilege checks that the requested privilege mode is usable, so a
// caller can fail before creating a scan row.
func (a *App) PreflightPrivilege(ctx context.Context, wantSudo bool) error {
	_, err := a.detectPrivilege(ctx, wantSudo)
	return err
}

// Accuracy returns the persisted accuracy setting of a scan.
func (a *App) Accuracy(ctx context.Context, id int64) string {
	raw, err := a.St.ScanOptionsJSON(ctx, id)
	if err != nil {
		return AccuracyNormal
	}
	var po persisted
	if json.Unmarshal([]byte(raw), &po) != nil || po.Accuracy == "" {
		return AccuracyNormal
	}
	return po.Accuracy
}

// RemoveScanData deletes a scan from the database and its raw output on disk.
func (a *App) RemoveScanData(ctx context.Context, id int64) error {
	if err := a.St.DeleteScan(ctx, id); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(a.Home, "scans", fmt.Sprint(id)))
}

// lastAddr returns the last address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	b := a.AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	r, _ := netip.AddrFromSlice(b)
	return r
}

// notifyChange sends a webhook for new findings since the previous scan of the
// same targets, when ~/.babylon/notify.yaml exists. The first scan of a set of
// targets is a baseline and sends nothing.
func (a *App) notifyChange(ctx context.Context, id int64) error {
	cfg, err := notify.Load(a.Home)
	if err != nil || cfg == nil {
		return err
	}
	sc, err := a.St.GetScanSummary(ctx, id)
	if err != nil || sc.Status != store.ScanCompleted {
		return err
	}
	prev, err := a.St.PreviousScan(ctx, id)
	if err != nil || prev == 0 {
		return err
	}
	d, err := a.St.DiffScans(ctx, prev, id)
	if err != nil {
		return err
	}
	msg := cfg.Build(id, sc.Targets, d)
	if msg == nil {
		return nil
	}
	return cfg.Send(ctx, msg)
}
