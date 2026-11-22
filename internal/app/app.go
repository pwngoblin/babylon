// Package app is the shared application layer used by both the CLI and the web
// UI: validating and persisting scan requests, and executing scans.
package app

import (
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
	flags := policy.Flags{AllowActive: req.AllowActive, CheckDefaultCreds: req.CheckDefaultCreds}
	res, err := policy.Resolve(req.Template, flags)
	if err != nil {
		return 0, err
	}
	if res.Template.RequiresCreds {
		return 0, fmt.Errorf("template %q needs credentials, which are not implemented yet", req.Template)
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
	targets := make([]string, 0, len(resolved))
	for _, t := range resolved {
		targets = append(targets, prefixString(t.Prefix))
	}
	if req.Workers <= 0 {
		req.Workers = 2
	}
	if req.NucleiWorkers <= 0 {
		req.NucleiWorkers = 2
	}
	po := persisted{Flags: flags, Workers: req.Workers, NucleiWorkers: req.NucleiWorkers,
		Sudo: req.Sudo && a.AllowSudo, Accuracy: req.Accuracy, Ports: req.Ports, Authorized: req.Authorized}
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
	if res.Template.Nuclei && res.Template.Ports != "" {
		if _, _, n, ok, _ := a.St.FeedState(ctx, "nuclei-templates"); ok && n > 0 {
			sopt.NucleiDir = a.NucleiDir()
		} else {
			out.Warnings = append(out.Warnings, "no Nuclei templates indexed; web/CVE template checks will be skipped (run: babylon update-feeds)")
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
