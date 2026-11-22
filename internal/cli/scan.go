package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"babylon/internal/engines/nmap"
	"babylon/internal/orchestrator"
	"babylon/internal/policy"
	"babylon/internal/runner"
	"babylon/internal/scan"
	"babylon/internal/store"
)

type scanOptions struct {
	home        string
	template    string
	name        string
	targetFile  string
	workers     int
	useSudo     bool
	authorized  bool
	allowActive bool
	defaultCred bool
	resume      int64
	deny        []string
	maxHosts    uint64
}

// persistedOptions is stored in scan.options_json so a resume reproduces the run.
type persistedOptions struct {
	Flags     policy.Flags `json:"flags"`
	Workers   int          `json:"workers"`
	Sudo      bool         `json:"sudo"`
	Privilege string       `json:"privilege"`
}

func newScanCmd() *cobra.Command {
	var o scanOptions
	cmd := &cobra.Command{
		Use:   "scan [targets...]",
		Short: "Run a scan (IPs, CIDRs, hostnames) or resume one with --resume",
		Long: `Run a scan using a Nessus-style template (host_discovery, basic, full_unauth, credentialed).

Targets are IPs, CIDRs or hostnames. Public addresses are refused unless
--i-have-authorization is given. Results are stored in the local database;
resume an interrupted scan with --resume <id>.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), o, args)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.home, "home", defaultHome(), "data directory (database and raw scan output)")
	f.StringVarP(&o.template, "template", "t", policy.TemplateBasic, "scan template: "+strings.Join(policy.TemplateNames(), ", "))
	f.StringVar(&o.name, "name", "", "optional scan name")
	f.StringVarP(&o.targetFile, "targets-file", "f", "", "file with one target per line")
	f.IntVar(&o.workers, "workers", 2, "concurrent nmap processes")
	f.BoolVar(&o.useSudo, "sudo", false, "run nmap via `sudo -n` for SYN/ARP/OS detection")
	f.BoolVar(&o.authorized, "i-have-authorization", false, "allow scanning non-private (public) addresses; you must be authorized to test them")
	f.BoolVar(&o.allowActive, "allow-active", false, "enable probe-level checks (full_unauth template only)")
	f.BoolVar(&o.defaultCred, "check-default-creds", false, "enable default-credential checks (opt-in, may trigger lockouts)")
	f.Int64Var(&o.resume, "resume", 0, "resume the scan with this id")
	f.StringSliceVar(&o.deny, "deny", nil, "CIDR never to scan (repeatable)")
	f.Uint64Var(&o.maxHosts, "max-hosts", 0, "refuse scans expanding to more addresses than this (default 1048576)")
	return cmd
}

func defaultHome() string {
	if h := os.Getenv("BABYLON_HOME"); h != "" {
		return h
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".babylon")
	}
	return ".babylon"
}

func runScan(ctx context.Context, out, errw io.Writer, o scanOptions, args []string) error {
	if err := os.MkdirAll(o.home, 0o700); err != nil {
		return err
	}
	db, err := store.Open(filepath.Join(o.home, "babylon.db"))
	if err != nil {
		return err
	}
	st := store.New(db)
	defer st.Close()

	var scanID int64
	var res *policy.Resolved
	var po persistedOptions

	// Detect privileges before any database mutation so a failure here cannot
	// leave an orphaned pending scan behind. On resume, --sudo is honoured from
	// the original scan's options too.
	useSudo := o.useSudo
	if o.resume > 0 {
		if sc, err := st.GetScan(ctx, o.resume); err == nil {
			var prev persistedOptions
			if json.Unmarshal(sc.Options, &prev) == nil {
				useSudo = useSudo || prev.Sudo
			}
		}
	}
	priv, err := detectPrivilege(ctx, useSudo)
	if err != nil {
		return err
	}
	if !priv.Raw() {
		fmt.Fprintln(errw, "warning: running unprivileged; using TCP connect scans, no ARP/OS detection (use --sudo or run as root for full fidelity)")
	}

	if o.resume > 0 {
		sc, err := st.GetScan(ctx, o.resume)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(sc.Options, &po); err != nil {
			return fmt.Errorf("scan %d has unreadable options: %w", sc.ID, err)
		}
		if res, err = policy.Resolve(sc.Template, po.Flags); err != nil {
			return err
		}
		scanID = sc.ID
		if o.workers == 2 && po.Workers > 0 {
			o.workers = po.Workers
		}
		fmt.Fprintf(out, "Resuming scan %d (%s), previous status: %s\n", sc.ID, sc.Template, sc.Status)
	} else {
		flags := policy.Flags{AllowActive: o.allowActive, CheckDefaultCreds: o.defaultCred}
		if res, err = policy.Resolve(o.template, flags); err != nil {
			return err
		}
		if res.Template.RequiresCreds {
			return fmt.Errorf("template %q needs credentials, which are not implemented yet", o.template)
		}
		raw, err := collectTargets(args, o.targetFile)
		if err != nil {
			return err
		}
		parsed, err := policy.ParseTargets(raw)
		if err != nil {
			return err
		}
		guard := policy.Guard{AllowPublic: o.authorized, MaxHosts: o.maxHosts}
		for _, d := range o.deny {
			p, err := netip.ParsePrefix(d)
			if err != nil {
				return fmt.Errorf("invalid --deny %q: %w", d, err)
			}
			guard.Deny = append(guard.Deny, p)
		}
		resolved, err := guard.Check(ctx, parsed)
		if err != nil {
			return err
		}
		targets := make([]string, 0, len(resolved))
		for _, t := range resolved {
			targets = append(targets, prefixString(t.Prefix))
		}
		po = persistedOptions{Flags: flags, Workers: o.workers, Sudo: o.useSudo}
		if scanID, err = st.CreateScan(ctx, o.name, o.template, targets, po); err != nil {
			return err
		}
		if o.authorized {
			fmt.Fprintln(errw, "warning: public-range guard disabled (--i-have-authorization); make sure you are authorized to scan these targets")
		}
	}

	orch, err := orchestrator.New(st, scan.Stages(res, st, scan.Options{Privilege: priv}), orchestrator.Config{
		Classes: map[string]int{scan.ClassNmap: o.workers},
		DataDir: o.home,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Scan %d: template=%s privilege=%s\n", scanID, res.Template.Name, priv)
	start := time.Now()
	sum, err := orch.Run(ctx, scanID)
	if err != nil {
		return err
	}
	printSummary(out, ctx, st, scanID, sum, time.Since(start))
	if sum.Status == store.ScanCancelled {
		fmt.Fprintf(out, "\nInterrupted. Resume with: babylon scan --resume %d\n", scanID)
		return fmt.Errorf("scan cancelled")
	}
	return nil
}

func collectTargets(args []string, file string) ([]string, error) {
	out := append([]string(nil), args...)
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				out = append(out, line)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets: give targets as arguments or with --targets-file")
	}
	return out, nil
}

func prefixString(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.String()
}

func detectPrivilege(ctx context.Context, wantSudo bool) (nmap.Privilege, error) {
	if os.Geteuid() == 0 {
		return nmap.PrivRoot, nil
	}
	if !wantSudo {
		return nmap.PrivNone, nil
	}
	// sudo -n never prompts: it succeeds only if a cached ticket or NOPASSWD rule exists.
	if _, err := runner.Run(ctx, runner.Spec{Tool: "sudo", Args: []string{"-n", "true"}, Timeout: 10 * time.Second}); err != nil {
		return nmap.PrivNone, fmt.Errorf("--sudo given but `sudo -n` is not usable (run `sudo -v` first, or configure NOPASSWD for nmap): %w", err)
	}
	return nmap.PrivSudo, nil
}

func printSummary(w io.Writer, ctx context.Context, st *store.Store, id int64, sum orchestrator.Summary, took time.Duration) {
	fmt.Fprintf(w, "\nScan %d %s in %s\n", id, sum.Status, took.Round(time.Millisecond))
	for _, stage := range []string{scan.StageSweep, scan.StagePortscan} {
		c, ok := sum.Counts[stage]
		if !ok {
			continue
		}
		total := 0
		for _, n := range c {
			total += n
		}
		fmt.Fprintf(w, "  %-9s %d/%d jobs done", stage, c[store.JobDone], total)
		if c[store.JobFailed] > 0 {
			fmt.Fprintf(w, ", %d FAILED", c[store.JobFailed])
		}
		fmt.Fprintln(w)
	}
	bg := context.WithoutCancel(ctx)
	live, _ := st.LiveHosts(bg, id)
	rows, _ := st.ListServices(bg, id)
	fmt.Fprintf(w, "  %d live hosts, %d open services\n\n", len(live), len(rows))
	last := ""
	for _, r := range rows {
		if r.Address != last {
			label := r.Address
			if r.OS != "" {
				label += "  (" + r.OS + ")"
			}
			fmt.Fprintln(w, label)
			last = r.Address
		}
		svc := strings.TrimSpace(strings.Join([]string{r.Name, r.Product, r.Version}, " "))
		fmt.Fprintf(w, "  %5d/%-3s %s\n", r.Port, r.Proto, svc)
		for _, weak := range r.TLSWeak {
			fmt.Fprintf(w, "            ! %s\n", weak)
		}
	}
}
