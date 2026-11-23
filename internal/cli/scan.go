package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"babylon/internal/app"
	"babylon/internal/audit"
	"babylon/internal/group"
	"babylon/internal/orchestrator"
	"babylon/internal/policy"
	"babylon/internal/scan"
	"babylon/internal/store"
)

type scanOptions struct {
	deep                                                                bool
	timing                                                              string
	sshUser, sshKey, sshPassEnv, sshPassphraseEnv, sshLabel, knownHosts string
	sshPort                                                             int
	trustNew                                                            bool
	home                                                                string
	template                                                            string
	name                                                                string
	targetFile                                                          string
	workers                                                             int
	useSudo                                                             bool
	authorized                                                          bool
	allowActive                                                         bool
	defaultCred                                                         bool
	resume                                                              int64
	deny                                                                []string
	maxHosts                                                            uint64
	nucleiWork                                                          int
	ports                                                               string
	accuracy                                                            string
}

func newScanCmd() *cobra.Command {
	var o scanOptions
	cmd := &cobra.Command{
		Use:   "scan [targets...]",
		Short: "Run a scan (IPs, CIDRs, hostnames) or resume one with --resume",
		Long: `Run a scan using a Nessus-style template (host_discovery, basic, full_unauth, credentialed).

Targets are IPs, CIDRs or hostnames. Public addresses are refused unless
--i-have-authorization is given. Results are stored in the local database
(see: babylon scans list); resume an interrupted scan with --resume <id>.`,
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
	f.StringVar(&o.ports, "ports", "", "TCP ports to scan, e.g. 22,80,8000-8100 (default: template's list)")
	f.IntVar(&o.nucleiWork, "nuclei-workers", 2, "concurrent nuclei processes")
	f.BoolVar(&o.deep, "deep", false, "run every allowed Nuclei template against every web/network service (finds more, much slower)")
	f.StringVar(&o.timing, "timing", policy.TimingStandard, "scan pacing: "+strings.Join(policy.TimingNames(), ", ")+" (fast-lan is for private networks only)")
	f.StringVar(&o.accuracy, "accuracy", app.AccuracyNormal, "report accuracy: normal (show unverified findings in their own section) or avoid-false-alarms (hide them)")
	f.StringVar(&o.sshUser, "ssh-user", "", "SSH user for credentialed audits (template: credentialed)")
	f.StringVar(&o.sshKey, "ssh-key", "", "path to an SSH private key")
	f.StringVar(&o.sshPassEnv, "ssh-password-env", "", "name of an environment variable holding the SSH password (never pass secrets as flags)")
	f.StringVar(&o.sshPassphraseEnv, "ssh-passphrase-env", "", "name of an environment variable holding the key passphrase")
	f.IntVar(&o.sshPort, "ssh-port", 22, "SSH port")
	f.StringVar(&o.sshLabel, "ssh-label", "", "label recorded with the scan to identify this credential set (default: the user name)")
	f.StringVar(&o.knownHosts, "known-hosts", "", "known_hosts file used to verify hosts (default ~/.ssh/known_hosts)")
	f.BoolVar(&o.trustNew, "trust-new-hosts", false, "trust unknown SSH host keys on first use and pin them in ~/.babylon/known_hosts (changed keys are still rejected)")
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
	a, err := app.Open(o.home)
	if err != nil {
		return err
	}
	defer a.Close()
	creds, err := o.sshCreds()
	if err != nil {
		return err
	}
	if creds != nil {
		if o.template != policy.TemplateCredentialed && o.resume == 0 {
			return fmt.Errorf("--ssh-* options need --template %s", policy.TemplateCredentialed)
		}
		a.SSH = creds
		a.HostKeys = audit.HostKeyPolicy{KnownHosts: o.knownHosts, TrustNew: o.trustNew}
	}
	a.AllowSudo = true // an interactive user may use sudo; `sudo -n` fails safely without a cached ticket

	id := o.resume
	if id > 0 {
		sc, err := a.St.GetScan(ctx, id)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Resuming scan %d (%s), previous status: %s\n", sc.ID, sc.Template, sc.Status)
	} else {
		raw, err := collectTargets(args, o.targetFile)
		if err != nil {
			return err
		}
		if err := a.PreflightPrivilege(ctx, o.useSudo); err != nil { // before any database write
			return err
		}
		id, err = a.Create(ctx, app.Request{
			Name: o.name, Template: o.template, Targets: raw, Ports: o.ports, Accuracy: o.accuracy,
			Timing: o.timing, Deep: o.deep, AllowActive: o.allowActive, CheckDefaultCreds: o.defaultCred, Authorized: o.authorized, Sudo: o.useSudo,
			Workers: o.workers, NucleiWorkers: o.nucleiWork, Deny: o.deny, MaxHosts: o.maxHosts,
		})
		if err != nil {
			return err
		}
	}

	fmt.Fprintf(out, "Scan %d started\n", id)
	start := time.Now()
	res, err := a.Run(ctx, id, o.useSudo)
	for _, w := range res.Warnings {
		fmt.Fprintln(errw, "warning:", w)
	}
	if err != nil {
		return err
	}
	printSummary(out, ctx, a.St, id, res.Summary, time.Since(start), res.Accuracy)
	if res.Summary.Status == store.ScanCancelled {
		fmt.Fprintf(out, "\nInterrupted. Resume with: babylon scan --resume %d\n", id)
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

type orchestratorSummary = orchestrator.Summary

func printSummary(w io.Writer, ctx context.Context, st *store.Store, id int64, sum orchestrator.Summary, took time.Duration, accuracy string) {
	fmt.Fprintf(w, "\nScan %d %s in %s\n", id, sum.Status, took.Round(time.Millisecond))
	for _, stage := range []string{scan.StageSweep, scan.StagePortscan, scan.StageNucleiDetect, scan.StageNucleiScan, scan.StageCPEMatch, scan.StageNative, scan.StageAudit} {
		c, ok := sum.Counts[stage]
		if !ok {
			continue
		}
		total := 0
		for _, n := range c {
			total += n
		}
		fmt.Fprintf(w, "  %-14s %d/%d jobs done", stage, c[store.JobDone], total)
		if c[store.JobFailed] > 0 {
			fmt.Fprintf(w, ", %d FAILED", c[store.JobFailed])
		}
		fmt.Fprintln(w)
	}
	bg := context.WithoutCancel(ctx)
	live, _ := st.LiveHosts(bg, id)
	rows, _ := st.ListServices(bg, id)
	findings, _ := st.ListFindings(bg, id, "")
	cov, _ := st.CheckRunCounts(bg, id)
	fmt.Fprintf(w, "  %d live hosts, %d open services, %d findings", len(live), len(rows), len(findings))
	if n := cov["skipped"]; n > 0 {
		fmt.Fprintf(w, " (%d service checks skipped: see coverage)", n)
	}
	fmt.Fprint(w, "\n\n")

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
	if len(findings) == 0 {
		return
	}
	var verified, possible, informational []store.FindingRow
	for _, f := range findings {
		switch {
		case f.Severity == "info":
			informational = append(informational, f)
		case f.Confidence == "tentative":
			possible = append(possible, f)
		default:
			verified = append(verified, f)
		}
	}
	section := func(title string, list []store.FindingRow) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s (%d)\n", title, len(list))
		groups, rest := group.Build(list)
		for _, g := range groups {
			kev := ""
			if g.KEVCount > 0 {
				kev = " KEV"
			}
			cvss := ""
			if g.MaxCVSS != nil {
				cvss = fmt.Sprintf("  max CVSS %.1f", *g.MaxCVSS)
			}
			fmt.Fprintf(w, "  %-8s %-22s %s%s%s  [%s]\n", strings.ToUpper(g.Severity), fmt.Sprintf("%s:%d", g.Address, g.Port), g.Title, cvss, kev, g.Confidence)
			fmt.Fprintf(w, "           fix: %s\n", g.Fix)
			shown := g.CVEs
			if len(shown) > 8 {
				shown = shown[:8]
			}
			more := ""
			if len(g.CVEs) > len(shown) {
				more = fmt.Sprintf(" … +%d more (babylon scans show %d)", len(g.CVEs)-len(shown), id)
			}
			fmt.Fprintf(w, "           %s%s\n", strings.Join(shown, ", "), more)
		}
		for _, f := range rest {
			where := f.Address
			if f.Port != 0 {
				where = fmt.Sprintf("%s:%d", f.Address, f.Port)
			}
			cve := ""
			if len(f.CVEs) > 0 {
				cve = "  " + strings.Join(f.CVEs, ",")
			}
			kev := ""
			if f.KEV {
				kev = " KEV"
			}
			fmt.Fprintf(w, "  %-8s %-22s %s%s%s  [%s]\n", strings.ToUpper(f.Severity), where, f.Title, cve, kev, strings.Join(f.Engines, "+"))
		}
	}
	section("Findings", verified)
	if accuracy != "avoid-false-alarms" {
		section("Possible findings (version-based, unverified)", possible)
	} else if len(possible) > 0 {
		fmt.Fprintf(w, "\n%d possible findings hidden by --accuracy avoid-false-alarms (stored; nothing is deleted)\n", len(possible))
	}
	section("Informational", informational)
}

// sshCreds builds in-memory credentials from flags and environment. Secrets
// are read from environment variables, so they never appear in shell history or
// the process list. nil means no SSH options were given.
func (o scanOptions) sshCreds() (*audit.Creds, error) {
	if o.sshUser == "" && o.sshKey == "" && o.sshPassEnv == "" {
		return nil, nil
	}
	if o.sshUser == "" {
		return nil, fmt.Errorf("--ssh-user is required")
	}
	c := &audit.Creds{User: o.sshUser, KeyPath: o.sshKey, Port: o.sshPort, Label: o.sshLabel}
	if c.Label == "" {
		c.Label = o.sshUser
	}
	if o.sshPassEnv != "" {
		if c.Password = os.Getenv(o.sshPassEnv); c.Password == "" {
			return nil, fmt.Errorf("environment variable %s is empty or unset", o.sshPassEnv)
		}
	}
	if o.sshPassphraseEnv != "" {
		if c.Passphrase = os.Getenv(o.sshPassphraseEnv); c.Passphrase == "" {
			return nil, fmt.Errorf("environment variable %s is empty or unset", o.sshPassphraseEnv)
		}
	}
	if c.KeyPath == "" && c.Password == "" {
		return nil, fmt.Errorf("give --ssh-key or --ssh-password-env")
	}
	return c, nil
}
