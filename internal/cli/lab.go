package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"

	"babylon/internal/app"
	"babylon/internal/lab"
	"babylon/internal/policy"
	"babylon/internal/scan"
	"babylon/internal/store"
)

const defaultManifest = "deploy/lab/manifest.yaml"

func newLabCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lab",
		Short: "Measure detection quality against the lab (recall and false positives)",
		Long: `The lab is a set of deliberately vulnerable targets (deploy/lab). Its manifest
lists what a scan must find and what it must never report. These commands turn a
scan into numbers, so detection quality is measured before each release.`,
	}
	var manifest, home string
	var asJSON bool
	var scanID int64
	var caps []string

	check := &cobra.Command{
		Use:   "check",
		Short: "Score an existing scan against the manifest",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if scanID == 0 {
				return fmt.Errorf("--scan is required")
			}
			return labCheck(cmd.Context(), cmd.OutOrStdout(), home, manifest, scanID, caps, asJSON)
		},
	}
	check.Flags().Int64Var(&scanID, "scan", 0, "scan id to score")
	run := &cobra.Command{
		Use:   "run",
		Short: "Scan the lab as the manifest describes, then score the result",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return labRun(cmd.Context(), cmd.OutOrStdout(), home, manifest, asJSON, caps)
		},
	}
	up := &cobra.Command{
		Use:   "up",
		Short: "Start the lab containers (docker compose, 127.0.0.1 only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := exec.CommandContext(cmd.Context(), "docker", "compose", "-f", "deploy/lab/docker-compose.yml", "up", "-d", "--wait")
			c.Stdout, c.Stderr = cmd.OutOrStdout(), cmd.ErrOrStderr()
			return c.Run()
		},
	}
	down := &cobra.Command{
		Use:   "down",
		Short: "Stop and remove the lab containers",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := exec.CommandContext(cmd.Context(), "docker", "compose", "-f", "deploy/lab/docker-compose.yml", "down")
			c.Stdout, c.Stderr = cmd.OutOrStdout(), cmd.ErrOrStderr()
			return c.Run()
		},
	}
	for _, c := range []*cobra.Command{check, run} {
		f := c.Flags()
		f.StringVar(&manifest, "manifest", defaultManifest, "expected-findings manifest")
		f.StringVar(&home, "home", defaultHome(), "data directory")
		f.BoolVar(&asJSON, "json", false, "print the result as JSON")
		f.StringSliceVar(&caps, "has", nil, "capabilities the scan had, enabling expectations that need them (allow-active, deep, credentialed, root)")
	}
	cmd.AddCommand(up, down, check, run)
	return cmd
}

func labCheck(ctx context.Context, out io.Writer, home, manifestPath string, scanID int64, caps []string, asJSON bool) error {
	m, err := lab.Load(manifestPath)
	if err != nil {
		return err
	}
	a, err := app.Open(home)
	if err != nil {
		return err
	}
	defer a.Close()
	return labScore(ctx, out, a.St, m, scanID, caps, asJSON)
}

func labScore(ctx context.Context, out io.Writer, st *store.Store, m *lab.Manifest, scanID int64, caps []string, asJSON bool) error {
	rows, err := st.ListFindings(ctx, scanID, "")
	if err != nil {
		return err
	}
	opt := lab.Options{Capabilities: map[string]bool{}}
	for _, c := range caps {
		opt.Capabilities[c] = true
	}
	rep := lab.Evaluate(m, rows, opt)
	if asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Fprintln(out, string(b))
	} else {
		fmt.Fprint(out, rep.Text())
	}
	if !rep.Pass {
		return fmt.Errorf("lab check failed")
	}
	return nil
}

func labRun(ctx context.Context, out io.Writer, home, manifestPath string, asJSON bool, caps []string) error {
	m, err := lab.Load(manifestPath)
	if err != nil {
		return err
	}
	if len(m.Scan.Targets) == 0 {
		return fmt.Errorf("manifest has no scan.targets")
	}
	a, err := app.Open(home)
	if err != nil {
		return err
	}
	defer a.Close()
	tpl := m.Scan.Template
	if tpl == "" {
		tpl = policy.TemplateFullUnauth
	}
	id, err := a.Create(ctx, app.Request{Name: "lab " + time.Now().Format("2006-01-02 15:04"), Template: tpl, Targets: m.Scan.Targets,
		Ports: m.Scan.Ports, Timing: m.Scan.Timing, Deep: m.Scan.Deep, AllowActive: m.Scan.AllowActive, Workers: 2, NucleiWorkers: 2})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Lab scan %d started\n", id)
	start := time.Now()
	res, err := a.Run(ctx, id, false)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Scan %s in %s\n\n", res.Summary.Status, time.Since(start).Round(time.Second))
	// Nuclei-dependent expectations are only measured when every Nuclei job
	// finished; otherwise a stalled tool would be scored as a detection miss.
	nucleiOK := true
	for _, stage := range []string{scan.StageNucleiDetect, scan.StageNucleiScan} {
		if res.Summary.Counts[stage][store.JobFailed] > 0 {
			nucleiOK = false
		}
	}
	if nucleiOK {
		caps = append(caps, "nuclei")
	} else {
		fmt.Fprintln(out, "Note: Nuclei jobs failed (see docs/known-issues.md); expectations that need Nuclei are not measured.")
	}
	if m.Scan.AllowActive {
		caps = append(caps, "allow-active")
	}
	if m.Scan.Deep {
		caps = append(caps, "deep")
	}
	if os.Geteuid() == 0 {
		caps = append(caps, "root")
	}
	return labScore(ctx, out, a.St, m, id, caps, asJSON)
}
