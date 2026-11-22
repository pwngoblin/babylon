package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"babylon/internal/engines/nuclei"
	"babylon/internal/runner"
	"babylon/internal/store"
)

type feedsOptions struct {
	home         string
	only         []string
	templatesDir string
	noDownload   bool
}

func newFeedsCmd() *cobra.Command {
	var o feedsOptions
	cmd := &cobra.Command{
		Use:   "update-feeds",
		Short: "Download and index vulnerability data (Nuclei templates)",
		Long: `Updates local detection data so scans can run without outside network access.

Currently: nuclei-templates (downloaded with the nuclei binary, then indexed
into the local database so scans can select exactly the templates relevant to
each detected service). NVD, CISA KEV, EPSS and OSV feeds are planned.

Use --no-download with --templates-dir to index an existing checkout offline.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFeeds(cmd.Context(), cmd.OutOrStdout(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.home, "home", defaultHome(), "data directory")
	f.StringSliceVar(&o.only, "only", nil, "limit to these feeds (nuclei-templates)")
	f.StringVar(&o.templatesDir, "templates-dir", "", "use this nuclei-templates checkout instead of <home>/nuclei-templates")
	f.BoolVar(&o.noDownload, "no-download", false, "index only; do not contact the network")
	return cmd
}

func nucleiDir(home string) string { return filepath.Join(home, "nuclei-templates") }

func runFeeds(ctx context.Context, out io.Writer, o feedsOptions) error {
	for _, f := range o.only {
		if f != "nuclei-templates" {
			return fmt.Errorf("unknown feed %q (available: nuclei-templates)", f)
		}
	}
	if err := os.MkdirAll(o.home, 0o700); err != nil {
		return err
	}
	db, err := store.Open(filepath.Join(o.home, "babylon.db"))
	if err != nil {
		return err
	}
	st := store.New(db)
	defer st.Close()

	dir := nucleiDir(o.home)
	if o.templatesDir != "" {
		abs, err := filepath.Abs(o.templatesDir)
		if err != nil {
			return err
		}
		if abs != dir {
			if err := linkTemplates(abs, dir); err != nil {
				return err
			}
		}
	}

	if !o.noDownload {
		fmt.Fprintln(out, "Downloading nuclei-templates (needs network)...")
		if _, err := runner.Run(ctx, runner.Spec{
			Tool: "nuclei", Args: []string{"-update-templates", "-update-template-dir", dir, "-no-color"},
			Timeout: 20 * time.Minute, MaxStdout: 1 << 24,
		}); err != nil {
			return fmt.Errorf("template download failed: %w (use --no-download --templates-dir to index an existing checkout)", err)
		}
	}
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("no templates at %s: run without --no-download, or pass --templates-dir", dir)
	}

	fmt.Fprintf(out, "Indexing %s ...\n", dir)
	start := time.Now()
	var tpls []store.NucleiTemplate
	parsed, skipped, err := nuclei.IndexDir(dir, func(m nuclei.Meta) {
		tpls = append(tpls, store.NucleiTemplate{
			Path: m.Path, ID: m.ID, Name: m.Name, Severity: m.Severity, Protocols: m.Protocols, Tags: m.Tags,
			CVEs: m.CVEs, CVSS: m.CVSS, Vendor: m.Vendor, Product: m.Product, Verified: m.Verified,
		})
	})
	if err != nil {
		return err
	}
	if parsed == 0 {
		return fmt.Errorf("no templates found under %s", dir)
	}
	if err := st.ReplaceNucleiIndex(ctx, time.Now().UTC().Format("2006-01-02"), tpls); err != nil {
		return err
	}
	fmt.Fprintf(out, "Indexed %d templates (%d skipped) in %s\n", parsed, skipped, time.Since(start).Round(time.Millisecond))
	return nil
}

// linkTemplates points <home>/nuclei-templates at an existing checkout.
func linkTemplates(target, link string) error {
	if fi, err := os.Lstat(link); err == nil {
		if fi.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%s exists and is not a symlink; remove it or omit --templates-dir", link)
		}
		os.Remove(link)
	}
	return os.Symlink(target, link)
}
