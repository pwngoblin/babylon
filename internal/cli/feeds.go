package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"babylon/internal/engines/nuclei"
	"babylon/internal/intel"
	"babylon/internal/runner"
	"babylon/internal/store"
)

var allFeeds = []string{"nuclei-templates", "kev", "epss", "nvd", "cvelist", "osv", "msrc"}

type feedsOptions struct {
	home         string
	only         []string
	templatesDir string
	noDownload   bool
	osv          []string
	nvdPages     int
	cveYear      int
	msrcMonths   int
	status       bool
}

func newFeedsCmd() *cobra.Command {
	var o feedsOptions
	cmd := &cobra.Command{
		Use:   "update-feeds",
		Short: "Download and index vulnerability data (Nuclei templates, NVD, CISA KEV, EPSS, OSV)",
		Long: `Updates local detection data so scans run without outside network access.

  nuclei-templates  community checks, indexed so scans select only relevant ones
  kev               CISA Known Exploited Vulnerabilities
  epss              FIRST exploit-prediction scores
  nvd               NVD CVE + affected product/version ranges (powers version matching)
  cvelist           CVE Program records: version ranges for CVEs NVD has not analysed yet
  osv               OSV.dev ecosystem dumps (Debian, Ubuntu, Alpine, Rocky, Alma, PyPI, npm, Go)
  msrc              Microsoft security bulletins: Windows fix revisions (powers the Windows patch audit)

Downloads are conditional (ETag / Last-Modified), so repeat runs are quick. The
first NVD sync pages through ~430k CVEs: about 25 minutes without an API key,
a few minutes with one (set NVD_API_KEY; free at nvd.nist.gov). It is
resumable: interrupt and rerun to continue. Later runs fetch only changes.

Use --no-download with --templates-dir to index an existing Nuclei checkout offline.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFeeds(cmd.Context(), cmd.OutOrStdout(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.home, "home", defaultHome(), "data directory")
	f.StringSliceVar(&o.only, "only", nil, "limit to these feeds ("+strings.Join(allFeeds, ", ")+")")
	f.StringVar(&o.templatesDir, "templates-dir", "", "use this nuclei-templates checkout instead of <home>/nuclei-templates")
	f.BoolVar(&o.noDownload, "no-download", false, "index only; do not contact the network")
	f.StringSliceVar(&o.osv, "osv-ecosystems", intel.DefaultOSVEcosystems, "OSV ecosystems to fetch")
	f.IntVar(&o.nvdPages, "nvd-pages", 0, "stop the NVD download after this many pages of 2000 (seed a partial index; rerun to continue)")
	f.IntVar(&o.cveYear, "cvelist-from-year", 2024, "cvelistV5: import records from this CVE year onward")
	f.IntVar(&o.msrcMonths, "msrc-months", 12, "msrc: how many recent monthly bulletins to download (each is about 30 MB)")
	f.BoolVar(&o.status, "status", false, "show what is indexed and how old it is, then exit")
	return cmd
}

func nucleiDir(home string) string { return filepath.Join(home, "nuclei-templates") }

func runFeeds(ctx context.Context, out io.Writer, o feedsOptions) error {
	want := map[string]bool{}
	for _, f := range o.only {
		ok := false
		for _, a := range allFeeds {
			ok = ok || a == f
		}
		if !ok {
			return fmt.Errorf("unknown feed %q (available: %s)", f, strings.Join(allFeeds, ", "))
		}
		want[f] = true
	}
	if len(want) == 0 {
		for _, a := range allFeeds {
			want[a] = true
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

	if o.status {
		return printFeedStatus(ctx, out, st)
	}

	var failures []error
	run := func(name string, fn func() error) {
		if !want[name] {
			return
		}
		if err := fn(); err != nil {
			fmt.Fprintf(out, "  %s FAILED: %v\n", name, err)
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
		}
	}

	run("nuclei-templates", func() error { return updateNuclei(ctx, out, st, o) })
	if !o.noDownload {
		fetch := intel.NewFetcher()
		tmp := filepath.Join(o.home, "feeds-tmp")
		defer os.RemoveAll(tmp)
		run("kev", func() error {
			fmt.Fprintln(out, "CISA KEV ...")
			n, changed, err := intel.SyncKEV(ctx, fetch, st, "")
			reportSync(out, "kev", n, changed, err)
			return err
		})
		run("epss", func() error {
			fmt.Fprintln(out, "EPSS ...")
			n, changed, err := intel.SyncEPSS(ctx, fetch, st, "")
			reportSync(out, "epss", n, changed, err)
			return err
		})
		run("nvd", func() error {
			key := os.Getenv("NVD_API_KEY")
			if key == "" {
				fmt.Fprintln(out, "NVD (no API key: rate-limited; set NVD_API_KEY for a ~10x faster first sync) ...")
			} else {
				fmt.Fprintln(out, "NVD ...")
			}
			start := time.Now()
			n, err := intel.SyncNVD(ctx, fetch, st, intel.NVDConfig{APIKey: key, MaxPages: o.nvdPages,
				Logf: func(f string, a ...any) { fmt.Fprintf(out, f+"\n", a...) }})
			if err == nil {
				fmt.Fprintf(out, "  nvd: %d CVEs indexed (%s)\n", n, time.Since(start).Round(time.Second))
			}
			return err
		})
		run("cvelist", func() error {
			fmt.Fprintln(out, "cvelistV5 (version ranges for CVEs NVD has not analysed; ~700 MB download) ...")
			start := time.Now()
			n, changed, err := intel.SyncCVEList(ctx, fetch, st, "", tmp, o.cveYear)
			if err == nil {
				if changed {
					fmt.Fprintf(out, "  cvelist: ranges added for %d CVEs (%s)\n", n, time.Since(start).Round(time.Second))
				} else {
					fmt.Fprintln(out, "  cvelist: already up to date")
				}
			}
			return err
		})
		run("msrc", func() error {
			fmt.Fprintf(out, "Microsoft security bulletins (last %d months) ...\n", o.msrcMonths)
			n, err := intel.SyncMSRC(ctx, fetch, st, "", o.msrcMonths, func(f string, a ...any) { fmt.Fprintf(out, f+"\n", a...) })
			if err == nil {
				fmt.Fprintf(out, "  msrc: %d fixes added\n", n)
			}
			return err
		})
		run("osv", func() error {
			var errs []error
			for _, eco := range o.osv {
				fmt.Fprintf(out, "OSV %s ...\n", eco)
				n, changed, err := intel.SyncOSV(ctx, fetch, st, "", eco, tmp)
				reportSync(out, "osv:"+eco, n, changed, err)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", eco, err))
				}
				if ctx.Err() != nil {
					break
				}
			}
			return errors.Join(errs...)
		})
	} else if len(want) > 0 {
		fmt.Fprintln(out, "--no-download: only local indexing was performed")
	}
	if err := printFeedStatus(ctx, out, st); err != nil {
		return err
	}
	return errors.Join(failures...)
}

func reportSync(out io.Writer, name string, n int, changed bool, err error) {
	switch {
	case err != nil:
	case changed:
		fmt.Fprintf(out, "  %s: %d records updated\n", name, n)
	default:
		fmt.Fprintf(out, "  %s: up to date (%d records)\n", name, n)
	}
}

func printFeedStatus(ctx context.Context, out io.Writer, st *store.Store) error {
	feeds, err := st.ListFeeds(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "\nIndexed data:")
	if len(feeds) == 0 {
		fmt.Fprintln(out, "  (nothing yet: run babylon update-feeds)")
		return nil
	}
	sort.Slice(feeds, func(i, j int) bool { return feeds[i].Name < feeds[j].Name })
	for _, f := range feeds {
		age := ""
		if t, err := time.Parse(time.RFC3339, f.FetchedAt); err == nil {
			age = humanAge(time.Since(t))
		}
		note := ""
		if f.Name == "nvd" && f.Detail != "" {
			note = "  PARTIAL: rerun update-feeds to continue"
		}
		fmt.Fprintf(out, "  %-22s %9d records  updated %s%s\n", f.Name, f.Count, age, note)
	}
	if cves, ranges, err := st.CountCVEs(ctx); err == nil && cves > 0 {
		fmt.Fprintf(out, "  (%d CVEs, %d affected-product ranges available to the matcher)\n", cves, ranges)
	}
	return nil
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func updateNuclei(ctx context.Context, out io.Writer, st *store.Store, o feedsOptions) error {
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
