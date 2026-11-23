package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"babylon/internal/app"
	"babylon/internal/report"
	"babylon/internal/store"
)

func newScansCmd() *cobra.Command {
	var home string
	cmd := &cobra.Command{Use: "scans", Short: "Browse, export, compare and delete stored scans"}
	cmd.PersistentFlags().StringVar(&home, "home", defaultHome(), "data directory")

	open := func() (*app.App, error) { return app.Open(home) }

	cmd.AddCommand(&cobra.Command{
		Use: "list", Short: "List stored scans, newest first",
		RunE: func(c *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			list, err := a.St.ListScans(c.Context())
			if err != nil {
				return err
			}
			if len(list) == 0 {
				fmt.Fprintln(c.OutOrStdout(), "No scans stored yet. Run: babylon scan <targets>")
				return nil
			}
			w := c.OutOrStdout()
			fmt.Fprintf(w, "%-4s %-10s %-13s %-20s %-5s %-4s  %s\n", "ID", "STATUS", "TEMPLATE", "STARTED", "HOSTS", "JOBS", "FINDINGS (crit/high/med/low/info)")
			for _, s := range list {
				fmt.Fprintf(w, "%-4d %-10s %-13s %-20s %-5d %d/%-2d  %d/%d/%d/%d/%d  %s\n", s.ID, s.Status, s.Template, trimTS(s.StartedAt), s.Hosts,
					s.JobsDone, s.JobsTotal, s.Findings["critical"], s.Findings["high"], s.Findings["medium"], s.Findings["low"], s.Findings["info"], label(s))
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use: "show <id>", Short: "Show a stored scan's results", Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			sum, err := a.St.GetScanSummary(c.Context(), id)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "Scan %d (%s), status %s\n", id, sum.Template, sum.Status)
			printSummary(c.OutOrStdout(), c.Context(), a.St, id, summaryFromStore(c.Context(), a.St, id), 0, a.Accuracy(c.Context(), id))
			return nil
		},
	})

	var format, outFile, accuracy string
	exp := &cobra.Command{
		Use: "export <id>", Short: "Export a scan report (json, md, csv, html)", Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			acc := accuracy
			if acc == "" {
				acc = a.Accuracy(c.Context(), id)
			}
			r, err := report.Build(c.Context(), a.St, id, acc)
			if err != nil {
				return err
			}
			if format == "pdf" {
				if outFile == "" {
					return fmt.Errorf("--format pdf needs -o <file.pdf>")
				}
				return report.RenderPDF(c.Context(), r, outFile)
			}
			var w io.Writer = c.OutOrStdout()
			if outFile != "" {
				f, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // reports contain sensitive data
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			switch format {
			case "json":
				return report.WriteJSON(w, r)
			case "md", "markdown":
				return report.WriteMarkdown(w, r)
			case "csv":
				return report.WriteCSV(w, r)
			case "html":
				return report.WriteHTML(w, r)
			}
			return fmt.Errorf("unknown format %q (json, md, csv, html, pdf)", format)
		},
	}
	exp.Flags().StringVar(&format, "format", "md", "json, md, csv, html or pdf (pdf needs Chrome/Chromium/weasyprint)")
	exp.Flags().StringVarP(&outFile, "output", "o", "", "write to a file (mode 0600) instead of stdout")
	exp.Flags().StringVar(&accuracy, "accuracy", "", "override the scan's report accuracy (normal or avoid-false-alarms)")
	cmd.AddCommand(exp)

	cmd.AddCommand(&cobra.Command{
		Use: "diff <older-id> <newer-id>", Short: "Compare findings between two scans", Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			x, err := parseID(args[0])
			if err != nil {
				return err
			}
			y, err := parseID(args[1])
			if err != nil {
				return err
			}
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			d, err := a.St.DiffScans(c.Context(), x, y)
			if err != nil {
				return err
			}
			w := c.OutOrStdout()
			fmt.Fprintf(w, "Comparing scan %d -> %d\n", x, y)
			show := func(title string, list []store.FindingRow) {
				fmt.Fprintf(w, "\n%s (%d)\n", title, len(list))
				for _, f := range list {
					fmt.Fprintf(w, "  %-8s %-22s %s\n", strings.ToUpper(f.Severity), fmt.Sprintf("%s:%d", f.Address, f.Port), f.Title)
				}
			}
			show("NEW", d.New)
			show("NOT SEEN THIS TIME (resolved if the same hosts and engines were covered)", d.Resolved)
			fmt.Fprintf(w, "\nPersisting: %d\n", len(d.Persisting))
			return nil
		},
	})

	var yes bool
	del := &cobra.Command{
		Use: "delete <id>", Short: "Delete a scan and its raw output", Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			if !yes {
				return fmt.Errorf("deleting scan %d is permanent; re-run with --yes to confirm", id)
			}
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			if err := a.RemoveScanData(c.Context(), id); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "Deleted scan %d\n", id)
			return nil
		},
	}
	del.Flags().BoolVar(&yes, "yes", false, "confirm deletion")
	cmd.AddCommand(del)
	return cmd
}

func parseID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid scan id %q", s)
	}
	return id, nil
}

func trimTS(s string) string {
	if len(s) >= 19 {
		return strings.Replace(s[:19], "T", " ", 1)
	}
	return s
}

func label(s store.ScanSummary) string {
	t := strings.Join(s.Targets, ",")
	if len(t) > 30 {
		t = t[:27] + "..."
	}
	if s.Name != "" {
		return s.Name + " [" + t + "]"
	}
	return t
}

// summaryFromStore rebuilds an orchestrator-style summary for display.
func summaryFromStore(ctx context.Context, st *store.Store, id int64) (sum orchestratorSummary) {
	sum.Counts, _ = st.JobCounts(ctx, id)
	s, err := st.GetScanSummary(ctx, id)
	if err == nil {
		sum.Status = s.Status
	}
	keys := make([]string, 0, len(sum.Counts))
	for k := range sum.Counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return sum
}
