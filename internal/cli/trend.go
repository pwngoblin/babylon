package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"babylon/internal/app"
)

func newTrendCmd() *cobra.Command {
	var home string
	var limit int
	cmd := &cobra.Command{
		Use:   "trend",
		Short: "Show how open findings change over time for each set of targets you scan repeatedly",
		RunE: func(c *cobra.Command, _ []string) error {
			a, err := app.Open(home)
			if err != nil {
				return err
			}
			defer a.Close()
			series, err := a.St.Trends(c.Context(), limit)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			if len(series) == 0 {
				fmt.Fprintln(out, "no completed scans yet")
				return nil
			}
			for _, s := range series {
				fmt.Fprintf(out, "\n%s\n", strings.Join(s.Targets, ", "))
				fmt.Fprintf(out, "  %-6s %-20s %5s %5s %5s %5s %5s   %4s %8s\n", "SCAN", "FINISHED", "HOSTS", "CRIT", "HIGH", "MED", "LOW", "NEW", "RESOLVED")
				for i, p := range s.Points {
					nw, rs := fmt.Sprint(p.New), fmt.Sprint(p.Resolved)
					if i == 0 {
						nw, rs = "-", "-" // nothing to compare the first scan with
					}
					note := ""
					if p.Failed {
						note = "  (had failed jobs)"
					}
					fmt.Fprintf(out, "  #%-5d %-20.20s %5d %5d %5d %5d %5d   %4s %8s%s\n", p.ScanID, p.FinishedAt, p.Hosts,
						p.Findings["critical"], p.Findings["high"], p.Findings["medium"], p.Findings["low"], nw, rs, note)
				}
			}
			fmt.Fprintln(out, "\nNEW and RESOLVED compare each scan with the previous scan of the same targets. Triaged findings are not counted.")
			return nil
		},
	}
	cmd.Flags().StringVar(&home, "home", defaultHome(), "data directory")
	cmd.Flags().IntVar(&limit, "last", 10, "scans to show per set of targets (0 = all)")
	return cmd
}
