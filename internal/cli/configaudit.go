package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"babylon/internal/app"
	"babylon/internal/netaudit"
)

const maxConfigBytes = 16 << 20

func newConfigAuditCmd() *cobra.Command {
	var home, devType, host string
	cmd := &cobra.Command{
		Use:   "config-audit <config-file>",
		Short: "Audit a network device's exported running-config (Cisco IOS/IOS-XE) against a hardening baseline",
		Long: `Reads a saved configuration (for example "show running-config" output) and checks it
against hardening rules. Nothing is sent to the device. The result is stored as a
scan, so "babylon scans show", "scans export --compliance ...", triage and
"babylon trend" work on it. Run it again on a newer export to see what was fixed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("--host is required: a name or address that identifies the device in reports")
			}
			info, err := os.Stat(args[0])
			if err != nil {
				return err
			}
			if info.Size() > maxConfigBytes {
				return fmt.Errorf("%s is larger than %d MiB: is it a configuration file?", args[0], maxConfigBytes>>20)
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			a, err := app.Open(home)
			if err != nil {
				return err
			}
			defer a.Close()
			id, sum, err := netaudit.Record(c.Context(), a.St, host, devType, netaudit.Parse(string(data)))
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			fmt.Fprintf(out, "Scan %d: %s (%s): %d failed, %d passed, %d not assessed\n", id, host, devType, sum.Failed, sum.Passed, sum.Unknown)
			rows, err := a.St.ListFindings(c.Context(), id, "")
			if err != nil {
				return err
			}
			for _, r := range rows {
				fmt.Fprintf(out, "  %-8s %s  #%d\n", strings.ToUpper(r.Severity), r.Title, r.ID)
			}
			fmt.Fprintf(out, "\nReport: babylon scans export %d --format html -o report.html --compliance nist-800-53\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&home, "home", defaultHome(), "data directory")
	cmd.Flags().StringVar(&devType, "type", netaudit.CiscoIOS, "device type: "+netaudit.CiscoIOS)
	cmd.Flags().StringVar(&host, "host", "", "name or address of the device (required)")
	return cmd
}
