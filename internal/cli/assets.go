package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"babylon/internal/app"
	"babylon/internal/store"
)

func newAssetsCmd() *cobra.Command {
	var home string
	cmd := &cobra.Command{
		Use:   "assets",
		Short: "Inventory of known hosts: set how important they are and which are fragile",
	}
	cmd.PersistentFlags().StringVar(&home, "home", defaultHome(), "data directory")

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List known hosts with criticality and open findings from their latest scan",
		RunE: func(c *cobra.Command, _ []string) error {
			a, err := app.Open(home)
			if err != nil {
				return err
			}
			defer a.Close()
			list, err := a.St.ListAssets(c.Context())
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			if len(list) == 0 {
				fmt.Fprintln(out, "no assets yet: run a scan or use `babylon assets set`")
				return nil
			}
			fmt.Fprintf(out, "%-18s %-9s %-5s %-24s %-22s %s\n", "ADDRESS", "CRITICAL", "FRAG", "OPEN (crit/high/med/low)", "NAME / OS", "TAGS")
			for _, x := range list {
				fr := ""
				if x.Fragile {
					fr = "yes"
				}
				open := fmt.Sprintf("%d/%d/%d/%d", x.OpenFindings["critical"], x.OpenFindings["high"], x.OpenFindings["medium"], x.OpenFindings["low"])
				name := strings.Join(x.Hostnames, ",")
				if name == "" {
					name = x.OS
				}
				fmt.Fprintf(out, "%-18s %-9s %-5s %-24s %-22.22s %s\n", x.Address, store.CriticalityName(x.Criticality), fr, open, name, strings.Join(x.Tags, ","))
			}
			return nil
		},
	})

	var crit, tags string
	var fragile, notFragile bool
	set := &cobra.Command{
		Use:   "set <address>",
		Short: "Set criticality, fragility or tags (creates the asset if it has not been scanned yet)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			var u store.AssetUpdate
			if c.Flags().Changed("criticality") {
				n, err := store.ParseCriticality(crit)
				if err != nil {
					return err
				}
				u.Criticality = &n
			}
			if fragile && notFragile {
				return fmt.Errorf("use --fragile or --not-fragile, not both")
			}
			if fragile || notFragile {
				v := fragile
				u.Fragile = &v
			}
			if c.Flags().Changed("tags") {
				var t []string
				for _, x := range strings.Split(tags, ",") {
					if x = strings.TrimSpace(x); x != "" {
						t = append(t, x)
					}
				}
				u.Tags = &t
			}
			if u.Criticality == nil && u.Fragile == nil && u.Tags == nil {
				return fmt.Errorf("nothing to change: use --criticality, --fragile, --not-fragile or --tags")
			}
			a, err := app.Open(home)
			if err != nil {
				return err
			}
			defer a.Close()
			if err := a.St.UpdateAsset(c.Context(), args[0], u); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "updated %s\n", args[0])
			return nil
		},
	}
	set.Flags().StringVar(&crit, "criticality", "", "low, medium (default), high or critical: raises the rank of this host's findings")
	set.Flags().BoolVar(&fragile, "fragile", false, "never send active probes to this host (old appliances, PLCs, printers)")
	set.Flags().BoolVar(&notFragile, "not-fragile", false, "clear the fragile flag")
	set.Flags().StringVar(&tags, "tags", "", "comma-separated tags (replaces the current list)")
	cmd.AddCommand(set)
	return cmd
}
