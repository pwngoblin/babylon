package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"babylon/internal/native"
	"babylon/internal/pack"
)

func newChecksCmd() *cobra.Command {
	var home string
	cmd := &cobra.Command{
		Use:   "checks",
		Short: "List, validate and test check packs (built-in and ~/.babylon/checks)",
	}
	cmd.PersistentFlags().StringVar(&home, "home", defaultHome(), "data directory")
	packDir := func() string { return filepath.Join(home, "checks") }

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List every check: built-in Go checks and pack checks",
		RunE: func(c *cobra.Command, _ []string) error {
			return listChecks(c.OutOrStdout(), packDir())
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "validate [file...]",
		Short: "Validate pack files (schema, limits, regexes); with no files, the user pack directory",
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()
			if len(args) == 0 {
				defs, err := pack.All(packDir())
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "ok: %d checks (built-in and %s)\n", len(defs), packDir())
				return nil
			}
			for _, f := range args {
				data, err := os.ReadFile(f)
				if err != nil {
					return err
				}
				defs, err := pack.Parse(data, f)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "ok: %s (%d checks)\n", f, len(defs))
			}
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "test [id...]",
		Short: "Run every check's own fixtures against a local mock (nothing leaves this machine)",
		RunE: func(c *cobra.Command, ids []string) error {
			defs, err := pack.All(packDir())
			if err != nil {
				return err
			}
			want := map[string]bool{}
			for _, id := range ids {
				want[id] = true
			}
			out := c.OutOrStdout()
			failed, ran := 0, 0
			for _, d := range defs {
				if len(want) > 0 && !want[d.ID] {
					continue
				}
				ran++
				if err := pack.RunFixtures(d); err != nil {
					failed++
					fmt.Fprintf(out, "FAIL %s: %v\n", d.ID, err)
				}
			}
			if ran == 0 {
				return fmt.Errorf("no checks matched")
			}
			fmt.Fprintf(out, "%d checks, %d failed\n", ran, failed)
			if failed > 0 {
				return fmt.Errorf("%d check(s) failed their fixtures", failed)
			}
			return nil
		},
	})
	return cmd
}

func listChecks(out io.Writer, packDir string) error {
	type row struct{ id, kind, family, sev, name string }
	var rows []row
	for _, c := range native.Builtin() {
		rows = append(rows, row{c.ID, "go/" + c.Safety.String(), c.Family, "", c.Name})
	}
	defs, err := pack.All(packDir)
	if err != nil {
		return err
	}
	for _, d := range defs {
		k := d.Kind
		if d.Kind == "probe" {
			k += "/" + d.Transport
		}
		rows = append(rows, row{d.ID, "pack/" + k, d.Family, d.Severity, d.Name})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	for _, r := range rows {
		fmt.Fprintf(out, "%-16s %-20s %-8s %s\n", r.id, r.kind, r.sev, r.name)
	}
	fmt.Fprintf(out, "\n%d checks (%d built-in Go, %d from packs)\n", len(rows), len(native.Builtin()), len(defs))
	return nil
}
