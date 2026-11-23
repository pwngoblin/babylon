// Package cli wires the babylon command tree.
package cli

import (
	"context"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "0.0.0-dev"

// Execute runs the root command.
func Execute(ctx context.Context) error {
	root := &cobra.Command{
		Use:           "babylon",
		Short:         "Local-first vulnerability and configuration scanner",
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       Version,
	}
	root.AddCommand(newDoctorCmd(), newScanCmd(), newScansCmd(), newFeedsCmd(), newServeCmd(), newLabCmd(), newChecksCmd())
	return root.ExecuteContext(ctx)
}
