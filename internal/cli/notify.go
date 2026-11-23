package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"babylon/internal/notify"
)

func newNotifyCmd() *cobra.Command {
	var home string
	cmd := &cobra.Command{
		Use:   "notify",
		Short: "Webhook notifications for new findings (configure ~/.babylon/notify.yaml)",
	}
	cmd.PersistentFlags().StringVar(&home, "home", defaultHome(), "data directory")
	cmd.AddCommand(&cobra.Command{
		Use:   "test",
		Short: "Check notify.yaml and send a test message",
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := notify.Load(home)
			if err != nil {
				return err
			}
			if cfg == nil {
				return fmt.Errorf("no notify.yaml in %s. Example:\n\nwebhook:\n  url: https://hooks.example.com/services/XXX\n  format: slack   # or json\nmin_severity: high\n\n(then chmod 600 the file)", home)
			}
			msg := &notify.Message{Text: "Babylon test notification: the webhook is configured correctly.", Targets: []string{"test"}}
			if err := cfg.Send(c.Context(), msg); err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), "test message sent")
			return nil
		},
	})
	return cmd
}
