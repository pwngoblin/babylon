package cli

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"babylon/internal/app"
	"babylon/internal/store"
)

func newTriageCmd() *cobra.Command {
	var home string
	cmd := &cobra.Command{
		Use:   "triage",
		Short: "Mark findings as accepted risk or false positive (carried across scans, with an expiry)",
	}
	cmd.PersistentFlags().StringVar(&home, "home", defaultHome(), "data directory")

	var status, reason, expires string
	add := &cobra.Command{
		Use:   "add <finding-id>",
		Short: "Record a decision for a finding (ids are shown in `scans show` and reports)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(strings.TrimPrefix(args[0], "#"), 10, 64)
			if err != nil {
				return fmt.Errorf("finding id must be a number")
			}
			now := time.Now()
			exp, err := parseExpiry(expires, now)
			if err != nil {
				return err
			}
			st := map[string]string{"accepted-risk": store.TriageAcceptedRisk, "accepted_risk": store.TriageAcceptedRisk,
				"false-positive": store.TriageFalsePositive, "false_positive": store.TriageFalsePositive}[status]
			if st == "" {
				return fmt.Errorf("--status must be accepted-risk or false-positive")
			}
			a, err := app.Open(home)
			if err != nil {
				return err
			}
			defer a.Close()
			if err := a.St.SetTriage(c.Context(), id, st, reason, exp, now); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "finding %d marked %s\n", id, strings.ReplaceAll(st, "_", " "))
			return nil
		},
	}
	add.Flags().StringVar(&status, "status", "", "accepted-risk (needs --expires, at most 365 days) or false-positive")
	add.Flags().StringVar(&reason, "reason", "", "why (required)")
	add.Flags().StringVar(&expires, "expires", "", "when the decision lapses: 90d, 12w, or a date like 2026-12-31")
	cmd.AddCommand(add)

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List triage decisions, marking expired ones",
		RunE: func(c *cobra.Command, _ []string) error {
			a, err := app.Open(home)
			if err != nil {
				return err
			}
			defer a.Close()
			rows, err := a.St.ListTriage(c.Context(), time.Now())
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			if len(rows) == 0 {
				fmt.Fprintln(out, "no triage decisions")
				return nil
			}
			for _, r := range rows {
				state := "active"
				if !r.Active {
					state = "EXPIRED"
				}
				exp := r.ExpiresAt
				if exp == "" {
					exp = "never"
				}
				fmt.Fprintf(out, "#%-5d %-8s %-14s %-8s expires %-22s %s:%d %s\n        reason: %s\n", r.FindingID, strings.ToUpper(r.Severity),
					strings.ReplaceAll(r.Status, "_", " "), state, exp, r.Address, r.Port, r.Title, r.Reason)
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "remove <finding-id>",
		Short: "Delete a decision so the finding counts again",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(strings.TrimPrefix(args[0], "#"), 10, 64)
			if err != nil {
				return fmt.Errorf("finding id must be a number")
			}
			a, err := app.Open(home)
			if err != nil {
				return err
			}
			defer a.Close()
			if err := a.St.RemoveTriage(c.Context(), id); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "finding %d counts again\n", id)
			return nil
		},
	})
	return cmd
}

var durRe = regexp.MustCompile(`^(\d+)([dw])$`)

// parseExpiry accepts "" (none), "90d", "12w" or a date (end of that day, local time).
func parseExpiry(s string, now time.Time) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if m := durRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		if m[2] == "w" {
			n *= 7
		}
		t := now.AddDate(0, 0, n)
		return &t, nil
	}
	d, err := time.ParseInLocation("2006-01-02", s, now.Location())
	if err != nil {
		return nil, fmt.Errorf("--expires must look like 90d, 12w or 2026-12-31")
	}
	t := d.Add(24*time.Hour - time.Second)
	return &t, nil
}
