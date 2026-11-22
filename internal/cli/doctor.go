package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"babylon/internal/runner"
)

type toolCheck struct {
	name     string
	args     []string
	required bool
	why      string
	verRe    *regexp.Regexp // optional: tool-specific version pattern (first capture group)
}

var tools = []toolCheck{
	{name: "nmap", args: []string{"--version"}, required: true, why: "discovery, service fingerprinting, TLS"},
	{name: "nuclei", args: []string{"-version"}, required: true, why: "web/CVE/exposure templates", verRe: regexp.MustCompile(`Engine Version: v?(\d+\.\d+(?:\.\d+)?)`)},
	{name: "trivy", args: []string{"--version"}, why: "container images and language lockfiles (optional)"},
}

var versionRe = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check that required external tools and privileges are available",
		RunE: func(cmd *cobra.Command, _ []string) error {
			failed := false
			for _, t := range tools {
				status, ok := probe(cmd.Context(), t)
				mark := "ok  "
				if !ok {
					if t.required {
						mark = "FAIL"
						failed = true
					} else {
						mark = "warn"
					}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "[%s] %-7s %s (%s)\n", mark, t.name, status, t.why)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "[info] privileges: %s\n", privilegeNote())
			if failed {
				return fmt.Errorf("required tools are missing")
			}
			return nil
		},
	}
}

func probe(ctx context.Context, t toolCheck) (string, bool) {
	if _, err := exec.LookPath(t.name); err != nil {
		return "not found in PATH", false
	}
	res, err := runner.Run(ctx, runner.Spec{Tool: t.name, Args: t.args, Timeout: 10 * time.Second, MaxStdout: 1 << 16})
	out := ""
	if res != nil {
		out = string(res.Stdout) + res.StderrTail
	}
	if err != nil && out == "" {
		return fmt.Sprintf("failed to run: %v", err), false
	}
	if t.verRe != nil {
		if m := t.verRe.FindStringSubmatch(out); m != nil {
			return "v" + m[1], true
		}
	}
	if v := versionRe.FindString(out); v != "" {
		return "v" + v, true
	}
	return strings.TrimSpace(firstLine(out)), true
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func privilegeNote() string {
	if os.Geteuid() == 0 {
		return "running as root: nmap SYN/ARP/UDP scans available"
	}
	return "unprivileged: nmap will use sudo if configured, otherwise fall back to connect scans (reduced discovery)"
}
