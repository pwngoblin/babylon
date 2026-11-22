package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"babylon/internal/app"
	"babylon/internal/store"
	"babylon/internal/web"
)

func newServeCmd() *cobra.Command {
	var home, listen string
	var noOpen, allowSudo bool
	var maxScans int
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the local web UI (configure, start and track scans in a browser)",
		Long: `Starts a web interface on this machine only (loopback). It prints a URL
containing a one-time access token; opening it signs your browser in. Other
websites and other machines cannot drive it.

Scans started from the UI use the same engines, safety rules and database as
the command line, and stay visible in 'babylon scans list'.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), cmd.OutOrStdout(), home, listen, noOpen, allowSudo, maxScans)
		},
	}
	f := cmd.Flags()
	f.StringVar(&home, "home", defaultHome(), "data directory")
	f.StringVar(&listen, "listen", "127.0.0.1:8834", "address to listen on (loopback only)")
	f.BoolVar(&noOpen, "no-open", false, "do not open a browser")
	f.BoolVar(&allowSudo, "sudo", false, "let UI scans use `sudo -n nmap` (needs a cached sudo ticket or NOPASSWD)")
	f.IntVar(&maxScans, "max-scans", 2, "maximum simultaneously running scans")
	return cmd
}

func runServe(ctx context.Context, out interface{ Write([]byte) (int, error) }, home, listen string, noOpen, allowSudo bool, maxScans int) error {
	a, err := app.Open(home)
	if err != nil {
		return err
	}
	defer a.Close()
	a.AllowSudo = allowSudo

	// Scans left "running" by a previous process can no longer be running.
	if ids, err := a.St.RunningScanIDs(ctx); err == nil {
		for _, id := range ids {
			_ = a.St.SetScanStatus(ctx, id, store.ScanCancelled)
		}
	}

	token, err := web.NewToken()
	if err != nil {
		return err
	}
	srvHandler, err := web.New(a, token, listen, Version, maxScans)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", listen, err)
	}
	srv := &http.Server{
		Handler: srvHandler.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 32 << 10,
	}
	url := fmt.Sprintf("http://%s/?token=%s", ln.Addr().String(), token)
	fmt.Fprintf(out, "Babylon web UI: %s\n(access is limited to this machine; press Ctrl-C to stop; running scans are paused and can be resumed)\n", url)
	if !noOpen {
		openBrowser(url)
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv.Shutdown(shutCtx)
	srvHandler.Shutdown() // cancels running scans (resumable) and waits for them
	return nil
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return
	}
	_ = cmd.Start()
}
