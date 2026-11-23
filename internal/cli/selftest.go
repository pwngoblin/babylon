package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"babylon/internal/runner"
)

// nucleiSelfTest runs Nuclei over a few of the installed templates against a
// throwaway local web server. Nuclei has been seen to hang on some machines
// (the process never exits and no error is printed), which would otherwise
// show up only as a scan that never finishes. A healthy run takes about a second.
func nucleiSelfTest(ctx context.Context, templatesDir string, deadline time.Duration) (detail string, ok bool, ran bool) {
	var tpls []string
	_ = filepath.WalkDir(filepath.Join(templatesDir, "http", "exposed-panels"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".yaml") && len(tpls) < 60 {
			tpls = append(tpls, p)
		}
		return nil
	})
	if len(tpls) < 12 {
		return "no templates installed yet (run: babylon update-feeds --only nuclei-templates)", true, false
	}
	sort.Strings(tpls)
	tpls = tpls[:12]

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "could not open a local test port: " + err.Error(), true, false
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "<html>babylon selftest</html>") })}
	go srv.Serve(l)
	defer srv.Close()

	dir, err := os.MkdirTemp("", "babylon-selftest-")
	if err != nil {
		return err.Error(), true, false
	}
	defer os.RemoveAll(dir)
	tfile, gfile := filepath.Join(dir, "t.txt"), filepath.Join(dir, "g.txt")
	_ = os.WriteFile(tfile, []byte(strings.Join(tpls, "\n")+"\n"), 0o600)
	_ = os.WriteFile(gfile, []byte("http://"+l.Addr().String()+"\n"), 0o600)

	start := time.Now()
	_, err = runner.Run(ctx, runner.Spec{Tool: "nuclei", Timeout: deadline, MaxStdout: 1 << 20,
		Args: []string{"-l", gfile, "-t", tfile, "-duc", "-ni", "-silent", "-no-color", "-jsonl", "-timeout", "5", "-retries", "0"}})
	took := time.Since(start).Round(100 * time.Millisecond)
	if err != nil {
		return fmt.Sprintf("Nuclei did not complete a 12-template run on a local test server within %s (%v). "+
			"Web and CVE template checks will stall on this machine; see docs/known-issues.md", deadline, err), false, true
	}
	return fmt.Sprintf("completed a 12-template run in %s", took), true, true
}
