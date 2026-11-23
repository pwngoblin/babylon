// Package runner executes external tools safely: no shell, context timeouts,
// process-group kill, and bounded output capture.
package runner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	berr "babylon/internal/errors"
)

const (
	defaultGrace     = 3 * time.Second
	defaultStderrCap = 8 << 10 // bytes of stderr tail kept
)

// Spec describes one external invocation. Argv is passed directly to the
// binary; it is never interpreted by a shell.
type Spec struct {
	Tool       string                  // binary name or path
	Args       []string                // argv[1:]
	Timeout    time.Duration           // 0 = no timeout beyond ctx
	Grace      time.Duration           // time between SIGTERM and SIGKILL (default 3s)
	MaxStdout  int64                   // 0 = unlimited; exceeding it kills the process
	StdoutFile string                  // if set, stdout streams to this file instead of memory
	OnLine     func(line []byte) error // if set, stdout is streamed line by line (not captured)
	Env        []string                // extra env (appended to os.Environ())
	Dir        string
}

// Result is the outcome of a run.
type Result struct {
	Stdout     []byte // empty when StdoutFile or OnLine is used
	StderrTail string
	ExitCode   int
	Duration   time.Duration
}

// Run executes spec and returns when the process exits, times out, or ctx is
// cancelled. On timeout/cancel the whole process group is terminated.
func Run(ctx context.Context, spec Spec) (*Result, error) {
	path, err := resolveTool(spec.Tool)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", berr.ErrToolMissing, spec.Tool)
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if spec.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, spec.Timeout)
		defer cancel()
	}

	cmd := exec.Command(path, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Env = append(os.Environ(), spec.Env...)
	setProcessGroup(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr tailBuffer
	stderr.cap = defaultStderrCap
	cmd.Stderr = &stderr

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", spec.Tool, err)
	}

	grace := spec.Grace
	if grace == 0 {
		grace = defaultGrace
	}

	// Watchdog: kill the process group on ctx expiry.
	done := make(chan struct{})
	var wasKilled atomic.Bool
	watchdogExit := make(chan struct{})
	go func() {
		defer close(watchdogExit)
		select {
		case <-runCtx.Done():
			wasKilled.Store(true)
			killGroup(cmd, grace, done)
		case <-done:
		}
	}()

	res := &Result{}
	readErr := consume(stdout, spec, res, cmd)
	waitErr := cmd.Wait()
	close(done)
	<-watchdogExit
	res.Duration = time.Since(start)
	res.StderrTail = stderr.String()

	if wasKilled.Load() {
		// Killed by the watchdog: distinguish timeout from caller cancel.
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return res, fmt.Errorf("%w after %s: %s", berr.ErrTimeout, spec.Timeout, spec.Tool)
		}
		return res, ctx.Err()
	}

	if readErr != nil {
		return res, readErr
	}
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, &berr.ToolFailed{Tool: spec.Tool, ExitCode: res.ExitCode, StderrTail: res.StderrTail}
		}
		return res, waitErr
	}
	return res, nil
}

// consume drains stdout according to spec. If a limit or callback error is
// hit it kills the process group so Wait returns promptly.
func consume(r io.Reader, spec Spec, res *Result, cmd *exec.Cmd) error {
	var limit io.Reader = r
	var counter *countingReader
	if spec.MaxStdout > 0 {
		counter = &countingReader{r: r, max: spec.MaxStdout}
		limit = counter
	}

	fail := func(err error) error {
		killGroup(cmd, 0, nil)
		_, _ = io.Copy(io.Discard, r) // unblock the pipe
		return err
	}

	switch {
	case spec.OnLine != nil:
		sc := bufio.NewScanner(limit)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			line := append([]byte(nil), sc.Bytes()...)
			if err := spec.OnLine(line); err != nil {
				return fail(err)
			}
		}
		if err := sc.Err(); err != nil {
			if counter != nil && counter.exceeded {
				return fail(berr.ErrOutputLimit)
			}
			return fail(err)
		}
	case spec.StdoutFile != "":
		f, err := os.OpenFile(spec.StdoutFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		if _, err := io.Copy(f, limit); err != nil {
			if counter != nil && counter.exceeded {
				return fail(berr.ErrOutputLimit)
			}
			return fail(err)
		}
	default:
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, limit); err != nil {
			if counter != nil && counter.exceeded {
				return fail(berr.ErrOutputLimit)
			}
			return fail(err)
		}
		res.Stdout = buf.Bytes()
	}
	return nil
}

type countingReader struct {
	r        io.Reader
	n, max   int64
	exceeded bool
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		c.exceeded = true
		return n, berr.ErrOutputLimit
	}
	return n, err
}

// tailBuffer keeps only the last cap bytes written.
type tailBuffer struct {
	buf []byte
	cap int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.cap {
		t.buf = t.buf[len(t.buf)-t.cap:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(bytes.TrimSpace(t.buf)) }

// resolveTool finds an external program. BABYLON_<TOOL> (upper-case, '-' as
// '_') overrides the PATH lookup, so a pinned absolute path can be used
// instead of whatever PATH resolves first.
func resolveTool(name string) (string, error) {
	env := "BABYLON_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	if p := os.Getenv(env); p != "" {
		if !filepath.IsAbs(p) {
			return "", fmt.Errorf("%s must be an absolute path", env)
		}
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			return "", fmt.Errorf("%w: %s (%s)", berr.ErrToolMissing, name, env)
		}
		return p, nil
	}
	return exec.LookPath(name)
}
