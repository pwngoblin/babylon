package runner

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	berr "babylon/internal/errors"
)

func TestRunCapturesStdout(t *testing.T) {
	res, err := Run(context.Background(), Spec{Tool: "sh", Args: []string{"-c", "echo hello"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(res.Stdout)) != "hello" {
		t.Fatalf("got %q", res.Stdout)
	}
}

func TestToolMissing(t *testing.T) {
	_, err := Run(context.Background(), Spec{Tool: "definitely-not-a-real-binary"})
	if !errors.Is(err, berr.ErrToolMissing) {
		t.Fatalf("want ErrToolMissing, got %v", err)
	}
}

func TestNonZeroExit(t *testing.T) {
	_, err := Run(context.Background(), Spec{Tool: "sh", Args: []string{"-c", "echo boom >&2; exit 3"}})
	var tf *berr.ToolFailed
	if !errors.As(err, &tf) || tf.ExitCode != 3 || !strings.Contains(tf.StderrTail, "boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTimeoutKillsProcessGroup(t *testing.T) {
	start := time.Now()
	// The shell spawns a child sleeper; both must die.
	_, err := Run(context.Background(), Spec{
		Tool: "sh", Args: []string{"-c", "sleep 30 & sleep 30; wait"},
		Timeout: 200 * time.Millisecond, Grace: 200 * time.Millisecond,
	})
	if !errors.Is(err, berr.ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took too long to kill: %s", d)
	}
}

func TestContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	_, err := Run(ctx, Spec{Tool: "sleep", Args: []string{"30"}, Grace: 100 * time.Millisecond})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestOutputLimit(t *testing.T) {
	_, err := Run(context.Background(), Spec{
		Tool: "sh", Args: []string{"-c", "yes | head -c 10000000"},
		MaxStdout: 1024, Timeout: 10 * time.Second,
	})
	if !errors.Is(err, berr.ErrOutputLimit) {
		t.Fatalf("want ErrOutputLimit, got %v", err)
	}
}

func TestOnLineStreaming(t *testing.T) {
	var lines []string
	_, err := Run(context.Background(), Spec{
		Tool: "sh", Args: []string{"-c", "printf 'a\\nb\\nc\\n'"},
		OnLine: func(l []byte) error { lines = append(lines, string(l)); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(lines, ",") != "a,b,c" {
		t.Fatalf("got %v", lines)
	}
}

func TestOnLineErrorStopsProcess(t *testing.T) {
	sentinel := errors.New("stop")
	_, err := Run(context.Background(), Spec{
		Tool: "sh", Args: []string{"-c", "while true; do echo x; done"},
		OnLine:  func([]byte) error { return sentinel },
		Timeout: 10 * time.Second,
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("want sentinel, got %v", err)
	}
}

func TestResolveToolOverride(t *testing.T) {
	t.Setenv("BABYLON_NMAP", "relative/nmap")
	if _, err := resolveTool("nmap"); err == nil {
		t.Error("a relative override must be refused")
	}
	t.Setenv("BABYLON_NMAP", "/definitely/not/here")
	if _, err := resolveTool("nmap"); err == nil {
		t.Error("a missing override must fail rather than fall back to PATH")
	}
	exe, _ := os.Executable()
	t.Setenv("BABYLON_NMAP", exe)
	if p, err := resolveTool("nmap"); err != nil || p != exe {
		t.Errorf("override not used: %q %v", p, err)
	}
}
