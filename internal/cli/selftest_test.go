package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeTemplates(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	d := filepath.Join(dir, "http", "exposed-panels")
	_ = os.MkdirAll(d, 0o755)
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m"} {
		_ = os.WriteFile(filepath.Join(d, n+".yaml"), []byte("id: "+n+"\n"), 0o644)
	}
	return dir
}

func fakeNucleiBin(t *testing.T, body string) {
	t.Helper()
	bin := t.TempDir()
	_ = os.WriteFile(filepath.Join(bin, "nuclei"), []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestNucleiSelfTestDetectsAHungNuclei(t *testing.T) {
	fakeNucleiBin(t, "exec sleep 30")
	start := time.Now()
	detail, ok, ran := nucleiSelfTest(context.Background(), fakeTemplates(t), 2*time.Second)
	if ok || !ran || !strings.Contains(detail, "did not complete") {
		t.Fatalf("a hung nuclei must fail the self-test: %q ok=%v ran=%v", detail, ok, ran)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("must give up at the deadline, took %s", time.Since(start))
	}
}

func TestNucleiSelfTestPassesForAHealthyNuclei(t *testing.T) {
	fakeNucleiBin(t, "exit 0")
	if detail, ok, ran := nucleiSelfTest(context.Background(), fakeTemplates(t), 5*time.Second); !ok || !ran {
		t.Fatalf("%q", detail)
	}
}

func TestNucleiSelfTestIsSkippedWithoutTemplates(t *testing.T) {
	fakeNucleiBin(t, "exit 0")
	if detail, ok, ran := nucleiSelfTest(context.Background(), t.TempDir(), time.Second); !ok || ran || !strings.Contains(detail, "update-feeds") {
		t.Fatalf("%q ok=%v ran=%v", detail, ok, ran)
	}
}
