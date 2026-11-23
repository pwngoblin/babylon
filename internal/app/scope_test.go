package app

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestScope(t *testing.T) {
	home := t.TempDir()
	p := func(s string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(s)} }
	if err := checkScope(home, p("8.8.8.8/32")); err != nil {
		t.Fatalf("no scope file means no restriction: %v", err)
	}
	os.WriteFile(filepath.Join(home, ScopeFile), []byte("# lab\n127.0.0.1\n192.168.88.10/32 # one box\n10.1.0.0/24\n"), 0o600)
	for _, ok := range []string{"127.0.0.1/32", "192.168.88.10/32", "10.1.0.5/32", "10.1.0.0/24"} {
		if err := checkScope(home, p(ok)); err != nil {
			t.Errorf("%s should be allowed: %v", ok, err)
		}
	}
	for _, bad := range []string{"192.168.88.0/24", "192.168.88.11/32", "10.1.0.0/16", "8.8.8.8/32", "::1/128"} {
		if err := checkScope(home, p(bad)); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
	os.WriteFile(filepath.Join(home, ScopeFile), []byte("nonsense\n"), 0o600)
	if err := checkScope(home, p("127.0.0.1/32")); err == nil {
		t.Error("a malformed scope file must refuse everything, not allow everything")
	}
}
