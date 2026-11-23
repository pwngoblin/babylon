package app

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// ScopeFile is the optional allow-list of scannable ranges, one IP or CIDR per
// line ('#' starts a comment). If it exists, a scan can never target anything
// outside it: the scanner refuses, whatever flags are passed.
const ScopeFile = "scope.txt"

// loadScope returns the allowed prefixes; ok is false when no scope file exists.
func loadScope(home string) (prefixes []netip.Prefix, ok bool, err error) {
	f, err := os.Open(filepath.Join(home, ScopeFile))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if p, perr := netip.ParsePrefix(line); perr == nil {
			prefixes = append(prefixes, p.Masked())
		} else if a, aerr := netip.ParseAddr(line); aerr == nil {
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
		} else {
			return nil, true, fmt.Errorf("%s line %d: %q is not an IP or CIDR", ScopeFile, n, line)
		}
	}
	return prefixes, true, sc.Err()
}

// checkScope refuses targets outside the scope file (if there is one).
func checkScope(home string, targets []netip.Prefix) error {
	allowed, ok, err := loadScope(home)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	for _, t := range targets {
		in := false
		for _, a := range allowed {
			if a.Addr().BitLen() == t.Addr().BitLen() && a.Bits() <= t.Bits() && a.Contains(t.Addr()) {
				in = true
				break
			}
		}
		if !in {
			return fmt.Errorf("%s is outside the allowed scope (%s in the Babylon data directory); edit that file if you really mean to scan it", t, ScopeFile)
		}
	}
	return nil
}
