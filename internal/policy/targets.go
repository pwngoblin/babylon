// Package policy turns user intent (targets, template, flags) into safe,
// bounded engine configuration. Nothing here executes tools.
package policy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// DefaultMaxHosts caps how many addresses a single scan may expand to.
const DefaultMaxHosts = 1 << 20 // a /12 worth; callers may lower it

// Target is one parsed target definition.
type Target struct {
	Raw      string
	Prefix   netip.Prefix // set for IP (as /32 or /128) and CIDR
	Hostname string       // set for hostnames (resolved later by the guard)
}

// ParseTargets parses IPs, CIDRs and hostnames. It rejects anything else, in
// particular anything starting with "-" (so a target can never be mistaken for
// a tool flag) or containing whitespace/shell metacharacters.
func ParseTargets(inputs []string) ([]Target, error) {
	var out []Target
	for _, raw := range inputs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "-") {
			return nil, fmt.Errorf("invalid target %q: must not start with '-'", raw)
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, Target{Raw: s, Prefix: p.Masked()})
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, Target{Raw: s, Prefix: netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())})
			continue
		}
		if !validHostname(s) {
			return nil, fmt.Errorf("invalid target %q: not an IP, CIDR or hostname", raw)
		}
		out = append(out, Target{Raw: s, Hostname: strings.ToLower(strings.TrimSuffix(s, "."))})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets given")
	}
	return out, nil
}

func validHostname(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// Count returns how many addresses the prefix covers, saturating at max.
func (t Target) Count(max uint64) uint64 {
	if t.Hostname != "" {
		return 1
	}
	bits := t.Prefix.Addr().BitLen() - t.Prefix.Bits()
	if bits >= 63 || (uint64(1)<<bits) > max {
		return max + 1
	}
	return uint64(1) << bits
}

// IsPrivate reports whether addr is in a range a scanner may touch without an
// explicit authorization override: loopback, RFC1918, link-local, ULA, CGNAT.
func IsPrivate(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || cgnat.Contains(a)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Resolver resolves hostnames; net.DefaultResolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Guard enforces scope rules before any packet is sent.
type Guard struct {
	AllowPublic bool           // set only by an explicit authorization flag
	Deny        []netip.Prefix // never scanned, even if requested
	MaxHosts    uint64         // 0 = DefaultMaxHosts
	Resolver    Resolver       // nil = net.DefaultResolver
}

// Check validates targets and returns the resolved, in-scope target list
// (hostnames replaced by their addresses, original name kept in Raw).
func (g Guard) Check(ctx context.Context, targets []Target) ([]Target, error) {
	max := g.MaxHosts
	if max == 0 {
		max = DefaultMaxHosts
	}
	res := g.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	var out []Target
	var total uint64
	for _, t := range targets {
		expanded := []Target{t}
		if t.Hostname != "" {
			addrs, err := res.LookupNetIP(ctx, "ip", t.Hostname)
			if err != nil || len(addrs) == 0 {
				return nil, fmt.Errorf("cannot resolve %q: %v", t.Raw, err)
			}
			expanded = nil
			for _, a := range addrs {
				a = a.Unmap()
				expanded = append(expanded, Target{Raw: t.Raw, Hostname: t.Hostname, Prefix: netip.PrefixFrom(a, a.BitLen())})
			}
		}
		for _, e := range expanded {
			if err := g.checkOne(e); err != nil {
				return nil, err
			}
			total += e.Count(max)
			if total > max {
				return nil, fmt.Errorf("targets expand to more than %d addresses; narrow the scope or raise the limit", max)
			}
			out = append(out, e)
		}
	}
	return out, nil
}

func (g Guard) checkOne(t Target) error {
	for _, d := range g.Deny {
		if d.Overlaps(t.Prefix) {
			return fmt.Errorf("target %s overlaps denied range %s", t.Raw, d)
		}
	}
	if g.AllowPublic {
		return nil
	}
	// The whole prefix must sit inside one private block (so 10.0.0.0/7, which
	// spans public space, is rejected).
	if !privateSpan(t.Prefix) {
		return fmt.Errorf("target %s is not in a private range; scanning public addresses requires --i-have-authorization", t.Raw)
	}
	return nil
}

// privateSpan checks the whole prefix lies inside a single private block, so
// that e.g. 10.0.0.0/7 (which spans public space) is rejected.
func privateSpan(p netip.Prefix) bool {
	for _, b := range privateBlocks {
		if b.Bits() <= p.Bits() && b.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

var privateBlocks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}
