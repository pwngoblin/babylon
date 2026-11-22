package orchestrator

import (
	"fmt"
	"net/netip"
)

// ChunkTargets splits prefixes into chunks of at most maxHosts addresses each.
// Large prefixes are split into aligned sub-prefixes; small ones are packed
// together. Output is deterministic for a given input, so planning is
// idempotent across resume.
func ChunkTargets(prefixes []netip.Prefix, maxHosts uint64) ([][]string, error) {
	if maxHosts == 0 {
		return nil, fmt.Errorf("maxHosts must be > 0")
	}
	var chunks [][]string
	var cur []string
	var curN uint64

	flush := func() {
		if len(cur) > 0 {
			chunks = append(chunks, cur)
			cur, curN = nil, 0
		}
	}

	for _, p := range prefixes {
		for _, sp := range splitPrefix(p.Masked(), maxHosts) {
			n := hostCount(sp)
			if curN+n > maxHosts {
				flush()
			}
			cur = append(cur, prefixString(sp))
			curN += n
		}
	}
	flush()
	return chunks, nil
}

// hostCount returns the number of addresses in p, saturating at 1<<62.
func hostCount(p netip.Prefix) uint64 {
	bits := p.Addr().BitLen() - p.Bits()
	if bits >= 62 {
		return 1 << 62
	}
	return 1 << uint(bits)
}

func prefixString(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.String()
}

// splitPrefix breaks p into aligned sub-prefixes each holding <= maxHosts
// addresses (rounded down to a power of two).
func splitPrefix(p netip.Prefix, maxHosts uint64) []netip.Prefix {
	hostBits := 0
	for (uint64(1) << uint(hostBits+1)) <= maxHosts {
		hostBits++
	}
	total := p.Addr().BitLen() - p.Bits()
	if total <= hostBits {
		return []netip.Prefix{p}
	}
	newBits := p.Addr().BitLen() - hostBits
	count := uint64(1) << uint(newBits-p.Bits())
	out := make([]netip.Prefix, 0, count)
	addr := p.Addr()
	for i := uint64(0); i < count; i++ {
		out = append(out, netip.PrefixFrom(addr, newBits))
		addr = addPow2(addr, hostBits)
	}
	return out
}

// addPow2 returns a + 2^exp (byte-wise with carry; works for IPv4 and IPv6).
func addPow2(a netip.Addr, exp int) netip.Addr {
	b := a.AsSlice()
	idx := len(b) - 1 - exp/8
	carry := uint16(1) << uint(exp%8)
	for i := idx; i >= 0 && carry > 0; i-- {
		sum := uint16(b[i]) + carry
		b[i] = byte(sum)
		carry = sum >> 8
	}
	out, _ := netip.AddrFromSlice(b)
	return out
}
