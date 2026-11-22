package orchestrator

import (
	"net/netip"
	"testing"
)

func pfx(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		} else {
			a := netip.MustParseAddr(s)
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

func TestChunkSplitsLargePrefix(t *testing.T) {
	ch, err := ChunkTargets(pfx("10.0.0.0/22"), 256) // 1024 addrs -> 4 chunks of /24
	if err != nil || len(ch) != 4 {
		t.Fatalf("err=%v chunks=%v", err, ch)
	}
	want := []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"}
	for i, c := range ch {
		if len(c) != 1 || c[0] != want[i] {
			t.Fatalf("chunk %d = %v, want %s", i, c, want[i])
		}
	}
}

func TestChunkPacksSmallTargets(t *testing.T) {
	var in []string
	for i := 1; i <= 10; i++ {
		in = append(in, netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}).String())
	}
	ch, _ := ChunkTargets(pfx(in...), 4)
	if len(ch) != 3 || len(ch[0]) != 4 || len(ch[2]) != 2 {
		t.Fatalf("unexpected packing: %v", ch)
	}
}

func TestChunkCoversEverythingExactlyOnce(t *testing.T) {
	in := pfx("10.1.0.0/20", "192.168.5.0/25", "172.16.0.9", "fd00::/116")
	for _, max := range []uint64{1, 7, 64, 256, 1000} {
		ch, err := ChunkTargets(in, max)
		if err != nil {
			t.Fatal(err)
		}
		var total uint64
		for _, c := range ch {
			var n uint64
			for _, s := range c {
				p, err := netip.ParsePrefix(s)
				if err != nil {
					a := netip.MustParseAddr(s)
					p = netip.PrefixFrom(a, a.BitLen())
				}
				n += hostCount(p)
			}
			if n > max && max >= 1 {
				// A single indivisible unit (/32) can never exceed max>=1.
				t.Fatalf("max=%d: chunk %v has %d addrs", max, c, n)
			}
			total += n
		}
		var want uint64
		for _, p := range in {
			want += hostCount(p)
		}
		if total != want {
			t.Fatalf("max=%d: covered %d addrs, want %d", max, total, want)
		}
	}
}

func TestChunkDeterministic(t *testing.T) {
	a, _ := ChunkTargets(pfx("10.0.0.0/20", "10.9.9.9"), 100)
	b, _ := ChunkTargets(pfx("10.0.0.0/20", "10.9.9.9"), 100)
	if len(a) != len(b) {
		t.Fatal("non-deterministic chunk count")
	}
	for i := range a {
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				t.Fatal("non-deterministic chunk content")
			}
		}
	}
}
