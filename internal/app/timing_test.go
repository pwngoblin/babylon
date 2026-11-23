package app

import (
	"net/netip"
	"testing"
)

func TestLastAddr(t *testing.T) {
	for in, want := range map[string]string{"10.0.0.0/24": "10.0.0.255", "192.168.1.5/32": "192.168.1.5", "10.0.0.0/8": "10.255.255.255", "fd00::/64": "fd00::ffff:ffff:ffff:ffff", "10.0.0.8/29": "10.0.0.15"} {
		if got := lastAddr(netip.MustParsePrefix(in)).String(); got != want {
			t.Errorf("lastAddr(%s) = %s, want %s", in, got, want)
		}
	}
}
