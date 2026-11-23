package nmap

import (
	"slices"
	"strings"
	"testing"

	"babylon/internal/policy"
)

func scanArgsFor(t *testing.T, timing string) []string {
	t.Helper()
	res, err := policy.Resolve("basic", policy.Flags{Timing: timing})
	if err != nil {
		t.Fatal(err)
	}
	a, err := ScanArgs(res, []string{"10.0.0.5"}, "/tmp/x.xml", Opts{Timing: res.Timing, MaxRatePPS: 500, Ports: "22,80"})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func hasArg(a []string, flag, val string) bool {
	i := slices.Index(a, flag)
	return i >= 0 && (val == "" || (i+1 < len(a) && a[i+1] == val))
}

func TestTimingProfilesShapeNmapArgs(t *testing.T) {
	std := scanArgsFor(t, "")
	if !hasArg(std, "--max-retries", "2") || !hasArg(std, "--script-timeout", "60s") || !hasArg(std, "--max-rate", "500") || slices.ContainsFunc(std, func(s string) bool { return strings.HasPrefix(s, "-T") }) {
		t.Errorf("standard must keep the conservative defaults: %v", std)
	}
	fast := scanArgsFor(t, policy.TimingFastLAN)
	if !slices.Contains(fast, "-T4") || !hasArg(fast, "--max-retries", "1") || !hasArg(fast, "--max-rtt-timeout", "400ms") || !hasArg(fast, "--script-timeout", "15s") || !hasArg(fast, "--max-rate", "1000") {
		t.Errorf("fast-lan: %v", fast)
	}
	polite := scanArgsFor(t, policy.TimingPolite)
	if !slices.Contains(polite, "-T2") || !hasArg(polite, "--max-retries", "3") || !hasArg(polite, "--script-timeout", "120s") || !hasArg(polite, "--max-rate", "200") {
		t.Errorf("polite: %v", polite)
	}
	// Whatever the profile, the safety-relevant flags are unchanged.
	for _, a := range [][]string{std, fast, polite} {
		if !slices.Contains(a, "--open") || !slices.Contains(a, "-Pn") {
			t.Errorf("profile changed core flags: %v", a)
		}
	}
	if _, err := policy.Resolve("basic", policy.Flags{Timing: "turbo; rm -rf /"}); err == nil {
		t.Error("unknown timing names must be rejected")
	}
}

func TestUDPArgs(t *testing.T) {
	res, err := policy.Resolve("full_unauth", policy.Flags{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UDPArgs(res, []string{"10.0.0.5"}, "/tmp/u.xml", Opts{Privilege: PrivNone}); err == nil {
		t.Error("UDP scanning without raw sockets must be refused, not degraded")
	}
	a, err := UDPArgs(res, []string{"10.0.0.5"}, "/tmp/u.xml", Opts{Privilege: PrivRoot, Timing: res.Timing})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(a, "-sU") || !hasArg(a, "-p", UDPPorts) || !slices.Contains(a, "--open") {
		t.Errorf("udp args: %v", a)
	}
	for _, bad := range []string{"-sS", "-sT", "--top-ports", "-p-", "-O"} {
		if slices.Contains(a, bad) {
			t.Errorf("udp scan must stay targeted, found %s", bad)
		}
	}
	for _, port := range []string{"53", "123", "161", "623", "1900", "5353"} {
		if !strings.Contains(","+UDPPorts+",", ","+port+",") {
			t.Errorf("UDP port list is missing %s", port)
		}
	}
}
