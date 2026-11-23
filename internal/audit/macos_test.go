package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"babylon/internal/store"
)

func TestParseMacSettings(t *testing.T) {
	if ParseSIP("System Integrity Protection status: enabled.") != TriOn ||
		ParseSIP("System Integrity Protection status: disabled.") != TriOff ||
		ParseSIP("This is a custom configuration.") != TriOff || ParseSIP("") != TriUnknown {
		t.Error("SIP")
	}
	if ParseGatekeeper("assessments enabled") != TriOn || ParseGatekeeper("assessments disabled") != TriOff {
		t.Error("gatekeeper")
	}
	if ParseFileVault("FileVault is On.") != TriOn || ParseFileVault("FileVault is Off.") != TriOff || ParseFileVault("usage: fdesetup") != TriUnknown {
		t.Error("filevault")
	}
	if ParseALF("Firewall is enabled. (State = 1)") != TriOn || ParseALF("Firewall is disabled. (State = 0)") != TriOff {
		t.Error("alf")
	}
	if ParseStealth("Stealth mode enabled") != TriOn || ParseStealth("Stealth mode disabled") != TriOff ||
		ParseStealth("Firewall stealth mode is off") != TriOff || ParseStealth("Firewall stealth mode is on") != TriOn {
		t.Error("stealth")
	}
	d := ParseDefaults("{\n    AutomaticCheckEnabled = 1;\n    CriticalUpdateInstall = 0;\n    LastFullSuccessfulDate = \"2026-11-01 10:00:00 +0000\";\n    Nested = {\n        x = 1;\n    };\n}\n")
	if _, nested := d["x"]; nested || d["AutomaticCheckEnabled"] != "1" || d["CriticalUpdateInstall"] != "0" || d["LastFullSuccessfulDate"] == "" {
		t.Errorf("%v", d)
	}
	real := "{\n    AccountInfo =     {\n        FirstLogins =         {\n            alice = 1;\n        };\n    };\n    GuestEnabled = 0;\n    RecentUsers =     (\n        alice\n    );\n}\n"
	if r := ParseDefaults(real); r["GuestEnabled"] != "0" || r["alice"] != "" || len(r) != 1 {
		t.Errorf("real-world nested output: %v", r)
	}
	if ParseDefaults("  \n") != nil {
		t.Error("no output means nil")
	}
}

func TestCmpDotted(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"26.7", "26.7.1", -1}, {"26.10", "26.7", 1}, {"15.8.3", "15.8.3", 0}, {"26", "26.0", 0}, {"14.8.9", "15.0", -1}} {
		if got := CmpDotted(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d", c.a, c.b, got)
		}
	}
}

type fakeMacSrc struct {
	rels  []store.AppleRelease
	fixes []store.AppleFix
	n     int
}

func (f fakeMacSrc) AppleFixesForMajor(_ context.Context, m int) ([]store.AppleFix, error) {
	var out []store.AppleFix
	for _, x := range f.fixes {
		if x.Major == m {
			out = append(out, x)
		}
	}
	return out, nil
}
func (f fakeMacSrc) AppleReleases(_ context.Context, m int) ([]store.AppleRelease, error) {
	var out []store.AppleRelease
	for _, x := range f.rels {
		if x.Major == m {
			out = append(out, x)
		}
	}
	return out, nil
}
func (f fakeMacSrc) CountApple(context.Context) (int, int, error) { return f.n, len(f.rels), nil }

func macHost(ver string) *Facts { return &Facts{Mac: &MacFacts{ProductVersion: ver, Build: "25A"}} }

func TestMatchMacUpdates(t *testing.T) {
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	src := fakeMacSrc{n: 5,
		rels: []store.AppleRelease{
			{Major: 26, Release: "26.6", Product: "macOS Tahoe", Released: "2026-07-27"},
			{Major: 26, Release: "26.7", Product: "macOS Tahoe", Released: "2026-09-14"},
			{Major: 26, Release: "26.7.3", Product: "macOS Tahoe", Released: "2026-11-09"},
			{Major: 13, Release: "13.7.8", Product: "macOS Ventura", Released: "2025-08-20"},
		},
		fixes: []store.AppleFix{
			{Major: 26, Release: "26.6", CVE: "CVE-1", Product: "macOS Tahoe"},
			{Major: 26, Release: "26.7", CVE: "CVE-2", Product: "macOS Tahoe"},
			{Major: 26, Release: "26.7.3", CVE: "CVE-3", Product: "macOS Tahoe"},
			{Major: 26, Release: "26.7.3", CVE: "CVE-2", Product: "macOS Tahoe"}, // repeated: earliest fix wins
			{Major: 15, Release: "15.8.3", CVE: "CVE-9"},
		}}
	got, st, err := MatchMacUpdates(context.Background(), src, macHost("26.6"), now)
	if err != nil || st.Unsupported != "" || st.Latest != "26.7.3" || st.OutOfSupport {
		t.Fatalf("%+v %v", st, err)
	}
	if len(got) != 2 || got[0].CVE != "CVE-2" || got[0].FixedIn != "26.7" || got[1].CVE != "CVE-3" {
		t.Fatalf("a 26.6 host misses what 26.7 and 26.7.3 fixed, not CVE-1 or other lines: %+v", got)
	}
	if got, _, _ := MatchMacUpdates(context.Background(), src, macHost("26.7.3"), now); len(got) != 0 {
		t.Errorf("a current host has nothing missing: %+v", got)
	}
	// A line whose newest release is over a year old is out of support.
	_, st, _ = MatchMacUpdates(context.Background(), src, macHost("13.7.1"), now)
	if !st.OutOfSupport || st.Latest != "13.7.8" {
		t.Errorf("%+v", st)
	}
	// A line Apple does not list at all is out of support too.
	_, st, _ = MatchMacUpdates(context.Background(), src, macHost("11.7"), now)
	if !st.OutOfSupport || st.Unsupported == "" {
		t.Errorf("%+v", st)
	}
	// No data: say so instead of reporting a clean host.
	_, st, _ = MatchMacUpdates(context.Background(), fakeMacSrc{}, macHost("26.6"), now)
	if !strings.Contains(st.Unsupported, "update-feeds --only apple") || st.OutOfSupport {
		t.Errorf("%+v", st)
	}
}

func TestMacRulesUnknownIsNeverPass(t *testing.T) {
	f := macHost("26.6")
	for _, r := range MacRules {
		if res := r.Eval(f); res.Status != Unknown {
			t.Errorf("%s with no facts must be unknown, got %s", r.ID, res.Status)
		}
	}
	f.Mac.SIP, f.Mac.Gatekeeper, f.Mac.FileVault, f.Mac.Firewall = TriOff, TriOff, TriOff, TriOff
	f.Mac.SoftUpdate = map[string]string{"AutomaticCheckEnabled": "0", "CriticalUpdateInstall": "0"}
	f.Mac.Login = map[string]string{"GuestEnabled": "1", "autoLoginUser": "alice"}
	for _, r := range MacRules {
		res := r.Eval(f)
		if r.ID == "MAC-005" { // stealth mode defers to the firewall rule
			if res.Status != Unknown {
				t.Errorf("MAC-005: %s", res.Status)
			}
			continue
		}
		if res.Status != Fail || res.Remediation == "" || res.Evidence == "" {
			t.Errorf("%s: %+v", r.ID, res)
		}
	}
	f.Mac.SIP, f.Mac.Gatekeeper, f.Mac.FileVault, f.Mac.Firewall, f.Mac.Stealth = TriOn, TriOn, TriOn, TriOn, TriOn
	f.Mac.SoftUpdate = map[string]string{"AutomaticCheckEnabled": "1", "CriticalUpdateInstall": "1", "ConfigDataInstall": "1"}
	f.Mac.Login = map[string]string{"GuestEnabled": "0"}
	for _, r := range MacRules {
		if res := r.Eval(f); res.Status != Pass {
			t.Errorf("%s should pass: %+v", r.ID, res)
		}
	}
}

func TestCollectMacHostAndRuleSelection(t *testing.T) {
	r := fakeRunner{
		cmdUname:       "Darwin 25.1.0 arm64\n",
		cmdSwVers:      "ProductName: macOS\nProductVersion: 26.6.1\nBuildVersion: 25G90\n",
		cmdCsrutil:     "System Integrity Protection status: enabled.\n",
		cmdSpctl:       "assessments enabled\n",
		cmdFDE:         "FileVault is Off.\n",
		cmdALFState:    "Firewall is enabled. (State = 1)\n",
		cmdBrew:        "openssl@3 3.3.1\nwget 1.24.5\n",
		cmdSoftUpdate:  "{\n AutomaticCheckEnabled = 1;\n}\n",
		cmdLoginWindow: "{\n GuestEnabled = 0;\n}\n",
	}
	f, err := Collect(context.Background(), r)
	if err != nil || f.Mac == nil {
		t.Fatalf("%v %+v", err, f)
	}
	if f.OS.ID != "macos" || f.Mac.ProductVersion != "26.6.1" || f.Mac.Build != "25G90" || f.Mac.FileVault != TriOff || f.Mac.SIP != TriOn {
		t.Errorf("%+v %+v", f.OS, f.Mac)
	}
	if len(f.Packages) != 2 {
		t.Errorf("brew packages: %+v", f.Packages)
	}
	for _, e := range f.Errors {
		if strings.Contains(e, "os-release") || strings.Contains(e, "no installed packages") {
			t.Errorf("Linux-only noise on a Mac: %q", e)
		}
	}
	ids := map[string]bool{}
	for _, r := range RulesFor(f) {
		ids[r.ID] = true
	}
	if !ids["MAC-001"] || !ids["SSH-001"] || ids["PERM-001"] || ids["FW-001"] || ids["DOCKER-001"] {
		t.Errorf("rule selection: %v", ids)
	}
	if rs := RulesFor(&Facts{}); len(rs) != len(Rules) {
		t.Error("Linux hosts keep the full set")
	}
}

func TestMacCommandsAreAllowlistedAndReadOnly(t *testing.T) {
	cmds := []string{cmdCsrutil, cmdSpctl, cmdFDE, cmdALFState, cmdALFStealth, cmdSoftUpdate, cmdLoginWindow}
	allowedSet := map[string]bool{}
	for _, c := range AllowedCommands() {
		allowedSet[c] = true
	}
	for _, c := range cmds {
		if !allowedSet[c] {
			t.Errorf("%q is not allowlisted", c)
		}
		for _, bad := range []string{"write", "--set", "enable", "disable", "sudo", " -w "} {
			if strings.Contains(c, bad) {
				t.Errorf("%q looks like a modifying command", c)
			}
		}
	}
}
