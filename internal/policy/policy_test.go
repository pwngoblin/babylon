package policy

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, context.DeadlineExceeded
}

func TestParseTargets(t *testing.T) {
	ts, err := ParseTargets([]string{"10.0.0.1", "192.168.1.0/24", "Host.Example.com", "fd00::1"})
	if err != nil || len(ts) != 4 {
		t.Fatalf("err=%v len=%d", err, len(ts))
	}
	if ts[2].Hostname != "host.example.com" {
		t.Fatalf("hostname not normalized: %q", ts[2].Hostname)
	}
	for _, bad := range []string{"-sS", "--script=evil", "10.0.0.1; rm -rf /", "a b", "", "foo..bar", "-10.0.0.1"} {
		if _, err := ParseTargets([]string{bad}); err == nil && bad != "" {
			t.Errorf("target %q should be rejected", bad)
		}
	}
	if _, err := ParseTargets(nil); err == nil {
		t.Error("empty target list should error")
	}
}

func TestGuardPrivateVsPublic(t *testing.T) {
	g := Guard{MaxHosts: 1 << 25, Resolver: fakeResolver{"lab.local": {netip.MustParseAddr("10.1.2.3")}, "pub.example": {netip.MustParseAddr("93.184.216.34")}}}
	ok := []string{"127.0.0.1", "10.0.0.0/8", "172.16.5.0/24", "192.168.0.0/16", "100.64.1.1", "fd12::/120", "lab.local"}
	for _, s := range ok {
		ts, _ := ParseTargets([]string{s})
		if _, err := g.Check(context.Background(), ts); err != nil {
			t.Errorf("%s should be allowed: %v", s, err)
		}
	}
	bad := []string{"8.8.8.8", "93.184.216.0/24", "10.0.0.0/7", "172.0.0.0/8", "0.0.0.0/0", "pub.example", "2001:db8::1"}
	for _, s := range bad {
		ts, _ := ParseTargets([]string{s})
		if _, err := g.Check(context.Background(), ts); err == nil {
			t.Errorf("%s must be rejected without authorization", s)
		}
	}
	g.AllowPublic = true
	ts, _ := ParseTargets([]string{"8.8.8.8"})
	if _, err := g.Check(context.Background(), ts); err != nil {
		t.Errorf("public allowed with flag: %v", err)
	}
}

func TestGuardDenyAndLimits(t *testing.T) {
	g := Guard{Deny: []netip.Prefix{netip.MustParsePrefix("10.0.5.0/24")}, MaxHosts: 1000}
	ts, _ := ParseTargets([]string{"10.0.0.0/16"})
	if _, err := g.Check(context.Background(), ts); err == nil {
		t.Error("expected deny-range overlap or size error")
	}
	ts, _ = ParseTargets([]string{"10.0.5.7"})
	if _, err := g.Check(context.Background(), ts); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected denied error, got %v", err)
	}
	g = Guard{MaxHosts: 255}
	ts, _ = ParseTargets([]string{"10.0.0.0/24"})
	if _, err := g.Check(context.Background(), ts); err == nil {
		t.Error("/24 (256 addrs) must exceed MaxHosts=255")
	}
	g = Guard{MaxHosts: 256}
	if _, err := g.Check(context.Background(), ts); err != nil {
		t.Errorf("/24 within limit: %v", err)
	}
	ts, _ = ParseTargets([]string{"fd00::/16"})
	if _, err := (Guard{MaxHosts: 1000}).Check(context.Background(), ts); err == nil {
		t.Error("huge IPv6 prefix must exceed limit without overflow")
	}
}

// TestSafetyInvariants is the key safety test: for every template and every
// flag combination, no resolved config may contain a denied item, and the
// generated NSE expression must always subtract every denied category.
func TestSafetyInvariants(t *testing.T) {
	for _, name := range TemplateNames() {
		for _, active := range []bool{false, true} {
			for _, creds := range []bool{false, true} {
				r, err := Resolve(name, Flags{AllowActive: active, CheckDefaultCreds: creds})
				if active && name != TemplateFullUnauth {
					if err == nil {
						t.Errorf("%s: --allow-active must be rejected", name)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s active=%v creds=%v: %v", name, active, creds, err)
				}
				for _, c := range r.NSE.Categories {
					if contains(DeniedNSECategories, c) {
						t.Errorf("%s: denied NSE category %q present", name, c)
					}
				}
				if r.Template.NSE {
					expr, err := r.NSE.ScriptExpr()
					if err != nil {
						t.Fatal(err)
					}
					assertExprSafe(t, name+" expr", expr, len(r.NSE.Categories) > 0)
				}
				if r.Nuclei.Enabled {
					for _, d := range DeniedNucleiTags {
						if !contains(r.Nuclei.ExcludeTags, d) {
							t.Errorf("%s: nuclei tag %q not excluded", name, d)
						}
					}
					for _, d := range DeniedNucleiProtocols {
						if !contains(r.Nuclei.ExcludeProtocols, d) {
							t.Errorf("%s: nuclei protocol %q not excluded", name, d)
						}
					}
					for _, d := range DefaultLoginTags {
						if contains(r.Nuclei.ExcludeTags, d) == creds {
							t.Errorf("%s creds=%v: default-login tag %q exclusion wrong", name, creds, d)
						}
					}
				}
				if r.Native.Enabled && r.Native.MaxSafety >= SafetyIntrusive {
					t.Errorf("%s: native checks allow intrusive", name)
				}
				if r.Native.Enabled && r.Native.MaxSafety == SafetyProbe && !(active && name == TemplateFullUnauth) {
					t.Errorf("%s: probe level without --allow-active on Full", name)
				}
			}
		}
	}
}

func TestValidateRejectsTampering(t *testing.T) {
	if err := (NSEConfig{Categories: []string{"default", "intrusive"}}).Validate(); err == nil {
		t.Error("intrusive category must be rejected")
	}
	if err := (NSEConfig{Scripts: map[string][]string{"http-slowloris": {"apache"}}}).Validate(); err == nil {
		t.Error("non-allowlisted script must be rejected")
	}
	if err := (NucleiConfig{Enabled: true, ExcludeTags: []string{"dos"}, ExcludeProtocols: DeniedNucleiProtocols}).Validate(); err == nil {
		t.Error("missing exclusions must be rejected")
	}
	if err := (NativeConfig{Enabled: true, MaxSafety: SafetyIntrusive}).Validate(); err == nil {
		t.Error("intrusive native must be rejected")
	}
}

func TestNSEProductGuard(t *testing.T) {
	r, _ := Resolve(TemplateBasic, Flags{})
	if got := r.NSE.ScriptsForProduct("nginx 1.16.0"); len(got) != 0 {
		t.Errorf("nginx must not get apache-only script, got %v", got)
	}
	got := r.NSE.ScriptsForProduct("Apache httpd 2.4.49")
	if len(got) != 1 || got[0] != "http-vuln-cve2011-3192" {
		t.Errorf("apache should get its script, got %v", got)
	}
}

// TestDenyTablesGolden pins the minimum deny lists independently of the tables
// in safety.go, so removing an entry there fails CI instead of silently
// weakening every other safety test (which read from those same tables).
func TestDenyTablesGolden(t *testing.T) {
	golden := map[string][]string{
		"nse":       {"intrusive", "dos", "exploit", "brute", "fuzzer", "malware", "external"},
		"nuclei":    {"dos", "fuzz", "intrusive", "bruteforce"},
		"protocols": {"headless", "code", "javascript"},
		"defaultlg": {"default-login"},
	}
	tables := map[string][]string{
		"nse": DeniedNSECategories, "nuclei": DeniedNucleiTags,
		"protocols": DeniedNucleiProtocols, "defaultlg": DefaultLoginTags,
	}
	for k, want := range golden {
		for _, w := range want {
			if !contains(tables[k], w) {
				t.Errorf("deny table %q lost mandatory entry %q", k, w)
			}
		}
	}
}

func TestNamedScriptAllowlistAndExpr(t *testing.T) {
	r, _ := Resolve(TemplateBasic, Flags{})
	expr, err := r.NSE.ScriptExpr()
	if err != nil || !strings.Contains(expr, "ssl-cert") || !strings.Contains(expr, "ssl-enum-ciphers") || !strings.Contains(expr, "redis-info") {
		t.Fatalf("expr=%q err=%v", expr, err)
	}
	if strings.Contains(expr, "default") || strings.Contains(expr, "safe") {
		t.Fatalf("basic must use curated names only, got categories: %q", expr)
	}
	full, _ := Resolve(TemplateFullUnauth, Flags{})
	fexpr, _ := full.NSE.ScriptExpr()
	if !strings.HasPrefix(fexpr, "(default or safe) and not (") {
		t.Fatalf("full keeps broad categories with subtraction: %q", fexpr)
	}
	if err := (NSEConfig{Named: []string{"http-slowloris"}}).Validate(); err == nil {
		t.Error("arbitrary named script must be rejected")
	}
	if err := (NSEConfig{Named: []string{"ssl-cert"}}).Validate(); err != nil {
		t.Error(err)
	}
	if _, err := (NSEConfig{}).ScriptExpr(); err == nil {
		t.Error("empty NSE config must not produce an expression")
	}
	for _, n := range CuratedNSEScripts() {
		if NamedNSEReason(n) == "" {
			t.Errorf("script %s has no written justification", n)
		}
	}
}

// assertExprSafe checks an NSE --script expression: every bare token must be an
// allowlisted script name (or part of the category clause), and when a category
// clause is present it must subtract every denied category.
func assertExprSafe(t *testing.T, label, expr string, hasCategories bool) {
	t.Helper()
	clause := ""
	rest := expr
	if hasCategories {
		i := strings.Index(expr, "),")
		if i < 0 {
			i = len(expr) - 1
		}
		clause, rest = expr[:i+1], strings.TrimPrefix(expr[i+1:], ",")
		for _, d := range DeniedNSECategories {
			if !strings.Contains(clause, d) {
				t.Errorf("%s: category clause %q does not subtract %q", label, clause, d)
			}
		}
	}
	if rest == "" {
		return
	}
	for _, name := range strings.Split(rest, ",") {
		if NamedNSEReason(name) == "" {
			t.Errorf("%s: script %q is not in the named allowlist", label, name)
		}
	}
}

// TestNamedScriptsAgainstNmapCategories asks the installed nmap what categories
// each allowlisted script really has, so the allowlist cannot drift unsafe
// (e.g. after an nmap upgrade re-tags a script). Skipped without nmap.
func TestNamedScriptsAgainstNmapCategories(t *testing.T) {
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not installed")
	}
	// The only permitted exception: handshake enumeration tagged intrusive for volume.
	allowIntrusive := map[string]bool{"ssl-enum-ciphers": true}
	for _, name := range CuratedNSEScripts() {
		out, err := exec.Command("nmap", "--script-help", name).CombinedOutput()
		if err != nil {
			t.Errorf("script %s: nmap --script-help failed: %v", name, err)
			continue
		}
		var cats string
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "Categories:") {
				cats = strings.TrimSpace(strings.TrimPrefix(line, "Categories:"))
			}
		}
		if cats == "" {
			t.Errorf("script %s: nmap reports no categories (does it exist?)", name)
			continue
		}
		for _, c := range strings.Fields(cats) {
			if contains(DeniedNSECategories, c) && !(c == "intrusive" && allowIntrusive[name]) {
				t.Errorf("script %s has denied category %q (nmap says: %s)", name, c, cats)
			}
		}
	}
}
