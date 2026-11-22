package nmap

import (
	"strings"
	"testing"
	"time"

	"babylon/internal/policy"
)

func resolve(t *testing.T, name string, f policy.Flags) *policy.Resolved {
	t.Helper()
	r, err := policy.Resolve(name, f)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func has(args []string, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}

func TestTargetsAreValidated(t *testing.T) {
	for _, bad := range []string{"-sS", "--script=x", "", "host.example.com", "10.0.0.1 -p1", "10.0.0.0/33", "$(id)"} {
		if _, err := SweepArgs([]string{bad}, "/tmp/x.xml", Opts{}); err == nil {
			t.Errorf("target %q must be rejected", bad)
		}
	}
	if _, err := SweepArgs(nil, "/tmp/x.xml", Opts{}); err == nil {
		t.Error("empty targets must be rejected")
	}
	if _, err := SweepArgs([]string{"10.0.0.1", "192.168.0.0/24", "fd00::1"}, "/tmp/x.xml", Opts{}); err != nil {
		t.Error(err)
	}
}

func TestTargetsComeLastAfterAllOptions(t *testing.T) {
	r := resolve(t, policy.TemplateBasic, policy.Flags{})
	args, _ := ScanArgs(r, []string{"10.0.0.1", "10.0.0.2"}, "/tmp/x.xml", Opts{Privilege: PrivRoot, MaxRatePPS: 100})
	n := len(args)
	if args[n-2] != "10.0.0.1" || args[n-1] != "10.0.0.2" {
		t.Fatalf("targets must be the final args: %v", args)
	}
}

func TestPrivilegeSelectsScanType(t *testing.T) {
	r := resolve(t, policy.TemplateFullUnauth, policy.Flags{})
	raw, _ := ScanArgs(r, []string{"10.0.0.1"}, "/tmp/x.xml", Opts{Privilege: PrivSudo})
	if !has(raw, "-sS") || !has(raw, "-O") || has(raw, "-sT") {
		t.Errorf("privileged scan wrong: %v", raw)
	}
	unpriv, _ := ScanArgs(r, []string{"10.0.0.1"}, "/tmp/x.xml", Opts{Privilege: PrivNone})
	if !has(unpriv, "-sT") || has(unpriv, "-sS") || has(unpriv, "-O") {
		t.Errorf("unprivileged must use connect scan without OS detection: %v", unpriv)
	}
}

func TestPortSpecs(t *testing.T) {
	basic, _ := ScanArgs(resolve(t, policy.TemplateBasic, policy.Flags{}), []string{"10.0.0.1"}, "x", Opts{})
	if !has(basic, "--top-ports") || has(basic, "-p-") {
		t.Errorf("basic: %v", basic)
	}
	full, _ := ScanArgs(resolve(t, policy.TemplateFullUnauth, policy.Flags{}), []string{"10.0.0.1"}, "x", Opts{})
	if !has(full, "-p-") {
		t.Errorf("full: %v", full)
	}
	if _, err := ScanArgs(resolve(t, policy.TemplateHostDiscovery, policy.Flags{}), []string{"10.0.0.1"}, "x", Opts{}); err == nil {
		t.Error("host_discovery has no port scan")
	}
}

// Every template/flag combination that reaches Nmap must produce a script
// expression containing only allowlisted names, plus the full denied-category
// subtraction wherever a broad category is used.
func TestScriptExpressionIsAlwaysAllowlisted(t *testing.T) {
	for _, name := range []string{policy.TemplateBasic, policy.TemplateFullUnauth, policy.TemplateCredentialed} {
		for _, active := range []bool{false, true} {
			if active && name != policy.TemplateFullUnauth {
				continue
			}
			r := resolve(t, name, policy.Flags{AllowActive: active})
			args, err := ScanArgs(r, []string{"10.0.0.1"}, "x", Opts{Privilege: PrivRoot})
			if err != nil {
				t.Fatal(err)
			}
			var expr string
			for i, a := range args {
				if a == "--script" {
					expr = args[i+1]
				}
			}
			if expr == "" {
				t.Fatalf("%s: no --script", name)
			}
			if !strings.Contains(expr, "ssl-enum-ciphers") {
				t.Errorf("%s: TLS audit script missing from %q", name, expr)
			}
			if strings.Contains(expr, "(") { // broad categories present: must subtract everything denied
				for _, d := range policy.DeniedNSECategories {
					if !strings.Contains(expr, d) {
						t.Errorf("%s: script expr %q lacks %q", name, expr, d)
					}
				}
			} else {
				for _, n := range strings.Split(expr, ",") {
					if policy.NamedNSEReason(n) == "" {
						t.Errorf("%s: %q is not an allowlisted script", name, n)
					}
				}
			}
		}
	}
}

func TestSweepAndLimits(t *testing.T) {
	args, _ := SweepArgs([]string{"10.0.0.0/24"}, "/tmp/s.xml", Opts{MaxRatePPS: 300, HostTimeout: 90 * time.Second})
	for _, want := range []string{"-sn", "-n", "--max-rate", "300", "--host-timeout", "90s", "/tmp/s.xml"} {
		if !has(args, want) {
			t.Errorf("sweep args missing %q: %v", want, args)
		}
	}
}

func TestCommandWrapsSudoNonInteractively(t *testing.T) {
	tool, argv := Command(Opts{Privilege: PrivSudo}, []string{"-sn", "10.0.0.1"})
	if tool != "sudo" || argv[0] != "-n" || argv[1] != "nmap" {
		t.Errorf("tool=%s argv=%v", tool, argv)
	}
	tool, argv = Command(Opts{Privilege: PrivRoot}, []string{"-sn"})
	if tool != "nmap" || argv[0] != "-sn" {
		t.Errorf("tool=%s argv=%v", tool, argv)
	}
}

func TestCustomPortsValidatedAndUsed(t *testing.T) {
	r := resolve(t, policy.TemplateBasic, policy.Flags{})
	args, err := ScanArgs(r, []string{"10.0.0.1"}, "x", Opts{Ports: "22,80,8000-8100"})
	if err != nil || !has(args, "-p") || !has(args, "22,80,8000-8100") || has(args, "--top-ports") {
		t.Fatalf("args=%v err=%v", args, err)
	}
	for _, bad := range []string{"-sS", "22,-p", "0", "65536", "80-79", "a", "22;ls", "22,", ",22", "--script=x", "1-2-3"} {
		if _, err := ScanArgs(r, []string{"10.0.0.1"}, "x", Opts{Ports: bad}); err == nil {
			t.Errorf("ports %q must be rejected", bad)
		}
	}
}
