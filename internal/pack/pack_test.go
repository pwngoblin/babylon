package pack

import (
	"os"
	"strings"
	"testing"

	"babylon/internal/native"
	"babylon/internal/policy"
	"babylon/internal/store"
)

func TestBuiltinPacksParseAndFixturesPass(t *testing.T) {
	defs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) < 20 {
		t.Fatalf("expected the seed packs, got %d checks", len(defs))
	}
	seen := map[string]bool{}
	for _, d := range defs {
		if seen[d.ID] {
			t.Fatalf("duplicate id %s", d.ID)
		}
		seen[d.ID] = true
		d := d
		t.Run(d.ID, func(t *testing.T) {
			if err := RunFixtures(d); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A fixture runner that cannot fail proves nothing: make the vulnerable
// verdict wrong and the runner must notice.
func TestFixtureRunnerCatchesWrongExpectations(t *testing.T) {
	defs, _ := Builtin()
	var d Def
	for _, x := range defs {
		if x.ID == "BBL-HTTP-0001" {
			d = x
		}
	}
	d.Tests = append([]Test(nil), d.Tests...)
	for i := range d.Tests {
		if d.Tests[i].Want == "finding" {
			d.Tests[i].Want = "none"
		}
	}
	if err := RunFixtures(d); err == nil {
		t.Fatal("runner accepted a wrong expectation")
	}
}

const good = `schema: 1
checks:
  - id: TST-HTTP-0001
    name: n
    family: f
    severity: low
    kind: probe
    transport: http
    when: { ports: [80] }
    steps:
      - http: { path: /x }
        expect: { status: 200 }
    finding: { title: t, synopsis: s, remediation: r }
    tests:
      - { name: a, want: finding, responses: [{ status: 200 }] }
      - { name: b, want: none, responses: [{ status: 404 }] }
`

func TestParseAcceptsMinimalCheck(t *testing.T) {
	if _, err := Parse([]byte(good), "t"); err != nil {
		t.Fatal(err)
	}
}

// Each mutation breaks one rule; Parse must refuse every one.
func TestValidationRefusesUnsafeOrSloppyChecks(t *testing.T) {
	cases := map[string]struct{ old, new, want string }{
		"write method":      {"http: { path: /x }", "http: { method: POST, path: /x }", "not allowed"},
		"delete method":     {"http: { path: /x }", "http: { method: DELETE, path: /x }", "not allowed"},
		"path injection":    {"path: /x", `path: "/x\r\nHost: evil"`, "line breaks"},
		"relative path":     {"path: /x", "path: x", "start with /"},
		"no scope":          {"when: { ports: [80] }", "when: {}", "ports or services"},
		"bad port":          {"ports: [80]", "ports: [70000]", "out of range"},
		"accepts anything":  {"expect: { status: 200 }", "expect: {}", "expect something"},
		"bad regex":         {"expect: { status: 200 }", "expect: { body: '(' }", "expect.body"},
		"unknown key":       {"severity: low", "severity: low\n    sudo: true", "field sudo"},
		"bad severity":      {"severity: low", "severity: scary", "severity"},
		"bad kind":          {"kind: probe", "kind: exploit", "passive or probe"},
		"bad transport":     {"transport: http", "transport: smtp", "transport"},
		"no tests":          {"      - { name: b, want: none, responses: [{ status: 404 }] }\n", "", "two tests"},
		"only positive":     {"name: b, want: none", "name: b, want: finding", "both"},
		"response mismatch": {"responses: [{ status: 404 }]", "responses: []", "one response per step"},
		"bad id":            {"TST-HTTP-0001", "bad id", "id must"},
		"bad cve":           {"synopsis: s", "synopsis: s, cves: [CVE-1]", "bad CVE"},
		"bad control":       {"remediation: r }", "remediation: r }\n    controls: [nope]", "control"},
		"missing remedy":    {", remediation: r", "", "remediation"},
		"huge read":         {"- http: { path: /x }", "- read: 999999999\n        http: { path: /x }", "read must"},
		"too many steps":    {"      - http: { path: /x }\n        expect: { status: 200 }\n", strings.Repeat("      - http: { path: /x }\n        expect: { status: 200 }\n", 9), "steps"},
		"payload in http":   {"- http: { path: /x }", "- send: hi\n        http: { path: /x }", "only the http"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(good, c.old) {
				t.Fatalf("test bug: %q not in template", c.old)
			}
			_, err := Parse([]byte(strings.Replace(good, c.old, c.new, 1)), "t")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestPassiveChecksCannotSendAndProbesCannotMatch(t *testing.T) {
	passive := `schema: 1
checks:
  - id: TST-PASS-0001
    name: n
    family: f
    severity: low
    kind: passive
    transport: tcp
    when: { ports: [21] }
    match: [{ field: banner, regex: x }]
    finding: { title: t, synopsis: s, remediation: r }
    tests:
      - { name: a, want: finding, service: { banner: x } }
      - { name: b, want: none, service: { banner: y } }
`
	if _, err := Parse([]byte(passive), "t"); err == nil || !strings.Contains(err.Error(), "sends nothing") {
		t.Fatalf("passive check with transport accepted: %v", err)
	}
	bad := strings.Replace(passive, "    transport: tcp\n", "", 1)
	bad = strings.Replace(bad, "field: banner", "field: password", 1)
	if _, err := Parse([]byte(bad), "t"); err == nil || !strings.Contains(err.Error(), "match field") {
		t.Fatalf("unknown passive field accepted: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(passive, "    transport: tcp\n", "", 1)), "t"); err != nil {
		t.Fatalf("valid passive check rejected: %v", err)
	}
}

func TestSchemaVersionRequired(t *testing.T) {
	if _, err := Parse([]byte(strings.Replace(good, "schema: 1", "schema: 2", 1)), "t"); err == nil {
		t.Fatal("wrong schema accepted")
	}
}

// Probe-level packs must not load without --allow-active.
func TestProbeChecksAreNotOfferedAtReadOnlySafety(t *testing.T) {
	ro, err := Checks("", policy.SafetyReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	all, _ := Checks("", policy.SafetyProbe)
	if len(ro) == 0 || len(ro) >= len(all) {
		t.Fatalf("readonly=%d probe=%d", len(ro), len(all))
	}
	for _, c := range ro {
		if c.Safety != policy.SafetyReadOnly {
			t.Fatalf("%s is %s but was offered at read-only", c.ID, c.Safety)
		}
	}
	if _, err := native.Order(all, policy.SafetyReadOnly); err == nil {
		t.Fatal("Order accepted probe checks at read-only safety")
	}
}

// A pack can only touch ports the scan found open: a service on another port
// must be ignored even if its name matches.
func TestChecksOnlyApplyToMatchingOpenServices(t *testing.T) {
	d := mustOne(t, good)
	c := Compile(d)
	env := &native.Env{Address: "127.0.0.1", Services: []store.ServiceInfo{{Port: 8081, Proto: "tcp", Name: "http"}}}
	if c.Needs(env) == "" {
		t.Fatal("check applied to a service outside its scope")
	}
	env.Services[0].Port = 80
	if c.Needs(env) != "" {
		t.Fatal("check did not apply to its own port")
	}
	env.Services[0].Proto = "udp"
	if c.Needs(env) == "" {
		t.Fatal("tcp check applied to a udp service")
	}
}

func mustOne(t *testing.T, src string) Def {
	t.Helper()
	defs, err := Parse([]byte(src), "t")
	if err != nil {
		t.Fatal(err)
	}
	return defs[0]
}

func TestUserDirLoadsAndDuplicatesAreRefused(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(dir+"/mine.yaml", good); err != nil {
		t.Fatal(err)
	}
	defs, err := All(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range defs {
		found = found || d.ID == "TST-HTTP-0001"
	}
	if !found {
		t.Fatal("user check not loaded")
	}
	if err := writeFile(dir+"/dup.yaml", good); err != nil {
		t.Fatal(err)
	}
	if _, err := All(dir); err == nil || !strings.Contains(err.Error(), "defined twice") {
		t.Fatalf("duplicate id accepted: %v", err)
	}
	if err := writeFile(dir+"/dup.yaml", "schema: 1\nchecks: [oops"); err != nil {
		t.Fatal(err)
	}
	if _, err := All(dir); err == nil {
		t.Fatal("a malformed user pack must be an error, not silently ignored")
	}
	if defs, err := All(dir + "/missing"); err != nil || len(defs) == 0 {
		t.Fatalf("missing user dir should be fine: %v", err)
	}
}

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o644) }
