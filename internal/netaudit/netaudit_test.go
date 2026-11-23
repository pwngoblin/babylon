package netaudit

import (
	"babylon/internal/store"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"babylon/internal/audit"
)

func load(t *testing.T, name string) *Config {
	t.Helper()
	b, err := os.ReadFile("../../testdata/netconfig/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return Parse(string(b))
}

func results(c *Config) map[string]audit.Result {
	out := map[string]audit.Result{}
	for _, r := range IOSRules {
		out[r.ID] = r.Eval(c)
	}
	return out
}

func TestParseBlocksAndLookups(t *testing.T) {
	c := load(t, "ios-weak.cfg")
	vty := c.BlocksWith("line vty")
	if len(vty) != 2 || !vty[0].Has("transport input") || vty[1].Has("transport input") {
		t.Fatalf("vty blocks: %+v", vty)
	}
	if !c.Has("ip http server") || c.Has("ip ht") || !c.Has("no service password-encryption") {
		t.Error("top-level lookups must match whole commands")
	}
	crlf := Parse("hostname x\r\nline vty 0 4\r\n transport input ssh\r\n!\r\nsnmp-server community a RO\r\n")
	if len(crlf.BlocksWith("line vty")) != 1 || !crlf.BlocksWith("line vty")[0].Has("transport input") || !crlf.Has("snmp-server community") {
		t.Errorf("CRLF or block end handling: %+v", crlf)
	}
}

func TestWeakConfigFailsEveryRule(t *testing.T) {
	r := results(load(t, "ios-weak.cfg"))
	for _, rule := range IOSRules {
		if r[rule.ID].Status != audit.Fail {
			t.Errorf("%s should fail on the weak config: %+v", rule.ID, r[rule.ID])
		}
	}
	if ev := r["IOS-002"].Evidence; !strings.Contains(ev, "username admin password ***") || strings.Contains(ev, "hunter2") || strings.Contains(ev, "vtypass") || strings.Contains(ev, "0822455D0A16") {
		t.Errorf("evidence must not repeat the secrets: %s", ev)
	}
	if ev := r["IOS-004"].Evidence; !strings.Contains(ev, "public") || !strings.Contains(ev, "read-write") {
		t.Errorf("snmp evidence: %s", ev)
	}
	if ev := r["IOS-001"].Evidence; !strings.Contains(ev, "transport input all") || !strings.Contains(ev, "line vty 5 15") {
		t.Errorf("telnet evidence must cover both vty blocks: %s", ev)
	}
}

func TestHardenedConfigPassesEveryRule(t *testing.T) {
	r := results(load(t, "ios-hardened.cfg"))
	for _, rule := range IOSRules {
		if r[rule.ID].Status != audit.Pass {
			t.Errorf("%s should pass on the hardened config: %+v", rule.ID, r[rule.ID])
		}
	}
}

func TestEmptyConfigIsNotAPass(t *testing.T) {
	r := results(Parse("hostname lonely\n"))
	for _, id := range []string{"IOS-001", "IOS-003", "IOS-007"} {
		if r[id].Status != audit.Unknown {
			t.Errorf("%s: a config without the relevant section is unknown, got %+v", id, r[id])
		}
	}
	if r["IOS-008"].Status != audit.Fail { // absence of aaa new-model is itself the finding
		t.Errorf("IOS-008: %+v", r["IOS-008"])
	}
}

func TestSpecificVariants(t *testing.T) {
	cases := []struct {
		name, cfg, rule string
		want            audit.Status
	}{
		{"ssh only", "line vty 0 4\n transport input ssh\n access-class 1 in\n exec-timeout 5 0\n", "IOS-001", audit.Pass},
		{"telnet and ssh", "line vty 0 4\n transport input telnet ssh\n", "IOS-001", audit.Fail},
		{"exec-timeout zero", "line vty 0 4\n access-class 1 in\n exec-timeout 0 0\n", "IOS-007", audit.Fail},
		{"enable secret 5", "enable secret 5 $1$abcd$efgh\n", "IOS-003", audit.Fail},
		{"enable secret 8", "enable secret 8 $8$abcd$efgh\n", "IOS-003", audit.Pass},
		{"snmp custom RO", "snmp-server community Xk9!pq2 RO\n", "IOS-004", audit.Pass},
		{"snmp custom RW", "snmp-server community Xk9!pq2 RW\n", "IOS-004", audit.Fail},
		{"snmp acl after rw", "snmp-server community Xk9!pq2 RW 10\n", "IOS-004", audit.Fail},
		{"http disabled", "no ip http server\n", "IOS-005", audit.Pass},
		{"logging buffered only", "logging buffered 8192\n", "IOS-009", audit.Fail},
		{"logging ip", "logging 10.1.1.1\n", "IOS-009", audit.Pass},
		{"timestamps disabled", "ntp server 1.1.1.1\nservice timestamps log disable\n", "IOS-010", audit.Fail},
		{"cdp off", "no cdp run\n", "IOS-012", audit.Pass},
		{"type 9 user", "username a secret 9 $9$xxxx\n", "IOS-002", audit.Pass},
		{"secret 0 user", "username a secret 0 plain\n", "IOS-002", audit.Fail},
	}
	for _, c := range cases {
		var got audit.Result
		for _, r := range IOSRules {
			if r.ID == c.rule {
				got = r.Eval(Parse(c.cfg))
			}
		}
		if got.Status != c.want {
			t.Errorf("%s: %s got %s want %s (%+v)", c.name, c.rule, got.Status, c.want, got)
		}
	}
}

func TestRuleMetadata(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range IOSRules {
		if seen[r.ID] || r.Title == "" || r.Synopsis == "" || r.Eval == nil || !strings.HasPrefix(r.ID, "IOS-") {
			t.Errorf("bad rule %+v", r)
		}
		seen[r.ID] = true
	}
	if RulesFor("junos") != nil || len(RulesFor(CiscoIOS)) != len(IOSRules) {
		t.Error("RulesFor")
	}
}

func TestRecordStoresFindingsAndCheckRuns(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	defer st.Close()
	ctx := context.Background()
	id, sum, err := Record(ctx, st, "edge-r1", CiscoIOS, load(t, "ios-weak.cfg"))
	if err != nil || sum.Failed != len(IOSRules) || sum.Passed != 0 {
		t.Fatalf("%v %+v", err, sum)
	}
	rows, _ := st.ListFindings(ctx, id, "")
	if len(rows) != len(IOSRules) || rows[0].Address != "edge-r1" || rows[0].Family != Family {
		t.Fatalf("findings: %d %+v", len(rows), rows)
	}
	sc, _ := st.GetScanSummary(ctx, id)
	if sc.Status != store.ScanCompleted || sc.Template != "config_audit" {
		t.Fatalf("scan: %+v", sc)
	}
	// A second run on the same host reuses finding identities, so triage and trends work.
	id2, _, _ := Record(ctx, st, "edge-r1", CiscoIOS, load(t, "ios-hardened.cfg"))
	d, _ := st.DiffScans(ctx, id, id2)
	if len(d.Resolved) != len(IOSRules) || len(d.New) != 0 {
		t.Fatalf("fixing the config must resolve the findings: new=%d resolved=%d", len(d.New), len(d.Resolved))
	}
	if _, _, err := Record(ctx, st, "x", "junos", Parse("")); err == nil {
		t.Fatal("unsupported device type accepted")
	}
	_, sum, _ = Record(ctx, st, "lonely", CiscoIOS, Parse("hostname lonely\n"))
	if sum.Unknown == 0 {
		t.Fatalf("missing sections must be unknown: %+v", sum)
	}
}
