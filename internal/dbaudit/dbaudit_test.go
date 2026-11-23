package dbaudit

import (
	"context"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"babylon/internal/audit"
)

func bptr(b bool) *bool { return &b }

func TestEveryStatementIsReadOnly(t *testing.T) {
	forbidden := regexp.MustCompile(`(?i)\b(insert|update|delete|drop|alter|create|grant|revoke|truncate|set\s+(global|session|password)|call|exec|copy|load)\b`)
	for _, q := range Statements() {
		first := strings.ToUpper(strings.Fields(q)[0])
		if first != "SELECT" && first != "SHOW" {
			t.Errorf("statement is not a SELECT or SHOW: %s", q)
		}
		if forbidden.MatchString(q) {
			t.Errorf("statement contains a modifying keyword: %s", q)
		}
	}
}

func TestRuleIDsAreUniqueAndComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if seen[r.ID] || r.ID == "" || r.Eval == nil || r.Title == "" || r.Synopsis == "" || (r.Engine != Postgres && r.Engine != MySQL) {
			t.Errorf("bad rule %+v", r)
		}
		seen[r.ID] = true
		switch r.Severity {
		case "info", "low", "medium", "high", "critical":
		default:
			t.Errorf("%s: severity %q", r.ID, r.Severity)
		}
	}
	if len(RulesFor(Postgres)) < 7 || len(RulesFor(MySQL)) < 7 {
		t.Error("expected at least 7 rules per engine")
	}
}

func eval(t *testing.T, id string, f *Facts) audit.Result {
	t.Helper()
	for _, r := range Rules {
		if r.ID == id {
			return r.Eval(f)
		}
	}
	t.Fatalf("no rule %s", id)
	return audit.Result{}
}

func TestPostgresRules(t *testing.T) {
	f := &Facts{Engine: Postgres, Settings: map[string]string{"ssl": "off", "password_encryption": "md5", "log_connections": "off", "log_disconnections": "on"},
		HBAKnown: true,
		HBA: []HBARule{
			{Type: "local", Database: "all", User: "all", Method: "trust"},
			{Type: "host", Database: "all", User: "all", Address: "127.0.0.1", Method: "trust"},
			{Type: "host", Database: "all", User: "all", Address: "all", Method: "md5"},
			{Type: "host", Database: "app", User: "app", Address: "10.0.0.0/24", Method: "scram-sha-256"},
		},
		Accounts: []Account{{Name: "postgres", Super: true, CanLogin: true, NoPassword: bptr(false)}, {Name: "dba", Super: true, CanLogin: true, NoPassword: bptr(false)},
			{Name: "svc", CanLogin: true, NoPassword: bptr(true)}}}
	want := map[string]audit.Status{"PG-001": audit.Fail, "PG-002": audit.Fail, "PG-003": audit.Pass, "PG-008": audit.Fail, "PG-004": audit.Fail,
		"PG-005": audit.Fail, "PG-006": audit.Fail, "PG-007": audit.Fail}
	for id, st := range want {
		if r := eval(t, id, f); r.Status != st {
			t.Errorf("%s: got %s want %s (%+v)", id, r.Status, st, r)
		}
	}
	if r := eval(t, "PG-005", f); !strings.Contains(r.Evidence, "dba") || strings.Contains(r.Evidence, "postgres") {
		t.Errorf("superuser evidence: %s", r.Evidence)
	}
	f.HBA = append(f.HBA, HBARule{Type: "host", Database: "all", User: "all", Address: "10.1.2.3", Method: "trust"})
	if r := eval(t, "PG-003", f); r.Status != audit.Fail || !strings.Contains(r.Evidence, "10.1.2.3") {
		t.Errorf("remote trust must fail: %+v", r)
	}
	f.HBA = []HBARule{{Type: "host", Address: "0.0.0.0/0", Method: "reject"}}
	if r := eval(t, "PG-004", f); r.Status != audit.Pass {
		t.Errorf("a reject rule is not exposure: %+v", r)
	}

	good := &Facts{Engine: Postgres, HBAKnown: true, Settings: map[string]string{"ssl": "on", "password_encryption": "scram-sha-256", "log_connections": "on", "log_disconnections": "on"},
		Accounts: []Account{{Name: "postgres", Super: true, CanLogin: true, NoPassword: bptr(false)}}}
	for _, id := range []string{"PG-001", "PG-002", "PG-003", "PG-004", "PG-005", "PG-006", "PG-007", "PG-008"} {
		if r := eval(t, id, good); r.Status != audit.Pass {
			t.Errorf("hardened server must pass %s: %+v", id, r)
		}
	}
}

// Missing privileges are unknown, never a pass.
func TestUnreadableFactsAreUnknownNotPass(t *testing.T) {
	pg := &Facts{Engine: Postgres, Settings: map[string]string{}, Errors: []string{"hba: permission denied", "roles-password: permission denied"},
		Accounts: []Account{{Name: "x", CanLogin: true}}}
	for _, id := range []string{"PG-001", "PG-002", "PG-003", "PG-004", "PG-006", "PG-007", "PG-008"} {
		if r := eval(t, id, pg); r.Status != audit.Unknown {
			t.Errorf("%s: %+v", id, r)
		}
	}
	my := &Facts{Engine: MySQL, Settings: map[string]string{}}
	for _, id := range []string{"MY-001", "MY-002", "MY-003", "MY-004", "MY-005", "MY-006", "MY-007"} {
		if r := eval(t, id, my); r.Status != audit.Unknown {
			t.Errorf("%s: %+v", id, r)
		}
	}
}

func TestMySQLRules(t *testing.T) {
	f := &Facts{Engine: MySQL, Version: "10.5.29-MariaDB", Settings: map[string]string{"have_ssl": "DISABLED", "local_infile": "ON", "secure_file_priv": "", "general_log": "ON"},
		Accounts: []Account{
			{Name: "root", Host: "localhost", Super: true, NoPassword: bptr(false), AuthPlugin: "mysql_native_password"},
			{Name: "root", Host: "%", Super: true, NoPassword: bptr(false), AuthPlugin: "mysql_native_password"},
			{Name: "", Host: "localhost", NoPassword: bptr(true)},
			{Name: "sock", Host: "localhost", NoPassword: bptr(true), AuthPlugin: "unix_socket"},
			{Name: "old", Host: "%", NoPassword: bptr(true), Locked: true},
			{Name: "app", Host: "%", NoPassword: bptr(true)},
			{Name: "mariadb.sys", Host: "localhost", NoPassword: bptr(true)}, // server-internal, locked
		}}
	for _, id := range []string{"MY-001", "MY-002", "MY-003", "MY-004", "MY-005", "MY-006", "MY-007"} {
		if r := eval(t, id, f); r.Status != audit.Fail {
			t.Errorf("%s should fail: %+v", id, r)
		}
	}
	ev := eval(t, "MY-003", f).Evidence
	if !strings.Contains(ev, "'app'@'%'") || strings.Contains(ev, "'sock'") || strings.Contains(ev, "'old'") || strings.Contains(ev, "mariadb.sys") {
		t.Errorf("no-password evidence must skip socket-auth and locked accounts: %s", ev)
	}
	if ev := eval(t, "MY-004", f).Evidence; !strings.Contains(ev, "'root'@'%'") || strings.Contains(ev, "localhost") {
		t.Errorf("remote super evidence: %s", ev)
	}
	good := &Facts{Engine: MySQL, Settings: map[string]string{"have_ssl": "YES", "local_infile": "OFF", "secure_file_priv": "/var/lib/mysql-files/", "general_log": "OFF"},
		Accounts: []Account{{Name: "root", Host: "localhost", Super: true, NoPassword: bptr(false)}}}
	for _, id := range []string{"MY-001", "MY-002", "MY-003", "MY-004", "MY-005", "MY-006", "MY-007"} {
		if r := eval(t, id, good); r.Status != audit.Pass {
			t.Errorf("hardened server must pass %s: %+v", id, r)
		}
	}
}

func TestHBAAddress(t *testing.T) {
	cases := [][3]string{{"0.0.0.0", "0.0.0.0", "0.0.0.0/0"}, {"::", "::", "::/0"}, {"10.0.0.0", "255.255.255.0", "10.0.0.0/255.255.255.0"},
		{"127.0.0.1", "255.255.255.255", "127.0.0.1"}, {"all", "", "all"}, {"", "", ""}}
	for _, c := range cases {
		if got := hbaAddress(c[0], c[1]); got != c[2] {
			t.Errorf("hbaAddress(%q,%q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
	if !anyAddr("0.0.0.0/0") || !anyAddr("::/0") || !anyAddr("all") || anyAddr("10.0.0.0/8") {
		t.Error("anyAddr")
	}
}

func TestSanitizeRemovesPasswords(t *testing.T) {
	c := Creds{User: "u", Password: "s3cr3t-pw"}
	if got := Sanitize("dial failed for user u password s3cr3t-pw", c); strings.Contains(got, "s3cr3t-pw") {
		t.Fatalf("leaked: %s", got)
	}
}

// The collectors refuse to send a password unencrypted unless asked to.
func TestPlaintextRefusedUnlessAllowed(t *testing.T) {
	addr := os.Getenv("BABYLON_LAB_PG")
	if addr == "" {
		addr = "127.0.0.1:5432"
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err != nil {
		t.Skip("lab PostgreSQL not running (babylon lab up)")
	} else {
		c.Close()
	}
	host, port, _ := net.SplitHostPort(addr)
	p, _ := net.LookupPort("tcp", port)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := Collect(ctx, Postgres, host, p, Creds{User: "postgres", Password: "lab"})
	if err == nil || !strings.Contains(err.Error(), "refused to send credentials unencrypted") {
		t.Fatalf("a TLS-less server must be refused by default: %v", err)
	}
	if strings.Contains(err.Error(), "lab") && strings.Contains(err.Error(), "password") && strings.Contains(err.Error(), "=lab") {
		t.Fatalf("error leaks the password: %v", err)
	}
}
