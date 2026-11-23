package dbaudit

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"babylon/internal/audit"
)

// Live checks against the ground-truth lab (babylon lab up): PostgreSQL 11 on
// 5432 (postgres/lab) and MariaDB 10.5 on 3306 (root/lab). Skipped when the lab
// is not running.
func labUp(t *testing.T, addr string) (string, int) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Skipf("%s not reachable: start the lab with `babylon lab up`", addr)
	}
	c.Close()
	h, p, _ := net.SplitHostPort(addr)
	port, _ := net.LookupPort("tcp", p)
	return h, port
}

func results(f *Facts) map[string]audit.Result {
	out := map[string]audit.Result{}
	for _, r := range RulesFor(f.Engine) {
		out[r.ID] = r.Eval(f)
	}
	return out
}

func TestLivePostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("live lab test")
	}
	host, port := labUp(t, "127.0.0.1:5432")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f, err := Collect(ctx, Postgres, host, port, Creds{User: "postgres", Password: "lab", AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("version %s encrypted=%v settings=%v hba=%d accounts=%d errors=%v", f.Version, f.Encrypted, f.Settings, len(f.HBA), len(f.Accounts), f.Errors)
	if !strings.HasPrefix(f.Version, "11") || f.Encrypted || !f.HBAKnown || len(f.Accounts) == 0 {
		t.Fatalf("collection incomplete: %+v", f)
	}
	r := results(f)
	for id, res := range r {
		t.Logf("%s %s %s", id, res.Status, firstLine(res.Evidence+res.Reason))
	}
	if r["PG-001"].Status != audit.Fail { // the lab server has TLS off
		t.Errorf("PG-001: %+v", r["PG-001"])
	}
	if r["PG-002"].Status != audit.Fail { // PostgreSQL 11 defaults to md5
		t.Errorf("PG-002: %+v", r["PG-002"])
	}
	if r["PG-008"].Status != audit.Fail { // the official image trusts local connections
		t.Errorf("PG-008: %+v", r["PG-008"])
	}
	if r["PG-004"].Status != audit.Fail { // host all all all md5
		t.Errorf("PG-004: %+v", r["PG-004"])
	}
	if _, err := Collect(ctx, Postgres, host, port, Creds{User: "postgres", Password: "wrong", AllowPlaintext: true}); err == nil {
		t.Error("bad password accepted")
	} else if strings.Contains(err.Error(), "wrong") {
		t.Errorf("error leaks the password: %v", err)
	}
}

func TestLiveMariaDB(t *testing.T) {
	if testing.Short() {
		t.Skip("live lab test")
	}
	host, port := labUp(t, "127.0.0.1:3306")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f, err := Collect(ctx, MySQL, host, port, Creds{User: "root", Password: "lab", AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("version %s encrypted=%v accounts=%d errors=%v", f.Version, f.Encrypted, len(f.Accounts), f.Errors)
	if !f.IsMariaDB() || f.Encrypted || len(f.Accounts) == 0 {
		t.Fatalf("collection incomplete: %+v", f)
	}
	r := results(f)
	for id, res := range r {
		t.Logf("%s %s %s", id, res.Status, firstLine(res.Evidence+res.Reason))
	}
	if r["MY-001"].Status != audit.Fail { // have_ssl is DISABLED
		t.Errorf("MY-001: %+v", r["MY-001"])
	}
	if r["MY-004"].Status != audit.Fail { // the image creates root@'%'
		t.Errorf("MY-004: %+v", r["MY-004"])
	}
	if _, err := Collect(ctx, MySQL, host, port, Creds{User: "root", Password: "lab"}); err == nil || !strings.Contains(err.Error(), "refused to send credentials unencrypted") {
		t.Errorf("plaintext must be refused by default: %v", err)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
