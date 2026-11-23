package native

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"babylon/internal/engines/nmap"
	"babylon/internal/model"
	"babylon/internal/policy"
	"babylon/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	t.Cleanup(func() { st.Close() })
	return st
}

// ingestFixture loads a real Nmap XML into the store and returns the scan id.
func ingestFixture(t *testing.T, st *store.Store, path string) int64 {
	t.Helper()
	ctx := context.Background()
	id, _ := st.CreateScan(ctx, "t", "basic", []string{"127.0.0.1"}, map[string]any{})
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := nmap.Parse(f, func(h model.Host) error { return st.IngestHost(ctx, id, h) }); err != nil {
		t.Fatal(err)
	}
	return id
}

func envFor(t *testing.T, st *store.Store, scanID int64, addr string) *Env {
	t.Helper()
	ctx := context.Background()
	aid, _ := st.AssetID(ctx, addr)
	svcs, _ := st.OpenServices(ctx, scanID)
	var mine []store.ServiceInfo
	for _, s := range svcs {
		if s.Address == addr {
			mine = append(mine, s)
		}
	}
	kb, _ := st.KB(ctx, scanID, aid)
	tls, _ := st.TLSForAsset(ctx, scanID, aid)
	return &Env{Address: addr, AssetID: aid, Services: mine, TLS: tls, KB: kb, Now: time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)}
}

func TestChecksOnRealLabScan(t *testing.T) {
	st := newStore(t)
	scanID := ingestFixture(t, st, "../../testdata/nmap/lab-curated.xml")
	ctx := context.Background()
	env := envFor(t, st, scanID, "127.0.0.1")
	if len(env.KB) == 0 {
		t.Fatal("NSE script output must be stored in the knowledge base at ingest")
	}
	ordered, err := Order(Available(policy.SafetyReadOnly), policy.SafetyReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	if err := RunHost(ctx, st, scanID, env, ordered); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.ListFindings(ctx, scanID, "")
	byTitle := map[string]store.FindingRow{}
	for _, r := range rows {
		byTitle[r.Title] = r
	}
	// Unauthenticated Redis on the lab, found from stored NSE output.
	r, ok := byTitle["Redis Server - Unauthenticated Access"]
	if !ok || r.Port != 16379 || r.Severity != "high" || r.Confidence != model.ConfConfirmed || !strings.Contains(r.Evidence, "Version: 5.0.14") {
		t.Fatalf("redis finding: %+v ok=%v", r, ok)
	}
	// TRACE enabled on the Apache 2.4.49 target.
	if h, ok := byTitle["HTTP TRACE Method Is Enabled"]; !ok || h.Port != 18081 {
		t.Fatalf("http trace: %+v ok=%v", h, ok)
	}
	// nginx (GET HEAD only) must NOT be flagged.
	for _, r := range rows {
		if r.Title == "HTTP TRACE Method Is Enabled" && r.Port == 18082 {
			t.Error("false positive: nginx does not allow TRACE")
		}
	}
	// Coverage: every check has a recorded outcome; irrelevant ones are skipped WITH a reason.
	var ran, skipped, nreason int
	rowsCR, _ := st.DB.Query(`SELECT state, COALESCE(reason,'') FROM check_run WHERE scan_id=?`, scanID)
	defer rowsCR.Close()
	for rowsCR.Next() {
		var s, why string
		rowsCR.Scan(&s, &why)
		switch s {
		case "ran":
			ran++
		case "skipped":
			skipped++
			if why != "" {
				nreason++
			}
		}
	}
	if ran+skipped != len(Available(policy.SafetyReadOnly)) || skipped != nreason || ran < 3 || skipped < 8 {
		t.Fatalf("coverage: ran=%d skipped=%d withReason=%d of %d", ran, skipped, nreason, len(Available(policy.SafetyReadOnly)))
	}
}

func TestSSHWeakAlgorithmParsing(t *testing.T) {
	out := "\n  kex_algorithms: (3)\n      curve25519-sha256\n      diffie-hellman-group1-sha1\n      diffie-hellman-group14-sha1\n" +
		"  server_host_key_algorithms: (2)\n      ssh-ed25519\n      ssh-dss\n" +
		"  encryption_algorithms: (3)\n      aes256-gcm@openssh.com\n      3des-cbc\n      arcfour\n" +
		"  mac_algorithms: (2)\n      hmac-sha2-256\n      hmac-md5\n  compression_algorithms: (1)\n      none"
	weak := WeakSSHAlgorithms(out)
	want := []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "ssh-dss", "3des-cbc", "arcfour", "hmac-md5"}
	joined := strings.Join(weak, "|")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("missing weak algorithm %s in %v", w, weak)
		}
	}
	for _, ok := range []string{"curve25519", "ssh-ed25519", "aes256-gcm", "hmac-sha2-256", "none"} {
		if strings.Contains(joined, ok) {
			t.Errorf("strong algorithm %s flagged: %v", ok, weak)
		}
	}
	// A modern OpenSSH 8.4 default config (the real lab) must produce nothing.
	if w := WeakSSHAlgorithms("\n  kex_algorithms: (2)\n      curve25519-sha256\n      diffie-hellman-group16-sha512\n  mac_algorithms: (1)\n      hmac-sha2-256-etm@openssh.com"); len(w) != 0 {
		t.Errorf("modern config flagged: %v", w)
	}
}

func TestEachCheckFiresOnVulnerableOutputAndNotOnSafe(t *testing.T) {
	type tc struct {
		check  Check
		script string
		bad    string
		good   string
	}
	cases := []tc{
		{ftpAnonymous, "ftp-anon", "Anonymous FTP login allowed (FTP code 230)\n drwxr-xr-x 1 ftp ftp 0 pub", "Login denied"},
		{memcachedOpen, "memcached-info", "Process ID 1\n Version: 1.6.9", "ERROR: authentication required"},
		{mongodbOpen, "mongodb-info", "MongoDB Build info\n version = 4.0", "denied"},
		{x11Open, "x11-access", "X server access is granted", "X server access is denied"},
		{vncNoAuth, "vnc-info", "Protocol version: 3.8\n Security types:\n None (1)", "Security types:\n VNC Authentication (2)"},
		{dnsRecursion, "dns-recursion", "Recursion appears to be enabled", "Recursion appears to be disabled"},
		{smbv1, "smb-protocols", "dialects:\n NT LM 0.12 (SMBv1) [dangerous, but default]\n 2.02", "dialects:\n 2.02\n 2.10\n 3.00"},
		{smbSigning, "smb2-security-mode", "Message signing enabled but not required", "Message signing enabled and required"},
		{httpTrace, "http-methods", "Supported Methods: GET HEAD TRACE\n Potentially risky methods: TRACE", "Supported Methods: GET HEAD POST"},
		{redisUnauth, "redis-info", "Version: 6.0.1\n Role: master", "NOAUTH Authentication required"},
	}
	for _, c := range cases {
		mk := func(out string) *Env {
			raw, _ := json.Marshal(out)
			return &Env{Address: "10.0.0.5",
				Services: []store.ServiceInfo{{Port: 1234, Proto: "tcp", Name: "x"}},
				KB:       map[string]json.RawMessage{store.ScriptKey(1234, "tcp", c.script): raw}}
		}
		if f := c.check.Run(mk(c.bad)); len(f) != 1 || f[0].Title == "" || f[0].Remediation == "" || f[0].Evidence == "" || f[0].Port != 1234 {
			t.Errorf("%s: should fire on vulnerable output: %+v", c.check.ID, f)
		}
		if f := c.check.Run(mk(c.good)); len(f) != 0 {
			t.Errorf("%s: false positive on safe output: %+v", c.check.ID, f)
		}
		if why := c.check.Needs(&Env{KB: map[string]json.RawMessage{}}); why == "" {
			t.Errorf("%s: must be skipped (with a reason) when its script produced nothing", c.check.ID)
		}
	}
}

func TestTLSIssues(t *testing.T) {
	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	issues, sev := TLSIssues([]string{"TLSv1.0 is enabled (deprecated protocol)"}, "2021-01-01T00:00:00", "cn=a", "cn=a", now)
	joined := strings.Join(issues, "|")
	if sev != "medium" || !strings.Contains(joined, "expired on 2021-01-01") || !strings.Contains(joined, "self-signed") || !strings.Contains(joined, "deprecated") {
		t.Fatalf("sev=%s issues=%v", sev, issues)
	}
	if _, sev := TLSIssues([]string{"SSLv3 is enabled (broken protocol)"}, "", "", "", now); sev != "high" {
		t.Errorf("SSLv3 must be high, got %s", sev)
	}
	if issues, _ := TLSIssues(nil, "2030-01-01T00:00:00", "cn=a", "cn=ca", now); len(issues) != 0 {
		t.Errorf("healthy cert flagged: %v", issues)
	}
}

func TestOrderDependenciesAndValidation(t *testing.T) {
	run := func(*Env) []Finding { return nil }
	mk := func(id string, deps ...string) Check { return Check{ID: id, DependsOn: deps, Run: run} }
	ord, err := Order([]Check{mk("c", "b"), mk("b", "a"), mk("a")}, policy.SafetyReadOnly)
	if err != nil || ord[0].ID != "a" || ord[1].ID != "b" || ord[2].ID != "c" {
		t.Fatalf("order=%v err=%v", ord, err)
	}
	for name, cs := range map[string][]Check{
		"cycle":   {mk("x", "y"), mk("y", "x")},
		"unknown": {mk("x", "nope")},
		"dup":     {mk("x"), mk("x")},
		"no run":  {{ID: "x"}},
		"unsafe":  {{ID: "x", Run: run, Safety: policy.SafetyProbe}},
	} {
		if _, err := Order(cs, policy.SafetyReadOnly); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := Order([]Check{{ID: "p", Run: run, Safety: policy.SafetyProbe}}, policy.SafetyProbe); err != nil {
		t.Errorf("probe allowed at probe level: %v", err)
	}
	if _, err := Order([]Check{{ID: "i", Run: run, Safety: policy.SafetyIntrusive}}, policy.SafetyProbe); err == nil {
		t.Error("intrusive must never load")
	}
}

func TestSkippedDependencyAndPanicAreRecorded(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	id, _ := st.CreateScan(ctx, "t", "basic", []string{"x"}, map[string]any{})
	aid, _ := st.AssetID(ctx, "10.0.0.5")
	checks := []Check{
		{ID: "a", Needs: func(*Env) string { return "nothing to check" }, Run: func(*Env) []Finding { return nil }},
		{ID: "b", DependsOn: []string{"a"}, Run: func(*Env) []Finding { return nil }},
		{ID: "boom", Run: func(*Env) []Finding { panic("kaboom") }},
		{ID: "ok", Run: func(*Env) []Finding {
			return []Finding{{Port: 80, Title: "T", Severity: "low"}}
		}},
	}
	ord, err := Order(checks, policy.SafetyReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	if err := RunHost(ctx, st, id, &Env{Address: "10.0.0.5", AssetID: aid}, ord); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	rows, _ := st.DB.Query(`SELECT check_id, state||':'||COALESCE(reason,'') FROM check_run WHERE scan_id=?`, id)
	defer rows.Close()
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		got[k] = v
	}
	if got["a"] != "skipped:nothing to check" || got["b"] != "skipped:dependency a did not run" ||
		!strings.HasPrefix(got["boom"], "error:check panicked") || got["ok"] != "ran:" {
		t.Fatalf("check_run=%v", got)
	}
	if f, _ := st.ListFindings(ctx, id, ""); len(f) != 1 || f[0].Confidence != model.ConfConfirmed {
		t.Fatalf("findings=%+v", f)
	}
}

func TestProbeChecksOnlyAvailableWithActiveSafety(t *testing.T) {
	for _, c := range Available(policy.SafetyReadOnly) {
		if c.Safety != policy.SafetyReadOnly {
			t.Errorf("%s must not load without --allow-active", c.ID)
		}
	}
	if len(Available(policy.SafetyProbe)) <= len(Available(policy.SafetyReadOnly)) {
		t.Error("probe-level checks must load when active probes are allowed")
	}
	if _, err := Order(Builtin(), policy.SafetyReadOnly); err == nil {
		t.Error("Order must refuse probe checks at read-only safety")
	}
}

func TestWeakSSHAlgorithmsFromTerseNmapOutputPlusTables(t *testing.T) {
	out := "\n  kex_algorithms: (2)\n  encryption_algorithms: (1)\n  kex_algorithms:\n    curve25519-sha256\n    diffie-hellman-group14-sha1\n  encryption_algorithms:\n    3des-cbc"
	weak := WeakSSHAlgorithms(out)
	if len(weak) != 2 || !strings.Contains(weak[0], "diffie-hellman-group14-sha1") || weak[1] != "cipher: 3des-cbc" {
		t.Errorf("%v", weak)
	}
}

func TestMemcachedStatsWithoutVersionLine(t *testing.T) {
	e := &Env{Address: "10.0.0.5", Services: []store.ServiceInfo{{Address: "10.0.0.5", Port: 11211, Proto: "tcp"}},
		KB: map[string]json.RawMessage{store.ScriptKey(11211, "tcp", "memcached-info"): json.RawMessage(`"\n  Process ID: 1\n  Uptime: 85 seconds"`)}}
	if got := memcachedOpen.Run(e); len(got) != 1 {
		t.Errorf("real memcached-info output has no version line: %+v", got)
	}
}

func TestSeveralFindingsOfOneCheckOnOnePortAreNotMerged(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	id, _ := st.CreateScan(ctx, "a", "basic", []string{"10.0.0.5"}, map[string]any{})
	if err := st.IngestHost(ctx, id, model.Host{Address: "10.0.0.5", State: "up"}); err != nil {
		t.Fatal(err)
	}
	assetID, _ := st.AssetID(ctx, "10.0.0.5")
	two := Check{ID: "two", Name: "two", Family: "Misconfiguration", Run: func(*Env) []Finding {
		return []Finding{
			{Port: 3306, Proto: "tcp", Title: "Unsupported version", Severity: "high"},
			{Port: 3306, Proto: "tcp", Title: "Does not offer TLS", Severity: "low"},
			{Port: 3307, Proto: "tcp", Title: "Other port", Severity: "low"},
		}
	}}
	if err := RunHost(ctx, st, id, &Env{Address: "10.0.0.5", AssetID: assetID}, []Check{two}); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.ListFindings(ctx, id, "")
	if len(rows) != 3 {
		t.Fatalf("want 3 distinct findings, got %d: %+v", len(rows), rows)
	}
	// Stable across scans: the same run again adds nothing new.
	if err := RunHost(ctx, st, id, &Env{Address: "10.0.0.5", AssetID: assetID}, []Check{two}); err != nil {
		t.Fatal(err)
	}
	if rows, _ = st.ListFindings(ctx, id, ""); len(rows) != 3 {
		t.Fatalf("identity must be stable: %d", len(rows))
	}
}
