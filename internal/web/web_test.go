package web

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"babylon/internal/app"
	"babylon/internal/model"
)

const listen = "127.0.0.1:8834"

type harness struct {
	t     *testing.T
	app   *app.App
	srv   *Server
	h     http.Handler
	token string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	a, err := app.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := NewToken()
	s, err := New(a, tok, listen, "test", 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(); a.Close() })
	return &harness{t: t, app: a, srv: s, h: s.Handler(), token: tok}
}

type opt func(*http.Request)

func withHost(h string) opt      { return func(r *http.Request) { r.Host = h } }
func withHeader(k, v string) opt { return func(r *http.Request) { r.Header.Set(k, v) } }
func noCookie() opt              { return func(r *http.Request) { r.Header.Del("Cookie") } }

func (hn *harness) do(method, path, body string, opts ...opt) *httptest.ResponseRecorder {
	hn.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = listen
	req.Header.Set("Cookie", cookieName+"="+hn.token)
	if method != "GET" {
		req.Header.Set(csrfHeader, "1")
		req.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(req)
	}
	rr := httptest.NewRecorder()
	hn.h.ServeHTTP(rr, req)
	return rr
}

func TestAuthenticationAndTokenExchange(t *testing.T) {
	h := newHarness(t)
	if rr := h.do("GET", "/api/scans", "", noCookie()); rr.Code != 401 {
		t.Fatalf("api without cookie = %d", rr.Code)
	}
	if rr := h.do("GET", "/", "", noCookie()); rr.Code != 401 || !strings.Contains(rr.Body.String(), "not signed in") {
		t.Fatalf("index without cookie = %d", rr.Code)
	}
	if rr := h.do("GET", "/app.js", "", noCookie()); rr.Code != 401 {
		t.Fatalf("static assets must need the session, got %d", rr.Code)
	}
	if rr := h.do("GET", "/api/scans", "", withHeader("Cookie", cookieName+"=wrong")); rr.Code != 401 {
		t.Fatalf("wrong cookie = %d", rr.Code)
	}
	if rr := h.do("GET", "/?token=nope", "", noCookie()); rr.Code != 403 {
		t.Fatalf("bad token = %d", rr.Code)
	}
	rr := h.do("GET", "/?token="+h.token, "", noCookie())
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/" {
		t.Fatalf("token exchange: code=%d loc=%q (token must be stripped from the URL)", rr.Code, rr.Header().Get("Location"))
	}
	var ck *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == cookieName {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Value != h.token {
		t.Fatalf("session cookie wrong: %+v", ck)
	}
	if rr := h.do("GET", "/", ""); rr.Code != 200 || !strings.Contains(rr.Body.String(), "<title>Babylon</title>") {
		t.Fatalf("index when signed in = %d", rr.Code)
	}
}

func TestDNSRebindingAndHostAllowlist(t *testing.T) {
	h := newHarness(t)
	for _, host := range []string{"evil.example.com", "evil.example.com:8834", "127.0.0.1.evil.com:8834", "127.0.0.1:9999", "10.0.0.5:8834", ""} {
		if rr := h.do("GET", "/api/scans", "", withHost(host)); rr.Code != 403 {
			t.Errorf("Host %q must be refused even with a valid cookie, got %d", host, rr.Code)
		}
	}
	for _, host := range []string{"127.0.0.1:8834", "localhost:8834", "LOCALHOST:8834", "[::1]:8834"} {
		if rr := h.do("GET", "/api/status", "", withHost(host)); rr.Code != 200 {
			t.Errorf("Host %q should be allowed, got %d", host, rr.Code)
		}
	}
}

func TestCSRFProtection(t *testing.T) {
	h := newHarness(t)
	body := `{"template":"host_discovery","targets":["127.0.0.1"]}`
	// A cross-site form/fetch cannot add a custom header: refused.
	req := httptest.NewRequest("POST", "/api/scans", strings.NewReader(body))
	req.Host = listen
	req.Header.Set("Cookie", cookieName+"="+h.token)
	rr := httptest.NewRecorder()
	h.h.ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("POST without CSRF header = %d", rr.Code)
	}
	if rr := h.do("POST", "/api/scans", body, withHeader("Origin", "http://evil.example.com")); rr.Code != 403 {
		t.Fatalf("cross-origin POST = %d", rr.Code)
	}
	if rr := h.do("DELETE", "/api/scans/1", "", withHeader(csrfHeader, "0")); rr.Code != 403 {
		t.Fatalf("DELETE with wrong header = %d", rr.Code)
	}
	if rr := h.do("DELETE", "/api/scans/1", "", withHeader("Origin", "http://"+listen)); rr.Code == 403 {
		t.Fatalf("same-origin request must pass the CSRF layer, got %d", rr.Code)
	}
}

func TestSecurityHeadersEverywhere(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/", "/api/status", "/api/nope", "/app.js"} {
		for _, rr := range []*httptest.ResponseRecorder{h.do("GET", p, ""), h.do("GET", p, "", noCookie())} {
			csp := rr.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") ||
				!strings.Contains(csp, "frame-ancestors 'none'") {
				t.Errorf("%s: weak CSP %q", p, csp)
			}
			if rr.Header().Get("X-Content-Type-Options") != "nosniff" || rr.Header().Get("Referrer-Policy") != "no-referrer" || rr.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("%s: missing hardening headers", p)
			}
		}
	}
}

func TestNewRefusesNonLoopbackAndWeakToken(t *testing.T) {
	a, _ := app.Open(t.TempDir())
	defer a.Close()
	tok, _ := NewToken()
	for _, bad := range []string{"0.0.0.0:8834", "192.168.1.5:8834", "example.com:80", ":8834", "[::]:8834"} {
		if _, err := New(a, tok, bad, "t", 1); err == nil {
			t.Errorf("listen %q must be refused", bad)
		}
	}
	for _, ok := range []string{"127.0.0.1:0", "localhost:8834", "[::1]:8834"} {
		if _, err := New(a, tok, ok, "t", 1); err != nil {
			t.Errorf("listen %q should be allowed: %v", ok, err)
		}
	}
	if _, err := New(a, "short", listen, "t", 1); err == nil {
		t.Error("short token must be refused")
	}
	if t1, t2 := mustTok(t), mustTok(t); t1 == t2 || len(t1) != 64 {
		t.Error("tokens must be random and 256-bit")
	}
}

func mustTok(t *testing.T) string {
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestRequestValidation(t *testing.T) {
	h := newHarness(t)
	cases := map[string]string{
		"unknown field":    `{"template":"basic","targets":["10.0.0.1"],"admin":true}`,
		"not json":         `nope`,
		"public refused":   `{"template":"basic","targets":["8.8.8.8"]}`,
		"option injection": `{"template":"basic","targets":["-sS"]}`,
		"bad template":     `{"template":"rm -rf","targets":["10.0.0.1"]}`,
		"bad ports":        `{"template":"basic","targets":["10.0.0.1"],"ports":"22,-p"}`,
		"active on basic":  `{"template":"basic","targets":["10.0.0.1"],"allow_active":true}`,
		"creds not built":  `{"template":"credentialed","targets":["10.0.0.1"]}`,
		"empty targets":    `{"template":"basic","targets":[]}`,
		"bad accuracy":     `{"template":"basic","targets":["10.0.0.1"],"accuracy":"x"}`,
	}
	for name, body := range cases {
		rr := h.do("POST", "/api/scans", body)
		if rr.Code != 400 {
			t.Errorf("%s: want 400 got %d (%s)", name, rr.Code, rr.Body.String())
		}
	}
	if rr := h.do("POST", "/api/scans", strings.Repeat("a", maxBody+10)); rr.Code != 400 {
		t.Errorf("oversized body must be rejected, got %d", rr.Code)
	}
	// Nothing was created by any rejected request.
	if list, _ := h.app.St.ListScans(nil2()); len(list) != 0 {
		t.Fatalf("rejected requests created %d scans", len(list))
	}
	// A request cannot enable sudo: that is decided by whoever starts the server.
	var sresp map[string]any
	json.Unmarshal(h.do("GET", "/api/status", "").Body.Bytes(), &sresp)
	if sresp["sudo_allowed"] != false {
		t.Errorf("sudo must be off by default: %v", sresp["sudo_allowed"])
	}
}

func nil2() (ctx interface {
	Deadline() (time.Time, bool)
	Done() <-chan struct{}
	Err() error
	Value(any) any
}) {
	return bg{}
}

type bg struct{}

func (bg) Deadline() (time.Time, bool) { return time.Time{}, false }
func (bg) Done() <-chan struct{}       { return nil }
func (bg) Err() error                  { return nil }
func (bg) Value(any) any               { return nil }

// fakeNmap emulates a -sn sweep so a real scan can run end to end in a test.
func fakeNmap(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	fx, _ := filepath.Abs("../../testdata/nmap/sweep.xml")
	script := "#!/bin/sh\nout=\"\"\nwhile [ $# -gt 0 ]; do [ \"$1\" = \"-oX\" ] && out=\"$2\"; shift; done\ncp \"" + fx + "\" \"$out\"\n"
	if err := os.WriteFile(filepath.Join(dir, "nmap"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func waitStatus(t *testing.T, h *harness, id string, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var d map[string]map[string]any
		json.Unmarshal(h.do("GET", "/api/scans/"+id, "").Body.Bytes(), &d)
		if s := d["scan"]; s != nil && s["Status"] == want && s["running"] == false {
			return s
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("scan %s never reached %s", id, want)
	return nil
}

func TestScanLifecycleExportAndDelete(t *testing.T) {
	fakeNmap(t)
	h := newHarness(t)
	rr := h.do("POST", "/api/scans", `{"name":"web <b>test</b>","template":"host_discovery","targets":["10.0.0.0/29"]}`)
	if rr.Code != 201 {
		t.Fatalf("create = %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		ID      int64 `json:"id"`
		Started bool  `json:"started"`
	}
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := "1"
	if created.ID != 1 || !created.Started {
		t.Fatalf("created=%+v", created)
	}
	s := waitStatus(t, h, id, "completed")
	if s["Hosts"].(float64) != 1 {
		t.Fatalf("scan=%v", s)
	}

	// Seed a hostile finding to check export safety through the real HTTP path.
	h.app.St.RecordFinding(nil2(), 1, model.Finding{Fingerprint: "x", Address: "10.0.0.5", Port: 80, Proto: "tcp", Severity: "high",
		Title: "=cmd|' /C calc'!A0 <script>alert(1)</script>", Engine: "nuclei", EngineRef: "x", Confidence: model.ConfConfirmed})

	rep := h.do("GET", "/api/scans/1/report", "")
	if rep.Code != 200 || !strings.HasPrefix(rep.Header().Get("Content-Type"), "application/json") || !strings.Contains(rep.Body.String(), `"schema_version"`) {
		t.Fatalf("report = %d %s", rep.Code, rep.Header().Get("Content-Type"))
	}
	md := h.do("GET", "/api/scans/1/export?format=md", "")
	if md.Code != 200 || !strings.Contains(md.Header().Get("Content-Disposition"), `attachment; filename="babylon-scan-1.md"`) ||
		strings.Contains(md.Body.String(), "<script>") || !strings.Contains(md.Body.String(), "web &lt;b&gt;test&lt;/b&gt;") {
		t.Fatalf("markdown export unsafe or wrong: %d\n%s", md.Code, md.Body.String())
	}
	cs := h.do("GET", "/api/scans/1/export?format=csv", "")
	rows, err := csv.NewReader(strings.NewReader(cs.Body.String())).ReadAll()
	if err != nil || len(rows) < 2 || strings.HasPrefix(rows[1][5], "=") {
		t.Fatalf("csv formula not neutralized: %v err=%v", rows, err)
	}
	if c := h.do("GET", "/api/scans/1/export?format=md&compliance=nist-800-53", ""); c.Code != 200 || !strings.Contains(c.Body.String(), "## Compliance: NIST SP 800-53") {
		t.Errorf("compliance export: %d %s", c.Code, c.Body.String())
	}
	if h.do("GET", "/api/scans/1/export?format=md&compliance=bogus", "").Code != 400 {
		t.Error("unknown framework must be 400")
	}
	if tr := h.do("GET", "/api/trends", ""); tr.Code != 200 || !strings.HasPrefix(strings.TrimSpace(tr.Body.String()), "[") {
		t.Errorf("trends: %d %s", tr.Code, tr.Body.String())
	}
	if h.do("GET", "/api/scans/1/export?format=exe", "").Code != 400 {
		t.Error("unknown export format must be 400")
	}

	if rr := h.do("POST", "/api/scans/1/cancel", ""); rr.Code != 409 {
		t.Errorf("cancel of a finished scan = %d", rr.Code)
	}
	if rr := h.do("POST", "/api/scans/1/resume", ""); rr.Code != 409 {
		t.Errorf("resume of a completed scan = %d", rr.Code)
	}
	if rr := h.do("GET", "/api/scans/999", ""); rr.Code != 404 {
		t.Errorf("missing scan = %d", rr.Code)
	}
	if rr := h.do("GET", "/api/scans/abc", ""); rr.Code != 400 {
		t.Errorf("bad id = %d", rr.Code)
	}

	if rr := h.do("DELETE", "/api/scans/1", ""); rr.Code != 200 {
		t.Fatalf("delete = %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(h.app.Home, "scans", "1")); !os.IsNotExist(err) {
		t.Error("raw output directory must be removed with the scan")
	}
	if rr := h.do("DELETE", "/api/scans/1", ""); rr.Code != 404 {
		t.Errorf("second delete = %d", rr.Code)
	}
}

func TestConcurrentScanLimit(t *testing.T) {
	// A fake nmap that blocks keeps scans "running" so the limit can be hit.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "nmap"), []byte("#!/bin/sh\nsleep 30\n"), 0o755)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	a, _ := app.Open(t.TempDir())
	tok, _ := NewToken()
	s, _ := New(a, tok, listen, "t", 1) // limit = 1
	hn := &harness{t: t, app: a, srv: s, h: s.Handler(), token: tok}
	t.Cleanup(func() { s.Shutdown(); a.Close() })

	if rr := hn.do("POST", "/api/scans", `{"template":"host_discovery","targets":["10.0.0.1"]}`); rr.Code != 201 {
		t.Fatalf("first = %d", rr.Code)
	}
	rr := hn.do("POST", "/api/scans", `{"template":"host_discovery","targets":["10.0.0.2"]}`)
	if rr.Code != 202 || !strings.Contains(rr.Body.String(), `"started":false`) {
		t.Fatalf("second must be created but not started: %d %s", rr.Code, rr.Body.String())
	}
	if rr := hn.do("POST", "/api/scans/1/cancel", ""); rr.Code != 202 {
		t.Fatalf("cancel = %d", rr.Code)
	}
	waitStatus(t, hn, "1", "cancelled")
	if rr := hn.do("DELETE", "/api/scans/1", ""); rr.Code != 200 {
		t.Errorf("delete after cancel = %d", rr.Code)
	}
}

func TestScheduleAPI(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "nmap"), []byte("#!/bin/sh\nsleep 30\n"), 0o755)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	hn := newHarness(t)
	if rr := hn.do("GET", "/api/schedules", ""); rr.Code != 200 || strings.TrimSpace(rr.Body.String()) != "[]" {
		t.Fatalf("empty list = %d %q", rr.Code, rr.Body.String())
	}
	bad := `{"name":"x","every_minutes":5,"scan":{"template":"host_discovery","targets":["127.0.0.1"]}}`
	if rr := hn.do("POST", "/api/schedules", bad); rr.Code != 400 {
		t.Errorf("interval under 15 min = %d", rr.Code)
	}
	if rr := hn.do("POST", "/api/schedules", `{"name":"x","every_minutes":60,"scan":{"template":"host_discovery","targets":["8.8.8.8"]}}`); rr.Code != 400 {
		t.Errorf("public target must still be refused: %d", rr.Code)
	}
	ok := `{"name":"hourly","every_minutes":60,"scan":{"template":"host_discovery","targets":["127.0.0.1"],"max_hosts":1}}`
	rr := hn.do("POST", "/api/schedules", ok)
	if rr.Code != 201 {
		t.Fatalf("create = %d %s", rr.Code, rr.Body.String())
	}
	if rr := hn.do("POST", "/api/schedules/1/toggle", `{"enabled":false}`); rr.Code != 200 {
		t.Errorf("toggle = %d", rr.Code)
	}
	if rr := hn.do("POST", "/api/schedules/9/toggle", `{"enabled":false}`); rr.Code != 404 {
		t.Errorf("toggle missing = %d", rr.Code)
	}
	if rr := hn.do("POST", "/api/schedules", ok, noCookie()); rr.Code != 401 {
		t.Errorf("schedules need auth: %d", rr.Code)
	}
	if rr := hn.do("DELETE", "/api/schedules/1", ""); rr.Code != 200 {
		t.Errorf("delete = %d", rr.Code)
	}
}
