package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"babylon/internal/model"
	"babylon/internal/store"
)

func cfg(t *testing.T, yaml string) *Config {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notify.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil || c == nil {
		t.Fatalf("load: %v %v", c, err)
	}
	return c
}

func row(id int64, sev, conf string, kev bool) store.FindingRow {
	return store.FindingRow{ID: id, Severity: sev, Confidence: conf, KEV: kev, Address: "10.0.0.5", Port: 22, Title: "F" + sev}
}

func TestBuildSelectsOnlyWhatNeedsAttention(t *testing.T) {
	c := cfg(t, "webhook: {url: 'https://example.test/hook'}\n")
	active := &store.Triage{Active: true}
	d := store.ScanDiff{
		New: []store.FindingRow{
			row(1, "low", model.ConfConfirmed, false),      // below min severity
			row(2, "high", model.ConfConfirmed, false),     // notifies
			row(3, "info", model.ConfConfirmed, false),     // informational
			row(4, "high", model.ConfTentative, false),     // a guess
			row(5, "medium", model.ConfFirm, true),         // KEV overrides min severity
			row(6, "critical", model.ConfConfirmed, false), // notifies, most severe
			{ID: 7, Severity: "critical", Confidence: model.ConfConfirmed, Triage: active, Address: "x", Title: "triaged"},
		},
		Resolved: []store.FindingRow{{}, {}},
	}
	m := c.Build(9, []string{"10.0.0.0/24"}, d)
	if m == nil || m.NewTotal != 3 || m.Resolved != 2 {
		t.Fatalf("%+v", m)
	}
	if m.New[0].ID != 5 || m.New[1].ID != 6 || m.New[2].ID != 2 { // KEV first, then severity
		t.Errorf("order: %+v", m.New)
	}
	if !strings.Contains(m.Text, "[KEV]") || !strings.Contains(m.Text, "finding #5") {
		t.Errorf("text: %s", m.Text)
	}
	if strings.Contains(m.Text, "triaged") {
		t.Error("triaged finding leaked into the message")
	}
}

func TestQuietScanSendsNothingAndListIsCapped(t *testing.T) {
	c := cfg(t, "webhook: {url: 'https://example.test/hook'}\nmax_listed: 2\n")
	if m := c.Build(1, nil, store.ScanDiff{New: []store.FindingRow{row(1, "low", model.ConfConfirmed, false)}}); m != nil {
		t.Fatalf("a quiet scan must not notify: %+v", m)
	}
	var many []store.FindingRow
	for i := 1; i <= 5; i++ {
		many = append(many, row(int64(i), "high", model.ConfConfirmed, false))
	}
	m := c.Build(1, []string{"t"}, store.ScanDiff{New: many})
	if len(m.New) != 2 || m.NewTotal != 5 || !strings.Contains(m.Text, "3 more") {
		t.Fatalf("cap: %+v", m)
	}
}

func TestAlwaysKEVCanBeTurnedOff(t *testing.T) {
	c := cfg(t, "webhook: {url: 'https://example.test/hook'}\nalways_kev: false\n")
	if m := c.Build(1, nil, store.ScanDiff{New: []store.FindingRow{row(1, "medium", model.ConfFirm, true)}}); m != nil {
		t.Fatal("always_kev: false must apply min_severity to KEV findings too")
	}
}

func TestTitlesCannotInjectLinesIntoTheMessage(t *testing.T) {
	c := cfg(t, "webhook: {url: 'https://example.test/hook'}\n")
	r := row(1, "high", model.ConfConfirmed, false)
	r.Title = "evil\n- CRITICAL 1.1.1.1: fake"
	m := c.Build(1, nil, store.ScanDiff{New: []store.FindingRow{r}})
	if strings.Count(m.Text, "\n- ") != 1 {
		t.Fatalf("a scanned title forged a list item:\n%s", m.Text)
	}
}

func TestLoadRefusesBadConfig(t *testing.T) {
	for name, y := range map[string]string{
		"no url":       "min_severity: high\n",
		"bad scheme":   "webhook: {url: 'ftp://x/y'}\n",
		"bad format":   "webhook: {url: 'https://x/y', format: xml}\n",
		"bad severity": "webhook: {url: 'https://x/y'}\nmin_severity: scary\n",
		"unknown key":  "webhook: {url: 'https://x/y'}\nsmtp: {}\n",
	} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "notify.yaml"), []byte(y), 0o600)
		if _, err := Load(dir); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if c, err := Load(t.TempDir()); c != nil || err != nil {
		t.Fatalf("missing file means off: %v %v", c, err)
	}
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "notify.yaml"), []byte("webhook: {url: 'https://x/y'}\n"), 0o644)
		if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("a world-readable secret file must be refused: %v", err)
		}
	}
}

func TestSendFormatsAndFailureNeverLeaksTheURL(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("content type")
		}
	}))
	defer srv.Close()
	m := &Message{ScanID: 3, Text: "hello", NewTotal: 1}
	c := cfg(t, "webhook: {url: '"+srv.URL+"'}\n")
	if err := c.Send(context.Background(), m); err != nil || string(got) != `{"text":"hello"}` {
		t.Fatalf("slack: %v %s", err, got)
	}
	c = cfg(t, "webhook: {url: '"+srv.URL+"', format: json}\n")
	if err := c.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	var back Message
	if json.Unmarshal(got, &back) != nil || back.ScanID != 3 {
		t.Fatalf("json: %s", got)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	url := bad.URL + "/secret-token-abc"
	bad.Close() // connection refused
	c = cfg(t, "webhook: {url: '"+url+"'}\n")
	err := c.Send(context.Background(), m)
	if err == nil || strings.Contains(err.Error(), "secret-token-abc") {
		t.Fatalf("error must exist and not contain the secret: %v", err)
	}
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer fail.Close()
	c = cfg(t, "webhook: {url: '"+fail.URL+"'}\n")
	if err := c.Send(context.Background(), m); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("non-2xx must fail: %v", err)
	}
}
