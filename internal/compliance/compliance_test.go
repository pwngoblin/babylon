package compliance

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"babylon/internal/audit"
	"babylon/internal/dbaudit"
	"babylon/internal/model"
	"babylon/internal/native"
	"babylon/internal/netaudit"
	"babylon/internal/store"
)

// The mapping is keyed by check id. If a check is renamed or removed the entry
// would silently stop counting, so every key must name a real check or rule.
func TestEveryMappedCheckExists(t *testing.T) {
	known := map[string]bool{"cpe-version-match": true, "ssh-package-audit": true, "macos-patch-audit": true, "winrm-patch-audit": true}
	for _, c := range native.Builtin() {
		known[c.ID] = true
	}
	for _, r := range audit.Rules {
		known[r.ID] = true
	}
	for _, r := range audit.MacRules {
		known[r.ID] = true
	}
	for _, r := range netaudit.IOSRules {
		known[r.ID] = true
	}
	for _, r := range dbaudit.Rules {
		known[r.ID] = true
	}
	for _, r := range audit.WinRules {
		known[r.ID] = true
	}
	for id := range builtin {
		if !known[id] {
			t.Errorf("mapping names %q, which is not a check or rule", id)
		}
	}
	// And the other direction: new Go checks and rules must be mapped or listed here on purpose.
	for id := range known {
		if _, ok := builtin[id]; !ok {
			t.Errorf("check %q has no compliance mapping (add it to builtin)", id)
		}
	}
}

func TestEveryReferencedControlHasATitleAndPrefix(t *testing.T) {
	reg, err := DefaultRegistry("") // includes the controls declared in built-in packs
	if err != nil {
		t.Fatal(err)
	}
	for id, list := range reg {
		for _, c := range list {
			if Title(c) == "" {
				t.Errorf("%s: control %s has no title", id, c)
			}
		}
	}
}

func TestCrosswalkAddsPCIAndISOToNISTControls(t *testing.T) {
	reg := Registry(map[string][]string{"X-1": {"NIST-800-53:SC-8"}})
	got := strings.Join(reg["X-1"], " ")
	for _, want := range []string{"NIST-800-53:SC-8", "PCI-DSS-4:4.2.1", "ISO-27001:A.8.24"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}

func TestEvaluateFailPassNotAssessed(t *testing.T) {
	reg := map[string][]string{
		"chk-a": {"NIST-800-53:AC-3"},
		"chk-b": {"NIST-800-53:AC-3", "NIST-800-53:SC-8"},
		"chk-c": {"NIST-800-53:IA-5"},
		"chk-d": {"PCI-DSS-4:1.4.1"},
	}
	runs := []Run{
		{"h1", "chk-a", "ran", ""}, {"h2", "chk-a", "ran", ""},
		{"h1", "chk-b", "ran", ""},
		{"h1", "chk-c", "skipped", "no ssh"},
		{"h1", "chk-x", "ran", ""},
	}
	hits := []Hit{{"h2", "chk-a", "Open thing", "high"}}
	rep := Evaluate(NIST, reg, runs, hits)
	by := map[string]Control{}
	for _, c := range rep.Controls {
		by[c.ID] = c
	}
	if by["AC-3"].Status != StatusFail || len(by["AC-3"].HostsFailed) != 1 || by["AC-3"].HostsFailed[0] != "h2" || by["AC-3"].HostsPassed != 1 {
		t.Errorf("AC-3: %+v", by["AC-3"])
	}
	if by["SC-8"].Status != StatusPass {
		t.Errorf("SC-8: %+v", by["SC-8"])
	}
	if by["IA-5"].Status != StatusNotAssessed || len(by["IA-5"].NotRun) != 1 || !strings.Contains(by["IA-5"].NotRun[0], "no ssh") {
		t.Errorf("IA-5: %+v", by["IA-5"])
	}
	if _, ok := by["1.4.1"]; ok {
		t.Error("PCI control leaked into the NIST report")
	}
	if rep.Failed != 1 || rep.Passed != 1 || rep.NotAssess != 1 {
		t.Errorf("counts: %+v", rep)
	}
	if len(rep.Unmapped) != 1 || rep.Unmapped[0] != "chk-x" {
		t.Errorf("unmapped: %v", rep.Unmapped)
	}
}

// A pass must never be reported just because a failing check was skipped.
func TestSkippedChecksNeverPass(t *testing.T) {
	reg := map[string][]string{"chk": {"NIST-800-53:AC-3"}}
	rep := Evaluate(NIST, reg, []Run{{"h", "chk", "error", "boom"}}, nil)
	if rep.Controls[0].Status != StatusNotAssessed {
		t.Fatalf("%+v", rep.Controls[0])
	}
}

func TestNaturalOrder(t *testing.T) {
	reg := map[string][]string{"a": {"NIST-800-53:AC-12", "NIST-800-53:AC-2", "NIST-800-53:AU-2"}}
	rep := Evaluate(NIST, reg, nil, nil)
	var ids []string
	for _, c := range rep.Controls {
		ids = append(ids, c.ID)
	}
	if strings.Join(ids, ",") != "AC-2,AC-12,AU-2" {
		t.Fatalf("order %v", ids)
	}
}

func TestCheckForFinding(t *testing.T) {
	cases := map[[2]string]string{
		{"audit", "osv:DSA-1"}: "ssh-package-audit", {"audit", "apple:CVE-1"}: "macos-patch-audit",
		{"audit", "msrc:CVE-1"}: "winrm-patch-audit", {"audit", "SSH-001"}: "SSH-001", {"native", "redis-unauth"}: "redis-unauth",
		{"cpematch", "CVE-2021-1"}: "cpe-version-match",
	}
	for in, want := range cases {
		if got := CheckForFinding(in[0], in[1]); got != want {
			t.Errorf("%v: got %s want %s", in, got, want)
		}
	}
}

func TestForScanFromStore(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	defer st.Close()
	ctx := context.Background()
	id, _ := st.CreateScan(ctx, "s", "basic", []string{"10.0.0.5"}, map[string]any{})
	st.IngestHost(ctx, id, model.Host{Address: "10.0.0.5", State: "up", Ports: []model.Port{{Number: 6379, Proto: "tcp", State: "open", Service: model.Service{Name: "redis"}}}})
	st.RecordCheckRun(ctx, id, 1, "redis-unauth", "ran", "")
	st.RecordCheckRun(ctx, id, 1, "memcached-open", "ran", "")
	st.RecordFinding(ctx, id, model.Finding{Fingerprint: "r", Address: "10.0.0.5", Port: 6379, Proto: "tcp", Title: "Redis without auth", Severity: "high",
		Confidence: model.ConfConfirmed, Engine: "native", EngineRef: "redis-unauth"})
	rep, err := ForScan(ctx, st, id, PCI, "")
	if err != nil {
		t.Fatal(err)
	}
	var ac *Control
	for i := range rep.Controls {
		if rep.Controls[i].ID == "7.2.1" {
			ac = &rep.Controls[i]
		}
	}
	if ac == nil || ac.Status != StatusFail || len(ac.Failures) != 1 {
		t.Fatalf("PCI 7.2.1 should fail through the crosswalk: %+v", rep.Controls)
	}
	if _, err := ForScan(ctx, st, id, "bogus", ""); err == nil {
		t.Fatal("unknown framework accepted")
	}
}
