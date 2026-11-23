package scan

import (
	"context"
	"strings"
	"testing"
	"time"

	"babylon/internal/audit"
	grp "babylon/internal/group"
	"babylon/internal/store"
)

func windowsHost(ubr string) mapRunner {
	r := mapRunner{}
	for _, c := range audit.WinAllowedScripts() {
		switch {
		case strings.HasPrefix(c, "$o=Get-CimInstance"):
			r[c] = `{"Caption":"Microsoft Windows 10 Pro","Version":"10.0.19045","Build":"19045","UBR":` + ubr + `,"DisplayVersion":"22H2","Arch":"64-bit","ProductType":1}`
		case strings.HasPrefix(c, "Get-HotFix"):
			r[c] = `{"HotFixID":"KB5039211","InstalledOn":"2026-11-10"}`
		case strings.HasPrefix(c, "Get-ItemProperty"):
			r[c] = `{"DisplayName":"7-Zip","DisplayVersion":"19.00","Publisher":"x"}`
		case strings.HasPrefix(c, "$r=[ordered]"):
			r[c] = `{"smb1":false,"smbSigning":true,"fw_Domain":true,"fw_Private":true,"fw_Public":true,"av":true,"rtp":true,"sigAge":1,"nla":1,"uac":1,"wdigest":null,"lmcompat":5,"guest":false,"llmnr":0,"autorun":255}`
		case c == "net accounts":
			r[c] = "Minimum password length: 14\nMaximum password age (days): 60\nLockout threshold: 5\n"
		case strings.HasPrefix(c, "Get-LocalGroupMember"):
			r[c] = `{"Name":"PC\\Administrator","ObjectClass":"User"}`
		}
	}
	return r
}

func TestWinAuditEndToEnd(t *testing.T) {
	st, id := cpeStore(t)
	ctx := context.Background()
	c1, c2 := 7.8, 9.8
	err := st.UpsertMSRC(ctx, []store.MSRCFix{
		{Build: "10.0.19045", CVE: "CVE-2026-1111", FixedUBR: 5000, KB: "5001", Title: "Kernel EoP", CVSS: &c1, Severity: "high"},
		{Build: "10.0.19045", CVE: "CVE-2026-2222", FixedUBR: 5100, KB: "5009", Title: "SMB RCE", CVSS: &c2, Severity: "critical"},
		{Build: "10.0.19045", CVE: "CVE-2025-0001", FixedUBR: 3000, KB: "4000", Title: "old, already installed"},
		{Build: "10.0.22631", CVE: "CVE-2026-3333", FixedUBR: 9, KB: "7", Title: "other build"},
	}, store.FeedInfo{Name: "msrc:2026-Oct"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, st, id, "10.0.0.9", "Windows 10", apache("2.4.49", ""))
	cfg := &WinAuditConfig{Creds: audit.WinCreds{User: "scan", Password: "s3cretpw", Label: "lab"}, Now: func() time.Time { return time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC) },
		Connect: func(context.Context, string) (audit.Runner, func(), error) {
			return windowsHost("4529"), func() {}, nil
		}}
	if err := winAuditHost(ctx, ctx, st, cfg, id, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.ListFindings(ctx, id, "")
	var patches []store.FindingRow
	for _, r := range rows {
		if r.Family == familyWinPatch {
			patches = append(patches, r)
		}
		if r.Family == "Local configuration" && !strings.Contains(r.Title, "out of support") { // Windows 10 is past end of support
			t.Errorf("a hardened host must not fail rules: %+v", r.Title)
		}
	}
	if len(patches) != 2 {
		t.Fatalf("want the 2 missing fixes only, got %+v", patches)
	}
	for _, p := range patches {
		if p.Confidence != "confirmed" || p.Version != "10.0.19045.4529" || !strings.Contains(p.Product, "Windows 10") || !strings.Contains(p.Remediation, "or later") {
			t.Errorf("patch finding: %+v", p)
		}
	}
	groups, _ := grp.Build(patches)
	if len(groups) != 1 || !strings.HasPrefix(groups[0].Title, "Missing Windows updates:") || !strings.Contains(groups[0].Title, "10.0.19045.5100") || !strings.Contains(groups[0].Fix, "KB5009") {
		t.Errorf("grouping: %+v", groups)
	}
	sess, _ := st.AuditSessions(ctx, id)
	if len(sess) != 1 || sess[0].OSFamily != "windows" || sess[0].Transport != "winrm" || sess[0].Result != "ok" {
		t.Errorf("session: %+v", sess)
	}
	// A fully patched host yields no patch findings.
	cfg.Connect = func(context.Context, string) (audit.Runner, func(), error) {
		return windowsHost("9999"), func() {}, nil
	}
	st2, id2 := cpeStore(t)
	_ = st2.UpsertMSRC(ctx, []store.MSRCFix{{Build: "10.0.19045", CVE: "CVE-2026-1111", FixedUBR: 5000, KB: "5001"}}, store.FeedInfo{Name: "msrc:x"})
	ingest(t, st2, id2, "10.0.0.9", "Windows 10", apache("2.4.49", ""))
	if err := winAuditHost(ctx, ctx, st2, cfg, id2, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	if rows, _ := st2.ListFindings(ctx, id2, ""); func() int {
		n := 0
		for _, r := range rows {
			if r.Family == familyWinPatch {
				n++
			}
		}
		return n
	}() != 0 {
		t.Error("a patched host must have no missing-patch findings")
	}
}

func TestWinAuditFailureDoesNotLeakPassword(t *testing.T) {
	st, id := cpeStore(t)
	ingest(t, st, id, "10.0.0.9", "Windows", apache("2.4.49", ""))
	cfg := &WinAuditConfig{Creds: audit.WinCreds{User: "scan", Password: "hunter2hunter2"},
		Connect: func(context.Context, string) (audit.Runner, func(), error) {
			return nil, nil, errString("auth failed for scan:hunter2hunter2")
		}}
	if err := winAuditHost(context.Background(), context.Background(), st, cfg, id, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	sess, _ := st.AuditSessions(context.Background(), id)
	if len(sess) != 1 || sess[0].Result != "failed" || strings.Contains(sess[0].Error, "hunter2") {
		t.Errorf("%+v", sess)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
