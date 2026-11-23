package scan

import (
	"context"
	"strings"
	"testing"

	"babylon/internal/audit"
	grp "babylon/internal/group"
	"babylon/internal/model"
	"babylon/internal/store"
)

func macHostRunner(version string) mapRunner {
	r := mapRunner{}
	for _, c := range audit.AllowedCommands() {
		switch {
		case strings.HasPrefix(c, "uname"):
			r[c] = "Darwin 25.1.0 arm64\n"
		case strings.HasPrefix(c, "sw_vers"):
			r[c] = "ProductName: macOS\nProductVersion: " + version + "\nBuildVersion: 25G90\n"
		case strings.HasPrefix(c, "csrutil"):
			r[c] = "System Integrity Protection status: enabled.\n"
		case strings.HasPrefix(c, "spctl"):
			r[c] = "assessments enabled\n"
		case strings.HasPrefix(c, "fdesetup"):
			r[c] = "FileVault is Off.\n"
		case strings.Contains(c, "--getglobalstate"):
			r[c] = "Firewall is enabled. (State = 1)\n"
		case strings.Contains(c, "--getstealthmode"):
			r[c] = "Stealth mode disabled\n"
		case strings.Contains(c, "com.apple.SoftwareUpdate"):
			r[c] = "{\n AutomaticCheckEnabled = 1;\n CriticalUpdateInstall = 1;\n}\n"
		case strings.Contains(c, "com.apple.loginwindow"):
			r[c] = "{\n GuestEnabled = 0;\n}\n"
		case strings.HasPrefix(c, "brew"):
			r[c] = "openssl@3 3.3.1\nwget 1.24.5\n"
		}
	}
	return r
}

func TestMacAuditEndToEnd(t *testing.T) {
	st, id := cpeStore(t)
	ctx := context.Background()
	if err := st.UpsertAppleReleases(ctx, []store.AppleRelease{
		{Major: 26, Release: "26.6", Product: "macOS Tahoe", Released: "2026-07-27"},
		{Major: 26, Release: "26.7", Product: "macOS Tahoe", Released: "2026-09-14"},
		{Major: 26, Release: "26.7.3", Product: "macOS Tahoe", Released: "2026-11-09"},
	}); err != nil {
		t.Fatal(err)
	}
	for rel, cves := range map[string][]string{"26.6": {"CVE-2026-0001"}, "26.7": {"CVE-2026-0002", "CVE-2026-0003"}, "26.7.3": {"CVE-2026-0004"}} {
		if err := st.UpsertAppleFixes(ctx, 26, rel, cves, store.FeedInfo{Name: "apple:" + rel}); err != nil {
			t.Fatal(err)
		}
	}
	ingest(t, st, id, "10.0.0.9", "", model.Port{Number: 22, Proto: "tcp", State: "open", Service: model.Service{Name: "ssh"}})

	cfg := &AuditConfig{Creds: audit.Creds{User: "audit", Password: "s3cretpw", Label: "mac"},
		Connect: func(context.Context, string) (audit.Runner, func(), error) {
			return macHostRunner("26.6"), func() {}, nil
		}}
	if err := auditHost(ctx, ctx, st, cfg, id, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}

	rows, _ := st.ListFindings(ctx, id, "")
	var patch, cfgf []store.FindingRow
	for _, r := range rows {
		switch r.Family {
		case familyMacPatch:
			patch = append(patch, r)
		case "Local configuration":
			cfgf = append(cfgf, r)
		}
	}
	if len(patch) != 3 {
		t.Fatalf("a 26.6 host misses the CVEs of 26.7 and 26.7.3 only: %+v", patch)
	}
	for _, p := range patch {
		if p.Confidence != "confirmed" || p.Product != "macOS Tahoe" || p.Version != "26.6" || !strings.Contains(p.Remediation, "26.7.3 or later") {
			t.Errorf("%+v", p)
		}
	}
	groups, _ := grp.Build(patch)
	if len(groups) != 1 || groups[0].Title != "Missing macOS updates: macOS Tahoe (26.6 -> 26.7.3)" || len(groups[0].CVEs) != 3 {
		t.Fatalf("%+v", groups)
	}
	if len(cfgf) != 2 { // FileVault off, stealth mode off
		var ts []string
		for _, c := range cfgf {
			ts = append(ts, c.Title)
		}
		t.Errorf("want FileVault and stealth findings, got %v", ts)
	}
	runs, _ := st.ListCheckRuns(ctx, id)
	got := map[string]string{}
	for _, r := range runs {
		got[r.CheckID] = r.State
	}
	if got["macos-patch-audit"] != "ran" || got["MAC-003"] != "ran" || got["MAC-001"] != "ran" || got["ssh-package-audit"] != "skipped" {
		t.Errorf("check runs: %v", got)
	}
	if _, ok := got["FW-001"]; ok {
		t.Error("Linux-only rules must not run on a Mac")
	}
	sess, _ := st.AuditSessions(ctx, id)
	if len(sess) != 1 || sess[0].OSName != "macOS 26.6" || sess[0].Packages != 2 {
		t.Errorf("%+v", sess)
	}
}

func TestMacAuditWithoutAppleDataSaysSoAndEndOfSupport(t *testing.T) {
	st, id := cpeStore(t)
	ctx := context.Background()
	ingest(t, st, id, "10.0.0.9", "", model.Port{Number: 22, Proto: "tcp", State: "open", Service: model.Service{Name: "ssh"}})
	cfg := &AuditConfig{Creds: audit.Creds{User: "a", Password: "s3cretpw"},
		Connect: func(context.Context, string) (audit.Runner, func(), error) {
			return macHostRunner("26.6"), func() {}, nil
		}}
	if err := auditHost(ctx, ctx, st, cfg, id, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	runs, _ := st.ListCheckRuns(ctx, id)
	for _, r := range runs {
		if r.CheckID == "macos-patch-audit" && (r.State != "skipped" || !strings.Contains(r.Reason, "update-feeds --only apple")) {
			t.Errorf("no data must be a visible skip, not a clean result: %+v", r)
		}
	}
	rows, _ := st.ListFindings(ctx, id, "")
	for _, r := range rows {
		if r.Family == familyMacPatch {
			t.Errorf("no patch findings without data: %+v", r)
		}
	}

	// Line Apple no longer lists: an unsupported-software finding.
	st2, id2 := cpeStore(t)
	_ = st2.UpsertAppleReleases(ctx, []store.AppleRelease{{Major: 26, Release: "26.7", Product: "macOS Tahoe", Released: "2026-09-14"}})
	_ = st2.UpsertAppleFixes(ctx, 26, "26.7", []string{"CVE-2026-1"}, store.FeedInfo{Name: "apple:26.7"})
	ingest(t, st2, id2, "10.0.0.9", "", model.Port{Number: 22, Proto: "tcp", State: "open", Service: model.Service{Name: "ssh"}})
	cfg.Connect = func(context.Context, string) (audit.Runner, func(), error) {
		return macHostRunner("12.7.6"), func() {}, nil
	}
	if err := auditHost(ctx, ctx, st2, cfg, id2, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	rows, _ = st2.ListFindings(ctx, id2, "")
	found := false
	for _, r := range rows {
		if r.Family == "Unsupported software" && strings.Contains(r.Title, "macOS") {
			found = true
		}
	}
	if !found {
		t.Errorf("want an end-of-support finding: %+v", rows)
	}
}
