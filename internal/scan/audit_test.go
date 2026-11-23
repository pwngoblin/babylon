package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"babylon/internal/audit"
	"babylon/internal/model"
	"babylon/internal/store"
)

type mapRunner map[string]string

func (m mapRunner) Run(_ context.Context, cmd string) (string, error) {
	if v, ok := m[cmd]; ok {
		return v, nil
	}
	return "", errors.New("exit status 127")
}

// Command strings are mirrored from the collector so the fake host answers the
// real commands (an unknown command yields no output, like a missing tool).
func ubuntuHost() mapRunner {
	var r = mapRunner{}
	for _, c := range audit.AllowedCommands() {
		switch {
		case strings.HasPrefix(c, "cat /etc/os-release"):
			r[c] = "ID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n"
		case strings.HasPrefix(c, "uname"):
			r[c] = "Linux 5.15.0 x86_64\n"
		case strings.HasPrefix(c, "dpkg-query"):
			r[c] = "libssl3\t3.0.2-0ubuntu1.10\tinstall ok installed\tamd64\topenssl\t3.0.2-0ubuntu1.10\n" +
				"openssl\t3.0.2-0ubuntu1.10\tinstall ok installed\tamd64\topenssl\t3.0.2-0ubuntu1.10\n" +
				"openssh-server\t1:8.9p1-3ubuntu0.13\tinstall ok installed\tamd64\topenssh\t1:8.9p1-3ubuntu0.13\n" +
				"bash\t5.1-6ubuntu1.1\tinstall ok installed\tamd64\tbash\t5.1-6ubuntu1.1\n"
		case strings.HasPrefix(c, "sshd -T"):
			r[c] = "permitrootlogin yes\npasswordauthentication yes\npermitemptypasswords no\nx11forwarding no\nciphers chacha20-poly1305@openssh.com\nmacs hmac-sha2-256\nmaxauthtries 3\nclientaliveinterval 300\n"
		case strings.HasPrefix(c, "stat -c"):
			r[c] = "644 root root /etc/passwd\n640 root shadow /etc/shadow\n"
		}
	}
	return r
}

func TestAuditStageEndToEnd(t *testing.T) {
	st, id := cpeStore(t)
	ctx := context.Background()
	// OSV: openssl is outdated (two CVEs), openssh is already patched, bash is fine.
	err := st.ReplaceOSVEcosystem(ctx, "Ubuntu", []store.OSVRecord{
		{ID: "USN-1", Aliases: []string{"CVE-2024-0001", "CVE-2024-0002"}, Summary: "openssl issues",
			Affected: []store.OSVAffected{{Ecosystem: "Ubuntu:22.04:LTS", Package: "openssl", Introduced: "0", Fixed: "3.0.2-0ubuntu1.15"}}},
		{ID: "USN-2", Aliases: []string{"CVE-2023-0099"},
			Affected: []store.OSVAffected{{Ecosystem: "Ubuntu:22.04:LTS", Package: "openssh", Introduced: "0", Fixed: "1:8.9p1-3ubuntu0.1"}}},
	}, store.FeedInfo{Name: "osv:Ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	// An unauthenticated banner guess that the audit must supersede (Apache 2.4.49 on Ubuntu is
	// vendor-patched territory: distro marker in the banner makes it tentative).
	ingest(t, st, id, "10.0.0.5", "Linux 5.15", apache("2.4.49", "(Ubuntu)"), model.Port{Number: 22, Proto: "tcp", State: "open", Service: model.Service{Name: "ssh", Product: "OpenSSH", Version: "8.9p1"}})
	all, _ := st.OpenServices(ctx, id)
	if err := matchHost(ctx, st, id, "10.0.0.5", all); err != nil {
		t.Fatal(err)
	}
	before, _ := st.ListFindings(ctx, id, "")
	tentative := 0
	for _, f := range before {
		if f.Confidence == "tentative" {
			tentative++
		}
	}
	if tentative == 0 {
		t.Fatalf("setup: expected tentative banner findings, got %+v", before)
	}

	cfg := &AuditConfig{Creds: audit.Creds{User: "audit", Password: "s3cretpw", Label: "lab"},
		Connect: func(context.Context, string) (audit.Runner, func(), error) { return ubuntuHost(), func() {}, nil }}
	if err := auditHost(ctx, ctx, st, cfg, id, "10.0.0.5"); err != nil {
		t.Fatal(err)
	}

	rows, _ := st.ListFindings(ctx, id, "")
	var pkg, cfgf []store.FindingRow
	for _, r := range rows {
		switch r.Family {
		case "Outdated package":
			pkg = append(pkg, r)
		case "Local configuration":
			cfgf = append(cfgf, r)
		}
	}
	if len(pkg) != 2 {
		t.Fatalf("want 2 openssl CVE findings, got %+v", pkg)
	}
	for _, p := range pkg {
		if p.Confidence != "confirmed" || p.Product != "openssl" || p.Version != "3.0.2-0ubuntu1.10" || !strings.Contains(p.Remediation, "apt-get update && apt-get install --only-upgrade libssl3 openssl") {
			t.Errorf("package finding: %+v", p)
		}
	}
	for _, r := range pkg {
		if strings.Contains(r.Title, "openssh") || strings.Contains(r.Title, "bash") {
			t.Errorf("patched package reported: %+v", r)
		}
	}
	var ids []string
	for _, r := range cfgf {
		ids = append(ids, r.Title)
	}
	if len(cfgf) != 1 || !strings.Contains(cfgf[0].Title, "root login") {
		t.Errorf("want only SSH-001 to fail, got %v", ids)
	}

	sess, _ := st.AuditSessions(ctx, id)
	if len(sess) != 1 || sess[0].Result != "ok" || sess[0].Packages != 4 || sess[0].Ecosystem != "Ubuntu:22.04" {
		t.Errorf("audit session: %+v", sess)
	}
	// Coverage: unreadable inputs are skipped with a reason, not silently passed.
	runs, _ := st.ListCheckRuns(ctx, id)
	got := map[string]string{}
	for _, r := range runs {
		got[r.CheckID] = r.State
	}
	if got["ssh-audit"] != "ran" || got["ssh-package-audit"] != "ran" || got["SSH-001"] != "ran" || got["FW-001"] != "skipped" || got["KERN-001"] != "skipped" {
		t.Errorf("check runs: %v", got)
	}
}

func TestAuditSupersedesPatchedBannerGuess(t *testing.T) {
	st, id := cpeStore(t)
	ctx := context.Background()
	_ = st.ReplaceOSVEcosystem(ctx, "Ubuntu", nil, store.FeedInfo{Name: "osv:Ubuntu"})
	// Apache 2.4.49 banner on Ubuntu → tentative guess; the host actually has the distro-patched apache2.
	ingest(t, st, id, "10.0.0.5", "Linux", apache("2.4.49", "(Ubuntu)"))
	all, _ := st.OpenServices(ctx, id)
	_ = matchHost(ctx, st, id, "10.0.0.5", all)
	if rows, _ := st.ListFindings(ctx, id, ""); len(rows) == 0 || rows[0].Confidence != "tentative" {
		t.Fatalf("setup: %+v", rows)
	}
	h := ubuntuHost()
	for c := range h {
		if strings.HasPrefix(c, "dpkg-query") {
			h[c] = "apache2\t2.4.52-1ubuntu4.9\tinstall ok installed\tamd64\tapache2\t2.4.52-1ubuntu4.9\n"
		}
	}
	cfg := &AuditConfig{Creds: audit.Creds{User: "u", Password: "pw"}, Connect: func(context.Context, string) (audit.Runner, func(), error) { return h, func() {}, nil }}
	if err := auditHost(ctx, ctx, st, cfg, id, "10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	for _, r := range func() []store.FindingRow { x, _ := st.ListFindings(ctx, id, ""); return x }() {
		if r.Family == "Vulnerable software (version match)" {
			t.Errorf("banner guess for an audited, packaged product must be superseded: %+v", r)
		}
	}
}

func TestAuditFailureIsRecordedWithoutSecrets(t *testing.T) {
	st, id := cpeStore(t)
	ctx := context.Background()
	ingest(t, st, id, "10.0.0.5", "", apache("2.4.49", ""))
	cfg := &AuditConfig{Creds: audit.Creds{User: "u", Password: "hunter2hunter2"},
		Connect: func(context.Context, string) (audit.Runner, func(), error) {
			return nil, nil, errors.New("ssh handshake: auth failed for password hunter2hunter2")
		}}
	if err := auditHost(ctx, ctx, st, cfg, id, "10.0.0.5"); err != nil {
		t.Fatalf("a host-side failure must not fail the scan: %v", err)
	}
	sess, _ := st.AuditSessions(ctx, id)
	if len(sess) != 1 || sess[0].Result != "failed" || strings.Contains(sess[0].Error, "hunter2") || !strings.Contains(sess[0].Error, "***") {
		t.Errorf("session: %+v", sess)
	}
	runs, _ := st.ListCheckRuns(ctx, id)
	for _, r := range runs {
		if r.CheckID == "ssh-audit" && (r.State != "error" || strings.Contains(r.Reason, "hunter2")) {
			t.Errorf("check run: %+v", r)
		}
	}
}

func TestAuditSupersedesFirmGuessOnlyWhenPackageMatches(t *testing.T) {
	st, id := cpeStore(t)
	ctx := context.Background()
	_ = st.ReplaceOSVEcosystem(ctx, "Ubuntu", nil, store.FeedInfo{Name: "osv:Ubuntu"})
	// No distro marker anywhere, so the guess is firm, not tentative.
	ingest(t, st, id, "10.0.0.5", "", apache("2.4.49", ""))
	all, _ := st.OpenServices(ctx, id)
	_ = matchHost(ctx, st, id, "10.0.0.5", all)
	count := func() int {
		n := 0
		rows, _ := st.ListFindings(ctx, id, "")
		for _, r := range rows {
			if r.Family == "Vulnerable software (version match)" {
				n++
			}
		}
		return n
	}
	if count() == 0 {
		t.Fatal("setup: no banner findings")
	}
	run := func(version string) {
		h := ubuntuHost()
		for c := range h {
			if strings.HasPrefix(c, "dpkg-query") {
				h[c] = "apache2\t" + version + "\tinstall ok installed\tamd64\tapache2\t" + version + "\n"
			}
		}
		cfg := &AuditConfig{Creds: audit.Creds{User: "u", Password: "pw"}, Connect: func(context.Context, string) (audit.Runner, func(), error) { return h, func() {}, nil }}
		if err := auditHost(ctx, ctx, st, cfg, id, "10.0.0.5"); err != nil {
			t.Fatal(err)
		}
	}
	// The installed package is a different upstream version: the banner may come from some
	// other build, so the guess is kept.
	run("2.4.52-1ubuntu4.9")
	if count() == 0 {
		t.Error("a firm guess whose version does not match the installed package must be kept")
	}
	// The package's upstream version equals the banner: the audit is authoritative.
	run("2.4.49-1ubuntu1")
	if count() != 0 {
		t.Error("a guess for the installed package's own version must be superseded by the audit")
	}
}
