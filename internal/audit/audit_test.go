package audit

import (
	"context"
	"strings"
	"testing"

	"babylon/internal/store"
)

func TestParsers(t *testing.T) {
	os := ParseOSRelease("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\nPRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n")
	if os.ID != "ubuntu" || os.VersionID != "22.04" || os.Codename != "jammy" {
		t.Errorf("os-release: %+v", os)
	}
	if p, s := os.Ecosystem(); p != "Ubuntu:22.04" || s != "deb" {
		t.Errorf("ecosystem %q %q", p, s)
	}
	if p, _ := (OSInfo{ID: "alpine", VersionID: "3.19.1"}).Ecosystem(); p != "Alpine:v3.19" {
		t.Errorf("alpine eco %q", p)
	}
	if p, s := (OSInfo{ID: "rocky", VersionID: "9.3"}).Ecosystem(); p != "Rocky Linux:9" || s != "rpm" {
		t.Errorf("rocky eco %q %q", p, s)
	}
	if p, _ := (OSInfo{ID: "arch"}).Ecosystem(); p != "" {
		t.Error("unsupported distro must give no ecosystem")
	}

	deb := ParseDpkg("openssl\t3.0.2-0ubuntu1.10\tinstall ok installed\tamd64\topenssl\t3.0.2-0ubuntu1.10\n" +
		"libssl3\t3.0.2-0ubuntu1.10\tinstall ok installed\tamd64\topenssl\t3.0.2-0ubuntu1.10\n" +
		"removed-pkg\t1.0\tdeinstall ok config-files\tamd64\t\t\n" +
		"bash\t5.1-6ubuntu1\tinstall ok installed\tamd64\t\t\n")
	if len(deb) != 3 {
		t.Fatalf("dpkg parsed %d: %+v", len(deb), deb)
	}
	if deb[1].SrcName != "openssl" || deb[2].SrcName != "bash" || deb[2].SrcVersion != "5.1-6ubuntu1" {
		t.Errorf("dpkg source mapping: %+v", deb)
	}

	rpm := ParseRPM("openssl-libs\t1:3.0.7-27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\ngpg-pubkey\t0:1-2\t(none)\t(none)\n")
	if len(rpm) != 1 || rpm[0].SrcName != "openssl" || rpm[0].Version != "1:3.0.7-27.el9" {
		t.Errorf("rpm: %+v", rpm)
	}

	apk := ParseAPK("libcrypto3-3.1.4-r0 x86_64 {openssl} (Apache-2.0) [installed]\nbusybox-1.36.1-r15 x86_64 {busybox} (GPL-2.0-only) [installed]\n")
	if len(apk) != 2 || apk[0].Name != "libcrypto3" || apk[0].Version != "3.1.4-r0" || apk[0].SrcName != "openssl" || apk[0].Arch != "x86_64" {
		t.Errorf("apk list: %+v", apk)
	}
	if a := ParseAPK("musl-1.2.4-r2\nca-certificates-bundle-20230506-r0\n"); len(a) != 2 || a[1].Name != "ca-certificates-bundle" || a[1].Version != "20230506-r0" {
		t.Errorf("apk info -v: %+v", a)
	}

	sshd := ParseSSHD("# c\nPermitRootLogin yes\nPermitRootLogin no\nMatch User bob\n  PermitRootLogin no\n", false)
	if sshd["permitrootlogin"][0] != "yes" || len(sshd["permitrootlogin"]) != 1 {
		t.Errorf("raw sshd_config: first directive wins and Match blocks are ignored: %v", sshd)
	}
	eff := ParseSSHD("permitrootlogin without-password\nciphers a,b\n", true)
	if eff["ciphers"][0] != "a,b" {
		t.Errorf("sshd -T: %v", eff)
	}

	ss := ParseSS("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
		"tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n" +
		"tcp LISTEN 0 511 127.0.0.1:6379 0.0.0.0:*\n" +
		"tcp LISTEN 0 128 [::]:2375 [::]:*\n" +
		"udp UNCONN 0 0 *:5353 *:*\n" +
		"tcp LISTEN 0 5 [fe80::1%eth0]:631 [::]:*\n")
	if len(ss) != 5 || ss[0].Port != 22 || !ss[1].Loopback() || ss[2].Loopback() || ss[2].Port != 2375 || ss[3].Proto != "udp" || ss[3].Addr != "0.0.0.0" || ss[4].Addr != "fe80::1" {
		t.Errorf("ss: %+v", ss)
	}
	ns := ParseSS("Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 0.0.0.0:6379 0.0.0.0:* LISTEN\n")
	if len(ns) != 1 || ns[0].Port != 6379 || ns[0].Loopback() {
		t.Errorf("netstat: %+v", ns)
	}

	files := ParseStat("644 root root /etc/passwd\n640 root shadow /etc/shadow\nstat: cannot stat '/etc/x': No such file\n")
	if len(files) != 2 || files[1].Group != "shadow" {
		t.Errorf("stat: %+v", files)
	}
}

type fakeSrc struct{ rows []store.PkgAdvisory }

func (f fakeSrc) OSVForPackages(_ context.Context, _ string, names []string) ([]store.PkgAdvisory, error) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []store.PkgAdvisory
	for _, r := range f.rows {
		if want[r.Package] {
			out = append(out, r)
		}
	}
	return out, nil
}

func TestMatchPackagesDebian(t *testing.T) {
	f := &Facts{OS: OSInfo{ID: "ubuntu", VersionID: "22.04"}, Packages: []Package{
		{Name: "libssl3", Version: "3.0.2-0ubuntu1.10", SrcName: "openssl", SrcVersion: "3.0.2-0ubuntu1.10"},
		{Name: "openssl", Version: "3.0.2-0ubuntu1.10", SrcName: "openssl", SrcVersion: "3.0.2-0ubuntu1.10"},
		{Name: "bash", Version: "5.1-6ubuntu1.1", SrcName: "bash", SrcVersion: "5.1-6ubuntu1.1"},
	}}
	src := fakeSrc{rows: []store.PkgAdvisory{
		{Advisory: "USN-1", Package: "openssl", Introduced: "0", Fixed: "3.0.2-0ubuntu1.15", CVEs: []string{"CVE-2024-0001", "CVE-2024-0002"}},
		{Advisory: "USN-2", Package: "openssl", Introduced: "0", Fixed: "3.0.2-0ubuntu1.12", CVEs: []string{"CVE-2024-0001"}}, // same CVE, earlier fix
		{Advisory: "USN-3", Package: "openssl", Introduced: "0", Fixed: "3.0.2-0ubuntu1.9", CVEs: []string{"CVE-2023-9"}},     // already patched
		{Advisory: "USN-4", Package: "bash", Introduced: "0", Fixed: "5.1-6ubuntu1.1", CVEs: []string{"CVE-2022-1"}},          // patched exactly at fix
		{Advisory: "USN-5", Package: "openssl", Introduced: "3.1", Fixed: "3.1.5", CVEs: []string{"CVE-3"}},                   // not yet introduced
		{Advisory: "USN-6", Package: "openssl", Introduced: "0", CVEs: []string{"CVE-NOFIX"}},                                 // unfixed
	}}
	got, st, err := MatchPackages(context.Background(), src, f)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, v := range got {
		seen[v.Package.Name+"/"+v.CVE] = v.Fixed
	}
	// The vulnerable source package yields findings for each installed binary built from it.
	if seen["libssl3/CVE-2024-0001"] != "3.0.2-0ubuntu1.12" {
		t.Errorf("must keep the lowest fix that resolves a CVE: %v", seen)
	}
	if _, ok := seen["openssl/CVE-2024-0002"]; !ok {
		t.Errorf("missing CVE-2024-0002: %v", seen)
	}
	for _, bad := range []string{"libssl3/CVE-2023-9", "bash/CVE-2022-1", "libssl3/CVE-3", "libssl3/CVE-NOFIX"} {
		if _, ok := seen[bad]; ok {
			t.Errorf("false positive %s", bad)
		}
	}
	if st.Unfixed != 2 { // libssl3 and openssl both map to the unfixed advisory
		t.Errorf("unfixed count = %d, want 2", st.Unfixed)
	}

	_, st, _ = MatchPackages(context.Background(), src, &Facts{OS: OSInfo{ID: "arch"}, Packages: f.Packages})
	if st.Unsupported == "" {
		t.Error("unsupported distro must report why matching was skipped")
	}
}

func TestMatchPackagesRPMAndAPK(t *testing.T) {
	rp := &Facts{OS: OSInfo{ID: "rocky", VersionID: "9.3"}, Packages: []Package{{Name: "openssl-libs", Version: "1:3.0.7-24.el9", SrcName: "openssl", SrcVersion: "1:3.0.7-24.el9"}}}
	got, _, _ := MatchPackages(context.Background(), fakeSrc{rows: []store.PkgAdvisory{
		{Advisory: "RLSA-1", Package: "openssl", Introduced: "0", Fixed: "1:3.0.7-27.el9", CVEs: []string{"CVE-1"}},
		{Advisory: "RLSA-2", Package: "openssl", Introduced: "0", Fixed: "1:3.0.7-24.el9", CVEs: []string{"CVE-2"}},
	}}, rp)
	if len(got) != 1 || got[0].CVE != "CVE-1" {
		t.Errorf("rpm: %+v", got)
	}
	ap := &Facts{OS: OSInfo{ID: "alpine", VersionID: "3.19.1"}, Packages: []Package{{Name: "libcrypto3", Version: "3.1.4-r0", SrcName: "openssl", SrcVersion: "3.1.4-r0"}}}
	got, _, _ = MatchPackages(context.Background(), fakeSrc{rows: []store.PkgAdvisory{
		{Advisory: "A1", Package: "openssl", Introduced: "0", Fixed: "3.1.4-r1", CVEs: []string{"CVE-9"}},
		{Advisory: "A2", Package: "openssl", Introduced: "0", Fixed: "3.1.4-r0", CVEs: []string{"CVE-8"}},
	}}, ap)
	if len(got) != 1 || got[0].CVE != "CVE-9" {
		t.Errorf("apk: %+v", got)
	}
}

func TestRules(t *testing.T) {
	good := &Facts{
		SSHD: ParseSSHD("permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\nx11forwarding no\nciphers chacha20-poly1305@openssh.com\nmacs hmac-sha2-256\n", true), SSHDSrc: "sshd -T",
		Files:     ParseStat("644 root root /etc/passwd\n640 root shadow /etc/shadow\n440 root root /etc/sudoers\n"),
		Firewall:  Firewall{Known: true, Active: true, Tool: "ufw"},
		Sysctl:    map[string]string{"kernel.dmesg_restrict": "1", "kernel.kptr_restrict": "2", "net.ipv4.ip_forward": "0"},
		Listening: []Socket{{Proto: "tcp", Addr: "0.0.0.0", Port: 22}, {Proto: "tcp", Addr: "127.0.0.1", Port: 6379}},
	}
	for _, r := range Rules {
		if res := r.Eval(good); res.Status != Pass {
			t.Errorf("%s on a hardened host = %v (%s)", r.ID, res.Status, res.Evidence)
		}
	}
	bad := &Facts{
		SSHD: ParseSSHD("permitrootlogin yes\npasswordauthentication yes\npermitemptypasswords yes\nx11forwarding yes\nciphers aes128-cbc,aes256-gcm@openssh.com\nmacs hmac-md5\n", true), SSHDSrc: "sshd -T",
		Files:     ParseStat("666 root root /etc/passwd\n644 root root /etc/shadow\n"),
		Firewall:  Firewall{Known: true, Tool: "ufw"},
		Sysctl:    map[string]string{"kernel.dmesg_restrict": "0", "net.ipv4.ip_forward": "1"},
		Listening: []Socket{{Proto: "tcp", Addr: "0.0.0.0", Port: 6379, Process: "redis"}, {Proto: "tcp", Addr: "::", Port: 2375}},
	}
	for _, r := range Rules {
		res := r.Eval(bad)
		if res.Status != Fail || res.Evidence == "" || res.Remediation == "" {
			t.Errorf("%s on a weak host = %+v", r.ID, res)
		}
	}
	// Missing data is "unknown", never a silent pass or fail.
	for _, r := range Rules {
		if res := r.Eval(&Facts{}); res.Status != Unknown || res.Reason == "" {
			t.Errorf("%s with no facts = %+v, want unknown with a reason", r.ID, res)
		}
	}
	// Raw sshd_config (no sshd -T): absent directives use OpenSSH defaults.
	raw := &Facts{SSHD: ParseSSHD("Port 22\n", false), SSHDSrc: "sshd_config"}
	if res := ruleSSHRoot(raw); res.Status != Pass {
		t.Errorf("default PermitRootLogin is prohibit-password: %+v", res)
	}
	if res := ruleSSHWeakCrypto(raw); res.Status != Unknown {
		t.Errorf("cipher audit needs effective config: %+v", res)
	}
	// Inactive firewall but nothing exposed is fine.
	if res := ruleFirewall(&Facts{Firewall: Firewall{Known: true}, Listening: []Socket{{Addr: "127.0.0.1", Port: 80}}}); res.Status != Pass {
		t.Errorf("firewall off with only loopback listeners: %+v", res)
	}
}

func TestAllowlistIsReadOnly(t *testing.T) {
	// Every command segment must start with a known read-only binary.
	safe := map[string]bool{"cat": true, "uname": true, "dpkg-query": true, "rpm": true, "apk": true, "sw_vers": true,
		"brew": true, "sshd": true, "/usr/sbin/sshd": true, "ufw": true, "firewall-cmd": true, "iptables": true,
		"nft": true, "ss": true, "netstat": true, "stat": true, "sysctl": true}
	for _, c := range AllowedCommands() {
		if strings.ContainsAny(strings.ReplaceAll(c, "2>/dev/null", ""), ">;&`$(") && !strings.Contains(c, "${") {
			t.Errorf("command %q has shell metacharacters beyond ||, quoting and discarded stderr", c)
		}
		for _, seg := range strings.Split(c, "||") {
			bin := strings.Fields(strings.TrimSpace(seg))[0]
			if !safe[bin] {
				t.Errorf("command %q: %q is not a known read-only binary", c, bin)
			}
		}
		// Subcommands that change state.
		for _, bad := range []string{"sysctl -w", "brew install", "apk add", "apk del", "rpm -i", "rpm -e", "rpm -U"} {
			if strings.Contains(c, bad) {
				t.Errorf("command %q contains state-changing %q", c, bad)
			}
		}
	}
	// Firewall tools are only ever listed, never modified.
	if cmdIPTables != "iptables -S 2>/dev/null" || cmdNft != "nft list ruleset 2>/dev/null" {
		t.Error("firewall commands must stay list-only")
	}
	// The runner refuses anything else.
	if _, err := (fakeRunner{}).Run(context.Background(), "rm -rf /"); err != ErrCommandNotAllowed {
		t.Errorf("unlisted command must be refused, got %v", err)
	}
}

type fakeRunner map[string]string

func (f fakeRunner) Run(_ context.Context, cmd string) (string, error) {
	if !allowed[cmd] {
		return "", ErrCommandNotAllowed
	}
	return f[cmd], nil
}

func TestCollect(t *testing.T) {
	r := fakeRunner{
		cmdOSRelease: "ID=debian\nVERSION_ID=\"12\"\n",
		cmdUname:     "Linux 6.1.0 x86_64\n",
		cmdDpkg:      "bash\t5.2.15-2+b2\tinstall ok installed\tamd64\tbash\t5.2.15-2\n",
		cmdSSHDConf:  "PermitRootLogin yes\n",
		cmdSS:        "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n",
		cmdStat:      "644 root root /etc/passwd\n",
	}
	f, err := Collect(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if f.OS.ID != "debian" || len(f.Packages) != 1 || f.Packages[0].SrcVersion != "5.2.15-2" || f.SSHDSrc != "sshd_config" || len(f.Listening) != 1 || f.Firewall.Known {
		t.Errorf("facts: %+v", f)
	}
	if _, err := Collect(context.Background(), fakeRunner{}); err == nil {
		t.Error("a host that returns nothing must be an error, not an empty success")
	}
}
