package audit

import "testing"

// addBaseline fills the facts the hardening baseline needs, either hardened or weak.
func addBaseline(f *Facts, good bool) {
	if good {
		f.Baseline = &Baseline{
			LoginDefs: ParseKeyValues("PASS_MAX_DAYS 90\nPASS_MIN_LEN 12\n"),
			Accounts:  ParsePasswd("root:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n"),
			Mounts:    ParseMounts("tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n"),
			Units:     ParseUnits("rsyslog.service enabled\nchrony.service enabled\nunattended-upgrades.service enabled\n"),
		}
		f.Files = append(f.Files, ParseStat("644 root root /etc/group\n640 root shadow /etc/gshadow\n644 root root /etc/crontab\n")...)
		for k, v := range map[string]string{"net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.all.send_redirects": "0",
			"net.ipv4.conf.all.accept_source_route": "0", "net.ipv4.tcp_syncookies": "1", "kernel.randomize_va_space": "2", "fs.suid_dumpable": "0"} {
			f.Sysctl[k] = v
		}
		f.SSHD["maxauthtries"] = []string{"3"}
		f.SSHD["clientaliveinterval"] = []string{"300"}
		return
	}
	f.Baseline = &Baseline{
		LoginDefs: ParseKeyValues("PASS_MAX_DAYS 99999\nPASS_MIN_LEN 5\n"),
		Accounts:  ParsePasswd("root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\nwww:x:33:33::/var/www:/bin/bash\n"),
		Mounts:    ParseMounts("/dev/sda1 / ext4 rw 0 0\n"),
		Units:     ParseUnits("telnet.socket enabled\nvsftpd.service enabled\n"),
	}
	f.Files = append(f.Files, ParseStat("666 root root /etc/group\n664 root shadow /etc/gshadow\n")...)
	for k, v := range map[string]string{"net.ipv4.conf.all.accept_redirects": "1", "kernel.randomize_va_space": "0", "fs.suid_dumpable": "2"} {
		f.Sysctl[k] = v
	}
	f.SSHD["maxauthtries"] = []string{"10"}
	f.SSHD["hostbasedauthentication"] = []string{"yes"}
}

func TestParseBaselineInputs(t *testing.T) {
	acc := ParsePasswd("root:x:0:0:root:/root:/bin/bash\nbad line\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n")
	if len(acc) != 2 || acc[1].Name != "bin" || acc[1].UID != 2 {
		t.Errorf("%+v", acc)
	}
	kv := ParseKeyValues("# c\nPASS_MAX_DAYS\t90\nminlen = 12\n")
	if kv["PASS_MAX_DAYS"] != "90" || kv["minlen"] != "12" {
		t.Errorf("%+v", kv)
	}
	if ParseUnits("") != nil {
		t.Error("no systemd output must yield nil (unknown), not an empty set")
	}
}

func TestBaselineUnknownWithoutFacts(t *testing.T) {
	for _, r := range baselineRules {
		if res := r.Eval(&Facts{}); res.Status != Unknown {
			t.Errorf("%s with no facts must be unknown, got %s", r.ID, res.Status)
		}
	}
}
