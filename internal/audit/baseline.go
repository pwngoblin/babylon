package audit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The hardening baseline: configuration checks for Linux hosts in the spirit of
// the CIS benchmarks (account policy, services, filesystem, network and kernel
// parameters, logging, time, updates). The wording and thresholds are Babylon's
// own. Each rule reads only collected facts, and returns Unknown, never Pass,
// when the data needed could not be read.

const (
	cmdLoginDefs = `cat /etc/login.defs 2>/dev/null`
	cmdPasswd    = `cat /etc/passwd 2>/dev/null`
	cmdPwQuality = `cat /etc/security/pwquality.conf 2>/dev/null`
	cmdMounts    = `cat /proc/mounts 2>/dev/null`
	cmdUnits     = `systemctl list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null`
	cmdSysctlNet = `sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.rp_filter net.ipv4.tcp_syncookies kernel.randomize_va_space fs.suid_dumpable 2>/dev/null`
	cmdStat2     = `stat -c '%a %U %G %n' /etc/group /etc/gshadow /etc/crontab 2>/dev/null`
)

func init() {
	allow(cmdLoginDefs, cmdPasswd, cmdPwQuality, cmdMounts, cmdUnits, cmdSysctlNet, cmdStat2)
	Rules = append(Rules, baselineRules...)
}

// Baseline is the extra facts the hardening rules need; nil fields were not collected.
type Baseline struct {
	LoginDefs map[string]string // nil when /etc/login.defs was unreadable
	Accounts  []Account         // nil when /etc/passwd was unreadable
	PwQuality map[string]string
	Mounts    []Mount
	Units     map[string]bool // enabled systemd unit files; nil without systemd
}

type Account struct {
	Name  string
	UID   int
	Shell string
}

type Mount struct{ Path, Type, Options string }

func (m Mount) has(opt string) bool {
	for _, o := range strings.Split(m.Options, ",") {
		if o == opt {
			return true
		}
	}
	return false
}

// collectBaseline gathers the baseline facts using the allowlisted commands.
func collectBaseline(f *Facts, run func(string) string) {
	b := &Baseline{}
	if out := run(cmdLoginDefs); out != "" {
		b.LoginDefs = ParseKeyValues(out)
	}
	b.Accounts = ParsePasswd(run(cmdPasswd))
	if out := run(cmdPwQuality); out != "" {
		b.PwQuality = ParseKeyValues(out)
	}
	b.Mounts = ParseMounts(run(cmdMounts))
	b.Units = ParseUnits(run(cmdUnits))
	for k, v := range ParseSysctl(run(cmdSysctlNet)) {
		if f.Sysctl == nil {
			f.Sysctl = map[string]string{}
		}
		f.Sysctl[k] = v
	}
	f.Files = append(f.Files, ParseStat(run(cmdStat2))...)
	f.Baseline = b
}

// ParseKeyValues reads "KEY value" or "KEY = value" config lines, ignoring comments.
func ParseKeyValues(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		} else if fs := strings.Fields(line); len(fs) >= 2 {
			out[fs[0]] = strings.Join(fs[1:], " ")
		}
	}
	return out
}

func ParsePasswd(s string) []Account {
	var out []Account
	for _, line := range strings.Split(s, "\n") {
		p := strings.Split(strings.TrimSpace(line), ":")
		if len(p) < 7 {
			continue
		}
		uid, err := strconv.Atoi(p[2])
		if err != nil {
			continue
		}
		out = append(out, Account{Name: p[0], UID: uid, Shell: p[6]})
	}
	return out
}

func ParseMounts(s string) []Mount {
	var out []Mount
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 {
			out = append(out, Mount{Path: f[1], Type: f[2], Options: f[3]})
		}
	}
	return out
}

func ParseUnits(s string) map[string]bool {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	u := map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		if f := strings.Fields(line); len(f) >= 1 {
			u[f[0]] = true
		}
	}
	return u
}

func unitEnabled(b *Baseline, names ...string) []string {
	var on []string
	for _, n := range names {
		if b.Units[n] {
			on = append(on, n)
		}
	}
	return on
}

func baselineMissing(what string) Result {
	return Result{Status: Unknown, Reason: what + " could not be read by the audit account"}
}

var baselineRules = []Rule{
	{ID: "ACC-001", Title: "Accounts other than root have UID 0", Severity: "high",
		Synopsis: "Any account with UID 0 is a root account; extras are a classic backdoor.", Eval: ruleUID0},
	{ID: "ACC-002", Title: "Password ageing is not enforced", Severity: "low",
		Synopsis: "PASS_MAX_DAYS is unset or longer than a year.", Eval: rulePassAge},
	{ID: "ACC-003", Title: "Minimum password length is below 8", Severity: "low",
		Synopsis: "The system does not require reasonably long passwords.", Eval: rulePassLen},
	{ID: "ACC-004", Title: "System accounts have login shells", Severity: "low",
		Synopsis: "Service accounts should not be able to log in interactively.", Eval: ruleSystemShells},
	{ID: "SVC-002", Title: "Legacy cleartext or unneeded services are enabled", Severity: "high",
		Synopsis: "telnet, rsh, rlogin, tftp, talk or NIS services start at boot.", Eval: ruleLegacyServices},
	{ID: "FS-001", Title: "/tmp is not mounted with nodev and nosuid", Severity: "low",
		Synopsis: "A separate, restricted /tmp limits what an attacker can do with a writable directory.", Eval: ruleTmpMount},
	{ID: "PERM-002", Title: "Group, gshadow or crontab files have unsafe permissions", Severity: "medium",
		Synopsis: "These files must not be writable by group or others.", Eval: rulePermsExtra},
	{ID: "NET-001", Title: "Network stack accepts redirects, source routing or lacks SYN cookies", Severity: "medium",
		Synopsis: "sysctl network parameters allow traffic manipulation or weaken flood protection.", Eval: ruleNetSysctl},
	{ID: "KERN-002", Title: "Address space randomisation or core-dump protection is weakened", Severity: "medium",
		Synopsis: "kernel.randomize_va_space is not 2 or fs.suid_dumpable is not 0.", Eval: ruleASLR},
	{ID: "SSH-005", Title: "SSH allows many authentication attempts", Severity: "low",
		Synopsis: "MaxAuthTries above 4 makes online guessing easier.", Eval: ruleSSHMaxAuth},
	{ID: "SSH-006", Title: "SSH trusts host-based auth, rhosts or user environments", Severity: "medium",
		Synopsis: "HostbasedAuthentication, IgnoreRhosts or PermitUserEnvironment are set unsafely.", Eval: ruleSSHTrust},
	{ID: "SSH-007", Title: "SSH idle sessions are not closed", Severity: "low",
		Synopsis: "ClientAliveInterval is unset or zero, so abandoned sessions stay open.", Eval: ruleSSHIdle},
	{ID: "LOG-001", Title: "No system logging daemon is enabled", Severity: "low",
		Synopsis: "Without rsyslog, syslog-ng or auditd, security events may not be kept.", Eval: ruleLogging},
	{ID: "TIME-001", Title: "No time synchronisation service is enabled", Severity: "low",
		Synopsis: "Accurate time is needed for logs, certificates and Kerberos.", Eval: ruleTimeSync},
	{ID: "UPD-001", Title: "Automatic security updates are not enabled", Severity: "low",
		Synopsis: "No unattended-upgrades, dnf-automatic or yum-cron service is enabled.", Eval: ruleAutoUpdates},
}

func ruleUID0(f *Facts) Result {
	if f.Baseline == nil || f.Baseline.Accounts == nil {
		return baselineMissing("/etc/passwd")
	}
	var bad []string
	for _, a := range f.Baseline.Accounts {
		if a.UID == 0 && a.Name != "root" {
			bad = append(bad, a.Name)
		}
	}
	if len(bad) > 0 {
		return Result{Status: Fail, Evidence: "UID 0 accounts besides root: " + strings.Join(bad, ", "),
			Remediation: "Remove the account or give it a unique non-zero UID; investigate how it was created."}
	}
	return Result{Status: Pass, Evidence: "root is the only UID 0 account"}
}

func rulePassAge(f *Facts) Result {
	if f.Baseline == nil || f.Baseline.LoginDefs == nil {
		return baselineMissing("/etc/login.defs")
	}
	v := f.Baseline.LoginDefs["PASS_MAX_DAYS"]
	n, err := strconv.Atoi(v)
	if err != nil || n > 365 || n < 0 || n == 99999 {
		return Result{Status: Fail, Evidence: "PASS_MAX_DAYS = " + orNone(v),
			Remediation: "Set PASS_MAX_DAYS to 365 or less in /etc/login.defs (and apply to existing users with chage)."}
	}
	return Result{Status: Pass, Evidence: "PASS_MAX_DAYS = " + v}
}

func orNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

func rulePassLen(f *Facts) Result {
	b := f.Baseline
	if b == nil || (b.PwQuality == nil && b.LoginDefs == nil) {
		return baselineMissing("/etc/security/pwquality.conf and /etc/login.defs")
	}
	v := b.PwQuality["minlen"]
	src := "pwquality minlen"
	if v == "" {
		v, src = b.LoginDefs["PASS_MIN_LEN"], "PASS_MIN_LEN"
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 8 {
		return Result{Status: Fail, Evidence: src + " = " + orNone(v),
			Remediation: "Set `minlen = 12` in /etc/security/pwquality.conf (and enable pam_pwquality in the PAM stack)."}
	}
	return Result{Status: Pass, Evidence: fmt.Sprintf("%s = %d", src, n)}
}

func ruleSystemShells(f *Facts) Result {
	if f.Baseline == nil || f.Baseline.Accounts == nil {
		return baselineMissing("/etc/passwd")
	}
	okShell := func(s string) bool {
		return strings.HasSuffix(s, "/nologin") || strings.HasSuffix(s, "/false") || s == "" || strings.HasSuffix(s, "/sync") || strings.HasSuffix(s, "/shutdown") || strings.HasSuffix(s, "/halt")
	}
	var bad []string
	for _, a := range f.Baseline.Accounts {
		if a.UID > 0 && a.UID < 1000 && a.Name != "nobody" && !okShell(a.Shell) {
			bad = append(bad, fmt.Sprintf("%s (%s)", a.Name, a.Shell))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return Result{Status: Fail, Evidence: strings.Join(bad, "\n"), Remediation: "Set the shell of service accounts to /usr/sbin/nologin (usermod -s /usr/sbin/nologin <user>)."}
	}
	return Result{Status: Pass, Evidence: "no system account has an interactive shell"}
}

var legacyUnits = []string{"telnet.socket", "telnetd.service", "rsh.socket", "rlogin.socket", "rexec.socket", "tftp.socket", "tftpd-hpa.service",
	"talk.socket", "ypserv.service", "ypbind.service", "xinetd.service", "rsh-server.service", "vsftpd.service"}

func ruleLegacyServices(f *Facts) Result {
	if f.Baseline == nil || f.Baseline.Units == nil {
		return Result{Status: Unknown, Reason: "systemd unit list unavailable (host may not use systemd)"}
	}
	if on := unitEnabled(f.Baseline, legacyUnits...); len(on) > 0 {
		return Result{Status: Fail, Evidence: "enabled at boot: " + strings.Join(on, ", "),
			Remediation: "Disable and remove them (systemctl disable --now <unit>), and use SSH/SFTP instead of telnet, rsh and plain FTP."}
	}
	return Result{Status: Pass, Evidence: "no legacy service is enabled"}
}

func ruleTmpMount(f *Facts) Result {
	if f.Baseline == nil || len(f.Baseline.Mounts) == 0 {
		return baselineMissing("/proc/mounts")
	}
	for _, m := range f.Baseline.Mounts {
		if m.Path == "/tmp" {
			if m.has("nodev") && m.has("nosuid") {
				return Result{Status: Pass, Evidence: "/tmp mounted " + m.Options}
			}
			return Result{Status: Fail, Evidence: "/tmp mounted with " + m.Options, Remediation: "Add nodev,nosuid (and noexec where workable) to the /tmp entry in /etc/fstab or tmp.mount."}
		}
	}
	return Result{Status: Fail, Evidence: "/tmp is not a separate mount", Remediation: "Mount /tmp as tmpfs or its own partition with nodev,nosuid,noexec."}
}

func rulePermsExtra(f *Facts) Result {
	var checked int
	var bad []string
	for _, fi := range f.Files {
		switch fi.Path {
		case "/etc/group", "/etc/gshadow", "/etc/crontab":
			checked++
			if len(fi.Mode) >= 2 && !strings.ContainsAny(fi.Mode[len(fi.Mode)-2:], "2367") {
				continue
			}
			bad = append(bad, fmt.Sprintf("%s mode %s", fi.Path, fi.Mode))
		}
	}
	if checked == 0 {
		return baselineMissing("/etc/group, /etc/gshadow and /etc/crontab")
	}
	if len(bad) > 0 {
		return Result{Status: Fail, Evidence: strings.Join(bad, "\n"), Remediation: "chmod go-w on these files (/etc/gshadow should be 640 or stricter)."}
	}
	return Result{Status: Pass, Evidence: fmt.Sprintf("%d file(s) not group/other-writable", checked)}
}

func ruleNetSysctl(f *Facts) Result {
	want := map[string]string{"net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.all.send_redirects": "0",
		"net.ipv4.conf.all.accept_source_route": "0", "net.ipv4.tcp_syncookies": "1"}
	var bad []string
	seen := 0
	for k, w := range want {
		if v, ok := f.Sysctl[k]; ok {
			seen++
			if v != w {
				bad = append(bad, fmt.Sprintf("%s = %s (want %s)", k, v, w))
			}
		}
	}
	if seen == 0 {
		return baselineMissing("network sysctl values")
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return Result{Status: Fail, Evidence: strings.Join(bad, "\n"), Remediation: "Set these in /etc/sysctl.d/ and apply with `sysctl --system`."}
	}
	return Result{Status: Pass, Evidence: "redirects and source routing off, SYN cookies on"}
}

func ruleASLR(f *Facts) Result {
	a, okA := f.Sysctl["kernel.randomize_va_space"]
	d, okD := f.Sysctl["fs.suid_dumpable"]
	if !okA && !okD {
		return baselineMissing("kernel.randomize_va_space and fs.suid_dumpable")
	}
	var bad []string
	if okA && a != "2" {
		bad = append(bad, "kernel.randomize_va_space = "+a+" (want 2)")
	}
	if okD && d != "0" {
		bad = append(bad, "fs.suid_dumpable = "+d+" (want 0)")
	}
	if len(bad) > 0 {
		return Result{Status: Fail, Evidence: strings.Join(bad, "\n"), Remediation: "Set kernel.randomize_va_space=2 and fs.suid_dumpable=0 in /etc/sysctl.d/."}
	}
	return Result{Status: Pass, Evidence: "ASLR full, suid core dumps off"}
}

func ruleSSHMaxAuth(f *Facts) Result {
	v, ok := sshdVal(f, "maxauthtries", "6")
	if !ok {
		return noSSHD()
	}
	if n, err := strconv.Atoi(v); err != nil || n > 4 {
		return Result{Status: Fail, Evidence: "MaxAuthTries " + v, Remediation: "Set `MaxAuthTries 4` in /etc/ssh/sshd_config."}
	}
	return Result{Status: Pass, Evidence: "MaxAuthTries " + v}
}

func ruleSSHTrust(f *Facts) Result {
	if _, ok := sshdVal(f, "x11forwarding", "no"); !ok {
		return noSSHD()
	}
	var bad []string
	if v, _ := sshdVal(f, "hostbasedauthentication", "no"); v == "yes" {
		bad = append(bad, "HostbasedAuthentication yes")
	}
	if v, _ := sshdVal(f, "ignorerhosts", "yes"); v == "no" {
		bad = append(bad, "IgnoreRhosts no")
	}
	if v, _ := sshdVal(f, "permituserenvironment", "no"); v == "yes" {
		bad = append(bad, "PermitUserEnvironment yes")
	}
	if len(bad) > 0 {
		return Result{Status: Fail, Evidence: strings.Join(bad, "\n"), Remediation: "Set HostbasedAuthentication no, IgnoreRhosts yes and PermitUserEnvironment no."}
	}
	return Result{Status: Pass, Evidence: "host-based auth off, rhosts ignored, user environment off"}
}

func ruleSSHIdle(f *Facts) Result {
	v, ok := sshdVal(f, "clientaliveinterval", "0")
	if !ok {
		return noSSHD()
	}
	if n, err := strconv.Atoi(v); err != nil || n <= 0 || n > 900 {
		return Result{Status: Fail, Evidence: "ClientAliveInterval " + v, Remediation: "Set `ClientAliveInterval 300` and `ClientAliveCountMax 2`."}
	}
	return Result{Status: Pass, Evidence: "ClientAliveInterval " + v}
}

func ruleLogging(f *Facts) Result {
	if f.Baseline == nil || f.Baseline.Units == nil {
		return Result{Status: Unknown, Reason: "systemd unit list unavailable"}
	}
	if on := unitEnabled(f.Baseline, "rsyslog.service", "syslog-ng.service", "auditd.service", "syslog.service"); len(on) > 0 {
		return Result{Status: Pass, Evidence: "enabled: " + strings.Join(on, ", ")}
	}
	return Result{Status: Fail, Evidence: "none of rsyslog, syslog-ng or auditd is enabled (journald alone may not persist logs)",
		Remediation: "Install and enable rsyslog or auditd, and persist the journal (Storage=persistent)."}
}

func ruleTimeSync(f *Facts) Result {
	if f.Baseline == nil || f.Baseline.Units == nil {
		return Result{Status: Unknown, Reason: "systemd unit list unavailable"}
	}
	if on := unitEnabled(f.Baseline, "chrony.service", "chronyd.service", "ntp.service", "ntpd.service", "systemd-timesyncd.service"); len(on) > 0 {
		return Result{Status: Pass, Evidence: "enabled: " + strings.Join(on, ", ")}
	}
	return Result{Status: Fail, Evidence: "no time synchronisation service is enabled", Remediation: "Enable chrony or systemd-timesyncd."}
}

func ruleAutoUpdates(f *Facts) Result {
	if f.Baseline == nil || f.Baseline.Units == nil {
		return Result{Status: Unknown, Reason: "systemd unit list unavailable"}
	}
	if on := unitEnabled(f.Baseline, "unattended-upgrades.service", "dnf-automatic.timer", "dnf-automatic-install.timer", "yum-cron.service", "apt-daily-upgrade.timer"); len(on) > 0 {
		return Result{Status: Pass, Evidence: "enabled: " + strings.Join(on, ", ")}
	}
	return Result{Status: Fail, Evidence: "no automatic update service is enabled", Remediation: "Enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL family), or confirm patching is handled by another process."}
}
