package netaudit

import (
	"fmt"
	"regexp"
	"strings"

	"babylon/internal/audit"
)

// Type names accepted by --type.
const CiscoIOS = "cisco-ios"

// Rule is one hardening check over a parsed configuration.
type Rule struct {
	ID       string
	Title    string
	Severity string
	Synopsis string
	Eval     func(*Config) audit.Result
}

func pass(ev string) audit.Result { return audit.Result{Status: audit.Pass, Evidence: ev} }

func fail(ev, fix string) audit.Result {
	return audit.Result{Status: audit.Fail, Evidence: ev, Remediation: fix}
}

// RulesFor returns the rules for a device type, or nil if unsupported.
func RulesFor(deviceType string) []Rule {
	if deviceType == CiscoIOS {
		return IOSRules
	}
	return nil
}

// IOSRules are the Cisco IOS / IOS-XE hardening rules.
var IOSRules = []Rule{
	{ID: "IOS-001", Title: "Telnet is allowed on remote login lines", Severity: "high",
		Synopsis: "A vty line accepts Telnet, which sends the login and every command in cleartext.", Eval: iosTelnet},
	{ID: "IOS-002", Title: "Passwords are stored in cleartext", Severity: "medium",
		Synopsis: "service password-encryption is off and passwords appear in the configuration unencrypted or with the weak type 7 encoding.", Eval: iosPasswordStorage},
	{ID: "IOS-003", Title: "Privileged mode uses a weak or missing secret", Severity: "high",
		Synopsis: "enable password is used instead of enable secret, or the secret uses a weak hash.", Eval: iosEnable},
	{ID: "IOS-004", Title: "SNMP uses default or writable community strings", Severity: "high",
		Synopsis: "A well-known community string (public, private) or a read-write community is configured.", Eval: iosSNMP},
	{ID: "IOS-005", Title: "The plain HTTP management server is enabled", Severity: "medium",
		Synopsis: "ip http server exposes the device's web interface over unencrypted HTTP.", Eval: iosHTTP},
	{ID: "IOS-006", Title: "SSH version 2 is not enforced", Severity: "medium",
		Synopsis: "The device allows SSH version 1 or does not pin version 2.", Eval: iosSSHv2},
	{ID: "IOS-007", Title: "Remote login lines have no access list or idle timeout", Severity: "medium",
		Synopsis: "A vty line accepts connections from any address or never times out idle sessions.", Eval: iosVTYHardening},
	{ID: "IOS-008", Title: "Centralized authentication (AAA) is not enabled", Severity: "medium",
		Synopsis: "aaa new-model is missing, so logins rely on local line passwords.", Eval: iosAAA},
	{ID: "IOS-009", Title: "No remote logging is configured", Severity: "low",
		Synopsis: "No syslog server is set, so events are lost when the device reboots or is tampered with.", Eval: iosLogging},
	{ID: "IOS-010", Title: "Time is not synchronized or log timestamps are missing", Severity: "low",
		Synopsis: "No NTP server is configured or log entries carry no timestamps.", Eval: iosTime},
	{ID: "IOS-011", Title: "Legacy small services or source routing are enabled", Severity: "medium",
		Synopsis: "tcp/udp small servers, finger, BOOTP or IP source routing are active.", Eval: iosLegacy},
	{ID: "IOS-012", Title: "CDP is enabled globally", Severity: "low",
		Synopsis: "Cisco Discovery Protocol leaks device model, software version and addresses to neighbours.", Eval: iosCDP},
	{ID: "IOS-013", Title: "No login banner is configured", Severity: "low",
		Synopsis: "There is no legal warning banner shown before login.", Eval: iosBanner},
}

var weakCommunity = regexp.MustCompile(`(?i)^(public|private|cisco|community|snmp|admin|test)$`)

func iosTelnet(c *Config) audit.Result {
	var bad []string
	for _, b := range c.BlocksWith("line vty") {
		for _, l := range b.Find("transport input") {
			f := strings.Fields(l)[2:]
			if len(f) == 0 {
				continue
			}
			for _, w := range f {
				if w == "telnet" || w == "all" {
					bad = append(bad, b.Header+": "+l)
					break
				}
			}
		}
		if !b.Has("transport input") { // IOS default for vty lines is to allow every protocol
			bad = append(bad, b.Header+": no transport input restriction (Telnet is allowed by default)")
		}
	}
	if len(c.BlocksWith("line vty")) == 0 {
		return audit.Result{Status: audit.Unknown, Reason: "no line vty block in the configuration"}
	}
	if len(bad) == 0 {
		return pass("vty lines accept SSH only")
	}
	return fail(strings.Join(bad, "\n"), "On every vty line set: transport input ssh")
}

// weakCredential classifies the words after a "password" keyword: "" when the
// credential is stored as a strong hash, otherwise why it is weak.
func weakCredential(after []string) string {
	if len(after) == 0 {
		return ""
	}
	switch after[0] {
	case "7":
		return "type 7 (reversible encoding)"
	case "0":
		return "cleartext"
	case "5", "8", "9":
		return ""
	}
	return "cleartext"
}

func iosPasswordStorage(c *Config) audit.Result {
	var bad []string
	scan := func(where, l string) {
		f := strings.Fields(l)
		for i, w := range f {
			if w == "password" || (w == "secret" && i+1 < len(f) && f[i+1] == "0") {
				after := f[i+1:]
				if w == "secret" {
					after = []string{"0"}
				}
				if why := weakCredential(after); why != "" {
					bad = append(bad, fmt.Sprintf("%s: %s (%s)", where, redact(l), why))
				}
				return
			}
		}
	}
	for _, l := range c.Top {
		if strings.HasPrefix(l, "username ") {
			scan("global", l)
		}
	}
	for _, b := range c.Blocks {
		for _, l := range b.Lines {
			if strings.HasPrefix(l, "password ") {
				scan(b.Header, l)
			}
		}
	}
	if len(bad) == 0 {
		return pass("no cleartext or reversible passwords found")
	}
	fix := "Replace line and user passwords with secrets (username NAME algorithm-type scrypt secret ...) and use type 8 or 9 hashes."
	if !c.Has("service password-encryption") {
		fix = "Enable service password-encryption as a stopgap. " + fix
	}
	return fail(strings.Join(dedupe(bad), "\n"), fix)
}

func contains(f []string, s string) bool {
	for _, x := range f {
		if x == s {
			return true
		}
	}
	return false
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// redact hides the secret part of a line so the finding evidence never repeats it.
func redact(l string) string {
	f := strings.Fields(l)
	for i, w := range f {
		if (w == "password" || w == "secret") && i+1 < len(f) {
			return strings.Join(f[:i+1], " ") + " ***"
		}
	}
	return l
}

func iosEnable(c *Config) audit.Result {
	var bad []string
	if c.Has("enable password") {
		bad = append(bad, "enable password is set (cleartext or reversible)")
	}
	secrets := c.Find("enable secret")
	for _, l := range secrets {
		f := strings.Fields(l)
		if len(f) >= 3 && (f[2] == "5" || f[2] == "0") {
			bad = append(bad, fmt.Sprintf("enable secret uses type %s", f[2]))
		}
		if len(f) == 3 { // "enable secret <text>" with no type is a cleartext secret that the device will hash itself
			bad = append(bad, "enable secret has no hash type (cleartext in the file)")
		}
	}
	if len(secrets) == 0 && !c.Has("enable password") {
		return audit.Result{Status: audit.Unknown, Reason: "no enable secret or password in this configuration"}
	}
	if len(bad) == 0 {
		return pass("enable secret uses type 8 or 9")
	}
	return fail(strings.Join(dedupe(bad), "\n"), "Use enable algorithm-type scrypt secret (type 9) or sha256 (type 8), and remove enable password.")
}

func iosSNMP(c *Config) audit.Result {
	var bad []string
	for _, l := range c.Find("snmp-server community") {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		rw := len(f) > 3 && strings.EqualFold(f[3], "rw")
		for _, x := range f[3:] {
			if strings.EqualFold(x, "rw") {
				rw = true
			}
		}
		switch {
		case weakCommunity.MatchString(f[2]):
			bad = append(bad, fmt.Sprintf("community %q (well-known)%s", f[2], map[bool]string{true: ", read-write", false: ""}[rw]))
		case rw:
			bad = append(bad, "a read-write community is configured")
		}
	}
	if len(bad) == 0 {
		return pass("no default or read-write SNMP communities")
	}
	return fail(strings.Join(bad, "\n"), "Remove the community strings and use SNMPv3 with authentication and encryption (snmp-server group ... v3 priv); never allow RW.")
}

func iosHTTP(c *Config) audit.Result {
	if c.Has("ip http server") && !c.Has("no ip http server") {
		return fail("ip http server", "Disable it (no ip http server) and use ip http secure-server only where a web interface is needed, restricted by ip http access-class.")
	}
	return pass("the plain HTTP server is not enabled")
}

func iosSSHv2(c *Config) audit.Result {
	if !c.Has("ip ssh version 2") {
		return fail("ip ssh version 2 is not set", "Set ip ssh version 2 (needs a domain name and an RSA key of at least 2048 bits).")
	}
	return pass("ip ssh version 2")
}

func iosVTYHardening(c *Config) audit.Result {
	blocks := c.BlocksWith("line vty")
	if len(blocks) == 0 {
		return audit.Result{Status: audit.Unknown, Reason: "no line vty block in the configuration"}
	}
	var bad []string
	for _, b := range blocks {
		if !b.Has("access-class") {
			bad = append(bad, b.Header+": no access-class")
		}
		et := b.Find("exec-timeout")
		if len(et) == 0 || et[0] == "exec-timeout 0 0" {
			bad = append(bad, b.Header+": idle sessions never time out")
		}
	}
	if len(bad) == 0 {
		return pass("vty lines have an access-class and an idle timeout")
	}
	return fail(strings.Join(bad, "\n"), "Add access-class <ACL> in and exec-timeout 10 0 to every vty line.")
}

func iosAAA(c *Config) audit.Result {
	if c.Has("aaa new-model") {
		return pass("aaa new-model")
	}
	return fail("aaa new-model is not configured", "Enable aaa new-model with TACACS+ or RADIUS and a local fallback account.")
}

func iosLogging(c *Config) audit.Result {
	for _, l := range c.Find("logging host") {
		return pass(l)
	}
	for _, l := range c.Find("logging") {
		f := strings.Fields(l)
		if len(f) == 2 && regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`).MatchString(f[1]) {
			return pass(l)
		}
	}
	return fail("no logging host is configured", "Add logging host <syslog-server> and logging trap informational.")
}

func iosTime(c *Config) audit.Result {
	var bad []string
	if !c.Has("ntp server") && !c.Has("ntp peer") {
		bad = append(bad, "no ntp server")
	}
	ts := c.Find("service timestamps log")
	if len(ts) == 0 || strings.Contains(ts[0], "disable") {
		bad = append(bad, "service timestamps log datetime is not set")
	}
	if len(bad) == 0 {
		return pass("NTP and log timestamps are configured")
	}
	return fail(strings.Join(bad, "\n"), "Configure ntp server (with authentication) and service timestamps log datetime msec localtime show-timezone.")
}

func iosLegacy(c *Config) audit.Result {
	var bad []string
	for _, s := range []string{"service tcp-small-servers", "service udp-small-servers", "ip finger", "service finger", "ip bootp server", "ip source-route"} {
		if c.Has(s) {
			bad = append(bad, s)
		}
	}
	if !c.Has("ip source-route") && !c.Has("no ip source-route") {
		// IOS enables source routing by default; the config only shows the "no" form.
		bad = append(bad, "ip source-route is not disabled (default is enabled)")
	}
	if len(bad) == 0 {
		return pass("legacy services and source routing are disabled")
	}
	return fail(strings.Join(bad, "\n"), "Add: no service tcp-small-servers, no service udp-small-servers, no ip finger, no ip bootp server, no ip source-route.")
}

func iosCDP(c *Config) audit.Result {
	if c.Has("no cdp run") {
		return pass("no cdp run")
	}
	return fail("CDP is not disabled globally (default is enabled)", "Add no cdp run, or disable it per interface facing untrusted networks (no cdp enable).")
}

func iosBanner(c *Config) audit.Result {
	if c.Has("banner login") || c.Has("banner motd") || c.Has("banner exec") {
		return pass("a banner is configured")
	}
	return fail("no banner login, motd or exec", "Add banner login with a legal warning that unauthorized access is prohibited.")
}
