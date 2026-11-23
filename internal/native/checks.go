package native

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"babylon/internal/policy"
)

// Available returns the built-in checks permitted at a safety level. Checks above
// it are not offered at all (and Order would reject them), so a scan without
// --allow-active never even loads the probing checks.
func Available(max policy.Safety) []Check {
	var out []Check
	for _, c := range Builtin() {
		if c.Safety <= max {
			out = append(out, c)
		}
	}
	return out
}

// Builtin returns Babylon's built-in checks.
func Builtin() []Check {
	base := []Check{
		sshWeakAlgorithms, redisUnauth, ftpAnonymous, smbSigning, smbv1, memcachedOpen, mongodbOpen,
		x11Open, nfsExports, dnsRecursion, snmpPublic, vncNoAuth, telnetService, httpTrace, tlsWeakness,
	}
	base = append(base, windowsChecks()...)
	return append(base, probeChecks()...)
}

func scriptNeeds(id string) func(*Env) string {
	return func(e *Env) string {
		if len(e.ScriptAnywhere(id)) == 0 {
			return "no " + id + " result (service absent or script found nothing)"
		}
		return ""
	}
}

// perHit runs fn for each service that produced output for a script.
func perHit(e *Env, script string, fn func(ScriptHit) *Finding) []Finding {
	var out []Finding
	for _, h := range e.ScriptAnywhere(script) {
		if f := fn(h); f != nil {
			f.Port, f.Proto = h.Service.Port, h.Service.Proto
			out = append(out, *f)
		}
	}
	return out
}

// ---- SSH ----

var sshWeakKex = map[string]string{
	"diffie-hellman-group1-sha1": "1024-bit Diffie-Hellman with SHA-1", "diffie-hellman-group14-sha1": "SHA-1 key exchange",
	"diffie-hellman-group-exchange-sha1": "SHA-1 key exchange",
}
var sshWeakCiphers = []string{"3des-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc", "des-cbc", "rijndael-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"}
var sshWeakMACs = []string{"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com", "hmac-ripemd160"}
var sshWeakHostKeys = []string{"ssh-dss"}

var sshWeakAlgorithms = Check{
	ID: "ssh-weak-algorithms", Name: "SSH server supports weak algorithms", Family: "Misconfiguration",
	Needs: scriptNeeds("ssh2-enum-algos"),
	Run: func(e *Env) []Finding {
		return perHit(e, "ssh2-enum-algos", func(h ScriptHit) *Finding {
			weak := WeakSSHAlgorithms(h.Output)
			if len(weak) == 0 {
				return nil
			}
			return &Finding{
				Title: "SSH Server Supports Weak Algorithms", Severity: "low",
				Synopsis:    "The SSH server offers cryptographic algorithms that are considered weak.",
				Description: "The server advertises deprecated key exchange, cipher, MAC or host-key algorithms. A client or attacker may negotiate them, weakening the connection.",
				Remediation: "Remove the listed algorithms from the sshd configuration (KexAlgorithms, Ciphers, MACs, HostKeyAlgorithms).",
				Evidence:    strings.Join(weak, "\n"), Detection: "config",
			}
		})
	},
}

// WeakSSHAlgorithms extracts weak algorithms from ssh2-enum-algos output.
func WeakSSHAlgorithms(out string) []string {
	var weak []string
	section := ""
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "kex_algorithms"):
			section = "kex"
		case strings.HasPrefix(t, "server_host_key_algorithms"):
			section = "hostkey"
		case strings.HasPrefix(t, "encryption_algorithms"):
			section = "cipher"
		case strings.HasPrefix(t, "mac_algorithms"):
			section = "mac"
		case strings.HasPrefix(t, "compression_algorithms"):
			section = ""
		case t != "" && section != "":
			if why, ok := sshWeakKex[t]; ok && section == "kex" {
				weak = append(weak, fmt.Sprintf("kex: %s (%s)", t, why))
			}
			if section == "cipher" && contains(sshWeakCiphers, t) {
				weak = append(weak, "cipher: "+t)
			}
			if section == "mac" && contains(sshWeakMACs, t) {
				weak = append(weak, "mac: "+t)
			}
			if section == "hostkey" && contains(sshWeakHostKeys, t) {
				weak = append(weak, "host key: "+t)
			}
		}
	}
	return weak
}

// ---- unauthenticated data services ----

var redisUnauth = Check{
	ID: "redis-unauth", Name: "Redis accessible without authentication", Family: "Misconfiguration",
	Needs: scriptNeeds("redis-info"),
	Run: func(e *Env) []Finding {
		return perHit(e, "redis-info", func(h ScriptHit) *Finding {
			if !strings.Contains(h.Output, "Version:") { // INFO only answers when unauthenticated
				return nil
			}
			return &Finding{
				Title: "Redis Server - Unauthenticated Access", Severity: "high",
				Synopsis:    "A Redis server answers commands without authentication.",
				Description: "Anyone who can reach this port can read and modify all data and, with common configurations, achieve code execution on the host.",
				Remediation: "Enable authentication (requirepass / ACLs), bind Redis to localhost or a private interface, and restrict access with a firewall.",
				Evidence:    firstLines(h.Output, 8),
			}
		})
	},
}

var memcachedOpen = Check{
	ID: "memcached-open", Name: "Memcached accessible without authentication", Family: "Misconfiguration",
	Needs: scriptNeeds("memcached-info"),
	Run: func(e *Env) []Finding {
		return perHit(e, "memcached-info", func(h ScriptHit) *Finding {
			low := strings.ToLower(h.Output)
			// memcached-info prints "Process ID", "Uptime" and server stats only when the
			// server answered `stats` without authentication.
			if !strings.Contains(low, "process id") && !strings.Contains(low, "uptime") && !strings.Contains(low, "version") {
				return nil
			}
			return &Finding{
				Title: "Memcached Server Accessible Without Authentication", Severity: "high",
				Synopsis:    "A memcached server answers to unauthenticated requests.",
				Description: "Exposed memcached leaks cached data and can be abused for amplification attacks.",
				Remediation: "Bind memcached to localhost or a private interface, enable SASL authentication, and filter the port at the firewall.",
				Evidence:    firstLines(h.Output, 8),
			}
		})
	},
}

var mongodbOpen = Check{
	ID: "mongodb-open", Name: "MongoDB accessible without authentication", Family: "Misconfiguration",
	Needs: scriptNeeds("mongodb-info"),
	Run: func(e *Env) []Finding {
		return perHit(e, "mongodb-info", func(h ScriptHit) *Finding {
			if !strings.Contains(h.Output, "MongoDB Build info") {
				return nil
			}
			return &Finding{
				Title: "MongoDB Server Accessible Without Authentication", Severity: "high",
				Synopsis:    "A MongoDB server returns server information without authentication.",
				Description: "Unauthenticated MongoDB access commonly exposes the full database to the network.",
				Remediation: "Enable authentication (security.authorization), bind to a private interface, and restrict access with a firewall.",
				Evidence:    firstLines(h.Output, 8),
			}
		})
	},
}

var x11Open = Check{
	ID: "x11-open", Name: "X11 server accepts connections", Family: "Misconfiguration",
	Needs: scriptNeeds("x11-access"),
	Run: func(e *Env) []Finding {
		return perHit(e, "x11-access", func(h ScriptHit) *Finding {
			if !strings.Contains(h.Output, "X server access is granted") {
				return nil
			}
			return &Finding{
				Title: "X11 Server Accepts Unauthenticated Connections", Severity: "critical",
				Synopsis:    "An X server grants access to remote clients without authentication.",
				Description: "Remote clients can capture the screen, log keystrokes and inject input.",
				Remediation: "Disable TCP listening in the X server (-nolisten tcp) or require MIT-MAGIC-COOKIE authentication.",
				Evidence:    firstLines(h.Output, 4),
			}
		})
	},
}

var vncNoAuth = Check{
	ID: "vnc-no-auth", Name: "VNC server without authentication", Family: "Misconfiguration",
	Needs: scriptNeeds("vnc-info"),
	Run: func(e *Env) []Finding {
		return perHit(e, "vnc-info", func(h ScriptHit) *Finding {
			if !regexp.MustCompile(`(?i)\bNone\b`).MatchString(h.Output) {
				return nil
			}
			return &Finding{
				Title: "VNC Server Allows Connections Without Authentication", Severity: "critical",
				Synopsis:    "The VNC server offers the 'None' security type.",
				Description: "Anyone who can reach the port gets full interactive control of the desktop.",
				Remediation: "Require VNC authentication or tunnel VNC through SSH/VPN and block direct access.",
				Evidence:    firstLines(h.Output, 8),
			}
		})
	},
}

// ---- file/name services ----

var ftpAnonymous = Check{
	ID: "ftp-anon", Name: "Anonymous FTP login allowed", Family: "Misconfiguration",
	Needs: scriptNeeds("ftp-anon"),
	Run: func(e *Env) []Finding {
		return perHit(e, "ftp-anon", func(h ScriptHit) *Finding {
			if !strings.Contains(h.Output, "Anonymous FTP login allowed") {
				return nil
			}
			return &Finding{
				Title: "Anonymous FTP Login Allowed", Severity: "medium",
				Synopsis:    "The FTP server accepts anonymous logins.",
				Description: "Anonymous users can list, and often download or upload, files.",
				Remediation: "Disable anonymous access unless it is required, and make any anonymous area read-only.",
				Evidence:    firstLines(h.Output, 10),
			}
		})
	},
}

var nfsExports = Check{
	ID: "nfs-exports", Name: "NFS exports visible", Family: "Misconfiguration",
	Needs: scriptNeeds("nfs-showmount"),
	Run: func(e *Env) []Finding {
		return perHit(e, "nfs-showmount", func(h ScriptHit) *Finding {
			return &Finding{
				Title: "NFS Exports Are Listed to Remote Hosts", Severity: "medium",
				Synopsis:    "The NFS server reveals its export list.",
				Description: "Exports may be mountable by untrusted hosts, exposing file systems.",
				Remediation: "Restrict exports to specific client hosts or networks and review export options (e.g. no_root_squash).",
				Evidence:    firstLines(h.Output, 12),
			}
		})
	},
}

var dnsRecursion = Check{
	ID: "dns-recursion", Name: "DNS server allows recursion", Family: "Misconfiguration",
	Needs: scriptNeeds("dns-recursion"),
	Run: func(e *Env) []Finding {
		return perHit(e, "dns-recursion", func(h ScriptHit) *Finding {
			if !strings.Contains(h.Output, "Recursion appears to be enabled") {
				return nil
			}
			return &Finding{
				Title: "DNS Server Allows Recursive Queries From Arbitrary Clients", Severity: "medium",
				Synopsis:    "An open resolver can be abused for amplification attacks and cache snooping.",
				Description: "The DNS server resolves names for any client that asks.",
				Remediation: "Restrict recursion to trusted networks (allow-recursion / access control).",
				Evidence:    firstLines(h.Output, 4),
			}
		})
	},
}

var snmpPublic = Check{
	ID: "snmp-public", Name: "SNMP answers to the public community", Family: "Misconfiguration",
	Needs: scriptNeeds("snmp-info"),
	Run: func(e *Env) []Finding {
		return perHit(e, "snmp-info", func(h ScriptHit) *Finding {
			return &Finding{
				Title: "SNMP Agent Responds to the Default 'public' Community String", Severity: "medium",
				Synopsis:    "System information is readable with a default community string.",
				Description: "SNMP v1/v2c community strings are passwords sent in clear text; the default exposes device details and, if writable, configuration.",
				Remediation: "Change the community strings, prefer SNMPv3, and restrict access to management hosts.",
				Evidence:    firstLines(h.Output, 8),
			}
		})
	},
}

var telnetService = Check{
	ID: "telnet-service", Name: "Telnet service present", Family: "Misconfiguration",
	Needs: func(e *Env) string {
		if !e.HasService("telnet") {
			return "no telnet service"
		}
		return ""
	},
	Run: func(e *Env) []Finding {
		var out []Finding
		for _, s := range e.Services {
			if strings.EqualFold(s.Name, "telnet") {
				out = append(out, Finding{Port: s.Port, Proto: s.Proto, Title: "Cleartext Telnet Service Is Running", Severity: "medium",
					Synopsis:    "Telnet transmits credentials and data without encryption.",
					Description: "Anyone able to observe the traffic can read passwords and session contents.",
					Remediation: "Disable Telnet and use SSH.", Evidence: fmt.Sprintf("telnet open on %d/%s", s.Port, s.Proto)})
			}
		}
		return out
	},
}

// ---- SMB ----

var smbSigning = Check{
	ID: "smb-signing", Name: "SMB signing not required", Family: "Misconfiguration",
	Needs: func(e *Env) string {
		if len(e.ScriptAnywhere("smb2-security-mode"))+len(e.ScriptAnywhere("smb-security-mode")) == 0 {
			return "no SMB security-mode result"
		}
		return ""
	},
	Run: func(e *Env) []Finding {
		var out []Finding
		for _, id := range []string{"smb2-security-mode", "smb-security-mode"} {
			out = append(out, perHit(e, id, func(h ScriptHit) *Finding {
				low := strings.ToLower(h.Output)
				if !strings.Contains(low, "not required") && !strings.Contains(low, "not enabled") && !strings.Contains(low, "disabled") {
					return nil
				}
				return &Finding{
					Title: "SMB Signing Not Required", Severity: "medium",
					Synopsis:    "The SMB server does not require message signing.",
					Description: "Without required signing an attacker positioned on the network can relay or tamper with SMB traffic (NTLM relay attacks).",
					Remediation: "Require SMB signing (Windows: 'Microsoft network server: Digitally sign communications (always)'; Samba: server signing = mandatory).",
					Evidence:    firstLines(h.Output, 6),
				}
			})...)
		}
		return out
	},
}

var smbv1 = Check{
	ID: "smbv1", Name: "SMBv1 enabled", Family: "Misconfiguration",
	Needs: scriptNeeds("smb-protocols"),
	Run: func(e *Env) []Finding {
		return perHit(e, "smb-protocols", func(h ScriptHit) *Finding {
			if !strings.Contains(h.Output, "NT LM 0.12") && !strings.Contains(strings.ToUpper(h.Output), "SMBV1") {
				return nil
			}
			return &Finding{
				Title: "SMBv1 Protocol Is Enabled", Severity: "high",
				Synopsis:    "The server supports the obsolete SMBv1 dialect.",
				Description: "SMBv1 has known critical weaknesses and was the vector for wormable attacks such as EternalBlue-class exploits.",
				Remediation: "Disable SMBv1 and require SMB 2.1 or later.",
				Evidence:    firstLines(h.Output, 8),
			}
		})
	},
}

// ---- HTTP ----

var httpTrace = Check{
	ID: "http-trace", Name: "HTTP TRACE enabled", Family: "Misconfiguration",
	Needs: scriptNeeds("http-methods"),
	Run: func(e *Env) []Finding {
		return perHit(e, "http-methods", func(h ScriptHit) *Finding {
			if !strings.Contains(h.Output, "TRACE") {
				return nil
			}
			return &Finding{
				Title: "HTTP TRACE Method Is Enabled", Severity: "low",
				Synopsis:    "The web server allows the HTTP TRACE method.",
				Description: "TRACE can aid cross-site tracing attacks that expose request headers such as cookies.",
				Remediation: "Disable TRACE (Apache: TraceEnable off; nginx does not enable it by default).",
				Evidence:    firstLines(h.Output, 4),
			}
		})
	},
}

// ---- TLS ----

var tlsWeakness = Check{
	ID: "tls-weakness", Name: "TLS configuration weaknesses", Family: "Misconfiguration",
	Needs: func(e *Env) string {
		if len(e.TLS) == 0 {
			return "no TLS services"
		}
		return ""
	},
	Run: func(e *Env) []Finding {
		var out []Finding
		for _, t := range e.TLS {
			issues, sev := TLSIssues(t.Weak, t.NotAfter, t.Subject, t.Issuer, e.Now)
			if len(issues) == 0 {
				continue
			}
			out = append(out, Finding{Port: t.Port, Proto: t.Proto, Title: "TLS Configuration Weaknesses", Severity: sev,
				Synopsis:    "The TLS service uses weak protocols, ciphers or certificate settings.",
				Description: "Weak TLS settings allow downgrade or decryption attacks and indicate poor certificate hygiene.",
				Remediation: "Disable SSLv2/SSLv3/TLS 1.0/1.1 and weak ciphers, use RSA 2048+ or ECDSA keys with SHA-256+, and renew expired certificates.",
				Evidence:    strings.Join(issues, "\n")})
		}
		return out
	},
}

// TLSIssues turns stored TLS facts into issue strings and a severity.
func TLSIssues(weak []string, notAfter, subject, issuer string, now time.Time) ([]string, string) {
	issues := append([]string(nil), weak...)
	sev := "low"
	for _, w := range weak {
		switch {
		case strings.Contains(w, "SSLv2") || strings.Contains(w, "SSLv3") || strings.Contains(w, "broken protocol"):
			sev = maxSev(sev, "high")
		case strings.Contains(w, "deprecated protocol") || strings.Contains(w, "weak cipher") || strings.Contains(w, "shorter than 2048"):
			sev = maxSev(sev, "medium")
		}
	}
	if notAfter != "" {
		if t, err := time.Parse("2006-01-02T15:04:05", notAfter); err == nil && t.Before(now) {
			issues = append(issues, "certificate expired on "+t.Format("2006-01-02"))
			sev = maxSev(sev, "medium")
		}
	}
	if subject != "" && subject == issuer {
		issues = append(issues, "certificate is self-signed")
	}
	sort.Strings(issues)
	return issues, sev
}

func maxSev(a, b string) string {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// ---- helpers ----

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = append(lines[:n], "…")
	}
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t")
	}
	return strings.Join(lines, "\n")
}

// Max returns the highest safety level of the given checks.
func Max(checks []Check) policy.Safety {
	m := policy.SafetyReadOnly
	for _, c := range checks {
		if c.Safety > m {
			m = c.Safety
		}
	}
	return m
}
