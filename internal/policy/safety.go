package policy

import (
	"fmt"
	"sort"
	"strings"
)

// This file is the single source of truth for what engines may run. Engine
// adapters never accept user-supplied tags/scripts; they take a Resolved config
// built here and re-validated by Validate. Denied entries must be unreachable.

// Nmap NSE categories.
var (
	// DeniedNSECategories can never appear in a script expression.
	DeniedNSECategories = []string{"intrusive", "dos", "exploit", "brute", "fuzzer", "malware", "external"}

	// baseNSECategories are always allowed (read-only discovery).
	baseNSECategories = []string{"default", "safe"}

	// namedNSEScripts is the curated, exact-name allowlist. Each entry has a
	// written reason. All are read-only banner/configuration queries; the only
	// "intrusive"-tagged one (ssl-enum-ciphers) is a documented exception:
	// nmap tags it for handshake volume, not impact. A test verifies these
	// against nmap's own category data so the list cannot drift unsafe.
	namedNSEScripts = map[string]string{
		"banner":              "reads the service greeting",
		"ssl-cert":            "reads the server certificate",
		"ssl-enum-ciphers":    "enumerates protocols/ciphers via handshakes (tagged intrusive by nmap for volume, not impact)",
		"ssh2-enum-algos":     "lists SSH algorithms offered (weak-algorithm checks)",
		"ssh-hostkey":         "reads SSH host key fingerprints",
		"redis-info":          "reads INFO; succeeds only without authentication (unauthenticated Redis)",
		"ftp-anon":            "tests anonymous FTP login (a read-only login attempt)",
		"ftp-syst":            "asks FTP SYST/STAT",
		"smb-protocols":       "lists dialects the SMB server supports (SMBv1 detection)",
		"smb2-security-mode":  "reads SMB2 signing configuration",
		"smb-security-mode":   "reads SMB signing/authentication configuration",
		"smb-os-discovery":    "reads OS information advertised over SMB",
		"smb2-capabilities":   "reads SMB2 capabilities",
		"rdp-ntlm-info":       "reads NTLM info advertised during RDP negotiation",
		"http-title":          "reads the page title",
		"http-methods":        "reads allowed HTTP methods via OPTIONS",
		"mysql-info":          "reads the MySQL handshake banner",
		"ms-sql-info":         "reads SQL Server instance info",
		"dns-recursion":       "checks whether a DNS server recurses for arbitrary queries",
		"ntp-info":            "reads NTP server info",
		"snmp-info":           "reads SNMP system info (v1/v2c public community only)",
		"telnet-ntlm-info":    "reads NTLM info from a Telnet service",
		"vnc-info":            "reads VNC protocol/security types",
		"mongodb-info":        "reads MongoDB server info (shows unauthenticated access)",
		"memcached-info":      "reads memcached stats (shows unauthenticated access)",
		"rtsp-methods":        "reads supported RTSP methods",
		"imap-capabilities":   "reads IMAP CAPABILITY",
		"pop3-capabilities":   "reads POP3 CAPA",
		"smtp-commands":       "reads SMTP EHLO capabilities",
		"nfs-showmount":       "lists NFS exports (read-only)",
		"rpcinfo":             "queries the RPC portmapper",
		"ldap-rootdse":        "reads the LDAP root DSE (anonymous, read-only)",
		"x11-access":          "checks whether an X11 server accepts connections",
		"rdp-enum-encryption": "lists the RDP security layers and encryption levels a server accepts (NLA check); nmap category safe",
		"smb-vuln-ms17-010":   "detects the MS17-010 (EternalBlue) flaw by a protocol check without exploiting it; nmap categories vuln,safe",
	}

	// vulnNSEScripts is the curated subset of `vuln` scripts. Each entry is only
	// run when Nmap identified a matching product (see NSEGuards), because the
	// spike showed blanket `vuln` produces false positives
	// (e.g. http-vuln-cve2011-3192 flagging nginx).
	vulnNSEScripts = map[string][]string{
		// script name -> product substrings (lowercase) that justify running it
		"http-vuln-cve2011-3192": {"apache"},
		"ssl-heartbleed":         {"openssl", "ssl", "https"},
		"ssl-poodle":             {"ssl", "https"},
		"ssl-dh-params":          {"ssl", "https"},
	}
)

// Nuclei.
var (
	// DeniedNucleiTags are excluded from every run (-etags).
	DeniedNucleiTags = []string{"dos", "fuzz", "fuzzing", "intrusive", "bruteforce", "kev-bruteforce", "oast", "rce-exploit"}

	// DefaultLoginTags are denied unless CheckDefaultCreds is set.
	DefaultLoginTags = []string{"default-login", "default-logins"}

	// DeniedNucleiProtocols are excluded via -exclude-type.
	DeniedNucleiProtocols = []string{"headless", "code", "javascript"}
)

// Native check safety levels, ordered.
type Safety int

const (
	SafetyReadOnly  Safety = iota // banner/version/config reads
	SafetyProbe                   // active but non-destructive probes
	SafetyIntrusive               // never loadable
)

func (s Safety) String() string {
	switch s {
	case SafetyReadOnly:
		return "read-only"
	case SafetyProbe:
		return "probe"
	default:
		return "intrusive"
	}
}

// NSEConfig is what the Nmap adapter is allowed to run.
type NSEConfig struct {
	Categories []string            // allowed categories
	Named      []string            // exact-name scripts from namedNSEScripts (e.g. TLS audit)
	Scripts    map[string][]string // curated vuln scripts → product guards
}

// NucleiConfig is what the Nuclei adapter is allowed to run.
type NucleiConfig struct {
	Enabled          bool
	ExcludeTags      []string
	ExcludeProtocols []string
	IncludeDefault   bool // default-login templates enabled
}

// NativeConfig bounds native checks.
type NativeConfig struct {
	Enabled   bool
	MaxSafety Safety
}

// Validate re-checks a resolved config against the deny tables. It is called by
// Resolve and again by each adapter; the redundancy is deliberate.
func (n NSEConfig) Validate() error {
	for _, c := range n.Categories {
		if contains(DeniedNSECategories, c) {
			return fmt.Errorf("denied NSE category %q in config", c)
		}
	}
	for _, s := range n.Named {
		if _, ok := namedNSEScripts[s]; !ok {
			return fmt.Errorf("NSE script %q is not in the named allowlist", s)
		}
	}
	for s := range n.Scripts {
		if _, ok := vulnNSEScripts[s]; !ok {
			return fmt.Errorf("NSE script %q is not in the curated allowlist", s)
		}
	}
	return nil
}

func (n NucleiConfig) Validate() error {
	if !n.Enabled {
		return nil
	}
	for _, want := range DeniedNucleiTags {
		if !contains(n.ExcludeTags, want) {
			return fmt.Errorf("nuclei config missing mandatory exclusion %q", want)
		}
	}
	if !n.IncludeDefault {
		for _, want := range DefaultLoginTags {
			if !contains(n.ExcludeTags, want) {
				return fmt.Errorf("nuclei default-login tag %q must be excluded without --check-default-creds", want)
			}
		}
	}
	for _, want := range DeniedNucleiProtocols {
		if !contains(n.ExcludeProtocols, want) {
			return fmt.Errorf("nuclei config missing mandatory protocol exclusion %q", want)
		}
	}
	return nil
}

func (n NativeConfig) Validate() error {
	if n.Enabled && n.MaxSafety >= SafetyIntrusive {
		return fmt.Errorf("native checks cannot allow %s level", n.MaxSafety)
	}
	return nil
}

// ScriptExpr builds the --script expression. Categories are joined with `or`;
// denied categories are always subtracted. Curated scripts are named explicitly
// by the adapter only for services whose product matches their guard.
func (n NSEConfig) ScriptExpr() (string, error) {
	if err := n.Validate(); err != nil {
		return "", err
	}
	var parts []string
	if len(n.Categories) > 0 {
		cats := append([]string(nil), n.Categories...)
		sort.Strings(cats)
		parts = append(parts, "("+strings.Join(cats, " or ")+") and not ("+strings.Join(DeniedNSECategories, " or ")+")")
	}
	// Named scripts are individually allowlisted, so they are exempt from the
	// category subtraction; they are appended as comma-separated expressions.
	named := append([]string(nil), n.Named...)
	sort.Strings(named)
	parts = append(parts, named...)
	if len(parts) == 0 {
		return "", fmt.Errorf("no NSE scripts configured")
	}
	return strings.Join(parts, ","), nil
}

// CuratedNSEScripts returns the named allowlist in stable order.
func CuratedNSEScripts() []string {
	out := make([]string, 0, len(namedNSEScripts))
	for k := range namedNSEScripts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NamedNSEReason explains why a named script is allowed ("" if it is not).
func NamedNSEReason(name string) string { return namedNSEScripts[name] }

// ScriptsForProduct returns curated scripts whose guard matches product.
func (n NSEConfig) ScriptsForProduct(product string) []string {
	var out []string
	p := strings.ToLower(product)
	for s, guards := range n.Scripts {
		for _, g := range guards {
			if strings.Contains(p, g) {
				out = append(out, s)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
