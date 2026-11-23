// Package compliance turns what a scan already recorded (which checks ran,
// which produced findings) into a per-control report. The mapping from checks
// to controls is Babylon's own, at control level, and is an evidence aid for an
// assessor, not an assessment: it is not an official CIS, PCI SSC or ISO mapping
// and does not copy benchmark text.
package compliance

import (
	"sort"
	"strings"
)

// Framework identifiers accepted by --compliance.
const (
	NIST = "nist-800-53"
	PCI  = "pci-dss-4"
	ISO  = "iso-27001"
)

var prefix = map[string]string{NIST: "NIST-800-53:", PCI: "PCI-DSS-4:", ISO: "ISO-27001:"}

// Frameworks lists the supported framework ids.
func Frameworks() []string { return []string{NIST, PCI, ISO} }

// FrameworkTitle is the display name.
func FrameworkTitle(f string) string {
	switch f {
	case NIST:
		return "NIST SP 800-53 Rev. 5"
	case PCI:
		return "PCI DSS v4.0"
	case ISO:
		return "ISO/IEC 27001:2022 Annex A"
	}
	return f
}

// crosswalk maps a NIST control to the PCI DSS 4.0 requirement and ISO 27001
// Annex A control that cover the same ground, as a coarse approximation.
var crosswalk = map[string][]string{
	"AC-2":  {"PCI-DSS-4:8.2.2", "ISO-27001:A.5.18"},
	"AC-3":  {"PCI-DSS-4:7.2.1", "ISO-27001:A.5.15"},
	"AC-6":  {"PCI-DSS-4:7.2.2", "ISO-27001:A.8.2"},
	"AC-7":  {"PCI-DSS-4:8.3.4", "ISO-27001:A.8.5"},
	"AC-12": {"PCI-DSS-4:8.2.8", "ISO-27001:A.8.5"},
	"AC-17": {"ISO-27001:A.8.20"},
	"AU-2":  {"PCI-DSS-4:10.2.1", "ISO-27001:A.8.15"},
	"AU-8":  {"PCI-DSS-4:10.6.1", "ISO-27001:A.8.17"},
	"AU-12": {"PCI-DSS-4:10.2.1", "ISO-27001:A.8.15"},
	"CM-6":  {"PCI-DSS-4:2.2.1", "ISO-27001:A.8.9"},
	"CM-7":  {"PCI-DSS-4:2.2.4", "ISO-27001:A.8.9"},
	"CM-11": {"ISO-27001:A.8.19"},
	"IA-2":  {"PCI-DSS-4:8.3.1", "ISO-27001:A.8.5"},
	"IA-5":  {"PCI-DSS-4:8.3.6", "ISO-27001:A.5.17"},
	"SA-22": {"PCI-DSS-4:6.3.2", "ISO-27001:A.8.8"},
	"SC-7":  {"PCI-DSS-4:1.4.1", "ISO-27001:A.8.20"},
	"SC-8":  {"PCI-DSS-4:4.2.1", "ISO-27001:A.8.24"},
	"SC-13": {"PCI-DSS-4:4.2.1", "ISO-27001:A.8.24"},
	"SC-28": {"PCI-DSS-4:3.5.1", "ISO-27001:A.8.24"},
	"SI-2":  {"PCI-DSS-4:6.3.3", "ISO-27001:A.8.8"},
	"SI-3":  {"PCI-DSS-4:5.2.1", "ISO-27001:A.8.7"},
	"SI-7":  {"PCI-DSS-4:11.5.2", "ISO-27001:A.8.9"},
}

// builtin maps the Go checks and audit rules to NIST controls (an entry that
// already has a framework prefix is a direct mapping where the crosswalk is too coarse). Pack checks carry
// their own controls: in YAML.
var builtin = map[string][]string{
	// network and service checks
	"consul-api-open": {"AC-3", "CM-7"}, "couchdb-open": {"AC-3"}, "dns-recursion": {"CM-7"},
	"docker-api-open": {"AC-3", "CM-7"}, "docker-registry-open": {"AC-3"}, "elasticsearch-open": {"AC-3"},
	"epmd-exposed": {"AC-3", "CM-7"}, "etcd-open": {"AC-3"}, "ftp-anon": {"AC-3"}, "http-hsts-missing": {"SC-8"},
	"http-trace": {"CM-7"}, "ipmi-cipher-zero": {"IA-2"}, "jupyter-open": {"AC-3"}, "k8s-api-anonymous": {"AC-3"},
	"kibana-open": {"AC-3"}, "kubelet-api-open": {"AC-3"}, "kubelet-ro-open": {"AC-3"}, "ldap-anonymous": {"AC-3"},
	"memcached-open": {"AC-3", "SC-7"}, "mongodb-open": {"AC-3"}, "mqtt-anonymous": {"AC-3"},
	"mysql-probe": {"SC-8", "SA-22"}, "nfs-exports": {"AC-3", "CM-7"}, "ntp-mode6": {"CM-7"},
	"postgres-tls-probe": {"SC-8"}, "prometheus-open": {"AC-3", "CM-7"}, "rdp-security-layer": {"IA-2", "SC-8"},
	"redis-unauth": {"AC-3"}, "rsync-modules-open": {"AC-3"}, "smb-ms17-010": {"SI-2"}, "smb-signing": {"SC-8"},
	"smbv1": {"CM-7", "SC-8"}, "snmp-public": {"AC-3", "PCI-DSS-4:2.2.2"}, "snmp-public-probe": {"AC-3", "PCI-DSS-4:2.2.2"},
	"solr-admin-open": {"AC-3"}, "ssh-weak-algorithms": {"SC-13", "SC-8"}, "telnet-service": {"CM-7", "SC-8"},
	"tftp-open": {"AC-3", "CM-7"}, "tls-probe": {"SC-8", "SC-13"}, "tls-weakness": {"SC-8", "SC-13"},
	"vnc-no-auth": {"IA-2", "AC-3"}, "windows-eol": {"SA-22", "SI-2"}, "winrm-http": {"SC-8"},
	"x11-open": {"AC-3"}, "yarn-rm-open": {"AC-3"}, "zookeeper-open": {"AC-3"},
	// patch and version audits
	"cpe-version-match": {"SI-2"}, "ssh-package-audit": {"SI-2"}, "macos-patch-audit": {"SI-2"}, "winrm-patch-audit": {"SI-2"},
	// Linux hardening
	"ACC-001": {"AC-2", "AC-6"}, "ACC-002": {"IA-5"}, "ACC-003": {"IA-5"}, "ACC-004": {"AC-2", "AC-6"},
	"SVC-001": {"CM-7", "SC-7"}, "SVC-002": {"CM-7"}, "FS-001": {"CM-6"}, "PERM-001": {"AC-3", "CM-6"},
	"PERM-002": {"AC-3", "CM-6"}, "NET-001": {"SC-7", "CM-6"}, "KERN-001": {"CM-6", "SI-16"}, "KERN-002": {"SI-16"},
	"SSH-001": {"AC-6", "AC-17"}, "SSH-002": {"SC-13"}, "SSH-003": {"IA-5"}, "SSH-004": {"CM-7"}, "SSH-005": {"AC-7"},
	"SSH-006": {"IA-2", "AC-17"}, "SSH-007": {"AC-12"}, "LOG-001": {"AU-2", "AU-12"}, "TIME-001": {"AU-8"},
	"UPD-001": {"SI-2"}, "FW-001": {"SC-7"},
	"DOCKER-001": {"AC-6", "SC-39"}, "DOCKER-002": {"AC-6"}, "DOCKER-003": {"SC-39"}, "DOCKER-004": {"AC-6"}, "DOCKER-005": {"AC-6"},
	// databases
	"PG-001": {"SC-8"}, "PG-002": {"IA-5"}, "PG-003": {"IA-2", "AC-3"}, "PG-004": {"SC-7", "AC-3"}, "PG-005": {"AC-6"},
	"PG-006": {"AU-2"}, "PG-007": {"IA-5"}, "PG-008": {"IA-2"},
	"MY-001": {"SC-8"}, "MY-002": {"AC-2"}, "MY-003": {"IA-5"}, "MY-004": {"AC-6"}, "MY-005": {"CM-7"}, "MY-006": {"CM-7"}, "MY-007": {"CM-6"},
	// macOS
	"MAC-001": {"CM-6", "SI-7"}, "MAC-002": {"CM-11"}, "MAC-003": {"SC-28"}, "MAC-004": {"SC-7"}, "MAC-005": {"SC-7"},
	"MAC-006": {"SI-2"}, "MAC-007": {"SI-2"}, "MAC-008": {"AC-2"}, "MAC-009": {"AC-2", "IA-2"},
	// Windows
	"WIN-001": {"CM-7"}, "WIN-002": {"SC-8"}, "WIN-003": {"SC-7"}, "WIN-004": {"SI-3"}, "WIN-005": {"SI-3"},
	"WIN-006": {"IA-2", "SC-8"}, "WIN-007": {"AC-6"}, "WIN-008": {"IA-5", "SC-28"}, "WIN-009": {"IA-5", "SC-13"},
	"WIN-010": {"AC-2"}, "WIN-011": {"IA-5"}, "WIN-012": {"AC-6"}, "WIN-013": {"CM-7", "SC-8"}, "WIN-014": {"SI-2"},
	"WIN-015": {"SA-22", "SI-2"},
}

// Registry maps check id -> full control list ("FRAMEWORK:id"), with the
// PCI/ISO crosswalk applied to every NIST control. packControls are the
// controls: lists from check packs (already "FRAMEWORK:id").
func Registry(packControls map[string][]string) map[string][]string {
	reg := map[string][]string{}
	add := func(id string, ctl ...string) {
		set := map[string]bool{}
		for _, c := range reg[id] {
			set[c] = true
		}
		for _, c := range ctl {
			set[c] = true
			if strings.HasPrefix(c, prefix[NIST]) {
				for _, x := range crosswalk[strings.TrimPrefix(c, prefix[NIST])] {
					set[x] = true
				}
			}
		}
		out := make([]string, 0, len(set))
		for c := range set {
			out = append(out, c)
		}
		sort.Strings(out)
		reg[id] = out
	}
	for id, nist := range builtin {
		ctl := make([]string, len(nist))
		for i, n := range nist {
			ctl[i] = prefix[NIST] + n
			if strings.Contains(n, ":") { // a direct non-NIST mapping, used as written
				ctl[i] = n
			}
		}
		add(id, ctl...)
	}
	for id, ctl := range packControls {
		add(id, ctl...)
	}
	return reg
}

// CheckForFinding returns the check id a finding's engine reference belongs to,
// so a finding can be attributed to the control checks that produced it.
func CheckForFinding(engine, ref string) string {
	switch {
	case engine == "audit" && strings.HasPrefix(ref, "osv:"):
		return "ssh-package-audit"
	case engine == "audit" && strings.HasPrefix(ref, "apple:"), engine == "audit" && ref == "macos-eol":
		return "macos-patch-audit"
	case engine == "audit" && strings.HasPrefix(ref, "msrc:"):
		return "winrm-patch-audit"
	case engine == "cpematch":
		return "cpe-version-match"
	}
	return ref
}

var titles = map[string]string{
	"NIST-800-53:AC-2": "Account Management", "NIST-800-53:AC-3": "Access Enforcement", "NIST-800-53:AC-6": "Least Privilege",
	"NIST-800-53:AC-7": "Unsuccessful Logon Attempts", "NIST-800-53:AC-12": "Session Termination", "NIST-800-53:AC-14": "Permitted Actions Without Identification or Authentication",
	"NIST-800-53:AC-17": "Remote Access", "NIST-800-53:AU-2": "Event Logging", "NIST-800-53:AU-8": "Time Stamps",
	"NIST-800-53:AU-12": "Audit Record Generation", "NIST-800-53:CM-6": "Configuration Settings", "NIST-800-53:CM-7": "Least Functionality",
	"NIST-800-53:CM-11": "User-Installed Software", "NIST-800-53:IA-2": "Identification and Authentication (Users)",
	"NIST-800-53:IA-5": "Authenticator Management", "NIST-800-53:SA-12": "Supply Chain Protection", "NIST-800-53:SA-22": "Unsupported System Components",
	"NIST-800-53:SC-5": "Denial-of-Service Protection", "NIST-800-53:SC-7": "Boundary Protection", "NIST-800-53:SC-8": "Transmission Confidentiality and Integrity",
	"NIST-800-53:SC-13": "Cryptographic Protection", "NIST-800-53:SC-28": "Protection of Information at Rest", "NIST-800-53:SC-39": "Process Isolation",
	"NIST-800-53:SI-2": "Flaw Remediation", "NIST-800-53:SI-3": "Malicious Code Protection", "NIST-800-53:SI-7": "Software, Firmware, and Information Integrity",
	"NIST-800-53:SI-16": "Memory Protection",
	"PCI-DSS-4:1.4.1":   "Network controls between trusted and untrusted networks", "PCI-DSS-4:2.2.1": "Configuration standards are developed and applied",
	"PCI-DSS-4:2.2.4": "Only necessary services, protocols and functions are enabled", "PCI-DSS-4:3.5.1": "Stored account data is rendered unreadable",
	"PCI-DSS-4:4.2.1": "Strong cryptography protects data in transit", "PCI-DSS-4:5.2.1": "Anti-malware solution deployed",
	"PCI-DSS-4:6.3.2": "Inventory of bespoke and third-party software components", "PCI-DSS-4:6.3.3": "Security patches installed in a defined time",
	"PCI-DSS-4:7.2.1": "Access control model defined", "PCI-DSS-4:7.2.2": "Access assigned on least privilege", "PCI-DSS-4:8.2.2": "Shared or generic accounts controlled",
	"PCI-DSS-4:8.2.8": "Idle sessions are terminated", "PCI-DSS-4:8.3.4": "Invalid authentication attempts are limited", "PCI-DSS-4:8.3.6": "Password complexity and length",
	"PCI-DSS-4:8.3.1": "All user access is authenticated with at least one factor", "PCI-DSS-4:2.2.2": "Vendor default accounts are managed", "PCI-DSS-4:10.2.1": "Audit logs are enabled and active", "PCI-DSS-4:10.6.1": "System clocks are synchronized",
	"PCI-DSS-4:11.5.2": "Change-detection mechanism for critical files",
	"ISO-27001:A.5.15": "Access control", "ISO-27001:A.5.17": "Authentication information", "ISO-27001:A.5.18": "Access rights",
	"ISO-27001:A.8.2": "Privileged access rights", "ISO-27001:A.8.5": "Secure authentication", "ISO-27001:A.8.7": "Protection against malware",
	"ISO-27001:A.8.8": "Management of technical vulnerabilities", "ISO-27001:A.8.9": "Configuration management", "ISO-27001:A.8.15": "Logging",
	"ISO-27001:A.8.17": "Clock synchronization", "ISO-27001:A.8.19": "Installation of software on operational systems", "ISO-27001:A.8.20": "Networks security",
	"ISO-27001:A.8.24": "Use of cryptography",
}

// Title returns the display name for a control id ("" when unknown).
func Title(control string) string { return titles[control] }
