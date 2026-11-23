package native

import (
	"fmt"
	"strings"

	"babylon/internal/winrel"
)

// Windows infrastructure checks over data Nmap already collected (SMB OS
// discovery, RDP negotiation, the MS17-010 protocol check). They read results
// only; no check here logs in or sends anything itself.

var windowsEOL = Check{
	ID: "windows-eol", Name: "Windows version is out of support", Family: "Unsupported software",
	Needs: scriptNeeds("smb-os-discovery"),
	Run: func(e *Env) []Finding {
		return perHit(e, "smb-os-discovery", func(h ScriptHit) *Finding {
			os, rel := winrel.FromSMB(h.Output)
			if rel == nil || !rel.EOL.Before(e.Now) {
				return nil
			}
			sev := "high"
			if rel.Name == "Windows 10" {
				sev = "medium" // ESU may apply
			}
			return &Finding{
				Title: "Unsupported Windows Version: " + rel.Name, Severity: sev,
				Synopsis:    "The host runs a Windows version that no longer receives security updates.",
				Description: fmt.Sprintf("%s reached end of support on %s. New vulnerabilities are not fixed, so the host is exposed to every flaw published since.%s", rel.Name, rel.EOL.Format("2006-01-02"), rel.Note),
				Remediation: "Upgrade to a supported Windows release. Until then, isolate the host from untrusted networks.",
				Evidence:    "SMB advertised: " + os, Detection: "version", Confidence: "firm",
			}
		})
	},
}

var ms17010 = Check{
	ID: "smb-ms17-010", Name: "MS17-010 (EternalBlue) missing patch", Family: "Missing patch",
	Needs: scriptNeeds("smb-vuln-ms17-010"),
	Run: func(e *Env) []Finding {
		return perHit(e, "smb-vuln-ms17-010", func(h ScriptHit) *Finding {
			up := strings.ToUpper(h.Output)
			if !strings.Contains(up, "STATE: VULNERABLE") || strings.Contains(up, "NOT VULNERABLE") {
				return nil
			}
			cvss := 8.1
			return &Finding{
				Title: "MS17-010: SMBv1 Remote Code Execution (EternalBlue)", Severity: "critical", CVSS: &cvss,
				CVEs:        []string{"CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146", "CVE-2017-0148"},
				Synopsis:    "The SMB server is missing the MS17-010 security update.",
				Description: "Unpatched SMBv1 allows unauthenticated remote code execution. It was used by WannaCry and NotPetya and is still widely exploited.",
				Remediation: "Install the MS17-010 security update (or any later cumulative update) and disable SMBv1.",
				Evidence:    firstLines(h.Output, 10), Detection: "behaviour",
			}
		})
	},
}

var rdpSecurity = Check{
	ID: "rdp-security-layer", Name: "RDP security configuration", Family: "Misconfiguration",
	Needs: scriptNeeds("rdp-enum-encryption"),
	Run: func(e *Env) []Finding {
		return perHit(e, "rdp-enum-encryption", func(h ScriptHit) *Finding {
			nla := strings.Contains(h.Output, "CredSSP (NLA): SUCCESS")
			native := strings.Contains(h.Output, "Native RDP: SUCCESS")
			ssl := strings.Contains(h.Output, "SSL: SUCCESS")
			switch {
			case native:
				return &Finding{
					Title: "RDP Accepts Legacy RDP Security (No TLS)", Severity: "high",
					Synopsis:    "The Remote Desktop service accepts the old, weaker RDP security layer.",
					Description: "Classic RDP security encrypts with RC4 and does not authenticate the server, which makes man-in-the-middle attacks and credential capture practical.",
					Remediation: "Set the RDP security layer to 'SSL (TLS 1.0)' or negotiate, and require Network Level Authentication (NLA).",
					Evidence:    firstLines(h.Output, 12),
				}
			case !nla && ssl:
				return &Finding{
					Title: "RDP Does Not Require Network Level Authentication", Severity: "medium",
					Synopsis:    "Remote Desktop shows a login screen before the user is authenticated.",
					Description: "Without NLA the server spends resources on unauthenticated sessions and exposes the pre-authentication attack surface (BlueKeep-class flaws, brute forcing).",
					Remediation: "Enable 'Require user authentication for remote connections by using Network Level Authentication'.",
					Evidence:    firstLines(h.Output, 12),
				}
			}
			return nil
		})
	},
}

var winrmCleartext = Check{
	ID: "winrm-http", Name: "WinRM exposed over HTTP", Family: "Misconfiguration",
	Needs: func(e *Env) string {
		if len(openPort(e, []int{5985})) == 0 {
			return "WinRM HTTP port 5985 not open"
		}
		return ""
	},
	Run: func(e *Env) []Finding {
		var out []Finding
		for _, s := range openPort(e, []int{5985}) {
			out = append(out, Finding{Port: s.Port, Proto: "tcp", Title: "WinRM Management Service Reachable Over HTTP", Severity: "low",
				Synopsis:    "Windows Remote Management is listening on its unencrypted HTTP port.",
				Description: "WinRM over HTTP relies on message-level encryption that depends on the authentication method; with Basic authentication enabled, credentials cross the network in clear text. The service is also a remote administration surface.",
				Remediation: "Use WinRM over HTTPS (5986), disable Basic and unencrypted traffic, and limit the port to management hosts with a firewall.",
				Evidence:    "port 5985/tcp open", Detection: "config", Confidence: "firm"})
		}
		return out
	},
}

func windowsChecks() []Check { return []Check{windowsEOL, ms17010, rdpSecurity, winrmCleartext} }
