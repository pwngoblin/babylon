// Package model holds Babylon's engine-independent domain types.
package model

// Host is one scanned host as observed in a single scan.
type Host struct {
	Address   string // canonical IP
	Hostnames []string
	MAC       string
	Vendor    string
	State     string // up | down
	Reason    string
	OS        *OSGuess
	Ports     []Port
}

// OSGuess is Nmap's best operating-system match.
type OSGuess struct {
	Name     string
	Family   string // linux | windows | macos | other (normalized)
	Accuracy int
	CPE      string
}

// Port is a port observation with its detected service.
type Port struct {
	Number  int
	Proto   string // tcp | udp
	State   string // open | closed | filtered | open|filtered ...
	Service Service
	Scripts []Script
	TLS     *TLS
}

type Service struct {
	Name      string
	Product   string
	Version   string
	ExtraInfo string
	Tunnel    string // "ssl" when TLS-wrapped
	CPEs      []string
	Banner    string
}

// Script is a raw NSE result.
type Script struct {
	ID     string
	Output string
}

// TLS summarizes certificate and protocol/cipher audit for a port.
type TLS struct {
	Subject   string
	Issuer    string
	NotBefore string
	NotAfter  string
	SigAlgo   string
	KeyType   string
	KeyBits   int
	SANs      []string
	Protocols []TLSProtocol
	Weak      []string // human-readable weakness notes
}

type TLSProtocol struct {
	Name          string // e.g. TLSv1.2
	Ciphers       []TLSCipher
	LeastStrength string // nmap grade A-F
}

type TLSCipher struct {
	Name     string
	Strength string
}

// Finding is the normalized, engine-independent vulnerability record
// (Nessus-style schema).
type Finding struct {
	Fingerprint string // stable identity across scans and engines
	Address     string // asset IP
	Port        int    // 0 = host-level
	Proto       string // tcp | udp | ""
	Title       string
	Family      string
	Severity    string // info | low | medium | high | critical
	CVSS        *float64
	CVSSVector  string
	CVEs        []string
	EPSS        *float64
	Synopsis    string
	Description string
	Remediation string
	Solution    string // VendorFix | Mitigation | Workaround | WillNotFix | ""
	Confidence  string // tentative | firm | confirmed
	Detection   string // behaviour | version | config
	Engine      string // nuclei | native | cpematch | nmap | audit
	EngineRef   string // template id / check id
	Evidence    string // redacted, size-capped
	RawRef      string
}

// Confidence levels, ordered weakest to strongest.
const (
	ConfTentative = "tentative"
	ConfFirm      = "firm"
	ConfConfirmed = "confirmed"
)

// ConfidenceRank orders confidence levels (higher = stronger).
func ConfidenceRank(c string) int {
	switch c {
	case ConfConfirmed:
		return 3
	case ConfFirm:
		return 2
	case ConfTentative:
		return 1
	}
	return 0
}

// SeverityRank orders severities (higher = worse).
func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}
