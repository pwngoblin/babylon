package native

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"babylon/internal/policy"
	"babylon/internal/store"
)

// Direct TLS probe: one ClientHello per protocol version (TLS 1.0 to 1.3), then
// a look at the certificate the server presents. This is what any browser does;
// no application data is sent. It complements Nmap's ssl-enum-ciphers by working
// without NSE and by checking things Nmap's output does not give us directly.

var tlsVersions = []struct {
	id   uint16
	name string
}{
	{tls.VersionTLS10, "TLS 1.0"}, {tls.VersionTLS11, "TLS 1.1"}, {tls.VersionTLS12, "TLS 1.2"}, {tls.VersionTLS13, "TLS 1.3"},
}

// TLSFacts is what the probe learned about one endpoint.
type TLSFacts struct {
	Versions []string // supported protocol versions, oldest first
	Cert     *x509.Certificate
}

func probeTLS(addr string) (TLSFacts, bool) {
	var f TLSFacts
	for _, v := range tlsVersions {
		d := &net.Dialer{Timeout: 4 * time.Second}
		conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
			MinVersion: v.id, MaxVersion: v.id, InsecureSkipVerify: true, //nolint:gosec // we inspect, not trust
		})
		if err != nil {
			continue
		}
		f.Versions = append(f.Versions, v.name)
		if st := conn.ConnectionState(); f.Cert == nil && len(st.PeerCertificates) > 0 {
			f.Cert = st.PeerCertificates[0]
		}
		conn.Close()
	}
	return f, len(f.Versions) > 0
}

func weakSigAlg(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		return true
	}
	return false
}

// tlsFindings turns probe facts into findings. now is injectable for tests.
func tlsFindings(port int, f TLSFacts, now time.Time) []Finding {
	var out []Finding
	mk := func(title, sev, syn, desc, fix, ev string) {
		out = append(out, Finding{Port: port, Proto: "tcp", Title: title, Severity: sev, Synopsis: syn, Description: desc, Remediation: fix, Evidence: ev})
	}
	has := func(n string) bool {
		for _, v := range f.Versions {
			if v == n {
				return true
			}
		}
		return false
	}
	if has("TLS 1.0") || has("TLS 1.1") {
		mk("Deprecated TLS Protocol Versions Enabled", "medium",
			"The server still negotiates TLS 1.0 or 1.1.",
			"TLS 1.0 and 1.1 were deprecated by RFC 8996 and fail PCI DSS. They rely on weak constructions and expose clients to downgrade and decryption attacks.",
			"Disable TLS 1.0 and 1.1; allow TLS 1.2 and 1.3 only.",
			"accepted: "+strings.Join(f.Versions, ", "))
	}
	if !has("TLS 1.2") && !has("TLS 1.3") {
		mk("No Modern TLS Version Supported", "high",
			"The server does not offer TLS 1.2 or 1.3.",
			"Current browsers and clients refuse older protocol versions, and the connection offers weak protection.",
			"Enable TLS 1.2 and 1.3.", "accepted: "+strings.Join(f.Versions, ", "))
	}
	if c := f.Cert; c != nil {
		subject := c.Subject.CommonName
		if now.Before(c.NotAfter) && c.NotAfter.Sub(now) < 30*24*time.Hour {
			days := int(c.NotAfter.Sub(now).Hours() / 24)
			mk("TLS Certificate Expires Soon", "low",
				"The server certificate expires within 30 days.",
				"When the certificate expires, clients will show security errors or refuse to connect.",
				"Renew the certificate and automate renewal (for example ACME).",
				fmt.Sprintf("subject %q expires %s (%d days)", subject, c.NotAfter.Format("2006-01-02"), days))
		}
		if weakSigAlg(c.SignatureAlgorithm) {
			mk("TLS Certificate Signed With a Weak Hash", "medium",
				"The certificate signature uses MD5 or SHA-1.",
				"Collision attacks make SHA-1 and MD5 signatures forgeable; browsers reject such certificates.",
				"Reissue the certificate with SHA-256 or stronger.",
				fmt.Sprintf("subject %q signature algorithm %s", subject, c.SignatureAlgorithm))
		}
		if k, ok := c.PublicKey.(interface{ Size() int }); ok && c.PublicKeyAlgorithm == x509.RSA && k.Size()*8 < 2048 {
			mk("TLS Certificate Uses a Short RSA Key", "medium",
				"The certificate public key is shorter than 2048 bits.",
				"RSA keys under 2048 bits can be factored with feasible resources.",
				"Reissue with an RSA key of at least 2048 bits or an ECDSA P-256 key.",
				fmt.Sprintf("subject %q RSA %d bits", subject, k.Size()*8))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out
}

func tlsServices(e *Env) []store.ServiceInfo {
	var out []store.ServiceInfo
	for _, s := range e.Services {
		if s.Proto != "tcp" {
			continue
		}
		n := strings.ToLower(s.Name)
		if s.Tunnel == "ssl" || strings.Contains(n, "https") || strings.Contains(n, "ssl") || s.Port == 443 || s.Port == 8443 {
			out = append(out, s)
		}
	}
	return out
}

var tlsProbe = Check{
	ID: "tls-probe", Name: "TLS protocol and certificate probe", Family: "Misconfiguration", Safety: policy.SafetyProbe,
	Needs: func(e *Env) string {
		if len(tlsServices(e)) == 0 {
			return "no TLS service"
		}
		return ""
	},
	Run: func(e *Env) []Finding {
		var out []Finding
		for _, s := range tlsServices(e) {
			if f, ok := probeTLS(net.JoinHostPort(e.Address, strconv.Itoa(s.Port))); ok {
				out = append(out, tlsFindings(s.Port, f, e.Now)...)
			}
		}
		return out
	},
}
