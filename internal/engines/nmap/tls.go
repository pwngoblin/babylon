package nmap

import (
	"strconv"
	"strings"

	"babylon/internal/model"
)

// extractTLS builds a TLS summary from the ssl-cert and ssl-enum-ciphers
// scripts on a port. It returns nil when neither is present.
func extractTLS(scripts []xScript) *model.TLS {
	var t *model.TLS
	get := func() *model.TLS {
		if t == nil {
			t = &model.TLS{}
		}
		return t
	}
	for _, s := range scripts {
		switch s.ID {
		case "ssl-cert":
			parseCert(s, get())
		case "ssl-enum-ciphers":
			parseCiphers(s, get())
		}
	}
	if t != nil {
		t.Weak = weaknesses(t)
	}
	return t
}

func parseCert(s xScript, t *model.TLS) {
	for _, tb := range s.Tables {
		switch tb.Key {
		case "subject":
			t.Subject = dn(tb)
		case "issuer":
			t.Issuer = dn(tb)
		case "validity":
			for _, e := range tb.Elems {
				switch e.Key {
				case "notBefore":
					t.NotBefore = e.Value
				case "notAfter":
					t.NotAfter = e.Value
				}
			}
		case "pubkey":
			for _, e := range tb.Elems {
				switch e.Key {
				case "type":
					t.KeyType = e.Value
				case "bits":
					t.KeyBits, _ = strconv.Atoi(e.Value)
				}
			}
		case "extensions":
			for _, ext := range tb.Tables {
				for _, e := range ext.Elems {
					if e.Key == "name" && e.Value == "X509v3 Subject Alternative Name" {
						for _, e2 := range ext.Elems {
							if e2.Key == "value" {
								for _, part := range strings.Split(e2.Value, ",") {
									part = strings.TrimSpace(part)
									if strings.HasPrefix(part, "DNS:") {
										t.SANs = append(t.SANs, strings.TrimPrefix(part, "DNS:"))
									}
								}
							}
						}
					}
				}
			}
		}
	}
	for _, e := range s.Elems {
		if e.Key == "sig_algo" {
			t.SigAlgo = e.Value
		}
	}
}

// dn renders a distinguished-name table as "commonName=x, organizationName=y".
func dn(tb xTable) string {
	var parts []string
	for _, e := range tb.Elems {
		parts = append(parts, e.Key+"="+e.Value)
	}
	return strings.Join(parts, ", ")
}

func parseCiphers(s xScript, t *model.TLS) {
	for _, proto := range s.Tables {
		p := model.TLSProtocol{Name: proto.Key}
		for _, e := range proto.Elems {
			if e.Key == "least strength" {
				p.LeastStrength = e.Value
			}
		}
		for _, sub := range proto.Tables {
			if sub.Key != "ciphers" {
				continue
			}
			for _, c := range sub.Tables {
				var ci model.TLSCipher
				for _, e := range c.Elems {
					switch e.Key {
					case "name":
						ci.Name = e.Value
					case "strength":
						ci.Strength = e.Value
					}
				}
				if ci.Name != "" {
					p.Ciphers = append(p.Ciphers, ci)
				}
			}
		}
		if p.Name != "" {
			t.Protocols = append(t.Protocols, p)
		}
	}
}

// weaknesses derives plain-language notes later turned into findings.
func weaknesses(t *model.TLS) []string {
	var out []string
	for _, p := range t.Protocols {
		switch p.Name {
		case "SSLv2", "SSLv3":
			out = append(out, p.Name+" is enabled (broken protocol)")
		case "TLSv1.0", "TLSv1.1":
			out = append(out, p.Name+" is enabled (deprecated protocol)")
		}
		for _, c := range p.Ciphers {
			if c.Strength == "D" || c.Strength == "E" || c.Strength == "F" {
				out = append(out, p.Name+": weak cipher "+c.Name+" (grade "+c.Strength+")")
			}
		}
	}
	if t.KeyType == "rsa" && t.KeyBits > 0 && t.KeyBits < 2048 {
		out = append(out, "RSA key shorter than 2048 bits ("+strconv.Itoa(t.KeyBits)+")")
	}
	if strings.Contains(strings.ToLower(t.SigAlgo), "md5") || strings.Contains(strings.ToLower(t.SigAlgo), "sha1") {
		out = append(out, "certificate signed with weak algorithm "+t.SigAlgo)
	}
	return out
}
