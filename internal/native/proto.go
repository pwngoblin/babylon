package native

import (
	"bytes"
	"encoding/binary"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"babylon/internal/policy"
	"babylon/internal/store"
)

// Protocol probes for directory, boot, time, management and Erlang services.
// Each sends one or two small requests that only ask the service to describe
// itself or to refuse a request that cannot succeed. No login is attempted,
// no file is read, and no state is changed. All are probe-level (--allow-active).

// udpExchange sends one datagram and returns the first reply. The socket is
// not connected: TFTP servers answer from a new ephemeral port (the transfer
// id), which a connected socket would silently drop. Replies are accepted from
// any port of the probed address.
func udpExchange(host string, port int, send []byte) ([]byte, error) {
	dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	network := "udp4"
	if dst.IP.To4() == nil {
		network = "udp6"
	}
	c, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.WriteToUDP(send, dst); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		if from.IP.Equal(dst.IP) {
			return buf[:n], nil
		}
	}
}

// ---- LDAP (BER by hand: three small messages) ----

func lber(tag byte, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	n := len(body)
	switch {
	case n < 128:
		return append([]byte{tag, byte(n)}, body...)
	case n < 256:
		return append([]byte{tag, 0x81, byte(n)}, body...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, body...)
	}
}

func lberInt(v int) []byte    { return lber(0x02, []byte{byte(v)}) }
func lberStr(s string) []byte { return lber(0x04, []byte(s)) }

// lberNext splits one TLV off b.
func lberNext(b []byte) (tag byte, content, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	n, off := int(b[1]), 2
	if b[1]&0x80 != 0 {
		l := int(b[1] & 0x7f)
		if l == 0 || l > 3 || len(b) < 2+l {
			return 0, nil, nil, false
		}
		n = 0
		for _, x := range b[2 : 2+l] {
			n = n<<8 | int(x)
		}
		off = 2 + l
	}
	if n < 0 || len(b) < off+n {
		return 0, nil, nil, false
	}
	return tag, b[off : off+n], b[off+n:], true
}

// ldapMessages splits a byte stream into LDAPMessages, returning for each the
// protocolOp tag and its content.
func ldapMessages(b []byte) (ops []struct {
	Tag     byte
	Content []byte
}) {
	for len(b) > 0 {
		tag, msg, rest, ok := lberNext(b)
		if !ok || tag != 0x30 {
			return
		}
		b = rest
		_, _, afterID, ok := lberNext(msg) // messageID
		if !ok {
			return
		}
		op, content, _, ok := lberNext(afterID)
		if !ok {
			return
		}
		ops = append(ops, struct {
			Tag     byte
			Content []byte
		}{op, content})
	}
	return
}

// ldapResultCode reads the resultCode of a *Response operation.
func ldapResultCode(content []byte) (int, bool) {
	tag, v, _, ok := lberNext(content)
	if !ok || tag != 0x0a || len(v) != 1 {
		return 0, false
	}
	return int(v[0]), true
}

func ldapBindAnon() []byte {
	return lber(0x30, lberInt(1), lber(0x60, lberInt(3), lberStr(""), lber(0x80)))
}

// ldapSearchBase asks for one entry at baseDN (scope base), objectClass=*; with
// an empty baseDN that is the rootDSE.
func ldapSearchBase(id int, baseDN string, attrs ...string) []byte {
	var al [][]byte
	for _, a := range attrs {
		al = append(al, lberStr(a))
	}
	req := lber(0x63, lberStr(baseDN), lber(0x0a, []byte{0}), lber(0x0a, []byte{0}), lberInt(0), lberInt(0),
		lber(0x01, []byte{0}), lber(0x87, []byte("objectClass")), lber(0x30, al...))
	return lber(0x30, lberInt(id), req)
}

var dnRe = regexp.MustCompile(`(?i)^(dc|cn|o|ou|c)=`)

// ldapStrings returns every octet string in a SearchResultEntry that looks like a DN.
func ldapDNs(b []byte) []string {
	var out []string
	var walk func([]byte)
	walk = func(b []byte) {
		for len(b) > 0 {
			tag, content, rest, ok := lberNext(b)
			if !ok {
				return
			}
			switch {
			case tag&0x20 != 0: // constructed
				walk(content)
			case tag == 0x04 && dnRe.Match(content):
				out = append(out, string(content))
			}
			b = rest
		}
	}
	walk(b)
	return out
}

func ldapRun(e *Env, s store.ServiceInfo) []Finding {
	b, err := tcpExchange(e.Address, s.Port, ldapBindAnon(), 256, func(b []byte) bool { return len(ldapMessages(b)) >= 1 })
	if err != nil {
		return nil
	}
	ops := ldapMessages(b)
	if len(ops) == 0 || ops[0].Tag != 0x61 {
		return nil
	}
	if code, ok := ldapResultCode(ops[0].Content); !ok || code != 0 {
		return nil
	}
	// Same connection state is not needed: a rootDSE search is allowed without binding.
	resp, err := tcpExchange(e.Address, s.Port, append(ldapBindAnon(), ldapSearchBase(2, "", "namingContexts", "defaultNamingContext")...), 8192,
		func(b []byte) bool {
			for _, o := range ldapMessages(b) {
				if o.Tag == 0x65 {
					return true
				}
			}
			return false
		})
	var contexts []string
	if err == nil {
		for _, o := range ldapMessages(resp) {
			if o.Tag == 0x64 {
				contexts = append(contexts, ldapDNs(o.Content)...)
			}
		}
	}
	out := []Finding{{Title: "LDAP Server Accepts Anonymous Binds", Severity: "low",
		Synopsis:    "The directory accepts a bind with no name and no password.",
		Description: "Anonymous binds let anyone query the directory to the extent its access controls allow. The root DSE (naming contexts, supported controls) is always readable, but misconfigured servers also expose users, groups and hosts.",
		Remediation: "Disable anonymous binds (Active Directory: dsHeuristics; OpenLDAP: disallow bind_anon) unless a client requires them, and restrict reads with ACLs.",
		Evidence:    "anonymous simple bind -> resultCode 0 (success); naming contexts: " + strings.Join(contexts, ", ")}}
	if len(contexts) > 0 {
		// One base-scope read of the first naming context; only the DN is reported.
		r2, err := tcpExchange(e.Address, s.Port, append(ldapBindAnon(), ldapSearchBase(3, contexts[0], "objectClass")...), 8192,
			func(b []byte) bool {
				for _, o := range ldapMessages(b) {
					if o.Tag == 0x65 {
						return true
					}
				}
				return false
			})
		if err == nil {
			for _, o := range ldapMessages(r2) {
				if o.Tag == 0x64 {
					out = append(out, Finding{Title: "LDAP Directory Readable Without Authentication", Severity: "medium",
						Synopsis:    "An anonymous client can read directory entries below the naming context.",
						Description: "Anonymous reads normally reveal users, groups, computers and sometimes password-related attributes, which helps attackers plan password guessing and lateral movement.",
						Remediation: "Require authentication for all directory reads (Active Directory: remove anonymous access from the directory ACLs and enforce LDAP signing; OpenLDAP: restrict `access to` rules).",
						Evidence:    "anonymous base search of " + contexts[0] + " returned an entry"})
					break
				}
			}
		}
	}
	return out
}

// ---- TFTP ----

// A read request for a file that cannot exist. A reachable TFTP server answers
// with an ERROR packet; no data is requested or transferred.
func tftpRun(e *Env) []Finding { return tftpRunPort(e, 69) }

func tftpRunPort(e *Env, port int) []Finding {
	req := append([]byte{0, 1}, []byte("babylon-probe-nonexistent\x00octet\x00")...)
	b, err := udpExchange(e.Address, port, req)
	if err != nil || len(b) < 4 || b[0] != 0 || (b[1] != 5 && b[1] != 3) {
		return nil
	}
	ev := "RRQ for a nonexistent file -> "
	if b[1] == 5 {
		ev += "ERROR " + strconv.Itoa(int(binary.BigEndian.Uint16(b[2:4]))) + ": " + snippet(strings.TrimRight(string(b[4:]), "\x00"), 80)
	} else {
		ev += "DATA (the server returned a file)"
	}
	return []Finding{{Port: 69, Proto: "udp", Title: "TFTP Server Reachable (No Authentication)", Severity: "medium",
		Synopsis:    "A TFTP server answers requests from any client.",
		Description: "TFTP has no authentication. Anyone who can reach the service can read any file it serves and, if writes are enabled, upload files; device configurations and firmware images are commonly exposed this way.",
		Remediation: "Disable TFTP when not needed, or restrict it to provisioning hosts by firewall, serve only a dedicated directory, and disable writes.",
		Evidence:    ev}}
}

// ---- NTP mode 6 ----

// A mode 6 READVAR request for the system variables (what `ntpq -c rv` sends).
func ntpRun(e *Env) []Finding { return ntpRunPort(e, 123) }

func ntpRunPort(e *Env, port int) []Finding {
	req := []byte{0x16, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	b, err := udpExchange(e.Address, port, req)
	if err != nil || len(b) < 12 || b[0]&0x07 != 6 || b[1]&0x80 == 0 {
		return nil
	}
	vars := ""
	if len(b) > 12 {
		vars = snippet(strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' {
				return ' '
			}
			return r
		}, string(b[12:])), 300)
	}
	return []Finding{{Port: 123, Proto: "udp", Title: "NTP Mode 6 Control Queries Enabled", Severity: "low",
		Synopsis:    "The NTP server answers remote control (mode 6) queries.",
		Description: "Mode 6 replies reveal the daemon version, operating system and clock details, and can be used as a reflection and amplification vector for denial-of-service attacks.",
		Remediation: "Restrict queries with `restrict default noquery` (and `nomodify nopeer`) in ntp.conf, or use chrony/ntpd builds that disable remote control.",
		Evidence:    "READVAR (mode 6) answered: " + vars}}
}

// ---- IPMI 2.0 ----

// ipmiOpenSession sends an RMCP+ Open Session Request proposing one cipher
// suite (auth, integrity, confidentiality algorithm ids). A status of 0 means
// the BMC would accept that suite. No authentication exchange follows.
func ipmiOpenSession(host string, port int, auth, integ, conf byte) (accepted bool, answered bool) {
	payload := []byte{0x00, 0x00, 0x00, 0x00, 0xa0, 0xa1, 0xa2, 0xa3}
	payload = append(payload, 0x00, 0, 0, 8, auth, 0, 0, 0)
	payload = append(payload, 0x01, 0, 0, 8, integ, 0, 0, 0)
	payload = append(payload, 0x02, 0, 0, 8, conf, 0, 0, 0)
	pkt := []byte{0x06, 0x00, 0xff, 0x07, 0x06, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, byte(len(payload)), 0}
	pkt = append(pkt, payload...)
	b, err := udpExchange(host, port, pkt)
	if err != nil || len(b) < 18 || b[0] != 0x06 || b[4] != 0x06 || b[5] != 0x11 {
		return false, false
	}
	return b[17] == 0, true
}

func ipmiRun(e *Env) []Finding { return ipmiRunPort(e, 623) }

func ipmiRunPort(e *Env, port int) []Finding {
	var out []Finding
	if ok, ans := ipmiOpenSession(e.Address, port, 0x01, 0x01, 0x01); ans && ok { // cipher suite 3
		out = append(out, Finding{Port: 623, Proto: "udp", Title: "IPMI v2.0 Password Hash Disclosure", Severity: "medium",
			CVEs:        []string{"CVE-2013-4786"},
			Synopsis:    "The BMC supports IPMI 2.0 RMCP+ authentication, which lets a remote client obtain a password hash.",
			Description: "In IPMI 2.0 the BMC returns an HMAC of the user's password to any client that names a valid user (RAKP message 2). The hash can be cracked offline. This is part of the protocol, not a bug in one product.",
			Remediation: "Restrict the BMC to a dedicated management network, use long random IPMI passwords, and disable IPMI over LAN where it is not needed.",
			Evidence:    "RMCP+ Open Session Request with cipher suite 3 -> status 0 (accepted)"})
	}
	if ok, ans := ipmiOpenSession(e.Address, port, 0x00, 0x00, 0x00); ans && ok { // cipher suite 0
		out = append(out, Finding{Port: 623, Proto: "udp", Title: "IPMI v2.0 Cipher Suite 0 Enabled (Authentication Bypass)", Severity: "high",
			Synopsis:    "The BMC accepts the 'none' authentication cipher suite.",
			Description: "Cipher suite 0 performs no authentication, so a remote client can open an IPMI session with any password for a known user and control power and the console.",
			Remediation: "Disable cipher suite 0 in the BMC configuration (ipmitool lan set 1 cipher_privs XXXXXXXXXXXXXXX) and restrict the BMC network.",
			Evidence:    "RMCP+ Open Session Request with cipher suite 0 (auth none, integrity none, confidentiality none) -> status 0 (accepted)"})
	}
	return out
}

// ---- Erlang port mapper ----

// EPMD names request: length 1, 'n'. The reply lists registered Erlang nodes.
func epmdRun(e *Env, s store.ServiceInfo) *Finding {
	b, err := tcpExchange(e.Address, s.Port, []byte{0, 1, 'n'}, 2048, nil)
	if err != nil || len(b) < 4 {
		return nil
	}
	text := string(b[4:])
	if !strings.Contains(text, "name ") || !strings.Contains(text, "at port") {
		return nil
	}
	return &Finding{Title: "Erlang Port Mapper Daemon (EPMD) Exposed", Severity: "medium",
		Synopsis:    "EPMD lists Erlang nodes and their distribution ports to any client.",
		Description: "Erlang's distribution protocol is protected only by a shared cookie. Exposed nodes (RabbitMQ, CouchDB, ejabberd and others) with a guessable or default cookie allow remote code execution.",
		Remediation: "Bind EPMD and the distribution ports to localhost or a private cluster network, firewall 4369 and the distribution port range, and use a long random cookie or TLS distribution.",
		Evidence:    "registered nodes:\n" + strings.TrimSpace(snippet(text, 300))}
}

func udpProbe(id, name string, run func(*Env) []Finding) Check {
	return Check{ID: id, Name: name, Family: "Misconfiguration", Safety: policy.SafetyProbe, Run: run}
}

func protoChecks() []Check {
	ldap := tcpMulti("ldap-anonymous", "LDAP directory allows anonymous binds", []int{389, 3268}, ldapRun)
	return []Check{
		ldap,
		udpProbe("tftp-open", "TFTP server reachable", tftpRun),
		udpProbe("ntp-mode6", "NTP answers mode 6 control queries", ntpRun),
		udpProbe("ipmi-cipher-zero", "IPMI 2.0 cipher suites", ipmiRun),
		tcpCheck("epmd-exposed", "Erlang port mapper exposed", []int{4369}, epmdRun),
	}
}
