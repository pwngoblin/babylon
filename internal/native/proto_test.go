package native

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"babylon/internal/store"
)

func ldapResp(id int, op byte, content ...[]byte) []byte {
	return lber(0x30, lberInt(id), lber(op, content...))
}

func ldapDone(id int, op byte, code byte) []byte {
	return ldapResp(id, op, lber(0x0a, []byte{code}), lberStr(""), lberStr(""))
}

func ldapEntry(id int, dn, attr string, vals ...string) []byte {
	var vs [][]byte
	for _, v := range vals {
		vs = append(vs, lberStr(v))
	}
	return ldapResp(id, 0x64, lberStr(dn), lber(0x30, lber(0x30, lberStr(attr), lber(0x31, vs...))))
}

// ldapMock answers binds with bindCode and searches per readable.
func ldapMock(t *testing.T, bindCode byte, readable bool) net.Addr {
	return serveTCP(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			b := buf[:n]
			for len(b) > 0 {
				tag, msg, rest, ok := lberNext(b)
				if !ok || tag != 0x30 {
					break
				}
				b = rest
				_, idc, after, _ := lberNext(msg)
				id := int(idc[0])
				op, content, _, _ := lberNext(after)
				switch op {
				case 0x60:
					c.Write(ldapDone(id, 0x61, bindCode))
				case 0x63:
					_, base, _, _ := lberNext(content)
					if len(base) == 0 {
						c.Write(ldapEntry(id, "", "namingContexts", "dc=example,dc=com"))
						c.Write(ldapDone(id, 0x65, 0))
					} else if readable {
						c.Write(ldapEntry(id, string(base), "objectClass", "top"))
						c.Write(ldapDone(id, 0x65, 0))
					} else {
						c.Write(ldapDone(id, 0x65, 50))
					}
				}
			}
		}
	})
}

func TestLDAPAnonymousBind(t *testing.T) {
	for _, c := range []struct {
		name     string
		bind     byte
		readable bool
		want     []string
		notWant  string
	}{
		{"readable", 0, true, []string{"Anonymous Binds", "Directory Readable"}, ""},
		{"rootdse only", 0, false, []string{"Anonymous Binds"}, "Directory Readable"},
		{"bind refused", 49, true, nil, "Anonymous"},
	} {
		addr := ldapMock(t, c.bind, c.readable)
		env, port := tcpEnv(addr)
		got := titles(tcpMulti("l", "l", []int{port}, ldapRun).Run(env))
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: want %q in %q", c.name, w, got)
			}
		}
		if c.notWant != "" && strings.Contains(got, c.notWant) {
			t.Errorf("%s: unexpected %q in %q", c.name, c.notWant, got)
		}
		if c.name == "readable" && !strings.Contains(got, "Directory Readable") {
			t.Error("must report")
		}
	}
	// A non-LDAP service must produce nothing.
	addr := serveTCP(t, func(c net.Conn) { c.Write([]byte("SSH-2.0-x\r\n")) })
	env, port := tcpEnv(addr)
	if got := tcpMulti("l", "l", []int{port}, ldapRun).Run(env); len(got) != 0 {
		t.Errorf("%+v", got)
	}
}

func TestLDAPRequestsAreReadOnly(t *testing.T) {
	for _, req := range [][]byte{ldapBindAnon(), ldapSearchBase(2, "", "namingContexts")} {
		_, msg, _, _ := lberNext(req)
		_, _, after, _ := lberNext(msg)
		if op := after[0]; op != 0x60 && op != 0x63 {
			t.Errorf("only bind and search may be sent, got op 0x%02x", op)
		}
	}
}

func serveUDP(t *testing.T, handle func(req []byte) []byte) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if r := handle(append([]byte(nil), buf[:n]...)); r != nil {
				pc.WriteTo(r, addr)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestTFTPProbeAsksForNonexistentFileOnly(t *testing.T) {
	var mu sync.Mutex
	var got []byte
	port := serveUDP(t, func(req []byte) []byte {
		mu.Lock()
		got = req
		mu.Unlock()
		return append([]byte{0, 5, 0, 1}, []byte("File not found\x00")...)
	})
	f := tftpRunPort(&Env{Address: "127.0.0.1"}, port)
	if len(f) != 1 || !strings.Contains(f[0].Evidence, "ERROR 1") {
		t.Fatalf("%+v", f)
	}
	mu.Lock()
	defer mu.Unlock()
	if got[1] != 1 || !strings.Contains(string(got), "nonexistent") {
		t.Errorf("must be a read request for a file that cannot exist: % x", got)
	}
	if f := tftpRunPort(&Env{Address: "127.0.0.1"}, serveUDP(t, func([]byte) []byte { return nil })); len(f) != 0 {
		t.Error("silence is not a finding")
	}
}

func TestNTPMode6(t *testing.T) {
	port := serveUDP(t, func(req []byte) []byte {
		if req[0]&7 != 6 {
			return nil
		}
		return append([]byte{0x1e, 0x82, 0, 1, 0, 0, 0, 0, 0, 0, 0, 20}, []byte(`version="ntpd 4.2.8p15", system="Linux"`)...)
	})
	f := ntpRunPort(&Env{Address: "127.0.0.1"}, port)
	if len(f) != 1 || !strings.Contains(f[0].Evidence, "ntpd 4.2.8p15") {
		t.Fatalf("%+v", f)
	}
	// A normal time reply (mode 4) is not a control response.
	p2 := serveUDP(t, func([]byte) []byte { return append([]byte{0x24, 1}, make([]byte, 46)...) })
	if f := ntpRunPort(&Env{Address: "127.0.0.1"}, p2); len(f) != 0 {
		t.Errorf("%+v", f)
	}
}

func ipmiReply(status byte) []byte {
	r := []byte{0x06, 0, 0xff, 0x07, 0x06, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0x24, 0}
	return append(r, 0x00, status, 0, 0, 0xa0, 0xa1, 0xa2, 0xa3)
}

func TestIPMICipherSuites(t *testing.T) {
	// BMC that accepts cipher 3 and cipher 0.
	all := serveUDP(t, func(req []byte) []byte { return ipmiReply(0) })
	titlesAll := titles(ipmiRunPort(&Env{Address: "127.0.0.1"}, all))
	if !strings.Contains(titlesAll, "Password Hash Disclosure") || !strings.Contains(titlesAll, "Cipher Suite 0") {
		t.Errorf("%s", titlesAll)
	}
	// Accepts only suites that use authentication: cipher 0 request is refused.
	var sawNone atomic.Bool
	hardened := serveUDP(t, func(req []byte) []byte {
		if req[len(req)-24+4] == 0 { // auth algorithm byte of the first payload
			sawNone.Store(true)
			return ipmiReply(0x11) // no matching cipher suite
		}
		return ipmiReply(0)
	})
	got := titles(ipmiRunPort(&Env{Address: "127.0.0.1"}, hardened))
	if !sawNone.Load() || strings.Contains(got, "Cipher Suite 0") || !strings.Contains(got, "Hash") {
		t.Errorf("sawNone=%v %s", sawNone.Load(), got)
	}
	// A non-IPMI UDP service answers nothing useful.
	junk := serveUDP(t, func([]byte) []byte { return []byte("hello") })
	if f := ipmiRunPort(&Env{Address: "127.0.0.1"}, junk); len(f) != 0 {
		t.Errorf("%+v", f)
	}
}

func TestEPMD(t *testing.T) {
	addr := serveTCP(t, func(c net.Conn) {
		buf := make([]byte, 8)
		n, _ := c.Read(buf)
		if string(buf[:n]) != "\x00\x01n" {
			t.Errorf("only the names request may be sent: % x", buf[:n])
		}
		c.Write(append([]byte{0, 0, 0x11, 0x11}, []byte("name rabbit at port 25672\n")...))
	})
	env, port := tcpEnv(addr)
	got := tcpCheck("e", "e", []int{port}, epmdRun).Run(env)
	if len(got) != 1 || !strings.Contains(got[0].Evidence, "rabbit at port 25672") {
		t.Fatalf("%+v", got)
	}
	addr2 := serveTCP(t, func(c net.Conn) { c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")) })
	env2, port2 := tcpEnv(addr2)
	if got := tcpCheck("e", "e", []int{port2}, epmdRun).Run(env2); len(got) != 0 {
		t.Errorf("%+v", got)
	}
}

var _ = store.ServiceInfo{}
