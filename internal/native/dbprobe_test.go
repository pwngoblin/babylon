package native

import (
	"net"
	"strings"
	"testing"
	"time"
)

func mysqlGreeting(version string, caps uint16) []byte {
	body := []byte{10}
	body = append(body, version...)
	body = append(body, 0)
	body = append(body, 1, 0, 0, 0)                                // connection id
	body = append(body, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 0) // salt + filler
	body = append(body, byte(caps), byte(caps>>8))
	body = append(body, make([]byte, 20)...)
	return append([]byte{byte(len(body)), 0, 0, 0}, body...)
}

func TestParseMySQLGreeting(t *testing.T) {
	v, ssl, ok := ParseMySQLGreeting(mysqlGreeting("8.0.35", 0xffff))
	if !ok || v != "8.0.35" || !ssl {
		t.Errorf("%q %v %v", v, ssl, ok)
	}
	v, ssl, ok = ParseMySQLGreeting(mysqlGreeting("5.7.44", 0xf7ff&^0x0800))
	if !ok || v != "5.7.44" || ssl {
		t.Errorf("no-ssl: %q %v %v", v, ssl, ok)
	}
	if _, _, ok := ParseMySQLGreeting([]byte{0xff, 0x01, 0x02}); ok {
		t.Error("an error packet is not a greeting")
	}
}

func TestMySQLFindings(t *testing.T) {
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		ver  string
		ssl  bool
		want []string
	}{
		{"5.7.44", true, []string{"Unsupported Database Version: MySQL 5.7"}},
		{"8.0.35", true, []string{"MySQL 8.0"}},
		{"8.4.3", true, nil},
		{"5.5.5-10.3.39-MariaDB", false, []string{"MariaDB 10.3", "Does Not Offer TLS"}},
		{"10.11.6-MariaDB", true, nil},
	}
	for _, c := range cases {
		got := titles(mysqlFindings(c.ver, c.ssl, now))
		if len(c.want) == 0 && got != "" {
			t.Errorf("%s: unexpected %s", c.ver, got)
		}
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: want %q in %q", c.ver, w, got)
			}
		}
	}
}

func TestMySQLProbeReadsOnly(t *testing.T) {
	addr := serveTCP(t, func(c net.Conn) {
		c.Write(mysqlGreeting("5.7.44", 0xf7ff&^0x0800))
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 16)
		if n, _ := c.Read(buf); n > 0 {
			t.Errorf("the probe must not write to MySQL, sent % x", buf[:n])
		}
	})
	env, port := tcpEnv(addr)
	env.Now = time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	got := tcpMulti("x", "x", []int{port}, mysqlRun).Run(env)
	if !strings.Contains(titles(got), "MySQL 5.7") || !strings.Contains(titles(got), "TLS") {
		t.Errorf("got %s", titles(got))
	}
}

func TestPostgresTLSProbe(t *testing.T) {
	for _, c := range []struct {
		reply byte
		flag  bool
	}{{'N', true}, {'S', false}} {
		addr := serveTCP(t, func(conn net.Conn) {
			buf := make([]byte, 8)
			n, _ := conn.Read(buf)
			if string(buf[:n]) != string(pgSSLRequest) {
				t.Errorf("only the SSLRequest may be sent, got % x", buf[:n])
			}
			conn.Write([]byte{c.reply})
		})
		env, port := tcpEnv(addr)
		got := tcpMulti("p", "p", []int{port}, postgresRun).Run(env)
		if c.flag && len(got) != 1 || !c.flag && len(got) != 0 {
			t.Errorf("reply %q: %+v", c.reply, got)
		}
	}
}
