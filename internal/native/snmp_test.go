package native

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestSNMPRequestEncoding(t *testing.T) {
	// A hand-checked (matches the standard sysDescr.0 capture, OID encodes to 8 bytes) SNMPv2c GET for sysDescr.0 with community "public".
	got := snmpGetRequest("public", 1, oidSysDescr)
	want := []byte{0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
		0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding mismatch:\n got % x\nwant % x", got, want)
	}
}

func fakeSNMPAgent(t *testing.T, community string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := buf[:n]
			if !bytes.Contains(req, []byte(community)) || req[len(req)-1] != 0x00 {
				continue // wrong community: real agents stay silent
			}
			if bytes.Contains(req, []byte{0xa3}) { // SetRequest must never be sent
				t.Errorf("a SET was sent")
			}
			vb := func(o []int, v []byte) []byte { return tlv(0x30, berOID(o), v) }
			resp := tlv(0x30, berInt(1), tlv(0x04, []byte(community)),
				tlv(0xa2, berInt(0x2a), berInt(0), berInt(0), tlv(0x30,
					vb(oidSysDescr, tlv(0x04, []byte("Linux router 5.4.0 #1 SMP"))),
					vb(oidSysObjectID, tlv(0x06, []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x65})),
					vb(oidSysName, tlv(0x04, []byte("gw1"))))))
			pc.WriteTo(resp, from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestSNMPSystem(t *testing.T) {
	addr := fakeSNMPAgent(t, "public")
	d, o, n, err := snmpSystem(addr, "public")
	if err != nil || !strings.Contains(d, "Linux router") || o != "1.3.6.1.4.1.2021" || n != "gw1" {
		t.Fatalf("got %q %q %q %v", d, o, n, err)
	}
	f := snmpFinding(d, o, n)
	if f.Proto != "udp" || f.Port != 161 || !strings.Contains(f.Evidence, "gw1") {
		t.Errorf("%+v", f)
	}
	if _, _, _, err := snmpSystem(fakeSNMPAgent(t, "secret"), "public"); err == nil {
		t.Error("an agent that does not accept 'public' must not produce a finding")
	}
}

func TestSNMPParseGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {0x30}, {0x30, 0x84, 1, 2, 3, 4}, {0x30, 0x05, 0x02, 0x01}, bytes.Repeat([]byte{0xff}, 40)} {
		if _, _, err := parseSNMPResponse(b); err == nil {
			t.Errorf("garbage %x must be rejected", b)
		}
	}
}
