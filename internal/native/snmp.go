package native

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"babylon/internal/policy"
)

// SNMP probe over an ordinary UDP socket (no root needed, unlike Nmap's UDP
// scan). It sends one SNMPv2c GET for three read-only system objects using the
// default "public" community and reads the reply. It never sends a SET, never
// tries other community strings, and never walks the MIB.

var (
	oidSysDescr    = []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysObjectID = []int{1, 3, 6, 1, 2, 1, 1, 2, 0}
	oidSysName     = []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
)

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func tlv(tag byte, body ...[]byte) []byte {
	b := bytes.Join(body, nil)
	return append(append([]byte{tag}, berLen(len(b))...), b...)
}

func berInt(v int) []byte { return tlv(0x02, []byte{byte(v)}) }

func berOID(oid []int) []byte {
	b := []byte{byte(oid[0]*40 + oid[1])}
	for _, a := range oid[2:] {
		var tmp []byte
		tmp = append(tmp, byte(a&0x7f))
		for a >>= 7; a > 0; a >>= 7 {
			tmp = append([]byte{byte(a&0x7f) | 0x80}, tmp...)
		}
		b = append(b, tmp...)
	}
	return tlv(0x06, b)
}

func snmpGetRequest(community string, reqID int, oids ...[]int) []byte {
	var vbs [][]byte
	for _, o := range oids {
		vbs = append(vbs, tlv(0x30, berOID(o), []byte{0x05, 0x00}))
	}
	pdu := tlv(0xa0, berInt(reqID), berInt(0), berInt(0), tlv(0x30, vbs...))
	return tlv(0x30, berInt(1), tlv(0x04, []byte(community)), pdu) // version 1 = SNMPv2c
}

// berNext reads one TLV and returns tag, value and the remainder.
func berNext(b []byte) (tag byte, val, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("short BER")
	}
	tag = b[0]
	n, i := int(b[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 2 || len(b) < 2+k {
			return 0, nil, nil, errors.New("bad BER length")
		}
		n = 0
		for j := 0; j < k; j++ {
			n = n<<8 | int(b[2+j])
		}
		i = 2 + k
	}
	if len(b) < i+n {
		return 0, nil, nil, errors.New("truncated BER")
	}
	return tag, b[i : i+n], b[i+n:], nil
}

// parseSNMPResponse extracts the octet-string / OID values of a GetResponse by
// position in the varbind list; non-string values come back as "".
func parseSNMPResponse(msg []byte) (values []string, errStatus int, err error) {
	tag, body, _, err := berNext(msg)
	if err != nil || tag != 0x30 {
		return nil, 0, errors.New("not an SNMP message")
	}
	_, _, body, err = berNext(body) // version
	if err != nil {
		return nil, 0, err
	}
	_, _, body, err = berNext(body) // community
	if err != nil {
		return nil, 0, err
	}
	tag, pdu, _, err := berNext(body)
	if err != nil || tag != 0xa2 {
		return nil, 0, errors.New("not a GetResponse")
	}
	_, _, pdu, err = berNext(pdu) // request id
	if err != nil {
		return nil, 0, err
	}
	_, es, pdu, err := berNext(pdu) // error status
	if err != nil {
		return nil, 0, err
	}
	if len(es) > 0 {
		errStatus = int(es[len(es)-1])
	}
	_, _, pdu, err = berNext(pdu) // error index
	if err != nil {
		return nil, 0, err
	}
	tag, vbl, _, err := berNext(pdu)
	if err != nil || tag != 0x30 {
		return nil, 0, errors.New("no varbind list")
	}
	for len(vbl) > 0 {
		var vb []byte
		tag, vb, vbl, err = berNext(vbl)
		if err != nil || tag != 0x30 {
			return values, errStatus, err
		}
		_, _, vb, err = berNext(vb) // name
		if err != nil {
			return values, errStatus, err
		}
		vt, v, _, err := berNext(vb)
		if err != nil {
			return values, errStatus, err
		}
		switch vt {
		case 0x04:
			values = append(values, strings.ToValidUTF8(string(v), ""))
		case 0x06:
			values = append(values, oidString(v))
		default:
			values = append(values, "")
		}
	}
	return values, errStatus, nil
}

func oidString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := []string{fmt.Sprint(int(b[0]) / 40), fmt.Sprint(int(b[0]) % 40)}
	v := 0
	for _, x := range b[1:] {
		v = v<<7 | int(x&0x7f)
		if x&0x80 == 0 {
			parts = append(parts, fmt.Sprint(v))
			v = 0
		}
	}
	return strings.Join(parts, ".")
}

// snmpSystem queries sysDescr, sysObjectID and sysName with a community string.
func snmpSystem(addr string, community string) (descr, objectID, name string, err error) {
	c, err := net.DialTimeout("udp", addr, 3*time.Second)
	if err != nil {
		return "", "", "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write(snmpGetRequest(community, 0x2a, oidSysDescr, oidSysObjectID, oidSysName)); err != nil {
		return "", "", "", err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return "", "", "", err
	}
	vals, es, err := parseSNMPResponse(buf[:n])
	if err != nil || es != 0 || len(vals) < 3 {
		return "", "", "", errors.New("no usable SNMP reply")
	}
	return vals[0], vals[1], vals[2], nil
}

var snmpProbe = Check{
	ID: "snmp-public-probe", Name: "SNMP answers to the public community (direct probe)", Family: "Misconfiguration", Safety: policy.SafetyProbe,
	Needs: func(e *Env) string {
		if len(e.ScriptAnywhere("snmp-info")) > 0 {
			return "already reported from Nmap's snmp-info result"
		}
		return ""
	},
	Run: func(e *Env) []Finding {
		descr, oid, name, err := snmpSystem(net.JoinHostPort(e.Address, "161"), "public")
		if err != nil {
			return nil
		}
		return []Finding{snmpFinding(descr, oid, name)}
	},
}

func snmpFinding(descr, oid, name string) Finding {
	ev := "sysDescr: " + snippet(descr, 200) + "\nsysObjectID: " + oid + "\nsysName: " + snippet(name, 80)
	return Finding{Port: 161, Proto: "udp",
		Title: "SNMP Agent Responds to the Default 'public' Community String", Severity: "medium",
		Synopsis:    "System information is readable with a default community string.",
		Description: "SNMP v1/v2c community strings are passwords sent in clear text; the default exposes device details (and often interface, routing and user data) and, if a writable community is also default, configuration.",
		Remediation: "Change the community strings, prefer SNMPv3 with authentication and encryption, and restrict access to management hosts.",
		Evidence:    ev}
}
