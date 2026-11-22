package correlate

import (
	"strings"
	"testing"
)

func TestFingerprintCollapsesEnginesByCVE(t *testing.T) {
	a := Fingerprint("10.0.0.5", 80, "tcp", []string{"cve-2021-41773"}, "nuclei:CVE-2021-41773")
	b := Fingerprint("10.0.0.5", 80, "tcp", []string{"CVE-2021-41773"}, "cpematch:apache")
	if a != b {
		t.Fatal("same CVE on same service must share a fingerprint across engines")
	}
	if a == Fingerprint("10.0.0.5", 8080, "tcp", []string{"CVE-2021-41773"}, "x") {
		t.Fatal("different port must differ")
	}
	if Fingerprint("h", 1, "tcp", nil, "a") == Fingerprint("h", 1, "tcp", nil, "b") {
		t.Fatal("different check keys must differ without CVEs")
	}
	if Fingerprint("h", 1, "tcp", []string{"B", "A"}, "") != Fingerprint("h", 1, "tcp", []string{"A", "B"}, "") {
		t.Fatal("CVE order must not matter")
	}
}

func TestRedact(t *testing.T) {
	in := "GET / HTTP/1.1\nAuthorization: Bearer abc123\nCookie: sid=zzz\nHost: x\n" +
		"body: password=hunter2&user=bob api_key: AKIAABCDEFGHIJKLMNOP\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n" +
		"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghi\x01"
	out := Redact(in)
	for _, leak := range []string{"abc123", "zzz", "hunter2", "AKIAABCDEFGHIJKLMNOP", "MIIE", "eyJhbGci", "\x01"} {
		if strings.Contains(out, leak) {
			t.Errorf("secret %q leaked: %s", leak, out)
		}
	}
	for _, keep := range []string{"GET / HTTP/1.1", "Host: x", "user=bob"} {
		if !strings.Contains(out, keep) {
			t.Errorf("over-redacted %q: %s", keep, out)
		}
	}
}

func TestTruncateRuneBoundary(t *testing.T) {
	s := strings.Repeat("é", 5000) // 2 bytes each
	out := Truncate(s, 4097)
	if !strings.HasSuffix(out, "[truncated]") {
		t.Fatal("no marker")
	}
	body := strings.TrimSuffix(out, "\n…[truncated]")
	for _, r := range body {
		if r == '�' {
			t.Fatal("cut inside a multibyte rune")
		}
	}
}

func TestCanonicalKeyMergesEnginesOnNonCVEFindings(t *testing.T) {
	a := Fingerprint("10.0.0.5", 6379, "tcp", nil, CheckKey("nuclei", "exposed-redis"))
	b := Fingerprint("10.0.0.5", 6379, "tcp", nil, CheckKey("native", "redis-unauth"))
	if a != b {
		t.Fatal("nuclei and native reports of unauthenticated Redis must share a fingerprint")
	}
	if CheckKey("nuclei", "some-other-template") != "nuclei:some-other-template" {
		t.Fatal("unmapped checks keep an engine-specific key")
	}
}
