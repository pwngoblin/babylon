package native

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "lab.local"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func tlsServer(t *testing.T, min, max uint16, cert tls.Certificate) string {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: min, MaxVersion: max})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return l.Addr().String()
}

func titles(fs []Finding) string {
	var t []string
	for _, f := range fs {
		t = append(t, f.Title)
	}
	return strings.Join(t, " | ")
}

func TestTLSProbeOldProtocols(t *testing.T) {
	addr := tlsServer(t, tls.VersionTLS10, tls.VersionTLS12, testCert(t, time.Now().Add(365*24*time.Hour)))
	f, ok := probeTLS(addr)
	if !ok || strings.Join(f.Versions, ",") != "TLS 1.0,TLS 1.1,TLS 1.2" {
		t.Fatalf("versions: %+v ok=%v", f.Versions, ok)
	}
	got := tlsFindings(443, f, time.Now())
	if len(got) != 1 || !strings.Contains(got[0].Title, "Deprecated TLS") {
		t.Errorf("got %s", titles(got))
	}
}

func TestTLSProbeModernServerIsClean(t *testing.T) {
	addr := tlsServer(t, tls.VersionTLS12, tls.VersionTLS13, testCert(t, time.Now().Add(365*24*time.Hour)))
	f, _ := probeTLS(addr)
	if got := tlsFindings(443, f, time.Now()); len(got) != 0 {
		t.Errorf("modern config flagged: %s", titles(got))
	}
}

func TestTLSProbeExpiringSoon(t *testing.T) {
	addr := tlsServer(t, tls.VersionTLS12, tls.VersionTLS13, testCert(t, time.Now().Add(10*24*time.Hour)))
	f, _ := probeTLS(addr)
	got := tlsFindings(443, f, time.Now())
	if len(got) != 1 || !strings.Contains(got[0].Title, "Expires Soon") || !strings.Contains(got[0].Evidence, "days") {
		t.Errorf("got %s", titles(got))
	}
}

func TestTLSFindingsWeakFacts(t *testing.T) {
	c := &x509.Certificate{SignatureAlgorithm: x509.SHA1WithRSA, NotAfter: time.Now().Add(400 * 24 * time.Hour)}
	got := tlsFindings(443, TLSFacts{Versions: []string{"TLS 1.0"}, Cert: c}, time.Now())
	want := []string{"Deprecated TLS", "No Modern TLS", "Weak Hash"}
	for _, w := range want {
		if !strings.Contains(titles(got), w) {
			t.Errorf("missing %q in %s", w, titles(got))
		}
	}
}

func TestTLSProbeNotTLS(t *testing.T) {
	addr := serveTCP(t, func(c net.Conn) { c.Write([]byte("SSH-2.0-test\r\n")) })
	if _, ok := probeTLS(addr.String()); ok {
		t.Error("a non-TLS service must not yield facts")
	}
}
