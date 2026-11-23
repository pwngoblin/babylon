package nmap

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	"babylon/internal/model"
)

func parseFile(t *testing.T, path string) ([]model.Host, Stats, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var hosts []model.Host
	st, err := Parse(f, func(h model.Host) error { hosts = append(hosts, h); return nil })
	return hosts, st, err
}

func TestParseRealLabScan(t *testing.T) {
	hosts, st, err := parseFile(t, "../../../testdata/nmap/lab-services.xml")
	if err != nil || !st.Finished || len(hosts) != 1 {
		t.Fatalf("hosts=%d stats=%+v err=%v", len(hosts), st, err)
	}
	h := hosts[0]
	if h.Address != "127.0.0.1" || h.State != "up" || len(h.Ports) != 7 {
		t.Fatalf("host=%+v", h)
	}
	by := map[int]model.Port{}
	for _, p := range h.Ports {
		by[p.Number] = p
	}
	if p := by[18081]; p.Service.Product != "Apache httpd" || p.Service.Version != "2.4.49" || p.Service.CPEs[0] != "cpe:/a:apache:http_server:2.4.49" {
		t.Errorf("apache port: %+v", p.Service)
	}
	if p := by[16379]; p.Service.Name != "redis" || p.Service.Version != "5.0.14" {
		t.Errorf("redis port: %+v", p.Service)
	}
	if p := by[13000]; p.Service.Name != "unknown" && p.Service.Name != "" {
		t.Errorf("juice shop should be unidentified by nmap alone: %+v", p.Service)
	}
}

func TestParseNSEScriptsCaptured(t *testing.T) {
	hosts, _, err := parseFile(t, "../../../testdata/nmap/lab-nse.xml")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, p := range hosts[0].Ports {
		for _, s := range p.Scripts {
			ids[s.ID] = true
		}
	}
	for _, want := range []string{"ssh2-enum-algos", "redis-info", "http-vuln-cve2011-3192"} {
		if !ids[want] {
			t.Errorf("script %s not captured; have %v", want, ids)
		}
	}
	for _, p := range hosts[0].Ports {
		if p.Number == 12121 && p.Service.Banner == "" {
			t.Error("ftp banner (from banner script) not captured")
		}
	}
}

func TestParseTLSAndOS(t *testing.T) {
	hosts, st, err := parseFile(t, "../../../testdata/nmap/tls.xml")
	if err != nil || len(hosts) != 2 || !st.Finished {
		t.Fatalf("hosts=%d err=%v", len(hosts), err)
	}
	h := hosts[0]
	if h.MAC != "aa:bb:cc:00:11:22" || h.Vendor != "Acme" || h.Hostnames[0] != "web.lab.local" {
		t.Errorf("host meta: %+v", h)
	}
	if h.OS == nil || h.OS.Family != "linux" || h.OS.Accuracy != 97 || h.OS.CPE != "cpe:/o:linux:linux_kernel:5" {
		t.Errorf("os: %+v", h.OS)
	}
	if hosts[1].State != "down" {
		t.Errorf("second host should be down: %+v", hosts[1])
	}
	tl := h.Ports[0].TLS
	if tl == nil || tl.KeyType != "rsa" || tl.KeyBits != 1024 || tl.NotAfter != "2021-01-01T00:00:00" ||
		!strings.Contains(tl.Subject, "commonName=web.lab.local") || len(tl.SANs) != 2 || tl.SigAlgo != "sha1WithRSAEncryption" {
		t.Fatalf("tls: %+v", tl)
	}
	if len(tl.Protocols) != 2 || tl.Protocols[0].Name != "TLSv1.0" || tl.Protocols[0].LeastStrength != "D" {
		t.Errorf("protocols: %+v", tl.Protocols)
	}
	joined := strings.Join(tl.Weak, "|")
	for _, want := range []string{"TLSv1.0 is enabled", "weak cipher TLS_RSA_WITH_RC4_128_SHA", "RSA key shorter than 2048", "weak algorithm sha1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing weakness %q in %v", want, tl.Weak)
		}
	}
}

func TestTruncatedScanDeliversPartialResults(t *testing.T) {
	data, _ := os.ReadFile("../../../testdata/nmap/tls.xml")
	cut := strings.Index(string(data), "<host><status state=\"down\"")
	var got int
	st, err := Parse(strings.NewReader(string(data)[:cut]), func(model.Host) error { got++; return nil })
	if !errors.Is(err, ErrTruncated) || got != 1 || st.Finished {
		t.Fatalf("got=%d st=%+v err=%v", got, st, err)
	}
}

// Hostile banners: illegal char refs, raw control bytes, invalid UTF-8. A
// strict XML decoder would abort the whole document on any of these.
func TestHostileBannerBytesDoNotBreakParsing(t *testing.T) {
	doc := "<?xml version=\"1.0\"?><nmaprun><host><status state=\"up\"/><address addr=\"10.0.0.9\" addrtype=\"ipv4\"/><ports>" +
		"<port protocol=\"tcp\" portid=\"21\"><state state=\"open\"/><service name=\"ftp\" product=\"evil &#x1; &#0; &#xFFFFFF; &#x41; \x01 \xff\xfe bytes\"/></port>" +
		"</ports></host><runstats><finished/></runstats></nmaprun>"
	var h model.Host
	_, err := Parse(strings.NewReader(doc), func(x model.Host) error { h = x; return nil })
	if err != nil {
		t.Fatalf("hostile input must not fail parsing: %v", err)
	}
	prod := h.Ports[0].Service.Product
	//lint:ignore SA1011 the escapes are deliberate: the test feeds control bytes through the sanitizer
	if !strings.Contains(prod, "A") || strings.ContainsAny(prod, "\x01\xff") {
		t.Errorf("sanitized product = %q", prod)
	}
}

// The sanitizer must behave identically regardless of how reads are chunked.
func TestSanitizerChunkBoundaries(t *testing.T) {
	doc := "<a>x &#x1; y &#x41; é€😀 z &#65; \xff end</a>"
	want, _ := io.ReadAll(newSanitizer(strings.NewReader(doc)))
	got, err := io.ReadAll(iotest.OneByteReader(newSanitizer(iotest.OneByteReader(strings.NewReader(doc)))))
	if err != nil || string(got) != string(want) {
		t.Fatalf("chunked output differs:\n got=%q\nwant=%q err=%v", got, want, err)
	}
	if strings.Contains(string(want), "&#x1;") || !strings.Contains(string(want), "&#x41;") || !strings.Contains(string(want), "😀") {
		t.Errorf("unexpected sanitize result: %q", want)
	}
}

func TestEntityExpansionNotResolved(t *testing.T) {
	doc := `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="1"><state state="open"/><service name="&xxe;"/></port></ports></host><runstats/></nmaprun>`
	_, err := Parse(strings.NewReader(doc), func(h model.Host) error {
		if strings.Contains(h.Ports[0].Service.Name, "root:") {
			t.Fatal("external entity was resolved (XXE)")
		}
		return nil
	})
	if err == nil {
		t.Log("parsed without resolving entity")
	}
}

func TestCallbackErrorStopsParsing(t *testing.T) {
	sentinel := errors.New("stop")
	data, _ := os.ReadFile("../../../testdata/nmap/tls.xml")
	n := 0
	_, err := Parse(strings.NewReader(string(data)), func(model.Host) error { n++; return sentinel })
	if !errors.Is(err, sentinel) || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestHostScriptsOfSMBAreAttachedToThePort(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun><host><status state="up" reason="syn-ack"/><address addr="10.0.0.9" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="139"><state state="open"/><service name="netbios-ssn"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
</ports>
<hostscript>
<script id="smb2-security-mode" output="&#xa;  3.1.1: &#xa;    Message signing enabled but not required"/>
<script id="smb-os-discovery" output="OS: Windows Server 2012"/>
<script id="fcrdns" output="FAIL (No PTR record)"/>
<script id="port-states" output="tcp open"/>
</hostscript></host><runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>`
	var got model.Host
	if _, err := Parse(strings.NewReader(xml), func(h model.Host) error { got = h; return nil }); err != nil {
		t.Fatal(err)
	}
	ids := func(p model.Port) []string {
		var out []string
		for _, s := range p.Scripts {
			out = append(out, s.ID)
		}
		return out
	}
	var p445, p139 model.Port
	for _, p := range got.Ports {
		switch p.Number {
		case 445:
			p445 = p
		case 139:
			p139 = p
		}
	}
	if strings.Join(ids(p445), ",") != "smb2-security-mode,smb-os-discovery" || len(p139.Scripts) != 0 {
		t.Errorf("445: %v 139: %v (only SMB host scripts belong on the SMB port, once)", ids(p445), ids(p139))
	}

	// Only NetBIOS open: it takes the results. Nothing open: they are dropped, not misattributed.
	only139 := strings.Replace(strings.Replace(xml, `portid="445"><state state="open"/>`, `portid="445"><state state="closed"/>`, 1), "x", "x", 1)
	_, _ = Parse(strings.NewReader(only139), func(h model.Host) error { got = h; return nil })
	n139 := 0
	for _, p := range got.Ports {
		if p.Number == 139 {
			n139 = len(p.Scripts)
		}
	}
	if n139 != 2 {
		t.Errorf("139 should receive the SMB scripts when 445 is closed, got %d", n139)
	}
}

func TestSSHAlgorithmNamesComeFromTablesWhenOutputOnlyHasCounts(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun><host><status state="up" reason="syn-ack"/><address addr="10.0.0.9" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/>
<script id="ssh2-enum-algos" output="&#xa;  kex_algorithms: (2)&#xa;  encryption_algorithms: (1)"><table key="kex_algorithms"><elem>curve25519-sha256</elem><elem>diffie-hellman-group14-sha1</elem></table><table key="encryption_algorithms"><elem>3des-cbc</elem></table></script>
</port></ports></host><runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>`
	var got model.Host
	if _, err := Parse(strings.NewReader(xml), func(h model.Host) error { got = h; return nil }); err != nil {
		t.Fatal(err)
	}
	out := got.Ports[0].Scripts[0].Output
	for _, want := range []string{"kex_algorithms: (2)", "diffie-hellman-group14-sha1", "3des-cbc"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing from %q", want, out)
		}
	}
}
