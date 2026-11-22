package nuclei

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"babylon/internal/model"
	"babylon/internal/policy"
)

func parseFixture(t *testing.T) map[string][]Result {
	t.Helper()
	f, err := os.Open("../../../testdata/nuclei/results.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][]Result{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		r, err := ParseLine(sc.Bytes(), "raw/results.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		out[r.Finding.EngineRef] = append(out[r.Finding.EngineRef], r)
	}
	return out
}

func TestParseRealNucleiResults(t *testing.T) {
	res := parseFixture(t)

	// version-only CVE template (tagged passive, extractor "version") -> tentative / version
	v := res["CVE-2021-30047"][0].Finding
	if v.Confidence != model.ConfTentative || v.Detection != "version" || v.Severity != "high" ||
		v.CVSS == nil || *v.CVSS != 7.5 || len(v.CVEs) != 1 || v.CVEs[0] != "CVE-2021-30047" ||
		v.Address != "127.0.0.1" || v.Port != 12121 || v.Family != "Known vulnerabilities" || v.Remediation == "" || v.Solution != "VendorFix" ||
		v.EPSS == nil {
		t.Fatalf("cve finding: %+v", v)
	}
	// exposure -> confirmed, with request/response evidence
	c := res["configuration-listing"][0].Finding
	if c.Confidence != model.ConfConfirmed || c.Severity != "medium" || c.Family != "Exposures" ||
		!strings.Contains(c.Evidence, "matched at: http://127.0.0.1:18083/config/") || !strings.Contains(c.Evidence, "--- response ---") {
		t.Fatalf("exposure: %+v", c)
	}
	// misconfig high -> confirmed
	if d := res["dvwa-setup"][0].Finding; d.Severity != "high" || d.Confidence != model.ConfConfirmed {
		t.Fatalf("dvwa: %+v", d)
	}
	// info detections are facts, and yield technology tokens
	n := res["nginx-version"][0]
	if n.Finding.Confidence != model.ConfConfirmed || !n.Informational || n.Finding.Family != "Service detection" ||
		!strings.Contains(n.Finding.Evidence, "nginx/1.16.0") {
		t.Fatalf("nginx-version: %+v", n.Finding)
	}
	if toks := TechTokens(n.Tags); len(toks) != 1 || toks[0] != "nginx" {
		t.Fatalf("tech tokens = %v", toks)
	}
	// many matcher rows for one template share ONE fingerprint
	h := res["http-missing-security-headers"]
	if len(h) < 2 || h[0].Finding.Fingerprint != h[1].Finding.Fingerprint {
		t.Fatalf("header rows must share a fingerprint: %d rows", len(h))
	}
	// distinct targets must not share one
	if h[0].Finding.Fingerprint == res["configuration-listing"][0].Finding.Fingerprint {
		t.Fatal("unrelated findings share a fingerprint")
	}
}

func TestParseLineErrors(t *testing.T) {
	if _, err := ParseLine([]byte("not json"), ""); err == nil {
		t.Error("bad json must error")
	}
	if _, err := ParseLine([]byte(`{"info":{"name":"x"}}`), ""); err == nil {
		t.Error("missing template-id must error")
	}
	r, err := ParseLine([]byte(`{"template-id":"t","info":{"severity":"weird"},"ip":"10.0.0.1","port":"80"}`), "")
	if err != nil || r.Finding.Severity != "info" || r.Finding.Title != "t" {
		t.Fatalf("defaults: %+v err=%v", r.Finding, err)
	}
}

func TestEvidenceIsRedacted(t *testing.T) {
	line := `{"template-id":"leak","info":{"name":"x","severity":"high","tags":["exposure"]},"ip":"10.0.0.1","port":"80","matched-at":"http://10.0.0.1/",` +
		`"request":"GET / HTTP/1.1\r\nAuthorization: Bearer SECRET123\r\n","response":"HTTP/1.1 200\r\nSet-Cookie: sid=COOKIEVAL\r\n\r\npassword=hunter2"}`
	r, err := ParseLine([]byte(line), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"SECRET123", "COOKIEVAL", "hunter2"} {
		if strings.Contains(r.Finding.Evidence, leak) {
			t.Errorf("%s leaked into evidence", leak)
		}
	}
}

func TestArgsAreSafeAndExplicit(t *testing.T) {
	for _, creds := range []bool{false, true} {
		res, _ := policy.Resolve(policy.TemplateBasic, policy.Flags{CheckDefaultCreds: creds})
		args, err := Args(res.Nuclei, "/t/targets.txt", "/t/templates.txt", 150)
		if err != nil {
			t.Fatal(err)
		}
		joined := " " + strings.Join(args, " ") + " "
		for _, want := range []string{" -t /t/templates.txt ", " -l /t/targets.txt ", " -duc ", " -ni ", " -rl 150 ", "-exclude-type headless,code,javascript"} {
			if !strings.Contains(joined, want) {
				t.Errorf("args missing %q: %s", want, joined)
			}
		}
		if strings.Contains(joined, " -c ") || strings.Contains(joined, " -tags ") || strings.Contains(joined, " -as ") {
			t.Errorf("must not use -c/-tags/-as: %s", joined)
		}
		for _, d := range policy.DeniedNucleiTags {
			if !strings.Contains(joined, d) {
				t.Errorf("denied tag %q missing from -etags", d)
			}
		}
		if hasLogin := strings.Contains(joined, "default-login"); hasLogin == creds {
			t.Errorf("creds=%v but default-login excluded=%v", creds, hasLogin)
		}
	}
	if _, err := Args(policy.NucleiConfig{}, "a", "b", 1); err == nil {
		t.Error("disabled config must be refused")
	}
	bad := policy.NucleiConfig{Enabled: true, ExcludeTags: []string{"dos"}, ExcludeProtocols: policy.DeniedNucleiProtocols}
	if _, err := Args(bad, "a", "b", 1); err == nil {
		t.Error("config missing mandatory exclusions must be refused")
	}
}
