package nuclei

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func TestParseTemplateVariants(t *testing.T) {
	m, err := ParseTemplate("network/cves/2021/CVE-2021-30047.yaml", []byte(`
id: CVE-2021-30047
info:
  name: vsftpd < 3.0.3 - DoS
  severity: HIGH
  tags: cve,cve2021,network,FTP , vsftpd
  classification:
    cve-id: CVE-2021-30047
    cvss-score: 7.5
  metadata:
    vendor: vsftpd_project
    product: vsftpd
    verified: true
tcp:
  - inputs: [{data: "x"}]
`))
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "CVE-2021-30047" || m.Severity != "high" || len(m.Protocols) != 1 || m.Protocols[0] != "tcp" ||
		m.Product != "vsftpd" || !m.Verified || m.CVSS == nil || *m.CVSS != 7.5 || len(m.CVEs) != 1 {
		t.Fatalf("%+v", m)
	}
	want := map[string]bool{"cve": true, "cve2021": true, "network": true, "ftp": true, "vsftpd": true}
	for _, tag := range m.Tags {
		delete(want, tag)
	}
	if len(want) != 0 {
		t.Fatalf("tags not normalized (comma string, case, spaces): %v got %v", want, m.Tags)
	}

	// list-style tags, legacy `requests:` key, multiple CVEs
	m, err = ParseTemplate("http/x.yaml", []byte("id: x\ninfo:\n  name: n\n  severity: bogus\n  tags: [Tech, Apache]\n  classification:\n    cve-id: [CVE-1-1, cve-2-2]\nrequests:\n  - method: GET\n"))
	if err != nil || m.Severity != "info" || m.Protocols[0] != "http" || len(m.CVEs) != 2 || m.CVEs[1] != "CVE-2-2" {
		t.Fatalf("%+v err=%v", m, err)
	}
	if _, err := ParseTemplate("x.yaml", []byte("info: {name: n}")); err == nil {
		t.Error("template without id must be rejected")
	}
	if _, err := ParseTemplate("x.yaml", []byte(":\n\t- bad yaml [")); err == nil {
		t.Error("invalid yaml must error")
	}
}

// Integration: index a real templates checkout when BABYLON_TEST_TEMPLATES is
// set (skipped otherwise). Logs distribution used to calibrate selection.
func TestIndexRealTemplates(t *testing.T) {
	root := os.Getenv("BABYLON_TEST_TEMPLATES")
	if root == "" {
		t.Skip("set BABYLON_TEST_TEMPLATES to a nuclei-templates checkout")
	}
	start := time.Now()
	proto := map[string]int{}
	tags := map[string]int{}
	var n int
	parsed, skipped, err := IndexDir(root, func(m Meta) {
		n++
		for _, p := range m.Protocols {
			proto[p]++
		}
		for _, tg := range m.Tags {
			tags[tg]++
		}
	})
	if err != nil || parsed < 5000 {
		t.Fatalf("parsed=%d skipped=%d err=%v", parsed, skipped, err)
	}
	t.Logf("indexed %d templates (%d skipped) in %s", parsed, skipped, time.Since(start).Round(time.Millisecond))
	t.Logf("protocols: %v", proto)
	type kv struct {
		k string
		v int
	}
	var top []kv
	for _, k := range []string{"tech", "exposure", "misconfig", "cve", "panel", "default-login", "exposed-panels", "detect", "discovery", "oast", "fuzz", "dos", "intrusive", "bruteforce", "headless", "wordpress", "apache", "nginx", "redis", "ssh", "ftp", "xss", "sqli", "rce", "lfi", "unauth", "takeover", "token", "backup", "config"} {
		top = append(top, kv{k, tags[k]})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].v > top[j].v })
	t.Logf("tag counts: %v", top)
}

func TestIndexDirFollowsSymlinkedRoot(t *testing.T) {
	real := t.TempDir()
	os.MkdirAll(filepath.Join(real, "http"), 0o755)
	os.WriteFile(filepath.Join(real, "http", "a.yaml"), []byte("id: a\ninfo:\n  name: A\n  severity: low\nhttp:\n  - method: GET\n"), 0o644)
	link := filepath.Join(t.TempDir(), "templates")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	var got []string
	parsed, _, err := IndexDir(link, func(m Meta) { got = append(got, m.Path) })
	if err != nil || parsed != 1 || got[0] != "http/a.yaml" {
		t.Fatalf("parsed=%d got=%v err=%v", parsed, got, err)
	}
}
