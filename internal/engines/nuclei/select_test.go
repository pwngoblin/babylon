package nuclei

import (
	"reflect"
	"sort"
	"testing"

	"babylon/internal/policy"
	"babylon/internal/store"
)

func tpl(path string, sev string, protos []string, tags []string, product string) store.NucleiTemplate {
	return store.NucleiTemplate{Path: path, ID: path, Severity: sev, Protocols: protos, Tags: tags, Product: product}
}

func testIndex(t *testing.T, flags policy.Flags) (*Index, []store.NucleiTemplate) {
	t.Helper()
	all := []store.NucleiTemplate{
		tpl("tech/apache-detect.yaml", "info", []string{"http"}, []string{"tech", "apache"}, ""),
		tpl("tech/nginx-version.yaml", "info", []string{"http"}, []string{"tech", "nginx"}, ""),
		tpl("cve/apache-cve.yaml", "high", []string{"http"}, []string{"cve", "apache"}, "http_server"),
		tpl("cve/nginx-cve.yaml", "high", []string{"http"}, []string{"cve", "nginx"}, ""),
		tpl("cve/vsftpd.yaml", "high", []string{"tcp"}, []string{"cve", "ftp", "vsftpd"}, "vsftpd"),
		tpl("net/redis-noauth.yaml", "high", []string{"tcp"}, []string{"redis", "unauth", "misconfig"}, ""),
		tpl("mis/headers.yaml", "info", []string{"http"}, []string{"misconfig", "headers"}, ""),
		tpl("mis/exposed-env.yaml", "high", []string{"http"}, []string{"exposure", "config"}, ""),
		tpl("mis/low-exposure.yaml", "low", []string{"http"}, []string{"exposure"}, ""),
		// must NEVER be selectable:
		tpl("bad/dos.yaml", "high", []string{"http"}, []string{"dos", "apache"}, ""),
		tpl("bad/fuzz.yaml", "high", []string{"http"}, []string{"fuzz", "apache"}, ""),
		tpl("bad/intrusive.yaml", "high", []string{"http"}, []string{"intrusive", "apache"}, ""),
		tpl("bad/oast.yaml", "high", []string{"http"}, []string{"oast", "apache"}, ""),
		tpl("bad/bruteforce.yaml", "high", []string{"http"}, []string{"bruteforce", "apache"}, ""),
		tpl("bad/headless.yaml", "high", []string{"headless"}, []string{"apache", "misconfig"}, ""),
		tpl("bad/code.yaml", "high", []string{"http", "code"}, []string{"apache"}, ""),
		tpl("bad/js.yaml", "high", []string{"javascript"}, []string{"redis"}, ""),
		tpl("bad/workflow.yaml", "info", []string{"workflow"}, []string{"apache"}, ""),
		tpl("login/apache-login.yaml", "high", []string{"http"}, []string{"default-login", "apache"}, ""),
	}
	res, err := policy.Resolve(policy.TemplateBasic, flags)
	if err != nil {
		t.Fatal(err)
	}
	return NewIndex(all, res.Nuclei), all
}

func all(ix *Index, proto string, tokens []string, p Profile) []string {
	return ix.ForTokens(proto, tokens, p)
}

func TestDenyListedTemplatesAreUnreachable(t *testing.T) {
	ix, _ := testIndex(t, policy.Flags{})
	denied := map[string]bool{}
	for _, p := range []string{"bad/dos.yaml", "bad/fuzz.yaml", "bad/intrusive.yaml", "bad/oast.yaml", "bad/bruteforce.yaml",
		"bad/headless.yaml", "bad/code.yaml", "bad/js.yaml", "bad/workflow.yaml", "login/apache-login.yaml"} {
		denied[p] = true
	}
	// Try every selection entry point with every token that matches them.
	sets := [][]string{
		ix.Detect(Profile{DetectTags: []string{"tech", "apache", "redis", "misconfig"}}),
		all(ix, "http", []string{"apache", "redis", "nginx", "misconfig", "ftp"}, ProfileFor(policy.TemplateFullUnauth)),
		all(ix, "net", []string{"apache", "redis", "ftp", "vsftpd", "misconfig"}, ProfileFor(policy.TemplateFullUnauth)),
	}
	for _, s := range sets {
		for _, p := range s {
			if denied[p] {
				t.Errorf("denied template %s was selected", p)
			}
		}
	}
	if ix.Removed != 10 {
		t.Errorf("removed=%d, want 10", ix.Removed)
	}
	// default-login templates are only reachable with the explicit opt-in.
	ix2, _ := testIndex(t, policy.Flags{CheckDefaultCreds: true})
	if !contains(all(ix2, "http", []string{"apache"}, ProfileFor(policy.TemplateBasic)), "login/apache-login.yaml") {
		t.Error("default-login template must be selectable with --check-default-creds")
	}
	if ix2.Removed != 9 {
		t.Errorf("removed with creds flag=%d, want 9", ix2.Removed)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestSelectionIsServiceAware(t *testing.T) {
	ix, _ := testIndex(t, policy.Flags{})
	p := ProfileFor(policy.TemplateBasic)

	if got := ix.Detect(p); !reflect.DeepEqual(got, []string{"tech/apache-detect.yaml", "tech/nginx-version.yaml"}) {
		t.Errorf("detect=%v", got)
	}
	// Apache: its CVE template + generic misconfig/exposure >= medium; NOT nginx, NOT ftp, and NOT detect templates again.
	got := ix.ForTokens("http", []string{"apache"}, p)
	want := []string{"cve/apache-cve.yaml", "mis/exposed-env.yaml"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("apache http = %v, want %v", got, want)
	}
	// Full template widens generic coverage to low/info severity.
	full := ix.ForTokens("http", []string{"apache"}, ProfileFor(policy.TemplateFullUnauth))
	if !contains(full, "mis/headers.yaml") || !contains(full, "mis/low-exposure.yaml") {
		t.Errorf("full profile should include low-severity generic checks: %v", full)
	}
	// Network service: only tcp/ssl templates for its tokens; no generic web checks.
	net := ix.ForTokens("net", []string{"redis"}, p)
	if !reflect.DeepEqual(net, []string{"net/redis-noauth.yaml"}) {
		t.Errorf("redis net = %v", net)
	}
	ftp := ix.ForTokens("net", []string{"ftp", "vsftpd"}, p)
	if !reflect.DeepEqual(ftp, []string{"cve/vsftpd.yaml"}) {
		t.Errorf("ftp net = %v", ftp)
	}
	// Stop tokens select nothing by themselves.
	if got := ix.ForTokens("net", []string{"tcp", "unknown", "http"}, p); len(got) != 0 {
		t.Errorf("stop tokens selected %v", got)
	}
	// Product metadata match (template tagged differently from token).
	if got := ix.ForTokens("http", []string{"http_server"}, ProfileFor("none")); !contains(got, "cve/apache-cve.yaml") {
		t.Errorf("metadata product match failed: %v", got)
	}
}

func TestTokensForService(t *testing.T) {
	cases := []struct {
		name, product string
		cpes          []string
		want          []string
	}{
		{"http", "Apache httpd", []string{"cpe:/a:apache:http_server:2.4.49"}, []string{"http-server", "apache"}},
		{"http", "nginx", []string{"cpe:/a:igor_sysoev:nginx:1.16.0"}, []string{"nginx", "igor-sysoev"}},
		{"redis", "Redis key-value store", []string{"cpe:/a:redislabs:redis:5.0.14"}, []string{"redis", "redislabs"}},
		{"ftp", "vsftpd", []string{"cpe:2.3:a:vsftpd_project:vsftpd:3.0.2:*:*:*:*:*:*:*"}, []string{"vsftpd", "vsftpd-project", "ftp"}},
		{"unknown", "", nil, nil},
		{"ssh", "OpenSSH", nil, []string{"openssh", "ssh"}},
	}
	for _, c := range cases {
		got := TokensForService(c.name, c.product, c.cpes)
		sort.Strings(got)
		w := append([]string(nil), c.want...)
		sort.Strings(w)
		if len(got) == 0 && len(w) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, w) {
			t.Errorf("%s/%s: got %v want %v", c.name, c.product, got, w)
		}
	}
}
