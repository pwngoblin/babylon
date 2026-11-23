package native

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"babylon/internal/policy"
	"babylon/internal/store"
)

// Read-only HTTP probes for administrative APIs that must never be reachable
// without authentication. Each sends one or two plain GET requests with a short
// timeout and a small response cap, never a write, and only runs when active
// probes are allowed (--allow-active).

type apiProbe struct {
	id, name, title string
	ports           []int
	schemes         []string
	path            string
	match           func(status int, body string) bool
	severity        string
	synopsis, desc  string
	fix             string
}

func has2xx(status int) bool { return status == 200 }

var apiProbes = []apiProbe{
	{id: "docker-api-open", name: "Docker Engine API reachable without authentication", title: "Unauthenticated Docker Engine API exposed",
		ports: []int{2375}, schemes: []string{"http"}, path: "/version",
		match:    func(s int, b string) bool { return has2xx(s) && strings.Contains(b, `"ApiVersion"`) },
		severity: "critical", synopsis: "The Docker API answers on the network without authentication.",
		desc: "Anyone who can reach this port can start privileged containers and take over the host.",
		fix:  "Do not expose the Docker TCP socket. Bind it to localhost or a unix socket, or require mutual TLS (dockerd --tlsverify)."},
	{id: "kubelet-ro-open", name: "Kubelet read-only API exposed", title: "Unauthenticated Kubernetes Kubelet read-only API exposed",
		ports: []int{10255}, schemes: []string{"http"}, path: "/pods",
		match:    func(s int, b string) bool { return has2xx(s) && strings.Contains(b, `"PodList"`) },
		severity: "high", synopsis: "The Kubelet read-only port lists pods without authentication.",
		desc: "Pod specifications leak environment variables, image names and cluster layout.",
		fix:  "Disable the read-only port (readOnlyPort: 0 in the kubelet config) and firewall kubelet ports."},
	{id: "kubelet-api-open", name: "Kubelet API accepts anonymous requests", title: "Unauthenticated Kubernetes Kubelet API exposed",
		ports: []int{10250}, schemes: []string{"https"}, path: "/pods",
		match:    func(s int, b string) bool { return has2xx(s) && strings.Contains(b, `"PodList"`) },
		severity: "critical", synopsis: "The Kubelet API serves pod data to anonymous callers.",
		desc: "An anonymous kubelet allows command execution inside pods through its exec endpoints.",
		fix:  "Set authentication.anonymous.enabled=false and use webhook authorization on the kubelet."},
	{id: "elasticsearch-open", name: "Elasticsearch accessible without authentication", title: "Unauthenticated Elasticsearch exposed",
		ports: []int{9200}, schemes: []string{"http", "https"}, path: "/",
		match:    func(s int, b string) bool { return has2xx(s) && strings.Contains(b, `"cluster_name"`) },
		severity: "high", synopsis: "Elasticsearch answers API requests without credentials.",
		desc: "Anyone on the network can read, modify or delete indexed data.",
		fix:  "Enable security (xpack.security.enabled: true), require authentication and TLS, and bind to a private interface."},
	{id: "couchdb-open", name: "CouchDB accessible without authentication", title: "Unauthenticated CouchDB exposed",
		ports: []int{5984}, schemes: []string{"http"}, path: "/_all_dbs",
		match:    func(s int, b string) bool { return has2xx(s) && strings.HasPrefix(strings.TrimSpace(b), "[") },
		severity: "high", synopsis: "CouchDB lists its databases without credentials.",
		desc: "Anonymous access exposes stored documents and may allow admin takeover.",
		fix:  "Configure an admin user (require_valid_user = true) and bind to a private interface."},
	{id: "etcd-open", name: "etcd API accessible without authentication", title: "Unauthenticated etcd API exposed",
		ports: []int{2379}, schemes: []string{"http"}, path: "/version",
		match:    func(s int, b string) bool { return has2xx(s) && strings.Contains(b, `"etcdserver"`) },
		severity: "high", synopsis: "etcd answers client requests without authentication.",
		desc: "etcd often stores cluster secrets; open access exposes all of them.",
		fix:  "Enable client certificate authentication and firewall the client port."},
}

func openPort(e *Env, ports []int) []store.ServiceInfo {
	var out []store.ServiceInfo
	for _, s := range e.Services {
		if s.Proto != "tcp" {
			continue
		}
		for _, p := range ports {
			if s.Port == p {
				out = append(out, s)
			}
		}
	}
	return out
}

func probeCheck(p apiProbe) Check {
	return Check{
		ID: p.id, Name: p.name, Family: "Misconfiguration", Safety: policy.SafetyProbe,
		Needs: func(e *Env) string {
			if len(openPort(e, p.ports)) == 0 {
				return fmt.Sprintf("no open service on port %v", p.ports)
			}
			return ""
		},
		Run: func(e *Env) []Finding {
			var out []Finding
			for _, s := range openPort(e, p.ports) {
				for _, scheme := range p.schemes {
					status, body, err := httpProbe(scheme, e.Address, s.Port, p.path)
					if err != nil || !p.match(status, body) {
						continue
					}
					out = append(out, Finding{Port: s.Port, Proto: "tcp", Title: p.title, Severity: p.severity,
						Synopsis: p.synopsis, Description: p.desc, Remediation: p.fix,
						Evidence: fmt.Sprintf("GET %s://%s:%d%s -> %d\n%s", scheme, e.Address, s.Port, p.path, status, snippet(body, 300))})
					break
				}
			}
			return out
		},
	}
}

var hstsMissing = Check{
	ID: "http-hsts-missing", Name: "HTTPS site without Strict-Transport-Security", Family: "Misconfiguration", Safety: policy.SafetyProbe,
	Needs: func(e *Env) string {
		if len(httpsServices(e)) == 0 {
			return "no HTTPS service"
		}
		return ""
	},
	Run: func(e *Env) []Finding {
		var out []Finding
		for _, s := range httpsServices(e) {
			hdr, status, err := httpHeaders("https", e.Address, s.Port, "/")
			if err != nil || status >= 500 {
				continue
			}
			if hdr.Get("Strict-Transport-Security") == "" {
				out = append(out, Finding{Port: s.Port, Proto: "tcp", Title: "HTTPS service does not send Strict-Transport-Security", Severity: "low",
					Synopsis:    "Browsers are not told to insist on HTTPS for this site.",
					Description: "Without HSTS, a network attacker can strip HTTPS from a first visit (downgrade attack).",
					Remediation: "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.",
					Evidence:    fmt.Sprintf("GET https://%s:%d/ -> %d, no Strict-Transport-Security header", e.Address, s.Port, status),
					Confidence:  "firm"})
			}
		}
		return out
	},
}

func httpsServices(e *Env) []store.ServiceInfo {
	var out []store.ServiceInfo
	for _, s := range e.Services {
		if s.Proto == "tcp" && (s.Tunnel == "ssl" || strings.EqualFold(s.Name, "https")) {
			out = append(out, s)
		}
	}
	return out
}

var probeClient = &http.Client{
	Timeout: 6 * time.Second,
	Transport: &http.Transport{
		// Probes identify exposed services; they send no credentials or data, so
		// certificate trust is irrelevant (and kubelet/Docker certs are self-signed).
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func httpHeaders(scheme, host string, port int, path string) (http.Header, int, error) {
	resp, err := probeClient.Get(scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + path)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.Header, resp.StatusCode, nil
}

func httpProbe(scheme, host string, port int, path string) (int, string, error) {
	resp, err := probeClient.Get(scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + path)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, string(b), nil
}

func snippet(s string, n int) string {
	s = strings.ToValidUTF8(strings.TrimSpace(s), "")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

func probeChecks() []Check {
	out := make([]Check, 0, len(apiProbes)+1)
	for _, p := range apiProbes {
		out = append(out, probeCheck(p))
	}
	return append(out, hstsMissing)
}
