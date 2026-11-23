package native

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"babylon/internal/store"
)

func envForServer(t *testing.T, srv *httptest.Server, tunnel string) (*Env, int) {
	t.Helper()
	host, p, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://"))
	port, _ := strconv.Atoi(p)
	return &Env{Address: host, Services: []store.ServiceInfo{{Address: host, Port: port, Proto: "tcp", Name: "http", Tunnel: tunnel}}}, port
}

// retarget points a probe at the test server's port instead of its well-known one.
func retarget(p apiProbe, port int) Check { p.ports = []int{port}; return probeCheck(p) }

func probeByID(id string) apiProbe {
	for _, p := range apiProbes {
		if p.id == id {
			return p
		}
	}
	panic(id)
}

func TestAPIProbesFlagOpenServicesOnly(t *testing.T) {
	cases := []struct {
		id, path, body string
		open           bool
	}{
		{"docker-api-open", "/version", `{"Platform":{"Name":"Docker Engine"},"ApiVersion":"1.43"}`, true},
		{"docker-api-open", "/version", `{"message":"unauthorized"}`, false},
		{"elasticsearch-open", "/", `{"name":"n","cluster_name":"docker-cluster","tagline":"You Know, for Search"}`, true},
		{"couchdb-open", "/_all_dbs", `["_users","orders"]`, true},
		{"etcd-open", "/version", `{"etcdserver":"3.5.0","etcdcluster":"3.5.0"}`, true},
		{"kubelet-ro-open", "/pods", `{"kind":"PodList","items":[]}`, true},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("probes must only GET, got %s", r.Method)
			}
			if r.URL.Path == c.path || (c.path == "/" && r.URL.Path == "/") {
				if !c.open {
					w.WriteHeader(401)
				}
				w.Write([]byte(c.body))
				return
			}
			w.WriteHeader(404)
		}))
		env, port := envForServer(t, srv, "")
		chk := retarget(probeByID(c.id), port)
		if reason := chk.Needs(env); reason != "" {
			t.Fatalf("%s needs: %s", c.id, reason)
		}
		got := chk.Run(env)
		srv.Close()
		if c.open && (len(got) != 1 || got[0].Port != port || !strings.Contains(got[0].Evidence, "->")) {
			t.Errorf("%s: want 1 finding, got %+v", c.id, got)
		}
		if !c.open && len(got) != 0 {
			t.Errorf("%s: closed/authenticated service must not be flagged: %+v", c.id, got)
		}
	}
}

func TestProbeSkippedWhenPortClosed(t *testing.T) {
	chk := probeCheck(probeByID("docker-api-open"))
	if r := chk.Needs(&Env{}); r == "" {
		t.Error("check must record a skip reason when its port is not open")
	}
}

func TestProbesRequireActiveSafety(t *testing.T) {
	for _, c := range probeChecks() {
		if c.Safety.String() == "read-only" {
			t.Errorf("%s sends requests and must be a probe-level check", c.ID)
		}
	}
}

func TestHSTSMissing(t *testing.T) {
	plain := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hi")) }))
	defer plain.Close()
	env, _ := envForServer(t, plain, "ssl")
	if got := hstsMissing.Run(env); len(got) != 1 || got[0].Severity != "low" {
		t.Errorf("missing HSTS: %+v", got)
	}
	good := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}))
	defer good.Close()
	env, _ = envForServer(t, good, "ssl")
	if got := hstsMissing.Run(env); len(got) != 0 {
		t.Errorf("HSTS present must not be flagged: %+v", got)
	}
}
