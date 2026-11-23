package native

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"babylon/internal/store"
)

func tcpEnv(addr net.Addr) (*Env, int) {
	h, p, _ := net.SplitHostPort(addr.String())
	port := 0
	for _, ch := range p {
		port = port*10 + int(ch-'0')
	}
	return &Env{Address: h, Services: []store.ServiceInfo{{Address: h, Port: port, Proto: "tcp"}}}, port
}

func serveTCP(t *testing.T, handle func(net.Conn)) net.Addr {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
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
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return l.Addr()
}

func TestMQTTAnonymous(t *testing.T) {
	for _, tc := range []struct {
		rc   byte
		flag bool
	}{{0x00, true}, {0x05, false}} {
		addr := serveTCP(t, func(c net.Conn) {
			buf := make([]byte, 64)
			n, _ := c.Read(buf)
			if n < 14 || buf[0] != 0x10 {
				t.Errorf("unexpected packet: % x", buf[:n])
			}
			c.Write([]byte{0x20, 0x02, 0x00, tc.rc})
		})
		env, port := tcpEnv(addr)
		chk := tcpCheck("mqtt-anonymous", "x", []int{port}, mqttRun)
		got := chk.Run(env)
		if tc.flag && len(got) != 1 || !tc.flag && len(got) != 0 {
			t.Errorf("rc %d: got %+v", tc.rc, got)
		}
	}
}

func TestZooKeeperOpen(t *testing.T) {
	addr := serveTCP(t, func(c net.Conn) {
		buf := make([]byte, 8)
		n, _ := c.Read(buf)
		if string(buf[:n]) != "srvr" {
			t.Errorf("only srvr may be sent, got %q", buf[:n])
		}
		c.Write([]byte("Zookeeper version: 3.8.0\nMode: standalone\n"))
	})
	env, port := tcpEnv(addr)
	if got := tcpCheck("z", "z", []int{port}, zookeeperRun).Run(env); len(got) != 1 {
		t.Errorf("got %+v", got)
	}
	closed := serveTCP(t, func(c net.Conn) { c.Write([]byte("nope\n")) })
	env, port = tcpEnv(closed)
	if got := tcpCheck("z", "z", []int{port}, zookeeperRun).Run(env); len(got) != 0 {
		t.Errorf("non-zookeeper must not be flagged: %+v", got)
	}
}

func TestRsyncModules(t *testing.T) {
	addr := serveTCP(t, func(c net.Conn) {
		c.Write([]byte("@RSYNCD: 31.0\n"))
		r := bufio.NewReader(c)
		r.ReadString('\n') // client greeting
		line, _ := r.ReadString('\n')
		if strings.TrimSpace(line) != "" {
			t.Errorf("only an empty module request (list) may be sent, got %q", line)
		}
		c.Write([]byte("backup\tNightly backups\npublic\tPublic files\n@RSYNCD: EXIT\n"))
	})
	env, port := tcpEnv(addr)
	got := tcpCheck("r", "r", []int{port}, rsyncRun).Run(env)
	if len(got) != 1 || !strings.Contains(got[0].Evidence, "backup") {
		t.Errorf("got %+v", got)
	}
}

func TestInfraAPIProbes(t *testing.T) {
	cases := []struct{ id, path, body string }{
		{"consul-api-open", "/v1/agent/self", `{"Config":{"NodeName":"n1"}}`},
		{"docker-registry-open", "/v2/_catalog", `{"repositories":["app"]}`},
		{"yarn-rm-open", "/ws/v1/cluster/info", `{"clusterInfo":{"id":1}}`},
		{"solr-admin-open", "/solr/admin/info/system", `{"solr_home":"/var/solr"}`},
		{"jupyter-open", "/api/kernelspecs", `{"default":"python3","kernelspecs":{}}`},
		{"kibana-open", "/api/status", `{"version":{"number":"8.0"},"status":{}}`},
		{"prometheus-open", "/api/v1/status/buildinfo", `{"status":"success","data":{"goVersion":"go1.21"}}`},
	}
	byID := map[string]apiProbe{}
	for _, p := range infraAPIProbes {
		byID[p.id] = p
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("only GET allowed, got %s", r.Method)
			}
			if r.URL.Path == c.path {
				w.Write([]byte(c.body))
				return
			}
			w.WriteHeader(404)
		}))
		env, port := envForServer(t, srv, "")
		if got := retarget(byID[c.id], port).Run(env); len(got) != 1 {
			t.Errorf("%s: want 1 finding, got %+v", c.id, got)
		}
		srv.Close()
	}
	for id := range byID {
		found := false
		for _, c := range cases {
			found = found || c.id == id
		}
		if id != "k8s-api-anonymous" && !found {
			t.Errorf("probe %s has no test", id)
		}
	}
}

func TestInfraChecksAreProbeLevel(t *testing.T) {
	for _, c := range infraChecks() {
		if c.Safety.String() == "read-only" {
			t.Errorf("%s must be probe-level", c.ID)
		}
	}
}
