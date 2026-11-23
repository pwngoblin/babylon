package native

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"babylon/internal/policy"
	"babylon/internal/store"
)

// Infrastructure exposure checks. Like the API probes, each one only reads: a
// plain GET, or a short protocol handshake that asks the service to describe
// itself. Nothing is written, no credentials are tried, and every check is
// probe-level (only runs with --allow-active).

var infraAPIProbes = []apiProbe{
	{id: "consul-api-open", name: "Consul API reachable without ACLs", title: "Unauthenticated HashiCorp Consul API exposed",
		ports: []int{8500}, schemes: []string{"http"}, path: "/v1/agent/self",
		match: func(s int, b string) bool {
			return has2xx(s) && strings.Contains(b, `"Config"`) && strings.Contains(b, `"NodeName"`)
		},
		severity: "high", synopsis: "The Consul agent API answers without an ACL token.",
		desc: "With script checks enabled, anyone who can register a service check can run commands on the host. The API also reveals the service map and key/value data.",
		fix:  "Enable ACLs with default_policy=deny, disable script checks, and bind the API to a private interface."},
	{id: "docker-registry-open", name: "Docker registry catalog readable without authentication", title: "Unauthenticated Docker Registry exposed",
		ports: []int{5000}, schemes: []string{"http", "https"}, path: "/v2/_catalog",
		match:    func(s int, b string) bool { return has2xx(s) && strings.Contains(b, `"repositories"`) },
		severity: "medium", synopsis: "The container registry lists its images to anyone.",
		desc: "Images often contain source code, configuration and embedded secrets; an open registry also allows pushing tampered images when writes are not restricted.",
		fix:  "Require authentication (token or htpasswd) and TLS on the registry."},
	{id: "yarn-rm-open", name: "Hadoop YARN ResourceManager reachable", title: "Hadoop YARN ResourceManager exposed without authentication",
		ports: []int{8088}, schemes: []string{"http"}, path: "/ws/v1/cluster/info",
		match:    func(s int, b string) bool { return has2xx(s) && strings.Contains(b, `"clusterInfo"`) },
		severity: "critical", synopsis: "The YARN ResourceManager REST API answers unauthenticated requests.",
		desc: "An open ResourceManager lets anyone submit applications, which is remote code execution on the cluster and is widely abused by botnets.",
		fix:  "Enable Kerberos/simple authentication for the cluster and firewall the ResourceManager ports."},
	{id: "solr-admin-open", name: "Apache Solr admin API reachable", title: "Unauthenticated Apache Solr admin API exposed",
		ports: []int{8983}, schemes: []string{"http"}, path: "/solr/admin/info/system?wt=json",
		match:    func(s int, b string) bool { return has2xx(s) && strings.Contains(b, `"solr_home"`) },
		severity: "high", synopsis: "Solr's admin API returns system information without authentication.",
		desc: "Open Solr exposes indexed data and has a long history of remote-code-execution flaws reachable through its admin and config APIs.",
		fix:  "Enable the Solr authentication/authorization plugin and bind Solr to a private interface."},
	{id: "jupyter-open", name: "Jupyter server without a token or password", title: "Unauthenticated Jupyter server exposed",
		ports: []int{8888}, schemes: []string{"http", "https"}, path: "/api/kernelspecs",
		match:    func(s int, b string) bool { return has2xx(s) && strings.Contains(b, `"kernelspecs"`) },
		severity: "critical", synopsis: "A Jupyter server lets anyone use its kernels.",
		desc: "Jupyter runs arbitrary code by design; without a token or password, anyone on the network can execute commands as the user running it.",
		fix:  "Start Jupyter with token or password authentication, bind to localhost, and put it behind an authenticated proxy."},
	{id: "kibana-open", name: "Kibana reachable without login", title: "Kibana exposed without authentication",
		ports: []int{5601}, schemes: []string{"http", "https"}, path: "/api/status",
		match: func(s int, b string) bool {
			return has2xx(s) && strings.Contains(b, `"version"`) && strings.Contains(b, `"status"`)
		},
		severity: "medium", synopsis: "Kibana's status API answers without credentials.",
		desc: "An open Kibana usually means the indexed data behind it is readable by anyone on the network.",
		fix:  "Enable Elastic security so Kibana requires a login, and restrict network access."},
	{id: "prometheus-open", name: "Prometheus API reachable without authentication", title: "Unauthenticated Prometheus API exposed",
		ports: []int{9090}, schemes: []string{"http"}, path: "/api/v1/status/buildinfo",
		match:    func(s int, b string) bool { return has2xx(s) && strings.Contains(b, `"goVersion"`) },
		severity: "medium", synopsis: "The Prometheus HTTP API is open.",
		desc: "Metrics and target labels reveal internal hosts, versions and topology, and admin endpoints may be enabled.",
		fix:  "Put Prometheus behind an authenticating reverse proxy or enable basic auth/TLS (web.config.file)."},
	{id: "k8s-api-anonymous", name: "Kubernetes API server allows anonymous listing", title: "Kubernetes API server allows anonymous access",
		ports: []int{6443, 8443}, schemes: []string{"https"}, path: "/api/v1/namespaces",
		match:    func(s int, b string) bool { return has2xx(s) && strings.Contains(b, `"NamespaceList"`) },
		severity: "high", synopsis: "The Kubernetes API returns namespaces to an anonymous caller.",
		desc: "Anonymous access to cluster objects exposes workloads and often secrets, and can lead to cluster takeover.",
		fix:  "Set --anonymous-auth=false on the API server and review RBAC bindings for system:anonymous and system:unauthenticated."},
}

// ---- raw TCP handshakes ----

func tcpExchange(host string, port int, send []byte, readMax int, readUntil func([]byte) bool) ([]byte, error) {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 4*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	if len(send) > 0 {
		if _, err := c.Write(send); err != nil {
			return nil, err
		}
	}
	var buf []byte
	tmp := make([]byte, 2048)
	for len(buf) < readMax {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if readUntil != nil && readUntil(buf) {
			break
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

func tcpCheck(id, name string, ports []int, run func(e *Env, s store.ServiceInfo) *Finding) Check {
	return Check{
		ID: id, Name: name, Family: "Misconfiguration", Safety: policy.SafetyProbe,
		Needs: func(e *Env) string {
			if len(openPort(e, ports)) == 0 {
				return fmt.Sprintf("no open service on port %v", ports)
			}
			return ""
		},
		Run: func(e *Env) []Finding {
			var out []Finding
			for _, s := range openPort(e, ports) {
				if f := run(e, s); f != nil {
					f.Port, f.Proto = s.Port, "tcp"
					out = append(out, *f)
				}
			}
			return out
		},
	}
}

// MQTT: a CONNECT with an empty client id and no credentials. A CONNACK with
// return code 0 means the broker lets anonymous clients in. We disconnect at once.
var mqttConnect = []byte{0x10, 0x0c, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00}

func mqttRun(e *Env, s store.ServiceInfo) *Finding {
	b, err := tcpExchange(e.Address, s.Port, mqttConnect, 4, func(b []byte) bool { return len(b) >= 4 })
	if err != nil || len(b) < 4 || b[0] != 0x20 || b[3] != 0x00 {
		return nil
	}
	return &Finding{Title: "MQTT Broker Accepts Anonymous Connections", Severity: "medium",
		Synopsis:    "An MQTT broker accepted a connection with no username or password.",
		Description: "Anonymous clients can usually subscribe to every topic and publish to devices, leaking telemetry and allowing control of connected equipment.",
		Remediation: "Disable anonymous access (allow_anonymous false), require credentials or client certificates, and add topic ACLs.",
		Evidence:    "CONNECT (no credentials) -> CONNACK return code 0 (accepted)"}
}

// ZooKeeper's `srvr` four-letter command is the only one enabled by default
// on modern releases; it returns version and mode, and nothing else.
func zookeeperRun(e *Env, s store.ServiceInfo) *Finding {
	b, err := tcpExchange(e.Address, s.Port, []byte("srvr"), 1024, nil)
	if err != nil || !strings.Contains(string(b), "Zookeeper version:") {
		return nil
	}
	return &Finding{Title: "ZooKeeper Accessible Without Authentication", Severity: "medium",
		Synopsis:    "A ZooKeeper server answers commands from any client.",
		Description: "ZooKeeper without authentication lets anyone read and change the configuration and coordination data of the services that rely on it (Kafka, Hadoop, Solr and others).",
		Remediation: "Enable SASL or mutual TLS authentication, set ACLs on znodes, and restrict the client port with a firewall.",
		Evidence:    snippet(string(b), 240)}
}

// rsync: after the greeting, an empty module request makes the daemon list
// its modules, exactly what `rsync host::` does.
func rsyncRun(e *Env, s store.ServiceInfo) *Finding {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(e.Address, strconv.Itoa(s.Port)), 4*time.Second)
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	r := bufio.NewReader(io.LimitReader(c, 1<<16))
	greeting, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(greeting, "@RSYNCD:") {
		return nil
	}
	if _, err := c.Write([]byte(strings.TrimSpace(greeting) + "\n\n")); err != nil {
		return nil
	}
	var mods []string
	for len(mods) < 50 {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "@RSYNCD:") || strings.HasPrefix(line, "@ERROR") {
			break
		}
		if line != "" {
			mods = append(mods, line)
		}
		if err != nil {
			break
		}
	}
	if len(mods) == 0 {
		return nil
	}
	return &Finding{Title: "rsync Daemon Lists Modules Without Authentication", Severity: "medium",
		Synopsis:    "The rsync daemon reveals its shared modules to anyone.",
		Description: "Listed modules may be readable (and sometimes writable) without a password, exposing files or allowing planting of content.",
		Remediation: "Set `auth users` and `secrets file` on every module, use `hosts allow`, and disable `list` where possible.",
		Evidence:    "module list:\n" + strings.Join(mods, "\n")}
}

func infraChecks() []Check {
	out := make([]Check, 0, len(infraAPIProbes)+3)
	for _, p := range infraAPIProbes {
		out = append(out, probeCheck(p))
	}
	out = append(out, snmpProbe, tlsProbe, mysqlProbe, postgresProbe)
	return append(out,
		tcpCheck("mqtt-anonymous", "MQTT broker allows anonymous clients", []int{1883}, mqttRun),
		tcpCheck("zookeeper-open", "ZooKeeper answers unauthenticated commands", []int{2181}, zookeeperRun),
		tcpCheck("rsync-modules-open", "rsync daemon lists modules without authentication", []int{873}, rsyncRun))
}
