package audit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Status of a hardening rule on one host.
type Status string

const (
	Pass    Status = "pass"
	Fail    Status = "fail"
	Unknown Status = "unknown" // the facts needed were not collected (reason says why)
)

// Result is a rule's verdict with the evidence that justifies it.
type Result struct {
	Status      Status
	Evidence    string
	Reason      string // for Unknown
	Remediation string
}

// Rule is a data-driven hardening check evaluated purely against collected
// facts; it never touches the host. To add a check, append a Rule to Rules.
type Rule struct {
	ID       string
	Title    string
	Severity string // info | low | medium | high | critical
	Synopsis string
	Eval     func(*Facts) Result
}

// Rules are the built-in CIS-inspired baseline checks.
var Rules = []Rule{
	{ID: "SSH-001", Title: "SSH allows direct root login with a password", Severity: "medium",
		Synopsis: "sshd permits root to log in over SSH with a password.", Eval: ruleSSHRoot},
	{ID: "SSH-002", Title: "SSH password login is enabled together with weak ciphers or MACs", Severity: "medium",
		Synopsis: "Password authentication is on and sshd still offers legacy ciphers/MACs.", Eval: ruleSSHWeakCrypto},
	{ID: "SSH-003", Title: "SSH permits empty passwords", Severity: "high",
		Synopsis: "Accounts with an empty password can log in over SSH.", Eval: ruleSSHEmptyPw},
	{ID: "SSH-004", Title: "SSH X11 forwarding is enabled", Severity: "low",
		Synopsis: "X11 forwarding widens the attack surface of an SSH session.", Eval: ruleSSHX11},
	{ID: "PERM-001", Title: "Sensitive system files have unsafe permissions", Severity: "high",
		Synopsis: "/etc/passwd, /etc/shadow or /etc/sudoers is writable or readable by too many users.", Eval: rulePerms},
	{ID: "FW-001", Title: "Host firewall is inactive while services listen on the network", Severity: "medium",
		Synopsis: "No host firewall is active and non-loopback services are listening.", Eval: ruleFirewall},
	{ID: "KERN-001", Title: "Kernel hardening parameters are relaxed", Severity: "low",
		Synopsis: "sysctl values weaken kernel information-leak or routing protections.", Eval: ruleKernel},
	{ID: "SVC-001", Title: "Sensitive service listens on all network interfaces", Severity: "medium",
		Synopsis: "A database, cache or container API is bound to a non-loopback address.", Eval: ruleExposedServices},
	{ID: "DOCKER-001", Title: "Privileged container running", Severity: "high",
		Synopsis: "A container runs with --privileged, which removes most isolation from the host.", Eval: ruleDockerPrivileged},
	{ID: "DOCKER-002", Title: "Container has the Docker socket mounted", Severity: "high",
		Synopsis: "Access to docker.sock is equivalent to root on the host.", Eval: ruleDockerSocket},
	{ID: "DOCKER-003", Title: "Container shares a host namespace or sensitive host path", Severity: "medium",
		Synopsis: "Host network/PID namespace or a sensitive host directory is shared with a container.", Eval: ruleDockerHostShare},
	{ID: "DOCKER-004", Title: "Container has dangerous Linux capabilities added", Severity: "high",
		Synopsis: "Capabilities such as SYS_ADMIN or SYS_PTRACE allow container escape.", Eval: ruleDockerCaps},
	{ID: "DOCKER-005", Title: "Containers run as root", Severity: "low",
		Synopsis: "Processes in a container run as uid 0, so a breakout starts with root privileges.", Eval: ruleDockerRoot},
}

func dockerUnknown() Result {
	return Result{Status: Unknown, Reason: "Docker is not installed or the audit account cannot access it (needs the docker group or root)"}
}

func dockerEach(f *Facts, bad func(Container) string, fix string) Result {
	if f.Docker == nil {
		return dockerUnknown()
	}
	var hits []string
	for _, c := range f.Docker.Containers {
		if why := bad(c); why != "" {
			hits = append(hits, fmt.Sprintf("%s (%s): %s", c.Name, c.Image, why))
		}
	}
	if len(hits) == 0 {
		return Result{Status: Pass, Evidence: fmt.Sprintf("%d running container(s) checked", len(f.Docker.Containers))}
	}
	sort.Strings(hits)
	return Result{Status: Fail, Evidence: strings.Join(hits, "\n"), Remediation: fix}
}

func ruleDockerPrivileged(f *Facts) Result {
	return dockerEach(f, func(c Container) string {
		if c.Privileged {
			return "runs with --privileged"
		}
		return ""
	}, "Remove --privileged; grant only the specific capabilities and devices the workload needs.")
}

func ruleDockerSocket(f *Facts) Result {
	return dockerEach(f, func(c Container) string {
		for _, m := range c.Mounts {
			if strings.HasPrefix(m, "/var/run/docker.sock:") || strings.HasPrefix(m, "/run/docker.sock:") {
				return "mounts " + m
			}
		}
		return ""
	}, "Do not mount docker.sock into containers; use a restricted socket proxy if API access is unavoidable.")
}

var sensitiveMountSources = []string{"/", "/etc", "/root", "/proc", "/sys", "/boot", "/var/lib/docker", "/var/run"}

func ruleDockerHostShare(f *Facts) Result {
	return dockerEach(f, func(c Container) string {
		var why []string
		if c.Network == "host" {
			why = append(why, "host network")
		}
		if c.PidMode == "host" {
			why = append(why, "host PID namespace")
		}
		for _, m := range c.Mounts {
			src, _, _ := strings.Cut(m, ":")
			for _, s := range sensitiveMountSources {
				if src == s {
					why = append(why, "mounts host "+src)
				}
			}
		}
		return strings.Join(why, ", ")
	}, "Use bridge networking, avoid host PID, and mount only the specific directories a container needs (read-only where possible).")
}

var dangerousCaps = map[string]bool{"SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "DAC_READ_SEARCH": true, "ALL": true, "NET_ADMIN": false}

func ruleDockerCaps(f *Facts) Result {
	return dockerEach(f, func(c Container) string {
		var bad []string
		for _, cp := range c.CapAdd {
			if dangerousCaps[strings.TrimPrefix(strings.ToUpper(cp), "CAP_")] {
				bad = append(bad, cp)
			}
		}
		if len(bad) > 0 {
			return "adds " + strings.Join(bad, ", ")
		}
		return ""
	}, "Drop all capabilities (--cap-drop=ALL) and add back only what is required.")
}

func ruleDockerRoot(f *Facts) Result {
	return dockerEach(f, func(c Container) string {
		if c.User == "" || c.User == "root" || c.User == "0" {
			return "no non-root USER set"
		}
		return ""
	}, "Set a non-root USER in the image or run with --user.")
}

func sshdVal(f *Facts, key, def string) (string, bool) {
	if f.SSHD == nil {
		return "", false
	}
	if v, ok := f.SSHD[key]; ok && len(v) > 0 {
		return strings.ToLower(v[len(v)-1]), true
	}
	return def, true
}

func noSSHD() Result {
	return Result{Status: Unknown, Reason: "sshd configuration could not be read (needs root or readable /etc/ssh/sshd_config)"}
}

func ruleSSHRoot(f *Facts) Result {
	v, ok := sshdVal(f, "permitrootlogin", "prohibit-password")
	if !ok {
		return noSSHD()
	}
	if v == "yes" {
		return Result{Status: Fail, Evidence: "PermitRootLogin " + v + " (" + f.SSHDSrc + ")",
			Remediation: "Set `PermitRootLogin no` (or `prohibit-password`) in /etc/ssh/sshd_config and reload sshd."}
	}
	return Result{Status: Pass, Evidence: "PermitRootLogin " + v}
}

var weakCipher = []string{"3des-cbc", "arcfour", "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc"}
var weakMAC = []string{"hmac-md5", "hmac-sha1-96", "umac-64", "hmac-ripemd160"}

func ruleSSHWeakCrypto(f *Facts) Result {
	pw, ok := sshdVal(f, "passwordauthentication", "yes")
	if !ok {
		return noSSHD()
	}
	if f.SSHDSrc != "sshd -T" {
		return Result{Status: Unknown, Reason: "effective cipher list needs `sshd -T` (run the audit as root)"}
	}
	var bad []string
	for _, c := range splitList(f.SSHD["ciphers"]) {
		for _, w := range weakCipher {
			if c == w {
				bad = append(bad, c)
			}
		}
	}
	for _, m := range splitList(f.SSHD["macs"]) {
		for _, w := range weakMAC {
			if m == w {
				bad = append(bad, m)
			}
		}
	}
	if pw == "yes" && len(bad) > 0 {
		return Result{Status: Fail, Evidence: fmt.Sprintf("PasswordAuthentication yes; weak algorithms offered: %s", strings.Join(dedupe(bad), ", ")),
			Remediation: "Disable `PasswordAuthentication` (use keys) and restrict `Ciphers`/`MACs` to modern algorithms such as chacha20-poly1305, aes256-gcm and hmac-sha2-256-etm."}
	}
	return Result{Status: Pass, Evidence: "PasswordAuthentication " + pw}
}

func ruleSSHEmptyPw(f *Facts) Result {
	v, ok := sshdVal(f, "permitemptypasswords", "no")
	if !ok {
		return noSSHD()
	}
	if v == "yes" {
		return Result{Status: Fail, Evidence: "PermitEmptyPasswords yes (" + f.SSHDSrc + ")",
			Remediation: "Set `PermitEmptyPasswords no` in /etc/ssh/sshd_config and reload sshd."}
	}
	return Result{Status: Pass, Evidence: "PermitEmptyPasswords " + v}
}

func ruleSSHX11(f *Facts) Result {
	v, ok := sshdVal(f, "x11forwarding", "no")
	if !ok {
		return noSSHD()
	}
	if v == "yes" {
		return Result{Status: Fail, Evidence: "X11Forwarding yes (" + f.SSHDSrc + ")",
			Remediation: "Set `X11Forwarding no` in /etc/ssh/sshd_config unless remote GUI apps are needed."}
	}
	return Result{Status: Pass, Evidence: "X11Forwarding " + v}
}

func rulePerms(f *Facts) Result {
	if len(f.Files) == 0 {
		return Result{Status: Unknown, Reason: "file permissions could not be read"}
	}
	var bad []string
	for _, fi := range f.Files {
		m, err := strconv.ParseUint(fi.Mode, 8, 32)
		if err != nil {
			continue
		}
		switch fi.Path {
		case "/etc/passwd":
			if m&0o022 != 0 || fi.Owner != "root" {
				bad = append(bad, fmt.Sprintf("%s mode %s owner %s (expected 644 root, not writable by group/others)", fi.Path, fi.Mode, fi.Owner))
			}
		case "/etc/shadow":
			if m&0o027 != 0 || fi.Owner != "root" { // group may read (Debian: root:shadow 640); nobody else, nobody writes
				bad = append(bad, fmt.Sprintf("%s mode %s owner %s (expected 640 or stricter, owned by root)", fi.Path, fi.Mode, fi.Owner))
			}
		case "/etc/sudoers":
			if m&0o027 != 0 || fi.Owner != "root" {
				bad = append(bad, fmt.Sprintf("%s mode %s owner %s (expected 440 root)", fi.Path, fi.Mode, fi.Owner))
			}
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return Result{Status: Fail, Evidence: strings.Join(bad, "\n"),
			Remediation: "chmod 644 /etc/passwd; chmod 640 /etc/shadow; chmod 440 /etc/sudoers; chown root /etc/passwd /etc/shadow /etc/sudoers"}
	}
	return Result{Status: Pass, Evidence: "permissions of /etc/passwd, /etc/shadow, /etc/sudoers are within baseline"}
}

func externalSockets(f *Facts) []Socket {
	var out []Socket
	for _, s := range f.Listening {
		if !s.Loopback() {
			out = append(out, s)
		}
	}
	return out
}

func ruleFirewall(f *Facts) Result {
	if !f.Firewall.Known {
		return Result{Status: Unknown, Reason: "no firewall tool could be queried (needs root, or none installed)"}
	}
	ext := externalSockets(f)
	if f.Firewall.Active {
		return Result{Status: Pass, Evidence: f.Firewall.Tool + " is active"}
	}
	if len(ext) == 0 {
		return Result{Status: Pass, Evidence: "firewall inactive but nothing listens on a non-loopback address"}
	}
	var ev []string
	for i, s := range ext {
		if i == 10 {
			ev = append(ev, fmt.Sprintf("… and %d more", len(ext)-10))
			break
		}
		ev = append(ev, fmt.Sprintf("%s %s:%d", s.Proto, s.Addr, s.Port))
	}
	return Result{Status: Fail, Evidence: fmt.Sprintf("%s reports inactive; listening: %s", f.Firewall.Tool, strings.Join(ev, ", ")),
		Remediation: "Enable a host firewall (e.g. `ufw enable` or `systemctl enable --now firewalld`) and allow only the required ports."}
}

func ruleKernel(f *Facts) Result {
	if len(f.Sysctl) == 0 {
		return Result{Status: Unknown, Reason: "sysctl values could not be read"}
	}
	var bad []string
	if f.Sysctl["kernel.dmesg_restrict"] == "0" {
		bad = append(bad, "kernel.dmesg_restrict = 0 (unprivileged users can read kernel logs)")
	}
	if f.Sysctl["kernel.kptr_restrict"] == "0" {
		bad = append(bad, "kernel.kptr_restrict = 0 (kernel pointers are exposed)")
	}
	if f.Sysctl["net.ipv4.ip_forward"] == "1" {
		bad = append(bad, "net.ipv4.ip_forward = 1 (IP forwarding on; fine only for routers, container hosts and VPNs)")
	}
	if len(bad) > 0 {
		return Result{Status: Fail, Evidence: strings.Join(bad, "\n"),
			Remediation: "Set kernel.dmesg_restrict=1, kernel.kptr_restrict=1 (or 2) and net.ipv4.ip_forward=0 in /etc/sysctl.d/ unless this host is meant to route."}
	}
	return Result{Status: Pass, Evidence: "checked sysctl values are within baseline"}
}

// exposedPorts are services that must not face the network without deliberate
// protection. The audit sees binding, not authentication, so wording says so.
var exposedPorts = map[int]string{
	2375: "Docker Engine API", 6379: "Redis", 3306: "MySQL/MariaDB", 5432: "PostgreSQL",
	27017: "MongoDB", 11211: "Memcached", 9200: "Elasticsearch", 5984: "CouchDB", 2379: "etcd",
}

func ruleExposedServices(f *Facts) Result {
	if len(f.Listening) == 0 {
		return Result{Status: Unknown, Reason: "listening sockets could not be read"}
	}
	var bad []string
	for _, s := range externalSockets(f) {
		if name, ok := exposedPorts[s.Port]; ok && s.Proto == "tcp" {
			bad = append(bad, fmt.Sprintf("%s listens on %s:%d (%s)", name, s.Addr, s.Port, s.Process))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return Result{Status: Fail, Evidence: strings.Join(bad, "\n") + "\nThe audit cannot see whether authentication is enabled.",
			Remediation: "Bind the service to 127.0.0.1 or a private interface (or firewall it) and require authentication/TLS."}
	}
	return Result{Status: Pass, Evidence: "no sensitive datastore or API listens on a non-loopback address"}
}

func splitList(v []string) []string {
	var out []string
	for _, s := range v {
		for _, x := range strings.Split(s, ",") {
			if x = strings.ToLower(strings.TrimSpace(x)); x != "" {
				out = append(out, x)
			}
		}
	}
	return out
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
