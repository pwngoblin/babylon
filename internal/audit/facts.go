// Package audit implements credentialed (SSH) host auditing: a read-only fact
// collector, distro-aware package vulnerability matching against OSV, and
// data-driven hardening rules. Everything a host returns is untrusted text and
// is parsed defensively.
package audit

import (
	"bufio"
	"fmt"
	"sort"
	"strings"
)

// Facts is everything collected from one host.
type Facts struct {
	OS        OSInfo
	Packages  []Package
	SSHD      map[string][]string // lower-cased directive -> values (effective config if `sshd -T` worked)
	SSHDSrc   string              // "sshd -T" or "sshd_config" or ""
	Firewall  Firewall
	Listening []Socket
	Files     []FileInfo
	Sysctl    map[string]string
	Docker    *DockerInfo // nil when Docker is absent or not accessible to the audit account
	Errors    []string    // collection steps that failed (reported, never fatal)
}

type OSInfo struct {
	ID, VersionID, Codename, Pretty string
	Kernel                          string
}

// Package is one installed package. For deb and apk, Source* name the origin
// package, which is what vendor advisories are keyed on.
type Package struct {
	Name, Version, Arch string
	SrcName, SrcVersion string
}

type Firewall struct {
	Tool   string // ufw | firewalld | iptables | nftables | ""
	Active bool
	Known  bool // false when no tool could be queried (e.g. not root)
	Detail string
}

type Socket struct {
	Proto   string // tcp | udp
	Addr    string
	Port    int
	Process string
}

type FileInfo struct {
	Path         string
	Mode         string // octal, e.g. "640"
	Owner, Group string
}

// Loopback reports whether the socket only accepts local connections.
func (s Socket) Loopback() bool {
	return s.Addr == "127.0.0.1" || s.Addr == "::1" || strings.HasPrefix(s.Addr, "127.")
}

// Ecosystem returns the OSV ecosystem prefix and version-comparison scheme for
// the OS, or "" when the distro is not supported for package matching.
func (o OSInfo) Ecosystem() (prefix, scheme string) {
	major := o.VersionID
	if i := strings.IndexByte(major, '.'); i >= 0 {
		major = major[:i]
	}
	switch o.ID {
	case "debian":
		if major == "" {
			return "", ""
		}
		return "Debian:" + major, "deb"
	case "ubuntu":
		if o.VersionID == "" {
			return "", ""
		}
		return "Ubuntu:" + o.VersionID, "deb"
	case "alpine":
		parts := strings.Split(o.VersionID, ".")
		if len(parts) < 2 {
			return "", ""
		}
		return "Alpine:v" + parts[0] + "." + parts[1], "apk"
	case "rocky":
		return "Rocky Linux:" + major, "rpm"
	case "almalinux":
		return "AlmaLinux:" + major, "rpm"
	}
	return "", ""
}

// ParseOSRelease reads /etc/os-release.
func ParseOSRelease(s string) OSInfo {
	var o OSInfo
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			o.ID = strings.ToLower(v)
		case "VERSION_ID":
			o.VersionID = v
		case "VERSION_CODENAME":
			o.Codename = v
		case "PRETTY_NAME":
			o.Pretty = v
		}
	}
	return o
}

// ParseDpkg reads `dpkg-query -W -f='${Package}\t${Version}\t${Status}\t${Architecture}\t${source:Package}\t${source:Version}\n'`.
func ParseDpkg(s string) []Package {
	var out []Package
	for _, line := range strings.Split(s, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) < 4 || !strings.HasSuffix(f[2], "install ok installed") && f[2] != "install ok installed" {
			continue
		}
		p := Package{Name: f[0], Version: f[1], Arch: f[3], SrcName: f[0], SrcVersion: f[1]}
		if len(f) >= 6 {
			if f[4] != "" {
				p.SrcName = f[4]
			}
			if f[5] != "" {
				p.SrcVersion = f[5]
			}
		}
		if p.Name != "" && p.Version != "" {
			out = append(out, p)
		}
	}
	return out
}

// ParseRPM reads `rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n'`.
func ParseRPM(s string) []Package {
	var out []Package
	for _, line := range strings.Split(s, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) < 3 || f[0] == "" || f[0] == "gpg-pubkey" {
			continue
		}
		p := Package{Name: f[0], Version: f[1], Arch: f[2], SrcName: f[0], SrcVersion: f[1]}
		if len(f) >= 4 {
			if n := srpmName(f[3]); n != "" {
				p.SrcName = n
			}
		}
		out = append(out, p)
	}
	return out
}

// srpmName turns "openssl-3.0.7-27.el9.src.rpm" into "openssl".
func srpmName(s string) string {
	s = strings.TrimSuffix(s, ".src.rpm")
	for i := 0; i < 2; i++ { // strip -release then -version
		j := strings.LastIndexByte(s, '-')
		if j < 0 {
			return ""
		}
		s = s[:j]
	}
	return s
}

// ParseAPK reads `apk list -I` ("openssl-3.1.4-r0 x86_64 {openssl} (Apache-2.0) [installed]")
// and falls back to the bare `apk info -v` form ("openssl-3.1.4-r0").
func ParseAPK(s string) []Package {
	var out []Package
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name, ver, ok := splitAPKNameVer(fields[0])
		if !ok {
			continue
		}
		p := Package{Name: name, Version: ver, SrcName: name, SrcVersion: ver}
		for _, f := range fields[1:] {
			switch {
			case strings.HasPrefix(f, "{") && strings.HasSuffix(f, "}"):
				if o := strings.Trim(f, "{}"); o != "" {
					p.SrcName = o
				}
			case !strings.HasPrefix(f, "(") && !strings.HasPrefix(f, "[") && p.Arch == "":
				p.Arch = f
			}
		}
		out = append(out, p)
	}
	return out
}

// splitAPKNameVer splits "libcrypto3-3.1.4-r0": the version starts at the last
// "-" that is followed by a digit and precedes the "-rN" release.
func splitAPKNameVer(s string) (string, string, bool) {
	r := strings.LastIndex(s, "-r")
	if r < 0 {
		return "", "", false
	}
	v := strings.LastIndexByte(s[:r], '-')
	if v <= 0 || v+1 >= len(s) || s[v+1] < '0' || s[v+1] > '9' {
		return "", "", false
	}
	return s[:v], s[v+1:], true
}

// ParseSSHD parses `sshd -T` output or an sshd_config file. For raw config,
// the first occurrence of a directive wins (sshd semantics) and Match blocks
// are ignored because they only apply to some connections.
func ParseSSHD(s string, effective bool) map[string][]string {
	out := map[string][]string{}
	inMatch := false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, " ")
		if !ok {
			k, v, ok = strings.Cut(line, "=")
			if !ok {
				continue
			}
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if k == "match" {
			inMatch = true
			continue
		}
		if inMatch && !effective {
			continue
		}
		if _, seen := out[k]; seen && !effective {
			continue // first wins in a config file
		}
		out[k] = append(out[k], v)
	}
	return out
}

// ParseSS reads `ss -tulpn` (or netstat -tuln) listening sockets.
func ParseSS(s string) []Socket {
	var out []Socket
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 {
			continue
		}
		proto := strings.ToLower(f[0])
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}
		proto = proto[:3]
		// ss:      Netid State Recv-Q Send-Q Local Peer [users:(...)]
		// netstat: Proto Recv-Q Send-Q Local Foreign [State] [PID/Prog]
		local, rest := f[3], f[5:]
		if f[1] == strings.ToUpper(f[1]) && !isNum(f[1]) { // a State column: ss layout
			local = f[4]
		}
		addr, port, ok := splitHostPort(local)
		if !ok {
			continue
		}
		proc := ""
		for _, x := range rest {
			if strings.HasPrefix(x, "users:") || strings.Contains(x, "/") {
				proc = x
			}
		}
		out = append(out, Socket{Proto: proto, Addr: addr, Port: port, Process: proc})
	}
	return out
}

func splitHostPort(s string) (string, int, bool) {
	i := strings.LastIndexAny(s, ":.")
	if i < 0 {
		return "", 0, false
	}
	var port int
	if _, err := fmt.Sscanf(s[i+1:], "%d", &port); err != nil {
		return "", 0, false
	}
	addr := strings.Trim(s[:i], "[]")
	if i := strings.IndexByte(addr, '%'); i >= 0 { // ss zone suffix: fe80::1%eth0
		addr = addr[:i]
	}
	if addr == "*" || addr == "" {
		addr = "0.0.0.0"
	}
	return addr, port, true
}

// ParseStat reads `stat -c '%a %U %G %n'` lines.
func ParseStat(s string) []FileInfo {
	var out []FileInfo
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !isOctal(f[0]) {
			continue
		}
		out = append(out, FileInfo{Mode: f[0], Owner: f[1], Group: f[2], Path: strings.Join(f[3:], " ")})
	}
	return out
}

func isOctal(s string) bool {
	if s == "" || len(s) > 4 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '7' {
			return false
		}
	}
	return true
}

// ParseSysctl reads "key = value" lines.
func ParseSysctl(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// SortPackages gives deterministic output.
func SortPackages(p []Package) {
	sort.Slice(p, func(i, j int) bool {
		if p[i].Name != p[j].Name {
			return p[i].Name < p[j].Name
		}
		return p[i].Version < p[j].Version
	})
}

func isNum(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// DockerInfo is the isolation-relevant metadata of running containers.
type DockerInfo struct {
	Version    string
	Containers []Container
}

type Container struct {
	Name, Image, Network, PidMode, User string
	Privileged                          bool
	Mounts                              []string // source:destination
	CapAdd                              []string
}

// ParseDocker parses cmdDocker output; it returns nil unless the first line looks
// like a Docker server version (so a missing or inaccessible Docker is "unknown").
func ParseDocker(s string) *DockerInfo {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" || strings.Contains(lines[0], "|") || !isNum(string(strings.TrimSpace(lines[0])[0])) {
		return nil
	}
	d := &DockerInfo{Version: strings.TrimSpace(lines[0])}
	for _, l := range lines[1:] {
		p := strings.Split(strings.TrimSpace(l), "|")
		if len(p) < 8 {
			continue
		}
		c := Container{Name: strings.TrimPrefix(p[0], "/"), Image: p[1], Privileged: p[2] == "true", Network: p[3], PidMode: p[4], User: p[5]}
		for _, m := range strings.Split(p[6], ",") {
			if m != "" {
				c.Mounts = append(c.Mounts, m)
			}
		}
		caps := strings.Trim(p[7], "[] ")
		if caps != "" && caps != "<nil>" {
			c.CapAdd = strings.Fields(caps)
		}
		d.Containers = append(d.Containers, c)
	}
	return d
}
