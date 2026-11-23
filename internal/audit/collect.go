package audit

import (
	"context"
	"fmt"
	"strings"
)

// The complete set of commands Babylon runs on audited hosts. All are
// read-only queries; none modify state, read secrets (/etc/shadow contents are
// never read, only its mode), or take arguments from scan data.
const (
	cmdOSRelease = `cat /etc/os-release`
	cmdUname     = `uname -srm`
	cmdDpkg      = `dpkg-query -W -f='${Package}\t${Version}\t${Status}\t${Architecture}\t${source:Package}\t${source:Version}\n'`
	cmdRPM       = `rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n'`
	cmdAPK       = `apk list -I 2>/dev/null || apk info -v`
	cmdSwVers    = `sw_vers`
	cmdBrew      = `brew list --versions`
	cmdSSHDT     = `sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null`
	cmdSSHDConf  = `cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null`
	cmdUFW       = `ufw status 2>/dev/null`
	cmdFirewalld = `firewall-cmd --state 2>/dev/null`
	cmdIPTables  = `iptables -S 2>/dev/null`
	cmdNft       = `nft list ruleset 2>/dev/null`
	cmdSS        = `ss -tulpn 2>/dev/null || ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null`
	cmdStat      = `stat -c '%a %U %G %n' /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config 2>/dev/null`
	cmdSysctl    = `sysctl net.ipv4.ip_forward kernel.dmesg_restrict kernel.kptr_restrict 2>/dev/null`
	// cmdDocker prints the Docker server version, then one line per running
	// container describing how it is isolated. It only reads container metadata.
	cmdDocker = `docker info --format '{{.ServerVersion}}' 2>/dev/null && docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Name}}|{{.Config.Image}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.PidMode}}|{{.Config.User}}|{{range .Mounts}}{{.Source}}:{{.Destination}},{{end}}|{{.HostConfig.CapAdd}}' 2>/dev/null`
)

func init() {
	allow(cmdOSRelease, cmdUname, cmdDpkg, cmdRPM, cmdAPK, cmdSwVers, cmdBrew, cmdSSHDT, cmdSSHDConf,
		cmdUFW, cmdFirewalld, cmdIPTables, cmdNft, cmdSS, cmdStat, cmdSysctl, cmdDocker)
}

// AllowedCommands exposes the allowlist for tests and documentation.
func AllowedCommands() []string {
	out := make([]string, 0, len(allowed))
	for c := range allowed {
		out = append(out, c)
	}
	return out
}

// Collect gathers facts from a host. Individual step failures are recorded in
// Facts.Errors and never abort the audit; it errors only when the host yields
// neither an OS identity nor any packages (nothing useful learned).
func Collect(ctx context.Context, r Runner) (*Facts, error) {
	f := &Facts{}
	run := func(cmd string) string {
		out, err := r.Run(ctx, cmd)
		if err != nil && strings.TrimSpace(out) == "" {
			return ""
		}
		return out
	}
	note := func(msg string) { f.Errors = append(f.Errors, msg) }

	if out := run(cmdOSRelease); out != "" {
		f.OS = ParseOSRelease(out)
	} else {
		note("could not read /etc/os-release")
	}
	f.OS.Kernel = strings.TrimSpace(run(cmdUname))

	switch {
	case f.OS.ID == "debian" || f.OS.ID == "ubuntu" || strings.Contains(f.OS.ID, "mint") || strings.Contains(f.OS.ID, "kali"):
		f.Packages = ParseDpkg(run(cmdDpkg))
	case f.OS.ID == "alpine":
		f.Packages = ParseAPK(run(cmdAPK))
	case f.OS.ID == "darwin":
		// handled below
	default:
		// Try the package managers in order; the first that answers wins.
		if p := ParseDpkg(run(cmdDpkg)); len(p) > 0 {
			f.Packages = p
		} else if p := ParseRPM(run(cmdRPM)); len(p) > 0 {
			f.Packages = p
		} else if p := ParseAPK(run(cmdAPK)); len(p) > 0 {
			f.Packages = p
		}
	}
	if f.OS.ID != "debian" && f.OS.ID != "ubuntu" && f.OS.ID != "alpine" && len(f.Packages) == 0 {
		if p := ParseRPM(run(cmdRPM)); len(p) > 0 {
			f.Packages = p
		}
	}
	if len(f.Packages) == 0 {
		if sw := run(cmdSwVers); sw != "" {
			f.OS.ID, f.OS.Pretty = "macos", "macOS "+field(sw, "ProductVersion")
			f.OS.VersionID = field(sw, "ProductVersion")
		}
		f.Packages = append(f.Packages, parseBrew(run(cmdBrew))...)
	}
	if len(f.Packages) == 0 {
		note("no installed packages could be listed")
	}
	SortPackages(f.Packages)

	if out := run(cmdSSHDT); strings.TrimSpace(out) != "" {
		f.SSHD, f.SSHDSrc = ParseSSHD(out, true), "sshd -T"
	} else if out := run(cmdSSHDConf); strings.TrimSpace(out) != "" {
		f.SSHD, f.SSHDSrc = ParseSSHD(out, false), "sshd_config"
	}

	f.Firewall = detectFirewall(run)
	f.Listening = ParseSS(run(cmdSS))
	f.Files = ParseStat(run(cmdStat))
	f.Sysctl = ParseSysctl(run(cmdSysctl))
	f.Docker = ParseDocker(run(cmdDocker))
	collectBaseline(f, run)

	if f.OS.ID == "" && len(f.Packages) == 0 {
		return f, fmt.Errorf("host returned no OS information or packages; commands may be restricted for this account")
	}
	return f, nil
}

func field(s, key string) string {
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func parseBrew(s string) []Package {
	var out []Package
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			out = append(out, Package{Name: f[0], Version: f[len(f)-1], SrcName: f[0], SrcVersion: f[len(f)-1]})
		}
	}
	return out
}

// detectFirewall tries each tool; Known is true only when at least one gave an
// answer. A host where none can be queried (non-root) is "unknown", never "off".
func detectFirewall(run func(string) string) Firewall {
	if out := run(cmdUFW); out != "" {
		on := strings.Contains(strings.ToLower(out), "status: active")
		return Firewall{Tool: "ufw", Active: on, Known: true, Detail: firstLines(out, 3)}
	}
	if out := strings.TrimSpace(run(cmdFirewalld)); out != "" {
		return Firewall{Tool: "firewalld", Active: out == "running", Known: true, Detail: out}
	}
	if out := run(cmdIPTables); out != "" {
		// Any rule beyond the default ACCEPT policies counts as a configured firewall.
		rules := 0
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "-A ") {
				rules++
			}
		}
		drop := strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-P INPUT REJECT")
		return Firewall{Tool: "iptables", Active: rules > 0 || drop, Known: true, Detail: fmt.Sprintf("%d rules", rules)}
	}
	if out := run(cmdNft); strings.TrimSpace(out) != "" {
		return Firewall{Tool: "nftables", Active: strings.Contains(out, "chain "), Known: true, Detail: firstLines(out, 3)}
	}
	return Firewall{}
}

func firstLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[:n]
	}
	return strings.Join(l, "\n")
}
