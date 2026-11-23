package nmap

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"babylon/internal/policy"
)

// Privilege is how Nmap may be run.
type Privilege int

const (
	PrivNone Privilege = iota // unprivileged: connect scans, no ARP/OS/UDP
	PrivRoot                  // already root
	PrivSudo                  // via `sudo -n` (non-interactive)
)

func (p Privilege) String() string {
	return [...]string{"none", "root", "sudo"}[p]
}

// Raw reports whether raw sockets (SYN/ARP/OS detection) are available.
func (p Privilege) Raw() bool { return p != PrivNone }

// Opts are runtime limits for an Nmap invocation.
type Opts struct {
	Privilege   Privilege
	MaxRatePPS  int
	HostTimeout time.Duration
	Timing      policy.Timing // pacing profile; zero value behaves like standard
	Ports       string        // validated port list overriding the template (e.g. "22,80,8000-8100"); "" = template default
}

// ValidPorts accepts only comma-separated ports and ranges within 1-65535, so a
// user-supplied port list can never smuggle an option into the Nmap argv.
func ValidPorts(s string) error {
	if s == "" {
		return nil
	}
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 1 || a > 65535 {
			return fmt.Errorf("invalid port spec %q", s)
		}
		if isRange {
			b, err := strconv.Atoi(hi)
			if err != nil || b < a || b > 65535 {
				return fmt.Errorf("invalid port range %q", part)
			}
		}
	}
	return nil
}

// Command returns the executable and full argv, wrapping with sudo if needed.
func Command(o Opts, args []string) (tool string, argv []string) {
	if o.Privilege == PrivSudo {
		return "sudo", append([]string{"-n", "nmap"}, args...)
	}
	return "nmap", args
}

// validTarget accepts only literal IPs and CIDRs. Hostnames are resolved by the
// scope guard before they ever reach an engine, and anything starting with '-'
// could be parsed by Nmap as an option, so it is refused here as well as in the
// policy layer (defense in depth).
func validTarget(s string) error {
	if s == "" || s[0] == '-' {
		return fmt.Errorf("invalid nmap target %q", s)
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	return fmt.Errorf("invalid nmap target %q: not an IP or CIDR", s)
}

func checkTargets(targets []string) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets")
	}
	for _, t := range targets {
		if err := validTarget(t); err != nil {
			return err
		}
	}
	return nil
}

func common(xmlPath string, o Opts) []string {
	t := o.Timing
	retries := t.MaxRetries
	if retries == 0 {
		retries = 2
	}
	args := []string{"-n", "--no-stylesheet", "-oX", xmlPath, "--max-retries", strconv.Itoa(retries)}
	if t.NmapT > 0 {
		args = append(args, "-T"+strconv.Itoa(t.NmapT))
	}
	if t.MaxRTT != "" {
		args = append(args, "--max-rtt-timeout", t.MaxRTT)
	}
	if t.InitRTT != "" {
		args = append(args, "--initial-rtt-timeout", t.InitRTT)
	}
	if o.MaxRatePPS > 0 {
		rate := o.MaxRatePPS
		if t.RateFactor > 0 {
			rate = max(1, rate*t.RateFactor/100)
		}
		args = append(args, "--max-rate", strconv.Itoa(rate))
	}
	if o.HostTimeout > 0 {
		args = append(args, "--host-timeout", fmt.Sprintf("%ds", int(o.HostTimeout.Seconds())))
	}
	return args
}

// SweepArgs builds a host-discovery-only (-sn) invocation.
func SweepArgs(targets []string, xmlPath string, o Opts) ([]string, error) {
	if err := checkTargets(targets); err != nil {
		return nil, err
	}
	args := append([]string{"-sn", "-PE", "-PS22,80,443,445,3389", "-PA80,443"}, common(xmlPath, o)...)
	return append(args, targets...), nil
}

// ScanArgs builds the port/service/TLS scan for a resolved policy. Every flag
// originates from the template or the policy allowlists; the only caller data
// are validated IP/CIDR targets and our own output path.
func ScanArgs(res *policy.Resolved, targets []string, xmlPath string, o Opts) ([]string, error) {
	if err := checkTargets(targets); err != nil {
		return nil, err
	}
	if err := res.Validate(); err != nil {
		return nil, err
	}
	t := res.Template
	args := []string{"-Pn", "--open"}

	if o.Privilege.Raw() {
		args = append(args, "-sS")
	} else {
		args = append(args, "-sT")
	}
	if err := ValidPorts(o.Ports); err != nil {
		return nil, err
	}
	switch {
	case o.Ports != "":
		args = append(args, "-p", o.Ports)
	case t.Ports == "top1000":
		args = append(args, "--top-ports", "1000")
	case t.Ports == "all":
		args = append(args, "-p-")
	case t.Ports == "":
		return nil, fmt.Errorf("template %s defines no ports to scan", t.Name)
	default:
		return nil, fmt.Errorf("unknown port spec %q", t.Ports)
	}
	if t.ServiceDetect {
		args = append(args, "-sV", "--version-light")
	}
	if t.OSDetect && o.Privilege.Raw() {
		args = append(args, "-O", "--osscan-limit", "--max-os-tries", "1")
	}
	if t.NSE {
		expr, err := res.NSE.ScriptExpr()
		if err != nil {
			return nil, err
		}
		st := o.Timing.ScriptTimeout
		if st == "" {
			st = "60s"
		}
		args = append(args, "--script", expr, "--script-timeout", st)
	}
	args = append(args, common(xmlPath, o)...)
	return append(args, targets...), nil
}

// UDPPorts are the high-value UDP services worth probing (DNS, DHCP, TFTP,
// RPC, NTP, NetBIOS, SNMP, CLDAP, IKE, syslog, IPMI, OpenVPN, SSDP, SIP, mDNS).
// A full UDP sweep is far too slow; this list keeps it to seconds per host.
const UDPPorts = "53,67,68,69,111,123,137,138,161,389,500,514,623,1194,1900,5060,5353"

// UDPArgs builds the targeted UDP scan. UDP scanning needs raw sockets, so it
// is refused without privilege rather than silently degrading.
func UDPArgs(res *policy.Resolved, targets []string, xmlPath string, o Opts) ([]string, error) {
	if err := checkTargets(targets); err != nil {
		return nil, err
	}
	if err := res.Validate(); err != nil {
		return nil, err
	}
	if !o.Privilege.Raw() {
		return nil, fmt.Errorf("UDP scanning needs root or sudo")
	}
	args := []string{"-Pn", "--open", "-sU", "-p", UDPPorts, "-sV", "--version-light"}
	if res.Template.NSE {
		expr, err := res.NSE.ScriptExpr()
		if err != nil {
			return nil, err
		}
		st := o.Timing.ScriptTimeout
		if st == "" {
			st = "60s"
		}
		args = append(args, "--script", expr, "--script-timeout", st)
	}
	args = append(args, common(xmlPath, o)...)
	return append(args, targets...), nil
}
