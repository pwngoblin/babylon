package matcher

import (
	"regexp"
	"strings"
)

// distroMarker finds explicit evidence that a binary was built by a Linux
// distribution, which routinely backports security fixes without changing the
// upstream version string.
var distroMarker = regexp.MustCompile(`(?i)\b(ubuntu|debian|deb\d+u\d+|~deb\d+|centos|red ?hat|rhel|rocky|alma(linux)?|fedora|opensuse|suse|sles|amazon linux|alpine|oracle linux|raspbian|kali)\b|\.el\d+|\.fc\d+|\bel[5-9]\b|\bel1\d\b|ubuntu\d`)

// distroPackaged lists products that distributions routinely package and patch
// in place. When the host is known to run Linux but the banner does not say
// which build this is, a version match is downgraded to tentative.
var distroPackaged = map[string]bool{
	"openssh": true, "http_server": true, "nginx": true, "openssl": true, "php": true, "bind": true, "samba": true,
	"proftpd": true, "postfix": true, "exim": true, "dovecot": true, "mysql": true, "mariadb": true, "postgresql": true,
	"sudo": true, "curl": true, "squid": true, "lighttpd": true, "haproxy": true, "dnsmasq": true, "bash": true, "vim": true,
}

// CaveatBackport is attached to findings that may be affected by vendor patches.
const CaveatBackport = "Banner version may include vendor backported patches; verify with a credentialed scan."

// Assess decides how much a version match can be trusted when scanning
// unauthenticated. It never returns "confirmed": that needs an independent
// behavioural check (merged later) or a credentialed package audit.
func Assess(product, banner string, hostOS string) (confidence, caveat string) {
	if distroMarker.MatchString(banner) {
		return "tentative", CaveatBackport
	}
	if m := distroMarker.FindString(hostOS); m != "" && distroPackaged[strings.ToLower(product)] {
		return "tentative", CaveatBackport
	}
	if isLinuxOS(hostOS) && distroPackaged[strings.ToLower(product)] {
		return "tentative", CaveatBackport
	}
	return "firm", ""
}

func isLinuxOS(os string) bool { return strings.Contains(strings.ToLower(os), "linux") }
