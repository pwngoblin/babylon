package audit

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"babylon/internal/store"
)

// macOS audit: read-only queries of the OS version and security settings.
// Missing updates come from Apple's per-release CVE lists (feed "apple");
// settings are judged by MAC-* rules. Every command is fixed text, runs
// without arguments from scan data, and changes nothing.
const (
	cmdCsrutil     = `csrutil status 2>/dev/null`
	cmdSpctl       = `spctl --status 2>/dev/null`
	cmdFDE         = `fdesetup status 2>/dev/null`
	cmdALFState    = `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null`
	cmdALFStealth  = `/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null`
	cmdSoftUpdate  = `defaults read /Library/Preferences/com.apple.SoftwareUpdate 2>/dev/null`
	cmdLoginWindow = `defaults read /Library/Preferences/com.apple.loginwindow 2>/dev/null`
)

func init() {
	allow(cmdCsrutil, cmdSpctl, cmdFDE, cmdALFState, cmdALFStealth, cmdSoftUpdate, cmdLoginWindow)
}

// Tri is a setting that may be on, off or not determined.
type Tri int

const (
	TriUnknown Tri = iota
	TriOn
	TriOff
)

// MacFacts are the macOS-specific facts of one host.
type MacFacts struct {
	ProductVersion string // 26.6.1
	Build          string
	SIP            Tri
	Gatekeeper     Tri
	FileVault      Tri
	Firewall       Tri
	Stealth        Tri
	SoftUpdate     map[string]string // com.apple.SoftwareUpdate keys (nil if not readable)
	Login          map[string]string // com.apple.loginwindow keys (nil if not readable)
}

func (m *MacFacts) Major() int {
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.SplitN(m.ProductVersion, ".", 2)[0])
	return n
}

func triFrom(s string, on, off *regexp.Regexp) Tri {
	switch {
	case off.MatchString(s):
		return TriOff
	case on.MatchString(s):
		return TriOn
	}
	return TriUnknown
}

var (
	reSIPOn   = regexp.MustCompile(`(?i)protection status:\s*enabled`)
	reSIPOff  = regexp.MustCompile(`(?i)protection status:\s*disabled|custom configuration`)
	reGKOn    = regexp.MustCompile(`(?i)assessments enabled`)
	reGKOff   = regexp.MustCompile(`(?i)assessments disabled`)
	reFDEOn   = regexp.MustCompile(`(?i)filevault is on`)
	reFDEOff  = regexp.MustCompile(`(?i)filevault is off`)
	reALFOn   = regexp.MustCompile(`(?i)\(state = [12]\)|firewall is enabled`)
	reALFOff  = regexp.MustCompile(`(?i)\(state = 0\)|firewall is disabled`)
	reStealOn = regexp.MustCompile(`(?i)stealth mode (is )?(enabled|on)\b`)
	reStealOf = regexp.MustCompile(`(?i)stealth mode (is )?(disabled|off)\b`)
	reDefault = regexp.MustCompile(`^\s*"?([A-Za-z0-9_.-]+)"?\s*=\s*"?([^";]*?)"?\s*;\s*$`)
)

func ParseSIP(s string) Tri        { return triFrom(s, reSIPOn, reSIPOff) }
func ParseGatekeeper(s string) Tri { return triFrom(s, reGKOn, reGKOff) }
func ParseFileVault(s string) Tri  { return triFrom(s, reFDEOn, reFDEOff) }
func ParseALF(s string) Tri        { return triFrom(s, reALFOn, reALFOff) }
func ParseStealth(s string) Tri    { return triFrom(s, reStealOn, reStealOf) }

// ParseDefaults reads the top-level `key = value;` lines of `defaults read`
// output. Nested dictionaries and arrays are skipped. nil means no output.
func ParseDefaults(s string) map[string]string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := map[string]string{}
	depth := 0
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if depth == 1 {
			if m := reDefault.FindStringSubmatch(line); m != nil {
				out[m[1]] = strings.TrimSpace(m[2])
			}
		}
		depth += strings.Count(t, "{") + strings.Count(t, "(") - strings.Count(t, "}") - strings.Count(t, ")")
	}
	return out
}

func collectMac(f *Facts, run func(string) string) {
	m := &MacFacts{}
	if sw := run(cmdSwVers); sw != "" {
		m.ProductVersion = field(sw, "ProductVersion")
		m.Build = field(sw, "BuildVersion")
		f.OS.ID, f.OS.Pretty, f.OS.VersionID = "macos", "macOS "+m.ProductVersion, m.ProductVersion
	}
	m.SIP = ParseSIP(run(cmdCsrutil))
	m.Gatekeeper = ParseGatekeeper(run(cmdSpctl))
	m.FileVault = ParseFileVault(run(cmdFDE))
	m.Firewall = ParseALF(run(cmdALFState))
	m.Stealth = ParseStealth(run(cmdALFStealth))
	m.SoftUpdate = ParseDefaults(run(cmdSoftUpdate))
	m.Login = ParseDefaults(run(cmdLoginWindow))
	f.Mac = m
}

// ---- missing updates ----

// MacSource abstracts the Apple release data (the store in production).
type MacSource interface {
	AppleFixesForMajor(ctx context.Context, major int) ([]store.AppleFix, error)
	AppleReleases(ctx context.Context, major int) ([]store.AppleRelease, error)
	CountApple(ctx context.Context) (fixes, releases int, err error)
}

// MacPatchStats describes the patch match for coverage reporting.
type MacPatchStats struct {
	Unsupported  string // why no match was possible ("" = matched)
	Latest       string // newest known release of the host's line
	LatestDate   string
	OutOfSupport bool // Apple has published nothing for this line recently
	Product      string
}

// MacMissing is a CVE the host's macOS version does not yet fix.
type MacMissing struct {
	CVE     string
	FixedIn string
	CVSS    *float64
	Product string
}

// CmpDotted compares dotted numeric versions ("26.7" < "26.7.1" < "26.10").
func CmpDotted(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// macSupportWindow: Apple ships security fixes for the newest three major
// lines. A line with no release for this long is treated as unsupported.
const macSupportWindow = 365 * 24 * time.Hour

// MatchMacUpdates lists CVEs fixed by releases newer than the installed one in
// the same major line. For each CVE the earliest release that fixes it is kept.
func MatchMacUpdates(ctx context.Context, src MacSource, f *Facts, now time.Time) ([]MacMissing, MacPatchStats, error) {
	var stats MacPatchStats
	if f.Mac == nil || f.Mac.ProductVersion == "" || f.Mac.Major() == 0 {
		stats.Unsupported = "macOS version not available"
		return nil, stats, nil
	}
	if n, _, err := src.CountApple(ctx); err != nil {
		return nil, stats, err
	} else if n == 0 {
		stats.Unsupported = "no Apple security data indexed (run: babylon update-feeds --only apple)"
		return nil, stats, nil
	}
	major := f.Mac.Major()
	rels, err := src.AppleReleases(ctx, major)
	if err != nil {
		return nil, stats, err
	}
	if len(rels) == 0 {
		stats.Unsupported = fmt.Sprintf("Apple has no security release listed for macOS %d; the line is end of life or the feed is old", major)
		stats.OutOfSupport = true
		return nil, stats, nil
	}
	for _, r := range rels {
		if stats.Latest == "" || CmpDotted(r.Release, stats.Latest) > 0 {
			stats.Latest, stats.LatestDate, stats.Product = r.Release, r.Released, r.Product
		}
	}
	if t, err := time.Parse("2006-01-02", stats.LatestDate); err == nil && now.Sub(t) > macSupportWindow {
		stats.OutOfSupport = true
	}
	fixes, err := src.AppleFixesForMajor(ctx, major)
	if err != nil {
		return nil, stats, err
	}
	first := map[string]store.AppleFix{}
	for _, x := range fixes {
		if CmpDotted(x.Release, f.Mac.ProductVersion) <= 0 {
			continue
		}
		if cur, ok := first[x.CVE]; !ok || CmpDotted(x.Release, cur.Release) < 0 {
			first[x.CVE] = x
		}
	}
	var out []MacMissing
	for _, x := range first {
		out = append(out, MacMissing{CVE: x.CVE, FixedIn: x.Release, CVSS: x.CVSS, Product: x.Product})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CVE < out[j].CVE })
	return out, stats, nil
}

// ---- hardening rules ----

func macUnknown(what string) Result {
	return Result{Status: Unknown, Reason: what + " could not be read (command unavailable or needs a privileged account)"}
}

func macTri(t Tri, what, evPass, evFail, fix string) Result {
	switch t {
	case TriOn:
		return Result{Status: Pass, Evidence: evPass}
	case TriOff:
		return Result{Status: Fail, Evidence: evFail, Remediation: fix}
	}
	return macUnknown(what)
}

// MacRules are the macOS baseline checks (CIS-inspired).
var MacRules = []Rule{
	{ID: "MAC-001", Title: "System Integrity Protection is disabled", Severity: "high",
		Synopsis: "SIP protects system files and processes from modification, even by root.",
		Eval: func(f *Facts) Result {
			return macTri(f.Mac.SIP, "csrutil status", "SIP enabled", "csrutil status reports SIP disabled or customised",
				"Boot into Recovery and run `csrutil enable`.")
		}},
	{ID: "MAC-002", Title: "Gatekeeper is disabled", Severity: "medium",
		Synopsis: "Gatekeeper checks that downloaded software is signed and notarised.",
		Eval: func(f *Facts) Result {
			return macTri(f.Mac.Gatekeeper, "spctl --status", "assessments enabled", "spctl --status: assessments disabled",
				"Run `sudo spctl --master-enable`.")
		}},
	{ID: "MAC-003", Title: "FileVault disk encryption is off", Severity: "medium",
		Synopsis: "Without FileVault the disk contents are readable by anyone with physical access.",
		Eval: func(f *Facts) Result {
			return macTri(f.Mac.FileVault, "fdesetup status", "FileVault is On", "fdesetup status: FileVault is Off",
				"Enable FileVault in System Settings > Privacy & Security, and escrow the recovery key.")
		}},
	{ID: "MAC-004", Title: "The macOS application firewall is off", Severity: "medium",
		Synopsis: "The built-in firewall is not filtering incoming connections to applications.",
		Eval: func(f *Facts) Result {
			return macTri(f.Mac.Firewall, "socketfilterfw --getglobalstate", "firewall enabled", "socketfilterfw: firewall disabled (State = 0)",
				"Enable it in System Settings > Network > Firewall, or `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on`.")
		}},
	{ID: "MAC-005", Title: "Firewall stealth mode is off", Severity: "low",
		Synopsis: "The Mac answers probes (ICMP, closed-port replies) that stealth mode would drop.",
		Eval: func(f *Facts) Result {
			if f.Mac.Firewall == TriOff {
				return Result{Status: Unknown, Reason: "firewall is off (see MAC-004)"}
			}
			return macTri(f.Mac.Stealth, "socketfilterfw --getstealthmode", "stealth mode enabled", "stealth mode disabled",
				"Run `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on`.")
		}},
	{ID: "MAC-006", Title: "Automatic software update checks are disabled", Severity: "medium",
		Synopsis: "The Mac does not check for new macOS updates on its own.",
		Eval: func(f *Facts) Result {
			if f.Mac.SoftUpdate == nil {
				return macUnknown("the software update settings")
			}
			v, ok := f.Mac.SoftUpdate["AutomaticCheckEnabled"]
			if !ok { // the key is only written when changed; the default is on
				return Result{Status: Pass, Evidence: "AutomaticCheckEnabled not overridden (default: on)"}
			}
			if v == "0" {
				return Result{Status: Fail, Evidence: "com.apple.SoftwareUpdate AutomaticCheckEnabled = 0",
					Remediation: "Enable Automatic checks in System Settings > General > Software Update."}
			}
			return Result{Status: Pass, Evidence: "AutomaticCheckEnabled = " + v}
		}},
	{ID: "MAC-007", Title: "Security updates are not installed automatically", Severity: "low",
		Synopsis: "Critical system and security data updates are not applied without a user action.",
		Eval: func(f *Facts) Result {
			var off []string
			seen := 0
			for _, k := range []string{"CriticalUpdateInstall", "ConfigDataInstall"} {
				if v, ok := f.Mac.SoftUpdate[k]; ok {
					seen++
					if v == "0" {
						off = append(off, k+" = 0")
					}
				}
			}
			if seen == 0 {
				return macUnknown("the automatic security update settings")
			}
			if len(off) > 0 {
				return Result{Status: Fail, Evidence: "com.apple.SoftwareUpdate: " + strings.Join(off, ", "),
					Remediation: "Turn on 'Install Security Responses and system files' in System Settings > General > Software Update > Automatic updates."}
			}
			return Result{Status: Pass, Evidence: "security and config data updates enabled"}
		}},
	{ID: "MAC-008", Title: "The Guest account is enabled", Severity: "medium",
		Synopsis: "A shared Guest login lets anyone use the Mac without credentials.",
		Eval: func(f *Facts) Result {
			v, ok := f.Mac.Login["GuestEnabled"]
			if !ok {
				return macUnknown("the GuestEnabled setting")
			}
			if v == "1" {
				return Result{Status: Fail, Evidence: "com.apple.loginwindow GuestEnabled = 1",
					Remediation: "Disable it in System Settings > Users & Groups > Guest User."}
			}
			return Result{Status: Pass, Evidence: "GuestEnabled = " + v}
		}},
	{ID: "MAC-009", Title: "Automatic login is enabled", Severity: "high",
		Synopsis: "The Mac logs a user in at boot without a password.",
		Eval: func(f *Facts) Result {
			if f.Mac.Login == nil {
				return macUnknown("the login window settings")
			}
			if u, ok := f.Mac.Login["autoLoginUser"]; ok && u != "" {
				return Result{Status: Fail, Evidence: "com.apple.loginwindow autoLoginUser = " + u,
					Remediation: "Disable automatic login in System Settings > Users & Groups."}
			}
			return Result{Status: Pass, Evidence: "no automatic login user"}
		}},
}

// RulesFor returns the hardening rules that apply to the audited host: the
// macOS baseline plus the SSH rules for a Mac, the Linux rules otherwise.
func RulesFor(f *Facts) []Rule {
	if f.Mac == nil {
		return Rules
	}
	out := append([]Rule(nil), MacRules...)
	for _, r := range Rules {
		if strings.HasPrefix(r.ID, "SSH-") {
			out = append(out, r)
		}
	}
	return out
}
