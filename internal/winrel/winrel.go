// Package winrel knows Microsoft's Windows support lifecycle dates. Both the
// unauthenticated SMB check and the credentialed Windows audit use it.
package winrel

import (
	"regexp"
	"strings"
	"time"
)

type Release struct {
	Match string // lowercase substring of the advertised OS name
	Name  string
	EOL   time.Time // end of security updates (no paid extension assumed)
	Note  string
}

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// Order matters: more specific names first ("2008 r2" before "2008", "8.1" before "8").
var Releases = []Release{
	{"windows server 2025", "Windows Server 2025", day(2034, 11, 14), ""},
	{"windows server 2022", "Windows Server 2022", day(2031, 10, 14), ""},
	{"windows server 2019", "Windows Server 2019", day(2029, 1, 9), ""},
	{"windows server 2016", "Windows Server 2016", day(2027, 1, 12), ""},
	{"windows server 2012 r2", "Windows Server 2012 R2", day(2023, 10, 10), ""},
	{"windows server 2012", "Windows Server 2012", day(2023, 10, 10), ""},
	{"windows server 2008 r2", "Windows Server 2008 R2", day(2020, 1, 14), ""},
	{"windows server 2008", "Windows Server 2008", day(2020, 1, 14), ""},
	{"windows server 2003", "Windows Server 2003", day(2015, 7, 14), ""},
	{"windows 2000", "Windows 2000", day(2010, 7, 13), ""},
	{"windows xp", "Windows XP", day(2014, 4, 8), ""},
	{"windows vista", "Windows Vista", day(2017, 4, 11), ""},
	{"windows 7", "Windows 7", day(2020, 1, 14), ""},
	{"windows 8.1", "Windows 8.1", day(2023, 1, 10), ""},
	{"windows 8", "Windows 8", day(2016, 1, 12), ""},
	{"windows 10", "Windows 10", day(2025, 10, 14), " Paid Extended Security Updates (ESU) can extend this for some editions; verify if the host is enrolled."},
	{"windows 11", "Windows 11", day(2099, 1, 1), ""}, // per-version dates vary; treat as supported
}

var smbOSLine = regexp.MustCompile(`(?im)^\s*OS:\s*(.+)$`)

// Lookup matches an OS name such as "Microsoft Windows Server 2012 R2 Standard".
func Lookup(osName string) *Release {
	low := strings.ToLower(osName)
	for i := range Releases {
		if strings.Contains(low, Releases[i].Match) {
			return &Releases[i]
		}
	}
	return nil
}

// FromSMB reads the OS name from Nmap's smb-os-discovery output.
func FromSMB(output string) (string, *Release) {
	m := smbOSLine.FindStringSubmatch(output)
	if m == nil {
		return "", nil
	}
	os := strings.TrimSpace(m[1])
	return os, Lookup(os)
}
