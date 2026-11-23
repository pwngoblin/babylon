package native

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"babylon/internal/store"
)

func scriptEnv(port int, script, out string, now time.Time) *Env {
	raw, _ := json.Marshal(out)
	return &Env{Address: "10.0.0.9", Now: now,
		Services: []store.ServiceInfo{{Address: "10.0.0.9", Port: port, Proto: "tcp"}},
		KB:       map[string]json.RawMessage{store.ScriptKey(port, "tcp", script): raw}}
}

var now2026 = time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)

func TestWindowsEOL(t *testing.T) {
	cases := []struct {
		os   string
		want string // "" = no finding
		sev  string
	}{
		{"Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)", "Windows Server 2008 R2", "high"},
		{"Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)", "Windows 7", "high"},
		{"Windows 8.1 Pro 9600", "Windows 8.1", "high"},
		{"Windows Server 2012 R2 Standard 9600", "Windows Server 2012 R2", "high"},
		{"Windows 10 Pro 19045 (Windows 10 Pro 6.3)", "Windows 10", "medium"},
		{"Windows Server 2016 Standard 14393", "", ""},
		{"Windows Server 2022 Standard 20348", "", ""},
		{"Unix (Samba 4.13.2)", "", ""},
	}
	for _, c := range cases {
		out := "  OS: " + c.os + "\n  Computer name: srv\n"
		got := windowsEOL.Run(scriptEnv(445, "smb-os-discovery", out, now2026))
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%q must not be flagged: %+v", c.os, got)
			}
			continue
		}
		if len(got) != 1 || !strings.Contains(got[0].Title, c.want) || got[0].Severity != c.sev {
			t.Errorf("%q: got %+v", c.os, got)
		}
	}
	// Server 2016 becomes unsupported only after its end date.
	out := "  OS: Windows Server 2016 Standard 14393\n"
	if got := windowsEOL.Run(scriptEnv(445, "smb-os-discovery", out, time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC))); len(got) != 1 {
		t.Errorf("2016 after Jan 2027 must be flagged: %+v", got)
	}
}

func TestMS17010(t *testing.T) {
	vuln := "  VULNERABLE:\n  Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)\n    State: VULNERABLE\n    IDs:  CVE:CVE-2017-0143\n"
	got := ms17010.Run(scriptEnv(445, "smb-vuln-ms17-010", vuln, now2026))
	if len(got) != 1 || got[0].Severity != "critical" || len(got[0].CVEs) == 0 {
		t.Errorf("vulnerable host: %+v", got)
	}
	if got := ms17010.Run(scriptEnv(445, "smb-vuln-ms17-010", "  NOT VULNERABLE: patched\n", now2026)); len(got) != 0 {
		t.Errorf("patched host flagged: %+v", got)
	}
}

func TestRDPSecurity(t *testing.T) {
	nlaOK := "  Security layer\n    CredSSP (NLA): SUCCESS\n    SSL: SUCCESS\n"
	noNLA := "  Security layer\n    CredSSP (NLA): FAILED\n    SSL: SUCCESS\n"
	legacy := "  Security layer\n    Native RDP: SUCCESS\n    SSL: SUCCESS\n"
	if got := rdpSecurity.Run(scriptEnv(3389, "rdp-enum-encryption", nlaOK, now2026)); len(got) != 0 {
		t.Errorf("NLA required must be clean: %+v", got)
	}
	if got := rdpSecurity.Run(scriptEnv(3389, "rdp-enum-encryption", noNLA, now2026)); len(got) != 1 || got[0].Severity != "medium" {
		t.Errorf("no NLA: %+v", got)
	}
	if got := rdpSecurity.Run(scriptEnv(3389, "rdp-enum-encryption", legacy, now2026)); len(got) != 1 || got[0].Severity != "high" {
		t.Errorf("legacy RDP: %+v", got)
	}
}

func TestWinRMHTTP(t *testing.T) {
	e := &Env{Address: "10.0.0.9", Services: []store.ServiceInfo{{Port: 5985, Proto: "tcp"}}}
	if got := winrmCleartext.Run(e); len(got) != 1 || got[0].Port != 5985 {
		t.Errorf("%+v", got)
	}
	if winrmCleartext.Needs(&Env{}) == "" {
		t.Error("must skip when 5985 is closed")
	}
}
