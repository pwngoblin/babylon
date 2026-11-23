package audit

import (
	"context"
	"strings"
	"testing"
	"time"
)

type fakeWin map[string]string

func (f fakeWin) Run(ctx context.Context, cmd string) (string, error) {
	if out, ok := f[cmd]; ok {
		return out, nil
	}
	return "", context.DeadlineExceeded
}

var now2026 = time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)

func weakWin() fakeWin {
	return fakeWin{
		psOS:          `{"Caption":"Microsoft Windows 10 Pro","Version":"10.0.19045","Build":"19045","UBR":4529,"DisplayVersion":"22H2","Arch":"64-bit","ProductType":1}`,
		psHotfix:      `[{"HotFixID":"KB5039211","InstalledOn":"2024-06-20"},{"HotFixID":"KB5001","InstalledOn":"2024-01-02"}]`,
		psSoftware:    `[{"DisplayName":"7-Zip 19.00","DisplayVersion":"19.00","Publisher":"Igor Pavlov"}]`,
		psSecurity:    `{"smb1":true,"smbSigning":false,"fw_Domain":true,"fw_Private":false,"fw_Public":true,"av":true,"rtp":false,"sigAge":40,"nla":0,"uac":0,"wdigest":1,"lmcompat":1,"guest":true,"llmnr":null,"autorun":null}`,
		psNetAccounts: "Minimum password length:                              0\r\nMaximum password age (days):                          Unlimited\r\nLockout threshold:                                    Never\r\n",
		psAdmins:      `[{"Name":"PC\\Administrator","ObjectClass":"User"},{"Name":"PC\\a","ObjectClass":"User"},{"Name":"PC\\b","ObjectClass":"User"},{"Name":"PC\\c","ObjectClass":"User"},{"Name":"PC\\d","ObjectClass":"User"}]`,
	}
}

func goodWin() fakeWin {
	g := weakWin()
	g[psOS] = `{"Caption":"Microsoft Windows Server 2022 Standard","Version":"10.0.20348","Build":"20348","UBR":2700,"Arch":"64-bit","ProductType":3}`
	g[psHotfix] = `{"HotFixID":"KB5043","InstalledOn":"2026-11-01"}`
	g[psSecurity] = `{"smb1":false,"smbSigning":true,"fw_Domain":true,"fw_Private":true,"fw_Public":true,"av":true,"rtp":true,"sigAge":1,"nla":1,"uac":1,"wdigest":null,"lmcompat":5,"guest":false,"llmnr":0,"autorun":255}`
	g[psNetAccounts] = "Minimum password length:                              14\r\nMaximum password age (days):                          60\r\nLockout threshold:                                    5\r\n"
	g[psAdmins] = `{"Name":"PC\\Administrator","ObjectClass":"User"}`
	return g
}

func TestCollectWindowsAndRules(t *testing.T) {
	f, err := CollectWindows(context.Background(), weakWin(), now2026)
	if err != nil {
		t.Fatal(err)
	}
	if f.BuildKey() != "10.0.19045" || f.FullVersion() != "10.0.19045.4529" || f.Server || len(f.Hotfixes) != 2 || len(f.Software) != 1 || len(f.Admins) != 5 {
		t.Fatalf("facts: %+v", f)
	}
	for _, r := range WinRules {
		if res := r.Eval(f); res.Status != Fail || res.Evidence == "" || res.Remediation == "" {
			t.Errorf("%s on a weak host = %+v", r.ID, res)
		}
	}
	g, err := CollectWindows(context.Background(), goodWin(), now2026)
	if err != nil || !g.Server || g.BuildKey() != "10.0.20348" || len(g.Admins) != 1 {
		t.Fatalf("good facts: %v %+v", err, g)
	}
	for _, r := range WinRules {
		if res := r.Eval(g); res.Status != Pass {
			t.Errorf("%s on a hardened host = %+v", r.ID, res)
		}
	}
}

func TestWindowsUnknownIsNeverPass(t *testing.T) {
	// A non-admin account: the security query returns nothing usable.
	w := goodWin()
	w[psSecurity] = `{}`
	delete(w, psNetAccounts)
	delete(w, psAdmins)
	f, err := CollectWindows(context.Background(), w, now2026)
	if err != nil {
		t.Fatal(err)
	}
	unknown := map[string]bool{}
	for _, r := range WinRules {
		if r.Eval(f).Status == Unknown {
			unknown[r.ID] = true
		}
	}
	for _, id := range []string{"WIN-001", "WIN-002", "WIN-003", "WIN-006", "WIN-007", "WIN-010", "WIN-011", "WIN-012", "WIN-013"} {
		if !unknown[id] {
			t.Errorf("%s must be unknown when its data could not be read", id)
		}
	}
	// A missing OS query is a hard failure: nothing useful was learned.
	if _, err := CollectWindows(context.Background(), fakeWin{}, now2026); err == nil {
		t.Error("a host that returns no version must fail the audit")
	}
}

func TestWindowsAllowlistIsReadOnly(t *testing.T) {
	for _, s := range WinAllowedScripts() {
		low := strings.ToLower(s)
		for _, bad := range []string{"set-", "remove-", "new-", "invoke-", "start-", "stop-", "restart-", "enable-", "disable-", "add-", "install-", "out-file", "iex", "downloadstring", "format-", "clear-", "write-"} {
			if strings.Contains(low, bad) {
				t.Errorf("script contains state-changing or risky %q: %.80s", bad, s)
			}
		}
		if !strings.HasPrefix(low, "$") && !strings.HasPrefix(low, "get-") && s != "net accounts" {
			t.Errorf("unexpected script start: %.60s", s)
		}
	}
	if _, err := (WinGuard{fakeWin{}}).Run(context.Background(), "Remove-Item C:\\ -Recurse"); err != ErrCommandNotAllowed {
		t.Errorf("a script outside the allowlist must be refused, got %v", err)
	}
}

func TestWinCredsValidate(t *testing.T) {
	if (WinCreds{User: "a"}).Validate() == nil || (WinCreds{Password: "p"}).Validate() == nil {
		t.Error("user and password are both required")
	}
	if (WinCreds{}).port() != 5986 || (WinCreds{HTTP: true}).port() != 5985 || (WinCreds{Port: 9999}).port() != 9999 {
		t.Error("default ports")
	}
}
