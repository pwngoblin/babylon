package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"babylon/internal/store"
	"babylon/internal/winrel"
)

// Windows credentialed audit (over WinRM). Everything Babylon runs on a Windows
// host is one of the fixed, read-only PowerShell scripts below (Get-* queries
// and `net accounts`); none takes data from scan results as an argument.

const (
	psOS = `$o=Get-CimInstance Win32_OperatingSystem; $v=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; [pscustomobject]@{Caption=$o.Caption;Version=$o.Version;Build=$o.BuildNumber;UBR=$v.UBR;DisplayVersion=$v.DisplayVersion;Arch=$o.OSArchitecture;ProductType=$o.ProductType} | ConvertTo-Json -Compress`

	psHotfix = `Get-HotFix | Select-Object HotFixID,@{n='InstalledOn';e={if($_.InstalledOn){$_.InstalledOn.ToString('yyyy-MM-dd')}}} | ConvertTo-Json -Compress`

	psSoftware = `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher | ConvertTo-Json -Compress`

	// psSecurity reports one JSON object. A key is present only when its query
	// succeeded; a present key with null means the setting is not configured
	// (so the OS default applies). A missing key means "could not be read".
	psSecurity = `$r=[ordered]@{}; ` +
		`try{$c=Get-SmbServerConfiguration; $r.smb1=$c.EnableSMB1Protocol; $r.smbSigning=$c.RequireSecuritySignature}catch{}; ` +
		`try{Get-NetFirewallProfile | ForEach-Object{$r['fw_'+$_.Name]=[bool]$_.Enabled}}catch{}; ` +
		`try{$d=Get-MpComputerStatus; $r.av=$d.AntivirusEnabled; $r.rtp=$d.RealTimeProtectionEnabled; $r.sigAge=$d.AntivirusSignatureAge}catch{}; ` +
		`try{$r.nla=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction Stop).UserAuthentication}catch{}; ` +
		`try{$r.uac=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop).EnableLUA}catch{}; ` +
		`try{$r.wdigest=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction Stop).UseLogonCredential}catch{}; ` +
		`try{$r.lmcompat=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop).LmCompatibilityLevel}catch{}; ` +
		`try{$r.guest=(Get-LocalUser -Name Guest -ErrorAction Stop).Enabled}catch{}; ` +
		`try{$r.llmnr=(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction Stop).EnableMulticast}catch{$r.llmnr=$null}; ` +
		`try{$r.autorun=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction Stop).NoDriveTypeAutoRun}catch{$r.autorun=$null}; ` +
		`$r | ConvertTo-Json -Compress`

	psNetAccounts = `net accounts`

	psAdmins = `Get-LocalGroupMember -Group Administrators | Select-Object Name,ObjectClass | ConvertTo-Json -Compress`
)

var winAllowed = map[string]bool{psOS: true, psHotfix: true, psSoftware: true, psSecurity: true, psNetAccounts: true, psAdmins: true}

// WinAllowedScripts exposes the allowlist for tests.
func WinAllowedScripts() []string {
	out := make([]string, 0, len(winAllowed))
	for s := range winAllowed {
		out = append(out, s)
	}
	return out
}

// WinGuard wraps a Runner so only allowlisted scripts can run.
type WinGuard struct{ R Runner }

func (g WinGuard) Run(ctx context.Context, cmd string) (string, error) {
	if !winAllowed[cmd] {
		return "", ErrCommandNotAllowed
	}
	return g.R.Run(ctx, cmd)
}

// WinFacts is what one Windows host reported.
type WinFacts struct {
	Caption, Version, Build, DisplayVersion, Arch string
	UBR                                           int
	Server                                        bool
	Hotfixes                                      []Hotfix
	Software                                      []WinSoftware
	Sec                                           map[string]any // see psSecurity
	Policy                                        map[string]string
	Admins                                        []string
	Now                                           time.Time
	Errors                                        []string
}

type Hotfix struct{ ID, InstalledOn string }
type WinSoftware struct{ Name, Version, Publisher string }

// BuildKey is the MSRC build identifier, for example 10.0.19045.
func (f *WinFacts) BuildKey() string {
	if f.Version == "" {
		return ""
	}
	parts := strings.Split(f.Version, ".")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ".")
	}
	if f.Build != "" && len(parts) >= 2 {
		return parts[0] + "." + parts[1] + "." + f.Build
	}
	return ""
}

// FullVersion is build plus update revision, e.g. 10.0.19045.4529.
func (f *WinFacts) FullVersion() string { return f.BuildKey() + "." + strconv.Itoa(f.UBR) }

// jsonList decodes PowerShell's ConvertTo-Json output, which is an object for one
// item and an array for several.
func jsonList(s string, into any) error {
	s = strings.TrimSpace(strings.TrimPrefix(s, "\xef\xbb\xbf"))
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "{") {
		s = "[" + s + "]"
	}
	return json.Unmarshal([]byte(s), into)
}

// CollectWindows gathers facts through a Runner that enforces the allowlist.
func CollectWindows(ctx context.Context, r Runner, now time.Time) (*WinFacts, error) {
	r = WinGuard{r}
	f := &WinFacts{Now: now}
	note := func(msg string) { f.Errors = append(f.Errors, msg) }

	out, err := r.Run(ctx, psOS)
	if err != nil || strings.TrimSpace(out) == "" {
		return f, fmt.Errorf("could not read Windows version: %v", err)
	}
	var os struct {
		Caption, Version, Build, DisplayVersion, Arch string
		UBR                                           json.Number
		ProductType                                   int
	}
	var one []struct {
		Caption, Version, Build, DisplayVersion, Arch string
		UBR                                           json.Number
		ProductType                                   int
	}
	if err := jsonList(out, &one); err != nil || len(one) == 0 {
		return f, fmt.Errorf("unreadable Windows version output: %v", err)
	}
	os = one[0]
	f.Caption, f.Version, f.Build, f.DisplayVersion, f.Arch = os.Caption, os.Version, os.Build, os.DisplayVersion, os.Arch
	f.Server = os.ProductType != 1
	if n, err := os.UBR.Int64(); err == nil {
		f.UBR = int(n)
	} else {
		note("update revision (UBR) could not be read; missing-patch results are unavailable")
	}

	if out, err := r.Run(ctx, psHotfix); err == nil {
		var hs []struct{ HotFixID, InstalledOn string }
		if jsonList(out, &hs) == nil {
			for _, h := range hs {
				f.Hotfixes = append(f.Hotfixes, Hotfix{h.HotFixID, h.InstalledOn})
			}
		}
	} else {
		note("hotfix list unavailable")
	}
	if out, err := r.Run(ctx, psSoftware); err == nil {
		var ss []struct{ DisplayName, DisplayVersion, Publisher string }
		if jsonList(out, &ss) == nil {
			for _, s := range ss {
				f.Software = append(f.Software, WinSoftware{s.DisplayName, s.DisplayVersion, s.Publisher})
			}
		}
	} else {
		note("installed software list unavailable")
	}
	if out, err := r.Run(ctx, psSecurity); err == nil && strings.TrimSpace(out) != "" {
		_ = json.Unmarshal([]byte(strings.TrimSpace(out)), &f.Sec)
	} else {
		note("security settings unavailable")
	}
	if out, err := r.Run(ctx, psNetAccounts); err == nil {
		f.Policy = parseNetAccounts(out)
	}
	if out, err := r.Run(ctx, psAdmins); err == nil {
		var as []struct{ Name, ObjectClass string }
		if jsonList(out, &as) == nil {
			for _, a := range as {
				f.Admins = append(f.Admins, a.Name)
			}
		}
	}
	return f, nil
}

var accountsLine = regexp.MustCompile(`^\s*([^:]+?):\s*(.+?)\s*$`)

func parseNetAccounts(s string) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		if m := accountsLine.FindStringSubmatch(strings.TrimRight(l, "\r")); m != nil {
			out[strings.ToLower(m[1])] = m[2]
		}
	}
	return out
}

// ---- missing patches (MSRC) ----

// WinPatchStats describes the patch match for reporting coverage.
type WinPatchStats struct {
	Unsupported string // reason the audit could not match patches
	Latest      store.MSRCFix
}

// MatchWindowsUpdates lists known fixes the host does not have yet.
func MatchWindowsUpdates(ctx context.Context, st *store.Store, f *WinFacts) ([]store.MSRCFix, WinPatchStats, error) {
	var stats WinPatchStats
	key := f.BuildKey()
	if key == "" || f.UBR == 0 {
		stats.Unsupported = "build number or update revision not available"
		return nil, stats, nil
	}
	if n, _, err := st.CountMSRC(ctx); err != nil {
		return nil, stats, err
	} else if n == 0 {
		stats.Unsupported = "no Microsoft security data indexed (run: babylon update-feeds --only msrc)"
		return nil, stats, nil
	}
	fixes, err := st.MSRCMissing(ctx, key, f.UBR)
	if err != nil {
		return nil, stats, err
	}
	for _, x := range fixes {
		if x.FixedUBR > stats.Latest.FixedUBR {
			stats.Latest = x
		}
	}
	return fixes, stats, nil
}

// ---- hardening rules ----

type WinRule struct {
	ID       string
	Title    string
	Severity string
	Synopsis string
	Eval     func(*WinFacts) Result
}

func secBool(f *WinFacts, key string) (val bool, present bool) {
	v, ok := f.Sec[key]
	if !ok {
		return false, false
	}
	b, isBool := v.(bool)
	return b, isBool
}

func secNum(f *WinFacts, key string) (val float64, present, configured bool) {
	v, ok := f.Sec[key]
	if !ok {
		return 0, false, false
	}
	n, isNum := v.(float64)
	return n, true, isNum
}

func winUnknown(what string) Result {
	return Result{Status: Unknown, Reason: what + " could not be read (the account may lack administrator rights)"}
}

var WinRules = []WinRule{
	{"WIN-001", "SMBv1 is enabled", "high", "The obsolete SMBv1 protocol is enabled on the server.", func(f *WinFacts) Result {
		v, ok := secBool(f, "smb1")
		switch {
		case !ok:
			return winUnknown("SMB server configuration")
		case v:
			return Result{Status: Fail, Evidence: "EnableSMB1Protocol = True", Remediation: "Run `Set-SmbServerConfiguration -EnableSMB1Protocol $false` and remove the SMB1 Windows feature."}
		}
		return Result{Status: Pass, Evidence: "SMBv1 disabled"}
	}},
	{"WIN-002", "SMB signing is not required", "medium", "Unsigned SMB traffic can be relayed or tampered with.", func(f *WinFacts) Result {
		v, ok := secBool(f, "smbSigning")
		switch {
		case !ok:
			return winUnknown("SMB server configuration")
		case !v:
			return Result{Status: Fail, Evidence: "RequireSecuritySignature = False", Remediation: "Run `Set-SmbServerConfiguration -RequireSecuritySignature $true`."}
		}
		return Result{Status: Pass, Evidence: "SMB signing required"}
	}},
	{"WIN-003", "Windows Firewall is disabled on a profile", "high", "At least one firewall profile (Domain, Private, Public) is turned off.", func(f *WinFacts) Result {
		var off, seen []string
		for _, p := range []string{"Domain", "Private", "Public"} {
			if v, ok := secBool(f, "fw_"+p); ok {
				seen = append(seen, p)
				if !v {
					off = append(off, p)
				}
			}
		}
		switch {
		case len(seen) == 0:
			return winUnknown("firewall profiles")
		case len(off) > 0:
			return Result{Status: Fail, Evidence: "disabled: " + strings.Join(off, ", "), Remediation: "Run `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True`."}
		}
		return Result{Status: Pass, Evidence: "all firewall profiles enabled"}
	}},
	{"WIN-004", "Antivirus or real-time protection is off", "high", "Microsoft Defender is not actively protecting the host.", func(f *WinFacts) Result {
		av, ok1 := secBool(f, "av")
		rtp, ok2 := secBool(f, "rtp")
		if !ok1 && !ok2 {
			return Result{Status: Unknown, Reason: "Microsoft Defender status unavailable (another AV product may be installed, or the account lacks rights)"}
		}
		if (ok1 && !av) || (ok2 && !rtp) {
			return Result{Status: Fail, Evidence: fmt.Sprintf("AntivirusEnabled=%v RealTimeProtectionEnabled=%v", av, rtp), Remediation: "Enable real-time protection, or confirm a managed AV product is active."}
		}
		return Result{Status: Pass, Evidence: "Defender enabled with real-time protection"}
	}},
	{"WIN-005", "Antivirus signatures are out of date", "medium", "Defender signatures are older than 14 days.", func(f *WinFacts) Result {
		n, ok, conf := secNum(f, "sigAge")
		if !ok || !conf {
			return winUnknown("Defender signature age")
		}
		if n > 14 {
			return Result{Status: Fail, Evidence: fmt.Sprintf("signatures are %.0f days old", n), Remediation: "Run `Update-MpSignature` and check that the host can reach Microsoft update services."}
		}
		return Result{Status: Pass, Evidence: fmt.Sprintf("signatures are %.0f days old", n)}
	}},
	{"WIN-006", "Remote Desktop does not require Network Level Authentication", "medium", "RDP shows a login screen before authentication.", func(f *WinFacts) Result {
		n, ok, conf := secNum(f, "nla")
		switch {
		case !ok || !conf:
			return winUnknown("RDP settings")
		case n != 1:
			return Result{Status: Fail, Evidence: fmt.Sprintf("UserAuthentication = %.0f", n), Remediation: "Enable `Require user authentication for remote connections by using Network Level Authentication`."}
		}
		return Result{Status: Pass, Evidence: "NLA required"}
	}},
	{"WIN-007", "User Account Control is disabled", "high", "UAC prompts for elevation are turned off.", func(f *WinFacts) Result {
		n, ok, conf := secNum(f, "uac")
		switch {
		case !ok || !conf:
			return winUnknown("UAC setting")
		case n == 0:
			return Result{Status: Fail, Evidence: "EnableLUA = 0", Remediation: "Set `EnableLUA` to 1 (policy `User Account Control: Run all administrators in Admin Approval Mode`) and reboot."}
		}
		return Result{Status: Pass, Evidence: "EnableLUA = 1"}
	}},
	{"WIN-008", "WDigest stores cleartext credentials in memory", "high", "UseLogonCredential is set, so passwords can be read from memory.", func(f *WinFacts) Result {
		n, ok, conf := secNum(f, "wdigest")
		switch {
		case !ok:
			return Result{Status: Pass, Evidence: "WDigest key absent (modern Windows defaults to off)"}
		case conf && n == 1:
			return Result{Status: Fail, Evidence: "UseLogonCredential = 1", Remediation: "Set `UseLogonCredential` to 0 under HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest."}
		}
		return Result{Status: Pass, Evidence: "UseLogonCredential not enabled"}
	}},
	{"WIN-009", "LAN Manager authentication level is weak", "medium", "The host still accepts LM or NTLMv1 responses.", func(f *WinFacts) Result {
		n, ok, conf := secNum(f, "lmcompat")
		switch {
		case !ok:
			return winUnknown("LmCompatibilityLevel")
		case !conf: // not configured: the OS default (3 or higher on supported Windows) applies
			return Result{Status: Pass, Evidence: "LmCompatibilityLevel not set (OS default)"}
		case n < 3:
			return Result{Status: Fail, Evidence: fmt.Sprintf("LmCompatibilityLevel = %.0f", n), Remediation: "Set `Network security: LAN Manager authentication level` to `Send NTLMv2 response only. Refuse LM & NTLM` (5)."}
		}
		return Result{Status: Pass, Evidence: fmt.Sprintf("LmCompatibilityLevel = %.0f", n)}
	}},
	{"WIN-010", "Guest account is enabled", "medium", "The built-in Guest account can be used to log in.", func(f *WinFacts) Result {
		v, ok := secBool(f, "guest")
		switch {
		case !ok:
			return winUnknown("Guest account state")
		case v:
			return Result{Status: Fail, Evidence: "Guest account enabled", Remediation: "Run `Disable-LocalUser -Name Guest`."}
		}
		return Result{Status: Pass, Evidence: "Guest account disabled"}
	}},
	{"WIN-011", "Password policy is weak", "low", "Minimum length, maximum age or lockout settings are not enforced.", func(f *WinFacts) Result {
		if len(f.Policy) == 0 {
			return winUnknown("`net accounts` output")
		}
		var bad []string
		if v, err := strconv.Atoi(f.Policy["minimum password length"]); err == nil && v < 8 {
			bad = append(bad, fmt.Sprintf("minimum password length %d", v))
		}
		if v := f.Policy["maximum password age (days)"]; strings.EqualFold(v, "unlimited") {
			bad = append(bad, "passwords never expire")
		}
		if v := f.Policy["lockout threshold"]; strings.EqualFold(v, "never") {
			bad = append(bad, "no account lockout threshold")
		}
		if len(bad) > 0 {
			return Result{Status: Fail, Evidence: strings.Join(bad, "\n"), Remediation: "Set a minimum length of at least 12, a lockout threshold of 10 or fewer attempts, and an expiry that fits your policy (`net accounts` or Group Policy)."}
		}
		return Result{Status: Pass, Evidence: "length, age and lockout policy set"}
	}},
	{"WIN-012", "Many accounts are local administrators", "low", "More than four members in the local Administrators group.", func(f *WinFacts) Result {
		if f.Admins == nil {
			return winUnknown("local Administrators group")
		}
		if len(f.Admins) > 4 {
			return Result{Status: Fail, Evidence: strings.Join(f.Admins, "\n"), Remediation: "Remove accounts that do not need administrator rights; use named, least-privilege accounts."}
		}
		return Result{Status: Pass, Evidence: fmt.Sprintf("%d administrator accounts", len(f.Admins))}
	}},
	{"WIN-013", "LLMNR name resolution is enabled", "low", "Link-Local Multicast Name Resolution lets attackers capture credentials by answering name queries.", func(f *WinFacts) Result {
		v, ok := f.Sec["llmnr"]
		if !ok {
			return winUnknown("DNS client policy")
		}
		if n, isNum := v.(float64); isNum && n == 0 {
			return Result{Status: Pass, Evidence: "EnableMulticast = 0"}
		}
		return Result{Status: Fail, Evidence: "LLMNR is not disabled by policy", Remediation: "Enable the policy `Turn off multicast name resolution` (EnableMulticast = 0)."}
	}},
	{"WIN-014", "No security update was installed in the last 90 days", "medium", "The most recent installed hotfix is older than 90 days (heuristic).", func(f *WinFacts) Result {
		if len(f.Hotfixes) == 0 {
			return winUnknown("hotfix history")
		}
		var latest time.Time
		for _, h := range f.Hotfixes {
			if t, err := time.Parse("2006-01-02", h.InstalledOn); err == nil && t.After(latest) {
				latest = t
			}
		}
		if latest.IsZero() {
			return winUnknown("hotfix install dates")
		}
		if age := f.Now.Sub(latest); age > 90*24*time.Hour {
			return Result{Status: Fail, Evidence: fmt.Sprintf("last update installed %s (%d days ago)", latest.Format("2006-01-02"), int(age.Hours()/24)), Remediation: "Run Windows Update (or your patch tool) and check that updates are not being deferred or blocked."}
		}
		return Result{Status: Pass, Evidence: "last update installed " + latest.Format("2006-01-02")}
	}},
	{"WIN-015", "Windows version is out of support", "high", "The OS no longer receives security updates.", func(f *WinFacts) Result {
		rel := winrel.Lookup(f.Caption)
		if rel == nil {
			return Result{Status: Pass, Evidence: f.Caption}
		}
		if rel.EOL.Before(f.Now) {
			return Result{Status: Fail, Evidence: fmt.Sprintf("%s reached end of support on %s", rel.Name, rel.EOL.Format("2006-01-02")), Remediation: "Upgrade to a supported Windows release."}
		}
		return Result{Status: Pass, Evidence: fmt.Sprintf("%s supported until %s", rel.Name, rel.EOL.Format("2006-01-02"))}
	}},
}
