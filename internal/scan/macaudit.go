package scan

import (
	"context"
	"fmt"
	"time"

	"babylon/internal/audit"
	"babylon/internal/correlate"
	"babylon/internal/model"
	"babylon/internal/store"
)

const (
	checkMacPatch  = "macos-patch-audit"
	familyMacPatch = "Missing patch (macOS)"
)

// macPatchAudit compares the host's macOS version with Apple's per-release CVE
// lists and records one finding per missing CVE fix, plus an end-of-support
// finding when Apple no longer ships fixes for the host's line.
func macPatchAudit(bg context.Context, st *store.Store, scanID, assetID int64, addr string, facts *audit.Facts) error {
	missing, stats, err := audit.MatchMacUpdates(bg, st, facts, time.Now())
	if err != nil {
		return err
	}
	if stats.Unsupported != "" && !stats.OutOfSupport {
		return st.RecordCheckRun(bg, scanID, assetID, checkMacPatch, "skipped", stats.Unsupported)
	}
	for _, f := range macPatchFindings(addr, facts, missing, stats) {
		if err := st.RecordFinding(bg, scanID, f); err != nil {
			return err
		}
	}
	return st.RecordCheckRun(bg, scanID, assetID, checkMacPatch, "ran", "")
}

func macPatchFindings(addr string, f *audit.Facts, missing []audit.MacMissing, stats audit.MacPatchStats) []model.Finding {
	ver := f.Mac.ProductVersion
	product := stats.Product
	if product == "" {
		product = fmt.Sprintf("macOS %d", f.Mac.Major())
	}
	var out []model.Finding
	if stats.OutOfSupport {
		out = append(out, model.Finding{
			Fingerprint: correlate.Fingerprint(addr, 0, "", nil, "macos-eol"),
			Address:     addr, Title: fmt.Sprintf("Unsupported macOS version: %s %s", product, ver),
			Family: "Unsupported software", Severity: "high",
			Synopsis:    "Apple no longer publishes security updates for this macOS release line.",
			Description: fmt.Sprintf("The newest security release for macOS %d is %s (%s). Vulnerabilities found since then are not fixed in this line.", f.Mac.Major(), stats.Latest, stats.LatestDate),
			Remediation: "Upgrade to a supported macOS release (Apple supports roughly the newest three), or replace hardware that cannot run one.",
			Confidence:  model.ConfFirm, Detection: "version", Engine: "audit", EngineRef: "macos-eol",
			Evidence: fmt.Sprintf("Installed macOS %s (build %s); latest Apple security release for this line: %s on %s.", ver, f.Mac.Build, stats.Latest, stats.LatestDate),
		})
	}
	for _, x := range missing {
		sev := severityFromCVSS(x.CVSS)
		out = append(out, model.Finding{
			Fingerprint: correlate.Fingerprint(addr, 0, fmt.Sprintf("macos:%d", f.Mac.Major()), []string{x.CVE}, "macos:"+x.CVE),
			Address:     addr,
			Title:       fmt.Sprintf("%s: fixed in %s %s", x.CVE, product, x.FixedIn),
			Family:      familyMacPatch, Severity: sev, CVSS: x.CVSS, CVEs: []string{x.CVE},
			Synopsis:    fmt.Sprintf("The host runs macOS %s, which predates Apple's fix for %s.", ver, x.CVE),
			Description: fmt.Sprintf("Apple fixed %s in %s %s.", x.CVE, product, x.FixedIn),
			Remediation: fmt.Sprintf("Update macOS to %s or later (System Settings > General > Software Update, or `sudo softwareupdate -i -a`, or your MDM).", stats.Latest),
			Solution:    "VendorFix", Confidence: model.ConfConfirmed, Detection: "version", Engine: "audit", EngineRef: "apple:" + x.CVE,
			Evidence: fmt.Sprintf("Installed macOS %s (build %s); Apple fixed this in %s %s.", ver, f.Mac.Build, product, x.FixedIn),
			Product:  product, Version: ver,
		})
	}
	return out
}
