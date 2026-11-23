package scan

import (
	"babylon/internal/intel"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"babylon/internal/correlate"
	"babylon/internal/matcher"
	"babylon/internal/model"
	"babylon/internal/orchestrator"
	"babylon/internal/store"
)

const (
	StageCPEMatch = "cpematch"

	cpeHostsPerJob = 50
	cpeCheckID     = "cpe-version-match"
)

// cpeMatchStage maps every detected product/version to known CVEs from the
// local NVD index. It does no network I/O. Results are tentative or firm
// (never confirmed) unless an independent behavioural check agrees.
func cpeMatchStage(st *store.Store, extraDeps ...string) orchestrator.Stage {
	return orchestrator.Stage{
		Name:      StageCPEMatch,
		Class:     ClassNative,
		DependsOn: append([]string{StagePortscan}, extraDeps...),
		Plan: func(ctx context.Context, sc store.Scan) ([]store.JobSpec, error) {
			if n, _, _ := st.CountCVEs(ctx); n == 0 {
				return nil, nil // no feed: the caller warns; nothing to match against
			}
			svcs, err := st.OpenServices(ctx, sc.ID)
			if err != nil {
				return nil, err
			}
			seen := map[string]bool{}
			var hosts []string
			for _, s := range svcs {
				if !seen[s.Address] {
					seen[s.Address] = true
					hosts = append(hosts, s.Address)
				}
			}
			return chunkSpecs(hosts, cpeHostsPerJob, "cpe", nil), nil
		},
		Handle: func(ctx context.Context, job store.Job) error {
			bg := context.WithoutCancel(ctx)
			all, err := st.OpenServices(bg, job.ScanID)
			if err != nil {
				return err
			}
			for _, addr := range job.Targets {
				if err := matchHost(bg, st, job.ScanID, addr, all); err != nil {
					return fmt.Errorf("cpe matching %s: %w", addr, err)
				}
			}
			return nil
		},
	}
}

func matchHost(ctx context.Context, st *store.Store, scanID int64, addr string, all []store.ServiceInfo) error {
	var assetID int64
	checked, unchecked := 0, 0
	for _, s := range all {
		if s.Address != addr {
			continue
		}
		assetID = s.AssetID
		hits, stats, err := matcher.Match(ctx, st, matcher.Service{
			Address: s.Address, Port: s.Port, Proto: s.Proto, Name: s.Name, Product: s.Product, Version: s.Version,
			Extra: s.Extra, Banner: s.Banner, OS: s.OS, CPEs: s.CPEs,
		})
		if err != nil {
			return err
		}
		if !stats.Checked {
			unchecked++
			if f, ok := kevWatch(ctx, st, s); ok {
				if err := st.RecordFinding(ctx, scanID, f); err != nil {
					return err
				}
			}
			continue
		}
		checked++
		for _, h := range hits {
			if err := st.RecordFinding(ctx, scanID, hitToFinding(s, h)); err != nil {
				return err
			}
		}
	}
	if assetID == 0 {
		return nil
	}
	n, err := matchWebTech(ctx, st, scanID, addr, assetID, all)
	if err != nil {
		return err
	}
	checked += n
	if checked == 0 {
		return st.RecordCheckRun(ctx, scanID, assetID, cpeCheckID, "skipped", "no service reported a product and version")
	}
	reason := ""
	if unchecked > 0 {
		reason = fmt.Sprintf("%d of %d services had no version to match", unchecked, checked+unchecked)
	}
	return st.RecordCheckRun(ctx, scanID, assetID, cpeCheckID, "ran", reason)
}

func severityFromCVSS(c *float64) string {
	if c == nil {
		return "medium" // scored later by NVD; do not hide it
	}
	switch v := *c; {
	case v >= 9:
		return "critical"
	case v >= 7:
		return "high"
	case v >= 4:
		return "medium"
	case v > 0:
		return "low"
	}
	return "info"
}

func displayProduct(s store.ServiceInfo, h matcher.Hit) string {
	if p := strings.TrimSpace(s.Product); p != "" {
		return p
	}
	return strings.ReplaceAll(h.Product, "_", " ")
}

func hitToFinding(s store.ServiceInfo, h matcher.Hit) model.Finding {
	prod := displayProduct(s, h)
	remediation := "Check the vendor's advisory for a fixed release and upgrade."
	solution := ""
	if h.FixedIn != "" {
		remediation = fmt.Sprintf("Upgrade %s to %s or later.", prod, h.FixedIn)
		solution = "VendorFix"
	}
	desc := strings.TrimSpace(h.Description)
	if len(desc) > 1500 {
		desc = strings.ToValidUTF8(desc[:1500], "") + "…"
	}
	var ev strings.Builder
	fmt.Fprintf(&ev, "Detected %s %s on %d/%s (Nmap service detection)\nNVD affected range for %s:%s: %s", prod, h.Version, s.Port, s.Proto, h.Vendor, h.Product, h.Range)
	if h.Vector != "" {
		fmt.Fprintf(&ev, "\nCVSS vector: %s", h.Vector)
	}
	if h.Caveat != "" {
		ev.WriteString("\nNote: " + h.Caveat)
		desc += "\n\n" + h.Caveat
	}
	return model.Finding{
		Fingerprint: correlate.Fingerprint(s.Address, s.Port, s.Proto, []string{h.CVE}, ""),
		Address:     s.Address, Port: s.Port, Proto: s.Proto,
		Title:    fmt.Sprintf("%s: %s %s", h.CVE, prod, h.Version),
		Family:   "Vulnerable software (version match)",
		Severity: severityFromCVSS(h.CVSS),
		CVSS:     h.CVSS, CVSSVector: h.Vector, CVEs: []string{h.CVE},
		Synopsis:    fmt.Sprintf("The detected %s %s falls inside a version range affected by %s.", prod, h.Version, h.CVE),
		Description: desc, Remediation: remediation, Solution: solution,
		Confidence: h.Confidence, Detection: "version", Engine: "cpematch", EngineRef: h.Vendor + ":" + h.Product,
		Evidence: ev.String(), Product: prod, Version: h.Version,
	}
}

// matchWebTech matches versions learned from web responses (frameworks, CMSs,
// application servers) that Nmap's service detection does not report.
func matchWebTech(ctx context.Context, st *store.Store, scanID int64, addr string, assetID int64, all []store.ServiceInfo) (int, error) {
	kb, err := st.KB(ctx, scanID, assetID)
	if err != nil {
		return 0, err
	}
	checked := 0
	prefix := "Web/" + addr + ":"
	for key, raw := range kb {
		if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, "/cpe") {
			continue
		}
		port, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(key, prefix), "/cpe"))
		var cpes []string
		if json.Unmarshal(raw, &cpes) != nil {
			continue
		}
		var base store.ServiceInfo
		for _, s := range all {
			if s.Address == addr && s.Port == port {
				base = s
			}
		}
		if base.Address == "" {
			continue // the port is not in this scan's inventory
		}
		for _, c := range cpes {
			parsed, ok := intel.ParseCPE(c)
			if !ok || parsed.Version == "" {
				continue
			}
			svc := base
			svc.Product, svc.Version, svc.CPEs = strings.ReplaceAll(parsed.Product, "_", " "), parsed.Version, []string{c}
			hits, stats, err := matcher.Match(ctx, st, matcher.Service{
				Address: svc.Address, Port: svc.Port, Proto: svc.Proto, Name: svc.Name, Product: svc.Product, Version: svc.Version,
				Extra: svc.Extra, Banner: svc.Banner, OS: svc.OS, CPEs: svc.CPEs,
			})
			if err != nil {
				return checked, err
			}
			if !stats.Checked {
				continue
			}
			checked++
			for _, h := range hits {
				f := hitToFinding(svc, h)
				f.Evidence = strings.Replace(f.Evidence, "(Nmap service detection)", "(web technology detection)", 1)
				if err := st.RecordFinding(ctx, scanID, f); err != nil {
					return checked, err
				}
			}
		}
	}
	return checked, nil
}

func normName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// kevWatch covers a blind spot of version matching: a product is identified but
// its version cannot be read (appliances, hardened banners). If CISA lists known
// exploited vulnerabilities for that product, say so as a tentative finding:
// it cannot say the host is affected, only that the product is a known target.
func kevWatch(ctx context.Context, st *store.Store, s store.ServiceInfo) (model.Finding, bool) {
	prod := normName(s.Product)
	if len(prod) < 4 {
		return model.Finding{}, false
	}
	vendors := map[string]bool{}
	cpeProducts := map[string]bool{}
	for _, c := range s.CPEs {
		if p, ok := intel.ParseCPE(c); ok {
			vendors[normName(p.Vendor)] = true
			cpeProducts[normName(p.Product)] = true
		}
	}
	all, err := st.AllKEV(ctx)
	if err != nil {
		return model.Finding{}, false
	}
	var hits []store.KEVEntry
	for _, k := range all {
		kp, kv := normName(k.Product), normName(k.Vendor)
		if len(kp) < 4 {
			continue
		}
		// The KEV product must be the service's product (or the CPE product), and the
		// vendor must agree: through the CPE, or by appearing in the product string.
		productOK := kp == prod || strings.Contains(prod, kp) || cpeProducts[kp]
		vendorOK := vendors[kv] || (len(kv) >= 4 && strings.Contains(prod, kv))
		if productOK && vendorOK {
			hits = append(hits, k)
		}
	}
	if len(hits) == 0 {
		return model.Finding{}, false
	}
	var ids []string
	for _, h := range hits {
		ids = append(ids, h.CVE)
	}
	shown := ids
	if len(shown) > 12 {
		shown = shown[:12]
	}
	return model.Finding{
		Fingerprint: correlate.Fingerprint(s.Address, s.Port, s.Proto, nil, "kev-watch:"+prod),
		Address:     s.Address, Port: s.Port, Proto: s.Proto,
		Title:  fmt.Sprintf("%s is a known exploited product (%d CISA KEV entries); version unknown", s.Product, len(hits)),
		Family: "Known exploited product", Severity: "medium",
		Synopsis:    "The product is listed in the CISA Known Exploited Vulnerabilities catalogue, and its version could not be determined.",
		Description: "Babylon could not read the version of this service, so it cannot tell whether it is affected. Verify the version and patch level; a credentialed scan or the vendor's console will tell.",
		Remediation: "Identify the exact version and apply the vendor's security updates for the listed CVEs.",
		Confidence:  model.ConfTentative, Detection: "version", Engine: "cpematch", EngineRef: "kev-watch",
		CVEs:     nil,
		Evidence: fmt.Sprintf("Detected product %q on %d/%s with no version. CISA KEV entries for this product: %s", s.Product, s.Port, s.Proto, strings.Join(shown, ", ")),
		Product:  s.Product, Version: "unknown",
	}, true
}
