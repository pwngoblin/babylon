package audit

import (
	"context"
	"fmt"
	"sort"

	"babylon/internal/pkgver"
	"babylon/internal/store"
)

// AdvisorySource abstracts the OSV index (the store in production).
type AdvisorySource interface {
	OSVForPackages(ctx context.Context, ecoPrefix string, names []string) ([]store.PkgAdvisory, error)
}

// PkgVuln is one installed package affected by one advisory/CVE, with the
// version that fixes it. Version comparison uses the distro's own rules and
// the distro's own fixed version, so backported fixes are honoured: this is
// authoritative, unlike banner matching.
type PkgVuln struct {
	Package   Package // the installed package
	SrcName   string  // advisory package name
	Installed string  // version compared (source version for deb/apk)
	Advisory  string
	CVE       string // empty when the advisory carries none
	Fixed     string
	Summary   string
	Scheme    string // deb | rpm | apk
	Ecosystem string
}

// MatchStats say what was and was not checked.
type MatchStats struct {
	Ecosystem   string
	Unsupported string // non-empty: why package matching was skipped
	Packages    int
	Unfixed     int // advisories with no fixed version, not reported (nothing to act on)
}

// MatchPackages finds installed packages older than the vendor-fixed version.
// Advisories without a fixed version are counted but not reported: there is no
// patch to apply, and distros mark many such items "won't fix"/minor.
func MatchPackages(ctx context.Context, src AdvisorySource, f *Facts) ([]PkgVuln, MatchStats, error) {
	prefix, scheme := f.OS.Ecosystem()
	st := MatchStats{Ecosystem: prefix, Packages: len(f.Packages)}
	if prefix == "" {
		st.Unsupported = fmt.Sprintf("no OSV ecosystem for OS %q %q (supported: Debian, Ubuntu, Alpine, Rocky Linux, AlmaLinux)", f.OS.ID, f.OS.VersionID)
		return nil, st, nil
	}
	if len(f.Packages) == 0 {
		st.Unsupported = "no packages were collected"
		return nil, st, nil
	}
	// Index installed packages by the name advisories use.
	bySrc := map[string][]Package{}
	for _, p := range f.Packages {
		bySrc[p.SrcName] = append(bySrc[p.SrcName], p)
		if scheme == "rpm" && p.Name != p.SrcName {
			bySrc[p.Name] = append(bySrc[p.Name], p)
		}
	}
	names := make([]string, 0, len(bySrc))
	for n := range bySrc {
		names = append(names, n)
	}
	sort.Strings(names)
	advs, err := src.OSVForPackages(ctx, prefix, names)
	if err != nil {
		return nil, st, err
	}
	type key struct{ pkg, ver, id string }
	best := map[key]PkgVuln{}
	unfixed := map[string]bool{}
	for _, a := range advs {
		for _, p := range bySrc[a.Package] {
			installed := p.SrcVersion
			if scheme == "rpm" {
				installed = p.Version
			}
			if !affected(scheme, installed, a) {
				if a.Fixed == "" && a.LastAffected == "" && introducedOK(scheme, installed, a.Introduced) {
					unfixed[a.Advisory+"|"+p.Name] = true
				}
				continue
			}
			ids := a.CVEs
			if len(ids) == 0 {
				ids = []string{""}
			}
			for _, cve := range ids {
				id := cve
				if id == "" {
					id = a.Advisory
				}
				k := key{p.Name, installed, id}
				v := PkgVuln{Package: p, SrcName: a.Package, Installed: installed, Advisory: a.Advisory, CVE: cve,
					Fixed: a.Fixed, Summary: a.Summary, Scheme: scheme, Ecosystem: prefix}
				// Several advisories can cover one CVE; keep the lowest fix that resolves it.
				if old, ok := best[k]; ok {
					if c, _ := pkgver.Compare(scheme, v.Fixed, old.Fixed); c >= 0 && old.Fixed != "" {
						continue
					}
				}
				best[k] = v
			}
		}
	}
	st.Unfixed = len(unfixed)
	out := make([]PkgVuln, 0, len(best))
	for _, v := range best {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package.Name != out[j].Package.Name {
			return out[i].Package.Name < out[j].Package.Name
		}
		return out[i].CVE+out[i].Advisory < out[j].CVE+out[j].Advisory
	})
	return out, st, nil
}

func introducedOK(scheme, installed, introduced string) bool {
	if introduced == "" || introduced == "0" {
		return true
	}
	c, ok := pkgver.Compare(scheme, installed, introduced)
	return ok && c >= 0
}

// affected reports whether installed falls in the advisory range
// [introduced, fixed) or [introduced, last_affected].
func affected(scheme, installed string, a store.PkgAdvisory) bool {
	if !introducedOK(scheme, installed, a.Introduced) {
		return false
	}
	switch {
	case a.Fixed != "":
		c, ok := pkgver.Compare(scheme, installed, a.Fixed)
		return ok && c < 0
	case a.LastAffected != "":
		c, ok := pkgver.Compare(scheme, installed, a.LastAffected)
		return ok && c <= 0
	}
	return false
}
