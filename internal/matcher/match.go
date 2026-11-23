package matcher

import (
	"context"
	"sort"
	"strings"

	"babylon/internal/intel"
	"babylon/internal/store"
)

// Source is the vulnerability index the matcher reads.
type Source interface {
	CPEMatches(ctx context.Context, vendor, product string) ([]store.MatchRow, error)
	VendorsForProduct(ctx context.Context, product string) ([]string, error)
}

// Service is one detected network service.
type Service struct {
	Address, Proto, Name, Product, Version, Extra, Banner, OS string
	Port                                                      int
	CPEs                                                      []string
}

// Hit is one CVE that a detected version falls inside the vulnerable range of.
type Hit struct {
	CVE         string
	Description string
	CVSS        *float64
	Vector      string
	Vendor      string // NVD vendor/product the hit came from
	Product     string
	Version     string // detected upstream version
	Range       string // human-readable vulnerable range
	FixedIn     string // first fixed upstream version if the range gives one
	Confidence  string
	Caveat      string
}

// Stats says why a service produced no (or few) hits, so coverage reports can
// tell "not vulnerable" from "could not be checked".
type Stats struct {
	Checked   bool   // a product and version were available to match
	Reason    string // set when Checked is false
	Unbounded int    // ranges with no version bound that were skipped as too broad
	AliasUsed string // non-empty when a vendor alias or unique-vendor fallback found the data
}

type target struct{ vendor, product, version string }

func targets(s Service) []target {
	var out []target
	seen := map[string]bool{}
	add := func(v, p, ver string) {
		if v == "" || p == "" || ver == "" {
			return
		}
		k := v + ":" + p + ":" + ver
		if !seen[k] {
			seen[k] = true
			out = append(out, target{v, p, ver})
		}
	}
	for _, raw := range s.CPEs {
		c, ok := intel.ParseCPE(raw)
		if !ok || c.Part != "a" {
			continue
		}
		ver := c.Version
		if c.Update != "" && ver != "" {
			ver += c.Update
		}
		if ver == "" {
			ver = CleanVersion(s.Version)
		}
		add(c.Vendor, c.Product, ver)
	}
	if len(out) == 0 {
		if vp, ok := productNames[strings.ToLower(strings.TrimSpace(s.Product))]; ok {
			v, p, _ := strings.Cut(vp, ":")
			add(v, p, CleanVersion(s.Version))
		}
	}
	return out
}

// Match finds CVEs whose vulnerable ranges contain the service's version.
func Match(ctx context.Context, src Source, s Service) ([]Hit, Stats, error) {
	ts := targets(s)
	if len(ts) == 0 {
		return nil, Stats{Reason: "no product/version identified"}, nil
	}
	st := Stats{Checked: true}
	byCVE := map[string]*Hit{}
	for _, t := range ts {
		cands := Candidates(t.vendor, t.product)
		rowsFor := map[[2]string][]store.MatchRow{}
		total := 0
		for _, c := range cands {
			rows, err := src.CPEMatches(ctx, c[0], c[1])
			if err != nil {
				return nil, st, err
			}
			rowsFor[c] = rows
			total += len(rows)
		}
		if total == 0 { // unknown vendor spelling: accept the product if only one vendor has it
			vs, err := src.VendorsForProduct(ctx, t.product)
			if err != nil {
				return nil, st, err
			}
			if len(vs) == 1 {
				c := [2]string{vs[0], t.product}
				rows, err := src.CPEMatches(ctx, c[0], c[1])
				if err != nil {
					return nil, st, err
				}
				rowsFor[c] = rows
				cands = append(cands, c)
				st.AliasUsed = vs[0] + ":" + t.product
			}
		} else if len(cands) > 1 || cands[0] != [2]string{t.vendor, t.product} {
			st.AliasUsed = "alias"
		}
		conf, caveat := Assess(t.product, strings.Join([]string{s.Banner, s.Version, s.Extra, s.Product}, " "), s.OS)
		for _, c := range cands {
			for _, r := range rowsFor[c] {
				if r.Match.TargetSW != "" {
					continue // plugin/extension for another platform, not the product itself
				}
				bounded, ok := inRange(t.version, r.Match)
				if !bounded {
					st.Unbounded++
					continue
				}
				if !ok {
					continue
				}
				h, exists := byCVE[r.CVE]
				if !exists {
					h = &Hit{CVE: r.CVE, Description: r.Description, CVSS: r.CVSS, Vector: r.Vector,
						Vendor: c[0], Product: c[1], Version: t.version, Confidence: conf, Caveat: caveat}
					byCVE[r.CVE] = h
				}
				h.Range = describeRange(r.Match)
				if fx := fixedIn(r.Match); fx != "" && (h.FixedIn == "" || Compare(fx, h.FixedIn) > 0) {
					h.FixedIn = fx
				}
			}
		}
	}
	hits := make([]Hit, 0, len(byCVE))
	for _, h := range byCVE {
		hits = append(hits, *h)
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].CVE < hits[j].CVE })
	return hits, st, nil
}

// inRange reports whether the version is inside the match. bounded=false means
// the entry names no version at all ("every version"), which is skipped rather
// than treated as a hit: it is overwhelmingly noise for an unauthenticated scan.
func inRange(ver string, m store.CPEMatch) (bounded, in bool) {
	if m.Exact != "" {
		return true, Compare(ver, m.Exact) == 0
	}
	if m.StartIncl == "" && m.StartExcl == "" && m.EndIncl == "" && m.EndExcl == "" {
		return false, false
	}
	if m.StartIncl != "" && Compare(ver, m.StartIncl) < 0 {
		return true, false
	}
	if m.StartExcl != "" && Compare(ver, m.StartExcl) <= 0 {
		return true, false
	}
	if m.EndIncl != "" && Compare(ver, m.EndIncl) > 0 {
		return true, false
	}
	if m.EndExcl != "" && Compare(ver, m.EndExcl) >= 0 {
		return true, false
	}
	return true, true
}

func describeRange(m store.CPEMatch) string {
	if m.Exact != "" {
		return "= " + m.Exact
	}
	var parts []string
	if m.StartIncl != "" {
		parts = append(parts, ">= "+m.StartIncl)
	}
	if m.StartExcl != "" {
		parts = append(parts, "> "+m.StartExcl)
	}
	if m.EndIncl != "" {
		parts = append(parts, "<= "+m.EndIncl)
	}
	if m.EndExcl != "" {
		parts = append(parts, "< "+m.EndExcl)
	}
	return strings.Join(parts, ", ")
}

func fixedIn(m store.CPEMatch) string { return m.EndExcl }
