package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"babylon/internal/store"
)

// NVDURL is the NVD CVE API 2.0 endpoint.
const NVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

const (
	nvdPageSize   = 2000
	nvdTimeLayout = "2006-01-02T15:04:05.000"
	nvdMaxWindow  = 119 * 24 * time.Hour // the API rejects ranges over 120 days
)

type nvdPage struct {
	ResultsPerPage  int    `json:"resultsPerPage"`
	StartIndex      int    `json:"startIndex"`
	TotalResults    int    `json:"totalResults"`
	Timestamp       string `json:"timestamp"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V40 []nvdMetric `json:"cvssMetricV40"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []nvdNode `json:"nodes"`
	} `json:"configurations"`
}

type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

type nvdNode struct {
	CPEMatch []struct {
		Vulnerable            bool   `json:"vulnerable"`
		Criteria              string `json:"criteria"`
		VersionStartIncluding string `json:"versionStartIncluding"`
		VersionStartExcluding string `json:"versionStartExcluding"`
		VersionEndIncluding   string `json:"versionEndIncluding"`
		VersionEndExcluding   string `json:"versionEndExcluding"`
	} `json:"cpeMatch"`
	Children []nvdNode `json:"children"`
}

// ParseNVDPage converts one NVD API page into records. It also returns the
// page's totalResults and the server timestamp.
func ParseNVDPage(r io.Reader) (recs []store.CVERecord, total int, serverTime string, err error) {
	var p nvdPage
	if err := json.NewDecoder(io.LimitReader(r, 256<<20)).Decode(&p); err != nil {
		return nil, 0, "", fmt.Errorf("parse NVD page: %w", err)
	}
	for _, v := range p.Vulnerabilities {
		recs = append(recs, convertCVE(v.CVE))
	}
	return recs, p.TotalResults, p.Timestamp, nil
}

func primaryMetric(ms []nvdMetric) (nvdMetric, bool) {
	for _, m := range ms {
		if m.Type == "Primary" {
			return m, true
		}
	}
	if len(ms) > 0 {
		return ms[0], true
	}
	return nvdMetric{}, false
}

func convertCVE(c nvdCVE) store.CVERecord {
	r := store.CVERecord{ID: c.ID, Published: c.Published, Modified: c.LastModified, Status: c.VulnStatus}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			r.Description = d.Value
			break
		}
	}
	if m, ok := primaryMetric(c.Metrics.V31); ok {
		s := m.CVSSData.BaseScore
		r.CVSS, r.Vector = &s, m.CVSSData.VectorString
	} else if m, ok := primaryMetric(c.Metrics.V30); ok {
		s := m.CVSSData.BaseScore
		r.CVSS, r.Vector = &s, m.CVSSData.VectorString
	}
	if m, ok := primaryMetric(c.Metrics.V40); ok {
		s := m.CVSSData.BaseScore
		r.CVSS4 = &s
		if r.CVSS == nil { // v4-only CVEs still need a score
			r.CVSS, r.Vector = &s, m.CVSSData.VectorString
		}
	}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				r.CWE = d.Value
			}
		}
	}
	seen := map[store.CPEMatch]bool{}
	var walk func(n nvdNode)
	walk = func(n nvdNode) {
		for _, m := range n.CPEMatch {
			if !m.Vulnerable {
				continue
			}
			cpe, ok := ParseCPE(m.Criteria)
			if !ok || cpe.Part == "h" {
				continue
			}
			pm := store.CPEMatch{Vendor: cpe.Vendor, Product: cpe.Product, TargetSW: cpe.TargetSW,
				StartIncl: m.VersionStartIncluding, StartExcl: m.VersionStartExcluding,
				EndIncl: m.VersionEndIncluding, EndExcl: m.VersionEndExcluding}
			if cpe.Version != "" {
				pm.Exact = cpe.Version
				if cpe.Update != "" {
					pm.Exact += "-" + cpe.Update
				}
			}
			if !seen[pm] {
				seen[pm] = true
				r.Matches = append(r.Matches, pm)
			}
		}
		for _, ch := range n.Children {
			walk(ch)
		}
	}
	for _, cfg := range c.Configurations {
		for _, n := range cfg.Nodes {
			walk(n)
		}
	}
	return r
}

// NVDConfig controls an NVD sync.
type NVDConfig struct {
	BaseURL  string
	APIKey   string        // optional; raises the rate limit ten-fold
	Delay    time.Duration // between requests (default 6.5s keyless, 0.7s with a key)
	MaxPages int           // 0 = all; used to seed a partial index quickly
	Now      func() time.Time
	Logf     func(format string, args ...any)
}

func (c *NVDConfig) defaults() {
	if c.BaseURL == "" {
		c.BaseURL = NVDURL
	}
	if c.Delay == 0 {
		c.Delay = 6500 * time.Millisecond
		if c.APIKey != "" {
			c.Delay = 700 * time.Millisecond
		}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

type nvdDetail struct {
	Mode    string `json:"mode"` // "full" (in progress) or "incremental"
	Next    int    `json:"next"`
	Total   int    `json:"total"`
	Started string `json:"started"`
}

// SyncNVD downloads NVD data into the store. A first run pages through the
// whole CVE list (resumable if interrupted); later runs fetch only CVEs
// modified since the last sync. Each page is committed on its own, so an
// interrupted sync keeps what it has and continues where it stopped.
func SyncNVD(ctx context.Context, f *Fetcher, st *store.Store, cfg NVDConfig) (int, error) {
	cfg.defaults()
	hdr := map[string]string{}
	if cfg.APIKey != "" {
		hdr["apiKey"] = cfg.APIKey
	}
	cur, _, err := st.GetFeed(ctx, "nvd")
	if err != nil {
		return 0, err
	}
	var d nvdDetail
	if cur.Detail != "" {
		_ = json.Unmarshal([]byte(cur.Detail), &d)
	}
	total := cur.Count
	pages := 0
	first := true
	throttle := func() error {
		if first {
			first = false
			return nil
		}
		select {
		case <-time.After(cfg.Delay):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	fetch := func(q url.Values) ([]store.CVERecord, int, string, error) {
		if err := throttle(); err != nil {
			return nil, 0, "", err
		}
		res, err := f.Get(ctx, cfg.BaseURL+"?"+q.Encode(), "", "", hdr)
		if err != nil {
			return nil, 0, "", err
		}
		defer res.Body.Close()
		return ParseNVDPage(res.Body)
	}
	save := func(recs []store.CVERecord, fi store.FeedInfo) error {
		return st.UpsertCVEs(ctx, recs, &fi)
	}

	// Phase 1: full download (first run, or resuming an interrupted one).
	if cur.Version == "" || d.Mode == "full" {
		if d.Mode != "full" {
			d = nvdDetail{Mode: "full", Started: cfg.Now().UTC().Format(nvdTimeLayout)}
		}
		for {
			q := url.Values{"resultsPerPage": {fmt.Sprint(nvdPageSize)}, "startIndex": {fmt.Sprint(d.Next)}}
			recs, tot, ts, err := fetch(q)
			if err != nil {
				return total, err
			}
			if d.Started == "" {
				d.Started = ts
			}
			d.Total = tot
			d.Next += nvdPageSize
			total += len(recs)
			pages++
			done := d.Next >= tot || len(recs) == 0
			capped := cfg.MaxPages > 0 && pages >= cfg.MaxPages && !done
			fi := store.FeedInfo{Name: "nvd", Count: total}
			switch {
			case done:
				fi.Version, fi.Detail = d.Started, "" // complete: version is the sync start time
			case capped:
				fi.Version, fi.Detail = "", mustJSON(d)
			default:
				fi.Version, fi.Detail = "", mustJSON(d)
			}
			if err := save(recs, fi); err != nil {
				return total, err
			}
			cfg.Logf("  nvd: %d/%d", min(d.Next, tot), tot)
			if done {
				cur.Version = d.Started
				d = nvdDetail{}
				break
			}
			if capped {
				return total, nil // partial index, resumable on the next run
			}
		}
	}

	// Phase 2: incremental from the last completed sync to now.
	since, err := time.Parse(nvdTimeLayout, cur.Version)
	if err != nil {
		return total, fmt.Errorf("bad nvd sync time %q: %w", cur.Version, err)
	}
	end := cfg.Now().UTC()
	for since.Before(end) {
		winEnd := since.Add(nvdMaxWindow)
		if winEnd.After(end) {
			winEnd = end
		}
		idx := 0
		for {
			q := url.Values{
				"resultsPerPage": {fmt.Sprint(nvdPageSize)}, "startIndex": {fmt.Sprint(idx)},
				"lastModStartDate": {since.Format(nvdTimeLayout)}, "lastModEndDate": {winEnd.Format(nvdTimeLayout)},
			}
			recs, tot, _, err := fetch(q)
			if err != nil {
				return total, err
			}
			idx += nvdPageSize
			last := idx >= tot || len(recs) == 0
			fi := store.FeedInfo{Name: "nvd", Version: since.Format(nvdTimeLayout), Count: total}
			if last {
				fi.Version = winEnd.Format(nvdTimeLayout)
			}
			var n int
			_ = st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cve`).Scan(&n)
			fi.Count = n
			if err := save(recs, fi); err != nil {
				return total, err
			}
			if len(recs) > 0 {
				cfg.Logf("  nvd: updated %d CVEs", len(recs))
			}
			if last {
				break
			}
		}
		since = winEnd
	}
	var n int
	_ = st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cve`).Scan(&n)
	return n, nil
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
