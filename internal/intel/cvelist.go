package intel

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"babylon/internal/store"
)

// cvelistV5 (CVE Program JSON 5 records, with CISA Vulnrichment) supplies
// affected-version data for CVEs that NVD has not yet analysed. It is used only
// where NVD has no ranges of its own (NVD wins when sources overlap).

type cve5 struct {
	Meta struct {
		ID        string `json:"cveId"`
		State     string `json:"state"`
		Published string `json:"datePublished"`
		Updated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cve5Container   `json:"cna"`
		ADP []cve5Container `json:"adp"`
	} `json:"containers"`
}

type cve5Container struct {
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics  []map[string]json.RawMessage `json:"metrics"`
	Affected []struct {
		Vendor        string   `json:"vendor"`
		Product       string   `json:"product"`
		CPEs          []string `json:"cpes"`
		DefaultStatus string   `json:"defaultStatus"`
		Versions      []struct {
			Version     string `json:"version"`
			Status      string `json:"status"`
			LessThan    string `json:"lessThan"`
			LessOrEqual string `json:"lessThanOrEqual"`
			VersionType string `json:"versionType"`
		} `json:"versions"`
	} `json:"affected"`
}

var (
	saneVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+~:-]{0,60}$`)
	nonName     = regexp.MustCompile(`[^a-z0-9_.-]+`)
)

// cpeName normalises a free-text CNA vendor/product into CPE naming style.
func cpeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "_")
	return strings.Trim(nonName.ReplaceAllString(s, ""), "_.-")
}

func cvssFrom(c cve5Container) (*float64, string) {
	for _, m := range c.Metrics {
		for _, key := range []string{"cvssV3_1", "cvssV3_0"} {
			raw, ok := m[key]
			if !ok {
				continue
			}
			var v struct {
				Score  float64 `json:"baseScore"`
				Vector string  `json:"vectorString"`
			}
			if json.Unmarshal(raw, &v) == nil && v.Score > 0 {
				s := v.Score
				return &s, v.Vector
			}
		}
	}
	return nil, ""
}

// ParseCVE5 converts one CVE JSON 5 record. ok is false for records that are
// not published or carry no usable version ranges.
func ParseCVE5(b []byte) (rec store.CVERecord, ok bool, err error) {
	var d cve5
	if err := json.Unmarshal(b, &d); err != nil {
		return rec, false, err
	}
	if d.Meta.State != "PUBLISHED" || d.Meta.ID == "" {
		return rec, false, nil
	}
	rec = store.CVERecord{ID: strings.ToUpper(d.Meta.ID), Published: d.Meta.Published, Modified: d.Meta.Updated, Status: "CVEList"}
	for _, desc := range d.Containers.CNA.Descriptions {
		if strings.HasPrefix(desc.Lang, "en") {
			rec.Description = desc.Value
			break
		}
	}
	rec.CVSS, rec.Vector = cvssFrom(d.Containers.CNA)
	for _, adp := range d.Containers.ADP {
		if rec.CVSS == nil {
			rec.CVSS, rec.Vector = cvssFrom(adp)
		}
	}
	seen := map[store.CPEMatch]bool{}
	for _, c := range append([]cve5Container{d.Containers.CNA}, d.Containers.ADP...) {
		for _, a := range c.Affected {
			type vp struct{ v, p string }
			var names []vp
			for _, cp := range a.CPEs {
				if p, ok := ParseCPE(cp); ok && p.Vendor != "" && p.Product != "" {
					names = append(names, vp{p.Vendor, p.Product})
				}
			}
			if len(names) == 0 {
				if v, p := cpeName(a.Vendor), cpeName(a.Product); v != "" && p != "" {
					names = append(names, vp{v, p})
				}
			}
			for _, ver := range a.Versions {
				if ver.Status != "affected" {
					continue
				}
				switch strings.ToLower(ver.VersionType) {
				case "git", "rpm", "deb", "apk", "purl":
					continue // commit hashes and OS-package versions are not upstream versions
				}
				m := store.CPEMatch{}
				v := strings.TrimSpace(ver.Version)
				okv := func(s string) bool { return saneVersion.MatchString(s) }
				switch {
				case ver.LessThan != "" && ver.LessThan != "*":
					if !okv(ver.LessThan) {
						continue
					}
					m.EndExcl = ver.LessThan
					if v != "" && v != "0" && v != "*" && okv(v) {
						m.StartIncl = v
					}
				case ver.LessOrEqual != "" && ver.LessOrEqual != "*":
					if !okv(ver.LessOrEqual) {
						continue
					}
					m.EndIncl = ver.LessOrEqual
					if v != "" && v != "0" && v != "*" && okv(v) {
						m.StartIncl = v
					}
				case v != "" && v != "*" && v != "0" && okv(v) && ver.LessThan == "":
					m.Exact = v
				default:
					continue
				}
				for _, n := range names {
					mm := m
					mm.Vendor, mm.Product = n.v, n.p
					if !seen[mm] {
						seen[mm] = true
						rec.Matches = append(rec.Matches, mm)
					}
				}
			}
		}
	}
	return rec, len(rec.Matches) > 0, nil
}

// CVEListAPI is the GitHub API endpoint for the latest cvelistV5 release.
const CVEListAPI = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"

const maxInnerZip = 4 << 30

// ParseCVEListZip streams a cvelistV5 "all CVEs" archive (a zip holding
// cves.zip, which holds cves/<year>/<bucket>/CVE-*.json) and calls flush with
// batches of records that carry version ranges. Years before minYear are not
// read, which keeps recent-CVE syncs to a few minutes.
func ParseCVEListZip(outerPath string, minYear int, flush func([]store.CVERecord) error) (parsed int, err error) {
	outer, err := zip.OpenReader(outerPath)
	if err != nil {
		return 0, err
	}
	defer outer.Close()
	innerPath := outerPath + ".inner"
	var found bool
	for _, f := range outer.File {
		if f.Name != "cves.zip" {
			continue
		}
		found = true
		rc, err := f.Open()
		if err != nil {
			return 0, err
		}
		_, err = copyLimited(innerPath, rc, maxInnerZip)
		rc.Close()
		if err != nil {
			return 0, err
		}
		break
	}
	if !found {
		return 0, fmt.Errorf("archive has no cves.zip")
	}
	defer os.Remove(innerPath)
	return parseCVEListInner(innerPath, minYear, flush)
}

func parseCVEListInner(path string, minYear int, flush func([]store.CVERecord) error) (int, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return 0, err
	}
	defer zr.Close()
	var batch []store.CVERecord
	n := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > 8<<20 {
			continue
		}
		parts := strings.Split(f.Name, "/")
		if len(parts) < 3 {
			continue
		}
		if y, e := strconv.Atoi(parts[len(parts)-3]); e == nil && y < minYear {
			continue
		} else if e != nil && !strings.HasPrefix(filepath.Base(f.Name), "CVE-") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return n, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 8<<20))
		rc.Close()
		if err != nil {
			return n, err
		}
		rec, ok, err := ParseCVE5(b)
		if err != nil || !ok {
			continue // one malformed record must not stop the import
		}
		batch = append(batch, rec)
		n++
		if len(batch) >= 2000 {
			if err := flush(batch); err != nil {
				return n, err
			}
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		if err := flush(batch); err != nil {
			return n, err
		}
	}
	return n, nil
}

func copyLimited(dst string, r io.Reader, max int64) (int64, error) {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, io.LimitReader(r, max+1))
	if err == nil && n > max {
		err = fmt.Errorf("archive member exceeds the safety limit")
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
	}
	return n, err
}

// SyncCVEList downloads the latest cvelistV5 snapshot (skipping it when the
// release tag is unchanged) and adds version ranges for CVEs NVD has none for.
func SyncCVEList(ctx context.Context, f *Fetcher, st *store.Store, apiURL, tmpDir string, minYear int) (added int, changed bool, err error) {
	if apiURL == "" {
		apiURL = CVEListAPI
	}
	cur, _, err := st.GetFeed(ctx, "cvelist")
	if err != nil {
		return 0, false, err
	}
	res, err := f.Get(ctx, apiURL, "", "", map[string]string{"Accept": "application/vnd.github+json"})
	if err != nil {
		return 0, false, err
	}
	var rel struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&rel)
	res.Body.Close()
	if err != nil {
		return 0, false, fmt.Errorf("reading cvelistV5 release info: %w", err)
	}
	if rel.Tag == "" {
		return 0, false, fmt.Errorf("cvelistV5 release info has no tag")
	}
	if cur.Version == rel.Tag+"|"+strconv.Itoa(minYear) {
		return cur.Count, false, nil
	}
	assetURL := ""
	for _, a := range rel.Assets {
		if strings.HasSuffix(a.Name, "_all_CVEs_at_midnight.zip.zip") {
			assetURL = a.URL
		}
	}
	if assetURL == "" {
		return 0, false, fmt.Errorf("release %s has no full CVE archive", rel.Tag)
	}
	dl, err := f.Get(ctx, assetURL, "", "", nil)
	if err != nil {
		return 0, false, err
	}
	defer dl.Body.Close()
	path, err := toTemp(tmpDir, "cvelist-*.zip", dl.Body)
	if err != nil {
		return 0, false, err
	}
	defer os.Remove(path)
	total := 0
	_, err = ParseCVEListZip(path, minYear, func(b []store.CVERecord) error {
		n, e := st.AddCVEListRanges(ctx, b)
		total += n
		return e
	})
	if err != nil {
		return total, false, err
	}
	err = st.SetFeed(ctx, store.FeedInfo{Name: "cvelist", Version: rel.Tag + "|" + strconv.Itoa(minYear), Count: total})
	return total, err == nil, err
}
