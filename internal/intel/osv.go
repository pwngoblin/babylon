package intel

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"babylon/internal/store"
)

// OSVBase is the public OSV.dev bucket holding per-ecosystem dumps.
const OSVBase = "https://osv-vulnerabilities.storage.googleapis.com"

// DefaultOSVEcosystems are the dumps `update-feeds` fetches by default.
var DefaultOSVEcosystems = []string{"Debian", "Ubuntu", "Alpine", "Rocky Linux", "AlmaLinux", "PyPI", "npm", "Go"}

type osvDoc struct {
	ID        string          `json:"id"`
	Modified  string          `json:"modified"`
	Summary   string          `json:"summary"`
	Details   string          `json:"details"`
	Aliases   []string        `json:"aliases"`
	Upstream  []string        `json:"upstream"` // distro advisories name the upstream CVEs here
	Related   []string        `json:"related"`
	Severity  json.RawMessage `json:"severity"`
	Withdrawn string          `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

// ParseOSV converts one OSV JSON document. Withdrawn advisories yield ok=false.
// Git ranges are ignored (they cannot be matched against installed packages).
func ParseOSV(b []byte) (rec store.OSVRecord, ok bool, err error) {
	var d osvDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return rec, false, err
	}
	if d.ID == "" || d.Withdrawn != "" {
		return rec, false, nil
	}
	details := d.Details
	if len(details) > 4096 {
		details = strings.ToValidUTF8(details[:4096], "")
	}
	rec = store.OSVRecord{ID: d.ID, Modified: d.Modified, Summary: d.Summary, Details: details, Aliases: osvAliases(d)}
	if len(d.Severity) > 0 && string(d.Severity) != "null" {
		rec.Severity = d.Severity
	}
	for _, a := range d.Affected {
		if a.Package.Name == "" || a.Package.Ecosystem == "" {
			continue
		}
		base := store.OSVAffected{Ecosystem: a.Package.Ecosystem, Package: a.Package.Name}
		emitted := false
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue
			}
			cur := base
			open := false
			flush := func() {
				if open {
					rec.Affected = append(rec.Affected, cur)
					emitted = true
				}
				cur, open = base, false
			}
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					flush()
					cur.Introduced, open = e.Introduced, true
				case e.Fixed != "":
					if !open {
						cur.Introduced, open = "0", true
					}
					cur.Fixed = e.Fixed
					flush()
				case e.LastAffected != "":
					if !open {
						cur.Introduced, open = "0", true
					}
					cur.LastAffected = e.LastAffected
					flush()
				}
			}
			flush()
		}
		if len(a.Versions) > 0 {
			v := base
			v.Versions = a.Versions
			rec.Affected = append(rec.Affected, v)
			emitted = true
		}
		_ = emitted
	}
	return rec, len(rec.Affected) > 0, nil
}

// ParseOSVZip reads every advisory in an ecosystem dump.
func ParseOSVZip(path string) ([]store.OSVRecord, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var out []store.OSVRecord
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > 64<<20 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 64<<20))
		rc.Close()
		if err != nil {
			return nil, err
		}
		rec, ok, err := ParseOSV(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		if ok {
			out = append(out, rec)
		}
	}
	return out, nil
}

// SyncOSV downloads (conditionally) and indexes one ecosystem dump. It returns
// the number of advisories and whether anything changed.
func SyncOSV(ctx context.Context, f *Fetcher, st *store.Store, base, ecosystem, tmpDir string) (n int, changed bool, err error) {
	name := "osv:" + ecosystem
	cur, _, err := st.GetFeed(ctx, name)
	if err != nil {
		return 0, false, err
	}
	if base == "" {
		base = OSVBase
	}
	res, err := f.Get(ctx, base+"/"+url.PathEscape(ecosystem)+"/all.zip", cur.ETag, cur.LastModified, nil)
	if err != nil {
		return 0, false, err
	}
	if res.NotModified {
		return cur.Count, false, nil
	}
	defer res.Body.Close()
	path, err := toTemp(tmpDir, "osv-*.zip", res.Body)
	if err != nil {
		return 0, false, err
	}
	defer os.Remove(path)
	recs, err := ParseOSVZip(path)
	if err != nil {
		return 0, false, err
	}
	if len(recs) == 0 {
		return 0, false, fmt.Errorf("OSV %s dump had no usable advisories; keeping existing data", ecosystem)
	}
	err = st.ReplaceOSVEcosystem(ctx, ecosystem, recs, store.FeedInfo{Name: name, ETag: res.ETag, LastModified: res.LastModified, Version: res.LastModified})
	return len(recs), err == nil, err
}

// osvAliases merges aliases with the "upstream" and "related" CVE references
// that Debian and Ubuntu use, and the ID itself when it embeds a CVE.
func osvAliases(d osvDoc) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if a != "" && a != d.ID && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, a := range d.Aliases {
		add(a)
	}
	for _, a := range append(append([]string(nil), d.Upstream...), d.Related...) {
		if strings.HasPrefix(a, "CVE-") {
			add(a)
		}
	}
	if i := strings.Index(d.ID, "CVE-"); i >= 0 {
		add(d.ID[i:])
	}
	return out
}
