package intel

import (
	"context"
	"fmt"
	"html"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"babylon/internal/store"
)

// Apple publishes the CVEs fixed by each macOS release on its security
// releases page and one article per release. Babylon reads only the release
// index and the CVE ids in each macOS article.
const AppleIndexURL = "https://support.apple.com/en-us/100100"

var (
	appleRowRe  = regexp.MustCompile(`(?s)<tr>(.*?)</tr>`)
	appleCellRe = regexp.MustCompile(`(?s)<td[^>]*>(.*?)</td>`)
	appleHrefRe = regexp.MustCompile(`href="([^"]+)"`)
	tagRe       = regexp.MustCompile(`(?s)<[^>]*>`)
	appleNameRe = regexp.MustCompile(`^macOS ([A-Za-z][A-Za-z ]*?) (\d+(?:\.\d+)*)$`)
)

func cleanCell(s string) string {
	s = html.UnescapeString(tagRe.ReplaceAllString(s, " "))
	return strings.Join(strings.Fields(strings.ReplaceAll(s, " ", " ")), " ")
}

// ParseAppleIndex extracts macOS releases from Apple's security releases page.
// Safari, Xcode, app and "Background Security" entries are ignored.
func ParseAppleIndex(r io.Reader) ([]store.AppleRelease, error) {
	b, err := io.ReadAll(io.LimitReader(r, 32<<20))
	if err != nil {
		return nil, err
	}
	var out []store.AppleRelease
	seen := map[string]bool{}
	for _, row := range appleRowRe.FindAllStringSubmatch(string(b), -1) {
		cells := appleCellRe.FindAllStringSubmatch(row[1], -1)
		if len(cells) < 3 {
			continue
		}
		m := appleNameRe.FindStringSubmatch(cleanCell(cells[0][1]))
		if m == nil {
			continue
		}
		major, err := strconv.Atoi(strings.SplitN(m[2], ".", 2)[0])
		if err != nil || seen[m[2]] {
			continue
		}
		seen[m[2]] = true
		rel := store.AppleRelease{Major: major, Release: m[2], Product: "macOS " + m[1]}
		if t, err := time.Parse("02 Jan 2006", cleanCell(cells[2][1])); err == nil {
			rel.Released = t.Format("2006-01-02")
		}
		if h := appleHrefRe.FindStringSubmatch(cells[0][1]); h != nil {
			rel.URL = html.UnescapeString(h[1])
		}
		out = append(out, rel)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("Apple security releases page contained no macOS releases; the page layout may have changed")
	}
	return out, nil
}

// ParseAppleArticle returns the CVE ids named in one security release article.
func ParseAppleArticle(r io.Reader) ([]string, error) {
	b, err := io.ReadAll(io.LimitReader(r, 32<<20))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range cveRe.FindAllString(string(b), -1) {
		c = strings.ToUpper(c)
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out, nil
}

// SyncApple downloads the release index and, for releases newer than `months`,
// each article not already stored. Interrupt and rerun to continue.
func SyncApple(ctx context.Context, f *Fetcher, st *store.Store, indexURL string, months int, logf func(string, ...any)) (fixes int, err error) {
	if indexURL == "" {
		indexURL = AppleIndexURL
	}
	if months <= 0 {
		months = 24
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	res, err := f.Get(ctx, indexURL, "", "", nil)
	if err != nil {
		return 0, err
	}
	rels, err := ParseAppleIndex(res.Body)
	res.Body.Close()
	if err != nil {
		return 0, err
	}
	if err := st.UpsertAppleReleases(ctx, rels); err != nil {
		return 0, err
	}
	cutoff := time.Now().AddDate(0, -months, 0).Format("2006-01-02")
	for _, r := range rels {
		if r.URL == "" || (r.Released != "" && r.Released < cutoff) {
			continue
		}
		name := "apple:" + r.Release
		if cur, ok, _ := st.GetFeed(ctx, name); ok && cur.Version == r.Released {
			continue
		}
		url := r.URL
		if !strings.HasPrefix(url, "http") { // relative link (tests, mirrors)
			url = strings.TrimRight(indexURL[:strings.LastIndex(indexURL, "/")], "/") + "/" + strings.TrimLeft(url, "/")
		}
		a, err := f.Get(ctx, url, "", "", nil)
		if err != nil {
			return fixes, fmt.Errorf("%s: %w", r.Product+" "+r.Release, err)
		}
		cves, err := ParseAppleArticle(a.Body)
		a.Body.Close()
		if err != nil {
			return fixes, fmt.Errorf("%s: %w", r.Release, err)
		}
		if err := st.UpsertAppleFixes(ctx, r.Major, r.Release, cves, store.FeedInfo{Name: name, Version: r.Released}); err != nil {
			return fixes, err
		}
		fixes += len(cves)
		logf("  %s %s: %d CVEs", r.Product, r.Release, len(cves))
		select {
		case <-time.After(250 * time.Millisecond): // be polite to Apple's servers
		case <-ctx.Done():
			return fixes, ctx.Err()
		}
	}
	total, _, _ := st.CountApple(ctx)
	return fixes, st.SetFeed(ctx, store.FeedInfo{Name: "apple", Version: time.Now().UTC().Format("2006-01-02"), Count: total})
}
