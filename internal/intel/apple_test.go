package intel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func appleRow(name, avail, date, href string) string {
	link := name
	if href != "" {
		link = `<a href="` + href + `" class="gb-anchor">` + name + `</a>`
	}
	return `<tr><td class="gb-table-cell"><p class="gb-paragraph">` + link + `</p></td><td class="gb-table-cell"><p>` + avail + `</p></td><td class="gb-table-cell"><p>` + date + `</p></td></tr>`
}

func appleIndex(base string) string {
	return `<table><tr><th>Name</th><th>Available for</th><th>Release&nbsp;date</th></tr>` +
		appleRow("macOS Tahoe&nbsp;26.7.3", "macOS Tahoe", "09 Nov 2026", base+"/a1") +
		appleRow("macOS Sequoia 15.8.3", "macOS Sequoia", "09 Nov 2026", base+"/a2") +
		appleRow("Safari 27.2", "macOS Sequoia and macOS Tahoe", "26 Oct 2026", base+"/a3") +
		appleRow("Xcode 27.2", "macOS Tahoe 26.6 and later", "29 Oct 2026", base+"/a4") +
		appleRow("Background Security Improvements for iOS", "iOS 26.3.1", "17 Mar 2026", base+"/a5") +
		appleRow("macOS Ventura 13.7.8", "macOS Ventura", "20 Aug 2001", base+"/old") +
		appleRow("macOS Tahoe 26.7.2 (no link)", "macOS Tahoe", "26 Oct 2026", "") +
		`</table>`
}

func TestParseAppleIndexKeepsOnlyMacOSReleases(t *testing.T) {
	got, err := ParseAppleIndex(strings.NewReader(appleIndex("https://x")))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range got {
		names = append(names, fmt.Sprintf("%s %s/%d/%s", r.Product, r.Release, r.Major, r.Released))
	}
	want := []string{"macOS Tahoe 26.7.3/26/2026-11-09", "macOS Sequoia 15.8.3/15/2026-11-09", "macOS Ventura 13.7.8/13/2001-08-20"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("%v", names)
	}
	if got[0].URL != "https://x/a1" {
		t.Fatal(got[0].URL)
	}
	if _, err := ParseAppleIndex(strings.NewReader("<html>moved</html>")); err == nil {
		t.Fatal("a changed layout must be an error, not an empty success")
	}
}

func TestParseAppleArticleDedupes(t *testing.T) {
	got, _ := ParseAppleArticle(strings.NewReader("CVE-2026-1111: x <b>CVE-2026-2222</b> cve-2026-1111 CVE-2026-1111"))
	if strings.Join(got, ",") != "CVE-2026-1111,CVE-2026-2222" {
		t.Fatalf("%v", got)
	}
}

func TestSyncAppleSkipsOldAndKnownReleases(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	hits := map[string]int{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		switch r.URL.Path {
		case "/index":
			fmt.Fprint(w, appleIndex(srv.URL))
		case "/a1":
			fmt.Fprint(w, "CVE-2026-1111 CVE-2026-2222")
		case "/a2":
			fmt.Fprint(w, "CVE-2026-3333")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	n, err := SyncApple(ctx, fastFetcher(), st, srv.URL+"/index", 24, nil)
	if err != nil || n != 3 {
		t.Fatal(n, err)
	}
	if hits["/old"] != 0 {
		t.Error("a release older than the window must not be downloaded")
	}
	fx, _ := st.AppleFixesForMajor(ctx, 26)
	if len(fx) != 2 || fx[0].Release != "26.7.3" {
		t.Fatalf("%+v", fx)
	}
	// The index lists the old release even though its article was skipped.
	if rel, _ := st.AppleReleases(ctx, 13); len(rel) != 1 {
		t.Fatalf("%+v", rel)
	}
	// A second run downloads no article again.
	if _, err := SyncApple(ctx, fastFetcher(), st, srv.URL+"/index", 24, nil); err != nil {
		t.Fatal(err)
	}
	if hits["/a1"] != 1 || hits["/a2"] != 1 {
		t.Errorf("articles refetched: %v", hits)
	}
}
