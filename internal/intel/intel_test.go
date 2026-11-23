package intel

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"babylon/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	t.Cleanup(func() { st.Close() })
	return st
}

func fastFetcher() *Fetcher {
	f := NewFetcher()
	f.Backoff = time.Millisecond
	return f
}

func TestParseCPE(t *testing.T) {
	c, ok := ParseCPE(`cpe:2.3:a:f5:nginx:1.16.0:*:*:*:*:*:*:*`)
	if !ok || c.Vendor != "f5" || c.Product != "nginx" || c.Version != "1.16.0" || c.Part != "a" {
		t.Fatalf("%+v", c)
	}
	c, ok = ParseCPE(`cpe:/a:openbsd:openssh:8.4p1`)
	if !ok || c.Version != "8.4p1" {
		t.Fatalf("%+v", c)
	}
	c, _ = ParseCPE(`cpe:2.3:a:vendor:prod\:uct:1.0:p1:*:*:*:wordpress:*:*`)
	if c.Product != "prod:uct" || c.Update != "p1" || c.TargetSW != "wordpress" {
		t.Fatalf("escapes: %+v", c)
	}
	c, _ = ParseCPE(`cpe:2.3:a:v:p:*:*:*:*:*:*:*:*`)
	if c.Version != "" {
		t.Fatalf("wildcard version must be empty, got %q", c.Version)
	}
	if _, ok := ParseCPE("garbage"); ok {
		t.Fatal("garbage accepted")
	}
}

const kevJSON = `{"catalogVersion":"2026.11.20","vulnerabilities":[
 {"cveID":"CVE-2021-41773","vendorProject":"Apache","product":"HTTP Server","vulnerabilityName":"Path Traversal","dateAdded":"2021-11-03","dueDate":"2021-11-17","knownRansomwareCampaignUse":"Unknown","notes":""},
 {"cveID":"not-a-cve","vendorProject":"x","product":"y"}]}`

func TestParseKEV(t *testing.T) {
	e, ver, err := ParseKEV(strings.NewReader(kevJSON))
	if err != nil || ver != "2026.11.20" || len(e) != 1 || e[0].CVE != "CVE-2021-41773" || e[0].DueDate != "2021-11-17" {
		t.Fatalf("%+v %q %v", e, ver, err)
	}
	if _, _, err := ParseKEV(strings.NewReader(`{"vulnerabilities":[]}`)); err == nil {
		t.Fatal("an empty catalogue must be refused, not wipe the table")
	}
	if _, _, err := ParseKEV(strings.NewReader(`<html>`)); err == nil {
		t.Fatal("non-JSON must fail")
	}
}

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

const epssCSV = "#model_version:v2025.03.14,score_date:2026-11-22T00:00:00Z\ncve,epss,percentile\nCVE-2021-41773,0.94,0.99\nCVE-2020-0001,0.001,0.1\nbad,line\nCVE-2020-0002,7,0.5\n"

func TestParseEPSS(t *testing.T) {
	for name, body := range map[string][]byte{"plain": []byte(epssCSV), "gzip": gz(epssCSV)} {
		e, asOf, err := ParseEPSS(bytes.NewReader(body))
		if err != nil || len(e) != 2 || asOf != "2026-11-22T00:00:00Z" || e[0].Score != 0.94 {
			t.Fatalf("%s: %+v %q %v (out-of-range score must be dropped)", name, e, asOf, err)
		}
	}
	if _, _, err := ParseEPSS(strings.NewReader("cve,epss,percentile\n")); err == nil {
		t.Fatal("empty file must be refused")
	}
}

const nvdPageJSON = `{"resultsPerPage":3,"startIndex":0,"totalResults":3,"timestamp":"2026-11-22T10:00:00.000","vulnerabilities":[
{"cve":{"id":"CVE-2021-41773","published":"2021-10-05T09:15:00.000","lastModified":"2026-01-01T00:00:00.000","vulnStatus":"Analyzed",
 "descriptions":[{"lang":"es","value":"x"},{"lang":"en","value":"Path traversal in Apache 2.4.49"}],
 "metrics":{"cvssMetricV31":[{"type":"Secondary","cvssData":{"baseScore":5.0,"vectorString":"S"}},{"type":"Primary","cvssData":{"baseScore":7.5,"vectorString":"CVSS:3.1/AV:N"}}]},
 "weaknesses":[{"description":[{"value":"CWE-22"}]}],
 "configurations":[{"nodes":[{"operator":"AND","cpeMatch":[],"children":[
   {"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]},
   {"operator":"OR","cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}]}]}]}]}},
{"cve":{"id":"CVE-2022-0001","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"range"}],
 "configurations":[{"nodes":[{"operator":"OR","cpeMatch":[
  {"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*","versionStartIncluding":"0.6.18","versionEndExcluding":"1.20.1"},
  {"vulnerable":true,"criteria":"cpe:2.3:h:cisco:router:1.0:*:*:*:*:*:*:*"},
  {"vulnerable":true,"criteria":"cpe:2.3:a:openbsd:openssh:8.4:p1:*:*:*:*:*:*"}]}]}]}},
{"cve":{"id":"CVE-2022-0002","vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"** REJECT **"}]}}]}`

func TestParseNVDPage(t *testing.T) {
	recs, total, ts, err := ParseNVDPage(strings.NewReader(nvdPageJSON))
	if err != nil || total != 3 || ts == "" || len(recs) != 3 {
		t.Fatalf("%v %d %q %d", err, total, ts, len(recs))
	}
	a := recs[0]
	if a.Description != "Path traversal in Apache 2.4.49" || a.CVSS == nil || *a.CVSS != 7.5 || a.Vector != "CVSS:3.1/AV:N" || a.CWE != "CWE-22" {
		t.Fatalf("metadata: %+v", a)
	}
	if len(a.Matches) != 1 || a.Matches[0].Exact != "2.4.49" {
		t.Fatalf("nested children walked, duplicates removed, non-vulnerable context ignored: %+v", a.Matches)
	}
	b := recs[1]
	if len(b.Matches) != 2 {
		t.Fatalf("hardware CPE must be dropped: %+v", b.Matches)
	}
	if b.Matches[0].StartIncl != "0.6.18" || b.Matches[0].EndExcl != "1.20.1" || b.Matches[0].Exact != "" {
		t.Fatalf("range: %+v", b.Matches[0])
	}
	if b.Matches[1].Exact != "8.4-p1" {
		t.Fatalf("update folded into version: %+v", b.Matches[1])
	}
}

func TestUpsertReplacesStaleRangesAndDropsRejected(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	recs, _, _, _ := ParseNVDPage(strings.NewReader(nvdPageJSON))
	if err := st.UpsertCVEs(ctx, recs, nil); err != nil {
		t.Fatal(err)
	}
	cves, ranges, _ := st.CountCVEs(ctx)
	if cves != 2 || ranges != 3 {
		t.Fatalf("cves=%d ranges=%d (rejected must not be stored)", cves, ranges)
	}
	// re-analysis narrows CVE-2022-0001 to a single range
	recs[1].Matches = recs[1].Matches[:1]
	if err := st.UpsertCVEs(ctx, recs[1:2], nil); err != nil {
		t.Fatal(err)
	}
	if _, ranges, _ = st.CountCVEs(ctx); ranges != 2 {
		t.Fatalf("stale ranges kept: %d", ranges)
	}
	// a CVE later rejected disappears with its ranges
	rej := store.CVERecord{ID: "CVE-2022-0001", Status: "Rejected"}
	_ = st.UpsertCVEs(ctx, []store.CVERecord{rej}, nil)
	if cves, ranges, _ = st.CountCVEs(ctx); cves != 1 || ranges != 1 {
		t.Fatalf("after reject cves=%d ranges=%d", cves, ranges)
	}
}

func TestSyncKEVConditionalAndRefreshesFindings(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	var hits, conditional int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			atomic.AddInt32(&conditional, 1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, kevJSON)
	}))
	defer srv.Close()

	n, changed, err := SyncKEV(ctx, fastFetcher(), st, srv.URL)
	if err != nil || n != 1 || !changed {
		t.Fatal(n, changed, err)
	}
	n, changed, err = SyncKEV(ctx, fastFetcher(), st, srv.URL)
	if err != nil || changed || n != 1 || conditional != 1 {
		t.Fatalf("second sync must be a 304: n=%d changed=%v err=%v cond=%d", n, changed, err, conditional)
	}
	var cnt int
	st.DB.QueryRow(`SELECT COUNT(*) FROM kev`).Scan(&cnt)
	if cnt != 1 {
		t.Fatal("kev rows", cnt)
	}
}

func TestSyncEPSS(t *testing.T) {
	st := newStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(gz(epssCSV)) }))
	defer srv.Close()
	n, _, err := SyncEPSS(context.Background(), fastFetcher(), st, srv.URL)
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	var s float64
	st.DB.QueryRow(`SELECT score FROM epss WHERE cve_id='CVE-2021-41773'`).Scan(&s)
	if s != 0.94 {
		t.Fatal(s)
	}
}

func TestFetchRetriesTransientThenGivesUp(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	res, err := fastFetcher().Get(context.Background(), srv.URL, "", "", nil)
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	res.Body.Close()

	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer notFound.Close()
	atomic.StoreInt32(&n, 0)
	if _, err := fastFetcher().Get(context.Background(), notFound.URL, "", "", nil); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404 must fail fast: %v", err)
	}
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer dead.Close()
	if _, err := fastFetcher().Get(context.Background(), dead.URL, "", "", nil); err == nil || !strings.Contains(err.Error(), "giving up") {
		t.Fatalf("persistent 500: %v", err)
	}
}

// fakeNVD serves `total` synthetic CVEs, honouring paging and lastMod filters.
type fakeNVD struct {
	total    int
	modified map[string]bool // ids returned for lastMod queries
	calls    []string
	failAt   int32 // fail permanently (HTTP 400) on this call number, 0 = never
	n        int32
}

func (f *fakeNVD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call := atomic.AddInt32(&f.n, 1)
	f.calls = append(f.calls, r.URL.RawQuery)
	if f.failAt != 0 && call == f.failAt {
		w.WriteHeader(400)
		return
	}
	q := r.URL.Query()
	var start int
	fmt.Sscan(q.Get("startIndex"), &start)
	var ids []string
	total := f.total
	if q.Get("lastModStartDate") != "" {
		for id := range f.modified {
			ids = append(ids, id)
		}
		total = len(ids)
	} else {
		for i := start; i < start+nvdPageSize && i < f.total; i++ {
			ids = append(ids, fmt.Sprintf("CVE-2020-%04d", i))
		}
	}
	var sb strings.Builder
	for i, id := range ids {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"cve":{"id":%q,"vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"d"}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"}]}]}]}}`, id)
	}
	fmt.Fprintf(w, `{"resultsPerPage":%d,"startIndex":%d,"totalResults":%d,"timestamp":"2026-11-22T10:00:00.000","vulnerabilities":[%s]}`, len(ids), start, total, sb.String())
}

func TestSyncNVDFullResumeAndIncremental(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	fake := &fakeNVD{total: 4500, modified: map[string]bool{"CVE-2020-0001": true}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	tick := 0
	clock := func() time.Time { tick++; return now.Add(time.Duration(tick) * time.Hour) } // time passes during a long sync
	cfg := NVDConfig{BaseURL: srv.URL, Delay: time.Nanosecond, Now: clock}

	// interrupted after the second request (permanent failure)
	fake.failAt = 2
	if _, err := SyncNVD(ctx, fastFetcher(), st, cfg); err == nil {
		t.Fatal("expected failure")
	}
	if c, _, _ := st.CountCVEs(ctx); c != nvdPageSize {
		t.Fatalf("first page must be kept, have %d", c)
	}
	feed, _, _ := st.GetFeed(ctx, "nvd")
	if feed.Version != "" || feed.Detail == "" {
		t.Fatalf("interrupted sync must be marked partial: %+v", feed)
	}

	// resume continues at index 2000, not 0
	fake.failAt = 0
	fake.calls = nil
	n, err := SyncNVD(ctx, fastFetcher(), st, cfg)
	if err != nil || n != 4500 {
		t.Fatal(n, err)
	}
	if !strings.Contains(fake.calls[0], "startIndex=2000") {
		t.Fatalf("resume restarted from scratch: %v", fake.calls)
	}
	feed, _, _ = st.GetFeed(ctx, "nvd")
	if feed.Version == "" || feed.Detail != "" {
		t.Fatalf("complete sync: %+v", feed)
	}
	var sawIncremental bool
	for _, c := range fake.calls {
		sawIncremental = sawIncremental || strings.Contains(c, "lastModStartDate")
	}
	if !sawIncremental {
		t.Fatal("a full sync must finish with an incremental pass for changes made during the download")
	}

	// later run is incremental only
	fake.calls = nil
	if _, err := SyncNVD(ctx, fastFetcher(), st, NVDConfig{BaseURL: srv.URL, Delay: time.Nanosecond, Now: func() time.Time { return now.Add(10 * 24 * time.Hour) }}); err != nil {
		t.Fatal(err)
	}
	for _, c := range fake.calls {
		if !strings.Contains(c, "lastModStartDate") {
			t.Fatalf("expected only incremental queries: %v", fake.calls)
		}
	}
}

func TestSyncNVDWindowsLimitedTo120Days(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	fake := &fakeNVD{total: 1, modified: map[string]bool{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := SyncNVD(ctx, fastFetcher(), st, NVDConfig{BaseURL: srv.URL, Delay: time.Nanosecond, Now: func() time.Time { return t0 }}); err != nil {
		t.Fatal(err)
	}
	fake.calls = nil
	if _, err := SyncNVD(ctx, fastFetcher(), st, NVDConfig{BaseURL: srv.URL, Delay: time.Nanosecond, Now: func() time.Time { return t0.Add(300 * 24 * time.Hour) }}); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) < 3 {
		t.Fatalf("300 days must be split into <=119-day windows, got %d calls", len(fake.calls))
	}
}

func TestSyncNVDMaxPagesLeavesResumablePartial(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	srv := httptest.NewServer(&fakeNVD{total: 6000, modified: map[string]bool{}})
	defer srv.Close()
	cfg := NVDConfig{BaseURL: srv.URL, Delay: time.Nanosecond, MaxPages: 1}
	if _, err := SyncNVD(ctx, fastFetcher(), st, cfg); err != nil {
		t.Fatal(err)
	}
	if feed, _, _ := st.GetFeed(ctx, "nvd"); feed.Version != "" || feed.Detail == "" {
		t.Fatalf("a capped sync is partial: %+v", feed)
	}
}

func osvZip(t *testing.T, docs map[string]string) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for n, d := range docs {
		w, _ := zw.Create(n)
		w.Write([]byte(d))
	}
	zw.Close()
	return b.Bytes()
}

const osvAlpine = `{"id":"ALPINE-CVE-2023-1","modified":"2023-01-01T00:00:00Z","summary":"s","aliases":["CVE-2023-1"],
 "affected":[{"package":{"ecosystem":"Alpine:v3.18","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.1.1-r1"}]}]}]}`
const osvMulti = `{"id":"GHSA-x","modified":"2023-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"django"},"ranges":[
 {"type":"ECOSYSTEM","events":[{"introduced":"3.0"},{"fixed":"3.0.5"},{"introduced":"4.0"},{"last_affected":"4.0.2"}]},
 {"type":"GIT","events":[{"introduced":"abc"},{"fixed":"def"}]}]}]}`
const osvWithdrawn = `{"id":"X-1","withdrawn":"2023-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"x"},"versions":["1"]}]}`

func TestParseOSV(t *testing.T) {
	r, ok, err := ParseOSV([]byte(osvMulti))
	if err != nil || !ok || len(r.Affected) != 2 {
		t.Fatalf("%+v %v %v (git range must be ignored, two ecosystem ranges kept)", r, ok, err)
	}
	if a := r.Affected[0]; a.Introduced != "3.0" || a.Fixed != "3.0.5" {
		t.Fatalf("%+v", a)
	}
	if a := r.Affected[1]; a.Introduced != "4.0" || a.LastAffected != "4.0.2" {
		t.Fatalf("%+v", a)
	}
	if _, ok, _ := ParseOSV([]byte(osvWithdrawn)); ok {
		t.Fatal("withdrawn advisory must be skipped")
	}
	if _, _, err := ParseOSV([]byte("{")); err == nil {
		t.Fatal("bad json")
	}
}

func TestSyncOSVReplacesEcosystemOnly(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	var etagHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"z1"` {
			atomic.AddInt32(&etagHits, 1)
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"z1"`)
		switch {
		case strings.Contains(r.URL.Path, "Alpine"):
			w.Write(osvZip(t, map[string]string{"a.json": osvAlpine, "readme.txt": "x"}))
		default:
			w.Write(osvZip(t, map[string]string{"g.json": osvMulti}))
		}
	}))
	defer srv.Close()
	tmp := t.TempDir()
	if n, ch, err := SyncOSV(ctx, fastFetcher(), st, srv.URL, "Alpine", tmp); err != nil || n != 1 || !ch {
		t.Fatal(n, ch, err)
	}
	if n, ch, err := SyncOSV(ctx, fastFetcher(), st, srv.URL, "PyPI", tmp); err != nil || n != 1 || !ch {
		t.Fatal(n, ch, err)
	}
	// Alpine again: unchanged => 304, and PyPI rows must survive either way
	if _, ch, err := SyncOSV(ctx, fastFetcher(), st, srv.URL, "Alpine", tmp); err != nil || ch {
		t.Fatal(ch, err)
	}
	var alpine, pypi, aliases int
	st.DB.QueryRow(`SELECT COUNT(*) FROM osv_affected WHERE ecosystem LIKE 'Alpine%'`).Scan(&alpine)
	st.DB.QueryRow(`SELECT COUNT(*) FROM osv_affected WHERE ecosystem='PyPI'`).Scan(&pypi)
	st.DB.QueryRow(`SELECT COUNT(*) FROM osv_alias WHERE alias='CVE-2023-1'`).Scan(&aliases)
	if alpine != 1 || pypi != 2 || aliases != 1 {
		t.Fatalf("alpine=%d pypi=%d aliases=%d", alpine, pypi, aliases)
	}
	if left, _ := filepath.Glob(filepath.Join(tmp, "osv-*")); len(left) != 0 {
		t.Fatalf("temp downloads must be removed: %v", left)
	}
	_ = os.Remove
}

func TestSyncOSVRefusesEmptyDump(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	good := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if good {
			w.Write(osvZip(t, map[string]string{"a.json": osvAlpine}))
		} else {
			w.Write(osvZip(t, map[string]string{"junk.txt": "x"}))
		}
	}))
	defer srv.Close()
	if _, _, err := SyncOSV(ctx, fastFetcher(), st, srv.URL, "Alpine", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	good = false
	if _, _, err := SyncOSV(ctx, fastFetcher(), st, srv.URL, "Alpine", t.TempDir()); err == nil {
		t.Fatal("an empty dump must not wipe existing data")
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM osv_affected`).Scan(&n)
	if n != 1 {
		t.Fatalf("existing data lost: %d", n)
	}
}

func TestParseOSVUpstreamCVEs(t *testing.T) {
	rec, ok, err := ParseOSV([]byte(`{"id":"DEBIAN-CVE-2024-1234","modified":"2024-01-01T00:00:00Z","upstream":["CVE-2024-1234"],"related":["CVE-2024-9999","GHSA-x"],
	  "affected":[{"package":{"ecosystem":"Debian:12","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.11-1"}]}]}]}`))
	if err != nil || !ok {
		t.Fatal(err, ok)
	}
	want := map[string]bool{"CVE-2024-1234": true, "CVE-2024-9999": true}
	for _, a := range rec.Aliases {
		delete(want, a)
		if a == "GHSA-x" {
			t.Errorf("non-CVE related reference kept: %v", rec.Aliases)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing aliases %v in %v", want, rec.Aliases)
	}
}
