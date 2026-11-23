package intel

import (
	"context"

	"babylon/internal/store"
)

// SyncKEV downloads (conditionally) and stores the CISA KEV catalogue.
func SyncKEV(ctx context.Context, f *Fetcher, st *store.Store, url string) (n int, changed bool, err error) {
	if url == "" {
		url = KEVURL
	}
	cur, _, err := st.GetFeed(ctx, "kev")
	if err != nil {
		return 0, false, err
	}
	res, err := f.Get(ctx, url, cur.ETag, cur.LastModified, nil)
	if err != nil {
		return 0, false, err
	}
	if res.NotModified {
		return cur.Count, false, nil
	}
	defer res.Body.Close()
	entries, ver, err := ParseKEV(res.Body)
	if err != nil {
		return 0, false, err
	}
	err = st.ReplaceKEV(ctx, entries, store.FeedInfo{Name: "kev", Version: ver, ETag: res.ETag, LastModified: res.LastModified})
	return len(entries), err == nil, err
}

// SyncEPSS downloads (conditionally) and stores FIRST's EPSS scores.
func SyncEPSS(ctx context.Context, f *Fetcher, st *store.Store, url string) (n int, changed bool, err error) {
	if url == "" {
		url = EPSSURL
	}
	cur, _, err := st.GetFeed(ctx, "epss")
	if err != nil {
		return 0, false, err
	}
	res, err := f.Get(ctx, url, cur.ETag, cur.LastModified, nil)
	if err != nil {
		return 0, false, err
	}
	if res.NotModified {
		return cur.Count, false, nil
	}
	defer res.Body.Close()
	entries, asOf, err := ParseEPSS(res.Body)
	if err != nil {
		return 0, false, err
	}
	err = st.ReplaceEPSS(ctx, asOf, entries, store.FeedInfo{Name: "epss", Version: asOf, ETag: res.ETag, LastModified: res.LastModified})
	return len(entries), err == nil, err
}
