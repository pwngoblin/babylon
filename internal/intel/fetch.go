// Package intel downloads and parses vulnerability intelligence feeds (CISA
// KEV, FIRST EPSS, NVD, OSV) into the local database. Parsers are pure and
// tested against fixtures; the network layer supports conditional requests so
// repeated updates are cheap.
package intel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// Fetcher performs HTTP downloads with conditional-GET caching and retries.
type Fetcher struct {
	Client  *http.Client
	Retries int           // attempts after the first (default 3)
	Backoff time.Duration // base backoff (default 2s); tests set it tiny
	UA      string
}

// NewFetcher returns a Fetcher with sane timeouts.
func NewFetcher() *Fetcher {
	return &Fetcher{Client: &http.Client{Timeout: 45 * time.Minute}, Retries: 3, Backoff: 2 * time.Second, UA: "babylon-scanner/feeds"}
}

// Result of a download.
type Result struct {
	NotModified  bool
	ETag         string
	LastModified string
	Body         io.ReadCloser
}

// Get fetches url. If etag/lastModified are given the request is conditional
// and a 304 yields NotModified. Transient failures (429, 5xx, NVD's 403 rate
// limit) are retried with backoff, honouring Retry-After.
func (f *Fetcher) Get(ctx context.Context, url, etag, lastModified string, hdr map[string]string) (*Result, error) {
	retries := f.Retries
	if retries < 0 {
		retries = 0
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			wait := f.Backoff << (attempt - 1)
			if ra, ok := lastRetryAfter(lastErr); ok {
				wait = ra
			}
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", f.UA)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		if lastModified != "" {
			req.Header.Set("If-Modified-Since", lastModified)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := f.Client.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		switch {
		case resp.StatusCode == http.StatusNotModified:
			resp.Body.Close()
			return &Result{NotModified: true, ETag: etag, LastModified: lastModified}, nil
		case resp.StatusCode == http.StatusOK:
			return &Result{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), Body: resp.Body}, nil
		case resp.StatusCode == 429 || resp.StatusCode == 403 || resp.StatusCode >= 500:
			e := &statusError{code: resp.StatusCode, url: url}
			if s := resp.Header.Get("Retry-After"); s != "" {
				if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 120 {
					e.retryAfter = time.Duration(n) * time.Second
				}
			}
			resp.Body.Close()
			lastErr = e
		default:
			resp.Body.Close()
			return nil, &statusError{code: resp.StatusCode, url: url, permanent: true}
		}
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", retries+1, lastErr)
}

type statusError struct {
	code       int
	url        string
	retryAfter time.Duration
	permanent  bool
}

func (e *statusError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.url, e.code) }

func lastRetryAfter(err error) (time.Duration, bool) {
	if se, ok := err.(*statusError); ok && se.retryAfter > 0 {
		return se.retryAfter, true
	}
	return 0, false
}

// toTemp saves a body to a temp file in dir and returns its path.
func toTemp(dir, pattern string, r io.Reader) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), f.Close()
}
