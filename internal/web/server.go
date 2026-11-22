// Package web serves Babylon's local web UI and JSON API.
//
// A local service that can launch network scans must not be drivable by
// arbitrary websites open in the user's browser. Defences, in layers:
//   - binds to loopback only;
//   - a random per-run access token, exchanged once for an HttpOnly,
//     SameSite=Strict cookie (the token is then removed from the URL);
//   - Host header allowlist (blocks DNS rebinding);
//   - state-changing requests need a custom header (cross-origin pages cannot
//     send it without a CORS preflight, which is never granted) and a
//     same-origin Origin if one is sent;
//   - strict Content-Security-Policy; the UI never uses innerHTML.
package web

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"babylon/internal/app"
)

//go:embed static/*
var staticFS embed.FS

const (
	cookieName = "babylon_session"
	csrfHeader = "X-Babylon-Request"
	maxBody    = 1 << 20
)

// Server is the HTTP handler set.
type Server struct {
	app     *app.App
	token   string
	hosts   map[string]bool
	mgr     *manager
	version string
	static  http.Handler
}

// NewToken returns a fresh random access token.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// New builds a server. listen is the host:port it is bound to; maxConcurrent
// bounds simultaneously running scans.
func New(a *app.App, token, listen, version string, maxConcurrent int) (*Server, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("refusing to listen on %q: the web UI is loopback-only", host)
	}
	if len(token) < 32 {
		return nil, errors.New("access token too short")
	}
	hosts := map[string]bool{}
	for _, h := range []string{host, "localhost", "127.0.0.1", "[::1]"} {
		hosts[strings.ToLower(net.JoinHostPort(strings.Trim(h, "[]"), port))] = true
	}
	hosts["[::1]:"+port] = true
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	s := &Server{app: a, token: token, hosts: hosts, version: version, mgr: newManager(a, maxConcurrent), static: http.FileServer(http.FS(sub))}
	return s, nil
}

// Manager exposes shutdown/recovery for the process owner.
func (s *Server) Shutdown() { s.mgr.shutdown() }

// Handler returns the full handler with all protections applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", s.api(s.status))
	mux.HandleFunc("GET /api/scans", s.api(s.listScans))
	mux.HandleFunc("POST /api/scans", s.api(s.createScan))
	mux.HandleFunc("GET /api/scans/{id}", s.api(s.getScan))
	mux.HandleFunc("GET /api/scans/{id}/report", s.api(s.getReport))
	mux.HandleFunc("GET /api/scans/{id}/export", s.api(s.export))
	mux.HandleFunc("POST /api/scans/{id}/cancel", s.api(s.cancelScan))
	mux.HandleFunc("POST /api/scans/{id}/resume", s.api(s.resumeScan))
	mux.HandleFunc("DELETE /api/scans/{id}", s.api(s.deleteScan))
	mux.HandleFunc("GET /api/diff", s.api(s.diff))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, http.StatusNotFound, "not found") })
	mux.HandleFunc("/", s.index)
	return s.protect(mux)
}

// protect applies headers, Host check and CSRF rules to every request.
func (s *Server) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")

		if !s.hosts[strings.ToLower(r.Host)] { // DNS rebinding defence
			writeErr(w, http.StatusForbidden, "unexpected Host header")
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
		default:
			if r.Header.Get(csrfHeader) != "1" {
				writeErr(w, http.StatusForbidden, "missing "+csrfHeader+" header")
				return
			}
			if o := r.Header.Get("Origin"); o != "" && !strings.EqualFold(o, "http://"+r.Host) {
				writeErr(w, http.StatusForbidden, "cross-origin request refused")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.token)) == 1
}

// index serves the SPA, and exchanges ?token= for the session cookie.
func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if t := r.URL.Query().Get("token"); t != "" && r.URL.Path == "/" {
		if subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) != 1 {
			http.Error(w, "invalid token", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.token, Path: "/", HttpOnly: true,
			SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(24 * time.Hour)})
		http.Redirect(w, r, "/", http.StatusSeeOther) // drop the token from the URL
		return
	}
	if !s.authed(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Babylon: not signed in.\nOpen the URL printed by `babylon serve` (it contains a one-time access token).")
		return
	}
	s.static.ServeHTTP(w, r)
}

// api wraps a handler with authentication.
func (s *Server) api(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			writeErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		fn(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
