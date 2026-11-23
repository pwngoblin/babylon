package web

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"

	"babylon/internal/app"
	"babylon/internal/policy"
	"babylon/internal/report"
	"babylon/internal/store"
)

type templateInfo struct {
	Name          string `json:"name"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	RequiresCreds bool   `json:"requires_creds"`
	Implemented   bool   `json:"implemented"`
}

var templateDocs = []templateInfo{
	{policy.TemplateHostDiscovery, "Host Discovery", "Find live hosts only (ping and TCP probes). No port scan, no vulnerability checks. The lightest option.", false, true},
	{policy.TemplateBasic, "Basic Network Scan", "Discovery, top-1000 TCP ports, service and TLS fingerprinting, curated safe Nmap scripts, technology-aware Nuclei checks and built-in misconfiguration checks. Non-destructive.", false, true},
	{policy.TemplateFullUnauth, "Full Unauthenticated Scan", "Everything in Basic across all 65,535 TCP ports with broader Nuclei coverage. Slower. Active probes need the explicit opt-in.", false, true},
	{policy.TemplateCredentialed, "Credentialed Patch & Config Audit", "Logs in over SSH/WinRM to audit installed packages and configuration. Not implemented yet.", true, false},
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	tools := map[string]bool{}
	for _, t := range []string{"nmap", "nuclei", "trivy"} {
		_, err := exec.LookPath(t)
		tools[t] = err == nil
	}
	_, fetched, n, ok, _ := s.app.St.FeedState(r.Context(), "nuclei-templates")
	priv := "unprivileged (connect scans)"
	if os.Geteuid() == 0 {
		priv = "root"
	}
	writeJSON(w, 200, map[string]any{
		"version": s.version, "tools": tools, "privilege": priv, "sudo_allowed": s.app.AllowSudo,
		"nuclei_templates": map[string]any{"indexed": ok && n > 0, "count": n, "updated": fetched},
		"templates":        templateDocs,
	})
}

type scanOut struct {
	store.ScanSummary
	Running  bool     `json:"running"`
	Error    string   `json:"error,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Accuracy string   `json:"accuracy"`
}

func (s *Server) scanOut(r *http.Request, sm store.ScanSummary) scanOut {
	e, w := s.mgr.lastError(sm.ID)
	return scanOut{ScanSummary: sm, Running: s.mgr.isRunning(sm.ID), Error: e, Warnings: w, Accuracy: s.app.Accuracy(r.Context(), sm.ID)}
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	list, err := s.app.St.ListScans(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]scanOut, 0, len(list))
	for _, sm := range list {
		out = append(out, s.scanOut(r, sm))
	}
	writeJSON(w, 200, out)
}

func scanID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid scan id")
	}
	return id, nil
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	id, err := scanID(r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	sm, err := s.app.St.GetScanSummary(r.Context(), id)
	if err != nil {
		writeErr(w, 404, "scan not found")
		return
	}
	jobs, _ := s.app.St.ListJobs(r.Context(), id)
	if jobs == nil {
		jobs = []store.JobRow{} // a pending scan has no jobs yet; JSON must be [] not null
	}
	writeJSON(w, 200, map[string]any{"scan": s.scanOut(r, sm), "jobs": jobs})
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	var req app.Request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, 400, "invalid request body: "+err.Error())
		return
	}
	id, err := s.app.Create(r.Context(), req)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.mgr.start(id); err != nil {
		// Created but not started (e.g. too many running): the user can resume it later.
		writeJSON(w, 202, map[string]any{"id": id, "started": false, "message": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"id": id, "started": true})
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	id, err := scanID(r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	acc := r.URL.Query().Get("accuracy")
	if acc == "" {
		acc = s.app.Accuracy(r.Context(), id)
	}
	if acc != app.AccuracyNormal && acc != app.AccuracyAvoid {
		writeErr(w, 400, "invalid accuracy")
		return
	}
	rep, err := report.Build(r.Context(), s.app.St, id, acc)
	if err != nil {
		writeErr(w, 404, "scan not found")
		return
	}
	writeJSON(w, 200, rep)
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	id, err := scanID(r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	acc := r.URL.Query().Get("accuracy")
	if acc == "" {
		acc = s.app.Accuracy(r.Context(), id)
	}
	rep, err := report.Build(r.Context(), s.app.St, id, acc)
	if err != nil {
		writeErr(w, 404, "scan not found")
		return
	}
	var buf bytes.Buffer
	var ctype, ext string
	switch f := r.URL.Query().Get("format"); f {
	case "json":
		ctype, ext, err = "application/json", "json", report.WriteJSON(&buf, rep)
	case "csv":
		ctype, ext, err = "text/csv", "csv", report.WriteCSV(&buf, rep)
	case "html":
		ctype, ext, err = "text/html", "html", report.WriteHTML(&buf, rep)
	case "md", "markdown", "":
		ctype, ext, err = "text/markdown", "md", report.WriteMarkdown(&buf, rep)
	default:
		writeErr(w, 400, "format must be json, md, csv or html")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", ctype+"; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="babylon-scan-%d.%s"`, id, ext))
	w.Write(buf.Bytes())
}

func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request) {
	id, err := scanID(r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !s.mgr.cancel(id) {
		writeErr(w, 409, "scan is not running")
		return
	}
	writeJSON(w, 202, map[string]any{"cancelling": true})
}

func (s *Server) resumeScan(w http.ResponseWriter, r *http.Request) {
	id, err := scanID(r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	sm, err := s.app.St.GetScanSummary(r.Context(), id)
	if err != nil {
		writeErr(w, 404, "scan not found")
		return
	}
	if sm.Status == store.ScanCompleted {
		writeErr(w, 409, "scan already completed")
		return
	}
	if err := s.mgr.start(id); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 202, map[string]any{"resumed": true})
}

func (s *Server) deleteScan(w http.ResponseWriter, r *http.Request) {
	id, err := scanID(r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if s.mgr.isRunning(id) {
		writeErr(w, 409, "cancel the scan before deleting it")
		return
	}
	if err := s.app.RemoveScanData(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 404, "scan not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

func (s *Server) diff(w http.ResponseWriter, r *http.Request) {
	a, err1 := strconv.ParseInt(r.URL.Query().Get("a"), 10, 64)
	b, err2 := strconv.ParseInt(r.URL.Query().Get("b"), 10, 64)
	if err1 != nil || err2 != nil || a <= 0 || b <= 0 {
		writeErr(w, 400, "a and b must be scan ids")
		return
	}
	d, err := s.app.St.DiffScans(r.Context(), a, b)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"new": d.New, "resolved": d.Resolved, "persisting": d.Persisting})
}
