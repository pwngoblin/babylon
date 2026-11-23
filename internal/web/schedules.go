package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"babylon/internal/app"
)

func (s *Server) listSchedules(w http.ResponseWriter, r *http.Request) {
	list, err := s.app.St.ListSchedules(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, list)
}

type scheduleReq struct {
	Name         string      `json:"name"`
	EveryMinutes int         `json:"every_minutes"`
	Scan         app.Request `json:"scan"`
}

func (s *Server) createSchedule(w http.ResponseWriter, r *http.Request) {
	var req scheduleReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, 400, "invalid request body: "+err.Error())
		return
	}
	sid, first, err := s.app.CreateSchedule(r.Context(), req.Name, req.Scan, time.Duration(req.EveryMinutes)*time.Minute)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	started := s.mgr.start(first) == nil
	writeJSON(w, 201, map[string]any{"id": sid, "first_scan": first, "started": started})
}

func schedID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) toggleSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := schedID(r)
	if !ok {
		writeErr(w, 400, "bad schedule id")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid request body")
		return
	}
	if err := s.app.St.SetScheduleEnabled(r.Context(), id, body.Enabled); err != nil {
		writeErr(w, 404, "schedule not found")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) deleteSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := schedID(r)
	if !ok {
		writeErr(w, 400, "bad schedule id")
		return
	}
	if err := s.app.St.DeleteSchedule(r.Context(), id); err != nil {
		writeErr(w, 404, "schedule not found")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
