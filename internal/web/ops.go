package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"babylon/internal/store"
)

// ---- assets ----

type assetJSON struct {
	Address     string         `json:"address"`
	Hostnames   []string       `json:"hostnames"`
	OS          string         `json:"os"`
	Criticality string         `json:"criticality"`
	Fragile     bool           `json:"fragile"`
	Tags        []string       `json:"tags"`
	Open        map[string]int `json:"open_findings"`
	LastSeen    string         `json:"last_seen"`
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	list, err := s.app.St.ListAssets(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]assetJSON, 0, len(list))
	for _, a := range list {
		out = append(out, assetJSON{Address: a.Address, Hostnames: nz(a.Hostnames), OS: a.OS, Criticality: store.CriticalityName(a.Criticality),
			Fragile: a.Fragile, Tags: nz(a.Tags), Open: a.OpenFindings, LastSeen: a.LastSeen})
	}
	writeJSON(w, 200, out)
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *Server) updateAsset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Address     string    `json:"address"`
		Criticality *string   `json:"criticality"`
		Fragile     *bool     `json:"fragile"`
		Tags        *[]string `json:"tags"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeErr(w, 400, "invalid request body: "+err.Error())
		return
	}
	u := store.AssetUpdate{Fragile: body.Fragile}
	if body.Criticality != nil {
		n, err := store.ParseCriticality(*body.Criticality)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		u.Criticality = &n
	}
	if body.Tags != nil {
		var t []string
		for _, x := range *body.Tags {
			if x = strings.TrimSpace(x); x != "" && len(x) <= 40 {
				t = append(t, x)
			}
		}
		if len(t) > 20 {
			writeErr(w, 400, "at most 20 tags")
			return
		}
		u.Tags = &t
	}
	if err := s.app.St.UpdateAsset(r.Context(), strings.TrimSpace(body.Address), u); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- triage ----

type triageJSON struct {
	FindingID int64  `json:"finding_id"`
	Host      string `json:"host"`
	Port      int    `json:"port,omitempty"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Active    bool   `json:"active"`
}

func (s *Server) listTriage(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.St.ListTriage(r.Context(), time.Now())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]triageJSON, 0, len(rows))
	for _, x := range rows {
		out = append(out, triageJSON{x.FindingID, x.Address, x.Port, x.Title, x.Severity, x.Status, x.Reason, x.CreatedAt, x.ExpiresAt, x.Active})
	}
	writeJSON(w, 200, out)
}

func (s *Server) setTriage(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FindingID   int64  `json:"finding_id"`
		Status      string `json:"status"`
		Reason      string `json:"reason"`
		ExpiresDays int    `json:"expires_days"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeErr(w, 400, "invalid request body: "+err.Error())
		return
	}
	now := time.Now()
	var exp *time.Time
	if body.ExpiresDays > 0 {
		t := now.AddDate(0, 0, body.ExpiresDays)
		exp = &t
	}
	if err := s.app.St.SetTriage(r.Context(), body.FindingID, body.Status, body.Reason, exp, now); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) removeTriage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	if err := s.app.St.RemoveTriage(r.Context(), id); err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
