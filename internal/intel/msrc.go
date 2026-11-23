package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"babylon/internal/store"
)

// Microsoft Security Response Center (MSRC) data: the public CVRF API lists, for
// every CVE, the first build revision of each Windows version that fixes it.
// Babylon compares the host's build and update revision with these fix
// revisions. The data is free and needs no key.

const msrcAPI = "https://api.msrc.microsoft.com/cvrf/v3.0"

type msrcDoc struct {
	Vulnerability []struct {
		CVE   string `json:"CVE"`
		Title struct {
			Value string `json:"Value"`
		} `json:"Title"`
		Threats []struct {
			Type        int `json:"Type"`
			Description struct {
				Value string `json:"Value"`
			} `json:"Description"`
		} `json:"Threats"`
		CVSSScoreSets []struct {
			BaseScore float64 `json:"BaseScore"`
		} `json:"CVSSScoreSets"`
		Remediations []struct {
			Description struct {
				Value string `json:"Value"`
			} `json:"Description"`
			FixedBuild string `json:"FixedBuild"`
		} `json:"Remediations"`
	} `json:"Vulnerability"`
}

var fixedBuildRe = regexp.MustCompile(`^(\d+\.\d+\.\d+)\.(\d+)$`)

var msrcSeverity = map[string]string{"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}

// ParseMSRC reads one monthly CVRF document and returns its Windows build fixes.
func ParseMSRC(r io.Reader) ([]store.MSRCFix, error) {
	var d msrcDoc
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return nil, fmt.Errorf("parsing MSRC document: %w", err)
	}
	type k struct{ build, cve string }
	best := map[k]store.MSRCFix{}
	for _, v := range d.Vulnerability {
		if !strings.HasPrefix(v.CVE, "CVE-") {
			continue
		}
		sev, rank := "", 0
		for _, t := range v.Threats {
			if t.Type != 3 {
				continue
			}
			if s, ok := msrcSeverity[strings.ToLower(t.Description.Value)]; ok && rankOf(s) > rank {
				sev, rank = s, rankOf(s)
			}
		}
		var cvss *float64
		for _, s := range v.CVSSScoreSets {
			if cvss == nil || s.BaseScore > *cvss {
				b := s.BaseScore
				cvss = &b
			}
		}
		for _, rem := range v.Remediations {
			m := fixedBuildRe.FindStringSubmatch(rem.FixedBuild)
			if m == nil {
				continue
			}
			ubr, _ := strconv.Atoi(m[2])
			key := k{m[1], v.CVE}
			if cur, ok := best[key]; !ok || ubr > cur.FixedUBR {
				best[key] = store.MSRCFix{Build: m[1], CVE: v.CVE, FixedUBR: ubr, KB: strings.TrimSpace(rem.Description.Value),
					Title: v.Title.Value, CVSS: cvss, Severity: sev}
			}
		}
	}
	out := make([]store.MSRCFix, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Build != out[j].Build {
			return out[i].Build < out[j].Build
		}
		return out[i].CVE < out[j].CVE
	})
	return out, nil
}

func rankOf(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

type msrcUpdate struct {
	ID          string `json:"ID"`
	Title       string `json:"DocumentTitle"`
	Initial     string `json:"InitialReleaseDate"`
	CurrentDate string `json:"CurrentReleaseDate"`
	URL         string `json:"CvrfUrl"`
}

var monthAlias = regexp.MustCompile(`^\d{4}-[A-Z][a-z]{2}$`)

// SyncMSRC downloads the most recent `months` security bulletins. Months already
// stored with the same revision date are skipped. apiURL "" uses the public API.
func SyncMSRC(ctx context.Context, f *Fetcher, st *store.Store, apiURL string, months int, logf func(string, ...any)) (fixes int, err error) {
	if apiURL == "" {
		apiURL = msrcAPI
	}
	if months <= 0 {
		months = 12
	}
	hdr := map[string]string{"Accept": "application/json"}
	res, err := f.Get(ctx, apiURL+"/updates", "", "", hdr)
	if err != nil {
		return 0, err
	}
	var list struct {
		Value []msrcUpdate `json:"value"`
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(&list)
	res.Body.Close()
	if err != nil {
		return 0, fmt.Errorf("parsing MSRC update list: %w", err)
	}
	var updates []msrcUpdate
	for _, u := range list.Value {
		if monthAlias.MatchString(u.ID) && strings.Contains(u.Title, "Security Update") {
			updates = append(updates, u)
		}
	}
	sort.Slice(updates, func(i, j int) bool { return updates[i].Initial > updates[j].Initial })
	if len(updates) > months {
		updates = updates[:months]
	}
	for _, u := range updates {
		name := "msrc:" + u.ID
		if cur, ok, _ := st.GetFeed(ctx, name); ok && cur.Version == u.CurrentDate {
			continue
		}
		url := u.URL
		if url == "" {
			url = apiURL + "/cvrf/" + u.ID
		} else if apiURL != msrcAPI { // tests point the list at a local server
			url = apiURL + "/cvrf/" + u.ID
		}
		r, err := f.Get(ctx, url, "", "", hdr)
		if err != nil {
			return fixes, fmt.Errorf("%s: %w", u.ID, err)
		}
		parsed, err := ParseMSRC(io.LimitReader(r.Body, 1<<30))
		r.Body.Close()
		if err != nil {
			return fixes, fmt.Errorf("%s: %w", u.ID, err)
		}
		if err := st.UpsertMSRC(ctx, parsed, store.FeedInfo{Name: name, Version: u.CurrentDate, FetchedAt: time.Now().UTC().Format(time.RFC3339), Count: len(parsed)}); err != nil {
			return fixes, err
		}
		fixes += len(parsed)
		if logf != nil {
			logf("  msrc %s: %d fixes", u.ID, len(parsed))
		}
	}
	return fixes, nil
}
