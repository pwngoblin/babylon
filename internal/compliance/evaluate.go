package compliance

import (
	"sort"
	"strings"
)

// Run is one recorded check execution on one host.
type Run struct {
	Host, CheckID, State, Reason string
}

// Hit is one finding attributed to a check on a host.
type Hit struct {
	Host, CheckID, Title, Severity string
}

const (
	StatusFail        = "fail"
	StatusPass        = "pass"
	StatusNotAssessed = "not_assessed"
)

// Control is the result for one control across all scanned hosts.
type Control struct {
	ID          string   `json:"id"`
	Title       string   `json:"title,omitempty"`
	Status      string   `json:"status"`
	HostsFailed []string `json:"hosts_failed,omitempty"`
	HostsPassed int      `json:"hosts_passed"`
	Checks      []string `json:"checks"`
	Failures    []string `json:"failures,omitempty"` // "host: finding title"
	NotRun      []string `json:"not_run,omitempty"`  // checks mapped to this control that did not run, with reason
}

// Report is the per-control view of one scan for one framework.
type Report struct {
	Framework string    `json:"framework"`
	Title     string    `json:"title"`
	Controls  []Control `json:"controls"`
	Failed    int       `json:"failed"`
	Passed    int       `json:"passed"`
	NotAssess int       `json:"not_assessed"`
	// Unmapped lists checks that ran but support no control in this framework, so
	// the report never hides coverage it cannot place.
	Unmapped []string `json:"unmapped_checks,omitempty"`
	Caveat   string   `json:"caveat"`
}

const caveat = "Control mapping is Babylon's own approximation, an evidence aid and not an assessment. " +
	"A pass means the mapped checks ran and found nothing; it does not prove the control is met. " +
	"Controls with no mapped check are not listed."

// Evaluate builds the report. registry is check id -> controls (see Registry).
// A control fails if any mapped check produced a finding on any host, passes if
// at least one mapped check ran and none failed, and is not assessed otherwise.
func Evaluate(framework string, registry map[string][]string, runs []Run, hits []Hit) Report {
	pfx := prefix[framework]
	rep := Report{Framework: framework, Title: FrameworkTitle(framework), Caveat: caveat}

	type agg struct {
		checks   map[string]bool
		ran      map[string]map[string]bool // host -> check ran
		ranIDs   map[string]bool
		failed   map[string]bool // host
		failures []string
		notRun   map[string]bool
	}
	ctl := map[string]*agg{}
	get := func(id string) *agg {
		a := ctl[id]
		if a == nil {
			a = &agg{checks: map[string]bool{}, ranIDs: map[string]bool{}, ran: map[string]map[string]bool{}, failed: map[string]bool{}, notRun: map[string]bool{}}
			ctl[id] = a
		}
		return a
	}
	controlsOf := func(check string) []string {
		var out []string
		for _, c := range registry[check] {
			if strings.HasPrefix(c, pfx) {
				out = append(out, c)
			}
		}
		return out
	}
	for id, list := range registry {
		for _, c := range list {
			if strings.HasPrefix(c, pfx) {
				get(c).checks[id] = true
			}
		}
	}
	ranAnywhere := map[string]bool{}
	for _, r := range runs {
		cs := controlsOf(r.CheckID)
		if r.State == "ran" {
			ranAnywhere[r.CheckID] = true
		}
		for _, c := range cs {
			a := get(c)
			switch r.State {
			case "ran":
				if a.ran[r.Host] == nil {
					a.ran[r.Host] = map[string]bool{}
				}
				a.ran[r.Host][r.CheckID] = true
				a.ranIDs[r.CheckID] = true
			default:
				why := r.State
				if r.Reason != "" {
					why += ": " + r.Reason
				}
				a.notRun[r.CheckID+" on "+r.Host+" ("+why+")"] = true
			}
		}
	}
	for _, h := range hits {
		for _, c := range controlsOf(h.CheckID) {
			a := get(c)
			a.failed[h.Host] = true
			a.failures = append(a.failures, h.Host+": "+h.Title)
		}
	}

	ids := make([]string, 0, len(ctl))
	for id := range ctl {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return naturalLess(ids[i], ids[j]) })
	for _, id := range ids {
		a := ctl[id]
		c := Control{ID: strings.TrimPrefix(id, pfx), Title: Title(id)}
		for ch := range a.checks {
			// A control's evidence is the checks that actually ran; a control nothing ran for lists what could assess it.
			if len(a.ranIDs) == 0 || a.ranIDs[ch] {
				c.Checks = append(c.Checks, ch)
			}
		}
		sort.Strings(c.Checks)
		for h := range a.failed {
			c.HostsFailed = append(c.HostsFailed, h)
		}
		sort.Strings(c.HostsFailed)
		for h := range a.ran {
			if !a.failed[h] {
				c.HostsPassed++
			}
		}
		sort.Strings(a.failures)
		c.Failures = dedupe(a.failures)
		for n := range a.notRun {
			c.NotRun = append(c.NotRun, n)
		}
		sort.Strings(c.NotRun)
		switch {
		case len(a.failed) > 0:
			c.Status = StatusFail
			rep.Failed++
		case len(a.ran) > 0:
			c.Status = StatusPass
			rep.Passed++
		default:
			c.Status = StatusNotAssessed
			rep.NotAssess++
		}
		rep.Controls = append(rep.Controls, c)
	}
	for id := range ranAnywhere {
		if len(controlsOf(id)) == 0 {
			rep.Unmapped = append(rep.Unmapped, id)
		}
	}
	sort.Strings(rep.Unmapped)
	return rep
}

func dedupe(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// naturalLess orders "AC-2" before "AC-12" and "2.2.4" before "10.2.1".
func naturalLess(a, b string) bool {
	as, bs := tokens(a), tokens(b)
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		an, aok := atoi(as[i])
		bn, bok := atoi(bs[i])
		if aok && bok {
			return an < bn
		}
		return as[i] < bs[i]
	}
	return len(as) < len(bs)
}

func tokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '.' || r == ':' })
}

func atoi(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}
