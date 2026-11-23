// Package native is Babylon's plugin layer, modelled on how Nessus plugins work:
// each check declares what it needs (facts in the per-host knowledge base) and
// which checks must run before it. The runner orders checks by dependency,
// skips those whose preconditions are not met, and records why, so coverage is
// transparent. Checks here are pure functions over already-collected data;
// active probing, if added later, is a separate Safety level gated by policy.
package native

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"babylon/internal/correlate"
	"babylon/internal/model"
	"babylon/internal/policy"
	"babylon/internal/store"
)

// Env is what a check can see about one host.
type Env struct {
	Address  string
	AssetID  int64
	Services []store.ServiceInfo
	TLS      []store.TLSRow
	KB       map[string]json.RawMessage
	Now      time.Time
}

// Script returns an Nmap NSE script's output for a service, if it produced any.
func (e *Env) Script(port int, proto, id string) (string, bool) {
	raw, ok := e.KB[store.ScriptKey(port, proto, id)]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || strings.TrimSpace(s) == "" {
		return "", false
	}
	return s, true
}

// ScriptAnywhere returns every (service, output) pair for a script id.
func (e *Env) ScriptAnywhere(id string) []ScriptHit {
	var out []ScriptHit
	for _, s := range e.Services {
		if txt, ok := e.Script(s.Port, s.Proto, id); ok {
			out = append(out, ScriptHit{Service: s, Output: txt})
		}
	}
	return out
}

type ScriptHit struct {
	Service store.ServiceInfo
	Output  string
}

// HasService reports whether any open service has one of the given names.
func (e *Env) HasService(names ...string) bool {
	for _, s := range e.Services {
		for _, n := range names {
			if strings.EqualFold(s.Name, n) {
				return true
			}
		}
	}
	return false
}

// Check is one native plugin.
type Check struct {
	ID        string
	Name      string
	Family    string
	Safety    policy.Safety
	DependsOn []string
	// Controls are compliance references (framework:id) this check supports.
	Controls []string
	// Needs returns "" when the precondition holds, otherwise a human reason
	// the check cannot apply (recorded as the skip reason).
	Needs func(*Env) string
	Run   func(*Env) []Finding
}

// Finding is a check's output before identity/engine fields are filled in.
type Finding struct {
	Port        int
	Proto       string
	Title       string
	Severity    string
	CVSS        *float64
	CVEs        []string
	Synopsis    string
	Description string
	Remediation string
	Evidence    string
	Confidence  string // default confirmed: checks read observed data
	Detection   string // default config
}

// Order returns checks in dependency order (stable by ID within a level) and
// rejects unknown dependencies, cycles, and checks above the allowed safety.
func Order(checks []Check, max policy.Safety) ([]Check, error) {
	byID := map[string]Check{}
	for _, c := range checks {
		if c.ID == "" || c.Run == nil {
			return nil, fmt.Errorf("check %q: ID and Run are required", c.ID)
		}
		if _, dup := byID[c.ID]; dup {
			return nil, fmt.Errorf("duplicate check %q", c.ID)
		}
		if c.Safety > max {
			return nil, fmt.Errorf("check %q has safety %s, above the allowed %s", c.ID, c.Safety, max)
		}
		byID[c.ID] = c
	}
	var out []Check
	state := map[string]int{}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var visit func(string) error
	visit = func(id string) error {
		switch state[id] {
		case 1:
			return fmt.Errorf("check dependency cycle through %q", id)
		case 2:
			return nil
		}
		state[id] = 1
		c := byID[id]
		deps := append([]string(nil), c.DependsOn...)
		sort.Strings(deps)
		for _, d := range deps {
			if _, ok := byID[d]; !ok {
				return fmt.Errorf("check %q depends on unknown check %q", id, d)
			}
			if err := visit(d); err != nil {
				return err
			}
		}
		state[id] = 2
		out = append(out, c)
		return nil
	}
	for _, id := range ids {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// RunHost executes ordered checks against one host, recording findings and a
// check_run row for every check (ran / skipped with reason / error).
func RunHost(ctx context.Context, st *store.Store, scanID int64, env *Env, ordered []Check) error {
	ran := map[string]bool{}
	for _, c := range ordered {
		reason := ""
		for _, d := range c.DependsOn {
			if !ran[d] {
				reason = "dependency " + d + " did not run"
				break
			}
		}
		if reason == "" && c.Needs != nil {
			reason = c.Needs(env)
		}
		if reason != "" {
			if err := st.RecordCheckRun(ctx, scanID, env.AssetID, c.ID, "skipped", reason); err != nil {
				return err
			}
			continue
		}
		findings, err := safeRun(c, env)
		if err != nil {
			if e := st.RecordCheckRun(ctx, scanID, env.AssetID, c.ID, "error", err.Error()); e != nil {
				return e
			}
			continue
		}
		ran[c.ID] = true
		if err := st.RecordCheckRun(ctx, scanID, env.AssetID, c.ID, "ran", ""); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, f := range findings {
			mf := toModel(c, env, f)
			// A check that reports several findings for one port (for example an
			// end-of-life database that also lacks TLS) must not have them merged
			// into one by the shared fingerprint: later ones are keyed by title.
			pk := fmt.Sprintf("%d/%s", mf.Port, mf.Proto)
			if seen[pk] {
				mf.Fingerprint = correlate.Fingerprint(env.Address, mf.Port, mf.Proto, nil, correlate.CheckKey("native", c.ID+"#"+f.Title))
			}
			seen[pk] = true
			if err := st.RecordFinding(ctx, scanID, mf); err != nil {
				return err
			}
		}
	}
	return nil
}

func safeRun(c Check, env *Env) (out []Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("check panicked: %v", r)
		}
	}()
	return c.Run(env), nil
}

func toModel(c Check, env *Env, f Finding) model.Finding {
	conf, det := f.Confidence, f.Detection
	if conf == "" {
		conf = model.ConfConfirmed
	}
	if det == "" {
		det = "config"
	}
	proto := f.Proto
	if proto == "" && f.Port != 0 {
		proto = "tcp"
	}
	return model.Finding{
		Fingerprint: correlate.Fingerprint(env.Address, f.Port, proto, nil, correlate.CheckKey("native", c.ID)),
		Address:     env.Address, Port: f.Port, Proto: proto,
		Title: f.Title, Family: c.Family, Severity: f.Severity, CVSS: f.CVSS, CVEs: f.CVEs,
		Synopsis: f.Synopsis, Description: f.Description, Remediation: f.Remediation,
		Solution: solution(f.Remediation), Confidence: conf, Detection: det,
		Engine: "native", EngineRef: c.ID, Evidence: correlate.Redact(f.Evidence),
	}
}

func solution(rem string) string {
	if strings.TrimSpace(rem) == "" {
		return ""
	}
	return "Mitigation"
}
