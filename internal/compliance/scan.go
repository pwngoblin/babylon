package compliance

import (
	"context"
	"fmt"

	"babylon/internal/pack"
	"babylon/internal/store"
)

// DefaultRegistry combines the built-in mapping with controls declared by check
// packs (built-in and those in packDir).
func DefaultRegistry(packDir string) (map[string][]string, error) {
	defs, err := pack.All(packDir)
	if err != nil {
		return nil, err
	}
	pc := map[string][]string{}
	for _, d := range defs {
		if len(d.Controls) > 0 {
			pc[d.ID] = d.Controls
		}
	}
	return Registry(pc), nil
}

// ForScan builds the per-control report for a stored scan.
func ForScan(ctx context.Context, st *store.Store, scanID int64, framework, packDir string) (*Report, error) {
	known := false
	for _, f := range Frameworks() {
		known = known || f == framework
	}
	if !known {
		return nil, fmt.Errorf("unknown compliance framework %q (use %v)", framework, Frameworks())
	}
	reg, err := DefaultRegistry(packDir)
	if err != nil {
		return nil, err
	}
	checkRuns, err := st.ListCheckRuns(ctx, scanID)
	if err != nil {
		return nil, err
	}
	refs, err := st.FindingRefs(ctx, scanID)
	if err != nil {
		return nil, err
	}
	var runs []Run
	for _, c := range checkRuns {
		runs = append(runs, Run{Host: c.Address, CheckID: c.CheckID, State: c.State, Reason: c.Reason})
	}
	var hits []Hit
	for _, r := range refs {
		if r.Severity == "info" {
			continue // informational findings are not control failures
		}
		hits = append(hits, Hit{Host: r.Address, CheckID: CheckForFinding(r.Engine, r.EngineRef), Title: r.Title, Severity: r.Severity})
	}
	rep := Evaluate(framework, reg, runs, hits)
	return &rep, nil
}
