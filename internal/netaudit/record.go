package netaudit

import (
	"context"
	"fmt"

	"babylon/internal/audit"
	"babylon/internal/correlate"
	"babylon/internal/model"
	"babylon/internal/store"
)

// Family is the finding family for device configuration problems.
const Family = "Network device configuration"

// Summary counts rule outcomes.
type Summary struct {
	Failed, Passed, Unknown int
}

// Record evaluates the rules for deviceType against cfg and stores the result as
// a completed scan of one host: failures become findings, every rule leaves a
// check_run row (ran, or skipped with the reason when the config lacks the
// section it judges). It returns the scan id, so the normal reports, triage,
// compliance and trend features all work on it.
func Record(ctx context.Context, st *store.Store, host, deviceType string, cfg *Config) (int64, Summary, error) {
	var sum Summary
	rules := RulesFor(deviceType)
	if rules == nil {
		return 0, sum, fmt.Errorf("unsupported device type %q (supported: %s)", deviceType, CiscoIOS)
	}
	id, err := st.CreateScan(ctx, "config audit: "+host, "config_audit", []string{host}, map[string]any{"device_type": deviceType})
	if err != nil {
		return 0, sum, err
	}
	if err := st.IngestHost(ctx, id, model.Host{Address: host, State: "up", Hostnames: nil}); err != nil {
		return id, sum, err
	}
	assetID, err := st.AssetID(ctx, host)
	if err != nil {
		return id, sum, err
	}
	for _, r := range rules {
		res := r.Eval(cfg)
		switch res.Status {
		case audit.Unknown:
			sum.Unknown++
			if err := st.RecordCheckRun(ctx, id, assetID, r.ID, "skipped", res.Reason); err != nil {
				return id, sum, err
			}
			continue
		case audit.Fail:
			sum.Failed++
			f := model.Finding{
				Fingerprint: correlate.Fingerprint(host, 0, "", nil, "netaudit:"+r.ID),
				Address:     host, Title: r.Title, Family: Family, Severity: r.Severity,
				Synopsis: r.Synopsis, Remediation: res.Remediation,
				Confidence: model.ConfConfirmed, Detection: "config", Engine: "netaudit", EngineRef: r.ID,
				Evidence: res.Evidence,
			}
			if err := st.RecordFinding(ctx, id, f); err != nil {
				return id, sum, err
			}
		default:
			sum.Passed++
		}
		if err := st.RecordCheckRun(ctx, id, assetID, r.ID, "ran", ""); err != nil {
			return id, sum, err
		}
	}
	return id, sum, st.SetScanStatus(ctx, id, store.ScanCompleted)
}
