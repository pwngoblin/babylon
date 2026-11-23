package scan

import (
	"context"
	"fmt"
	"time"

	"babylon/internal/native"
	"babylon/internal/orchestrator"
	"babylon/internal/pack"
	"babylon/internal/policy"
	"babylon/internal/store"
)

const (
	StageNative = "native"
	ClassNative = "native"

	nativeHostsPerJob = 25
)

// nativeStage runs Babylon's built-in checks over data already collected by
// earlier stages (knowledge base, services, TLS). Read-only checks do no network
// I/O; probe-level checks (only with --allow-active) send a few read-only GETs.
func nativeStage(st *store.Store, res *policy.Resolved, packDir string, extraDeps ...string) (orchestrator.Stage, error) {
	packs, err := pack.Checks(packDir, res.Native.MaxSafety)
	if err != nil {
		return orchestrator.Stage{}, fmt.Errorf("check packs: %w", err)
	}
	ordered, err := native.Order(append(native.Available(res.Native.MaxSafety), packs...), res.Native.MaxSafety)
	if err != nil {
		return orchestrator.Stage{}, err
	}
	return orchestrator.Stage{
		Name:      StageNative,
		Class:     ClassNative,
		DependsOn: append([]string{StagePortscan}, extraDeps...),
		Plan: func(ctx context.Context, sc store.Scan) ([]store.JobSpec, error) {
			svcs, err := st.OpenServices(ctx, sc.ID)
			if err != nil {
				return nil, err
			}
			seen := map[string]bool{}
			var hosts []string
			for _, s := range svcs {
				if !seen[s.Address] {
					seen[s.Address] = true
					hosts = append(hosts, s.Address)
				}
			}
			return chunkSpecs(hosts, nativeHostsPerJob, "native", nil), nil
		},
		Handle: func(ctx context.Context, job store.Job) error {
			bg := context.WithoutCancel(ctx)
			all, err := st.OpenServices(bg, job.ScanID)
			if err != nil {
				return err
			}
			for _, addr := range job.Targets {
				env := &native.Env{Address: addr, Now: time.Now()}
				for _, s := range all {
					if s.Address == addr {
						env.AssetID = s.AssetID
						env.Services = append(env.Services, s)
					}
				}
				if env.AssetID == 0 {
					continue
				}
				if env.KB, err = st.KB(bg, job.ScanID, env.AssetID); err != nil {
					return err
				}
				if env.TLS, err = st.TLSForAsset(bg, job.ScanID, env.AssetID); err != nil {
					return err
				}
				if err := native.RunHost(bg, st, job.ScanID, env, ordered); err != nil {
					return fmt.Errorf("native checks on %s: %w", addr, err)
				}
			}
			return nil
		},
	}, nil
}
