// Package scan assembles orchestrator stages for a resolved policy: it is the
// glue between templates, engines and the store.
package scan

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"babylon/internal/engines/nmap"
	berr "babylon/internal/errors"
	"babylon/internal/model"
	"babylon/internal/orchestrator"
	"babylon/internal/policy"
	"babylon/internal/runner"
	"babylon/internal/store"
)

// Stage and resource-class names.
const (
	StageSweep    = "sweep"
	StagePortscan = "portscan"

	ClassNmap = "nmap"
)

// Options configure stage construction.
type Options struct {
	Privilege    nmap.Privilege
	SweepChunk   uint64        // addresses per sweep job (default 1024)
	ScanChunk    uint64        // hosts per port-scan job (default 128)
	SweepTimeout time.Duration // per job (default 15m)
	ScanTimeout  time.Duration // per job (default 3h)
	HostTimeout  time.Duration // nmap --host-timeout (default 30m)

	Ports         string        // overrides the template's port list (validated)
	NucleiDir     string        // nuclei-templates root; "" disables Nuclei stages
	NucleiRate    int           // requests/second (default 100)
	NucleiTimeout time.Duration // per job (default 45m)

	Audit *AuditConfig // credentials for the credentialed stage (in memory only); nil disables it
}

func (o *Options) defaults() {
	if o.SweepChunk == 0 {
		o.SweepChunk = 1024
	}
	if o.ScanChunk == 0 {
		o.ScanChunk = 128
	}
	if o.SweepTimeout == 0 {
		o.SweepTimeout = 15 * time.Minute
	}
	if o.ScanTimeout == 0 {
		o.ScanTimeout = 3 * time.Hour
	}
	if o.HostTimeout == 0 {
		o.HostTimeout = 30 * time.Minute
	}
	if o.NucleiRate == 0 {
		o.NucleiRate = 100
	}
	if o.NucleiTimeout == 0 {
		o.NucleiTimeout = 45 * time.Minute
	}
}

// Stages returns the stages implemented for the resolved template. Stages for
// engines not yet built (Nuclei, native checks, CPE matching, audit) are added
// here as they land.
func Stages(res *policy.Resolved, st *store.Store, opt Options) []orchestrator.Stage {
	stages, err := buildStages(res, st, opt)
	if err != nil {
		// Only possible if a built-in check is mis-declared; fail loudly in tests/dev.
		panic("scan: invalid built-in stage configuration: " + err.Error())
	}
	return stages
}

func buildStages(res *policy.Resolved, st *store.Store, opt Options) ([]orchestrator.Stage, error) {
	if opt.NucleiRate == 0 {
		opt.NucleiRate = res.Timing.NucleiRate // the profile sets the rate unless explicitly overridden
	}
	opt.defaults()
	nopt := nmap.Opts{Timing: res.Timing, Privilege: opt.Privilege, MaxRatePPS: res.Template.MaxRatePPS, HostTimeout: opt.HostTimeout, Ports: opt.Ports}

	stages := []orchestrator.Stage{{
		Name:  StageSweep,
		Class: ClassNmap,
		Plan:  planSweep(opt.SweepChunk),
		Handle: handleNmap(st, opt.SweepTimeout, "sweep.xml", func(job store.Job, xml string) ([]string, error) {
			return nmap.SweepArgs(job.Targets, xml, nopt)
		}, nopt),
	}}

	if res.Template.Ports != "" {
		stages = append(stages, orchestrator.Stage{
			Name:      StagePortscan,
			Class:     ClassNmap,
			DependsOn: []string{StageSweep},
			Plan:      planPortscan(st, opt.ScanChunk),
			Handle: handleNmap(st, opt.ScanTimeout, "scan.xml", func(job store.Job, xml string) ([]string, error) {
				return nmap.ScanArgs(res, job.Targets, xml, nopt)
			}, nopt),
		})
	}
	if res.Template.Nuclei && res.Template.Ports != "" && opt.NucleiDir != "" {
		stages = append(stages, newNucleiRuntime(st, res, opt).stages()...)
	}
	if res.Template.CPEMatch && res.Template.Ports != "" {
		var deps []string
		if res.Template.Nuclei && opt.NucleiDir != "" {
			deps = append(deps, StageNucleiDetect) // web versions found by detection feed the matcher
		}
		stages = append(stages, cpeMatchStage(st, deps...))
	}
	if res.Native.Enabled && res.Template.Ports != "" {
		ns, err := nativeStage(st, res)
		if err != nil {
			return nil, err
		}
		stages = append(stages, ns)
	}
	if res.Template.Audit && res.Template.Ports != "" && opt.Audit != nil {
		deps := []string{StagePortscan}
		if res.Template.CPEMatch {
			deps = append(deps, StageCPEMatch) // banner guesses must exist before the audit can supersede them
		}
		stages = append(stages, auditStage(st, opt.Audit, deps))
	}
	return stages, nil
}

func planSweep(chunk uint64) orchestrator.PlanFunc {
	return func(_ context.Context, sc store.Scan) ([]store.JobSpec, error) {
		prefixes, err := parsePrefixes(sc.Targets)
		if err != nil {
			return nil, err
		}
		return specs("nmap", prefixes, chunk)
	}
}

func planPortscan(st *store.Store, chunk uint64) orchestrator.PlanFunc {
	return func(ctx context.Context, sc store.Scan) ([]store.JobSpec, error) {
		live, err := st.LiveHosts(ctx, sc.ID)
		if err != nil {
			return nil, err
		}
		prefixes, err := parsePrefixes(live)
		if err != nil {
			return nil, err
		}
		return specs("nmap", prefixes, chunk)
	}
}

func specs(engine string, prefixes []netip.Prefix, chunk uint64) ([]store.JobSpec, error) {
	chunks, err := orchestrator.ChunkTargets(prefixes, chunk)
	if err != nil {
		return nil, err
	}
	out := make([]store.JobSpec, len(chunks))
	for i, c := range chunks {
		out[i] = store.JobSpec{Engine: engine, ChunkKey: fmt.Sprintf("%05d", i), Targets: c}
	}
	return out, nil
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("bad target %q", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// handleNmap returns a handler that runs Nmap for a job and ingests its XML.
// Partial XML from a killed scan is still ingested before the failure is
// reported, so retries only add to what was learned.
func handleNmap(st *store.Store, timeout time.Duration, xmlName string, build func(store.Job, string) ([]string, error), nopt nmap.Opts) orchestrator.Handler {
	return func(ctx context.Context, job store.Job) error {
		dir := job.RawDir
		if dir == "" {
			return orchestrator.Permanent(errors.New("job has no raw output directory"))
		}
		xmlPath := filepath.Join(dir, xmlName)
		_ = os.Remove(xmlPath) // never ingest a stale file from a previous attempt

		args, err := build(job, xmlPath)
		if err != nil {
			return orchestrator.Permanent(err)
		}
		tool, argv := nmap.Command(nopt, args)
		_, runErr := runner.Run(ctx, runner.Spec{
			Tool: tool, Args: argv, Timeout: timeout,
			StdoutFile: filepath.Join(dir, "nmap.stdout"), MaxStdout: 256 << 20,
		})
		if errors.Is(runErr, berr.ErrToolMissing) {
			return orchestrator.Permanent(runErr)
		}
		if runErr != nil && nopt.Privilege == nmap.PrivSudo && sudoNeedsPassword(runErr) {
			return orchestrator.Permanent(fmt.Errorf("sudo requires a password; run `sudo -v` first or configure passwordless sudo for nmap: %w", runErr))
		}

		found, ingestErr := ingestXML(ctx, st, job.ScanID, xmlPath)
		if runErr != nil {
			return runErr
		}
		if !found {
			return errors.New("nmap finished but wrote no XML output")
		}
		return ingestErr
	}
}

func sudoNeedsPassword(err error) bool {
	var tf *berr.ToolFailed
	return errors.As(err, &tf) && strings.Contains(strings.ToLower(tf.StderrTail), "password")
}

// ingestXML parses and stores a result file. found is false when the file does
// not exist.
func ingestXML(ctx context.Context, st *store.Store, scanID int64, path string) (found bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	_, err = nmap.Parse(f, func(h model.Host) error { return st.IngestHost(ctx, scanID, h) })
	return true, err
}
