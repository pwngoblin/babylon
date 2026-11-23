package scan

import (
	"babylon/internal/intel"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"babylon/internal/engines/nuclei"
	berr "babylon/internal/errors"
	"babylon/internal/orchestrator"
	"babylon/internal/policy"
	"babylon/internal/runner"
	"babylon/internal/store"
)

const (
	StageNucleiDetect = "nuclei-detect"
	StageNucleiScan   = "nuclei-scan"
	ClassNuclei       = "nuclei"

	nucleiTargetsPerJob = 50
	detectTargetsPerJob = 100
)

// nucleiRuntime holds what both Nuclei stages share.
type nucleiRuntime struct {
	st      *store.Store
	res     *policy.Resolved
	dir     string // templates root
	profile nuclei.Profile
	rate    int
	timeout time.Duration

	once sync.Once
	ix   *nuclei.Index
	err  error
}

func newNucleiRuntime(st *store.Store, res *policy.Resolved, opt Options) *nucleiRuntime {
	prof := nuclei.ProfileFor(res.Template.Name)
	prof.AllSafe = res.Flags.Deep
	return &nucleiRuntime{st: st, res: res, dir: opt.NucleiDir, profile: prof,
		rate: opt.NucleiRate, timeout: opt.NucleiTimeout}
}

// index loads the template index once per process, applying the safety filter.
func (n *nucleiRuntime) index(ctx context.Context) (*nuclei.Index, error) {
	n.once.Do(func() {
		tpls, err := n.st.LoadNucleiIndex(context.WithoutCancel(ctx))
		if err != nil {
			n.err = err
			return
		}
		n.ix = nuclei.NewIndex(tpls, n.res.Nuclei)
	})
	return n.ix, n.err
}

func (n *nucleiRuntime) stages() []orchestrator.Stage {
	return []orchestrator.Stage{
		{Name: StageNucleiDetect, Class: ClassNuclei, DependsOn: []string{StagePortscan}, Plan: n.planDetect, Handle: n.handleDetect},
		{Name: StageNucleiScan, Class: ClassNuclei, DependsOn: []string{StageNucleiDetect}, Plan: n.planScan, Handle: n.handleScan},
	}
}

// ---- classification of services ----

func isHTTP(s store.ServiceInfo) bool {
	name := strings.ToLower(s.Name)
	if strings.Contains(name, "http") {
		return true
	}
	p := strings.ToLower(s.Product)
	for _, k := range []string{"httpd", "nginx", "apache", "iis", "tomcat", "jetty", "lighttpd", "caddy", "gunicorn", "node.js", "express"} {
		if strings.Contains(p, k) {
			return true
		}
	}
	return false
}

// isHTTPCandidate also admits services Nmap could not identify: a read-only
// GET during the cheap detect phase is how Nessus-style service detection
// finds web servers on odd ports.
func isHTTPCandidate(s store.ServiceInfo) bool {
	if isHTTP(s) {
		return true
	}
	name := strings.ToLower(s.Name)
	return name == "unknown" || name == ""
}

func targetURL(s store.ServiceInfo) string {
	scheme := "http"
	if s.Tunnel == "ssl" || strings.HasPrefix(strings.ToLower(s.Name), "https") {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, hostLit(s.Address), s.Port)
}

func hostPort(s store.ServiceInfo) string { return fmt.Sprintf("%s:%d", hostLit(s.Address), s.Port) }

func hostLit(a string) string {
	if strings.Contains(a, ":") { // IPv6 literal
		return "[" + a + "]"
	}
	return a
}

func techKey(s store.ServiceInfo) string { return fmt.Sprintf("Web/%s:%d/tech", s.Address, s.Port) }

// ---- planning ----

func (n *nucleiRuntime) planDetect(ctx context.Context, sc store.Scan) ([]store.JobSpec, error) {
	ix, err := n.index(ctx)
	if err != nil {
		return nil, err
	}
	if ix.Len() == 0 {
		return nil, nil // no templates indexed: CLI warns; scan continues without Nuclei
	}
	svcs, err := n.st.OpenServices(ctx, sc.ID)
	if err != nil {
		return nil, err
	}
	var urls []string
	for _, s := range svcs {
		if s.Proto == "tcp" && isHTTPCandidate(s) {
			urls = append(urls, targetURL(s))
		}
	}
	return chunkSpecs(urls, detectTargetsPerJob, "detect", map[string]string{"phase": "detect"}), nil
}

type group struct {
	proto   string
	tokens  []string
	targets []string
}

func (n *nucleiRuntime) planScan(ctx context.Context, sc store.Scan) ([]store.JobSpec, error) {
	ix, err := n.index(ctx)
	if err != nil {
		return nil, err
	}
	if ix.Len() == 0 {
		return nil, nil
	}
	svcs, err := n.st.OpenServices(ctx, sc.ID)
	if err != nil {
		return nil, err
	}
	groups := map[string]*group{}
	for _, s := range svcs {
		if s.Proto != "tcp" {
			continue
		}
		tech, err := n.st.KBList(ctx, sc.ID, s.AssetID, techKey(s))
		if err != nil {
			return nil, err
		}
		tokens := nuclei.TokensForService(s.Name, s.Product, s.CPEs)
		g := &group{}
		switch {
		case isHTTP(s) || len(tech) > 0:
			g.proto, g.tokens = "http", union(tokens, tech)
			g.targets = []string{targetURL(s)}
		case len(tokens) > 0:
			g.proto, g.tokens = "net", tokens
			g.targets = []string{hostPort(s)}
		default:
			_ = n.st.RecordCheckRun(ctx, sc.ID, s.AssetID, fmt.Sprintf("nuclei:%d/%s", s.Port, s.Proto), "skipped", "service not identified; no technology to select templates by")
			continue
		}
		if len(ix.ForTokens(g.proto, g.tokens, n.profile)) == 0 {
			_ = n.st.RecordCheckRun(ctx, sc.ID, s.AssetID, fmt.Sprintf("nuclei:%d/%s", s.Port, s.Proto), "skipped", "no applicable templates for "+strings.Join(g.tokens, ","))
			continue
		}
		key := g.proto + "|" + strings.Join(g.tokens, ",")
		if ex, ok := groups[key]; ok {
			ex.targets = append(ex.targets, g.targets...)
		} else {
			groups[key] = g
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var specs []store.JobSpec
	for _, k := range keys {
		g := groups[k]
		params := map[string]string{"phase": "scan", "proto": g.proto, "tokens": strings.Join(g.tokens, ",")}
		specs = append(specs, chunkSpecs(g.targets, nucleiTargetsPerJob, g.proto+"-"+hash8(k), params)...)
	}
	return specs, nil
}

func chunkSpecs(targets []string, per int, keyPrefix string, params map[string]string) []store.JobSpec {
	var out []store.JobSpec
	for i := 0; i < len(targets); i += per {
		end := i + per
		if end > len(targets) {
			end = len(targets)
		}
		out = append(out, store.JobSpec{
			Engine: "nuclei", ChunkKey: fmt.Sprintf("%s-%03d", keyPrefix, i/per),
			Targets: targets[i:end], Params: params,
		})
	}
	return out
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{a, b} {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

func hash8(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:4])
}

// ---- execution ----

func (n *nucleiRuntime) handleDetect(ctx context.Context, job store.Job) error {
	ix, err := n.index(ctx)
	if err != nil {
		return orchestrator.Permanent(err)
	}
	tpls := ix.Detect(n.profile)
	return n.run(ctx, job, tpls, true)
}

func (n *nucleiRuntime) handleScan(ctx context.Context, job store.Job) error {
	ix, err := n.index(ctx)
	if err != nil {
		return orchestrator.Permanent(err)
	}
	tokens := strings.Split(job.Params["tokens"], ",")
	tpls := ix.ForTokens(job.Params["proto"], tokens, n.profile)
	return n.run(ctx, job, tpls, false)
}

// run executes Nuclei over the job's targets with exactly the given templates,
// recording every result. detect=true also feeds technologies to the KB.
func (n *nucleiRuntime) run(ctx context.Context, job store.Job, tpls []string, detect bool) error {
	if len(tpls) == 0 || len(job.Targets) == 0 {
		return nil
	}
	if job.RawDir == "" {
		return orchestrator.Permanent(errors.New("job has no raw output directory"))
	}
	root, err := filepath.Abs(n.dir)
	if err != nil {
		return orchestrator.Permanent(err)
	}
	var tl strings.Builder
	for _, rel := range tpls {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if !strings.HasPrefix(abs, root+string(os.PathSeparator)) { // defence against a poisoned index
			return orchestrator.Permanent(fmt.Errorf("template path escapes templates root: %q", rel))
		}
		tl.WriteString(abs + "\n")
	}
	tfile := filepath.Join(job.RawDir, "templates.txt")
	gfile := filepath.Join(job.RawDir, "targets.txt")
	if err := os.WriteFile(tfile, []byte(tl.String()), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(gfile, []byte(strings.Join(job.Targets, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	args, err := nuclei.Args(n.res.Nuclei, gfile, tfile, n.rate)
	if err != nil {
		return orchestrator.Permanent(err)
	}
	raw, err := os.OpenFile(filepath.Join(job.RawDir, "results.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer raw.Close()
	rawRef := filepath.Join("jobs", filepath.Base(job.RawDir), "results.jsonl")

	bg := context.WithoutCancel(ctx)
	var parseErrs int
	_, runErr := runner.Run(ctx, runner.Spec{
		Tool: "nuclei", Args: args, Timeout: n.timeout, MaxStdout: 1 << 30,
		OnLine: func(line []byte) error {
			if len(line) == 0 || line[0] != '{' {
				return nil
			}
			raw.Write(line)
			raw.Write([]byte{'\n'})
			res, err := nuclei.ParseLine(line, rawRef)
			if err != nil {
				parseErrs++
				return nil
			}
			if err := n.st.RecordFinding(bg, job.ScanID, res.Finding); err != nil {
				return err
			}
			if cpe := n.versionCPE(ctx, res); cpe != "" {
				aid, err := n.st.AssetID(bg, res.Finding.Address)
				if err != nil {
					return err
				}
				if err := n.st.MergeKBList(bg, job.ScanID, aid, webCPEKey(res.HostPort), []string{cpe}, "nuclei"); err != nil {
					return err
				}
			}
			if detect {
				if toks := nuclei.TechTokens(res.Tags); len(toks) > 0 {
					aid, err := n.st.AssetID(bg, res.Finding.Address)
					if err != nil {
						return err
					}
					key := "Web/" + res.HostPort + "/tech"
					if err := n.st.MergeKBList(bg, job.ScanID, aid, key, toks, "nuclei"); err != nil {
						return err
					}
				}
			}
			return nil
		},
	})
	if errors.Is(runErr, berr.ErrToolMissing) {
		return orchestrator.Permanent(runErr)
	}
	return runErr
}

// webCPEKey is the knowledge-base key holding product CPEs (with versions)
// learned from web responses on one "ip:port".
func webCPEKey(hostPort string) string { return "Web/" + hostPort + "/cpe" }

var versionLike = regexp.MustCompile(`^v?(\d+(?:\.\d+){1,3}(?:[-_.]?(?:p|rc|beta|alpha)?\d+)?[a-z]?)$`)

// versionCPE turns a detection result into a CPE 2.3 string when the template
// extracted a version and names the product (via its own CPE or index
// metadata). The result feeds the same CVE matcher as Nmap's service versions,
// so web applications, frameworks and servers are covered, not just daemons.
func (n *nucleiRuntime) versionCPE(ctx context.Context, res nuclei.Result) string {
	var ver string
	for _, e := range res.Extracted {
		if m := versionLike.FindStringSubmatch(strings.TrimSpace(e)); m != nil {
			ver = m[1]
			break
		}
	}
	if ver == "" {
		return ""
	}
	vendor, product := "", ""
	if c, ok := intel.ParseCPE(res.CPE); ok {
		vendor, product = c.Vendor, c.Product
	}
	if product == "" {
		if ix, err := n.index(ctx); err == nil {
			vendor, product = ix.VendorProduct(res.TemplateID)
		}
	}
	if vendor == "" || product == "" || !productNamed(product, res.TemplateID+" "+res.Finding.Title) {
		return ""
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, ver)
}

// productNamed guards against template metadata that names an unrelated
// product: the CPE product must appear in the template's own id or title.
func productNamed(product, text string) bool {
	norm := func(s string) string {
		return strings.NewReplacer("_", "", "-", "", " ", "", ".", "").Replace(strings.ToLower(s))
	}
	return strings.Contains(norm(text), norm(product))
}
