// Package nuclei wraps the Nuclei scanner: it indexes template metadata,
// selects exact templates per detected service, runs them, and maps results to
// Babylon findings.
package nuclei

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Meta is the indexed metadata of one template.
type Meta struct {
	Path      string // relative to the templates root, slash-separated
	ID        string
	Name      string
	Severity  string
	Protocols []string
	Tags      []string
	CVEs      []string
	CVSS      *float64
	Vendor    string
	Product   string
	Verified  bool
}

// protocolKeys maps top-level template keys to normalized protocol names.
var protocolKeys = map[string]string{
	"http": "http", "requests": "http", // "requests" is the legacy spelling
	"tcp": "tcp", "network": "tcp",
	"dns": "dns", "file": "file", "ssl": "ssl", "websocket": "websocket", "whois": "whois",
	"code": "code", "javascript": "javascript", "headless": "headless", // "flow" is a modifier on other protocols, not a protocol
	"workflows": "workflow",
}

// ParseTemplate extracts index metadata from one template's YAML.
func ParseTemplate(rel string, data []byte) (Meta, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Meta{}, err
	}
	m := Meta{Path: filepath.ToSlash(rel)}
	m.ID, _ = doc["id"].(string)
	info, _ := doc["info"].(map[string]any)
	m.Name, _ = info["name"].(string)
	m.Severity = strings.ToLower(str(info["severity"]))
	switch m.Severity {
	case "info", "low", "medium", "high", "critical":
	default:
		m.Severity = "info"
	}
	m.Tags = splitList(info["tags"])
	if cl, ok := info["classification"].(map[string]any); ok {
		for _, c := range splitList(cl["cve-id"]) {
			m.CVEs = append(m.CVEs, strings.ToUpper(c))
		}
		switch v := cl["cvss-score"].(type) {
		case float64:
			m.CVSS = &v
		case int:
			f := float64(v)
			m.CVSS = &f
		}
	}
	if md, ok := info["metadata"].(map[string]any); ok {
		m.Vendor = strings.ToLower(str(md["vendor"]))
		m.Product = strings.ToLower(str(md["product"]))
		m.Verified, _ = md["verified"].(bool)
	}
	seen := map[string]bool{}
	for k := range doc {
		if p, ok := protocolKeys[k]; ok && !seen[p] {
			seen[p] = true
			m.Protocols = append(m.Protocols, p)
		}
	}
	sort.Strings(m.Protocols)
	if m.ID == "" {
		return m, fmt.Errorf("template has no id")
	}
	return m, nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// splitList accepts "a, b" or ["a","b"] (templates use both).
func splitList(v any) []string {
	var out []string
	add := func(s string) {
		for _, p := range strings.Split(s, ",") {
			if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
				out = append(out, p)
			}
		}
	}
	switch t := v.(type) {
	case string:
		add(t)
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				add(s)
			}
		}
	}
	return out
}

// IndexDir walks a templates root and parses every .yaml template, calling fn
// per template. Unparseable files are counted and skipped, never fatal.
func IndexDir(root string, fn func(Meta)) (parsed, skipped int, err error) {
	// WalkDir does not follow a symlinked root (e.g. <home>/nuclei-templates
	// pointing at a checkout), so resolve it first.
	if resolved, rerr := filepath.EvalSymlinks(root); rerr == nil {
		root = resolved
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".github", "helpers", "profiles":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".yaml") || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			skipped++
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		m, perr := ParseTemplate(rel, data)
		if perr != nil || len(m.Protocols) == 0 {
			skipped++
			return nil
		}
		parsed++
		fn(m)
		return nil
	})
	return
}
