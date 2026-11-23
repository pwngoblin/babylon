package pack

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"babylon/internal/native"
	"babylon/internal/policy"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Builtin returns the packs shipped inside the binary.
func Builtin() ([]Def, error) {
	entries, err := builtinFS.ReadDir("builtin")
	if err != nil {
		return nil, err
	}
	var out []Def
	for _, e := range entries {
		data, err := builtinFS.ReadFile("builtin/" + e.Name())
		if err != nil {
			return nil, err
		}
		defs, err := Parse(data, "builtin/"+e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, defs...)
	}
	return out, nil
}

// LoadDir reads every *.yaml and *.yml file in dir. A missing directory is not
// an error (most installs have none); a malformed file is, so a typo can never
// silently remove a check.
func LoadDir(dir string) ([]Def, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Def
	for _, e := range entries {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if e.IsDir() || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		defs, err := Parse(data, path)
		if err != nil {
			return nil, err
		}
		out = append(out, defs...)
	}
	return out, nil
}

// All returns built-in plus user packs with ids checked unique. userDir may be "".
func All(userDir string) ([]Def, error) {
	defs, err := Builtin()
	if err != nil {
		return nil, err
	}
	user, err := LoadDir(userDir)
	if err != nil {
		return nil, err
	}
	defs = append(defs, user...)
	seen := map[string]string{}
	for _, d := range defs {
		if prev, dup := seen[d.ID]; dup {
			return nil, fmt.Errorf("check id %s is defined twice (%s and %s)", d.ID, prev, d.source)
		}
		seen[d.ID] = d.source
	}
	sort.SliceStable(defs, func(i, j int) bool { return defs[i].ID < defs[j].ID })
	return defs, nil
}

// Checks compiles the packs that fit the allowed safety level. Probe checks are
// not even offered without --allow-active.
func Checks(userDir string, max policy.Safety) ([]native.Check, error) {
	defs, err := All(userDir)
	if err != nil {
		return nil, err
	}
	var out []native.Check
	for _, d := range defs {
		if c := Compile(d); c.Safety <= max {
			out = append(out, c)
		}
	}
	return out, nil
}
