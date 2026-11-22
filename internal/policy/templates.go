package policy

import "fmt"

// Template names match Nessus scan templates.
const (
	TemplateHostDiscovery = "host_discovery"
	TemplateBasic         = "basic"
	TemplateFullUnauth    = "full_unauth"
	TemplateCredentialed  = "credentialed"
)

// Flags are the explicit, user-supplied opt-ins.
type Flags struct {
	AllowActive       bool // probe-level native checks (Full template only)
	CheckDefaultCreds bool // Nuclei default-login templates
}

// Template is declarative scan intent. It contains no argv and no tool strings
// beyond curated names.
type Template struct {
	Name          string
	RequiresCreds bool
	Ports         string // "" = none, "top1000", "all"
	UDPTop        int    // 0 = no UDP
	ServiceDetect bool
	OSDetect      bool
	TLSAudit      bool
	NSE           bool
	Nuclei        bool
	Native        bool
	NativeMax     Safety
	CPEMatch      bool
	Audit         bool // credentialed collectors
	MaxRatePPS    int
	Concurrency   int
}

var templates = map[string]Template{
	TemplateHostDiscovery: {Name: TemplateHostDiscovery, MaxRatePPS: 300, Concurrency: 64},
	TemplateBasic: {
		Name: TemplateBasic, Ports: "top1000", ServiceDetect: true, TLSAudit: true, NSE: true,
		Nuclei: true, Native: true, NativeMax: SafetyReadOnly, CPEMatch: true, MaxRatePPS: 500, Concurrency: 32,
	},
	TemplateFullUnauth: {
		Name: TemplateFullUnauth, Ports: "all", UDPTop: 100, ServiceDetect: true, OSDetect: true, TLSAudit: true,
		NSE: true, Nuclei: true, Native: true, NativeMax: SafetyReadOnly, CPEMatch: true, MaxRatePPS: 300, Concurrency: 16,
	},
	TemplateCredentialed: {
		Name: TemplateCredentialed, RequiresCreds: true, Ports: "top1000", ServiceDetect: true, TLSAudit: true,
		NSE: true, Nuclei: true, Native: true, NativeMax: SafetyReadOnly, CPEMatch: true, Audit: true,
		MaxRatePPS: 500, Concurrency: 32,
	},
}

// Resolved is the validated, per-engine configuration for one scan.
type Resolved struct {
	Template Template
	NSE      NSEConfig
	Nuclei   NucleiConfig
	Native   NativeConfig
	Flags    Flags
}

// Resolve expands a template and flags into engine configs, then validates them.
func Resolve(name string, f Flags) (*Resolved, error) {
	t, ok := templates[name]
	if !ok {
		return nil, fmt.Errorf("unknown template %q", name)
	}
	if f.AllowActive && name != TemplateFullUnauth {
		return nil, fmt.Errorf("--allow-active is only valid with the %s template", TemplateFullUnauth)
	}

	r := &Resolved{Template: t, Flags: f}

	if t.NSE {
		r.NSE = NSEConfig{Categories: append([]string(nil), baseNSECategories...), Scripts: vulnNSEScripts}
	}
	if t.Nuclei {
		r.Nuclei = NucleiConfig{
			Enabled:          true,
			ExcludeTags:      append([]string(nil), DeniedNucleiTags...),
			ExcludeProtocols: append([]string(nil), DeniedNucleiProtocols...),
			IncludeDefault:   f.CheckDefaultCreds,
		}
		if !f.CheckDefaultCreds {
			r.Nuclei.ExcludeTags = append(r.Nuclei.ExcludeTags, DefaultLoginTags...)
		}
	}
	if t.Native {
		max := t.NativeMax
		if f.AllowActive {
			max = SafetyProbe
		}
		r.Native = NativeConfig{Enabled: true, MaxSafety: max}
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate runs every engine config check.
func (r *Resolved) Validate() error {
	if err := r.NSE.Validate(); err != nil {
		return err
	}
	if err := r.Nuclei.Validate(); err != nil {
		return err
	}
	return r.Native.Validate()
}

// TemplateNames lists built-in templates (stable order).
func TemplateNames() []string {
	return []string{TemplateHostDiscovery, TemplateBasic, TemplateFullUnauth, TemplateCredentialed}
}
