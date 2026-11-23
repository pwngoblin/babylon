package intel

import "strings"

// CPE is the part of a CPE name Babylon matches on.
type CPE struct {
	Part, Vendor, Product, Version, Update, TargetSW string
}

// ParseCPE accepts CPE 2.3 formatted strings ("cpe:2.3:a:v:p:1.0:...") and the
// 2.2 URI form Nmap emits ("cpe:/a:v:p:1.0"). Wildcards ("*", "-") are
// returned as empty strings.
func ParseCPE(s string) (CPE, bool) {
	var fields []string
	switch {
	case strings.HasPrefix(s, "cpe:2.3:"):
		fields = splitCPE(strings.TrimPrefix(s, "cpe:2.3:"))
		for len(fields) < 11 {
			fields = append(fields, "*")
		}
	case strings.HasPrefix(s, "cpe:/"):
		fields = splitCPE(strings.TrimPrefix(s, "cpe:/"))
		// 2.2 URI: part:vendor:product:version:update:edition:language
		for len(fields) < 11 {
			fields = append(fields, "*")
		}
		// map to 2.3 positions: part,vendor,product,version,update,edition,language,sw_edition,target_sw,...
		fields[7], fields[8] = "*", "*"
	default:
		return CPE{}, false
	}
	c := CPE{Part: fields[0], Vendor: norm(fields[1]), Product: norm(fields[2]), Version: norm(fields[3]), Update: norm(fields[4]), TargetSW: norm(fields[8])}
	if c.Part == "" || c.Vendor == "" || c.Product == "" {
		return CPE{}, false
	}
	return c, true
}

func norm(s string) string {
	if s == "*" || s == "-" {
		return ""
	}
	return strings.ToLower(unescapeCPE(s))
}

// splitCPE splits on unescaped colons.
func splitCPE(s string) []string {
	var out []string
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			b.WriteByte(s[i])
			b.WriteByte(s[i+1])
			i++
		case s[i] == ':':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteByte(s[i])
		}
	}
	return append(out, b.String())
}

func unescapeCPE(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
