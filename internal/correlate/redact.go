package correlate

import (
	"regexp"
	"strings"
)

// MaxEvidence is the largest evidence string stored per finding occurrence.
const MaxEvidence = 4096

var redactors = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?im)^(\s*(?:proxy-)?authorization\s*:\s*).*$`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?im)^(\s*(?:set-)?cookie\s*:\s*).*$`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?im)^(\s*x-(?:api|auth)[\w-]*\s*:\s*).*$`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)\b((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|auth)\s*[=:]\s*)[^\s&"',;]+`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`), "[REDACTED PRIVATE KEY]"},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "[REDACTED AWS KEY]"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b`), "[REDACTED JWT]"},
}

// Redact removes likely secrets from evidence and caps its size. Evidence is
// attacker-influenced (it is data from the scanned host) and ends up in reports,
// so it is also stripped of control characters other than newline and tab.
func Redact(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' && r != '\r' {
			return '?'
		}
		return r
	}, s)
	for _, r := range redactors {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return Truncate(s, MaxEvidence)
}

// Truncate cuts s to max bytes on a rune boundary, marking the cut.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "\n…[truncated]"
}
