// Package matcher maps detected service versions to known CVEs using the local
// NVD index, with explicit confidence rules for distribution backports.
package matcher

import (
	"strings"
	"unicode"
)

type tokKind int

const (
	tokNum  tokKind = iota
	tokPre          // alpha, beta, rc, ... : sorts before the plain release
	tokPost         // p1, sp2, patch, letter suffixes (1.0.2k): sorts after it
)

type tok struct {
	kind tokKind
	num  string // digits without leading zeros (tokNum)
	word string // lower-case letters (tokPre/tokPost)
}

var preWords = map[string]bool{
	"alpha": true, "beta": true, "rc": true, "pre": true, "preview": true, "dev": true, "snapshot": true, "milestone": true, "cr": true,
}

// ambiguous single/double letters are pre-release only when followed by a
// number ("1.0a1", "2.0b2"), otherwise a patch letter ("1.0.2a", "8.4p1").
var ambiguousPre = map[string]bool{"a": true, "b": true, "m": true}

func tokenize(v string) []tok {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "v")
	var raw []tok
	i := 0
	for i < len(v) {
		c := rune(v[i])
		switch {
		case unicode.IsDigit(c):
			j := i
			for j < len(v) && unicode.IsDigit(rune(v[j])) {
				j++
			}
			n := strings.TrimLeft(v[i:j], "0")
			if n == "" {
				n = "0"
			}
			raw = append(raw, tok{kind: tokNum, num: n})
			i = j
		case unicode.IsLetter(c):
			j := i
			for j < len(v) && unicode.IsLetter(rune(v[j])) {
				j++
			}
			raw = append(raw, tok{kind: tokPost, word: v[i:j]})
			i = j
		default:
			i++
		}
	}
	for k := range raw {
		if raw[k].kind != tokPost {
			continue
		}
		w := raw[k].word
		followedByNum := k+1 < len(raw) && raw[k+1].kind == tokNum
		if preWords[w] || (ambiguousPre[w] && followedByNum) {
			raw[k].kind = tokPre
		}
	}
	return raw
}

func cmpNum(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// Compare orders two upstream version strings: -1 if a<b, 0 if equal, 1 if a>b.
// It handles dotted numbers, pre-release markers (1.0rc1 < 1.0), patch levels
// (8.4p1 > 8.4) and letter suffixes (1.0.2k). Distribution revisions are not
// understood here: unauthenticated matching only ever sees upstream versions.
func Compare(a, b string) int {
	x, y := tokenize(a), tokenize(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		switch {
		case i >= len(x):
			if y[i].kind == tokPre {
				return 1
			}
			return -1
		case i >= len(y):
			if x[i].kind == tokPre {
				return -1
			}
			return 1
		}
		p, q := x[i], y[i]
		if p.kind == tokNum && q.kind == tokNum {
			if c := cmpNum(p.num, q.num); c != 0 {
				return c
			}
			continue
		}
		if p.kind != tokNum && q.kind != tokNum {
			if p.kind != q.kind {
				if p.kind == tokPre {
					return -1
				}
				return 1
			}
			if c := strings.Compare(p.word, q.word); c != 0 {
				return c
			}
			continue
		}
		// number vs word: pre-release words sort below numbers, other words too
		if p.kind == tokNum {
			return 1
		}
		return -1
	}
	return 0
}

// CleanVersion extracts the upstream version from an Nmap version string such
// as "8.9p1 Ubuntu 3ubuntu0.1" or "2.4.49 ((Unix))" (first token starting with a digit).
func CleanVersion(s string) string {
	for _, f := range strings.Fields(s) {
		f = strings.Trim(f, "()[],;")
		if f != "" && f[0] >= '0' && f[0] <= '9' {
			return f
		}
	}
	return ""
}
