// Package pkgver compares package versions using each packaging system's own
// rules. These differ from upstream semver in ways that matter: Debian epochs
// and tildes, RPM's rpmvercmp and carets, and Alpine's suffix ordering. A wrong
// answer here is a false positive or a missed CVE, so the rules are kept
// literal and table-tested.
package pkgver

import (
	"strconv"
	"strings"
)

// Compare returns -1, 0 or 1 for a<b, a==b, a>b under the named scheme
// ("deb", "rpm" or "apk"). ok is false for an unknown scheme.
func Compare(scheme, a, b string) (int, bool) {
	switch scheme {
	case "deb":
		return Deb(a, b), true
	case "rpm":
		return RPM(a, b), true
	case "apk":
		return APK(a, b), true
	}
	return 0, false
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// ---------- Debian (dpkg) ----------

func splitDeb(v string) (epoch int, upstream, rev string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if e, err := strconv.Atoi(v[:i]); err == nil {
			epoch = e
			v = v[i+1:]
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// Deb compares Debian/Ubuntu versions: epoch, then upstream, then revision.
func Deb(a, b string) int {
	ea, ua, ra := splitDeb(a)
	eb, ub, rb := splitDeb(b)
	if ea != eb {
		return sign(ea - eb)
	}
	if c := debPart(ua, ub); c != 0 {
		return c
	}
	return debPart(ra, rb)
}

func debOrder(c byte, end bool) int {
	switch {
	case end:
		return 0
	case c == '~':
		return -1
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func debPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// non-digit prefix
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ca, cb byte
			ea, eb := i >= len(a) || isDigit(a[i]), j >= len(b) || isDigit(b[j])
			if !ea {
				ca = a[i]
			}
			if !eb {
				cb = b[j]
			}
			if oa, ob := debOrder(ca, ea), debOrder(cb, eb); oa != ob {
				return sign(oa - ob)
			}
			if !ea {
				i++
			}
			if !eb {
				j++
			}
		}
		// digit run
		si := i
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		sj := j
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := cmpNumStr(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	return 0
}

// cmpNumStr compares digit strings of any length without overflow.
func cmpNumStr(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return sign(strings.Compare(a, b))
}

// ---------- RPM ----------

func splitRPM(v string) (epoch int, ver, rel string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if e, err := strconv.Atoi(v[:i]); err == nil {
			epoch = e
			v = v[i+1:]
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// RPM compares "[epoch:]version-release" strings.
func RPM(a, b string) int {
	ea, va, ra := splitRPM(a)
	eb, vb, rb := splitRPM(b)
	if ea != eb {
		return sign(ea - eb)
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	return rpmvercmp(ra, rb)
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// rpmvercmp follows rpm's lib/rpmvercmp.c, including ~ and ^.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		// tilde sorts before everything, even the end
		ta, tb := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if ta || tb {
			if !ta {
				return 1
			}
			if !tb {
				return -1
			}
			i++
			j++
			continue
		}
		// caret sorts after the end but before anything else
		ca, cb := i < len(a) && a[i] == '^', j < len(b) && b[j] == '^'
		if ca || cb {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if !ca {
				return 1
			}
			if !cb {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		var numeric bool
		if isDigit(a[i]) {
			numeric = true
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		sa, sb := a[si:i], b[sj:j]
		if sb == "" { // segments of different type: numeric is newer
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			if c := cmpNumStr(sa, sb); c != 0 {
				return c
			}
		} else if c := strings.Compare(sa, sb); c != 0 {
			return sign(c)
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	}
	return 1
}

// ---------- Alpine (apk) ----------

var apkSuffixRank = map[string]int{
	"alpha": -4, "beta": -3, "pre": -2, "rc": -1,
	"cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5,
}

type apkVer struct {
	nums   []string
	letter string
	suf    []apkSuf
	rev    string
}

type apkSuf struct {
	rank int
	num  string
}

func parseAPK(v string) apkVer {
	v = strings.TrimSpace(v)
	var r apkVer
	if i := strings.LastIndex(v, "-r"); i >= 0 {
		r.rev = v[i+2:]
		v = v[:i]
	}
	parts := strings.Split(v, "_")
	main := parts[0]
	for _, s := range parts[1:] {
		k := 0
		for k < len(s) && isAlpha(s[k]) {
			k++
		}
		r.suf = append(r.suf, apkSuf{apkSuffixRank[s[:k]], s[k:]})
	}
	if n := len(main); n > 0 && isAlpha(main[n-1]) {
		r.letter = main[n-1:]
		main = main[:n-1]
	}
	r.nums = strings.Split(main, ".")
	return r
}

// APK compares Alpine package versions (1.2.3a_rc1_p2-r4).
func APK(a, b string) int {
	x, y := parseAPK(a), parseAPK(b)
	for i := 0; i < len(x.nums) || i < len(y.nums); i++ {
		var sa, sb string
		if i < len(x.nums) {
			sa = x.nums[i]
		}
		if i < len(y.nums) {
			sb = y.nums[i]
		}
		if sa == "" || sb == "" { // a missing component is older than a present one
			if sa == sb {
				continue
			}
			if sa == "" {
				return -1
			}
			return 1
		}
		if c := cmpNumStr(sa, sb); c != 0 {
			return c
		}
	}
	if c := strings.Compare(x.letter, y.letter); c != 0 {
		return sign(c)
	}
	for i := 0; i < len(x.suf) || i < len(y.suf); i++ {
		var sa, sb apkSuf
		if i < len(x.suf) {
			sa = x.suf[i]
		}
		if i < len(y.suf) {
			sb = y.suf[i]
		}
		if sa.rank != sb.rank {
			return sign(sa.rank - sb.rank)
		}
		if c := cmpNumStr(sa.num, sb.num); c != 0 {
			return c
		}
	}
	return cmpNumStr(x.rev, y.rev)
}
