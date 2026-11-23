package pkgver

import "testing"

func TestCompare(t *testing.T) {
	type tc struct {
		scheme, a, b string
		want         int
	}
	cases := []tc{
		// Debian: examples from Debian policy and dpkg's own test suite.
		{"deb", "1.0", "1.0", 0},
		{"deb", "1.0-1", "1.0-2", -1},
		{"deb", "1:0.9", "2.0", 1},    // epoch wins
		{"deb", "1.0~rc1", "1.0", -1}, // tilde sorts before end
		{"deb", "1.0~rc1", "1.0~rc2", -1},
		{"deb", "1.0~~", "1.0~", -1},
		{"deb", "1.0", "1.0+dfsg", -1},                        // + sorts after end
		{"deb", "1.0a", "1.0+", -1},                           // letters before non-letters
		{"deb", "3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.15", -1}, // numeric, not lexical
		{"deb", "3.0.2-0ubuntu1.9", "3.0.2-0ubuntu1.10", -1},
		{"deb", "1.2.3-1ubuntu0.1", "1.2.3-1", 1},
		{"deb", "2.36-9+deb12u4", "2.36-9+deb12u10", -1},
		{"deb", "0:1.0", "1.0", 0}, // absent epoch is 0
		{"deb", "1.0-0", "1.0", 0}, // hmm: revision 0 == empty
		{"deb", "7.6p1-4ubuntu0.7", "7.6p1-4ubuntu0.5", 1},
		// RPM: rpmvercmp test vectors.
		{"rpm", "1.0", "1.0", 0},
		{"rpm", "1.0", "2.0", -1},
		{"rpm", "2.0.1", "2.0", 1},
		{"rpm", "5.5p1", "5.5p2", -1},
		{"rpm", "1.0a", "1.0", 1},
		{"rpm", "10xyz", "10.1xyz", -1},
		{"rpm", "xyz10", "xyz10.1", -1},
		{"rpm", "1.0~rc1", "1.0", -1},
		{"rpm", "1.0~rc1", "1.0~rc2", -1},
		{"rpm", "1.0^git1", "1.0", 1},
		{"rpm", "1.0^git1", "1.0.1", -1},
		{"rpm", "1.0^", "1.0", 1},
		{"rpm", "1.0-1.el9", "1.0-2.el9", -1},
		{"rpm", "1:1.0-1", "2.0-1", 1},
		{"rpm", "3.0.7-27.el9", "3.0.7-27.el9_0.2", -1},
		{"rpm", "1.0", "1.0.0", -1},
		{"rpm", "a", "1", -1}, // numeric newer than alpha
		{"rpm", "0010", "10", 0},
		// Alpine.
		{"apk", "1.0", "1.0", 0},
		{"apk", "1.1.1k-r0", "1.1.1l-r0", -1},
		{"apk", "3.0.2-r0", "3.0.2-r1", -1},
		{"apk", "3.0.2-r9", "3.0.2-r10", -1},
		{"apk", "1.0_rc1", "1.0", -1},
		{"apk", "1.0_alpha", "1.0_beta", -1},
		{"apk", "1.0_p1", "1.0", 1},
		{"apk", "1.0_rc1", "1.0_rc2", -1},
		{"apk", "1.2", "1.10", -1},
		{"apk", "1.2", "1.2.1", -1},
		{"apk", "9.4_p1-r0", "9.5_p1-r0", -1},
	}
	for _, c := range cases {
		got, ok := Compare(c.scheme, c.a, c.b)
		if !ok {
			t.Fatalf("scheme %s unknown", c.scheme)
		}
		if got != c.want {
			t.Errorf("%s %q vs %q = %d, want %d", c.scheme, c.a, c.b, got, c.want)
		}
		if rev, _ := Compare(c.scheme, c.b, c.a); rev != -c.want {
			t.Errorf("%s antisymmetry %q vs %q = %d, want %d", c.scheme, c.b, c.a, rev, -c.want)
		}
	}
	if _, ok := Compare("nope", "1", "1"); ok {
		t.Error("unknown scheme must report !ok")
	}
}
