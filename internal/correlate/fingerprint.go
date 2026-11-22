// Package correlate normalizes, identifies and de-duplicates findings across engines.
package correlate

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// Fingerprint returns a stable identity for a finding. When CVEs are known the
// identity is the CVE set, so the same vulnerability reported by different
// engines (Nuclei template, version matcher, credentialed audit) collapses to
// one finding. Otherwise the engine-specific check key is used.
func Fingerprint(address string, port int, proto string, cves []string, checkKey string) string {
	id := "chk:" + checkKey
	if len(cves) > 0 {
		c := make([]string, len(cves))
		for i, v := range cves {
			c[i] = strings.ToUpper(strings.TrimSpace(v))
		}
		sort.Strings(c)
		id = "cve:" + strings.Join(c, ",")
	}
	sum := sha256.Sum256([]byte(address + "|" + strconv.Itoa(port) + "|" + proto + "|" + id))
	return hex.EncodeToString(sum[:16])
}

// canonical maps engine-specific check identities to one shared key, so the
// same non-CVE issue found by several engines becomes one finding.
var canonical = map[string]string{
	"native:redis-unauth":             "redis-unauthenticated",
	"nuclei:exposed-redis":            "redis-unauthenticated",
	"nuclei:redis-unauth":             "redis-unauthenticated",
	"native:ftp-anon":                 "ftp-anonymous-login",
	"nuclei:ftp-anonymous-login":      "ftp-anonymous-login",
	"native:http-trace":               "http-trace-enabled",
	"nuclei:http-trace":               "http-trace-enabled",
	"native:memcached-open":           "memcached-unauthenticated",
	"nuclei:memcached-stats":          "memcached-unauthenticated",
	"native:mongodb-open":             "mongodb-unauthenticated",
	"nuclei:mongodb-unauth":           "mongodb-unauthenticated",
	"native:smb-signing":              "smb-signing-not-required",
	"nuclei:smb-signing-not-required": "smb-signing-not-required",
}

// CheckKey returns the identity key for an engine's check, mapped to a shared
// canonical key when several engines are known to report the same issue.
func CheckKey(engine, ref string) string {
	k := engine + ":" + ref
	if c, ok := canonical[k]; ok {
		return c
	}
	return k
}
