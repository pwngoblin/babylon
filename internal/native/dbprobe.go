package native

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"

	"babylon/internal/store"
)

// Database exposure probes. MySQL speaks first, so we only read its greeting;
// PostgreSQL gets the standard 8-byte SSLRequest (what psql sends first) and
// answers with one byte. No login is attempted on either.

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

type dbRelease struct {
	prefix string
	name   string
	eol    time.Time
}

// Vendor lifecycle end dates for the major lines still seen in the wild.
// Treated as "firm", not "confirmed": distributions may backport fixes.
var mysqlReleases = []dbRelease{
	{"5.5.", "MySQL 5.5", day(2018, 12, 31)}, {"5.6.", "MySQL 5.6", day(2021, 2, 28)},
	{"5.7.", "MySQL 5.7", day(2023, 10, 31)}, {"8.0.", "MySQL 8.0", day(2026, 4, 30)},
}
var mariadbReleases = []dbRelease{
	{"5.5.", "MariaDB 5.5", day(2020, 4, 11)}, {"10.0.", "MariaDB 10.0", day(2019, 3, 31)},
	{"10.1.", "MariaDB 10.1", day(2020, 10, 17)}, {"10.2.", "MariaDB 10.2", day(2022, 5, 23)},
	{"10.3.", "MariaDB 10.3", day(2023, 5, 25)}, {"10.4.", "MariaDB 10.4", day(2024, 6, 18)},
	{"10.5.", "MariaDB 10.5", day(2025, 6, 24)}, {"10.6.", "MariaDB 10.6", day(2026, 7, 6)},
}

// ParseMySQLGreeting reads a server handshake: version string and whether the
// server advertises TLS (CLIENT_SSL, 0x0800).
func ParseMySQLGreeting(b []byte) (version string, ssl bool, ok bool) {
	if len(b) < 5+1 || b[4] != 10 { // 3-byte length, sequence, protocol version 10
		return "", false, false
	}
	rest := b[5:]
	i := bytes.IndexByte(rest, 0)
	if i <= 0 || len(rest) < i+1+4+8+1+2 {
		return "", false, false
	}
	version = string(rest[:i])
	caps := rest[i+1+4+8+1:]
	capLow := int(caps[0]) | int(caps[1])<<8
	return version, capLow&0x0800 != 0, true
}

var mariaRe = regexp.MustCompile(`(?i)mariadb`)

func mysqlRelease(version string) *dbRelease {
	v := version
	list := mysqlReleases
	if mariaRe.MatchString(v) {
		list = mariadbReleases
		v = strings.TrimPrefix(v, "5.5.5-") // MariaDB prefixes a fake 5.5.5- for compatibility
	}
	for i := range list {
		if strings.HasPrefix(v, list[i].prefix) {
			return &list[i]
		}
	}
	return nil
}

func mysqlFindings(version string, ssl bool, now time.Time) []Finding {
	var out []Finding
	if rel := mysqlRelease(version); rel != nil && rel.eol.Before(now) {
		out = append(out, Finding{Title: "Unsupported Database Version: " + rel.name, Severity: "high",
			Synopsis:    "The database server runs a release line that no longer receives security fixes.",
			Description: fmt.Sprintf("%s reached end of life on %s. Vulnerabilities found since are not fixed in this line (distribution packages may still carry backports).", rel.name, rel.eol.Format("2006-01-02")),
			Remediation: "Upgrade to a supported release.", Evidence: "server version: " + version, Detection: "version", Confidence: "firm"})
	}
	if !ssl {
		out = append(out, Finding{Title: "MySQL Server Does Not Offer TLS", Severity: "low",
			Synopsis:    "The server does not advertise TLS support during the handshake.",
			Description: "Queries, results and credential exchanges travel unencrypted; a network observer can read data.",
			Remediation: "Configure ssl_cert/ssl_key (or enable the automatic TLS in 5.7+/MariaDB 10.4+) and require TLS for remote accounts.",
			Evidence:    "handshake capabilities lack CLIENT_SSL (server version " + version + ")"})
	}
	return out
}

func mysqlRun(e *Env, s store.ServiceInfo) []Finding {
	b, err := tcpExchange(e.Address, s.Port, nil, 512, func(b []byte) bool { return len(b) >= 60 })
	if err != nil {
		return nil
	}
	ver, ssl, ok := ParseMySQLGreeting(b)
	if !ok {
		return nil
	}
	return mysqlFindings(ver, ssl, e.Now)
}

var mysqlProbe = tcpMulti("mysql-probe", "MySQL/MariaDB handshake probe", []int{3306}, mysqlRun)

// pgSSLRequest is the fixed SSLRequest startup packet (length 8, code 80877103).
var pgSSLRequest = []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}

func postgresRun(e *Env, s store.ServiceInfo) []Finding {
	b, err := tcpExchange(e.Address, s.Port, pgSSLRequest, 1, func(b []byte) bool { return len(b) >= 1 })
	if err != nil || len(b) < 1 || b[0] != 'N' { // 'S' = TLS available; anything else is not a Postgres answer we understand
		return nil
	}
	return []Finding{{Title: "PostgreSQL Server Does Not Offer TLS", Severity: "low",
		Synopsis:    "The server answered the TLS request with 'N' (no TLS).",
		Description: "Queries, results and password exchanges travel unencrypted; a network observer can read data.",
		Remediation: "Enable ssl = on with a certificate and key, and use hostssl rules in pg_hba.conf for remote clients.",
		Evidence:    "SSLRequest -> 'N'"}}
}

var postgresProbe = tcpMulti("postgres-tls-probe", "PostgreSQL TLS support probe", []int{5432}, postgresRun)

// tcpMulti is tcpCheck for probes that can return several findings.
func tcpMulti(id, name string, ports []int, run func(e *Env, s store.ServiceInfo) []Finding) Check {
	c := tcpCheck(id, name, ports, func(*Env, store.ServiceInfo) *Finding { return nil })
	c.Run = func(e *Env) []Finding {
		var out []Finding
		for _, s := range openPort(e, ports) {
			for _, f := range run(e, s) {
				f.Port, f.Proto = s.Port, "tcp"
				out = append(out, f)
			}
		}
		return out
	}
	return c
}
