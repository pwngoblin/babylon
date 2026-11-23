package dbaudit

import (
	"fmt"
	"strings"

	"babylon/internal/audit"
)

// Rule is a database hardening check evaluated purely against collected facts.
type Rule struct {
	ID       string
	Title    string
	Severity string // info | low | medium | high | critical
	Synopsis string
	Engine   string // Postgres or MySQL
	Eval     func(*Facts) audit.Result
}

func unknown(why string) audit.Result { return audit.Result{Status: audit.Unknown, Reason: why} }

func pass(ev string) audit.Result { return audit.Result{Status: audit.Pass, Evidence: ev} }

func fail(ev, fix string) audit.Result {
	return audit.Result{Status: audit.Fail, Evidence: ev, Remediation: fix}
}

func lacks(f *Facts, what string) bool {
	for _, e := range f.Errors {
		if strings.HasPrefix(e, what) {
			return true
		}
	}
	return false
}

// Rules are the built-in database checks.
var Rules = []Rule{
	{ID: "PG-001", Engine: Postgres, Title: "PostgreSQL does not offer TLS", Severity: "medium",
		Synopsis: "The server has ssl turned off, so every client connection, including passwords, crosses the network unencrypted.", Eval: pgSSL},
	{ID: "PG-002", Engine: Postgres, Title: "PostgreSQL stores passwords with MD5", Severity: "medium",
		Synopsis: "password_encryption is md5, which is weak and allows pass-the-hash.", Eval: pgPasswordEncryption},
	{ID: "PG-003", Engine: Postgres, Title: "pg_hba.conf allows remote connections without a password (trust)", Severity: "high",
		Synopsis: "A trust rule for remote clients lets them connect as any allowed user without authenticating.", Eval: pgTrust},
	{ID: "PG-008", Engine: Postgres, Title: "pg_hba.conf trusts local connections", Severity: "low",
		Synopsis: "A trust rule for the local socket or loopback lets any local user act as any database user.", Eval: pgLocalTrust},
	{ID: "PG-004", Engine: Postgres, Title: "pg_hba.conf accepts connections from any address", Severity: "medium",
		Synopsis: "A remote rule covers every IPv4 or IPv6 address.", Eval: pgAnyAddress},
	{ID: "PG-005", Engine: Postgres, Title: "More superuser accounts than necessary", Severity: "medium",
		Synopsis: "Login roles other than the bootstrap account have superuser rights.", Eval: pgSuperusers},
	{ID: "PG-006", Engine: Postgres, Title: "Connection logging is off", Severity: "low",
		Synopsis: "log_connections or log_disconnections is off, so access cannot be reconstructed.", Eval: pgLogging},
	{ID: "PG-007", Engine: Postgres, Title: "Login roles without a password", Severity: "medium",
		Synopsis: "Some login roles have no password set.", Eval: pgNoPassword},
	{ID: "MY-001", Engine: MySQL, Title: "MySQL/MariaDB has TLS disabled", Severity: "medium",
		Synopsis: "The server was started without TLS support, so client traffic, including passwords, is unencrypted.", Eval: myTLS},
	{ID: "MY-002", Engine: MySQL, Title: "Anonymous accounts exist", Severity: "high",
		Synopsis: "An account with an empty user name lets anyone connect.", Eval: myAnonymous},
	{ID: "MY-003", Engine: MySQL, Title: "Accounts with an empty password", Severity: "high",
		Synopsis: "Some accounts authenticate with no password.", Eval: myNoPassword},
	{ID: "MY-004", Engine: MySQL, Title: "Privileged accounts can log in from any host", Severity: "high",
		Synopsis: "An account with the SUPER privilege accepts connections from remote hosts.", Eval: myRemoteSuper},
	{ID: "MY-005", Engine: MySQL, Title: "LOAD DATA LOCAL INFILE is enabled", Severity: "medium",
		Synopsis: "local_infile lets a malicious server read files from clients, and widens injection impact.", Eval: myLocalInfile},
	{ID: "MY-006", Engine: MySQL, Title: "File import and export is not restricted", Severity: "medium",
		Synopsis: "secure_file_priv is empty, so users with FILE privilege can read and write anywhere the server can.", Eval: mySecureFilePriv},
	{ID: "MY-007", Engine: MySQL, Title: "General query log is on", Severity: "low",
		Synopsis: "The general log records every statement, including ones that contain passwords.", Eval: myGeneralLog},
}

// RulesFor returns the rules for an engine.
func RulesFor(engine string) []Rule {
	var out []Rule
	for _, r := range Rules {
		if r.Engine == engine {
			out = append(out, r)
		}
	}
	return out
}

// ---- PostgreSQL ----

func pgSSL(f *Facts) audit.Result {
	v, ok := f.Setting("ssl")
	if !ok {
		return unknown("the ssl setting could not be read")
	}
	if v == "on" {
		return pass("ssl = on")
	}
	return fail("ssl = "+v, "Set ssl = on in postgresql.conf with a server certificate and key, and use hostssl rules in pg_hba.conf.")
}

func pgPasswordEncryption(f *Facts) audit.Result {
	v, ok := f.Setting("password_encryption")
	if !ok {
		return unknown("the password_encryption setting could not be read")
	}
	if v == "md5" || v == "off" || v == "false" {
		return fail("password_encryption = "+v, "Set password_encryption = scram-sha-256 (PostgreSQL 10+), then reset every role's password so it is stored as SCRAM, and switch pg_hba methods from md5 to scram-sha-256.")
	}
	return pass("password_encryption = " + v)
}

func pgHBA(f *Facts) (bool, audit.Result) {
	if !f.HBAKnown {
		return false, unknown("pg_hba_file_rules is not readable (needs a superuser or pg_read_all_settings, PostgreSQL 10 or later)")
	}
	return true, audit.Result{}
}

func loopback(h HBARule) bool {
	if h.Type == "local" {
		return true
	}
	switch h.Address {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

func trustRules(f *Facts, remote bool) []string {
	var out []string
	for _, h := range f.HBA {
		if strings.EqualFold(h.Method, "trust") && loopback(h) != remote {
			out = append(out, fmt.Sprintf("%s %s %s %s trust", h.Type, h.Database, h.User, h.Address))
		}
	}
	return out
}

func pgTrust(f *Facts) audit.Result {
	if ok, r := pgHBA(f); !ok {
		return r
	}
	if bad := trustRules(f, true); len(bad) > 0 {
		return fail(strings.Join(bad, "\n"), "Replace trust with scram-sha-256 in pg_hba.conf and reload the server. A remote trust rule lets matching clients connect without a password.")
	}
	return pass("no trust rules for remote clients")
}

func pgLocalTrust(f *Facts) audit.Result {
	if ok, r := pgHBA(f); !ok {
		return r
	}
	if bad := trustRules(f, false); len(bad) > 0 {
		return fail(strings.Join(bad, "\n"), "Use peer (local sockets) or scram-sha-256 instead of trust, so any local user cannot become any database user.")
	}
	return pass("no trust rules for local connections")
}

func anyAddr(a string) bool {
	a = strings.TrimSpace(a)
	return a == "0.0.0.0/0" || a == "::/0" || a == "all" || strings.HasPrefix(a, "0.0.0.0 ") || a == "0.0.0.0"
}

func pgAnyAddress(f *Facts) audit.Result {
	if ok, r := pgHBA(f); !ok {
		return r
	}
	var bad []string
	for _, h := range f.HBA {
		if strings.HasPrefix(h.Type, "host") && anyAddr(h.Address) && !strings.EqualFold(h.Method, "reject") {
			bad = append(bad, fmt.Sprintf("%s %s %s %s %s", h.Type, h.Database, h.User, h.Address, h.Method))
		}
	}
	if len(bad) == 0 {
		return pass("no remote rule covers every address")
	}
	return fail(strings.Join(bad, "\n"), "Limit remote pg_hba.conf rules to the application and administration networks, and set listen_addresses to the interfaces that need it.")
}

func pgSuperusers(f *Facts) audit.Result {
	if len(f.Accounts) == 0 {
		return unknown("the role list could not be read")
	}
	var extra []string
	for _, a := range f.Accounts {
		if a.Super && a.CanLogin && a.Name != "postgres" {
			extra = append(extra, a.Name)
		}
	}
	if len(extra) == 0 {
		return pass("no superuser login roles besides postgres")
	}
	return fail("superuser login roles: "+strings.Join(extra, ", "), "Remove SUPERUSER from roles that do not need it (ALTER ROLE name NOSUPERUSER) and use narrower privileges or pg_monitor-style predefined roles.")
}

func pgLogging(f *Facts) audit.Result {
	c, ok1 := f.Setting("log_connections")
	d, ok2 := f.Setting("log_disconnections")
	if !ok1 || !ok2 {
		return unknown("logging settings could not be read")
	}
	if c == "on" && d == "on" {
		return pass("log_connections and log_disconnections are on")
	}
	return fail(fmt.Sprintf("log_connections = %s, log_disconnections = %s", c, d), "Set log_connections = on and log_disconnections = on in postgresql.conf.")
}

func pgNoPassword(f *Facts) audit.Result {
	if lacks(f, "roles-password") {
		return unknown("pg_authid is not readable by the audit account (needs a superuser)")
	}
	var bad []string
	seen := false
	for _, a := range f.Accounts {
		if a.NoPassword == nil || !a.CanLogin {
			continue
		}
		seen = true
		if *a.NoPassword {
			bad = append(bad, a.Name)
		}
	}
	if !seen {
		return unknown("password status is not visible to the audit account")
	}
	if len(bad) == 0 {
		return pass("every login role has a password")
	}
	return fail("login roles without a password: "+strings.Join(bad, ", "), "Set a password, or confirm these roles authenticate by peer or certificate only and are not reachable with trust or password rules.")
}

// ---- MySQL / MariaDB ----

func myTLS(f *Facts) audit.Result {
	v, ok := f.Setting("have_ssl")
	if !ok {
		v, ok = f.Setting("have_openssl")
	}
	if !ok {
		return unknown("have_ssl could not be read")
	}
	switch strings.ToUpper(v) {
	case "YES":
		return pass("have_ssl = YES")
	}
	return fail("have_ssl = "+v, "Configure ssl_cert, ssl_key and ssl_ca in the server, restart, and set require_secure_transport = ON (MySQL) or require TLS per account (REQUIRE SSL).")
}

func myNeedUsers(f *Facts) (audit.Result, bool) {
	if len(f.Accounts) == 0 {
		return unknown("mysql.user is not readable by the audit account"), false
	}
	return audit.Result{}, true
}

func myAnonymous(f *Facts) audit.Result {
	if r, ok := myNeedUsers(f); !ok {
		return r
	}
	var bad []string
	for _, a := range f.Accounts {
		if a.Name == "" && !a.Locked {
			bad = append(bad, "''@'"+a.Host+"'")
		}
	}
	if len(bad) == 0 {
		return pass("no anonymous accounts")
	}
	return fail("anonymous accounts: "+strings.Join(bad, ", "), "DROP USER the anonymous accounts (run mysql_secure_installation).")
}

// internalAccounts are created and locked by the server itself.
var internalAccounts = map[string]bool{"mariadb.sys": true, "mysql.sys": true, "mysql.session": true, "mysql.infoschema": true}

func myNoPassword(f *Facts) audit.Result {
	if r, ok := myNeedUsers(f); !ok {
		return r
	}
	var bad []string
	for _, a := range f.Accounts {
		if a.Locked || a.NoPassword == nil || !*a.NoPassword || internalAccounts[strings.ToLower(a.Name)] {
			continue
		}
		switch strings.ToLower(a.AuthPlugin) {
		case "unix_socket", "auth_socket", "mysql_no_login", "auth_pam", "authentication_pam", "gssapi", "named_pipe":
			continue // authenticates by something other than a stored password
		}
		bad = append(bad, fmt.Sprintf("'%s'@'%s'", a.Name, a.Host))
	}
	if len(bad) == 0 {
		return pass("every account has a password or an external authentication plugin")
	}
	return fail("accounts without a password: "+strings.Join(bad, ", "), "Set a password (ALTER USER ... IDENTIFIED BY ...) or lock the account (ALTER USER ... ACCOUNT LOCK).")
}

func localHost(h string) bool {
	switch strings.ToLower(h) {
	case "localhost", "127.0.0.1", "::1", "":
		return true
	}
	return false
}

func myRemoteSuper(f *Facts) audit.Result {
	if r, ok := myNeedUsers(f); !ok {
		return r
	}
	var bad []string
	for _, a := range f.Accounts {
		if a.Super && !a.Locked && !localHost(a.Host) {
			bad = append(bad, fmt.Sprintf("'%s'@'%s'", a.Name, a.Host))
		}
	}
	if len(bad) == 0 {
		return pass("privileged accounts are limited to local hosts")
	}
	return fail("privileged accounts reachable remotely: "+strings.Join(bad, ", "), "Restrict administrative accounts to localhost or a named administration host, and use a separate least-privilege account for applications.")
}

func myLocalInfile(f *Facts) audit.Result {
	v, ok := f.Setting("local_infile")
	if !ok {
		return unknown("local_infile could not be read")
	}
	if isOn(v) {
		return fail("local_infile = "+v, "Set local_infile = 0 in the server configuration.")
	}
	return pass("local_infile = " + v)
}

func isOn(v string) bool {
	switch strings.ToUpper(v) {
	case "ON", "1", "YES", "TRUE":
		return true
	}
	return false
}

func mySecureFilePriv(f *Facts) audit.Result {
	v, ok := f.Setting("secure_file_priv")
	if !ok {
		return unknown("secure_file_priv could not be read")
	}
	if strings.TrimSpace(v) == "" {
		return fail("secure_file_priv is empty", "Set secure_file_priv to a dedicated directory (or NULL to disable import and export).")
	}
	return pass("secure_file_priv = " + v)
}

func myGeneralLog(f *Facts) audit.Result {
	v, ok := f.Setting("general_log")
	if !ok {
		return unknown("general_log could not be read")
	}
	if isOn(v) {
		return fail("general_log = "+v, "Turn the general log off (SET GLOBAL general_log = OFF) outside of short troubleshooting windows.")
	}
	return pass("general_log = " + v)
}
