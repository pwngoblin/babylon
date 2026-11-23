// Package dbaudit audits database servers with read-only credentials: a
// collector gathers settings, accounts and (for PostgreSQL) host-based
// authentication rules with fixed SELECT/SHOW statements inside a read-only
// transaction, and pure rules judge the collected facts. Rules never touch the
// server, so they are testable without one.
package dbaudit

import "strings"

// Engines.
const (
	Postgres = "postgresql"
	MySQL    = "mysql" // also MariaDB
)

// Facts is what the collector learned about one database server.
type Facts struct {
	Engine    string
	Version   string
	Encrypted bool              // the audit connection itself used TLS
	Settings  map[string]string // lower-case setting name -> value
	Accounts  []Account
	HBA       []HBARule // PostgreSQL pg_hba rules, when readable
	HBAKnown  bool
	Errors    []string // queries that failed (usually missing privilege): rules that need them report unknown
}

// Account is a database login.
type Account struct {
	Name        string
	Host        string // MySQL only
	Super       bool
	CanLogin    bool  // PostgreSQL
	NoPassword  *bool // nil when not visible to the audit account
	AuthPlugin  string
	Locked      bool
	Description string
}

// HBARule is one pg_hba.conf line.
type HBARule struct {
	Type, Database, User, Address, Method string
}

// Setting returns a setting value (case-insensitive name) and whether it was collected.
func (f *Facts) Setting(name string) (string, bool) {
	v, ok := f.Settings[strings.ToLower(name)]
	return v, ok
}

// IsMariaDB reports whether a MySQL-family server is MariaDB.
func (f *Facts) IsMariaDB() bool { return strings.Contains(strings.ToLower(f.Version), "mariadb") }
