package dbaudit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
)

// Creds are database credentials. They live in memory for the scan and are never stored.
type Creds struct {
	User, Password, Label string
	Database              string // PostgreSQL database to connect to (default postgres)
	// AllowPlaintext lets the audit connect without TLS when the server has none.
	// Off by default: the password would cross the network unencrypted.
	AllowPlaintext bool
}

// Statements run by the collectors. All are SELECT or SHOW; the connection is
// opened read-only as well, and a test asserts that nothing else can be added.
var (
	pgStatements = []string{
		`SELECT current_setting('server_version')`,
		`SELECT name, setting FROM pg_settings WHERE name IN ('ssl','password_encryption','listen_addresses','log_connections','log_disconnections','fsync','ssl_min_protocol_version','shared_preload_libraries')`,
		`SELECT rolname, rolsuper, rolcanlogin FROM pg_roles`,
		`SELECT rolname, rolpassword IS NULL FROM pg_authid`,
		`SELECT type, array_to_string(database, ','), array_to_string(user_name, ','), COALESCE(address,''), COALESCE(netmask,''), auth_method FROM pg_hba_file_rules WHERE error IS NULL`,
	}
	myStatements = []string{
		`SELECT VERSION()`,
		`SHOW GLOBAL VARIABLES`,
		`SELECT User, Host, COALESCE(plugin,''), (COALESCE(authentication_string,'')='') AS nopw, Super_priv, COALESCE(account_locked,'N') FROM mysql.user`,
		`SELECT User, Host, COALESCE(plugin,''), (COALESCE(authentication_string,'')='') AS nopw, Super_priv, 'N' FROM mysql.user`,
	}
)

// Statements lists every SQL statement the collectors can run.
func Statements() []string { return append(append([]string{}, pgStatements...), myStatements...) }

// Collect connects to one database server and gathers facts. A failure of an
// individual query is recorded in Facts.Errors (rules that need it report
// unknown); only a failure to connect or authenticate is returned as an error.
func Collect(ctx context.Context, engine, host string, port int, c Creds) (*Facts, error) {
	var f *Facts
	var err error
	switch engine {
	case Postgres:
		f, err = collectPG(ctx, host, port, c)
	case MySQL:
		f, err = collectMySQL(ctx, host, port, c)
	default:
		return nil, fmt.Errorf("unsupported database engine %q", engine)
	}
	if err != nil {
		return nil, errors.New(Sanitize(err.Error(), c))
	}
	return f, nil
}

// Sanitize removes credentials from an error message before it is stored.
func Sanitize(msg string, c Creds) string {
	if c.Password != "" {
		msg = strings.ReplaceAll(msg, c.Password, "***")
	}
	return msg
}

const plaintextHint = "the server does not support TLS, so the audit refused to send credentials unencrypted (use --db-allow-plaintext to accept that on a trusted network)"

func collectPG(ctx context.Context, host string, port int, c Creds) (*Facts, error) {
	dbname := c.Database
	if dbname == "" {
		dbname = "postgres"
	}
	open := func(sslmode string) (*sql.DB, error) {
		u := url.URL{Scheme: "postgres", User: url.UserPassword(c.User, c.Password), Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: "/" + dbname}
		q := url.Values{"sslmode": {sslmode}, "connect_timeout": {"10"}, "application_name": {"babylon-audit"}}
		u.RawQuery = q.Encode()
		conn, err := pq.NewConnector(u.String())
		if err != nil {
			return nil, err
		}
		return sql.OpenDB(conn), nil
	}
	encrypted := true
	db, err := open("require")
	if err == nil {
		if err = db.PingContext(ctx); err != nil && strings.Contains(err.Error(), "SSL is not enabled") {
			db.Close()
			if !c.AllowPlaintext {
				return nil, errors.New(plaintextHint)
			}
			encrypted = false
			if db, err = open("disable"); err == nil {
				err = db.PingContext(ctx)
			}
		}
	}
	if err != nil {
		if db != nil {
			db.Close()
		}
		return nil, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	f := &Facts{Engine: Postgres, Encrypted: encrypted, Settings: map[string]string{}}
	if err := tx.QueryRowContext(ctx, pgStatements[0]).Scan(&f.Version); err != nil {
		return nil, fmt.Errorf("reading the server version: %w", err)
	}
	pgRows(ctx, f, tx, "settings", pgStatements[1], func(r *sql.Rows) error {
		var n, v string
		if err := r.Scan(&n, &v); err != nil {
			return err
		}
		f.Settings[strings.ToLower(n)] = v
		return nil
	})
	idx := map[string]int{}
	pgRows(ctx, f, tx, "roles", pgStatements[2], func(r *sql.Rows) error {
		var a Account
		if err := r.Scan(&a.Name, &a.Super, &a.CanLogin); err != nil {
			return err
		}
		idx[a.Name] = len(f.Accounts)
		f.Accounts = append(f.Accounts, a)
		return nil
	})
	pgRows(ctx, f, tx, "roles-password", pgStatements[3], func(r *sql.Rows) error {
		var n string
		var np bool
		if err := r.Scan(&n, &np); err != nil {
			return err
		}
		if i, ok := idx[n]; ok {
			v := np
			f.Accounts[i].NoPassword = &v
		}
		return nil
	})
	if ok := pgRows(ctx, f, tx, "hba", pgStatements[4], func(r *sql.Rows) error {
		var h HBARule
		var addr, mask string
		if err := r.Scan(&h.Type, &h.Database, &h.User, &addr, &mask, &h.Method); err != nil {
			return err
		}
		h.Address = hbaAddress(addr, mask)
		f.HBA = append(f.HBA, h)
		return nil
	}); ok {
		f.HBAKnown = true
	}
	return f, nil
}

// A failed query inside a PostgreSQL transaction aborts the whole transaction,
// so each optional query runs in its own savepoint.
func pgRows(ctx context.Context, f *Facts, tx *sql.Tx, what, query string, each func(*sql.Rows) error) bool {
	if _, err := tx.ExecContext(ctx, "SAVEPOINT q"); err != nil {
		f.Errors = append(f.Errors, what+": "+err.Error())
		return false
	}
	rows, err := tx.QueryContext(ctx, query)
	if err == nil {
		for rows.Next() {
			if err = each(rows); err != nil {
				break
			}
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
	}
	if err != nil {
		_, _ = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT q")
		f.Errors = append(f.Errors, what+": "+err.Error())
		return false
	}
	_, _ = tx.ExecContext(ctx, "RELEASE SAVEPOINT q")
	return true
}

// hbaAddress renders a pg_hba address and netmask the way pg_hba.conf writes them.
func hbaAddress(addr, mask string) string {
	switch {
	case addr == "":
		return ""
	case (addr == "0.0.0.0" && mask == "0.0.0.0") || (addr == "::" && mask == "::"):
		return addr + "/0"
	case mask != "" && mask != "255.255.255.255" && mask != "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff":
		return addr + "/" + mask
	}
	return addr
}

func collectMySQL(ctx context.Context, host string, port int, c Creds) (*Facts, error) {
	open := func(tlsMode string) (*sql.DB, error) {
		cfg := mysql.NewConfig()
		cfg.User, cfg.Passwd, cfg.Net = c.User, c.Password, "tcp"
		cfg.Addr = net.JoinHostPort(host, strconv.Itoa(port))
		cfg.TLSConfig = tlsMode
		cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 10*time.Second, 30*time.Second, 30*time.Second
		cfg.AllowNativePasswords = true
		conn, err := mysql.NewConnector(cfg)
		if err != nil {
			return nil, err
		}
		return sql.OpenDB(conn), nil
	}
	encrypted := true
	db, err := open("skip-verify") // encrypt without verifying: the audit identifies the server by address
	if err == nil {
		if err = db.PingContext(ctx); err != nil && errors.Is(err, mysql.ErrNoTLS) {
			db.Close()
			if !c.AllowPlaintext {
				return nil, errors.New(plaintextHint)
			}
			encrypted = false
			if db, err = open("false"); err == nil {
				err = db.PingContext(ctx)
			}
		}
	}
	if err != nil {
		if db != nil {
			db.Close()
		}
		return nil, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	f := &Facts{Engine: MySQL, Encrypted: encrypted, Settings: map[string]string{}}
	if err := tx.QueryRowContext(ctx, myStatements[0]).Scan(&f.Version); err != nil {
		return nil, fmt.Errorf("reading the server version: %w", err)
	}
	if rows, err := tx.QueryContext(ctx, myStatements[1]); err != nil {
		f.Errors = append(f.Errors, "variables: "+err.Error())
	} else {
		for rows.Next() {
			var n, v string
			if rows.Scan(&n, &v) == nil {
				f.Settings[strings.ToLower(n)] = v
			}
		}
		rows.Close()
	}
	var rows *sql.Rows
	for _, q := range myStatements[2:] { // the first form needs account_locked (MySQL 5.7.6+); the second works on older servers
		if rows, err = tx.QueryContext(ctx, q); err == nil {
			break
		}
	}
	if err != nil {
		f.Errors = append(f.Errors, "accounts: "+err.Error())
		return f, nil
	}
	for rows.Next() {
		var a Account
		var nopw int
		var super, locked string
		if err := rows.Scan(&a.Name, &a.Host, &a.AuthPlugin, &nopw, &super, &locked); err != nil {
			f.Errors = append(f.Errors, "accounts: "+err.Error())
			break
		}
		np := nopw == 1
		a.NoPassword, a.Super, a.Locked = &np, strings.EqualFold(super, "Y"), strings.EqualFold(locked, "Y")
		f.Accounts = append(f.Accounts, a)
	}
	rows.Close()
	return f, nil
}
