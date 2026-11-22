package store

import "testing"

func TestOpenAndMigrate(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != 2 {
		t.Fatalf("user_version = %d, err = %v", v, err)
	}
	var fk int
	db.QueryRow("PRAGMA foreign_keys").Scan(&fk)
	if fk != 1 {
		t.Fatal("foreign keys not enabled")
	}

	// Constraint checks: invalid status and invalid JSON are rejected.
	if _, err := db.Exec(`INSERT INTO scan(template,targets_json,options_json,status) VALUES('basic','[]','{}','bogus')`); err == nil {
		t.Fatal("expected CHECK violation for status")
	}
	if _, err := db.Exec(`INSERT INTO scan(template,targets_json,options_json,status) VALUES('basic','not json','{}','pending')`); err == nil {
		t.Fatal("expected CHECK violation for json")
	}
	if _, err := db.Exec(`INSERT INTO scan(template,targets_json,options_json,status) VALUES('basic','[]','{}','pending')`); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := migrate(db); err != nil {
		t.Fatalf("second migrate failed: %v", err)
	}
}
