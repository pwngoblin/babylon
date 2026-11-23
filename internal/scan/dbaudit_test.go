package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"babylon/internal/dbaudit"
	"babylon/internal/model"
	"babylon/internal/store"
)

func dbPort(n int, name string) model.Port {
	return model.Port{Number: n, Proto: "tcp", State: "open", Service: model.Service{Name: name}}
}

func TestDBAuditStageEndToEnd(t *testing.T) {
	st, id := cpeStore(t)
	ctx := context.Background()
	ingest(t, st, id, "10.0.0.9", "", dbPort(5432, "postgresql"), dbPort(3306, "mysql"), dbPort(80, "http"))
	var asked []string
	cfg := &DBAuditConfig{Creds: dbaudit.Creds{User: "audit", Password: "s3cretpw", Label: "lab"},
		Collect: func(_ context.Context, engine, host string, port int, _ dbaudit.Creds) (*dbaudit.Facts, error) {
			asked = append(asked, engine)
			if engine == dbaudit.MySQL {
				return nil, errors.New("access denied for user audit using password s3cretpw")
			}
			return &dbaudit.Facts{Engine: dbaudit.Postgres, Version: "11.16", Settings: map[string]string{
				"ssl": "off", "password_encryption": "scram-sha-256", "log_connections": "on", "log_disconnections": "on"}}, nil
		}}
	stage := dbAuditStage(st, cfg, nil)
	specs, err := stage.Plan(ctx, store.Scan{ID: id})
	if err != nil || len(specs) != 1 || len(specs[0].Targets) != 2 {
		t.Fatalf("plan must pick the two database services and not the web server: %+v %v", specs, err)
	}
	if err := stage.Handle(ctx, store.Job{ScanID: id, Targets: specs[0].Targets}); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.ListFindings(ctx, id, "")
	var titles []string
	for _, r := range rows {
		titles = append(titles, r.Title)
		if r.Port != 5432 || r.Family != familyDBConfig || r.Confidence != "confirmed" {
			t.Errorf("finding: %+v", r)
		}
	}
	if len(rows) != 1 || !strings.Contains(titles[0], "does not offer TLS") {
		t.Fatalf("want only the PG-001 finding: %v", titles)
	}
	runs, _ := st.ListCheckRuns(ctx, id)
	states := map[string]string{}
	for _, r := range runs {
		states[r.CheckID] = r.State + ":" + r.Reason
	}
	if !strings.HasPrefix(states["pg-audit"], "ran") || !strings.HasPrefix(states["PG-001"], "ran") {
		t.Errorf("runs: %v", states)
	}
	if !strings.HasPrefix(states["mysql-audit"], "error") {
		t.Errorf("a failed login must be recorded as an error: %v", states)
	}
	if strings.Contains(states["mysql-audit"], "s3cretpw") {
		t.Errorf("password leaked into the check run: %s", states["mysql-audit"])
	}
	// HBA was not collected: rules that need it must be skipped, not passed.
	if !strings.HasPrefix(states["PG-003"], "skipped") {
		t.Errorf("PG-003 should be skipped when pg_hba is unreadable: %v", states["PG-003"])
	}
}
