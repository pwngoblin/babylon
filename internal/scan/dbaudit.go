package scan

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"babylon/internal/audit"
	"babylon/internal/correlate"
	"babylon/internal/dbaudit"
	"babylon/internal/model"
	"babylon/internal/orchestrator"
	"babylon/internal/store"
)

const (
	StageDBAudit = "dbaudit"

	checkPGAudit    = "pg-audit"
	checkMySQLAudit = "mysql-audit"

	familyDBConfig = "Database configuration"
)

// DBAuditConfig carries in-memory database credentials. Never persisted.
type DBAuditConfig struct {
	Creds dbaudit.Creds
	// Collect gathers facts; nil uses the real collectors. Tests inject a fake.
	Collect func(ctx context.Context, engine, host string, port int, c dbaudit.Creds) (*dbaudit.Facts, error)
}

func (c *DBAuditConfig) collect(ctx context.Context, engine, host string, port int) (*dbaudit.Facts, error) {
	if c.Collect != nil {
		return c.Collect(ctx, engine, host, port, c.Creds)
	}
	return dbaudit.Collect(ctx, engine, host, port, c.Creds)
}

// dbEngine maps an Nmap service name to a supported database engine.
func dbEngine(s store.ServiceInfo) string {
	switch strings.ToLower(s.Name) {
	case "postgresql", "postgres":
		return dbaudit.Postgres
	case "mysql", "mariadb":
		return dbaudit.MySQL
	}
	return ""
}

func dbCheckID(engine string) string {
	if engine == dbaudit.Postgres {
		return checkPGAudit
	}
	return checkMySQLAudit
}

// dbAuditStage audits PostgreSQL and MySQL/MariaDB servers found by the port
// scan, using one credential set, read-only.
func dbAuditStage(st *store.Store, cfg *DBAuditConfig, deps []string) orchestrator.Stage {
	return orchestrator.Stage{
		Name:      StageDBAudit,
		Class:     ClassNative,
		DependsOn: deps,
		Plan: func(ctx context.Context, sc store.Scan) ([]store.JobSpec, error) {
			svcs, err := st.OpenServices(ctx, sc.ID)
			if err != nil {
				return nil, err
			}
			var targets []string
			for _, s := range svcs {
				if s.Proto == "tcp" && dbEngine(s) != "" {
					targets = append(targets, fmt.Sprintf("%s|%d|%s", s.Address, s.Port, dbEngine(s)))
				}
			}
			return chunkSpecs(targets, 2, "dbaudit", nil), nil
		},
		Handle: func(ctx context.Context, job store.Job) error {
			bg := context.WithoutCancel(ctx)
			for _, t := range job.Targets {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				parts := strings.Split(t, "|")
				if len(parts) != 3 {
					continue
				}
				port, _ := strconv.Atoi(parts[1])
				hctx, cancel := context.WithTimeout(ctx, auditHostTO)
				err := dbAuditOne(hctx, bg, st, cfg, job.ScanID, parts[0], port, parts[2])
				cancel()
				if err != nil {
					return fmt.Errorf("auditing %s:%d: %w", parts[0], port, err)
				}
			}
			return nil
		},
	}
}

func dbAuditOne(ctx, bg context.Context, st *store.Store, cfg *DBAuditConfig, scanID int64, addr string, port int, engine string) error {
	assetID, err := st.AssetID(bg, addr)
	if err != nil {
		return err
	}
	check := dbCheckID(engine)
	facts, err := cfg.collect(ctx, engine, addr, port)
	if err != nil {
		return st.RecordCheckRun(bg, scanID, assetID, check, "error", fmt.Sprintf("port %d: %s", port, dbaudit.Sanitize(err.Error(), cfg.Creds)))
	}
	_ = st.SetKB(bg, scanID, assetID, fmt.Sprintf("audit.db.%d", port), map[string]any{
		"label": cfg.Creds.Label, "user": cfg.Creds.User, "engine": engine, "version": facts.Version, "tls": facts.Encrypted}, "dbaudit")
	if err := st.RecordCheckRun(bg, scanID, assetID, check, "ran", strings.Join(facts.Errors, "; ")); err != nil {
		return err
	}
	for _, r := range dbaudit.RulesFor(engine) {
		res := r.Eval(facts)
		switch res.Status {
		case audit.Unknown:
			if err := st.RecordCheckRun(bg, scanID, assetID, r.ID, "skipped", res.Reason); err != nil {
				return err
			}
			continue
		case audit.Fail:
			if err := st.RecordFinding(bg, scanID, dbRuleFinding(addr, port, r, res)); err != nil {
				return err
			}
		}
		if err := st.RecordCheckRun(bg, scanID, assetID, r.ID, "ran", ""); err != nil {
			return err
		}
	}
	return nil
}

func dbRuleFinding(addr string, port int, r dbaudit.Rule, res audit.Result) model.Finding {
	return model.Finding{
		Fingerprint: correlate.Fingerprint(addr, port, "tcp", nil, "dbaudit:"+r.ID),
		Address:     addr, Port: port, Proto: "tcp", Title: r.Title, Family: familyDBConfig, Severity: r.Severity,
		Synopsis: r.Synopsis, Remediation: res.Remediation,
		Confidence: model.ConfConfirmed, Detection: "config", Engine: "dbaudit", EngineRef: r.ID,
		Evidence: res.Evidence,
	}
}
