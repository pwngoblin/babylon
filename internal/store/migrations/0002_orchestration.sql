-- Orchestration support: stage planning markers and retry backoff.

-- A stage is "planned" once its jobs have been created (possibly zero jobs).
-- Planning is idempotent, so resume never duplicates work.
CREATE TABLE scan_stage (
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  stage TEXT NOT NULL,
  planned_at TEXT NOT NULL,
  PRIMARY KEY(scan_id, stage)
);

-- Earliest time a queued job may be claimed (retry backoff). NULL = now.
ALTER TABLE scan_job ADD COLUMN not_before TEXT;
