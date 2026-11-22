-- Per-job parameters (e.g. the Nuclei tag set for a group of targets).
ALTER TABLE scan_job ADD COLUMN params_json TEXT CHECK(params_json IS NULL OR json_valid(params_json));

-- How a finding was derived: behaviour (verified by a probe/response), version
-- (inferred from a version string), config (read from configuration/state).
ALTER TABLE finding ADD COLUMN detection TEXT NOT NULL DEFAULT 'behaviour'
  CHECK(detection IN ('behaviour','version','config'));

-- Nessus-style per-host knowledge base: facts recorded by earlier stages and
-- read by later checks.
CREATE TABLE kb (
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES asset(id),
  key TEXT NOT NULL,
  value_json TEXT NOT NULL CHECK(json_valid(value_json)),
  source TEXT NOT NULL,
  PRIMARY KEY(scan_id, asset_id, key)
);

-- Coverage transparency: which checks ran, were skipped (and why) or errored.
CREATE TABLE check_run (
  scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES asset(id),
  check_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('ran','skipped','error')),
  reason TEXT,
  PRIMARY KEY(scan_id, asset_id, check_id)
);
