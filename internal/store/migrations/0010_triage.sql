-- Triage decisions on findings. Findings are identified by a fingerprint that is
-- stable across scans, so a decision carries over until it expires.
CREATE TABLE triage (
  finding_id INTEGER PRIMARY KEY REFERENCES finding(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('accepted_risk','false_positive')),
  reason TEXT NOT NULL CHECK(length(trim(reason)) > 0),
  created_at TEXT NOT NULL,
  expires_at TEXT,
  CHECK(status = 'false_positive' OR expires_at IS NOT NULL)
);
