-- Recurring scans. The request is stored as JSON (never credentials: those are
-- supplied per scan from the environment and cannot be scheduled).
CREATE TABLE schedule (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    request_json  TEXT NOT NULL,
    interval_min  INTEGER NOT NULL CHECK (interval_min >= 15),
    enabled       INTEGER NOT NULL DEFAULT 1,
    next_run      INTEGER NOT NULL,        -- unix seconds
    last_run      INTEGER,
    last_scan_id  INTEGER,
    last_error    TEXT,
    created_at    INTEGER NOT NULL
);
