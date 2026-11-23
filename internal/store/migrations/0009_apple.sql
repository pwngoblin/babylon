-- Apple macOS security releases: which CVEs each release fixed, per macOS major line.
CREATE TABLE macos_release (
    major    INTEGER NOT NULL,      -- 26 for macOS Tahoe 26.x
    release  TEXT NOT NULL,         -- 26.7.3
    product  TEXT NOT NULL,         -- macOS Tahoe
    released TEXT,                  -- YYYY-MM-DD
    url      TEXT,
    PRIMARY KEY (major, release)
) WITHOUT ROWID;

CREATE TABLE macos_fix (
    major   INTEGER NOT NULL,
    release TEXT NOT NULL,          -- first release that fixed the CVE
    cve     TEXT NOT NULL,
    PRIMARY KEY (major, release, cve)
) WITHOUT ROWID;
CREATE INDEX idx_macos_fix_cve ON macos_fix(cve);
