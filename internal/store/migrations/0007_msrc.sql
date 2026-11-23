-- Microsoft Security Response Center fixes: for each Windows build and CVE, the
-- update revision (UBR) that fixes it. A host is missing the fix when its UBR is lower.
CREATE TABLE msrc_fix (
    os_build   TEXT NOT NULL,      -- e.g. 10.0.19045
    cve        TEXT NOT NULL,
    fixed_ubr  INTEGER NOT NULL,
    kb         TEXT,
    title      TEXT,
    cvss       REAL,
    severity   TEXT,
    PRIMARY KEY (os_build, cve)
) WITHOUT ROWID;
