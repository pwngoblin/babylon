-- Babylon's own index of Nuclei template metadata (like a Nessus plugin
-- database). Scans select exact template files from here instead of letting
-- Nuclei scan a 14k-file directory, and safety rules are enforced on this
-- metadata, not just on command-line flags.
CREATE TABLE nuclei_template (
  path TEXT PRIMARY KEY,                 -- relative to the templates root
  id TEXT NOT NULL,
  name TEXT,
  severity TEXT NOT NULL DEFAULT 'info',
  protocols TEXT NOT NULL CHECK(json_valid(protocols)),   -- ["http","tcp",...]
  tags TEXT NOT NULL CHECK(json_valid(tags)),
  cves TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(cves)),
  cvss REAL,
  vendor TEXT, product TEXT,
  verified INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_nt_id ON nuclei_template(id);
