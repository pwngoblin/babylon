-- Feed bookkeeping for conditional downloads and resumable syncs.
ALTER TABLE feed_state ADD COLUMN etag TEXT;
ALTER TABLE feed_state ADD COLUMN last_modified TEXT;
ALTER TABLE feed_state ADD COLUMN detail TEXT;

-- Product/version a version-derived finding is about; the key for root-cause grouping.
ALTER TABLE finding ADD COLUMN product TEXT;
ALTER TABLE finding ADD COLUMN version TEXT;

CREATE INDEX idx_cpe_cve ON cpe_match(cve_id);
CREATE INDEX idx_osv_alias ON osv_alias(alias);
CREATE INDEX idx_finding_group ON finding(asset_id, port, product, version);
