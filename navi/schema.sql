CREATE TABLE IF NOT EXISTS cf_schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cf_scans (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    started TIMESTAMPTZ NOT NULL,
    finished TIMESTAMPTZ NOT NULL,
    report JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS cf_issues (
    project TEXT NOT NULL,
    id TEXT NOT NULL,
    first_scan TEXT NOT NULL REFERENCES cf_scans(id),
    last_scan TEXT NOT NULL REFERENCES cf_scans(id),
    PRIMARY KEY(project, id)
);
CREATE TABLE IF NOT EXISTS cf_occurrences (
    scan_id TEXT NOT NULL REFERENCES cf_scans(id) ON DELETE CASCADE,
    issue_id TEXT NOT NULL,
    issue JSONB NOT NULL,
    PRIMARY KEY(scan_id, issue_id)
);
CREATE INDEX IF NOT EXISTS cf_scans_project ON cf_scans(project, started DESC);
INSERT INTO cf_schema_version(version) VALUES (1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS cf_experiments (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    created TIMESTAMPTZ NOT NULL,
    evidence JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS cf_experiments_project ON cf_experiments(project, created DESC);
INSERT INTO cf_schema_version(version) VALUES (2) ON CONFLICT DO NOTHING;
