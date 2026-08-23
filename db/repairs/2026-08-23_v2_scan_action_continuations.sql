-- Append-only two-phase action-plan authority for discovery-derived work.

BEGIN;

ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS scan_continuation_allocation_json JSONB;
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS scan_continuation_allocation_digest TEXT;
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS scan_continuation_applied_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS scan_action_plan_revisions (
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    plan_digest CHAR(64) NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
    parent_plan_digest CHAR(64),
    continuation_allocation_digest CHAR(64),
    plan_json JSONB NOT NULL CHECK (jsonb_typeof(plan_json) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scan_id, revision),
    UNIQUE (scan_id, plan_digest)
);

CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_action_continuations_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;
