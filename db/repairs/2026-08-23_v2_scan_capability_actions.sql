-- Immutable action graph and durable scheduler index for canonical Scan V2.

BEGIN;

ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_action_plan_json JSONB;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_action_plan_digest TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_action_plan_schema TEXT;

CREATE TABLE IF NOT EXISTS scan_capability_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    action_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 512),
    capability_name TEXT NOT NULL,
    adapter_name TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    output_schema TEXT NOT NULL,
    action_digest CHAR(64) NOT NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    execution_plan_digest CHAR(64) NOT NULL CHECK (execution_plan_digest ~ '^[0-9a-f]{64}$'),
    target_binding_digest CHAR(64) NOT NULL CHECK (target_binding_digest ~ '^[0-9a-f]{64}$'),
    input_binding_digest CHAR(64) NOT NULL CHECK (input_binding_digest ~ '^[0-9a-f]{64}$'),
    requested_budget JSONB NOT NULL CHECK (jsonb_typeof(requested_budget) = 'object'),
    placement_json JSONB NOT NULL CHECK (jsonb_typeof(placement_json) = 'object'),
    dependencies_json JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(dependencies_json) = 'array'),
    required BOOLEAN NOT NULL,
    supporting BOOLEAN NOT NULL,
    status TEXT NOT NULL DEFAULT 'planned' CHECK (status IN (
        'planned','leased','running','success','partial','skipped','blocked',
        'failed','cancelled','timed_out'
    )),
    reason_code TEXT,
    reservation_id TEXT,
    receipt_id TEXT,
    receipt_hash CHAR(64),
    observation_manifest_id UUID,
    result_digest CHAR(64),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT scan_capability_actions_action_unique UNIQUE (scan_id, action_id),
    CONSTRAINT scan_capability_actions_ordinal_unique UNIQUE (scan_id, ordinal),
    CONSTRAINT scan_capability_actions_terminal_result_check CHECK (
        status NOT IN ('success','partial','failed','timed_out')
        OR (receipt_hash ~ '^[0-9a-f]{64}$' AND result_digest ~ '^[0-9a-f]{64}$')
    )
);
CREATE INDEX IF NOT EXISTS idx_scan_capability_actions_scan_status
    ON scan_capability_actions(scan_id, status, ordinal);
CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_capability_actions_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;
