-- Durable, content-free checkpoints for canonical Scan stage execution.

BEGIN;

CREATE TABLE IF NOT EXISTS scan_stage_checkpoints (
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    job_id TEXT NOT NULL,
    stage_index SMALLINT NOT NULL CHECK (stage_index >= 0 AND stage_index < 32),
    stage_name TEXT NOT NULL CHECK (stage_name ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$'),
    status TEXT NOT NULL CHECK (
        status IN ('completed','partial','skipped','failed','cancelled')
    ),
    execution_plan_digest TEXT NOT NULL CHECK (execution_plan_digest ~ '^[0-9a-f]{64}$'),
    target_binding_digest TEXT NOT NULL CHECK (target_binding_digest ~ '^[0-9a-f]{64}$'),
    history_digest TEXT NOT NULL CHECK (history_digest ~ '^[0-9a-f]{64}$'),
    stage_row_digest TEXT NOT NULL CHECK (stage_row_digest ~ '^[0-9a-f]{64}$'),
    stage_row_json JSONB NOT NULL CHECK (
        jsonb_typeof(stage_row_json) = 'object'
        AND stage_row_json - ARRAY[
            'index','name','enabled','status','reason','adapter',
            'capability_names','output_keys','elapsed_ms'
        ]::text[] = '{}'::jsonb
    ),
    worker_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scan_id, job_id, stage_index),
    CONSTRAINT scan_stage_checkpoints_stage_unique
        UNIQUE (scan_id, job_id, stage_name)
);
CREATE INDEX IF NOT EXISTS idx_scan_stage_checkpoints_scan
    ON scan_stage_checkpoints(scan_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_stage_checkpoints_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;
