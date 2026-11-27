-- Canonical durable endpoint/candidate/request/template work manifests.

BEGIN;

CREATE TABLE IF NOT EXISTS scan_work_manifests (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('endpoint','candidate','request','template')),
    schema_version TEXT NOT NULL,
    content_schema TEXT NOT NULL,
    target_binding_digest CHAR(64) NOT NULL CHECK (target_binding_digest ~ '^[0-9a-f]{64}$'),
    source_action_ids JSONB NOT NULL CHECK (jsonb_typeof(source_action_ids)='array'),
    status TEXT NOT NULL CHECK (status IN ('complete','partial','cancelled')),
    reason_code TEXT,
    entry_count INTEGER NOT NULL CHECK (entry_count >= 0 AND entry_count <= 100000),
    manifest_digest CHAR(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    content_json JSONB NOT NULL CHECK (jsonb_typeof(content_json)='object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT scan_work_manifest_identity_unique UNIQUE (scan_id, kind, manifest_digest),
    CONSTRAINT scan_work_manifest_reason_check CHECK (
        (status='complete' AND reason_code IS NULL)
        OR (status<>'complete' AND reason_code IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_scan_work_manifests_scan_kind
    ON scan_work_manifests(scan_id, kind, created_at DESC);

INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_work_manifests_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;
