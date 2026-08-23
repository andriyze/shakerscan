-- Private capability observations behind content-free immutable references.

BEGIN;

CREATE TABLE IF NOT EXISTS scan_observation_manifests (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    action_id TEXT NOT NULL,
    capability_name TEXT NOT NULL,
    output_schema TEXT NOT NULL,
    manifest_digest CHAR(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    content_sha256 CHAR(64) NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    observation_count INTEGER NOT NULL CHECK (observation_count >= 0 AND observation_count <= 100000),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 67108864),
    object_key TEXT NOT NULL,
    manifest_json JSONB NOT NULL CHECK (jsonb_typeof(manifest_json)='object'),
    observations_json JSONB NOT NULL CHECK (jsonb_typeof(observations_json)='array'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT scan_observation_identity_unique UNIQUE (scan_id, action_id, content_sha256)
);
CREATE INDEX IF NOT EXISTS idx_scan_observation_manifests_scan_action
    ON scan_observation_manifests(scan_id, action_id, created_at DESC);

INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_observation_manifests_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;
