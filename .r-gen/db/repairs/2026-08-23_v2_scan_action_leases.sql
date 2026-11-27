-- Durable, short-lived placement leases and generic action result references.

BEGIN;

ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS result_json JSONB;
ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS backend_name TEXT;
ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS worker_id TEXT;
ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS lease_id UUID;
ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS lease_token_hash CHAR(64);
ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_scan_capability_actions_lease_expiry
    ON scan_capability_actions(lease_expires_at)
    WHERE status IN ('leased','running');

INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_action_leases_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;
