-- Full redacted receipts paired with generic action result references.

BEGIN;

ALTER TABLE scan_capability_actions
    ADD COLUMN IF NOT EXISTS receipt_json JSONB;

INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_action_receipts_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;
