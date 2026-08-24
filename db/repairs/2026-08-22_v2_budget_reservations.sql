-- V2 durable budget reservation schema for Scan and Hunt.
-- Idempotent for existing installations; runtime also verifies this schema before use.

BEGIN;

CREATE TABLE IF NOT EXISTS budget_reservations (
    id TEXT PRIMARY KEY,
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('scan','hunt')),
    owner_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    action_digest TEXT NOT NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    capability_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('requested','reserved','running','committed','released','failed')
    ),
    requested_json JSONB NOT NULL CHECK (jsonb_typeof(requested_json) = 'object'),
    actual_json JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(actual_json) = 'object'),
    hold_applied BOOLEAN NOT NULL DEFAULT false,
    worker_id TEXT,
    lease_expires_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    execution_receipt_hash TEXT,
    failure_reason TEXT,
    execution_uncertain BOOLEAN NOT NULL DEFAULT false,
    version INTEGER NOT NULL CHECK (version > 0),
    state_digest TEXT NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$'),
    state_json JSONB NOT NULL CHECK (jsonb_typeof(state_json) = 'object'),
    ledger_after_hold_json JSONB CHECK (
        ledger_after_hold_json IS NULL OR jsonb_typeof(ledger_after_hold_json) = 'object'
    ),
    ledger_after_settlement_json JSONB CHECK (
        ledger_after_settlement_json IS NULL OR jsonb_typeof(ledger_after_settlement_json) = 'object'
    ),
    receipt_json JSONB CHECK (receipt_json IS NULL OR jsonb_typeof(receipt_json) = 'object'),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT budget_reservations_action_unique UNIQUE (owner_kind, owner_id, action_id),
    CONSTRAINT budget_reservations_identity_unique UNIQUE (
        id, owner_kind, owner_id, action_id, action_digest
    ),
    CONSTRAINT budget_reservations_runtime_state_check CHECK (
        (status = 'requested' AND hold_applied = false AND worker_id IS NULL
            AND lease_expires_at IS NULL AND started_at IS NULL AND finished_at IS NULL)
        OR
        (status = 'reserved' AND hold_applied = true AND worker_id IS NULL
            AND lease_expires_at IS NOT NULL AND started_at IS NULL AND finished_at IS NULL)
        OR
        (status = 'running' AND hold_applied = true AND worker_id IS NOT NULL
            AND lease_expires_at IS NOT NULL AND started_at IS NOT NULL AND finished_at IS NULL)
        OR
        (status IN ('committed','released','failed')
            AND lease_expires_at IS NULL AND finished_at IS NOT NULL)
    ),
    CONSTRAINT budget_reservations_committed_receipt_check CHECK (
        status <> 'committed' OR execution_receipt_hash ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT budget_reservations_uncertain_check CHECK (
        execution_uncertain = false OR (status = 'failed' AND hold_applied = true)
    )
);
ALTER TABLE budget_reservations ADD COLUMN IF NOT EXISTS action_digest TEXT;
UPDATE budget_reservations
SET action_digest = repeat('0', 64)
WHERE action_digest IS NULL;
ALTER TABLE budget_reservations ALTER COLUMN action_digest SET NOT NULL;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'budget_reservations_action_digest_check'
          AND conrelid = 'budget_reservations'::regclass
    ) THEN
        ALTER TABLE budget_reservations
        ADD CONSTRAINT budget_reservations_action_digest_check
        CHECK (action_digest ~ '^[0-9a-f]{64}$');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'budget_reservations_identity_unique'
          AND conrelid = 'budget_reservations'::regclass
    ) THEN
        ALTER TABLE budget_reservations
        ADD CONSTRAINT budget_reservations_identity_unique
        UNIQUE (id, owner_kind, owner_id, action_id, action_digest);
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_budget_reservations_owner
    ON budget_reservations(owner_kind, owner_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_budget_reservations_stale
    ON budget_reservations(lease_expires_at)
    WHERE status IN ('reserved','running');
CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_budget_reservations_v1'), ('v2_budget_reservations_v2'),
       ('v2_budget_reservation_identity_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;
