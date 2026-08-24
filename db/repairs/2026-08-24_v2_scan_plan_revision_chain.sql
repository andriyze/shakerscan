-- Add content-addressed evidence for the sole bounded Scan plan amendment.

BEGIN;

ALTER TABLE scan_action_plan_revisions
    ADD COLUMN IF NOT EXISTS revision_schema TEXT;
ALTER TABLE scan_action_plan_revisions
    ADD COLUMN IF NOT EXISTS discovery_result_digest CHAR(64);
ALTER TABLE scan_action_plan_revisions
    ADD COLUMN IF NOT EXISTS work_manifest_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE scan_action_plan_revisions
    ADD COLUMN IF NOT EXISTS continuation_plan_digest CHAR(64);
ALTER TABLE scan_action_plan_revisions
    ADD COLUMN IF NOT EXISTS revision_digest CHAR(64);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='scan_action_plan_revisions_work_refs_check'
          AND conrelid='scan_action_plan_revisions'::regclass
    ) THEN
        ALTER TABLE scan_action_plan_revisions
        ADD CONSTRAINT scan_action_plan_revisions_work_refs_check
        CHECK (jsonb_typeof(work_manifest_refs_json)='array');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='scan_action_plan_revisions_revision_bound_check'
          AND conrelid='scan_action_plan_revisions'::regclass
    ) THEN
        ALTER TABLE scan_action_plan_revisions
        ADD CONSTRAINT scan_action_plan_revisions_revision_bound_check
        CHECK (revision IN (0,1));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='scan_action_plan_revisions_chain_digests_check'
          AND conrelid='scan_action_plan_revisions'::regclass
    ) THEN
        ALTER TABLE scan_action_plan_revisions
        ADD CONSTRAINT scan_action_plan_revisions_chain_digests_check
        CHECK (
            (discovery_result_digest IS NULL OR discovery_result_digest ~ '^[0-9a-f]{64}$')
            AND (continuation_plan_digest IS NULL OR continuation_plan_digest ~ '^[0-9a-f]{64}$')
            AND (revision_digest IS NULL OR revision_digest ~ '^[0-9a-f]{64}$')
        );
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_plan_revision_chain_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;
