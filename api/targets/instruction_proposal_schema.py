"""The proposal table, kept free of route imports so the startup migration can install it."""
try:
    from runtime.asset_capability_specs import MAX_TARGET_SKILL_CHARACTERS
except ModuleNotFoundError:
    from ..runtime.asset_capability_specs import MAX_TARGET_SKILL_CHARACTERS

MAX_REASON_CHARACTERS = 2000
MAX_TITLE_CHARACTERS = 120

MAX_SAVED_ACTION_REVIEW_CHARACTERS = 65_536
PROPOSAL_KINDS = ('instructions', 'saved_action')

# Additive and idempotent: installed by the unified startup migration
# (api/targets/asset_migration.py) and, with the same definition, by db/init.sql.
# ``kind`` separates instruction proposals from saved-action proposals. For a saved action,
# ``methodology`` is the canonical text the reviewer reads (the recipe as indented JSON) and
# ``action_body`` the recipe that accepting applies. The DO block upgrades a table created before
# ``kind`` existed; once the named shape constraint exists it only reads the catalog.
INSTRUCTION_PROPOSAL_SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS target_instruction_proposals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    base_revision INTEGER NOT NULL CHECK (base_revision >= 0),
    base_sha256 TEXT CHECK (base_sha256 IS NULL OR base_sha256 ~ '^[0-9a-f]{{64}}$'),
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND {MAX_TITLE_CHARACTERS}),
    methodology TEXT NOT NULL,
    methodology_sha256 TEXT NOT NULL CHECK (methodology_sha256 ~ '^[0-9a-f]{{64}}$'),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND {MAX_REASON_CHARACTERS}),
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(evidence_refs) = 'array'),
    proposed_by TEXT NOT NULL CHECK (proposed_by ~ '^(hunt|operator):' AND length(proposed_by) <= 200),
    hunt_run_id UUID REFERENCES hunt_runs(id) ON DELETE SET NULL,
    rebased_from UUID REFERENCES target_instruction_proposals(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','accepted','rejected','superseded')),
    decided_by TEXT CHECK (decided_by IS NULL OR length(decided_by) <= 200),
    decided_at TIMESTAMPTZ,
    decision_note TEXT CHECK (decision_note IS NULL OR length(decision_note) <= {MAX_REASON_CHARACTERS}),
    applied_revision INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    kind TEXT NOT NULL DEFAULT 'instructions',
    action_operation TEXT,
    action_id UUID,
    action_body JSONB
);
DO $proposals$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'target_instruction_proposals'::regclass
                     AND conname = 'target_instruction_proposals_shape') THEN
        ALTER TABLE target_instruction_proposals
            ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'instructions',
            ADD COLUMN IF NOT EXISTS action_operation TEXT,
            ADD COLUMN IF NOT EXISTS action_id UUID,
            ADD COLUMN IF NOT EXISTS action_body JSONB,
            DROP CONSTRAINT IF EXISTS target_instruction_proposals_methodology_check,
            ADD CONSTRAINT target_instruction_proposals_shape CHECK (length(methodology) >= 1 AND (
                (kind = 'instructions' AND length(methodology) <= {MAX_TARGET_SKILL_CHARACTERS}
                 AND action_operation IS NULL AND action_id IS NULL AND action_body IS NULL)
                OR (kind = 'saved_action' AND length(methodology) <= {MAX_SAVED_ACTION_REVIEW_CHARACTERS}
                    AND action_operation IS NOT NULL AND action_operation IN ('create','update','delete')
                    AND (action_operation = 'create') = (action_id IS NULL)
                    AND (action_operation = 'delete') = (action_body IS NULL)
                    AND (action_body IS NULL OR jsonb_typeof(action_body) = 'object'))));
    END IF;
END
$proposals$;
CREATE INDEX IF NOT EXISTS idx_target_instruction_proposals_target
    ON target_instruction_proposals(target_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_target_instruction_proposals_hunt
    ON target_instruction_proposals(hunt_run_id) WHERE hunt_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_target_instruction_proposals_pending
    ON target_instruction_proposals(created_at) WHERE status = 'pending';
"""
