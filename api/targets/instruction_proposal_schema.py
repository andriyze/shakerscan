"""The proposal table, kept free of route imports so the startup migration can install it."""
try:
    from runtime.asset_capability_specs import MAX_TARGET_SKILL_CHARACTERS
except ModuleNotFoundError:
    from ..runtime.asset_capability_specs import MAX_TARGET_SKILL_CHARACTERS

MAX_REASON_CHARACTERS = 2000
MAX_TITLE_CHARACTERS = 120

# Additive and idempotent: installed by the unified startup migration
# (api/targets/asset_migration.py) and, with the same definition, by db/init.sql.
INSTRUCTION_PROPOSAL_SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS target_instruction_proposals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    base_revision INTEGER NOT NULL CHECK (base_revision >= 0),
    base_sha256 TEXT CHECK (base_sha256 IS NULL OR base_sha256 ~ '^[0-9a-f]{{64}}$'),
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND {MAX_TITLE_CHARACTERS}),
    methodology TEXT NOT NULL CHECK (length(methodology) BETWEEN 1 AND {MAX_TARGET_SKILL_CHARACTERS}),
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
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_target_instruction_proposals_target
    ON target_instruction_proposals(target_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_target_instruction_proposals_hunt
    ON target_instruction_proposals(hunt_run_id) WHERE hunt_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_target_instruction_proposals_pending
    ON target_instruction_proposals(created_at) WHERE status = 'pending';
"""
