-- hunt_coverage_angle_events exactly as the first coverage-ledger release installed it:
-- no event_seq, an auto-named status check and timestamp-ordered indexes.
CREATE TABLE hunt_coverage_angle_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    family TEXT NOT NULL,
    locus_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    mechanism TEXT NOT NULL DEFAULT '',
    principal_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    hypothesis TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (
        status IN ('planned','testing','negative','partial','blocked','candidate')
    ),
    evidence_action_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    contradictory_evidence_action_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    candidate_id UUID,
    blocker TEXT,
    proof_gap TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_hunt_coverage_angle_events_run
ON hunt_coverage_angle_events(hunt_run_id, created_at DESC, id DESC);
CREATE INDEX idx_hunt_coverage_angle_events_fingerprint
ON hunt_coverage_angle_events(hunt_run_id, fingerprint, created_at DESC, id DESC);
