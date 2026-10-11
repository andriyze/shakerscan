"""The interpretation table, kept free of route imports so the startup migration can install it.

One row is one attributed entry about a target: an agent's (or an operator's) observation,
hypothesis, explanation, next step or note, or a narrow negative result. Entries are appended and
superseded, never rewritten: only the lifecycle columns (status and who changed it) are updated.

The dependency and applicability columns are added after the table (not inside it), so a table
created by an earlier 2.9.0 build and a fresh install end with the same columns in the same order.

``finding_dismissed`` is a human decision. Besides the route checks, the table itself refuses a
dismissal that an operator did not write.
"""

KINDS = ("observation", "hypothesis", "explanation", "next_step", "note", "negative_result")
NEGATIVE_STATES = ("experiment_completed_negative", "experiment_inconclusive", "hypothesis_refuted",
                   "finding_dismissed")
PROVENANCES = ("observed", "inferred", "quoted_from_target")
STATUSES = ("active", "superseded", "retracted", "reopened")
DISMISSAL_REASONS = ("false_positive", "accepted_risk", "duplicate")
#: Whether an entry's recorded dependencies still hold (hunt/knowledge_changes.py). ``superseded``
#: is the entry's status, not a stored applicability; ``unknown`` is never treated as unchanged.
APPLICABILITY_STATES = ("applicable", "needs_revalidation", "historical", "unknown")
MAX_TITLE_CHARACTERS = 200
#: The stored ceiling; a Hunt writes at most MAX_AGENT_BODY_CHARACTERS (see interpretations.py).
#: Larger bodies hold an operator's entry or the imported advisory knowledge (12,000 characters).
MAX_BODY_CHARACTERS = 12_000
MAX_NOTE_CHARACTERS = 2_000


def _values(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


# Additive and idempotent: installed by the unified startup migration
# (api/targets/asset_migration.py) and, with the same definition, by db/init.sql.
INTERPRETATION_SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS target_interpretations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ({_values(KINDS)})),
    negative_state TEXT CHECK (negative_state IS NULL OR negative_state IN ({_values(NEGATIVE_STATES)})),
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND {MAX_TITLE_CHARACTERS}),
    body TEXT NOT NULL DEFAULT '' CHECK (length(body) <= {MAX_BODY_CHARACTERS}),
    provenance TEXT NOT NULL CHECK (provenance IN ({_values(PROVENANCES)})),
    written_by TEXT NOT NULL CHECK (written_by ~ '^(hunt|operator|system):' AND length(written_by) <= 200),
    hunt_run_id UUID REFERENCES hunt_runs(id) ON DELETE SET NULL,
    agent_label TEXT CHECK (agent_label IS NULL OR length(agent_label) <= 80),
    model_label TEXT CHECK (model_label IS NULL OR length(model_label) <= 120),
    observed_at TIMESTAMPTZ,
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(evidence_refs) = 'array'),
    conditions JSONB NOT NULL DEFAULT '{{}}'::jsonb CHECK (jsonb_typeof(conditions) = 'object'),
    conditions_sha256 TEXT NOT NULL CHECK (conditions_sha256 ~ '^[0-9a-f]{{64}}$'),
    experiment_key TEXT CHECK (experiment_key IS NULL OR experiment_key ~ '^[0-9a-f]{{64}}$'),
    subject JSONB CHECK (subject IS NULL OR jsonb_typeof(subject) = 'object'),
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    dismissal_reason TEXT CHECK (dismissal_reason IS NULL OR dismissal_reason IN ({_values(DISMISSAL_REASONS)})),
    supersedes UUID REFERENCES target_interpretations(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ({_values(STATUSES)})),
    status_changed_by TEXT CHECK (status_changed_by IS NULL OR length(status_changed_by) <= 200),
    status_changed_at TIMESTAMPTZ,
    status_note TEXT CHECK (status_note IS NULL OR length(status_note) <= {MAX_NOTE_CHARACTERS}),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT target_interpretations_negative_shape CHECK ((kind = 'negative_result') = (negative_state IS NOT NULL)),
    CONSTRAINT target_interpretations_dismissal_is_human CHECK (
        (negative_state = 'finding_dismissed') IS NOT TRUE
        OR (written_by LIKE 'operator:%' AND hunt_run_id IS NULL AND finding_id IS NOT NULL
            AND dismissal_reason IS NOT NULL)),
    CONSTRAINT target_interpretations_dismissal_fields CHECK (
        negative_state = 'finding_dismissed' OR (finding_id IS NULL AND dismissal_reason IS NULL)),
    CONSTRAINT target_interpretations_reopen_shape CHECK (
        status <> 'reopened' OR negative_state = 'finding_dismissed')
);
CREATE INDEX IF NOT EXISTS idx_target_interpretations_target
    ON target_interpretations(target_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_target_interpretations_hunt
    ON target_interpretations(hunt_run_id) WHERE hunt_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_target_interpretations_experiment
    ON target_interpretations(target_id, experiment_key) WHERE experiment_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_target_interpretations_one_dismissal
    ON target_interpretations(finding_id) WHERE negative_state = 'finding_dismissed' AND status = 'active';
-- Whatever path changes a finding's status (a route, a scan or verifier re-detecting it, or an
-- earlier engine after a rollback), an operator's dismissal ends when the status leaves the
-- dismissed statuses: it is marked reopened, never left active beside an active finding.
CREATE OR REPLACE FUNCTION target_interpretations_end_dismissal() RETURNS trigger
LANGUAGE plpgsql AS $end_dismissal$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status
            AND NEW.status NOT IN ('false_positive', 'accepted_risk') THEN
        UPDATE target_interpretations
           SET status = 'reopened', status_changed_by = 'system:finding-status', status_changed_at = NOW(),
               status_note = 'The finding status changed outside the dismissal.'
         WHERE finding_id = NEW.id AND negative_state = 'finding_dismissed' AND status = 'active';
    END IF;
    RETURN NULL;
END
$end_dismissal$;
DO $end_dismissal_trigger$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'findings_end_dismissal'
                   AND tgrelid = 'findings'::regclass) THEN
        CREATE TRIGGER findings_end_dismissal AFTER UPDATE OF status ON findings
            FOR EACH ROW EXECUTE FUNCTION target_interpretations_end_dismissal();
    END IF;
END
$end_dismissal_trigger$;
DO $applicability_columns$
BEGIN
    -- Checked first: ALTER TABLE takes an exclusive lock even when every column already exists,
    -- and this runs at every start.
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()
                   AND table_name = 'target_interpretations' AND column_name = 'applicability_checked_at') THEN
        ALTER TABLE target_interpretations
            ADD COLUMN IF NOT EXISTS dependencies JSONB NOT NULL DEFAULT '{{}}'::jsonb
                CHECK (jsonb_typeof(dependencies) = 'object'),
            ADD COLUMN IF NOT EXISTS applicability TEXT NOT NULL DEFAULT 'unknown'
                CHECK (applicability IN ({_values(APPLICABILITY_STATES)})),
            ADD COLUMN IF NOT EXISTS applicability_reason JSONB
                CHECK (applicability_reason IS NULL OR jsonb_typeof(applicability_reason) = 'object'),
            ADD COLUMN IF NOT EXISTS applicability_changed_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS applicability_checked_at TIMESTAMPTZ;
    END IF;
END
$applicability_columns$;
DO $applicability_indexes$
BEGIN
    -- Checked first: CREATE INDEX IF NOT EXISTS still takes a SHARE lock on the table (it waits
    -- for every open writer) even when the index exists, and this runs at every start.
    IF to_regclass('idx_target_interpretations_applicability') IS NULL THEN
        CREATE INDEX idx_target_interpretations_applicability
            ON target_interpretations(target_id, applicability_checked_at NULLS FIRST)
            WHERE status = 'active' AND dependencies <> '{{}}'::jsonb;
    END IF;
    -- Later responses of the same request are looked up by path (hunt/knowledge_dependencies.py);
    -- built once, at the first start of a release that has it.
    IF to_regclass('idx_hunt_actions_http_request_path') IS NULL THEN
        CREATE INDEX idx_hunt_actions_http_request_path
            ON hunt_actions ((input_summary->'input'->>'path'), completed_at DESC)
            WHERE capability_name = 'http.request';
    END IF;
END
$applicability_indexes$;
"""
