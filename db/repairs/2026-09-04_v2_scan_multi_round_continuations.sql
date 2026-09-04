-- Permit eight append-only Scan work rounds plus one terminal-finalizer revision.

BEGIN;

ALTER TABLE scan_action_plan_revisions
    DROP CONSTRAINT IF EXISTS scan_action_plan_revisions_revision_bound_check;
ALTER TABLE scan_action_plan_revisions
    DROP CONSTRAINT IF EXISTS scan_action_plan_revisions_revision_check;
ALTER TABLE scan_action_plan_revisions
    DROP CONSTRAINT IF EXISTS scan_action_plan_revisions_immutable_shape_check;
ALTER TABLE scan_action_plan_revisions
    DROP CONSTRAINT IF EXISTS scan_action_plan_revisions_multi_round_bound_check;
ALTER TABLE scan_action_plan_revisions
    DROP CONSTRAINT IF EXISTS scan_action_plan_revisions_multi_round_shape_check;

ALTER TABLE scan_action_plan_revisions
    ADD CONSTRAINT scan_action_plan_revisions_multi_round_bound_check
    CHECK (revision BETWEEN 0 AND 9);
ALTER TABLE scan_action_plan_revisions
    ADD CONSTRAINT scan_action_plan_revisions_multi_round_shape_check
    CHECK (
        (
            revision=0
            AND parent_plan_digest IS NULL
            AND continuation_allocation_digest IS NULL
            AND discovery_result_digest IS NULL
            AND work_manifest_refs_json='[]'::jsonb
            AND continuation_plan_digest IS NULL
        )
        OR
        (
            revision BETWEEN 1 AND 9
            AND parent_plan_digest IS NOT NULL
            AND continuation_allocation_digest IS NOT NULL
            AND discovery_result_digest IS NOT NULL
            AND jsonb_array_length(work_manifest_refs_json) > 0
            AND continuation_plan_digest IS NOT NULL
        )
    ) NOT VALID;

INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_plan_multi_round_v1')
ON CONFLICT (name) DO NOTHING;

COMMIT;
