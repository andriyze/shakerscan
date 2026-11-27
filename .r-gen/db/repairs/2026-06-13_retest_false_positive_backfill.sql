-- One-time repair: historical retests mislabeled a "failed to replay" /
-- AI-timeout outcome as verdict='false_positive' at low/zero confidence.
--
-- The corrected classifier (api/worker.py) only emits false_positive for
-- high-confidence objective evidence (>= 0.7). This backfill brings existing
-- rows in line with that invariant: any false_positive below the confidence
-- bar becomes 'inconclusive' so the UI no longer shows a terminal
-- "False positive" at 0% confidence. Lifecycle status (findings.status) is
-- intentionally NOT touched — it remains analyst-controlled.
--
-- The same retest series briefly over-promoted inconclusive deterministic
-- replays to likely_vulnerable when prover steps were merely attempted. The
-- second repair block targets that exact promotion marker only when proof has no
-- evidence and confidence is below the partial-evidence threshold.

BEGIN;

UPDATE finding_verifications
SET verdict = 'inconclusive',
    result_status = 'inconclusive',
    verdict_reason = COALESCE(NULLIF(verdict_reason, ''), '')
        || ' [backfill: downgraded false_positive->inconclusive; insufficient confidence for a false positive]',
    updated_at = NOW()
WHERE verdict = 'false_positive'
  AND COALESCE(confidence, 0) < 0.7;

WITH bad_promotions AS (
    SELECT id
    FROM finding_verifications
    WHERE verdict = 'likely_vulnerable'
      AND result_status = 'inconclusive'
      AND COALESCE(confidence, 0) < 0.3
      AND COALESCE(proof->>'proven', 'false') = 'false'
      AND COALESCE(proof->>'evidence_type', '') = ''
      AND verdict_reason ILIKE '%promoted from inconclusive: deterministic tier found partial evidence%'
)
UPDATE finding_verifications fv
SET verdict = 'inconclusive',
    result_status = 'inconclusive',
    verdict_reason = regexp_replace(
        COALESCE(NULLIF(fv.verdict_reason, ''), 'Retest was inconclusive.'),
        '\s*\[promoted from inconclusive: deterministic tier found partial evidence\]',
        '',
        'gi'
    )
        || ' [backfill: downgraded likely_vulnerable->inconclusive; prover attempts had no partial evidence]',
    updated_at = NOW()
FROM bad_promotions bp
WHERE fv.id = bp.id;

UPDATE findings
SET last_verification_verdict = 'inconclusive',
    last_verification_status = 'inconclusive',
    updated_at = NOW()
WHERE last_verification_verdict = 'false_positive'
  AND COALESCE(last_verification_confidence, 0) < 0.7;

WITH latest_bad_promotions AS (
    SELECT DISTINCT ON (finding_id) finding_id
    FROM finding_verifications
    WHERE verdict = 'inconclusive'
      AND result_status = 'inconclusive'
      AND verdict_reason ILIKE '%downgraded likely_vulnerable->inconclusive%'
    ORDER BY finding_id, COALESCE(completed_at, updated_at, created_at) DESC
)
UPDATE findings f
SET last_verification_verdict = 'inconclusive',
    last_verification_status = 'inconclusive',
    updated_at = NOW()
FROM latest_bad_promotions lbp
WHERE f.id = lbp.finding_id
  AND f.last_verification_verdict = 'likely_vulnerable'
  AND COALESCE(f.last_verification_confidence, 0) < 0.3;

COMMIT;
