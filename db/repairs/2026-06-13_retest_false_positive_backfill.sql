-- One-time repair: historical retests mislabeled a "failed to replay" /
-- AI-timeout outcome as verdict='false_positive' at low/zero confidence.
--
-- The corrected classifier (api/worker.py) only emits false_positive for
-- high-confidence objective evidence (>= 0.7). This backfill brings existing
-- rows in line with that invariant: any false_positive below the confidence
-- bar becomes 'inconclusive' so the UI no longer shows a terminal
-- "False positive" at 0% confidence. Lifecycle status (findings.status) is
-- intentionally NOT touched — it remains analyst-controlled.

BEGIN;

UPDATE finding_verifications
SET verdict = 'inconclusive',
    result_status = 'inconclusive',
    verdict_reason = COALESCE(NULLIF(verdict_reason, ''), '')
        || ' [backfill: downgraded false_positive->inconclusive; insufficient confidence for a false positive]',
    updated_at = NOW()
WHERE verdict = 'false_positive'
  AND COALESCE(confidence, 0) < 0.7;

UPDATE findings
SET last_verification_verdict = 'inconclusive',
    last_verification_status = 'inconclusive',
    updated_at = NOW()
WHERE last_verification_verdict = 'false_positive'
  AND COALESCE(last_verification_confidence, 0) < 0.7;

COMMIT;
