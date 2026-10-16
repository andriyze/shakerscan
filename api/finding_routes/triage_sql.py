"""Canonical finding status/verdict write shared by triage and knowledge decisions."""

FINDING_UPDATE_SQL = """
    UPDATE findings
    SET status = COALESCE($1::text, findings.status),
        resolved_at = CASE WHEN $1::text = 'resolved' THEN COALESCE(findings.resolved_at, NOW())
                           WHEN $1::text = 'active' THEN NULL
                           ELSE findings.resolved_at END,
        notes = COALESCE($2, findings.notes),
        analyst_verdict = CASE $5::text WHEN 'set' THEN $3::text WHEN 'clear' THEN NULL
                                        ELSE findings.analyst_verdict END,
        analyst_verdict_at = CASE $5::text WHEN 'set' THEN NOW() WHEN 'clear' THEN NULL
                                           ELSE findings.analyst_verdict_at END,
        -- Clearing a verdict keeps its notes unless the request sends new ones: the notes are
        -- the record of why a verdict was set, an automated retest's included, and survive it.
        analyst_verdict_notes = CASE WHEN $5::text IN ('set', 'clear')
                                     THEN COALESCE($2, findings.analyst_verdict_notes)
                                     ELSE findings.analyst_verdict_notes END,
        updated_at = NOW()
    FROM (SELECT id, status FROM findings WHERE id = $4 FOR UPDATE) AS prior
    WHERE findings.id = prior.id
    RETURNING findings.id, findings.target_id, findings.device_target_id, findings.status,
              prior.status AS previous_status, findings.analyst_verdict,
              findings.analyst_verdict_at
"""

