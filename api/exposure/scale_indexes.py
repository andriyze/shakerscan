"""The findings index behind the Exposure asset counts (no imports: the index builder loads it).

A finding "needs verification" when no retest or analyst settled it (``needs_verification_sql``).
The asset list counts that as the active total (trigger-maintained summary) minus the settled
rows, which this partial index holds; they are normally a small share of the active rows.
"""
from __future__ import annotations

NEEDS_VERDICTS = ("inconclusive", "error", "likely_vulnerable", "exploited")
NEEDS_ANALYST = ("needs_review", "retest_needed")


def needs_verification_sql(prefix: str = "f.") -> str:
    """``active_finding_proof_counts``' "needs verification" test before the proof (a verified row
    is not counted; the SQL subtracts those). ``prefix`` qualifies the columns ('' in an index)."""
    return (
        f"({prefix}last_verification_verdict IS NULL"
        f" OR {prefix}last_verification_verdict IN {tuple(NEEDS_VERDICTS)!r}"
        f" OR {prefix}analyst_verdict IN {tuple(NEEDS_ANALYST)!r})"
    )


SETTLED_PREDICATE = f"status = 'active' AND NOT COALESCE({needs_verification_sql('')}, false)"

# (index name, table, definition after "ON"), built CONCURRENTLY by runtime/loop_scale_indexes.py.
EXPOSURE_SCALE_INDEXES: tuple[tuple[str, str, str], ...] = (
    ("idx_findings_active_settled_target", "findings", f"findings (target_id) WHERE {SETTLED_PREDICATE}"),
)

__all__ = ["EXPOSURE_SCALE_INDEXES", "NEEDS_ANALYST", "NEEDS_VERDICTS", "SETTLED_PREDICATE", "needs_verification_sql"]
