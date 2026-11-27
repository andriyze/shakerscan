"""Compare-and-set claims for the existing ASM dispatch timestamps.

A stale leader cannot dispatch a target another tick already claimed. Failed dispatches
release only their own stamp; newer claims remain intact.
"""
from datetime import datetime, timezone
import json

#: The targets columns a dispatch stamps; each is also the target's dispatch claim.
_ASM_CLAIM_COLUMNS = frozenset({"asm_last_recon_at", "asm_last_test_at"})


async def _claim_asm_dispatch(conn, target_id, column: str, seen) -> datetime | None:
    """Claim one target's dispatch by moving ``column`` from the value this tick read.

    Leadership keeps one dispatcher running, but a leader whose tick hung past its timeout can
    still be finishing that tick when the next leader starts: both read the same target as due.
    The stamp is a compare-and-set on what the tick read, so exactly one of them moves it and
    dispatches; the other finds it moved and leaves the target alone. Returns the stamp written,
    or None when another dispatch moved it first.
    """
    if column not in _ASM_CLAIM_COLUMNS:
        raise ValueError(f"not an ASM dispatch column: {column}")
    claimed_at = datetime.now(timezone.utc)
    tag = await conn.execute(
        f"UPDATE targets SET {column} = $3 WHERE id = $1 AND {column} IS NOT DISTINCT FROM $2",
        target_id, seen, claimed_at,
    )
    return claimed_at if str(tag or "").strip().endswith(" 1") else None


async def _release_asm_dispatch(conn, target_id, column: str, seen, claimed_at: datetime) -> None:
    """Undo a claim whose dispatch did not happen (only if nothing moved the stamp since)."""
    if column not in _ASM_CLAIM_COLUMNS:
        raise ValueError(f"not an ASM dispatch column: {column}")
    await conn.execute(
        f"UPDATE targets SET {column} = $2 WHERE id = $1 AND {column} = $3",
        target_id, seen, claimed_at,
    )



def _asm_dispatch_as_utc(value: datetime) -> datetime:
    """The dispatcher clock is naive UTC; stored backoffs are aware. Compare in one frame."""
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _asm_dispatch_backoff_until(metadata_json) -> datetime | None:
    """When the target's last dispatcher decision was a failed dispatch whose
    ``next_eligible_at`` is still ahead, return that instant; otherwise ``None``."""
    metadata = metadata_json
    if isinstance(metadata, (str, bytes)):
        try:
            metadata = json.loads(metadata)
        except ValueError:
            return None
    if not isinstance(metadata, dict):
        return None
    last = metadata.get("asm_last_decision")
    if not isinstance(last, dict) or last.get("blocked_by") != "dispatch_failed":
        return None
    raw = last.get("next_eligible_at")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


