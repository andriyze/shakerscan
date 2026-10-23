"""A per-Hunt bound on the bytes its candidate writes store.

Candidates share ``max_candidates`` (one record per call) with findings, and every field is bounded
in characters only: a create or sighting stores a candidate row and an observation row, which with
four-byte characters at every limit (title, claim, evidence list, locus, and the 20,000-character
objective each observation records) is about 260 KB, so a generous record allowance could hold
gigabytes per Hunt. Like the finding bound (``finding_actions.MAX_FINDING_BYTES_PER_HUNT``) a
write that would take the Hunt's candidate records past the bound is refused as an input error:
nothing is written or charged, no budget state is recorded and the Hunt keeps running.

The bound counts what the Hunt's writes stored, in UTF-8: its observation rows (title, claim,
evidence references, context) and the candidate rows it created (title, claim, locus, evidence
references). About 1,030 candidates of the largest size fit in 256 MiB; a typical candidate of a
kilobyte or two fits by the hundred thousand, more than the largest profile's record allowance.
"""
from __future__ import annotations

import json
from typing import Any, Mapping
import uuid

from fastapi import HTTPException

MAX_CANDIDATE_BYTES_PER_HUNT = 256 * 1024 * 1024
# The largest stored title and claim (characters x 4 bytes) and evidence list, for a correction
# that leaves a field as it is: its observation copies the stored value.
_LARGEST_TITLE_BYTES = 300 * 4
_LARGEST_CLAIM_BYTES = 8_000 * 4
_LARGEST_REFS_BYTES = len(json.dumps(["\U0001F600" * 120] * 100, ensure_ascii=False).encode())
# A correction's lifecycle context (event, changed fields, flags).
_CORRECTION_CONTEXT_BYTES = 512

STORED_CANDIDATE_BYTES_SQL = """SELECT
    COALESCE((SELECT SUM(octet_length(o.title) + octet_length(o.claim)
                         + octet_length(o.evidence_refs::text) + octet_length(o.observation_context::text))
              FROM investigation_candidate_observations o WHERE o.hunt_run_id=$1), 0)
  + COALESCE((SELECT SUM(octet_length(c.title) + octet_length(c.claim)
                         + octet_length(c.canonical_locus::text) + octet_length(c.evidence_refs::text))
              FROM investigation_candidates c
              WHERE c.hunt_run_id=$1 AND c.id IN (
                  SELECT o.candidate_id FROM investigation_candidate_observations o
                  WHERE o.hunt_run_id=$1)), 0)"""


def _text(value: Any) -> int:
    return len(str(value or "").encode("utf-8"))


def _json(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))


def sighting_bytes(candidate: Mapping[str, Any], observation_context: Mapping[str, Any]) -> int:
    """At most what one create or sighting stores: a new candidate row and its observation."""
    content = _text(candidate.get("title")) + _text(candidate.get("claim")) + _json(candidate.get("evidence_refs") or [])
    extra = dict(candidate.get("locus_metadata") or {})
    context = {**observation_context, **({"locus_metadata": extra} if extra else {})}
    return 2 * content + _json(candidate.get("canonical_locus") or {}) + _json(context)


def correction_bytes(changes: Mapping[str, Any]) -> int:
    """At most what one correction stores: its observation of the corrected row (the row itself is
    replaced in place). A field left as it is counts at its largest stored size."""
    title = _text(changes["title"]) if changes.get("title") is not None else _LARGEST_TITLE_BYTES
    claim = _text(changes["claim"]) if changes.get("claim") is not None else _LARGEST_CLAIM_BYTES
    refs = _json(changes["evidence_refs"]) if changes.get("evidence_refs") is not None else _LARGEST_REFS_BYTES
    return title + claim + refs + _CORRECTION_CONTEXT_BYTES


async def require_candidate_room(conn: Any, hunt_id: Any, size: int) -> None:
    """Refuse a write that would take this Hunt's candidate records past the bound."""
    stored = int(await conn.fetchval(STORED_CANDIDATE_BYTES_SQL, uuid.UUID(str(hunt_id))) or 0)
    if stored + int(size) > MAX_CANDIDATE_BYTES_PER_HUNT:
        raise HTTPException(status_code=422, detail={
            "error": "candidate_bytes_limit",
            "message": (
                f"This Hunt's candidate records hold {stored:,} bytes; this {int(size):,}-byte write "
                f"would pass the {MAX_CANDIDATE_BYTES_PER_HUNT:,}-byte limit per Hunt. Record a "
                "shorter claim or correct an existing candidate; nothing was written and the Hunt "
                "keeps running."
            ),
        })


__all__ = [
    "MAX_CANDIDATE_BYTES_PER_HUNT", "STORED_CANDIDATE_BYTES_SQL", "correction_bytes",
    "require_candidate_room", "sighting_bytes",
]
