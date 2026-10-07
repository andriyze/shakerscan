"""Resolve the evidence a Hunt candidate cites before the candidate is stored.

A candidate is non-authoritative, but its evidence references are what a reviewer and a verifier
follow. Accepting a nonexistent identifier, or one that belongs to another Hunt or target, made a
claim look supported by evidence it never had. Every reference must resolve to a record of this
Hunt (an action, its receipt, or an HTTP transaction), to a finding on this Hunt's target, or, on a
device Hunt, to a ``devref_N`` evidence entry in this Hunt's device runtime.

Accepted reference forms (case-insensitive prefix, canonical UUID):

* ``<uuid>`` -- any of the kinds below
* ``action:<uuid>`` / ``hunt_action:<uuid>``
* ``receipt:<uuid>`` / ``tool_receipt:<uuid>``
* ``transaction:<uuid>`` / ``http_transaction:<uuid>`` / ``capture:<uuid>``
* ``finding:<uuid>``
* ``devref_<n>`` (device Hunts)
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any
from uuid import UUID

_PREFIX_KINDS = {
    "action": "action", "hunt_action": "action",
    "receipt": "receipt", "tool_receipt": "receipt",
    "transaction": "transaction", "http_transaction": "transaction", "capture": "transaction",
    "finding": "finding",
}
_DEVICE_REF = re.compile(r"devref_[1-9][0-9]{0,8}")

EVIDENCE_QUERY = """
SELECT a.id::text AS id, 'action' AS kind
FROM hunt_actions a WHERE a.id = ANY($1::uuid[]) AND a.hunt_run_id = $2::uuid
UNION ALL
SELECT a.receipt_id::text AS id, 'receipt' AS kind
FROM hunt_actions a WHERE a.receipt_id = ANY($1::uuid[]) AND a.hunt_run_id = $2::uuid
UNION ALL
SELECT t.id::text AS id, 'transaction' AS kind
FROM http_transactions t WHERE t.id = ANY($1::uuid[]) AND t.hunt_run_id = $2::uuid
UNION ALL
SELECT f.id::text AS id, 'finding' AS kind
FROM findings f
WHERE f.id = ANY($1::uuid[])
  AND (f.hunt_run_id = $2::uuid
       OR ($3::uuid IS NOT NULL AND f.target_id = $3::uuid)
       OR ($4::uuid IS NOT NULL AND f.device_target_id = $4::uuid))
"""


class CandidateEvidenceError(ValueError):
    """One or more evidence references do not resolve to this Hunt's evidence."""

    def __init__(self, message: str, references: list[str]) -> None:
        super().__init__(message)
        self.references = references


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except ValueError:
            return {}
        return dict(decoded) if isinstance(decoded, Mapping) else {}
    return {}


def parse_evidence_reference(value: Any) -> tuple[str | None, str]:
    """Return (expected kind or None for any, canonical identifier); raise on malformed input."""
    text = str(value or "").strip()
    if _DEVICE_REF.fullmatch(text):
        return "device_evidence", text
    prefix, separator, rest = text.partition(":")
    kind = None
    if separator:
        kind = _PREFIX_KINDS.get(prefix.strip().lower())
        if kind is None:
            raise CandidateEvidenceError(
                f"evidence reference kind {prefix[:40]!r} is not supported", [text[:120]],
            )
        text = rest.strip()
    try:
        return kind, str(UUID(text))
    except (ValueError, AttributeError) as exc:
        raise CandidateEvidenceError(
            "evidence references must be Hunt record UUIDs (optionally prefixed with "
            "action:, receipt:, transaction: or finding:) or devref_N",
            [str(value)[:120]],
        ) from exc


async def resolve_candidate_evidence(
    conn: Any, *, run: Mapping[str, Any], references: list[str],
) -> list[str]:
    """Return the references unchanged when every one resolves; raise otherwise.

    Missing and out-of-Hunt references are reported identically: a caller learns that a
    reference is not evidence of this Hunt, never whether it exists elsewhere.
    """
    parsed = [(reference, *parse_evidence_reference(reference)) for reference in references]
    identifiers = sorted({
        identifier for _reference, kind, identifier in parsed if kind != "device_evidence"
    })
    found: dict[str, set[str]] = {}
    if identifiers:
        target_id = str(run["target_id"]) if run.get("target_id") else None
        device_id = str(run["device_target_id"]) if run.get("device_target_id") else None
        rows = await conn.fetch(
            EVIDENCE_QUERY, identifiers, str(run["id"]), target_id, device_id,
        )
        for row in rows:
            found.setdefault(str(row["id"]), set()).add(str(row["kind"]))
    device_evidence = _json_object(
        _json_object(_json_object(run.get("context_pack")).get("device_runtime")).get("evidence")
    )
    unresolved: list[str] = []
    for reference, kind, identifier in parsed:
        if kind == "device_evidence":
            resolved = bool(run.get("device_target_id")) and identifier in device_evidence
        else:
            kinds = found.get(identifier, set())
            resolved = bool(kinds) if kind is None else kind in kinds
        if not resolved:
            unresolved.append(str(reference)[:120])
    if unresolved:
        raise CandidateEvidenceError(
            "evidence references do not resolve to records of this Hunt or its target",
            unresolved,
        )
    return list(references)
