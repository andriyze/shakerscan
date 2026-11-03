"""Resolve the evidence a Hunt candidate cites before the candidate is stored.

A candidate is non-authoritative, but its evidence references are what a reviewer and a verifier
follow. Accepting a nonexistent identifier, or one that belongs to another Hunt or target, made a
claim look supported by evidence it never had. Every reference must resolve to a record of this
Hunt (an action, its receipt, or an HTTP transaction), to a finding on this Hunt's target, or, on a
device Hunt, to a ``devref_N`` evidence entry in this Hunt's device runtime.

An action, or the receipt of an action, is evidence only once it settled as ``completed`` or
``partial``. An action refused at admission is stored as ``failed`` with no traffic, and a
``blocked``, ``running`` or ``reserved`` action has produced nothing to cite yet; such a reference
is refused as ``candidate_evidence_unsettled``. The caller owns these actions, so naming the
status reveals nothing about another Hunt.

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
# Action statuses whose output exists and may be cited. Everything else is refused.
SETTLED_ACTION_STATUSES = frozenset({"completed", "partial"})
UNRESOLVED = "candidate_evidence_unresolved"
UNSETTLED = "candidate_evidence_unsettled"

EVIDENCE_QUERY = """
SELECT a.id::text AS id, 'action' AS kind, a.status::text AS status
FROM hunt_actions a WHERE a.id = ANY($1::uuid[]) AND a.hunt_run_id = $2::uuid
UNION ALL
SELECT a.receipt_id::text AS id, 'receipt' AS kind, a.status::text AS status
FROM hunt_actions a WHERE a.receipt_id = ANY($1::uuid[]) AND a.hunt_run_id = $2::uuid
UNION ALL
SELECT t.id::text AS id, 'transaction' AS kind, NULL::text AS status
FROM http_transactions t WHERE t.id = ANY($1::uuid[]) AND t.hunt_run_id = $2::uuid
UNION ALL
SELECT f.id::text AS id, 'finding' AS kind, NULL::text AS status
FROM findings f
WHERE f.id = ANY($1::uuid[])
  AND (f.hunt_run_id = $2::uuid
       OR ($3::uuid IS NOT NULL AND f.target_id = $3::uuid)
       OR ($4::uuid IS NOT NULL AND f.device_target_id = $4::uuid))
"""


class CandidateEvidenceError(ValueError):
    """One or more evidence references are not settled evidence of this Hunt.

    ``references`` lists the unresolved references and ``unsettled`` those naming an action of
    this Hunt that has not completed; ``code`` is ``UNRESOLVED`` whenever any reference is
    unresolved, else ``UNSETTLED``.
    """

    def __init__(
        self, message: str, references: list[str], *,
        unsettled: list[str] | None = None, code: str = UNRESOLVED,
    ) -> None:
        super().__init__(message)
        self.references = references
        self.unsettled = list(unsettled or [])
        self.code = code


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
    found: dict[str, dict[str, str | None]] = {}
    if identifiers:
        target_id = str(run["target_id"]) if run.get("target_id") else None
        device_id = str(run["device_target_id"]) if run.get("device_target_id") else None
        rows = await conn.fetch(
            EVIDENCE_QUERY, identifiers, str(run["id"]), target_id, device_id,
        )
        for row in rows:
            status = row["status"]
            found.setdefault(str(row["id"]), {})[str(row["kind"])] = (
                None if status is None else str(status)
            )
    device_evidence = _json_object(
        _json_object(_json_object(run.get("context_pack")).get("device_runtime")).get("evidence")
    )
    unresolved: list[str] = []
    unsettled: list[str] = []
    for reference, kind, identifier in parsed:
        if kind == "device_evidence":
            if not (bool(run.get("device_target_id")) and identifier in device_evidence):
                unresolved.append(str(reference)[:120])
            continue
        kinds = found.get(identifier, {})
        matches = list(kinds.items()) if kind is None else (
            [(kind, kinds[kind])] if kind in kinds else []
        )
        if not matches:
            unresolved.append(str(reference)[:120])
        elif not any(
            status is None or status in SETTLED_ACTION_STATUSES for _kind, status in matches
        ):
            unsettled.append(str(reference)[:120])
    if unresolved:
        raise CandidateEvidenceError(
            "evidence references do not resolve to records of this Hunt or its target",
            unresolved, unsettled=unsettled, code=UNRESOLVED,
        )
    if unsettled:
        raise CandidateEvidenceError(
            "evidence references name actions of this Hunt that did not complete; cite a "
            "completed or partial action, its receipt, or a captured transaction",
            [], unsettled=unsettled, code=UNSETTLED,
        )
    return list(references)


# The identity each cited record was gathered as: the managed credentials an action used, the
# principal slot of an archived call, and the principal a scanner action ran as (its settled
# result). A cited finding contributes its own ``evidence_principals``.
EVIDENCE_PRINCIPALS_QUERY = """
WITH cited_actions AS (
    SELECT a.id FROM hunt_actions a
    WHERE a.hunt_run_id = $2::uuid AND (a.id = ANY($1::uuid[]) OR a.receipt_id = ANY($1::uuid[]))
)
SELECT u.slot AS slot FROM hunt_credential_uses u
WHERE u.hunt_run_id = $2::uuid AND u.action_id IN (SELECT id FROM cited_actions)
UNION
SELECT t.principal_slot FROM http_transactions t
WHERE t.hunt_run_id = $2::uuid
  AND (t.id = ANY($1::uuid[]) OR t.hunt_action_id IN (SELECT id FROM cited_actions))
UNION
SELECT a.result_summary->>'as_principal' FROM hunt_actions a
WHERE a.id IN (SELECT id FROM cited_actions)
UNION
SELECT jsonb_array_elements_text(
    CASE WHEN jsonb_typeof(f.evidence->'evidence_principals') = 'array'
         THEN f.evidence->'evidence_principals' ELSE '[]'::jsonb END)
FROM findings f WHERE f.id = ANY($1::uuid[]) AND f.hunt_run_id = $2::uuid
"""
_NOT_A_PRINCIPAL = frozenset({"", "anonymous", "anon", "none", "ssh"})


async def evidence_principals(
    conn: Any, *, run: Mapping[str, Any], references: list[str] | None,
) -> list[str]:
    """The HTTP principals other than ``anonymous`` that resolved evidence was gathered as.

    A retest cannot send a Hunt principal, so a candidate whose evidence was gathered signed in
    must not be judged by an anonymous retest (``retest_contract.candidate_evidence_principals``).
    """
    identifiers = sorted({
        identifier for kind, identifier in (parse_evidence_reference(item) for item in references or ())
        if kind != "device_evidence"
    })
    if not identifiers:
        return []
    rows = await conn.fetch(EVIDENCE_PRINCIPALS_QUERY, identifiers, str(run["id"]))
    slots = {str(row.get("slot") or "").strip().lower()[:80] for row in rows}
    return sorted(slots - _NOT_A_PRINCIPAL)


async def record_evidence_principals(conn: Any, candidate_id: Any, principals: list[str]) -> None:
    """Add principals to a candidate's ``verification_context``; never removes one."""
    if not principals:
        return
    row = await conn.fetchrow(
        "SELECT verification_context FROM investigation_candidates WHERE id=$1::uuid FOR UPDATE",
        str(candidate_id),
    )
    if row is None:
        return
    recorded = _json_object(row["verification_context"]).get("evidence_principals")
    merged = sorted({*(recorded if isinstance(recorded, list) else ()), *principals})
    await conn.execute(
        """UPDATE investigation_candidates
           SET verification_context = COALESCE(verification_context, '{}'::jsonb) || $2::jsonb
           WHERE id=$1::uuid""",
        str(candidate_id), json.dumps({"evidence_principals": merged}),
    )
