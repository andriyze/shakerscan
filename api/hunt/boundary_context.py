"""Read-only candidate/evidence context for human review of AI boundaries.

No candidate prose, tool input, response body, credential, attack prompt, policy
approval, or executable proposal is returned. A resolved reference establishes
an association with this Hunt, not the correctness or integrity of its contents.
"""
from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping
from typing import Any
from uuid import UUID

MAX_OBSERVATIONS = 50
MAX_REFERENCES = 100
MAX_JSON_BYTES = 65536

_FAMILIES = {
    "cross_tenant_retrieval": "cross_tenant_read",
    "forbidden_agent_action": "cross_tenant_action",
    "agent_action": "cross_tenant_action",
    "approval_bypass": "approval_bypass",
    "tool_principal_boundary": "tool_principal",
    "tool_boundary": "tool_principal",
}
_REQUIRED_FIELDS = {
    "cross_tenant_read": (),
    "cross_tenant_action": (
        "verifier_path", "state_path", "initial_value", "forbidden_value", "prompt",
    ),
    "approval_bypass": (
        "verifier_path", "state_path", "initial_value", "forbidden_value", "prompt",
        "approval_path", "approval_state_path", "required_approval_value",
    ),
    "tool_principal": (
        "tool_name", "expected_principal", "tool_calls_path", "tool_name_field",
        "executed_field", "principal_field", "prompt",
    ),
}
_KNOWN_FIELDS = frozenset(k for fields in _REQUIRED_FIELDS.values() for k in fields)
_CANDIDATE_STATUSES = frozenset({
    "new", "verification_queued", "verifying", "verified", "refuted",
    "inconclusive", "blocked", "expired",
})

# The immutable observation, rather than the candidate's aggregate references,
# owns run provenance when two Hunts deduplicate to one candidate.
CANDIDATE_QUERY = """
SELECT c.id, c.family, c.status, c.canonical_locus
FROM investigation_candidates c
WHERE c.id=$1::uuid
  AND ((c.target_id=$3::uuid AND c.device_target_id IS NULL AND c.plane='web')
    OR (c.device_target_id=$4::uuid AND c.target_id IS NULL AND c.plane='device'))
  AND EXISTS (
    SELECT 1 FROM investigation_candidate_observations o
    WHERE o.candidate_id=c.id AND o.hunt_run_id=$2::uuid
  )
"""
OBSERVATIONS_QUERY = """
SELECT id, evidence_refs
FROM investigation_candidate_observations
WHERE candidate_id=$1::uuid AND hunt_run_id=$2::uuid
ORDER BY observed_at DESC, id DESC LIMIT $3
"""
EVIDENCE_QUERY = """
SELECT a.id, 'hunt_action' AS kind
FROM hunt_actions a
WHERE a.id=ANY($1::uuid[]) AND a.hunt_run_id=$2::uuid
UNION
SELECT r.id, 'tool_receipt' AS kind
FROM tool_receipts r JOIN hunt_actions a ON a.receipt_id=r.id
WHERE r.id=ANY($1::uuid[]) AND a.hunt_run_id=$2::uuid
UNION
SELECT t.id, 'http_transaction' AS kind
FROM http_transactions t
WHERE t.id=ANY($1::uuid[]) AND t.hunt_run_id=$2::uuid
  AND t.plane='hunt' AND t.scan_id IS NULL
  AND ((t.target_id=$3::uuid AND t.device_target_id IS NULL)
    OR (t.device_target_id=$4::uuid AND t.target_id IS NULL))
"""


class BoundaryContextError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _uuid(value: Any) -> str:
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise BoundaryContextError("invalid_context_identifier") from exc


def _json(value: Any, expected: type) -> Any:
    """Bound JSON parsing; never interpret a Python repr or evaluate stored text."""
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_JSON_BYTES:
            raise BoundaryContextError("stored_context_too_large")
        try:
            value = json.loads(value)
        except (ValueError, RecursionError) as exc:
            raise BoundaryContextError("stored_context_not_json") from exc
    if not isinstance(value, expected):
        raise BoundaryContextError("stored_context_wrong_type")
    try:
        size = len(json.dumps(value, allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise BoundaryContextError("stored_context_not_json") from exc
    if size > MAX_JSON_BYTES:
        raise BoundaryContextError("stored_context_too_large")
    return value


def _context_summary(locus: Any, kind: str | None) -> dict[str, Any]:
    issues: list[str] = []
    context: dict[str, Any] = {}
    try:
        source = _json(locus, dict)
        raw = source.get("ai_boundary_context")
        if raw is not None:
            # Older PR revisions stored str(dict), possibly truncated. Do not
            # guess a repair or silently reinterpret it as an empty context.
            if not isinstance(raw, dict):
                issues.append("boundary_context_not_structured")
            else:
                context = _json(raw, dict)
    except BoundaryContextError as exc:
        issues.append(exc.code)
    present = sorted(_KNOWN_FIELDS.intersection(context))
    required = _REQUIRED_FIELDS.get(kind, ())
    return {
        "present_fields": present,
        "missing_fields": [key for key in required if key not in context],
        "issues": issues,
        "values_returned": False,
        "field_presence_is_not_validation": True,
        "unassessed": ["principal_bindings", "business_policy", "postcondition_validity"],
    }


async def inspect_candidate_boundary_context(
    conn: Any, *, run: Mapping[str, Any], candidate_id: str,
) -> dict[str, Any]:
    """Load exactly one Hunt-owned candidate and bounded, run-local references.

    The caller supplies a server-loaded Hunt row and a read-only snapshot. This
    function issues SELECTs only and never calls a compiler, queue or verifier.
    """
    hunt_id, candidate_id = _uuid(run.get("id")), _uuid(candidate_id)
    target_id = _uuid(run["target_id"]) if run.get("target_id") else None
    device_id = _uuid(run["device_target_id"]) if run.get("device_target_id") else None
    if (target_id is None) == (device_id is None):
        raise BoundaryContextError("candidate_not_found")
    candidate = await conn.fetchrow(CANDIDATE_QUERY, candidate_id, hunt_id, target_id, device_id)
    if candidate is None:
        raise BoundaryContextError("candidate_not_found")
    rows = await conn.fetch(OBSERVATIONS_QUERY, candidate_id, hunt_id, MAX_OBSERVATIONS + 1)
    observations_truncated = len(rows) > MAX_OBSERVATIONS
    references: list[str] = []
    malformed = 0
    references_truncated = False
    issues: set[str] = set()
    for row in rows[:MAX_OBSERVATIONS]:
        try:
            values = _json(row["evidence_refs"], list)
        except BoundaryContextError:
            issues.add("observation_references_malformed")
            continue
        if len(values) > MAX_REFERENCES:
            references_truncated = True
        for value in values[:MAX_REFERENCES]:
            try:
                reference = _uuid(value)
            except BoundaryContextError:
                malformed += 1
                continue
            if reference not in references:
                if len(references) >= MAX_REFERENCES:
                    references_truncated = True
                else:
                    references.append(reference)
    matches: dict[str, set[str]] = defaultdict(set)
    if references:
        evidence = await conn.fetch(EVIDENCE_QUERY, references, hunt_id, target_id, device_id)
        for item in evidence:
            reference = str(item["id"])
            if reference in references:
                matches[reference].add(item["kind"])
    resolved = []
    unavailable = ambiguous = 0
    for reference in references:
        kinds = matches[reference]
        if len(kinds) != 1:
            unavailable += not kinds
            ambiguous += len(kinds) > 1
            continue
        resolved.append({"id": reference, "kind": next(iter(kinds)), "association_checked": True})
    # Unresolved IDs are not echoed: refs are caller-authored and may point to
    # another run. Missing and out-of-scope records are deliberately indistinguishable.
    kind = _FAMILIES.get(str(candidate["family"]))
    context = _context_summary(candidate["canonical_locus"], kind)
    evidence_complete = bool(resolved) and not any((
        malformed, unavailable, ambiguous, observations_truncated,
        references_truncated, issues,
    ))
    return {
        "schema_version": "hunt-boundary-context/v1",
        "hunt_id": hunt_id,
        "candidate_id": candidate_id,
        "kind": kind,
        "candidate_status": candidate["status"] if candidate["status"] in _CANDIDATE_STATUSES else "unknown",
        "status": "context_available" if kind and evidence_complete and not context["issues"] and not context["missing_fields"] else "needs_context",
        "context": context,
        "evidence": {
            "resolved": resolved,
            "unavailable_count": unavailable,
            "ambiguous_count": ambiguous,
            "malformed_reference_count": malformed,
            "observations_read": min(len(rows), MAX_OBSERVATIONS),
            "observations_truncated": observations_truncated,
            "references_truncated": references_truncated,
            "issues": sorted(issues),
            "complete_for_inspected_references": evidence_complete,
            "content_integrity_verified": False,
            "supported_reference_kinds": ["hunt_action", "tool_receipt", "http_transaction"],
        },
        "execution_enabled": False,
        "proposal_compiled": False,
        "verification_performed": False,
        "promotion_authority": False,
    }
