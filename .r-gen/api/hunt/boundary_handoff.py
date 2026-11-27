"""Read-only handoff from one Hunt-owned candidate to the AI Boundary compiler."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .boundary_context import CANDIDATE_QUERY, inspect_candidate_boundary_context, read_candidate_boundary_source_binding

try:
    from ai_gate.boundary.hypothesis import compile_hunt_candidate_boundary
except ModuleNotFoundError:  # package import in host-side tests
    from ..ai_gate.boundary.hypothesis import compile_hunt_candidate_boundary


async def compile_candidate_boundary_handoff(
    conn: Any, *, run: Mapping[str, Any], candidate_id: str,
    principal_context: dict[str, Any], expected_rule: str | None,
) -> dict[str, Any]:
    """Compile only a server-loaded candidate and associated evidence from this Hunt.

    The caller supplies controlled-principal declarations and, optionally, an
    explicit operator rule. These declarations are never promoted to observed
    facts; the deterministic verifier must establish the actual bindings.
    """
    inspection = await inspect_candidate_boundary_context(
        conn, run=run, candidate_id=candidate_id,
    )
    missing: list[str] = []
    if inspection["kind"] is None:
        missing.append("supported_ai_boundary_family")
    if not inspection["evidence"]["complete_for_inspected_references"]:
        missing.append("run_local_evidence_association")
    if inspection["context"]["issues"]:
        missing.append("structured_boundary_context")
    result: dict[str, Any] = {
        "schema_version": "hunt-boundary-handoff/v1",
        "hunt_id": inspection["hunt_id"],
        "candidate_id": inspection["candidate_id"],
        "status": "needs_context",
        "missing_facts": missing,
        "candidate_context": inspection,
        "proposal": None,
        "proposal_compiled": False,
        "execution_enabled": False,
        "verification_performed": False,
        "promotion_authority": False,
        "principal_bindings_verified": False,
        "business_policy_verified": False,
    }
    if missing:
        return result

    candidate = await conn.fetchrow(
        CANDIDATE_QUERY, inspection["candidate_id"], inspection["hunt_id"],
        str(run["target_id"]) if run.get("target_id") else None,
        str(run["device_target_id"]) if run.get("device_target_id") else None,
    )
    # The route holds a repeatable-read snapshot, so a vanished row indicates an
    # invalid caller transaction. Keep the same not-found behavior as inspection.
    if candidate is None:
        from .boundary_context import BoundaryContextError
        raise BoundaryContextError("candidate_not_found")
    references = [item["id"] for item in inspection["evidence"]["resolved"]]
    projected = compile_hunt_candidate_boundary(
        {
            "id": inspection["candidate_id"],
            "family": candidate["family"],
            "canonical_locus": candidate["canonical_locus"],
            "evidence_refs": references,
        },
        principal_context=principal_context,
        policy_context=(
            {"expected_rule": expected_rule, "expected_rule_source": "operator"}
            if expected_rule is not None else None
        ),
    )
    proposal = projected["proposal"]
    source_binding = await read_candidate_boundary_source_binding(
        conn, run=run, candidate_id=inspection["candidate_id"],
    )
    if source_binding is not None:
        proposal["source_binding"] = source_binding
    result.update(
        status=proposal["status"],
        missing_facts=proposal["missing_facts"],
        proposal=proposal,
        proposal_compiled=True,
        provenance_references_included=min(len(references), 20),
        provenance_references_omitted=max(0, len(references) - 20),
    )
    return result
