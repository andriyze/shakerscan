"""Retain an observed authorization lead without promoting it to proof.

Candidate creation requires the existing reviewed, receipt-backed crossing. Readback
preserves historical associations independently of a later attempt's assessment.
"""
from __future__ import annotations

from typing import Any, Mapping
import uuid

try:
    import investigation_candidates
except ModuleNotFoundError:
    from .. import investigation_candidates

from .authorization_evidence import AuthorizationWorkflowError, mapping
from .authorization_history import with_candidate_history
from .authorization_repository import MAX_ATTEMPTS, uid


LINK_TYPE = "authorization_candidate_link"
SOURCE_KIND = "hunt_authorization"


def candidate_plan(state: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return bounded material for a lead, never authorization proof."""
    attempts = state.get("attempts")
    latest = attempts[-1] if isinstance(attempts, list) and attempts else None
    if not isinstance(latest, Mapping):
        return None
    if (
        state.get("baseline_kind") != "own_object"
        or state.get("expected_access") != "denied"
        or state.get("authorization_assessment") != "potential_violation"
        or state.get("cross_access_observed") is not True
        or state.get("selected_request_examined") is not True
        or latest.get("cross_access_observed") is not True
        or latest.get("authorization_assessment") != "potential_violation"
        or latest.get("proof_state") != "inconclusive"
        or latest.get("certainty") != "observed"
        or not latest.get("action_id")
        or not latest.get("receipt_id")
    ):
        return None

    evidence_refs = []
    for value in [latest.get("action_id"), latest.get("receipt_id"), *(latest.get("transaction_ids") or [])]:
        text = str(value or "").strip()
        if text and text not in evidence_refs:
            evidence_refs.append(text[:120])
    if len(evidence_refs) < 2:
        return None

    route = str(state.get("route") or "").strip()[:1000]
    if not route:
        return None
    attempt = latest.get("attempt")
    if type(attempt) is not int or attempt < 1:
        return None

    return {
        "family": "bola",
        "locus": {"method": "GET", "route": route},
        "title": "Potential object authorization violation: cross-principal access reproduced",
        "claim": (
            "The canonical Hunt authorization action reproduced stable access by the secondary "
            "principal to the exact selected object while the reviewed proposal declared that "
            "access should be denied. This is an unverified authorization candidate: the "
            "technical crossing is evidenced, but the business entitlement still requires human "
            "review before a vulnerability can be asserted."
        ),
        "severity": "high",
        "evidence_refs": evidence_refs[:100],
        "verifier_contract_id": None,
        "observation_context": {
            "schema_version": "hunt-authorization-candidate/v1",
            "authorization_proposal_id": str(state.get("proposal_id") or ""),
            "authorization_proposal_digest": str(state.get("proposal_digest") or ""),
            "attempt": attempt,
            "action_id": str(latest["action_id"]),
            "receipt_id": str(latest["receipt_id"]),
            "expected_access": "denied",
            "expectation_source": "operator_declared_not_proof",
            "authorization_assessment": "potential_violation",
            "cross_access_observed": True,
            "proof_state": "inconclusive",
            "authoritative": False,
            "finding_promoted": False,
        },
    }


def _link_reference(state: Mapping[str, Any], plan: Mapping[str, Any]) -> tuple[Any, str, str, Any]:
    """The deterministic identity of this proposal attempt's candidate link."""
    proposal_id = uid(state.get("proposal_id"))
    action_id = str(plan["observation_context"]["action_id"])
    return (proposal_id, action_id, f"authz:{proposal_id}:candidate:{action_id}",
            uuid.uuid5(proposal_id, f"candidate:{action_id}"))


async def _linked_candidate(conn: Any, service: Any, hunt_id: Any, link_key: str,
                            attempt: Any) -> tuple[Mapping[str, Any], dict[str, Any] | None]:
    """Resolve an existing link within the Hunt's target, without creating one."""
    run = await service.repo.run(conn, hunt_id)
    row = await conn.fetchrow(
        "SELECT attributes FROM application_graph_nodes WHERE target_id=$1 "
        "AND node_type=$2 AND node_key=$3",
        uid(run["target_id"]), LINK_TYPE, link_key,
    )
    link = mapping(dict(row).get("attributes")) if row else {}
    if not link:
        return run, None
    existing = await conn.fetchrow(
        "SELECT id,status,fingerprint FROM investigation_candidates "
        "WHERE id=$1::uuid AND target_id=$2::uuid",
        str(link.get("candidate_id") or ""), str(run["target_id"]),
    )
    if not existing:
        raise AuthorizationWorkflowError(
            "Authorization candidate link is inconsistent with the candidate store"
        )
    item = dict(existing)
    return run, {
        "id": str(item["id"]), "status": str(item["status"]),
        "fingerprint": str(item["fingerprint"]), "authoritative": False,
        "created_from_attempt": attempt,
    }


async def attach_authorization_candidate(service: Any, hunt_id: Any, state: Mapping[str, Any]) -> dict[str, Any]:
    """Read every retained attempt association; a later result cannot erase history."""
    # These are immutable proposal properties, not the latest attempt's outcome.
    # Other proposal kinds have never materialized links through this bridge.
    if state.get("baseline_kind") != "own_object" or state.get("expected_access") != "denied":
        return with_candidate_history(state, [])
    attempts = state.get("attempts") or []
    if not isinstance(attempts, list) or len(attempts) > MAX_ATTEMPTS:
        raise AuthorizationWorkflowError("Invalid investigation attempt history")
    history = []
    if attempts:
        proposal_id = uid(state.get("proposal_id"))
        async with service.pool.acquire() as conn:
            for attempt in attempts:
                link_key = f"authz:{proposal_id}:candidate:{attempt['action_id']}"
                _, candidate = await _linked_candidate(
                    conn, service, hunt_id, link_key, attempt["attempt"])
                if candidate:
                    history.append(candidate)
    return with_candidate_history(state, history)


async def ensure_authorization_candidate(service: Any, hunt_id: Any, state: Mapping[str, Any]) -> dict[str, Any]:
    """Materialize at most one observation per proposal attempt, including concurrent retries.

    Lock the existing immutable proposal BEFORE checking its link. A transaction alone
    is insufficient: two READ COMMITTED callers can both observe a missing link. All
    writes and the link commit together; read-only requests never take this write path.
    """
    plan = candidate_plan(state)
    if plan is None:
        return await attach_authorization_candidate(service, hunt_id, state)

    proposal_id, action_id, link_key, link_id = _link_reference(state, plan)
    attempt = plan["observation_context"]["attempt"]
    async with service.pool.acquire() as conn:
        async with conn.transaction():
            run = await service.repo.run(conn, hunt_id)
            await service.repo.proposal(conn, run, proposal_id, lock=True)
            _, existing = await _linked_candidate(conn, service, hunt_id, link_key, attempt)
            if not existing:
                candidate = investigation_candidates.normalize_candidate(
                    plane="web", target_id=str(run["target_id"]), hunt_run_id=str(run["id"]),
                    family=plan["family"], locus=plan["locus"], title=plan["title"],
                    claim=plan["claim"], severity=plan["severity"],
                    evidence_refs=plan["evidence_refs"],
                    verifier_contract_id=plan["verifier_contract_id"], source_kind=SOURCE_KIND,
                )
                created = await investigation_candidates.upsert_candidate(
                    conn, candidate, created_by="hunt_authorization_workflow",
                    observation_context=plan["observation_context"],
                )
                await service.repo.insert_node(
                    conn, run, link_id, LINK_TYPE, link_key,
                    {"hunt_id": str(run["id"]), "proposal_id": str(proposal_id),
                     "action_id": action_id, "candidate_id": created["id"],
                     "candidate_fingerprint": created["fingerprint"], "authoritative": False},
                )
    return await attach_authorization_candidate(service, hunt_id, state)
