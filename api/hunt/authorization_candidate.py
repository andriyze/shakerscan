"""Materialize a proven-to-have-happened authorization lead as a non-authoritative candidate.

Selected-object mode deliberately does not claim that cross-access is forbidden: the access rule
comes from business context.  But once the operator reviewed a proposal with expected_access=denied
and the canonical authz action reproduced stable access to the exact selected object, silently
leaving the result as an isolated workflow response makes Hunt lose a useful lead.

This module bridges that result into the existing investigation_candidates store.  The candidate is
explicitly unverified, has no verifier contract, and carries only canonical action/receipt/
transaction references.  It cannot mutate finding proof state.
"""
from __future__ import annotations

from typing import Any, Mapping
import uuid

try:
    import investigation_candidates
except ModuleNotFoundError:
    from .. import investigation_candidates

from .authorization_evidence import AuthorizationWorkflowError, mapping
from .authorization_repository import uid


LINK_TYPE = "authorization_candidate_link"
SOURCE_KIND = "hunt_authorization"


def candidate_plan(state: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return the bounded candidate material for one exact potential violation.

    Nothing is produced for unknown/shared/denied/incomplete outcomes.  A selected-object crossing
    remains technical access evidence, not authorization proof, so the returned plan has no
    verifier contract and says so in both its claim and observation context.
    """
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


async def ensure_authorization_candidate(service: Any, hunt_id: Any, state: Mapping[str, Any]) -> dict[str, Any]:
    """Create at most one candidate observation for this proposal attempt, transactionally.

    Re-approving the same canonical attempt is idempotent. A later real retry may append a new
    observation to the same fingerprint because it is new evidence, while the deterministic link
    prevents repeated reads/retries of one action from spamming the observation ledger.
    """
    plan = candidate_plan(state)
    result = dict(state)
    if plan is None:
        result["candidate"] = None
        return result

    proposal_id = uid(state.get("proposal_id"))
    action_id = str(plan["observation_context"]["action_id"])
    link_key = f"authz:{proposal_id}:candidate:{action_id}"
    link_id = uuid.uuid5(proposal_id, f"candidate:{action_id}")

    async with service.pool.acquire() as conn:
        async with conn.transaction():
            run = await service.repo.run(conn, hunt_id)
            row = await conn.fetchrow(
                "SELECT attributes FROM application_graph_nodes WHERE target_id=$1 "
                "AND node_type=$2 AND node_key=$3",
                uid(run["target_id"]), LINK_TYPE, link_key,
            )
            link = mapping(dict(row).get("attributes")) if row else {}
            if link:
                candidate_id = link.get("candidate_id")
                existing = await conn.fetchrow(
                    "SELECT id,status,fingerprint FROM investigation_candidates WHERE id=$1::uuid",
                    str(candidate_id or ""),
                )
                if not existing:
                    raise AuthorizationWorkflowError(
                        "Authorization candidate link is inconsistent with the candidate store"
                    )
                item = dict(existing)
                result["candidate"] = {
                    "id": str(item["id"]), "status": str(item["status"]),
                    "fingerprint": str(item["fingerprint"]), "authoritative": False,
                    "created_from_attempt": plan["observation_context"]["attempt"],
                }
                return result

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
                 "candidate_fingerprint": created["fingerprint"],
                 "authoritative": False},
            )
            result["candidate"] = {
                "id": created["id"], "status": created["status"],
                "fingerprint": created["fingerprint"], "authoritative": False,
                "created_from_attempt": plan["observation_context"]["attempt"],
            }
    return result
