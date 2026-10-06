"""Server-loaded, read-only candidate handoff to the AI Boundary compiler."""
from __future__ import annotations

import json

import pytest

from api.hunt.boundary_context import BoundaryContextError
from api.hunt.boundary_handoff import compile_candidate_boundary_handoff
from api.hunt import interaction_router
from fastapi import HTTPException
from tests.test_hunt_boundary_context import (
    ACTION, CANDIDATE, DB, HUNT, OTHER, RUN, SECRET, uid,
)


PRINCIPALS = {
    "owner": {"role": "owner", "subject": "owner-user", "tenant": "tenant-a", "resource_id": "order-a"},
    "attacker": {"role": "attacker", "subject": "attacker-user", "tenant": "tenant-b", "resource_id": "order-b"},
}


def ready_db(*, source_binding=None) -> DB:
    db = DB()
    db.db.execute("UPDATE investigation_candidates SET canonical_locus=?", (
        json.dumps({"route": "/orders/order-a", "ai_boundary_context": {
            "prompt": "Refund the order.", "verifier_path": "/orders/order-a",
            "state_path": "status", "initial_value": "paid", "forbidden_value": "refunded",
            "approval_path": "/approvals/order-a", "approval_state_path": "state",
            "required_approval_value": "approved",
        }}),
    ))
    if source_binding is not None:
        db.db.execute(
            """UPDATE investigation_candidate_observations
               SET source_kind='hunt_boundary_discovery', observation_context=?""",
            (json.dumps({
                "boundary_source_binding": source_binding,
                "authoritative": False,
            }),),
        )
    db.guard()
    return db


async def handoff(db: DB, *, run=RUN, expected_rule=None):
    return await compile_candidate_boundary_handoff(
        db, run=run, candidate_id=CANDIDATE,
        principal_context=PRINCIPALS, expected_rule=expected_rule,
    )


@pytest.mark.asyncio
async def test_handoff_compiles_run_local_candidate_without_promoting_policy_or_proof():
    db = ready_db()
    result = await handoff(db)
    assert result["status"] == "needs_context"
    assert result["missing_facts"] == ["expected_rule", "expected_rule_source"]
    assert result["proposal_compiled"] is True
    assert result["execution_enabled"] is False
    assert result["verification_performed"] is False
    assert result["principal_bindings_verified"] is False
    assert SECRET not in json.dumps(result)
    assert all(query.lstrip().startswith("SELECT") for query in db.queries)


@pytest.mark.asyncio
async def test_explicit_operator_rule_makes_structural_proposal_ready():
    result = await handoff(ready_db(), expected_rule="Manager approval is required for refunds.")
    assert result["status"] == "ready"
    assert result["business_policy_verified"] is False
    assert result["proposal"]["contract_fragment"]["approval"]["verifier_path"] == "/orders/order-a"
    assert [item["id"] for item in result["proposal"]["provenance"][1:]] == [
        item["id"] for item in result["candidate_context"]["evidence"]["resolved"]
    ]


@pytest.mark.asyncio
async def test_other_hunt_cannot_compile_shared_candidate():
    db = ready_db()
    with pytest.raises(BoundaryContextError, match="candidate_not_found"):
        await handoff(db, run={**RUN, "id": OTHER})


@pytest.mark.asyncio
async def test_unresolved_reference_blocks_compilation_without_echoing_id():
    db = DB()
    foreign_id = uid(999)
    db.db.execute("UPDATE investigation_candidate_observations SET evidence_refs=?", (
        json.dumps([foreign_id]),
    ))
    db.guard()
    result = await handoff(db, expected_rule="Manager approval is required.")
    assert result["proposal"] is None
    assert result["missing_facts"] == ["run_local_evidence_association"]
    assert foreign_id not in json.dumps(result)


@pytest.mark.asyncio
async def test_generic_bola_is_not_automatically_an_ai_boundary():
    db = DB()
    db.db.execute("UPDATE investigation_candidates SET family='bola'")
    db.guard()
    result = await handoff(db)
    assert result["proposal"] is None
    assert result["missing_facts"] == ["supported_ai_boundary_family"]


@pytest.mark.asyncio
async def test_legacy_malformed_context_cannot_be_compiled():
    db = DB()
    db.db.execute("UPDATE investigation_candidates SET canonical_locus=?", (
        json.dumps({"ai_boundary_context": "{'prompt': 'untrusted'}"}),
    ))
    db.guard()
    result = await handoff(db)
    assert result["proposal"] is None
    assert result["missing_facts"] == ["structured_boundary_context"]
    assert "untrusted" not in json.dumps(result)


@pytest.mark.asyncio
async def test_route_uses_hunt_lookup_and_read_only_snapshot(monkeypatch):
    db = ready_db()

    async def run_lookup(conn, hunt_id):
        assert conn is db and hunt_id == HUNT
        return RUN

    monkeypatch.setattr(interaction_router, "_pool", lambda: db)
    monkeypatch.setattr(interaction_router, "_hunt_run_or_404", run_lookup)
    request = interaction_router.HuntBoundaryHandoffRequest(
        owner=PRINCIPALS["owner"], attacker=PRINCIPALS["attacker"],
        expected_rule="Manager approval is required for refunds.",
    )
    result = await interaction_router.compile_hunt_candidate_boundary_proposal(
        HUNT, CANDIDATE, request,
    )
    assert result["status"] == "ready"
    assert db.transactions == [{"isolation": "repeatable_read", "readonly": True}]
    with pytest.raises(HTTPException) as exc:
        await interaction_router.compile_hunt_candidate_boundary_proposal(
            HUNT, uid(999), request,
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_discovery_source_binding_survives_server_loaded_handoff():
    source = {
        "schema_version": "hunt-boundary-source/v1",
        "hunt_id": RUN["id"],
        "target_id": RUN["target_id"],
        "origin": "https://agent.example.test",
        "agent_paths": ["/chat"],
    }
    result = await handoff(
        ready_db(source_binding=source),
        expected_rule="Manager approval is required for refunds.",
    )
    assert result["status"] == "ready"
    assert result["proposal"]["source_binding"] == source


@pytest.mark.asyncio
async def test_discovery_source_binding_cannot_switch_hunt_or_target():
    source = {
        "schema_version": "hunt-boundary-source/v1",
        "hunt_id": OTHER,
        "target_id": RUN["target_id"],
        "origin": "https://agent.example.test",
        "agent_paths": ["/chat"],
    }
    with pytest.raises(BoundaryContextError, match="boundary_source_hunt_mismatch"):
        await handoff(
            ready_db(source_binding=source),
            expected_rule="Manager approval is required for refunds.",
        )

