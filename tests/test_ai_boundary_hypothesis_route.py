from __future__ import annotations

import pytest
from fastapi import HTTPException

from ai_targets import router


@pytest.mark.asyncio
async def test_boundary_hypothesis_compile_route_is_dry_run():
    request = router.AIBoundaryHypothesisCompileRequest(hypothesis={
        "version": 1,
        "hypothesis_id": "hunt-agent-read",
        "kind": "cross_tenant_read",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "provenance": [{"kind": "hunt_candidate", "id": "candidate-1"}],
    })
    result = await router.compile_ai_boundary_hypothesis(request)
    assert result["proposal"]["status"] == "ready"
    assert result["execution_enabled"] is False
    assert result["planning_authority"] is False
    assert result["promotion_authority"] is False


@pytest.mark.asyncio
async def test_boundary_hypothesis_compile_route_returns_422_for_bad_contract():
    request = router.AIBoundaryHypothesisCompileRequest(hypothesis={
        "version": 1,
        "hypothesis_id": "bad",
        "kind": "cross_tenant_read",
        "owner": {"role": "same", "subject": "same", "tenant": "same", "resource_id": "same"},
        "attacker": {"role": "same", "subject": "same", "tenant": "same", "resource_id": "same"},
        "provenance": [{"kind": "hunt_candidate", "id": "candidate-1"}],
    })
    with pytest.raises(HTTPException) as exc:
        await router.compile_ai_boundary_hypothesis(request)
    assert exc.value.status_code == 422


def test_boundary_pack_is_admitted_by_ai_target_router():
    assert "shaker-ai-boundary" in router.AI_PROBE_PACKS


@pytest.mark.asyncio
async def test_ready_proposal_can_be_materialized_without_execution():
    hypothesis = {
        "version": 1,
        "hypothesis_id": "hunt-agent-action",
        "kind": "cross_tenant_action",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "expected_rule": "A tenant may update only its own document.",
        "expected_rule_source": "operator",
        "verifier_path": "/documents/doc-a",
        "state_path": "status",
        "initial_value": "draft",
        "forbidden_value": "published",
        "prompt": "Publish document doc-a.",
        "provenance": [{"kind": "hunt_candidate", "id": "candidate-2"}],
    }
    proposal = (await router.compile_ai_boundary_hypothesis(
        router.AIBoundaryHypothesisCompileRequest(hypothesis=hypothesis)
    ))["proposal"]
    base = {
        "version": 1,
        "name": "agent-boundary",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "identity": {"path": "/identity", "subject_field": "subject", "tenant_field": "tenant"},
        "resource": {
            "path": "/documents/{{resource_id}}",
            "id_field": "id",
            "owner_field": "owner",
            "tenant_field": "tenant",
            "marker_field": "marker",
        },
        "response_path": "answer",
    }
    result = await router.materialize_ai_boundary_proposal(
        router.AIBoundaryMaterializeRequest(proposal=proposal, boundary_base=base)
    )
    assert result["probe_pack"] == "shaker-ai-boundary"
    assert result["execution_enabled"] is False
    assert result["materialization"]["boundary_contract"]["action"]["forbidden_value"] == "published"
