"""Real API model/catalog imports; run with scanner/requirements.lock installed."""

from __future__ import annotations

from pathlib import Path
import json

import pytest
from fastapi import HTTPException

from ai_gate.boundary import PACK
from ai_gate.boundary.contract import BoundaryContract
from ai_targets import router


def test_api_admission_includes_the_canonical_boundary_pack():
    assert PACK in router.AI_PROBE_PACKS
    request = router.AITargetScanRequest(probe_pack=PACK, scan_profile="standard", environment="staging")
    assert request.probe_pack == PACK


def test_shipped_example_uses_existing_principal_roles():
    raw = json.loads((Path(__file__).resolve().parents[1] / "examples/ai-boundary/customer-read-contract.json").read_text())
    contract = BoundaryContract.parse(raw)
    assert {contract.owner.role, contract.attacker.role} <= router.AI_PRINCIPAL_ROLES


@pytest.mark.asyncio
async def test_api_boundary_admission_does_not_bypass_normal_submission(monkeypatch):
    class ReachedNormalSubmission(Exception):
        pass

    def get_redis():
        # This is immediately after enum validation and before durable lookup.
        raise ReachedNormalSubmission

    monkeypatch.setattr(router, "get_redis", get_redis)
    with pytest.raises(ReachedNormalSubmission):
        await router._queue_ai_target_scan(
            "00000000-0000-0000-0000-000000000001",
            router.AITargetScanRequest(probe_pack=PACK, scan_profile="standard", environment="preview"))


@pytest.mark.asyncio
async def test_boundary_verify_materializes_then_uses_canonical_queue(monkeypatch):
    class FakeConn:
        async def fetchrow(self, query, *_args):
            if "FROM ai_targets" in query:
                return {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "name": "Support agent",
                    "target_type": "api_chat",
                    "endpoint_url": "https://agent.example.test/chat",
                    "method": "POST",
                    "headers_template": {},
                    "request_template": {"message": "{{prompt}}", "session_id": "{{session_id}}"},
                    "response_path": "answer",
                    "streaming_mode": "json",
                    "rate_limit_rps": 2,
                    "token_budget": 32000,
                    "request_budget": 64,
                    "production_mode": False,
                    "metadata_json": {},
                    "is_active": True,
                }
            return None
        async def fetch(self, *_args):
            return []

    class Acquire:
        async def __aenter__(self): return FakeConn()
        async def __aexit__(self, *_args): return False

    class Pool:
        def acquire(self): return Acquire()

    monkeypatch.setattr(router, "_pool_provider", lambda: Pool())
    monkeypatch.setattr(router, "_resolve_ai_gate_credential_refs", lambda *a, **k: None)

    async def refs(*_args, **_kwargs):
        return None, []
    monkeypatch.setattr(router, "_resolve_ai_gate_credential_refs", refs)

    captured = {}
    async def queue(target_id, request, **kwargs):
        captured.update(target_id=target_id, request=request, kwargs=kwargs)
        return {"scan_id": "scan-1", "status": "queued", "probe_pack": request.probe_pack}
    monkeypatch.setattr(router, "_queue_ai_target_scan", queue)

    hypothesis = {
        "version": 1, "hypothesis_id": "hunt-read", "kind": "cross_tenant_read",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "provenance": [{"kind": "hunt_candidate", "id": "candidate-1"}],
    }
    from ai_gate.boundary.hypothesis import compile_boundary_hypothesis
    proposal = compile_boundary_hypothesis(hypothesis)
    base = {
        "version": 1, "name": "support-agent-boundary",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "identity": {"path": "/identity", "subject_field": "subject", "tenant_field": "tenant"},
        "resource": {"path": "/documents/{{resource_id}}", "id_field": "id", "owner_field": "owner", "tenant_field": "tenant", "marker_field": "marker"},
        "response_path": "answer",
    }
    result = await router.verify_ai_boundary_proposal(
        "00000000-0000-0000-0000-000000000001",
        router.AIBoundaryVerifyRequest(proposal=proposal, boundary_base=base),
    )
    assert result["status"] == "queued"
    assert captured["request"].probe_pack == "shaker-ai-boundary"
    override = captured["kwargs"]["target_override"]
    assert override["metadata_json"]["boundary_contract"]["name"] == "support-agent-boundary"
    assert override["metadata_json"]["boundary_proposal"]["provenance"][0]["id"] == "candidate-1"


@pytest.mark.asyncio
async def test_boundary_verify_refuses_production_before_queue():
    from ai_gate.boundary.hypothesis import compile_boundary_hypothesis
    proposal = compile_boundary_hypothesis({
        "version": 1, "hypothesis_id": "hunt-read", "kind": "cross_tenant_read",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "provenance": [{"kind": "hunt_candidate", "id": "candidate-1"}],
    })
    base = {
        "version": 1, "name": "support-agent-boundary",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "identity": {"path": "/identity", "subject_field": "subject", "tenant_field": "tenant"},
        "resource": {"path": "/documents/{{resource_id}}", "id_field": "id", "owner_field": "owner", "tenant_field": "tenant", "marker_field": "marker"},
        "response_path": "answer",
    }
    with pytest.raises(HTTPException) as exc:
        await router.verify_ai_boundary_proposal(
            "00000000-0000-0000-0000-000000000001",
            router.AIBoundaryVerifyRequest(
                proposal=proposal, boundary_base=base, environment="production"
            ),
        )
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_boundary_verify_rejects_hunt_discovery_bound_to_different_ai_endpoint(monkeypatch):
    class FakeConn:
        async def fetchrow(self, query, *_args):
            if "FROM ai_targets" in query:
                return {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "name": "Different agent",
                    "target_type": "api_chat",
                    "endpoint_url": "https://other.example.test/chat",
                    "method": "POST",
                    "headers_template": {},
                    "request_template": {"message": "{{prompt}}"},
                    "response_path": "answer",
                    "streaming_mode": "json",
                    "rate_limit_rps": 2,
                    "token_budget": 32000,
                    "request_budget": 64,
                    "production_mode": False,
                    "metadata_json": {},
                    "is_active": True,
                }
            return None
        async def fetch(self, *_args):
            return []

    class Acquire:
        async def __aenter__(self): return FakeConn()
        async def __aexit__(self, *_args): return False
    class Pool:
        def acquire(self): return Acquire()

    monkeypatch.setattr(router, "_pool_provider", lambda: Pool())
    async def forbidden_queue(*_args, **_kwargs):
        raise AssertionError("mismatched discovery provenance must fail before queueing")
    monkeypatch.setattr(router, "_queue_ai_target_scan", forbidden_queue)

    from ai_gate.boundary.hypothesis import compile_boundary_hypothesis
    proposal = compile_boundary_hypothesis({
        "version": 1, "hypothesis_id": "hunt-read", "kind": "cross_tenant_read",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "provenance": [{"kind": "hunt_candidate", "id": "candidate-1"}],
    })
    proposal["source_binding"] = {
        "schema_version": "hunt-boundary-source/v1",
        "hunt_id": "00000000-0000-0000-0000-000000000010",
        "target_id": "00000000-0000-0000-0000-000000000020",
        "origin": "https://agent.example.test",
        "agent_paths": ["/chat"],
    }
    base = {
        "version": 1, "name": "support-agent-boundary",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "identity": {"path": "/identity", "subject_field": "subject", "tenant_field": "tenant"},
        "resource": {"path": "/documents/{{resource_id}}", "id_field": "id", "owner_field": "owner", "tenant_field": "tenant", "marker_field": "marker"},
        "response_path": "answer",
    }
    with pytest.raises(HTTPException) as exc:
        await router.verify_ai_boundary_proposal(
            "00000000-0000-0000-0000-000000000001",
            router.AIBoundaryVerifyRequest(proposal=proposal, boundary_base=base),
        )
    assert exc.value.status_code == 409
    assert "discovery source binding" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_boundary_verify_accepts_matching_hunt_discovery_endpoint(monkeypatch):
    class FakeConn:
        async def fetchrow(self, query, *_args):
            if "FROM ai_targets" in query:
                return {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "name": "Observed agent",
                    "target_type": "api_chat",
                    "endpoint_url": "https://agent.example.test:443/chat",
                    "method": "POST",
                    "headers_template": {},
                    "request_template": {"message": "{{prompt}}"},
                    "response_path": "answer",
                    "streaming_mode": "json",
                    "rate_limit_rps": 2,
                    "token_budget": 32000,
                    "request_budget": 64,
                    "production_mode": False,
                    "metadata_json": {},
                    "is_active": True,
                }
            return None
        async def fetch(self, query, *_args):
            if "FROM ai_target_principals" in query:
                return [
                    {"role": "victim", "label": "victim"},
                    {"role": "attacker", "label": "attacker"},
                ]
            return []
    class Acquire:
        async def __aenter__(self): return FakeConn()
        async def __aexit__(self, *_args): return False
    class Pool:
        def acquire(self): return Acquire()

    monkeypatch.setattr(router, "_pool_provider", lambda: Pool())
    async def refs(*_args, **_kwargs):
        return None, []
    monkeypatch.setattr(router, "_resolve_ai_gate_credential_refs", refs)
    captured = {}
    async def queue(target_id, request, **kwargs):
        captured["override"] = kwargs["target_override"]
        return {"scan_id": "scan-bound", "status": "queued"}
    monkeypatch.setattr(router, "_queue_ai_target_scan", queue)

    from ai_gate.boundary.hypothesis import compile_boundary_hypothesis
    proposal = compile_boundary_hypothesis({
        "version": 1, "hypothesis_id": "hunt-read", "kind": "cross_tenant_read",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "provenance": [{"kind": "hunt_candidate", "id": "candidate-1"}],
    })
    proposal["source_binding"] = {
        "schema_version": "hunt-boundary-source/v1",
        "hunt_id": "00000000-0000-0000-0000-000000000010",
        "target_id": "00000000-0000-0000-0000-000000000020",
        "origin": "https://agent.example.test",
        "agent_paths": ["/chat"],
    }
    base = {
        "version": 1, "name": "support-agent-boundary",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "identity": {"path": "/identity", "subject_field": "subject", "tenant_field": "tenant"},
        "resource": {"path": "/documents/{{resource_id}}", "id_field": "id", "owner_field": "owner", "tenant_field": "tenant", "marker_field": "marker"},
        "response_path": "answer",
    }
    result = await router.verify_ai_boundary_proposal(
        "00000000-0000-0000-0000-000000000001",
        router.AIBoundaryVerifyRequest(proposal=proposal, boundary_base=base),
    )
    assert result["status"] == "queued"
    stored = captured["override"]["metadata_json"]["boundary_proposal"]["source_binding"]
    assert stored["origin"] == "https://agent.example.test"
    assert stored["agent_paths"] == ["/chat"]


@pytest.mark.asyncio
async def test_discovery_verification_requires_both_declared_roles_on_ai_target(monkeypatch):
    class FakeConn:
        async def fetchrow(self, query, *_args):
            if "FROM ai_targets" in query:
                return {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "name": "Observed agent",
                    "target_type": "api_chat",
                    "endpoint_url": "https://agent.example.test/chat",
                    "method": "POST",
                    "headers_template": {},
                    "request_template": {"message": "{{prompt}}"},
                    "response_path": "answer",
                    "streaming_mode": "json",
                    "rate_limit_rps": 2,
                    "token_budget": 32000,
                    "request_budget": 64,
                    "production_mode": False,
                    "metadata_json": {},
                    "is_active": True,
                }
            return None
        async def fetch(self, query, *_args):
            if "FROM ai_target_principals" in query:
                return [{"role": "victim", "label": "victim"}]
            return []
    class Acquire:
        async def __aenter__(self): return FakeConn()
        async def __aexit__(self, *_args): return False
    class Pool:
        def acquire(self): return Acquire()

    monkeypatch.setattr(router, "_pool_provider", lambda: Pool())
    from ai_gate.boundary.hypothesis import compile_boundary_hypothesis
    proposal = compile_boundary_hypothesis({
        "version": 1, "hypothesis_id": "hunt-read", "kind": "cross_tenant_read",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "provenance": [{"kind": "hunt_candidate", "id": "candidate-1"}],
    })
    proposal["source_binding"] = {
        "schema_version": "hunt-boundary-source/v1",
        "hunt_id": "00000000-0000-0000-0000-000000000010",
        "target_id": "00000000-0000-0000-0000-000000000020",
        "origin": "https://agent.example.test",
        "agent_paths": ["/chat"],
    }
    base = {
        "version": 1, "name": "support-agent-boundary",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "identity": {"path": "/identity", "subject_field": "subject", "tenant_field": "tenant"},
        "resource": {"path": "/documents/{{resource_id}}", "id_field": "id", "owner_field": "owner", "tenant_field": "tenant", "marker_field": "marker"},
        "response_path": "answer",
    }
    with pytest.raises(HTTPException) as exc:
        await router.verify_ai_boundary_proposal(
            "00000000-0000-0000-0000-000000000001",
            router.AIBoundaryVerifyRequest(proposal=proposal, boundary_base=base),
        )
    assert exc.value.status_code == 409
    assert "attacker" in str(exc.value.detail)

@pytest.mark.asyncio
async def test_discovery_verification_rejects_ambiguous_declared_roles_before_queue(monkeypatch):
    class FakeConn:
        async def fetchrow(self, query, *_args):
            if "FROM ai_targets" in query:
                return {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "name": "Observed agent",
                    "target_type": "api_chat",
                    "endpoint_url": "https://agent.example.test/chat",
                    "method": "POST",
                    "headers_template": {},
                    "request_template": {"message": "{{prompt}}"},
                    "response_path": "answer",
                    "streaming_mode": "json",
                    "rate_limit_rps": 2,
                    "token_budget": 32000,
                    "request_budget": 64,
                    "production_mode": False,
                    "metadata_json": {},
                    "is_active": True,
                }
            return None

        async def fetch(self, query, *_args):
            if "FROM ai_target_principals" in query:
                return [
                    {"role": "victim", "label": "victim"},
                    {"role": "attacker", "label": "attacker-a"},
                    {"role": "attacker", "label": "attacker-b"},
                ]
            return []

    class Acquire:
        async def __aenter__(self): return FakeConn()
        async def __aexit__(self, *_args): return False

    class Pool:
        def acquire(self): return Acquire()

    monkeypatch.setattr(router, "_pool_provider", lambda: Pool())

    async def forbidden_refs(*_args, **_kwargs):
        raise AssertionError("ambiguous role must fail before credential resolution")

    async def forbidden_queue(*_args, **_kwargs):
        raise AssertionError("ambiguous role must fail before queueing")

    monkeypatch.setattr(router, "_resolve_ai_gate_credential_refs", forbidden_refs)
    monkeypatch.setattr(router, "_queue_ai_target_scan", forbidden_queue)

    from ai_gate.boundary.hypothesis import compile_boundary_hypothesis
    proposal = compile_boundary_hypothesis({
        "version": 1, "hypothesis_id": "hunt-read", "kind": "cross_tenant_read",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "provenance": [{"kind": "hunt_candidate", "id": "candidate-1"}],
    })
    proposal["source_binding"] = {
        "schema_version": "hunt-boundary-source/v1",
        "hunt_id": "00000000-0000-0000-0000-000000000010",
        "target_id": "00000000-0000-0000-0000-000000000020",
        "origin": "https://agent.example.test",
        "agent_paths": ["/chat"],
    }
    base = {
        "version": 1, "name": "support-agent-boundary",
        "owner": {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"},
        "identity": {"path": "/identity", "subject_field": "subject", "tenant_field": "tenant"},
        "resource": {"path": "/documents/{{resource_id}}", "id_field": "id", "owner_field": "owner", "tenant_field": "tenant", "marker_field": "marker"},
        "response_path": "answer",
    }

    with pytest.raises(HTTPException) as exc:
        await router.verify_ai_boundary_proposal(
            "00000000-0000-0000-0000-000000000001",
            router.AIBoundaryVerifyRequest(proposal=proposal, boundary_base=base),
        )
    assert exc.value.status_code == 409
    assert "exactly one active AI target principal" in str(exc.value.detail)
    assert "attacker" in str(exc.value.detail)

