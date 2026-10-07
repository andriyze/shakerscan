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



# --- Hunt discovery provenance: admitted only against the Hunt record -----------

AI_TARGET_ID = "00000000-0000-0000-0000-000000000001"
HUNT_ID = "00000000-0000-4000-8000-000000000010"
HUNT_TARGET_ID = "00000000-0000-4000-8000-000000000020"
CANDIDATE_ID = "00000000-0000-4000-8000-000000000030"
CAPTURE_ID = "00000000-0000-4000-8000-000000000040"
OWNER = {"role": "victim", "subject": "user-a", "tenant": "tenant-a", "resource_id": "doc-a"}
ATTACKER = {"role": "attacker", "subject": "user-b", "tenant": "tenant-b", "resource_id": "doc-b"}


def _binding(**changes):
    return {
        "schema_version": "hunt-boundary-source/v1", "hunt_id": HUNT_ID,
        "target_id": HUNT_TARGET_ID, "origin": "https://agent.example.test",
        "agent_paths": ["/chat"], **changes,
    }


def _discovered_locus(**context):
    return {
        "method": "GET", "url": "https://agent.example.test/documents/{{resource_id}}",
        "route": "/documents/{{resource_id}}",
        "ai_boundary_context": {
            "discovery_draft_id": "a" * 64, "owner_resource_id": "doc-a",
            "attacker_resource_id": "doc-b", **context,
        },
    }


def _bound_proposal(*, provenance=None, owner=OWNER, attacker=ATTACKER, binding="default"):
    from ai_gate.boundary.hypothesis import compile_boundary_hypothesis
    proposal = compile_boundary_hypothesis({
        "version": 1, "hypothesis_id": f"hunt-{CANDIDATE_ID}", "kind": "cross_tenant_read",
        "owner": owner, "attacker": attacker,
        "provenance": provenance or [
            {"kind": "hunt_candidate", "id": CANDIDATE_ID}, {"kind": "evidence", "id": CAPTURE_ID},
        ],
    })
    if binding is not None:
        proposal["source_binding"] = _binding() if binding == "default" else binding
    return proposal


def _base(*, owner=OWNER, attacker=ATTACKER, path="/documents/{{resource_id}}"):
    return {
        "version": 1, "name": "support-agent-boundary", "owner": owner, "attacker": attacker,
        "identity": {"path": "/identity", "subject_field": "subject", "tenant_field": "tenant"},
        "resource": {"path": path, "id_field": "id", "owner_field": "owner",
                     "tenant_field": "tenant", "marker_field": "marker"},
        "response_path": "answer",
    }


class HuntRecordStore:
    """AI target rows plus the Hunt records the verify route must consult."""

    def __init__(self, *, endpoint="https://agent.example.test:443/chat", roles=("victim", "attacker"),
                 hunt_exists=True, hunt_target=HUNT_TARGET_ID, recorded="default", locus=None):
        self.endpoint, self.roles = endpoint, roles
        self.hunt_exists, self.hunt_target = hunt_exists, hunt_target
        self.recorded = _binding() if recorded == "default" else recorded
        self.locus = locus or _discovered_locus()
        self.queries = []

    async def fetchrow(self, query, *args):
        self.queries.append(query)
        if "FROM ai_targets" in query:
            return {
                "id": AI_TARGET_ID, "name": "Observed agent", "target_type": "api_chat",
                "endpoint_url": self.endpoint, "method": "POST", "headers_template": {},
                "request_template": {"message": "{{prompt}}"}, "response_path": "answer",
                "streaming_mode": "json", "rate_limit_rps": 2, "token_budget": 32000,
                "request_budget": 64, "production_mode": False, "metadata_json": {},
                "is_active": True,
            }
        if "FROM ai_target_credentials" in query:
            return None
        if "FROM hunt_runs" in query:
            if self.hunt_exists and str(args[0]) == HUNT_ID:
                return {"id": HUNT_ID, "target_id": self.hunt_target, "device_target_id": None}
            return None
        if "?|" in query:  # any discovery observation citing these candidates/captures
            cited = CANDIDATE_ID in args[0] or CAPTURE_ID in args[1]
            return {"candidate_id": CANDIDATE_ID} if cited and self.recorded else None
        if "FROM investigation_candidates c" in query:
            if str(args[0]) == CANDIDATE_ID and str(args[1]) == HUNT_ID:
                return {"id": CANDIDATE_ID, "family": "cross_tenant_retrieval",
                        "status": "new", "canonical_locus": json.dumps(self.locus)}
            return None
        if "investigation_candidate_observations" in query:  # this Hunt's latest binding
            if self.recorded and (str(args[0]), str(args[1])) == (CANDIDATE_ID, HUNT_ID):
                return {"observation_context": {"boundary_source_binding": self.recorded}}
            return None
        raise AssertionError(query)

    async def fetch(self, query, *_args):
        self.queries.append(query)
        if "FROM ai_target_principals" in query:
            return [{"role": role, "label": f"{role}-{index}"} for index, role in enumerate(self.roles)]
        raise AssertionError(query)


def _install(monkeypatch, store, *, queue_allowed=True):
    class Acquire:
        async def __aenter__(self): return store
        async def __aexit__(self, *_args): return False

    class Pool:
        def acquire(self): return Acquire()

    monkeypatch.setattr(router, "_pool_provider", lambda: Pool())
    captured = {}

    async def refs(*_args, **_kwargs):
        if not queue_allowed:
            raise AssertionError("refused provenance must fail before credential resolution")
        return None, []

    async def queue(target_id, request, **kwargs):
        if not queue_allowed:
            raise AssertionError("refused provenance must fail before queueing")
        captured.update(target_id=target_id, request=request, kwargs=kwargs)
        return {"scan_id": "scan-bound", "status": "queued"}

    monkeypatch.setattr(router, "_resolve_ai_gate_credential_refs", refs)
    monkeypatch.setattr(router, "_queue_ai_target_scan", queue)
    return captured


async def _verify(proposal, base=None):
    return await router.verify_ai_boundary_proposal(
        AI_TARGET_ID, router.AIBoundaryVerifyRequest(proposal=proposal, boundary_base=base or _base()),
    )


@pytest.mark.asyncio
async def test_discovery_binding_is_validated_against_hunt_then_queued_and_digest_bound(monkeypatch):
    store = HuntRecordStore()
    captured = _install(monkeypatch, store)
    result = await _verify(_bound_proposal())
    assert result["status"] == "queued"
    # The run receives the validated binding for persistence, and the executable
    # contract carries it so the recorded contract digest covers it.
    assert captured["kwargs"]["boundary_source_binding"] == _binding()
    contract = captured["kwargs"]["target_override"]["metadata_json"]["boundary_contract"]
    assert contract["source_binding"] == _binding()
    assert any("FROM hunt_runs" in query for query in store.queries)

    from ai_gate.boundary.hypothesis import materialize_boundary_contract
    bound = materialize_boundary_contract(_bound_proposal(), boundary_base=_base())
    unbound = materialize_boundary_contract(_bound_proposal(binding=None), boundary_base=_base())
    moved = materialize_boundary_contract(
        _bound_proposal(binding=_binding(agent_paths=["/v2/chat"])), boundary_base=_base(),
    )
    assert len({bound["boundary_contract_sha256"], unbound["boundary_contract_sha256"],
                moved["boundary_contract_sha256"]}) == 3


@pytest.mark.asyncio
async def test_boundary_verify_rejects_hunt_discovery_bound_to_different_ai_endpoint(monkeypatch):
    _install(monkeypatch, HuntRecordStore(endpoint="https://other.example.test/chat"), queue_allowed=False)
    with pytest.raises(HTTPException) as exc:
        await _verify(_bound_proposal())
    assert exc.value.status_code == 409
    assert "discovery source binding" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_discovery_verification_requires_both_declared_roles_on_ai_target(monkeypatch):
    _install(monkeypatch, HuntRecordStore(roles=("victim",)), queue_allowed=False)
    with pytest.raises(HTTPException) as exc:
        await _verify(_bound_proposal())
    assert exc.value.status_code == 409
    assert "attacker" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_discovery_verification_rejects_ambiguous_declared_roles_before_queue(monkeypatch):
    _install(monkeypatch, HuntRecordStore(roles=("victim", "attacker", "attacker")), queue_allowed=False)
    with pytest.raises(HTTPException) as exc:
        await _verify(_bound_proposal())
    assert exc.value.status_code == 409
    assert "exactly one active AI target principal" in str(exc.value.detail)
    assert "attacker" in str(exc.value.detail)


def _respelled(identifier):
    return identifier.replace("-", "").upper()


@pytest.mark.asyncio
@pytest.mark.parametrize("case, store_kwargs, proposal_kwargs, base_kwargs, code", [
    # Dropping the binding from a discovery-derived proposal no longer skips the gate,
    # even with a wrong endpoint and no principals on the selected AI target.
    ("stripped", {"endpoint": "https://other.example.test/chat", "roles": ()},
     {"binding": None}, {}, "boundary_source_binding_required"),
    ("stripped_candidate_kept_capture", {"endpoint": "https://other.example.test/chat"},
     {"binding": None, "provenance": [{"kind": "evidence", "id": CAPTURE_ID}]}, {},
     "boundary_source_binding_required"),
    ("stripped_respelled_candidate", {},
     {"binding": None, "provenance": [{"kind": "hunt_candidate", "id": _respelled(CANDIDATE_ID)}]}, {},
     "boundary_source_binding_required"),
    ("forged_hunt", {"hunt_exists": False}, {}, {}, "boundary_source_hunt_not_found"),
    ("other_asset", {"hunt_target": "00000000-0000-4000-8000-000000000099"}, {}, {},
     "boundary_source_target_mismatch"),
    ("not_recorded", {"recorded": None}, {}, {}, "boundary_source_binding_not_recorded"),
    ("superseded", {"recorded": _binding(agent_paths=["/v2/chat"])}, {}, {},
     "boundary_source_binding_superseded_or_mismatched"),
    ("no_candidate", {}, {"provenance": [{"kind": "evidence", "id": CAPTURE_ID}]}, {},
     "boundary_source_binding_requires_one_hunt_candidate"),
    ("resource_swap", {},
     {"owner": {**OWNER, "resource_id": "doc-z"}}, {"owner": {**OWNER, "resource_id": "doc-z"}},
     "boundary_source_resource_mismatch"),
    ("path_swap", {}, {}, {"path": "/admin/{{resource_id}}"}, "boundary_source_resource_path_mismatch"),
])
async def test_discovery_provenance_cannot_be_stripped_forged_or_repointed(
    monkeypatch, case, store_kwargs, proposal_kwargs, base_kwargs, code,
):
    _install(monkeypatch, HuntRecordStore(**store_kwargs), queue_allowed=False)
    with pytest.raises(HTTPException) as exc:
        await _verify(_bound_proposal(**proposal_kwargs), _base(**base_kwargs))
    assert exc.value.status_code == 409, case
    assert exc.value.detail == code, case


@pytest.mark.asyncio
async def test_unbound_proposals_without_discovery_provenance_keep_working(monkeypatch):
    # A plain operator proposal triggers no Hunt lookup at all.
    store = HuntRecordStore(recorded=None)
    captured = _install(monkeypatch, store)
    plain = _bound_proposal(binding=None, provenance=[{"kind": "operator_review", "id": "fixture-review"}])
    assert (await _verify(plain))["status"] == "queued"
    assert captured["kwargs"]["boundary_source_binding"] is None
    assert not any("hunt_runs" in q or "investigation_candidate" in q for q in store.queries)
    assert "source_binding" not in captured["kwargs"]["target_override"]["metadata_json"]["boundary_contract"]

    # A Hunt candidate that discovery never prepared has no binding to require.
    store = HuntRecordStore(recorded=None)
    captured = _install(monkeypatch, store)
    assert (await _verify(_bound_proposal(binding=None)))["status"] == "queued"
    assert any("?|" in q for q in store.queries)

    # A hand-built candidate may cite a capture discovery also used; the cited
    # candidate, not the shared capture, decides whether a binding is required.
    hand_built = "00000000-0000-4000-8000-000000000031"
    captured = _install(monkeypatch, HuntRecordStore())
    proposal = _bound_proposal(binding=None, provenance=[
        {"kind": "hunt_candidate", "id": hand_built}, {"kind": "evidence", "id": CAPTURE_ID},
    ])
    assert (await _verify(proposal))["status"] == "queued"


@pytest.mark.asyncio
async def test_queued_run_persists_hunt_binding_in_stored_scan_options(monkeypatch):
    captured = {}

    class Conn:
        async def fetchrow(self, query, *_args):
            if "FROM ai_targets" in query:
                return await HuntRecordStore().fetchrow(query)
            if "FROM ai_target_credentials" in query:
                return None
            raise AssertionError(query)

        async def fetch(self, query, *_args):
            assert "FROM ai_target_principals" in query
            return []

        async def execute(self, query, *args):
            assert "INSERT INTO scans" in query
            captured["stored_options"] = json.loads(args[4])
            return "INSERT 0 1"

    class Acquire:
        async def __aenter__(self): return Conn()
        async def __aexit__(self, *_args): return False

    class Pool:
        def acquire(self): return Acquire()

    class Redis:
        def hset(self, *_args, **_kwargs): return 1

    async def no_refs(*_args, **_kwargs):
        return None, []

    async def no_receipt(*_args, **_kwargs):
        return {}

    async def record(*_args, **_kwargs):
        return {"id": "operation-1"}

    monkeypatch.setattr(router, "_pool_provider", lambda: Pool())
    monkeypatch.setattr(router, "get_redis", lambda: Redis())
    monkeypatch.setattr(router, "_resolve_ai_gate_credential_refs", no_refs)
    monkeypatch.setattr(router, "_validate_approval_receipt_for_action", no_receipt)
    monkeypatch.setattr(router, "_record_command_result", record)
    monkeypatch.setattr(router, "enqueue_job", lambda _r, _q, payload: captured.update(job=payload))

    await router._queue_ai_target_scan(
        AI_TARGET_ID,
        router.AITargetScanRequest(probe_pack=PACK, scan_profile="standard", environment="preview"),
        boundary_source_binding=_binding(),
    )
    assert captured["stored_options"]["ai_boundary_source_binding"] == _binding()
    assert captured["job"]["options"]["ai_boundary_source_binding"] == _binding()


def test_worker_refuses_a_contract_binding_the_verify_route_did_not_admit():
    from ai_gate.boundary.contract import ContractError
    from ai_gate.boundary.hypothesis import materialize_boundary_contract
    from ai_gate.boundary.runner import prepare
    contract = materialize_boundary_contract(_bound_proposal(), boundary_base=_base())["boundary_contract"]
    options = {
        "ai_probe_pack": PACK, "ai_environment": "preview",
        "ai_target": {"target_type": "api_chat", "method": "POST", "streaming_mode": "json",
                      "endpoint_url": "https://agent.example.test/chat",
                      "metadata_json": {"boundary_contract": contract}},
    }
    with pytest.raises(ContractError, match="boundary_source_binding_not_admitted"):
        prepare("https://agent.example.test/chat", options, header_builder=None)
    # With the admitted binding recorded, preparation proceeds past the provenance check.
    with pytest.raises(ContractError) as later:
        prepare("https://agent.example.test/chat", {**options, "ai_boundary_source_binding": _binding()},
                header_builder=None)
    assert str(later.value) != "boundary_source_binding_not_admitted"
