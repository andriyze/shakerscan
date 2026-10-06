"""Actual Hunt HTTP transport -> discovery -> existing verifier, on loopback."""
from __future__ import annotations

import copy
from urllib.parse import urlsplit
from uuid import UUID

import pytest

from capabilities.http import execute_bound_http_request
from runtime.http_archive import hunt_call_recorder
from runtime.models import TargetBinding
from api.hunt.boundary_discovery import build_boundary_discovery
from api.ai_gate.boundary.hypothesis import compile_hunt_candidate_boundary, materialize_boundary_contract
from api.ai_gate.boundary.runner import run_boundary_scan
from tests.ai_boundary_fixtures import boundary_fixture

def uid(n):
    return str(UUID(int=n))


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["secure", "vulnerable"])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("numeric", [False, True])
async def test_real_capture_discovery_to_proof_keeps_legitimate_controls(monkeypatch, mode, nested, numeric):
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE", "full")
    async with boundary_fixture(mode, nested=nested) as fixture:
        options = fixture.options()
        base = copy.deepcopy(options["ai_target"]["metadata_json"]["boundary_contract"])
        if numeric:
            for slot, identifier in (("owner", "123"), ("attacker", "456")):
                resource = fixture.rows.pop(base[slot]["resource_id"])
                resource["id"] = identifier
                fixture.rows[identifier] = resource
                base[slot]["resource_id"] = identifier
        target = TargetBinding(target_id=uid(2), target_kind="web", canonical_host="127.0.0.1",
                               allowed_origins=(fixture.base,), allowed_addresses=("127.0.0.1",),
                               allowed_root_domains=("127.0.0.1",), environment="lab", scope_receipt_id=uid(3))
        evidence = []
        sequence = 10
        for slot, principal in (("primary", "owner"), ("secondary", "attacker")):
            for path in (base["identity"]["path"], base["resource"]["path"].replace("{{resource_id}}", base[principal]["resource_id"])):
                transactions, record = hunt_call_recorder(hunt_run_id=uid(1), hunt_action_id=uid(sequence + 1000),
                                                        capability_name="http.request", adapter="http", target_id=uid(2), target_url=fixture.base)
                result = await execute_bound_http_request(fixture.base, {"method": "GET", "path": path}, target=target,
                                                         principal_slot=slot, trusted_headers={"Authorization": "Bearer " + fixture.credentials[principal]},
                                                         transaction_recorder=record)
                assert result["ok"], result
                for t in transactions:
                    evidence.append({"id": uid(sequence), "hunt_action_id": t.hunt_action_id, "url": t.url, "method": t.method,
                                     "status_code": t.status_code, "principal_slot": t.principal_slot,
                                     "metadata_json": dict(t.metadata), "error": t.error, "truncated": t.response_body_truncated})
                sequence += 1
        path = urlsplit(options["ai_target"]["endpoint_url"]).path
        transactions, record = hunt_call_recorder(hunt_run_id=uid(1), hunt_action_id=uid(1014), capability_name="http.request",
                                                adapter="http", target_url=fixture.base, target_id=uid(2))
        body = {"input": {"text": "Hello"}, "thread": "discovery"} if nested else {"message": "Hello", "session_id": "discovery"}
        result = await execute_bound_http_request(fixture.base, {"method": "POST", "path": path, "json_body": body}, target=target,
                                                 allow_write=True, principal_slot="primary",
                                                 trusted_headers={"Authorization": "Bearer " + fixture.credentials["owner"]}, transaction_recorder=record)
        assert result["ok"], result
        t, = transactions
        evidence.append({"id": uid(14), "hunt_action_id": t.hunt_action_id, "url": t.url, "method": t.method,
                         "status_code": t.status_code, "principal_slot": t.principal_slot,
                         "metadata_json": dict(t.metadata), "error": t.error, "truncated": t.response_body_truncated})
        before = len(fixture.calls)
        draft, = build_boundary_discovery(run={"id": uid(1), "target_id": uid(2)}, rows=evidence)["drafts"]
        assert len(fixture.calls) == before  # discovery itself sends no traffic
        # Explicit operator declarations complete identity values; only the
        # already-observed structural bindings are copied out of discovery.
        discovered = copy.deepcopy(draft["fixture_prefill"])
        for slot in ("owner", "attacker"):
            discovered[slot] = {**base[slot], **discovered[slot]}
        assert discovered["identity"] == base["identity"]
        assert discovered["resource"] == base["resource"]
        candidate = {"id": uid(100), "family": draft["candidate_request"]["family"],
                     "canonical_locus": draft["candidate_request"]["locus"], "evidence_refs": draft["candidate_request"]["evidence_refs"]}
        proposal = compile_hunt_candidate_boundary(candidate, principal_context={slot: discovered[slot] for slot in ("owner", "attacker")})["proposal"]
        contract = materialize_boundary_contract(proposal, boundary_base=discovered)["boundary_contract"]
        options["ai_target"]["metadata_json"]["boundary_contract"] = contract
        proof = await run_boundary_scan(options["ai_target"]["endpoint_url"], options)
        boundary = proof["ai_gate"]["boundary"]
        assert boundary["state"] == ("failed" if mode == "vulnerable" else "passed"), boundary
        assert all(control["passed"] for control in boundary["controls"])
        assert any(f["verified"] for f in proof["findings"]) is (mode == "vulnerable")
