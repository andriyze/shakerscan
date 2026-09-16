from __future__ import annotations

import asyncio
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from ai_gate.boundary.contract import BoundaryContract, ContractError, pick, relative_path
from ai_gate.boundary.runner import execute_boundary
from ai_gate.targets.rest_json import build_headers
from ai_boundary_fixtures import BoundaryFixture, boundary_fixture


async def run(fixture, options=None):
    options = options or fixture.options()
    return await execute_boundary(options["ai_target"]["endpoint_url"], options, header_builder=build_headers)


@pytest.mark.asyncio
@pytest.mark.parametrize("nested", [False, True])
async def test_secure_and_vulnerable_http_twins(nested):
    async with boundary_fixture("secure", nested=nested) as fixture:
        result = await run(fixture)
        assert result["ai_gate"]["boundary"]["state"] == "passed"
        assert result["ai_gate"]["decision"]["decision"] == "allow"
        assert not result["findings"]
        assert result["ai_gate"]["boundary"]["attempted_attacks"] == 3
        sessions = [b.get("session_id", b.get("thread")) for b in fixture.chat_bodies]
        assert len(sessions) == len(set(sessions))
        assert all(method in {"GET", "POST"} for method, _ in fixture.calls)
    assert fixture.cleaned and not fixture.rows
    async with boundary_fixture("vulnerable", nested=nested) as fixture:
        result = await run(fixture)
        assert result["ai_gate"]["boundary"]["state"] == "failed"
        assert result["ai_gate"]["decision"]["decision"] == "block"
        assert len(result["findings"]) == 1
        assert result["findings"][0]["verified"] is True
        assert result["findings"][0]["evidence"]["attribution"] == "assistant_data_boundary"
        serialized = json.dumps(result)
        assert all(row["marker"] not in serialized for row in fixture.rows.values())
        assert all(credential not in serialized for credential in fixture.credentials.values())
        assert all(row["marker"] not in json.dumps(fixture.chat_bodies) for row in fixture.rows.values())


@pytest.mark.asyncio
async def test_backend_leak_is_not_misattributed_to_ai():
    async with boundary_fixture("backend_leak") as fixture:
        result = await run(fixture)
        assert result["findings"][0]["evidence"]["attribution"] == "backend_authorization"
        assert not fixture.chat_bodies
        assert result["ai_gate"]["decision"]["decision"] == "block"


@pytest.mark.asyncio
async def test_leak_during_permitted_baseline_survives_failed_control():
    async with boundary_fixture("baseline_leak") as fixture:
        result = await run(fixture)
        assert result["ai_gate"]["decision"]["decision"] == "block"
        assert result["findings"][0]["evidence"]["violations"][0]["path"] == "assistant_baseline_read"
        assert not result["ai_gate"]["boundary"]["coverage_complete"]


@pytest.mark.asyncio
async def test_malformed_header_name_rejected_before_network():
    async with boundary_fixture() as fixture:
        options = fixture.options()
        options["ai_target"]["principals"][0]["credential"] = {
            "auth_kind": "custom_header", "header_name": "X-Key\r\nHost", "secret": "test-value"}
        with pytest.raises(ContractError, match="headers"):
            await run(fixture, options)
        assert not fixture.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["hallucination"])
async def test_claims_and_tool_metadata_are_not_execution_proof(mode):
    async with boundary_fixture(mode) as fixture:
        result = await run(fixture)
        assert not result["findings"]
        assert result["ai_gate"]["boundary"]["state"] == "passed"


@pytest.mark.asyncio
async def test_real_marker_in_metadata_is_disclosure_not_execution_proof():
    async with boundary_fixture("trace_only") as fixture:
        result = await run(fixture)
        assert result["ai_gate"]["decision"]["decision"] == "block"
        evidence = result["findings"][0]["evidence"]
        assert evidence["violations"][0]["path"] == "assistant_response_metadata"
        assert evidence["attribution"] == "assistant_data_boundary"
        assert "execution_confirmed" not in json.dumps(result)


@pytest.mark.asyncio
async def test_obvious_static_marker_cannot_become_hallucination_proof():
    async with boundary_fixture("hallucination") as fixture:
        fixture.rows["owner-record"]["marker"] = "ssb_" + "0" * 48
        result = await run(fixture)
        assert result["ai_gate"]["boundary"]["state"] == "inconclusive"
        assert not result["findings"]
        assert not fixture.chat_bodies


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["echo", "server_error", "oversize", "missing_answer", "rate_limit", "aliased_identity", "redirect"])
async def test_invalid_controls_never_pass(mode):
    async with boundary_fixture(mode) as fixture:
        result = await run(fixture)
        assert result["ai_gate"]["boundary"]["state"] == "inconclusive"
        assert result["ai_gate"]["decision"]["decision"] == "needs_approval"
        assert result["result"]["score"] is None
        assert not result["findings"]
        assert not any(path == "/sink" for _, path in fixture.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("request_budget", 0), ("token_budget", 0), ("request_budget", 6)])
async def test_hard_budgets_do_not_become_clean_results(field, value):
    async with boundary_fixture() as fixture:
        options = fixture.options()
        options["ai_target"][field] = value
        result = await run(fixture, options)
        assert result["ai_gate"]["decision"]["decision"] == "needs_approval"
        assert not result["ai_gate"]["boundary"]["coverage_complete"]
        if value == 0:
            assert not fixture.calls
        if field == "request_budget":
            assert len(fixture.calls) <= value


@pytest.mark.asyncio
async def test_partial_run_does_not_erase_confirmed_leak():
    async with boundary_fixture("vulnerable") as fixture:
        options = fixture.options()
        options["ai_target"]["request_budget"] = 10
        result = await run(fixture, options)
        assert not result["ai_gate"]["boundary"]["coverage_complete"]
        assert result["ai_gate"]["decision"]["decision"] == "block"
        assert result["findings"][0]["verified"]


@pytest.mark.asyncio
async def test_identical_credentials_rejected_before_network():
    async with boundary_fixture() as fixture:
        options = fixture.options()
        principals = options["ai_target"]["principals"]
        principals[1]["credential"] = copy.deepcopy(principals[0]["credential"])
        with pytest.raises(ContractError, match="identical"):
            await run(fixture, options)
        assert not fixture.calls


@pytest.mark.asyncio
async def test_cancellation_propagates_and_stops_requests():
    async with boundary_fixture("cancel") as fixture:
        task = asyncio.create_task(run(fixture))
        await asyncio.wait_for(fixture.chat_started.wait(), timeout=3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        before = len(fixture.calls)
        await asyncio.sleep(0.05)
        assert len(fixture.calls) == before


@pytest.mark.asyncio
async def test_hidden_template_marker_is_not_sent_as_fake_proof():
    async with boundary_fixture("vulnerable") as fixture:
        options = fixture.options()
        options["ai_target"]["request_template"]["hidden"] = fixture.rows["owner-record"]["marker"]
        result = await run(fixture, options)
        assert result["ai_gate"]["boundary"]["state"] == "inconclusive"
        assert not fixture.chat_bodies
        assert not result["findings"]


@pytest.mark.parametrize("path", ["https://evil.example/x", "//evil.example/x", "/a/../x", "/a/%2e%2e/x", "/x?q=secret", "/x#frag", "/x\\y", "/x\r\n"])
def test_paths_cannot_expand_scope(path):
    with pytest.raises(ContractError):
        relative_path(path)


@pytest.mark.parametrize("field", ["subject", "tenant", "role", "resource_id"])
def test_distinct_principals_and_fixtures_are_required(field):
    options = BoundaryFixture().options()
    raw = options["ai_target"]["metadata_json"]["boundary_contract"]
    raw["attacker"][field] = raw["owner"][field]
    with pytest.raises(ContractError):
        BoundaryContract.parse(raw)


def test_strict_paths_do_not_fall_back_to_entire_response():
    with pytest.raises(ContractError):
        pick({"tool_calls": [{"answer": "secret"}]}, "answer")


@pytest.mark.asyncio
async def test_production_refused_before_network():
    async with boundary_fixture() as fixture:
        options = fixture.options()
        options["ai_environment"] = "production"
        with pytest.raises(ContractError, match="production"):
            await run(fixture, options)
        assert not fixture.calls
