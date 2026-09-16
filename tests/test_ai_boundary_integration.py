"""Requires the full checkout; exercises real AI Gate scoring/manifest/worker glue."""

from __future__ import annotations

from contextlib import asynccontextmanager
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_gate.boundary import PACK, PROBE_ID
from ai_gate.boundary.runner import run_boundary_scan
from ai_gate.probe_registry import get_probe_pack_definitions, get_probe_definition
from worker_handlers.ai_gate import AIGateWorkerHandler
from tests.ai_boundary_fixtures import boundary_fixture


def test_boundary_is_registered_in_the_existing_catalog():
    probes = get_probe_pack_definitions(PACK)
    assert len(probes) == 1 and probes[0].id == PROBE_ID
    assert get_probe_definition(PROBE_ID) is probes[0]
    assert probes[0].safe_for_production is False


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,decision", [("secure", "allow"), ("vulnerable", "block"), ("echo", "needs_approval")])
async def test_shared_scoring_manifest_and_redaction(mode, decision):
    async with boundary_fixture(mode) as fixture:
        options = fixture.options()
        result = await run_boundary_scan(options["ai_target"]["endpoint_url"], options)
        gate = result["ai_gate"]
        assert gate["decision"]["decision"] == decision
        manifest = gate["evidence_manifest"]
        assert manifest["probe_catalog"]["probe_pack"] == PACK
        assert manifest["evidence_hashes"]["findings_hash"].startswith("sha256:")
        assert not manifest["judging"]["semantic"]["enabled"]
        assert all(row["marker"] not in json.dumps(result) for row in fixture.rows.values())
        assert all(value not in json.dumps(result) for value in fixture.credentials.values())
        if mode == "echo":
            assert result["result"]["score"] is None
        else:
            import ai_gate_scan
            assert (result["result"]["score"], result["result"]["grade"]) == ai_gate_scan._score_result(result["findings"])


@pytest.mark.asyncio
async def test_manifest_never_persists_marker_from_invalid_configuration():
    async with boundary_fixture() as fixture:
        options = fixture.options()
        marker = fixture.rows["owner-record"]["marker"]
        options["ai_target"]["request_template"]["hidden"] = marker
        result = await run_boundary_scan(options["ai_target"]["endpoint_url"], options)
        assert result["ai_gate"]["decision"]["decision"] == "needs_approval"
        assert marker not in json.dumps(result)


@pytest.mark.asyncio
async def test_worker_dispatch_occurs_inside_existing_hydration():
    async with boundary_fixture("vulnerable") as fixture:
        options = fixture.options()
        events = []

        @asynccontextmanager
        async def hydrate(original, scan_id):
            assert original == {"ai_probe_pack": PACK}
            assert scan_id == "scan-fixture"
            events.append("hydrate")
            yield options
            events.append("release")

        services = SimpleNamespace(update_scan_progress=AsyncMock(), hydrate_ai_gate_options=hydrate,
                                   scan_cancel_requested=lambda _: False)
        result = await AIGateWorkerHandler(services).run(
            options["ai_target"]["endpoint_url"], {"ai_probe_pack": PACK},
            scan_id="scan-fixture", job_id="job-fixture")
        assert events == ["hydrate", "release"]
        assert result["ai_gate"]["decision"]["decision"] == "block"
        assert services.update_scan_progress.await_count == 2


@pytest.mark.asyncio
async def test_worker_preserves_legacy_pack_dispatch(monkeypatch):
    import ai_gate_scan
    legacy = AsyncMock(return_value={"legacy": True})
    monkeypatch.setattr(ai_gate_scan, "run_ai_target_scan", legacy)

    @asynccontextmanager
    async def hydrate(options, scan_id):
        yield dict(options)

    services = SimpleNamespace(update_scan_progress=AsyncMock(), hydrate_ai_gate_options=hydrate,
                                   scan_cancel_requested=lambda _: False)
    options = {"ai_probe_pack": "shaker-ai-smoke"}
    result = await AIGateWorkerHandler(services).run(
        "https://example.test/chat", options, scan_id="scan-fixture", job_id=None)
    assert result == {"legacy": True}
    legacy.assert_awaited_once_with("https://example.test/chat", options)


@pytest.mark.asyncio
async def test_verified_disclosure_uses_the_shared_typed_proof_contract():
    from ai_verdict_policy import has_deterministic_exploit_proof
    async with boundary_fixture("vulnerable") as fixture:
        options = fixture.options()
        result = await run_boundary_scan(options["ai_target"]["endpoint_url"], options)
        finding = result["findings"][0]
        assert has_deterministic_exploit_proof(finding)
        proof = finding["proof_contract_v2"]
        assert proof["schema_version"] == "proof-contract/v2"
        assert proof["subject"]["method"] == "POST"
        assert proof["subject"]["url"] == options["ai_target"]["endpoint_url"]
        assert proof["reexecution"]["verifier_build"] == "ai-boundary-read/v1"
        assert result["coverage"]["status"] == "complete"


@pytest.mark.asyncio
async def test_existing_worker_cancellation_prevents_network():
    import asyncio
    async with boundary_fixture() as fixture:
        options = fixture.options()
        with pytest.raises(asyncio.CancelledError):
            await run_boundary_scan(options["ai_target"]["endpoint_url"], options, cancelled=lambda: True)
        assert not fixture.calls
