"""Full-checkout integration tests for AI boundary verification."""
from __future__ import annotations
from contextlib import asynccontextmanager
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from ai_gate.boundary import PACK,PROBE_ID
from ai_gate.boundary.runner import run_boundary_scan
from ai_gate.probe_registry import get_probe_pack_definitions,get_probe_definition
from worker_handlers.ai_gate import AIGateWorkerHandler
from tests.ai_boundary_fixtures import boundary_fixture

def test_boundary_registered():
 probes=get_probe_pack_definitions(PACK);assert len(probes)==1 and probes[0].id==PROBE_ID;assert get_probe_definition(PROBE_ID) is probes[0];assert probes[0].safe_for_production is False
@pytest.mark.asyncio
@pytest.mark.parametrize("mode,decision",[("secure","allow"),("vulnerable","block"),("echo","needs_approval")])
async def test_scoring_manifest_redaction(mode,decision):
 async with boundary_fixture(mode) as f:
  o=f.options();r=await run_boundary_scan(o["ai_target"]["endpoint_url"],o);g=r["ai_gate"];assert g["decision"]["decision"]==decision;assert g["evidence_manifest"]["probe_catalog"]["probe_pack"]==PACK;assert all(x["marker"] not in json.dumps(r) for x in f.rows.values());assert all(v not in json.dumps(r) for v in f.credentials.values())
  if mode=="echo":assert r["result"]["score"] is None
  else:
   import ai_gate_scan
   assert (r["result"]["score"],r["result"]["grade"])==ai_gate_scan._score_result(r["findings"])
@pytest.mark.asyncio
async def test_manifest_never_persists_marker_from_invalid_configuration():
 async with boundary_fixture() as f:
  o=f.options();m=f.rows["owner-record"]["marker"];o["ai_target"]["request_template"]["hidden"]=m;r=await run_boundary_scan(o["ai_target"]["endpoint_url"],o);assert r["ai_gate"]["decision"]["decision"]=="needs_approval";assert m not in json.dumps(r)
@pytest.mark.asyncio
async def test_worker_dispatch_inside_hydration():
 async with boundary_fixture("vulnerable") as f:
  o=f.options();events=[]
  @asynccontextmanager
  async def hydrate(original,scan_id):events.append("hydrate");yield o;events.append("release")
  s=SimpleNamespace(update_scan_progress=AsyncMock(),hydrate_ai_gate_options=hydrate,scan_cancel_requested=lambda _:False);r=await AIGateWorkerHandler(s).run(o["ai_target"]["endpoint_url"],{"ai_probe_pack":PACK},scan_id="scan-fixture",job_id="job-fixture");assert events==["hydrate","release"];assert r["ai_gate"]["decision"]["decision"]=="block"
@pytest.mark.asyncio
async def test_worker_preserves_legacy_dispatch(monkeypatch):
 import ai_gate_scan
 legacy=AsyncMock(return_value={"legacy":True});monkeypatch.setattr(ai_gate_scan,"run_ai_target_scan",legacy)
 @asynccontextmanager
 async def hydrate(options,scan_id):yield dict(options)
 s=SimpleNamespace(update_scan_progress=AsyncMock(),hydrate_ai_gate_options=hydrate,scan_cancel_requested=lambda _:False);o={"ai_probe_pack":"shaker-ai-smoke"};r=await AIGateWorkerHandler(s).run("https://example.test/chat",o,scan_id="scan",job_id=None);assert r=={"legacy":True};legacy.assert_awaited_once_with("https://example.test/chat",o)
@pytest.mark.asyncio
async def test_verified_disclosure_uses_shared_proof_contract():
 from ai_verdict_policy import has_deterministic_exploit_proof
 async with boundary_fixture("vulnerable") as f:
  o=f.options();r=await run_boundary_scan(o["ai_target"]["endpoint_url"],o);finding=r["findings"][0];assert has_deterministic_exploit_proof(finding);p=finding["proof_contract_v2"];assert p["schema_version"]=="proof-contract/v2";assert p["subject"]["method"]=="POST";assert p["reexecution"]["verifier_build"]=="ai-boundary-read/v1"
@pytest.mark.asyncio
@pytest.mark.parametrize("mode,expected_type,proof_basis",[("indirect_disclosure","indirect_prompt_injection","indirect_canary_disclosure"),("indirect_action","indirect_agent_action","postcondition_verification")])
async def test_indirect_findings_are_deterministic_typed_proofs(mode,expected_type,proof_basis):
 from ai_verdict_policy import has_deterministic_exploit_proof
 async with boundary_fixture(mode) as f:
  o=f.options(with_indirect=True);r=await run_boundary_scan(o["ai_target"]["endpoint_url"],o);finding=next(x for x in r["findings"] if x["type"]==expected_type);assert has_deterministic_exploit_proof(finding);p=finding["proof_contract_v2"];assert p["proof_basis"]==proof_basis;assert p["reexecution"]["verifier_build"]=="ai-boundary-indirect/v1";serialized=json.dumps(r);assert f.document["marker"] not in serialized;assert all(v not in serialized for v in f.credentials.values())
@pytest.mark.asyncio
async def test_existing_worker_cancellation_prevents_network():
 async with boundary_fixture() as f:
  o=f.options()
  with pytest.raises(__import__("asyncio").CancelledError):await run_boundary_scan(o["ai_target"]["endpoint_url"],o,cancelled=lambda:True)
  assert not f.calls
