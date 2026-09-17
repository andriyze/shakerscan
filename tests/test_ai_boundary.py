from __future__ import annotations
import asyncio,json,sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"api"))
from ai_gate.boundary.contract import ContractError,pick,relative_path
from ai_gate.boundary.runner import execute_boundary
from ai_gate.targets.rest_json import build_headers
from tests.ai_boundary_fixtures import boundary_fixture
async def run(f,o=None):
 o=o or f.options();return await execute_boundary(o["ai_target"]["endpoint_url"],o,header_builder=build_headers)
@pytest.mark.asyncio
@pytest.mark.parametrize("nested",[False,True])
async def test_secure_and_vulnerable_http_twins(nested):
 async with boundary_fixture("secure",nested=nested) as f:
  r=await run(f);assert r["ai_gate"]["boundary"]["state"]=="passed";assert not r["findings"];assert r["ai_gate"]["boundary"]["attempted_attacks"]==3
 async with boundary_fixture("vulnerable",nested=nested) as f:
  r=await run(f);assert r["ai_gate"]["decision"]["decision"]=="block";assert r["findings"][0]["verified"]
@pytest.mark.asyncio
async def test_backend_leak_not_misattributed():
 async with boundary_fixture("backend_leak") as f:
  r=await run(f);assert r["findings"][0]["evidence"]["attribution"]=="backend_authorization";assert not f.chat_bodies
@pytest.mark.asyncio
async def test_verified_forbidden_action():
 async with boundary_fixture("action_vulnerable") as f:
  r=await run(f,f.options(with_action=True));x=next(x for x in r["findings"] if x["type"]=="forbidden_agent_action");assert x["verified"] and x["evidence"]["violations"][0]["postcondition_verified"]
@pytest.mark.asyncio
async def test_action_claim_not_execution_proof():
 async with boundary_fixture("action_claim") as f:
  r=await run(f,f.options(with_action=True));assert not any(x["type"]=="forbidden_agent_action" for x in r["findings"]);assert f.order["status"]=="paid"
@pytest.mark.asyncio
async def test_indirect_document_disclosure_is_deterministic():
 async with boundary_fixture("indirect_disclosure") as f:
  marker=f.document["marker"];o=f.options(with_indirect=True);assert marker not in json.dumps(o);r=await run(f,o);assert r["ai_gate"]["decision"]["decision"]=="block";v=next(v for v in r["ai_gate"]["boundary"]["violations"] if v["path"]=="indirect_data_disclosure");assert v["indirect_fixture_verified"] and marker not in json.dumps(r)
@pytest.mark.asyncio
async def test_indirect_document_can_cause_verified_action():
 async with boundary_fixture("indirect_action") as f:
  r=await run(f,f.options(with_indirect=True,indirect_action=True));v=next(v for v in r["ai_gate"]["boundary"]["violations"] if v["path"]=="indirect_forbidden_action");assert v["postcondition_verified"] and f.order["status"]=="refunded" and r["ai_gate"]["decision"]["decision"]=="block"
@pytest.mark.asyncio
async def test_secure_indirect_path_passes():
 async with boundary_fixture("secure") as f:
  r=await run(f,f.options(with_indirect=True));assert r["ai_gate"]["boundary"]["capabilities"]["indirect_injection"];assert r["ai_gate"]["boundary"]["state"]=="passed"
@pytest.mark.asyncio
@pytest.mark.parametrize("mode",["echo","server_error","oversize","missing_answer","rate_limit","aliased_identity","redirect"])
async def test_invalid_controls_never_pass(mode):
 async with boundary_fixture(mode) as f:
  r=await run(f);assert r["ai_gate"]["boundary"]["state"]=="inconclusive";assert r["result"]["score"] is None
@pytest.mark.asyncio
async def test_hallucination_not_proof():
 async with boundary_fixture("hallucination") as f:assert not (await run(f))["findings"]
@pytest.mark.asyncio
@pytest.mark.parametrize("field,value",[("request_budget",0),("token_budget",0),("request_budget",6)])
async def test_hard_budgets_never_pass(field,value):
 async with boundary_fixture() as f:
  o=f.options();o["ai_target"][field]=value;r=await run(f,o);assert r["ai_gate"]["decision"]["decision"]=="needs_approval"
@pytest.mark.asyncio
async def test_cancellation_propagates():
 async with boundary_fixture("cancel") as f:
  task=asyncio.create_task(run(f));await asyncio.wait_for(f.chat_started.wait(),3);task.cancel()
  with pytest.raises(asyncio.CancelledError):await task
@pytest.mark.parametrize("path",["https://evil.example/x","//evil.example/x","/a/../x","/a/%2e%2e/x","/x?q=secret","/x#frag","/x\\y"])
def test_paths_cannot_expand_scope(path):
 with pytest.raises(ContractError):relative_path(path)
def test_strict_paths_no_fallback():
 with pytest.raises(ContractError):pick({"tool_calls":[{"answer":"secret"}]},"answer")
@pytest.mark.asyncio
async def test_production_refused():
 async with boundary_fixture() as f:
  o=f.options();o["ai_environment"]="production"
  with pytest.raises(ContractError):await run(f,o)
