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
 async with boundary_fixture("secure",nested=nested) as f:assert (await run(f))["ai_gate"]["boundary"]["state"]=="passed"
 async with boundary_fixture("vulnerable",nested=nested) as f:assert (await run(f))["ai_gate"]["decision"]["decision"]=="block"
@pytest.mark.asyncio
async def test_verified_forbidden_action():
 async with boundary_fixture("action_vulnerable") as f:assert next(x for x in (await run(f,f.options(with_action=True)))["findings"] if x["type"]=="forbidden_agent_action")["verified"]
@pytest.mark.asyncio
async def test_approval_bypass_requires_absent_approval():
 async with boundary_fixture("approval_bypass") as f:assert next(x for x in (await run(f,f.options(with_approval=True)))["findings"] if x["type"]=="approval_bypass")["evidence"]["violations"][0]["approval_absence_verified"]
@pytest.mark.asyncio
async def test_legitimate_approval_not_bypass():
 async with boundary_fixture("approval_legit") as f:assert not any(x["type"]=="approval_bypass" for x in (await run(f,f.options(with_approval=True)))["findings"])
@pytest.mark.asyncio
async def test_tool_wrong_principal_plus_state_change_verified():
 async with boundary_fixture("tool_boundary") as f:
  x=next(x for x in (await run(f,f.options(with_tool=True)))["findings"] if x["type"]=="tool_principal_boundary");assert x["evidence"]["violations"][0]["postcondition_verified"]
@pytest.mark.asyncio
async def test_tool_claim_not_proof():
 async with boundary_fixture("tool_claim") as f:assert not any(x["type"]=="tool_principal_boundary" for x in (await run(f,f.options(with_tool=True)))["findings"])
@pytest.mark.asyncio
async def test_multiturn_action_requires_same_session_and_postcondition():
 async with boundary_fixture("multiturn_action") as f:
  r=await run(f,f.options(with_multiturn=True));x=next(x for x in r["findings"] if x["type"]=="multiturn_agent_action");v=x["evidence"]["violations"][0];assert v["session_continuity_verified"] and v["postcondition_verified"] and v["turn_count"]==3;assert f.order["status"]=="refunded"
@pytest.mark.asyncio
async def test_multiturn_disclosure_only_occurs_with_shared_session():
 async with boundary_fixture("multiturn_disclosure") as f:
  marker=f.rows["owner-record"]["marker"];o=f.options(with_multiturn=True,multiturn_disclosure=True);assert marker not in json.dumps(o);r=await run(f,o);x=next(x for x in r["findings"] if x["type"]=="multiturn_data_disclosure");assert x["evidence"]["violations"][0]["session_continuity_verified"] and marker not in json.dumps(r)
@pytest.mark.asyncio
async def test_secure_multiturn_path_passes():
 async with boundary_fixture("secure") as f:
  r=await run(f,f.options(with_multiturn=True));assert r["ai_gate"]["boundary"]["capabilities"]["multi_turn"] and r["ai_gate"]["boundary"]["state"]=="passed"
@pytest.mark.asyncio
async def test_indirect_disclosure_deterministic():
 async with boundary_fixture("indirect_disclosure") as f:
  marker=f.document["marker"];o=f.options(with_indirect=True);r=await run(f,o);assert any(v["path"]=="indirect_data_disclosure" for v in r["ai_gate"]["boundary"]["violations"]);assert marker not in json.dumps(r)
@pytest.mark.asyncio
async def test_indirect_verified_action():
 async with boundary_fixture("indirect_action") as f:assert any(v["path"]=="indirect_forbidden_action" for v in (await run(f,f.options(with_indirect=True,indirect_action=True)))["ai_gate"]["boundary"]["violations"])
@pytest.mark.asyncio
@pytest.mark.parametrize("mode",["echo","server_error","oversize","missing_answer","rate_limit","aliased_identity","redirect"])
async def test_invalid_controls_never_pass(mode):
 async with boundary_fixture(mode) as f:
  r=await run(f);assert r["ai_gate"]["boundary"]["state"]=="inconclusive" and r["result"]["score"] is None
@pytest.mark.asyncio
async def test_hallucination_not_proof():
 async with boundary_fixture("hallucination") as f:assert not (await run(f))["findings"]
@pytest.mark.asyncio
@pytest.mark.parametrize("field,value",[("request_budget",0),("token_budget",0),("request_budget",6)])
async def test_hard_budgets_never_pass(field,value):
 async with boundary_fixture() as f:
  o=f.options();o["ai_target"][field]=value;assert (await run(f,o))["ai_gate"]["decision"]["decision"]=="needs_approval"
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
