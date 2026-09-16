from __future__ import annotations
import asyncio,copy,json,sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"api"))
from ai_gate.boundary.contract import BoundaryContract,ContractError,pick,relative_path
from ai_gate.boundary.runner import execute_boundary
from ai_gate.targets.rest_json import build_headers
from tests.ai_boundary_fixtures import BoundaryFixture,boundary_fixture
async def run(fixture,options=None):
 options=options or fixture.options();return await execute_boundary(options["ai_target"]["endpoint_url"],options,header_builder=build_headers)
@pytest.mark.asyncio
@pytest.mark.parametrize("nested",[False,True])
async def test_secure_and_vulnerable_http_twins(nested):
 async with boundary_fixture("secure",nested=nested) as f:
  r=await run(f);assert r["ai_gate"]["boundary"]["state"]=="passed";assert not r["findings"];assert r["ai_gate"]["boundary"]["attempted_attacks"]==3;s=[b.get("session_id",b.get("thread")) for b in f.chat_bodies];assert len(s)==len(set(s))
 async with boundary_fixture("vulnerable",nested=nested) as f:
  r=await run(f);assert r["ai_gate"]["decision"]["decision"]=="block";assert r["findings"][0]["verified"];assert all(x["marker"] not in json.dumps(r) for x in f.rows.values())
@pytest.mark.asyncio
async def test_backend_leak_not_misattributed():
 async with boundary_fixture("backend_leak") as f:
  r=await run(f);assert r["findings"][0]["evidence"]["attribution"]=="backend_authorization";assert not f.chat_bodies
@pytest.mark.asyncio
async def test_verified_forbidden_action_uses_independent_owner_postcondition():
 async with boundary_fixture("action_vulnerable") as f:
  o=f.options(with_action=True);r=await run(f,o);finding=next(x for x in r["findings"] if x["type"]=="forbidden_agent_action");assert finding["verified"];assert finding["evidence"]["attribution"]=="agent_action";assert finding["evidence"]["violations"][0]["postcondition_verified"] is True;assert f.order["status"]=="refunded";assert r["ai_gate"]["decision"]["decision"]=="block"
@pytest.mark.asyncio
async def test_agent_claim_without_state_change_is_not_execution_proof():
 async with boundary_fixture("action_claim") as f:
  r=await run(f,f.options(with_action=True));assert not any(x["type"]=="forbidden_agent_action" for x in r["findings"]);assert f.order["status"]=="paid";assert r["ai_gate"]["boundary"]["state"]=="passed"
@pytest.mark.asyncio
async def test_action_contract_secure_path_passes():
 async with boundary_fixture("secure") as f:
  r=await run(f,f.options(with_action=True));assert r["ai_gate"]["boundary"]["capabilities"]["verified_forbidden_action"];assert r["ai_gate"]["boundary"]["attempted_attacks"]==4;assert r["ai_gate"]["decision"]["decision"]=="allow"
@pytest.mark.asyncio
async def test_leak_during_baseline_survives_incomplete_control():
 async with boundary_fixture("baseline_leak") as f:
  r=await run(f);assert r["ai_gate"]["decision"]["decision"]=="block";assert not r["ai_gate"]["boundary"]["coverage_complete"]
@pytest.mark.asyncio
async def test_malformed_header_rejected_before_network():
 async with boundary_fixture() as f:
  o=f.options();o["ai_target"]["principals"][0]["credential"]={"auth_kind":"custom_header","header_name":"X-Key\r\nHost","secret":"x"}
  with pytest.raises(ContractError):await run(f,o)
  assert not f.calls
@pytest.mark.asyncio
@pytest.mark.parametrize("mode",["echo","server_error","oversize","missing_answer","rate_limit","aliased_identity","redirect"])
async def test_invalid_controls_never_pass(mode):
 async with boundary_fixture(mode) as f:
  r=await run(f);assert r["ai_gate"]["boundary"]["state"]=="inconclusive";assert r["ai_gate"]["decision"]["decision"]=="needs_approval";assert r["result"]["score"] is None
@pytest.mark.asyncio
async def test_hallucinated_marker_not_proof():
 async with boundary_fixture("hallucination") as f:
  r=await run(f);assert not r["findings"]
@pytest.mark.asyncio
async def test_metadata_disclosure_is_not_action_execution():
 async with boundary_fixture("trace_only") as f:
  r=await run(f);assert r["findings"][0]["evidence"]["violations"][0]["path"]=="assistant_response_metadata";assert "execution_confirmed" not in json.dumps(r)
@pytest.mark.asyncio
@pytest.mark.parametrize("field,value",[("request_budget",0),("token_budget",0),("request_budget",6)])
async def test_hard_budgets_never_clean_pass(field,value):
 async with boundary_fixture() as f:
  o=f.options();o["ai_target"][field]=value;r=await run(f,o);assert r["ai_gate"]["decision"]["decision"]=="needs_approval";assert not r["ai_gate"]["boundary"]["coverage_complete"]
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
  assert not f.calls
@pytest.mark.asyncio
async def test_scope_guard_blocks_before_network():
 async with boundary_fixture() as f:
  o=f.options();o["runtime_scope_guard"]={"allowed_hosts":["another.example.test"],"environment":"preview","requires_runtime_destination_check":True}
  with pytest.raises(ContractError):await run(f,o)
  assert not f.calls
