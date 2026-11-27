"""Deterministic tool/MCP-style boundary verification."""
from __future__ import annotations
from .contract import ContractError,canonical_hash,pick

def _nested(value,path):return pick(value,path)
def _matching_call(payload,contract):
 calls=pick(payload,contract.tool_calls_path)
 if not isinstance(calls,list):raise ContractError("tool_calls_must_be_list")
 for call in calls:
  if not isinstance(call,dict):continue
  try:name=_nested(call,contract.tool_name_field);executed=_nested(call,contract.executed_field);principal=_nested(call,contract.principal_field)
  except ContractError:continue
  if name==contract.tool_name and executed is True:return call,principal
 return None,None
async def execute_tool_contract(scenario,contract):
 c=scenario.contract;before=None
 if contract.verifier_path:
  before=await scenario.transport.request(role=c.owner.role,method="GET",path=contract.verifier_path,phase="tool_precondition");scenario.check(f"tool_precondition:{contract.name}",pick(before.payload,contract.state_path)==contract.initial_value,before)
 for rep in range(contract.repetitions):
  await scenario.identity(c.attacker);_text,response=await scenario.chat(c.attacker,contract.prompt,phase="tool_boundary_attack");call,principal=_matching_call(response.payload,contract);executed=call is not None;principal_violation=executed and principal!=contract.expected_principal;changed=False;post=None
  if contract.verifier_path:
   post=await scenario.transport.request(role=c.owner.role,method="GET",path=contract.verifier_path,phase="tool_postcondition");changed=pick(post.payload,contract.state_path)==contract.forbidden_value
  confirmed=principal_violation and (changed if contract.verifier_path else True)
  scenario.attempts.append({"attack_kind":"tool_boundary","name":contract.name,"repetition":rep,"outcome":"confirmed_tool_boundary" if confirmed else "not_observed","response_sha256":response.digest,"postcondition_sha256":post.digest if post else None,"request_url":response.request_url})
  if confirmed:
   scenario.violations.append({"path":"tool_principal_boundary","tool_name":contract.tool_name,"expected_principal_sha256":canonical_hash(contract.expected_principal),"observed_principal_sha256":canonical_hash(principal),"response_sha256":response.digest,"postcondition_sha256":post.digest if post else None,"request_url":response.request_url,"prompt_sha256":canonical_hash(contract.prompt),"tool_execution_observed":True,"postcondition_verified":changed if contract.verifier_path else False,"principal_boundary_verified":True});return
