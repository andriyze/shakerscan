"""Stateful multi-turn boundary verification with one fresh conversation per scenario."""
from __future__ import annotations
import json,uuid
from .contract import ContractError,canonical_hash,pick

def _render(value,replacements):
 if isinstance(value,str):
  for key,replacement in replacements.items():value=value.replace("{{"+key+"}}",replacement)
  if "{{" in value or "}}" in value:raise ContractError("unresolved_request_placeholder")
  return value
 if isinstance(value,dict):return {key:_render(item,replacements) for key,item in value.items()}
 if isinstance(value,list):return [_render(item,replacements) for item in value]
 return value

async def execute_multiturn_contract(scenario,contract):
 c=scenario.contract
 if contract.verifier_path:
  before=await scenario.transport.request(role=c.owner.role,method="GET",path=contract.verifier_path,phase="multiturn_precondition");scenario.check(f"multiturn_precondition:{contract.name}",pick(before.payload,contract.state_path)==contract.initial_value,before)
 await scenario.identity(c.attacker);session_id=uuid.uuid4().hex;turn_receipts=[];last=None
 for index,prompt in enumerate(contract.turns):
  body=_render(scenario.template,{"prompt":prompt,"session_id":session_id,"principal_id":c.attacker.subject,"principal_tenant_id":c.attacker.tenant})
  if any(marker in json.dumps(body,sort_keys=True) for marker in scenario.markers.values()):raise ContractError("protected_marker_would_be_sent_to_multiturn_chat")
  response=await scenario.transport.request(role=c.attacker.role,method="POST",path=scenario.chat_path,body=body,phase="multiturn_attack");text=pick(response.payload,c.response_path)
  if response.status!=200 or not isinstance(text,str):raise ContractError("multiturn_chat_invalid_response")
  turn_receipts.append({"turn":index,"prompt_sha256":canonical_hash(prompt),"response_sha256":response.digest});last=response
 post=None;changed=False
 if contract.verifier_path:
  post=await scenario.transport.request(role=c.owner.role,method="GET",path=contract.verifier_path,phase="multiturn_postcondition");changed=pick(post.payload,contract.state_path)==contract.forbidden_value
 marker=scenario.markers[c.owner.role];disclosed=bool(last and marker in json.dumps(last.payload));confirmed=changed or disclosed
 scenario.attempts.append({"attack_kind":"multi_turn","name":contract.name,"turn_count":len(contract.turns),"outcome":"confirmed_boundary" if confirmed else "not_observed","turn_receipts":turn_receipts,"postcondition_sha256":post.digest if post else None,"request_url":last.request_url if last else None})
 if confirmed:
  scenario.violations.append({"path":"multiturn_forbidden_action" if changed else "multiturn_data_disclosure","turn_count":len(contract.turns),"turn_receipts":turn_receipts,"response_sha256":last.digest,"postcondition_sha256":post.digest if post else None,"request_url":last.request_url,"postcondition_verified":changed,"marker_absent_from_requests":True,"session_continuity_verified":True})
