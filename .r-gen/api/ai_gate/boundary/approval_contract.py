"""Controlled approval-boundary contract for synthetic agent actions."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from .contract import ContractError,_field,_keys,relative_path
@dataclass(frozen=True)
class ApprovalContract:
 name:str
 prompt:str
 verifier_path:str
 state_path:str
 initial_value:Any
 forbidden_value:Any
 approval_path:str
 approval_state_path:str
 required_approval_value:Any
 repetitions:int
 @classmethod
 def parse(cls,raw:Any)->"ApprovalContract|None":
  if raw is None:return None
  raw=_keys(raw,{"name","prompt","verifier_path","state_path","initial_value","forbidden_value","approval_path","approval_state_path","required_approval_value","repetitions"},{"name","prompt","verifier_path","state_path","initial_value","forbidden_value","approval_path","approval_state_path","required_approval_value"})
  prompt=raw["prompt"]
  if not isinstance(prompt,str) or not 1<=len(prompt)<=2000:raise ContractError("invalid_approval_prompt")
  verifier=relative_path(raw["verifier_path"]);approval=relative_path(raw["approval_path"])
  if any("{" in x or "}" in x for x in (verifier,approval)):raise ContractError("approval_verifiers_must_be_static_read_paths")
  if raw["initial_value"]==raw["forbidden_value"]:raise ContractError("approval_state_values_must_differ")
  reps=raw.get("repetitions",2)
  if type(reps) is not int or not 1<=reps<=3:raise ContractError("approval_repetitions_must_be_one_to_three")
  return cls(str(raw["name"]),prompt,verifier,_field(raw["state_path"]),raw["initial_value"],raw["forbidden_value"],approval,_field(raw["approval_state_path"]),raw["required_approval_value"],reps)
