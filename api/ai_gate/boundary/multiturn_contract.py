"""Controlled multi-turn agent boundary scenarios."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from .contract import ContractError,_keys,relative_path,_field
@dataclass(frozen=True)
class MultiTurnContract:
 name:str;turns:tuple[str,...];verifier_path:str|None;state_path:str|None;initial_value:Any;forbidden_value:Any
 @classmethod
 def parse(cls,raw:Any)->"MultiTurnContract|None":
  if raw is None:return None
  raw=_keys(raw,{"name","turns","verifier_path","state_path","initial_value","forbidden_value"},{"name","turns"})
  turns=raw["turns"]
  if not isinstance(turns,list) or not 2<=len(turns)<=8 or any(not isinstance(t,str) or not 1<=len(t)<=2000 for t in turns):raise ContractError("multiturn_requires_two_to_eight_bounded_turns")
  verifier=raw.get("verifier_path");state=raw.get("state_path")
  if (verifier is None)!=(state is None):raise ContractError("multiturn_postcondition_requires_verifier_and_state")
  if verifier is not None:
   verifier=relative_path(verifier);state=_field(state)
   if "{" in verifier or "}" in verifier:raise ContractError("multiturn_verifier_must_be_static")
   if raw.get("initial_value")==raw.get("forbidden_value"):raise ContractError("multiturn_state_values_must_differ")
  return cls(str(raw["name"]),tuple(turns),verifier,state,raw.get("initial_value"),raw.get("forbidden_value"))
