"""Controlled tool/MCP-style boundary contract.

This layer verifies returned tool telemetry and, for state-changing tools,
requires an independent application postcondition. It does not trust model text.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from .contract import ContractError,_field,_keys,relative_path
@dataclass(frozen=True)
class ToolContract:
 name:str;prompt:str;tool_calls_path:str;tool_name_field:str;tool_name:str;executed_field:str;principal_field:str;expected_principal:str;verifier_path:str|None;state_path:str|None;initial_value:Any;forbidden_value:Any;repetitions:int
 @classmethod
 def parse(cls,raw:Any)->"ToolContract|None":
  if raw is None:return None
  raw=_keys(raw,{"name","prompt","tool_calls_path","tool_name_field","tool_name","executed_field","principal_field","expected_principal","verifier_path","state_path","initial_value","forbidden_value","repetitions"},{"name","prompt","tool_calls_path","tool_name_field","tool_name","executed_field","principal_field","expected_principal"})
  if not isinstance(raw["prompt"],str) or not 1<=len(raw["prompt"])<=2000:raise ContractError("invalid_tool_prompt")
  for key in ("tool_calls_path","tool_name_field","executed_field","principal_field"):_field(raw[key])
  if not isinstance(raw["tool_name"],str) or not raw["tool_name"] or len(raw["tool_name"])>128:raise ContractError("invalid_tool_name")
  if not isinstance(raw["expected_principal"],str) or not raw["expected_principal"] or len(raw["expected_principal"])>128:raise ContractError("invalid_tool_expected_principal")
  verifier=raw.get("verifier_path");state=raw.get("state_path")
  if (verifier is None)!=(state is None):raise ContractError("tool_postcondition_requires_verifier_and_state")
  if verifier is not None:
   verifier=relative_path(verifier);state=_field(state)
   if "{" in verifier or "}" in verifier:raise ContractError("tool_verifier_must_be_static")
   if raw.get("initial_value")==raw.get("forbidden_value"):raise ContractError("tool_state_values_must_differ")
  reps=raw.get("repetitions",2)
  if type(reps) is not int or not 1<=reps<=3:raise ContractError("tool_repetitions_must_be_one_to_three")
  return cls(str(raw["name"]),raw["prompt"],_field(raw["tool_calls_path"]),_field(raw["tool_name_field"]),raw["tool_name"],_field(raw["executed_field"]),_field(raw["principal_field"]),raw["expected_principal"],verifier,state,raw.get("initial_value"),raw.get("forbidden_value"),reps)
