"""Contract for controlled indirect prompt-injection boundary tests.

The application test harness owns document creation/removal. ShakerScan only
references a declared synthetic document and independently verifies the effect.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from .contract import ContractError,_field,_keys,relative_path
@dataclass(frozen=True)
class IndirectContract:
 name:str
 trigger_prompt:str
 document_id:str
 document_path:str
 marker_field:str
 verifier_path:str|None
 state_path:str|None
 initial_value:Any
 forbidden_value:Any
 repetitions:int
 @classmethod
 def parse(cls,raw:Any)->"IndirectContract|None":
  if raw is None:return None
  raw=_keys(raw,{"name","trigger_prompt","document_id","document_path","marker_field","verifier_path","state_path","initial_value","forbidden_value","repetitions"},{"name","trigger_prompt","document_id","document_path","marker_field"})
  prompt=raw["trigger_prompt"]
  if not isinstance(prompt,str) or not 1<=len(prompt)<=2000:raise ContractError("invalid_indirect_trigger_prompt")
  doc_id=str(raw["document_id"])
  if not doc_id or len(doc_id)>128:raise ContractError("invalid_indirect_document_id")
  doc_path=relative_path(raw["document_path"])
  if doc_path.count("{{document_id}}")!=1:raise ContractError("indirect_document_path_requires_document_id")
  verifier=raw.get("verifier_path");state=raw.get("state_path")
  if (verifier is None)!=(state is None):raise ContractError("indirect_postcondition_requires_verifier_and_state_path")
  if verifier is not None:
   verifier=relative_path(verifier)
   if "{" in verifier or "}" in verifier:raise ContractError("indirect_verifier_must_be_static")
   state=_field(state)
   if raw.get("initial_value")==raw.get("forbidden_value"):raise ContractError("indirect_state_values_must_differ")
  repetitions=raw.get("repetitions",2)
  if type(repetitions) is not int or not 1<=repetitions<=3:raise ContractError("indirect_repetitions_must_be_one_to_three")
  return cls(str(raw["name"]),prompt,doc_id,doc_path,_field(raw["marker_field"]),verifier,state,raw.get("initial_value"),raw.get("forbidden_value"),repetitions)
