"""Shared policy for using AI verdicts in DAST precision decisions."""
from __future__ import annotations
from typing import Any
TRUSTED_AI_CLASSIFICATION_SOURCES={"provider","semantic_judge","llm_rubric","regex_classifier"};_CONFIRMED_EVIDENCE_LEVELS={"confirmed_exploit","proof_of_exploit","proof_of_exploitation","browser_proven"};_DETERMINISTIC_PROOF_TYPES={"browser_execution","cross_principal_replay","write_cross_principal_replay","postcondition_verification","indirect_canary_disclosure","sqli_data_extraction","data_extraction","oob_callback","repeated_semantic_response_diff"}
def _as_float(v,default=0.0):
 try:return float(v)
 except (TypeError,ValueError):return default
def _as_dict(v):return v if isinstance(v,dict) else {}
def _truthy(v):return v is True or isinstance(v,str) and v.strip().lower() in {"1","true","yes","on"}
def _has_browser_execution_proof(f,e):
 for p in (f.get("browser_proof"),e.get("browser_proof")):
  if isinstance(p,dict) and p.get("proven") is True and p.get("proof_producer")=="shakerscan" and str(p.get("evidence_type") or "").lower() in {"dom_execution","browser_execution"} and str(p.get("technique") or "").lower().startswith("headless_xss_"):return True
 return False
def _has_verified_proof_contract_v2(f):
 p=_as_dict(f.get("proof_contract_v2")) or _as_dict(_as_dict(f.get("evidence")).get("proof_contract_v2"));pred=_as_dict(p.get("predicate"));r=_as_dict(p.get("reexecution"));required=r.get("required",True) is not False;ok=r.get("performed") is True if required else r.get("performed") in {False,True};return bool(p.get("schema_version")=="proof-contract/v2" and str(p.get("contract_id") or "").strip() and str(p.get("contract_version") or "").strip() and str(r.get("verifier_build") or "").strip() and ok and p.get("verdict")=="verified" and p.get("promotable") is True and pred.get("satisfied") is True and not list(pred.get("missing") or []))
def _proof_type(f):
 e=_as_dict(f.get("evidence"));v=_as_dict(f.get("validation"));p=_as_dict(f.get("poe"));r=_as_dict(f.get("poe_result"));return str(f.get("proof_type") or e.get("proof_type") or v.get("proof_type") or v.get("poe_technique") or r.get("evidence_type") or p.get("evidence_type") or "").strip().lower()
def _legacy_reexecution_evidence(f):
 e=_as_dict(f.get("evidence"));v=_as_dict(f.get("validation"));p=_as_dict(f.get("poe_result")) or _as_dict(f.get("poe"))
 for c in (f,e,v,p):
  if any(c.get(k) is True for k in ("reexecuted_at_handoff","reexecution_performed","reexecuted","replayed")):return True,str(c.get("verifier_build") or f.get("tool") or "dast-verifier")[:200]
 if _has_browser_execution_proof(f,e):return True,str(v.get("verifier_build") or "headless-xss-verifier")[:200]
 pt=_proof_type(f)
 if pt in {"repeated_semantic_response_diff","cross_principal_replay","write_cross_principal_replay","postcondition_verification","indirect_canary_disclosure"}:return True,str(v.get("verifier_build") or f.get("tool") or pt)[:200]
 if p.get("proven") is True and str(p.get("evidence_type") or "").strip().lower() in _DETERMINISTIC_PROOF_TYPES:return True,str(p.get("verifier_build") or f.get("tool") or "proof-of-exploit")[:200]
 return False,None
def _has_legacy_deterministic_exploit_proof(f):
 e=_as_dict(f.get("evidence"));v=_as_dict(f.get("validation"));p=_as_dict(f.get("poe"));r=_as_dict(f.get("poe_result"))
 if any(_truthy(c.get(k)) for c,k in ((f,"proof_of_exploitation"),(e,"proof_of_exploitation"),(v,"poe_proven"),(p,"proven"),(r,"proven"))):return True
 if e.get("extraction_evidence") or f.get("extraction_evidence") or e.get("extracted_data") or f.get("extracted_data") or _has_browser_execution_proof(f,e):return True
 if _proof_type(f) in _DETERMINISTIC_PROOF_TYPES:return True
 return _truthy(v.get("verified")) and str(v.get("evidence_level") or "").strip().lower() in _CONFIRMED_EVIDENCE_LEVELS
def build_dast_proof_contract_v2(f):
 if not _has_legacy_deterministic_exploit_proof(f):return None
 e=_as_dict(f.get("evidence"));v=_as_dict(f.get("validation"));p=_as_dict(f.get("poe_result")) or _as_dict(f.get("poe"));basis=_proof_type(f) or "proof_of_exploitation";subject={"url":str(f.get("url") or e.get("url") or e.get("endpoint") or "")[:2000] or None,"method":str(f.get("method") or e.get("method") or "GET").upper()[:16]};obs=[{"proof_basis":basis,"postcondition_verified":any(x.get("postcondition_verified") is True for x in e.get("violations",[]) if isinstance(x,dict)),"indirect_fixture_verified":any(x.get("indirect_fixture_verified") is True for x in e.get("violations",[]) if isinstance(x,dict))}];reexec,verifier=_legacy_reexecution_evidence(f);return {"schema_version":"proof-contract/v2","contract_id":f"dast.{basis}"[:160],"contract_version":"1.0.0","family":str(f.get("family") or f.get("tool") or "dast")[:80],"subject":{k:x for k,x in subject.items() if x is not None},"reexecution":{"required":False,"performed":reexec,"verifier_build":verifier or str(v.get("verifier_build") or f.get("tool") or "dast-verifier")[:200]},"controls":[{"legacy_adapter":True,"normalization_boundary":"dast_precision_policy"}],"observations":obs,"proof_basis":basis,"predicate":{"satisfied":True,"reason":"trusted deterministic producer output normalized","requirements":["deterministic_proof"],"met":["deterministic_proof"],"missing":[],"refuted_by":[]},"verdict":"verified","promotable":True,"traffic_receipt_id":None,"tool_receipt_ids":[]}
def ai_confidence(f):return _as_float(f.get("ai_confidence"),0.0)
def ai_classification_source(f):return str(f.get("ai_classification_source") or "").strip().lower()
def has_deterministic_exploit_proof(f):return _has_verified_proof_contract_v2(f) if "proof_contract_v2" in f or "proof_contract_v2" in _as_dict(f.get("evidence")) else _has_legacy_deterministic_exploit_proof(f)
def is_trusted_ai_verdict(f:dict[str,Any],*,min_confidence:float=0.7)->bool:return ai_classification_source(f) in TRUSTED_AI_CLASSIFICATION_SOURCES and ai_confidence(f)>=min_confidence
def should_suppress_ai_false_positive(f:dict[str,Any],*,min_confidence:float=0.7)->bool:
 if has_deterministic_exploit_proof(f) or not is_trusted_ai_verdict(f,min_confidence=min_confidence):return False
 return str(f.get("ai_classification") or f.get("ai_verdict") or "").strip().lower() in {"false_positive","false-positive","not_exploitable","benign"}
