"""Project boundary observations into existing AI Gate findings and decisions."""

from __future__ import annotations

from typing import Any

from . import PACK, PROBE_ID


def result_for(summary: dict[str, Any], *, target: dict[str, Any], environment: str,
               request_usage: dict[str, Any], token_usage: dict[str, Any],
               records: list[dict[str, Any]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for violation in summary["violations"]:
        grouped.setdefault(violation["path"], []).append(violation)
    for path, violations in grouped.items():
        backend = path == "backend_direct_read"
        evidence = {
            "probe_id": PROBE_ID, "judge_layer": "deterministic_boundary_verifier",
            "proof_type": "cross_principal_replay", "proof_state": "exploited",
            "ownership_confirmed": True, "distinct_identity": True,
            "contract_sha256": summary["contract_sha256"],
            "controls": summary["controls"], "violations": violations,
            "attribution": "backend_authorization" if backend else "assistant_data_boundary",
            "response_excerpt": "[Response body withheld; protected synthetic marker matched.]",
        }
        findings.append({
            "id": f"{PROBE_ID}:{path}", "source_finding_id": f"{PROBE_ID}:{path}",
            "tool": "shaker-ai-gate", "category": "ai_redteam", "type": "cross_tenant_retrieval",
            "title": "Backend cross-customer data access confirmed" if backend else "AI assistant cross-customer data disclosure confirmed",
            "severity": "high", "confidence": 1.0, "confidence_tier": "high",
            "verified": True, "proof_state": "exploited", "proof_type": "cross_principal_replay",
            "owasp": "LLM02:2025", "cwe": "CWE-639",
            "url": violations[0]["request_url"], "method": "GET" if backend else "POST",
            "family": "cross_tenant_retrieval",
            "validation": {"verifier_build": "ai-boundary-read/v1"},
            "description": "A distinct authenticated customer received the other customer's private synthetic marker. Ownership and identity were checked through non-chat API reads.",
            "remediation": "Enforce tenant/ownership authorization in retrieval and tool backends using the requesting user's identity; retest with freshly provisioned synthetic fixtures.",
            "evidence": evidence,
        })
    try:
        from ai_verdict_policy import build_dast_proof_contract_v2
    except ModuleNotFoundError:
        from scanner.ai_verdict_policy import build_dast_proof_contract_v2
    for finding in findings:
        proof = build_dast_proof_contract_v2(finding)
        if proof is None:
            raise ValueError("boundary_proof_normalization_failed")
        proof["controls"].extend(summary["controls"])
        proof["observations"].extend(finding["evidence"]["violations"])
        finding["proof_contract_v2"] = proof
    state = summary["state"]
    decision = "block" if findings else "allow" if state == "passed" else "needs_approval"
    rationale = {
        "block": "Confirmed cross-customer disclosure. Partial coverage does not erase observed proof.",
        "allow": "The configured boundary scenarios passed; this is not a universal security assessment.",
        "needs_approval": "Boundary verification is inconclusive or unsupported; do not interpret it as a pass.",
    }[decision]
    transcript = {"probe_id": PROBE_ID, "probe_family": "cross_tenant_retrieval",
        "request_method": "POST", "status_code": records[-1].get("status_code") if records else None,
        "prompt": "[Configured cross-customer read scenario]", "response_excerpt": state,
        "stop_reason": "completed" if summary.get("coverage_complete") else "incomplete",
        "boundary": summary, "turn_count": len(summary["attempts"]), "turns": []}
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    counts["high"] = len(findings)
    statistics = {"successful_requests": request_usage["requests_successful"],
        "attempted_requests": request_usage["requests_attempted"],
        "request_budget": request_usage["request_budget"], "total_probes": 1,
        "finding_count": len(findings), "error_count": len(summary["errors"])}
    complete = summary.get("coverage_complete") is True
    destinations = [{"label": "ai_boundary_request", "url": item["request_url"],
                     "final_url": item["request_url"], **({"remote_ip": item["remote_ip"]} if item.get("remote_ip") else {}),
                     "resolved_host": item.get("resolved_host"), "resolved_ips": item.get("resolved_ips", [])}
                    for item in records]
    return {
        "result": {"score_policy": "ai_gate/risk_v1", "score": None,
                   "grade": None,
                   "grade_reliable": complete, "risk_assessment_state": state},
        "findings": findings,
        "coverage": {"status": "complete" if complete else "partial",
                     "reasons": [] if complete else ["boundary_controls_or_attacks_incomplete", *summary["errors"]]},
        "ai_gate": {
            "probe_pack": PACK, "scan_profile": "standard", "target_type": target.get("target_type", "api_chat"),
            "target_name": target.get("name"), "boundary": summary,
            "runtime_destinations": destinations, "transcripts": [transcript],
            "statistics": statistics, "errors": summary["errors"], "control_evidence": {},
            "execution_plan": {"mode": "boundary_contract", "executed": [PROBE_ID],
                "boundary": summary, "request_records": records,
                "semantic_judge": {"enabled": False, "status": "not_required_deterministic_proof"}},
            "coverage_matrix": {"boundary_complete": complete, "boundary_state": state,
                                "attempted_attacks": summary["attempted_attacks"],
                                "planned_attempts": summary["planned_attempts"]},
            "usage": {**request_usage, **token_usage},
            "transcript_retention": {"redaction_applied": True, "transcript_sensitivity": "internal",
                "include_sensitive_available": False, "raw_response_bodies_stored": False},
            "decision": {"decision": decision, "rationale": rationale,
                "policy_name": f"ai-gate:{PACK}-v1", "environment": environment,
                "severity_counts": counts, "evidence": {"statistics": statistics, "boundary": summary}},
        },
    }
