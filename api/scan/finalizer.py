"""Pure Scan report assembly from terminal action results and observations."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any, Mapping, Sequence

from .action_plan import ScanActionPlan
from .capability_result import CapabilityResultReference, CapabilityResultStatus


SCAN_REPORT_SCHEMA = "canonical-scan-report/v2"
_SEVERITY_WEIGHT = {
    "critical": 20,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0,
}
_ACTIVE_VERIFIER_CAPABILITIES = frozenset({
    "templates.scan", "xss.verify", "sqli.verify", "authz.verify",
    "browser.proof",
})
_TRAFFIC_BUDGETS = frozenset({
    "http_requests", "state_changing_requests", "browser_actions",
    "tcp_ports_attempted", "hosts_attempted",
})


class ScanFinalizationError(ValueError):
    """Terminal receipts are incomplete or inconsistent with the Scan plan."""


def _receipt(result: CapabilityResultReference) -> dict[str, Any]:
    return result.receipt_ref.canonical_dict()


def _base_finding(
    *,
    tool: str,
    title: str,
    severity: str,
    cwe: str,
    url: Any,
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "title": title,
        "description": title,
        "severity": severity,
        "cvss_score": {
            "critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0,
        }.get(severity),
        "tool": tool,
        "source": "dast",
        "cwe": cwe,
        "cwe_name": None,
        "owasp": None,
        "url": str(url or "") or None,
        "evidence": dict(evidence),
    }


def _findings_for_action(
    result: CapabilityResultReference,
    observations: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    receipt = _receipt(result)
    allowed_kinds = {
        "xss.verify": {"xss_alert"},
        "sqli.verify": {"sqli_finding"},
        "authz.verify": {"authz_differential"},
        "templates.scan": {"template_match"},
        "tls.inspect": {"tls_protocol"},
    }.get(result.capability_name, set())
    for raw in observations:
        item = dict(raw)
        kind = str(item.get("kind") or "")
        if kind not in allowed_kinds:
            continue
        if kind == "xss_alert" and item.get("proof_state") == "verified":
            finding = _base_finding(
                tool="dalfox",
                title="Verified cross-site scripting",
                severity="high",
                cwe="CWE-79",
                url=item.get("url"),
                evidence={
                    "url": item.get("url"),
                    "param": item.get("param"),
                    "payload_sha256": item.get("payload_sha256"),
                    "message": item.get("message"),
                    "canonical_capability": "xss.verify",
                    "capability_receipt": receipt,
                    "detail": {"verified": True, "type": "verified"},
                },
            )
            finding.update({
                "verified": True,
                "suspected": False,
                "needs_verification": False,
                "proof_state": "verified",
                "verification_reason": "Deterministic alert execution proof satisfied",
            })
            findings.append(finding)
        elif kind == "sqli_finding":
            # SQLMap labels remain candidates until a payload/control
            # differential produces the deterministic proof contract.
            finding = _base_finding(
                tool="sqlmap",
                title="Potential SQL injection",
                severity="high",
                cwe="CWE-89",
                url=item.get("url"),
                evidence={
                    "url": item.get("url"),
                    "method": item.get("method") or "GET",
                    "param": item.get("param"),
                    "sqlmap_message": item.get("message"),
                    "canonical_capability": "sqli.verify",
                    "capability_receipt": receipt,
                },
            )
            finding.update({
                "verified": False,
                "suspected": True,
                "needs_verification": True,
                "proof_state": "likely_vulnerable",
                "verification_reason": "Payload/control differential is missing",
            })
            findings.append(finding)
        elif (
            kind == "authz_differential"
            and item.get("proof_state") == "verified"
            and item.get("proof_type") == "cross_principal_replay"
            and item.get("principal_contexts_distinct") is True
            and item.get("object_absent_from_secondary_listing") is True
            and item.get("responses_equivalent") is True
        ):
            finding = _base_finding(
                tool="smart_authz",
                title="Verified broken object authorization",
                severity="high",
                cwe="CWE-639",
                url=item.get("consumer_url"),
                evidence={
                    "url": item.get("consumer_url"),
                    "producer_url": item.get("producer_url"),
                    "resource_id_sha256": item.get("resource_id_sha256"),
                    "owner_status": item.get("owner_status"),
                    "attacker_status": item.get("attacker_status"),
                    "accepted_principal_responses": dict(
                        item.get("accepted_principal_responses") or {}
                    ),
                    "distinct_principal_control": True,
                    "object_id_absent_from_attacker_listing": True,
                    "responses_equivalent": True,
                    "proof_type": "cross_principal_replay",
                    "canonical_capability": "authz.verify",
                    "capability_receipt": receipt,
                },
            )
            finding.update({
                "verified": True,
                "suspected": False,
                "needs_verification": False,
                "proof_state": "verified",
                "verification_reason": "Cross-principal owner-object replay proof satisfied",
            })
            findings.append(finding)
        elif kind == "tls_protocol":
            tls_issues = (
                (item.get("certificate_expired") is True,
                 "TLS certificate is expired", "high", "CWE-295"),
                (item.get("certificate_not_yet_valid") is True,
                 "TLS certificate is not yet valid", "medium", "CWE-295"),
                (item.get("certificate_hostname_matches") is False,
                 "TLS certificate hostname mismatch", "high", "CWE-295"),
                (item.get("certificate_trust") == "untrusted",
                 "TLS certificate chain is not trusted", "medium", "CWE-295"),
                (item.get("legacy_protocol_negotiated") is True,
                 "Legacy TLS protocol negotiated", "high", "CWE-326"),
                (item.get("weak_cipher") is True,
                 "Weak TLS cipher negotiated", "high", "CWE-327"),
                (item.get("certificate_weak_signature") is True,
                 "TLS certificate uses a weak signature", "high", "CWE-327"),
                (item.get("certificate_weak_public_key") is True,
                 "TLS certificate uses a weak public key", "high", "CWE-326"),
                (item.get("certificate_expiring_within_30_days") is True,
                 "TLS certificate expires within 30 days", "low", "CWE-295"),
            )
            for present, title, severity, cwe in tls_issues:
                if not present:
                    continue
                finding = _base_finding(
                    tool="tls.inspect",
                    title=title,
                    severity=severity,
                    cwe=cwe,
                    url=item.get("origin"),
                    evidence={
                        "origin": item.get("origin"),
                        "pinned_address": item.get("pinned_address"),
                        "port": item.get("port"),
                        "protocol": item.get("protocol"),
                        "cipher": item.get("cipher"),
                        "certificate_sha256": item.get("certificate_sha256"),
                        "canonical_capability": "tls.inspect",
                        "capability_receipt": receipt,
                    },
                )
                finding.update({
                    "verified": True,
                    "suspected": False,
                    "needs_verification": False,
                    "proof_state": "verified",
                    "verification_reason": (
                        "Pinned deterministic TLS posture proof satisfied"
                    ),
                })
                findings.append(finding)
        elif kind == "template_match":
            severity = str(item.get("severity") or "info").strip().lower()
            if severity not in _SEVERITY_WEIGHT:
                severity = "info"
            finding = _base_finding(
                tool="nuclei",
                title=str(item.get("name") or item.get("template_id") or "Template match")[:300],
                severity=severity,
                cwe=str(item.get("cwe") or "") or None,
                url=item.get("matched_at") or item.get("url"),
                evidence={
                    "template_id": item.get("template_id"),
                    "matcher_name": item.get("matcher_name"),
                    "matched_at": item.get("matched_at") or item.get("url"),
                    "canonical_capability": "templates.scan",
                    "capability_receipt": receipt,
                },
            )
            finding.update({
                "verified": False,
                "suspected": True,
                "needs_verification": severity in {"critical", "high"},
                "proof_state": "candidate",
                "verification_reason": "Template match requires its deterministic proof contract",
            })
            findings.append(finding)
    return findings


def _finding_identity(finding: Mapping[str, Any]) -> str:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), Mapping) else {}
    material = {
        "tool": finding.get("tool"),
        "title": finding.get("title"),
        "url": finding.get("url"),
        "param": evidence.get("param"),
        "template_id": evidence.get("template_id"),
        "resource_id_sha256": evidence.get("resource_id_sha256"),
    }
    return hashlib.sha256(json.dumps(
        material, sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")).hexdigest()


def _score(findings: Sequence[Mapping[str, Any]]) -> tuple[int, str]:
    score = max(0, 100 - sum(
        _SEVERITY_WEIGHT.get(str(item.get("severity") or "info"), 0)
        for item in findings
    ))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return score, grade


def finalize_scan_report(
    *,
    plan: ScanActionPlan,
    target_url: str,
    action_results: Mapping[str, CapabilityResultReference],
    observations: Mapping[str, Sequence[Mapping[str, Any]]],
    work_manifest_references: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Build the final report without network, process, filesystem, or clock access."""
    finalization_actions = tuple(
        action for action in plan.actions
        if action.action_id == "finalize.report"
    )
    if len(finalization_actions) != 1:
        raise ScanFinalizationError("plan must contain exactly one finalization action")
    finalization_action = finalization_actions[0]
    expected_actions = tuple(
        action for action in plan.actions
        if action.action_id != finalization_action.action_id
    )
    expected_ids = tuple(action.action_id for action in expected_actions)
    if set(action_results) != set(expected_ids):
        raise ScanFinalizationError(
            "finalization requires every pre-finalization action result"
        )
    findings_by_id: dict[str, dict[str, Any]] = {}
    action_rows: list[dict[str, Any]] = []
    for action in expected_actions:
        result = action_results[action.action_id]
        if result.action_digest != action.action_digest:
            raise ScanFinalizationError("action result is detached from finalization plan")
        rows = tuple(dict(item) for item in observations.get(action.action_id, ()))
        if result.observation_manifest_ref is None and rows:
            raise ScanFinalizationError("observations lack a manifest-bound action result")
        if (
            result.observation_manifest_ref is not None
            and len(rows) != result.observation_manifest_ref.count
        ):
            raise ScanFinalizationError("observation count differs from its action manifest")
        for finding in _findings_for_action(result, rows):
            findings_by_id.setdefault(_finding_identity(finding), finding)
        action_rows.append({
            "action_id": action.action_id,
            "stage": action.stage,
            "capability_name": action.capability_name,
            "required": action.required,
            "supporting": action.supporting,
            "status": result.status.value,
            "reason_code": (
                result.reason_code.value if result.reason_code is not None else None
            ),
            "receipt": result.receipt_ref.canonical_dict(),
            "observation_manifest": (
                result.observation_manifest_ref.canonical_dict()
                if result.observation_manifest_ref is not None else None
            ),
            "budget_reserved": dict(result.budget_reserved),
            "budget_consumed": dict(result.budget_consumed),
        })
    findings = list(findings_by_id.values())
    score, grade = _score(findings)
    required_rows = [
        (action, action_results[action.action_id])
        for action in expected_actions if action.required
    ]
    statuses = {result.status for _action, result in required_rows}
    cancelled = CapabilityResultStatus.CANCELLED in statuses
    failed = bool(statuses & {
        CapabilityResultStatus.FAILED,
        CapabilityResultStatus.BLOCKED,
    })
    degraded = bool(statuses - {CapabilityResultStatus.SUCCESS})
    coverage_status = (
        "cancelled" if cancelled else "failed" if failed and not findings
        else "partial" if degraded else "complete"
    )
    reasons = sorted({
        result.reason_code.value
        for _action, result in required_rows if result.reason_code is not None
    })
    work_manifests = [dict(item) for item in work_manifest_references]
    candidate_count = sum(
        max(0, int(item.get("entry_count") or 0))
        for item in work_manifests
        if item.get("kind") == "candidate" and item.get("status") != "cancelled"
    )
    zero_attempt_actions = [
        action.action_id
        for action in expected_actions
        if action.capability_name in _ACTIVE_VERIFIER_CAPABILITIES
        and candidate_count > 0
        and action_results[action.action_id].status in {
            CapabilityResultStatus.SUCCESS, CapabilityResultStatus.PARTIAL,
        }
        and not any(
            int(amount) > 0
            for name, amount in action_results[action.action_id].budget_consumed.items()
            if name in _TRAFFIC_BUDGETS
        )
    ]
    placement_gaps = [
        action.action_id
        for action in expected_actions
        if (
            action_results[action.action_id].reason_code is not None
            and action_results[action.action_id].reason_code.value
            == "placement_unavailable"
        )
    ]
    unproven_critical_high = sum(
        1 for item in findings
        if item.get("severity") in {"critical", "high"}
        and item.get("verified") is not True
    )
    required_incomplete = [
        (action, result)
        for action, result in required_rows
        if result.status is not CapabilityResultStatus.SUCCESS
    ]
    reliability_reasons = sorted({
        (
            result.reason_code.value
            if result.reason_code is not None
            else "required_capability_incomplete"
        )
        for _action, result in required_incomplete
    } | ({"active_verifier_zero_attempts"} if zero_attempt_actions else set())
      | ({"placement_unavailable"} if placement_gaps else set())
      | ({"unproven_critical_high"} if unproven_critical_high else set()))
    grade_reliable = not reliability_reasons
    rendered_grade = grade if grade_reliable else f"{grade}*"
    coverage_reasons = sorted(
        set(reasons)
        | ({"active_verifier_zero_attempts"} if zero_attempt_actions else set())
        | ({"placement_unavailable"} if placement_gaps else set())
    )
    action_status_counts = Counter(row["status"] for row in action_rows)
    optional_gaps = [
        {
            "action_id": action.action_id,
            "capability_name": action.capability_name,
            "status": action_results[action.action_id].status.value,
            "reason_code": (
                action_results[action.action_id].reason_code.value
                if action_results[action.action_id].reason_code is not None
                else None
            ),
        }
        for action in expected_actions
        if not action.required
        and action_results[action.action_id].status is not CapabilityResultStatus.SUCCESS
    ]
    capability_coverage = {
        "total": len(expected_actions),
        "required": len(required_rows),
        "completed": action_status_counts.get("success", 0),
        "partial": (
            action_status_counts.get("partial", 0)
            + action_status_counts.get("timed_out", 0)
        ),
        "blocked": action_status_counts.get("blocked", 0),
        "failed": action_status_counts.get("failed", 0),
        "skipped": action_status_counts.get("skipped", 0),
        "cancelled": action_status_counts.get("cancelled", 0),
        "actions": [{
            "action_id": row["action_id"],
            "capability_name": row["capability_name"],
            "required": row["required"],
            "status": row["status"],
            "reason_code": row["reason_code"],
        } for row in action_rows],
    }
    if zero_attempt_actions and coverage_status == "complete":
        coverage_status = "partial"
    verified = sum(1 for item in findings if item.get("verified") is True)
    suspected = sum(1 for item in findings if item.get("suspected") is True)
    return {
        "schema_version": SCAN_REPORT_SCHEMA,
        "target": str(target_url),
        "findings": findings,
        "result": {
            "score": score,
            "grade": rendered_grade,
            "grade_reliable": grade_reliable,
            "score_policy": "verified_and_suspected_severity_weight/v1",
        },
        "coverage": {
            "status": coverage_status,
            "reasons": coverage_reasons,
            "planned_action_count": len(plan.actions),
            "terminal_action_count": len(action_rows),
            "finalization_action_id": finalization_action.action_id,
            "capability_coverage": capability_coverage,
            "grade_reliability": {
                "reliable": grade_reliable,
                "reasons": reliability_reasons,
            },
            "optional_gaps": optional_gaps,
            "active_zero_attempt_actions": zero_attempt_actions,
        },
        "verification_summary": {
            "verified": verified,
            "suspected": suspected,
            "unproven_critical_high": unproven_critical_high,
        },
        "canonical_action_execution": {
            "schema_version": "canonical-scan-action-execution/v1",
            "plan_digest": plan.plan_digest,
            "execution_plan_digest": plan.execution_plan_digest,
            "target_binding_digest": plan.target_binding_digest,
            "actions": action_rows,
            "finalization_action": {
                "action_id": finalization_action.action_id,
                "action_digest": finalization_action.action_digest,
                "status": "success",
            },
            "work_manifests": work_manifests,
        },
        "scan_metadata": {
            "status": coverage_status,
            "partial": coverage_status == "partial",
            "cancelled": coverage_status == "cancelled",
            "finding_promotion_authority": "deterministic_proof_contracts_only",
            "finalizer": "pure_receipt_projection/v1",
            "grade_reliable": grade_reliable,
            "grade_reliability_reasons": reliability_reasons,
        },
    }
