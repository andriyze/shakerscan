from __future__ import annotations

import json
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any

try:
    from ai_gate.probe_registry import PROBE_PACK_DEFINITIONS
except ModuleNotFoundError as exc:
    if exc.name not in {"ai_gate", "ai_gate.probe_registry"}:
        raise
    from api.ai_gate.probe_registry import PROBE_PACK_DEFINITIONS


SCHEMA_VERSION = "2026-05-11.ai-redteam-artifacts.v1"

COURSE_MODULES: tuple[dict[str, Any], ...] = (
    {
        "week": 1,
        "title": "AI, LLM, RAG, and agent fundamentals",
        "focus": "Architecture, trust boundaries, prompt assembly, retrieval, tools, and model/app/test distinctions.",
        "shakerscan_support": [
            "AI Gate target templates for chat, RAG, agent trace, and MCP trace surfaces.",
            "Exposure graph nodes for AI targets, MCP tools, model artifacts, scans, and findings.",
        ],
        "recommended_outputs": ["AI system diagram", "trust-boundary notes", "initial risk list"],
    },
    {
        "week": 2,
        "title": "Scope, rules of engagement, and threat modeling",
        "focus": "Allowed tests, data handling, rate limits, production confirmation, evidence capture, and escalation paths.",
        "shakerscan_support": [
            "AI Gate production confirmation gate.",
            "Report exports with scope, target metadata, timestamps, probe packs, and evidence records.",
        ],
        "recommended_outputs": ["rules of engagement", "threat model", "test plan"],
    },
    {
        "week": 3,
        "title": "LLM application security testing",
        "focus": "Direct prompt injection, prompt leakage, sensitive disclosure, insecure output handling, and abuse controls.",
        "shakerscan_support": [
            "shaker-ai-smoke and shaker-owasp-llm probe packs.",
            "AI verdict, confidence, rationale, detector hits, and semantic judge fields on findings.",
        ],
        "recommended_outputs": ["prompt-injection finding", "leakage finding", "output-handling finding"],
    },
    {
        "week": 4,
        "title": "RAG security testing",
        "focus": "Retrieval authorization, data isolation, malicious documents, citations, stale documents, and grounding.",
        "shakerscan_support": [
            "shaker-rag-lite probe pack.",
            "RAG control evidence for ACLs, ingestion controls, tenant isolation, source citation, and content delimiting.",
        ],
        "recommended_outputs": ["RAG ACL tests", "malicious document tests", "citation/grounding notes"],
    },
    {
        "week": 5,
        "title": "Agent and tool security",
        "focus": "Tool scopes, approval gates, delegated identity, dry-run mode, transaction limits, logs, and kill switch.",
        "shakerscan_support": [
            "shaker-agent-abuse probe pack.",
            "Agent control evidence for scopes, approvals, sandboxing, audit logs, anomaly detection, and kill switch.",
        ],
        "recommended_outputs": ["tool inventory", "approval-bypass tests", "tool-call evidence"],
    },
    {
        "week": 6,
        "title": "MCP and connector security",
        "focus": "OAuth/OIDC, token audience, PKCE, consent, scopes, confused deputy, and tool metadata.",
        "shakerscan_support": [
            "shaker-mcp-security probe pack.",
            "MCP findings for audience confusion, PKCE gaps, overbroad scopes, local command consent bypass, and schema oversharing.",
        ],
        "recommended_outputs": ["MCP checklist", "scope/consent findings", "trace evidence"],
    },
    {
        "week": 7,
        "title": "Cloud AI security",
        "focus": "IAM, networking, secrets, logs, retention, private endpoints, SIEM, DLP, and egress controls.",
        "shakerscan_support": [
            "Control evidence fields for cloud security design, vendors, logging, retention, and incident response.",
            "Generic DAST scans for the surrounding app/API and exposed cloud metadata hints.",
        ],
        "recommended_outputs": ["cloud AI review memo", "logging and data-retention notes"],
    },
    {
        "week": 8,
        "title": "Model and data supply-chain security",
        "focus": "Model provenance, licenses, unsafe serialization, hashes, signatures, malware evidence, SBOMs, and approvals.",
        "shakerscan_support": [
            "Model Intake artifact scanner.",
            "Checks for unsafe formats, archive payloads, checksum mismatch, signature/provenance/model-card gaps, and approval gates.",
        ],
        "recommended_outputs": ["model intake SOP", "model supply-chain findings"],
    },
    {
        "week": 9,
        "title": "Automated evaluation and red-team tooling",
        "focus": "Repeatable eval sets, expected behavior, evidence, regression tests, and manual validation.",
        "shakerscan_support": [
            "Probe/test-case catalog endpoint.",
            "Exports for JSON, promptfoo-style YAML, PyRIT-style JSON, and garak-style JSONL seed sets.",
        ],
        "recommended_outputs": ["50-case eval set", "manual vs automated comparison"],
    },
    {
        "week": 10,
        "title": "Detection, monitoring, and AI incident response",
        "focus": "Prompt/retrieval/tool telemetry, alerts, containment, poisoned-doc rollback, and retest workflow.",
        "shakerscan_support": [
            "Probe transcripts, detector hits, AI target logs, finding status, analyst notes, and retest history.",
        ],
        "recommended_outputs": ["logging schema", "alert rules", "AI incident runbook"],
    },
    {
        "week": 11,
        "title": "AI governance and control mapping",
        "focus": "AI inventory, risk tiering, use-case intake, vendor review, control mapping, exceptions, and reassessment.",
        "shakerscan_support": [
            "AI control evidence pack mapped to NIST AI RMF, ISO 27001, OWASP LLM, and governance fields.",
            "Optional enforcement of missing control baseline as a finding.",
        ],
        "recommended_outputs": ["use-case intake", "risk rubric", "control mapping"],
    },
    {
        "week": 12,
        "title": "Capstone and portfolio packaging",
        "focus": "End-to-end assessment from scope through retest, evidence, mitigations, residual risk, and presentation.",
        "shakerscan_support": [
            "AI red-team report export with scope, findings, evidence, control readiness, calibration summary, and validation state.",
        ],
        "recommended_outputs": ["red-team report", "retest evidence", "portfolio summary"],
    },
)

CAPSTONE_CHECKLIST: tuple[dict[str, Any], ...] = (
    {
        "id": "scope",
        "label": "Scope and rules of engagement",
        "evidence_fields": ["target_url", "scan_type", "run_kind", "environment", "probe_pack", "created_at"],
    },
    {
        "id": "threat_model",
        "label": "Threat model and trust boundaries",
        "evidence_fields": ["metadata_json.threat_model", "metadata_json.cloud_security_design"],
    },
    {
        "id": "rag_controls",
        "label": "RAG access controls and malicious document tests",
        "evidence_fields": [
            "retrieval_acl_matrix",
            "metadata_filtering",
            "vector_tenant_isolation",
            "malicious_document_tests",
            "source_citation_policy",
        ],
    },
    {
        "id": "agent_controls",
        "label": "Agent/tool authorization controls",
        "evidence_fields": [
            "tool_inventory",
            "per_tool_scopes",
            "delegated_identity",
            "write_action_approval",
            "dry_run_mode",
            "transaction_limits",
        ],
    },
    {
        "id": "mcp_controls",
        "label": "MCP/OAuth connector controls",
        "evidence_fields": ["token_audience_validation", "no_token_passthrough", "user_consent", "audit_logs"],
    },
    {
        "id": "model_supply_chain",
        "label": "Model intake and supply-chain review",
        "evidence_fields": [
            "artifact_url",
            "model_card_url",
            "expected_sha256",
            "signature_url",
            "metadata_json.sbom",
            "metadata_json.security_evals",
        ],
    },
    {
        "id": "manual_validation",
        "label": "Manual validation and retest state",
        "evidence_fields": ["finding.status", "finding.notes", "last_verification_verdict", "ai_verdict"],
    },
    {
        "id": "reporting",
        "label": "Professional report, residual risk, and next steps",
        "evidence_fields": ["severity_counts", "evidence_items", "control_summary", "calibration_summary"],
    },
)


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    try:
        import uuid

        if isinstance(value, uuid.UUID):
            return str(value)
    except Exception:
        pass
    return value


def _decode_jsonish(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return value
    return value


def _as_dict(value: Any) -> dict[str, Any]:
    value = _decode_jsonish(value)
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    value = _decode_jsonish(value)
    return value if isinstance(value, list) else []


def _coerce_findings(scan: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    result = _as_dict(scan.get("result"))
    raw_findings = _as_list(result.get("findings"))
    persisted_findings = _as_list(scan.get("findings"))
    return [_json_safe(_as_dict(item)) for item in raw_findings], [_json_safe(_as_dict(item)) for item in persisted_findings]


def _evidence_record(finding: dict[str, Any]) -> dict[str, Any]:
    return _as_dict(finding.get("evidence"))


def _finding_keys(finding: dict[str, Any]) -> set[str]:
    evidence = _evidence_record(finding)
    candidates = [
        finding.get("id"),
        finding.get("fingerprint"),
        finding.get("source_finding_id"),
        evidence.get("source_finding_id"),
        evidence.get("fingerprint"),
        evidence.get("expected_finding"),
        evidence.get("oracle_expected_finding"),
    ]
    return {str(item).strip() for item in candidates if str(item or "").strip()}


def _persisted_by_key(persisted_findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    mapped: dict[str, dict[str, Any]] = {}
    for finding in persisted_findings:
        for key in _finding_keys(finding):
            mapped.setdefault(key, finding)
    return mapped


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        counts[severity if severity in counts else "info"] += 1
    return counts


def _value_counts(values: list[Any], default: str = "unknown") -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or default).strip().lower() or default
        counts[key] = counts.get(key, 0) + 1
    return counts


def _normalize_expected_id(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    return raw if raw.startswith("ai_gate:") else f"ai_gate:{raw}"


def _extract_expected_from_metadata(metadata: dict[str, Any]) -> list[str]:
    raw = metadata.get("expected_shakerscan_findings") or metadata.get("expected_findings") or []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return sorted({_normalize_expected_id(item) for item in raw if _normalize_expected_id(item)})


def _extract_detected_expected(findings: list[dict[str, Any]]) -> list[str]:
    detected: set[str] = set()
    for finding in findings:
        evidence = _evidence_record(finding)
        for key in ("oracle_expected_finding", "expected_finding"):
            normalized = _normalize_expected_id(evidence.get(key))
            if normalized:
                detected.add(normalized)
        source_id = str(finding.get("source_finding_id") or finding.get("id") or "").strip()
        if source_id.startswith("ai_gate:"):
            detected.add(source_id)
    return sorted(detected)


def _is_safe_fixture(scan: dict[str, Any], metadata: dict[str, Any]) -> bool:
    if metadata.get("safe_fixture") is True:
        return True
    result = _as_dict(scan.get("result"))
    ai_gate = _as_dict(result.get("ai_gate"))
    return ai_gate.get("safe_fixture") is True


def _build_calibration_summary(
    scan: dict[str, Any],
    findings: list[dict[str, Any]],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    expected = _extract_expected_from_metadata(metadata)
    detected = _extract_detected_expected(findings)
    safe_fixture = _is_safe_fixture(scan, metadata)
    actionable_detected = [
        finding
        for finding in findings
        if str(finding.get("severity") or "info").lower() not in {"info"}
    ]
    missed = sorted(set(expected) - set(detected))
    unexpected = sorted(set(detected) - set(expected)) if expected else []
    safe_fixture_failures = len(actionable_detected) if safe_fixture and not expected else 0

    available = bool(expected or detected or safe_fixture or metadata.get("calibration_run"))
    verdict = "not_available"
    if available:
        if missed or safe_fixture_failures:
            verdict = "fail"
        elif unexpected:
            verdict = "review"
        else:
            verdict = "pass"

    return {
        "available": available,
        "verdict": verdict,
        "expected": expected,
        "detected": detected,
        "missed": missed,
        "unexpected": unexpected,
        "safe_fixture": safe_fixture,
        "safe_fixture_failures": safe_fixture_failures,
    }


def _summarize_control_evidence(result: dict[str, Any]) -> dict[str, Any]:
    ai_gate = _as_dict(result.get("ai_gate"))
    control_evidence = _as_dict(ai_gate.get("control_evidence"))
    if not control_evidence:
        return {"available": False}
    summary = _as_dict(control_evidence.get("summary"))
    missing = _as_list(control_evidence.get("missing_required_controls"))
    return {
        "available": True,
        "schema_version": control_evidence.get("schema_version"),
        "target_type": control_evidence.get("target_type"),
        "probe_pack": control_evidence.get("probe_pack"),
        "scan_profile": control_evidence.get("scan_profile"),
        "risk_tier": control_evidence.get("risk_tier"),
        "summary": summary,
        "missing_required_controls": [
            {
                "id": item.get("id"),
                "label": item.get("label"),
                "frameworks": item.get("frameworks"),
            }
            for item in missing
            if isinstance(item, dict)
        ],
        "asset_inventory": _as_dict(control_evidence.get("asset_inventory")),
    }


def _summarize_model_intake(result: dict[str, Any]) -> dict[str, Any]:
    model_intake = _as_dict(result.get("model_intake"))
    if not model_intake:
        return {"available": False}
    checks = _as_dict(model_intake.get("checks"))
    failed_checks = [
        key
        for key, item in checks.items()
        if isinstance(item, dict) and str(item.get("status") or "").lower() in {"fail", "failed", "block"}
    ]
    return {
        "available": True,
        "summary": _as_dict(model_intake.get("summary")),
        "artifact": _as_dict(model_intake.get("artifact")),
        "decision": model_intake.get("decision") or _as_dict(model_intake.get("summary")).get("decision"),
        "failed_checks": failed_checks,
    }


def _evidence_excerpt(evidence: dict[str, Any], max_len: int = 500) -> str:
    preferred = (
        "response_excerpt",
        "response_text",
        "evidence",
        "message",
        "description",
        "note",
        "matched_text",
    )
    for key in preferred:
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:max_len]
    try:
        return json.dumps(evidence, ensure_ascii=False, sort_keys=True)[:max_len]
    except Exception:
        return str(evidence)[:max_len]


def _build_evidence_items(
    raw_findings: list[dict[str, Any]],
    persisted_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    persisted_map = _persisted_by_key(persisted_findings)
    items: list[dict[str, Any]] = []
    for finding in raw_findings:
        evidence = _evidence_record(finding)
        persisted = None
        for key in _finding_keys(finding):
            persisted = persisted_map.get(key)
            if persisted:
                break
        items.append({
            "id": finding.get("id") or evidence.get("source_finding_id"),
            "persisted_id": persisted.get("id") if persisted else None,
            "title": finding.get("title"),
            "severity": finding.get("severity") or "info",
            "owasp": finding.get("owasp"),
            "cwe": finding.get("cwe"),
            "description": finding.get("description"),
            "remediation": finding.get("remediation") or evidence.get("remediation"),
            "ai_verdict": finding.get("ai_verdict") or (persisted or {}).get("ai_verdict"),
            "ai_confidence": finding.get("ai_confidence") or (persisted or {}).get("ai_confidence"),
            "ai_rationale": finding.get("ai_rationale") or (persisted or {}).get("ai_rationale"),
            "validation": {
                "status": (persisted or finding).get("status"),
                "notes": (persisted or {}).get("notes"),
                "last_verification_verdict": (persisted or {}).get("last_verification_verdict"),
                "last_verification_confidence": (persisted or {}).get("last_verification_confidence"),
                "last_verified_at": (persisted or {}).get("last_verified_at"),
            },
            "evidence": {
                "probe_id": evidence.get("probe_id"),
                "judge_layer": evidence.get("judge_layer"),
                "matched_markers": evidence.get("matched_markers"),
                "expected_finding": evidence.get("expected_finding") or evidence.get("oracle_expected_finding"),
                "excerpt": _evidence_excerpt(evidence),
            },
        })
    return items


def _result_scope(scan: dict[str, Any], result: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    ai_gate = _as_dict(result.get("ai_gate"))
    model_intake = _as_dict(result.get("model_intake"))
    options = _as_dict(scan.get("options"))
    return {
        "scan_id": scan.get("id"),
        "target_url": scan.get("target_url"),
        "target_name": scan.get("target_name"),
        "scan_type": scan.get("scan_type"),
        "run_kind": scan.get("run_kind"),
        "ai_target_type": scan.get("ai_target_type") or ai_gate.get("target_type"),
        "environment": options.get("environment") or ai_gate.get("environment"),
        "probe_pack": options.get("probe_pack") or ai_gate.get("probe_pack"),
        "scan_profile": options.get("scan_profile") or ai_gate.get("scan_profile"),
        "model_intake_artifact": model_intake.get("artifact") or options.get("artifact_url"),
        "risk_tier": metadata.get("risk_tier") or metadata.get("ai_risk_tier"),
        "data_classification": metadata.get("data_classification") or metadata.get("data_classes"),
    }


def build_ai_learning_guide() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "title": "AI Security Testing & Red Teaming Learning Map",
        "summary": "A ShakerScan-oriented map from AI red-team learning outcomes to runnable probes, controls, evidence, and report artifacts.",
        "modules": list(COURSE_MODULES),
        "capstone_checklist": list(CAPSTONE_CHECKLIST),
    }


def build_ai_test_case_catalog(pack: str | None = None) -> dict[str, Any]:
    packs = []
    selected_packs = PROBE_PACK_DEFINITIONS
    if pack:
        if pack not in PROBE_PACK_DEFINITIONS:
            raise ValueError(f"unknown pack '{pack}'")
        selected_packs = {pack: PROBE_PACK_DEFINITIONS[pack]}
    for pack_id, probes in selected_packs.items():
        packs.append({
            "id": pack_id,
            "count": len(probes),
            "probes": [
                {
                    "id": probe.id,
                    "family": probe.family,
                    "title": probe.title,
                    "prompt": probe.prompt,
                    "owasp": probe.owasp,
                    "minimum_profile": probe.minimum_profile,
                    "technique": probe.technique,
                    "source_name": probe.source_name,
                    "source_reference": probe.source_reference,
                    "tactics": list(probe.tactics),
                    "expected_safe_behavior": probe.expected_safe_behavior,
                    "expected_attack_success": probe.expected_attack_success,
                    "severity_if_success": probe.severity_if_success,
                    "safe_for_production": probe.safe_for_production,
                    "turns": [
                        {"role": turn.role, "message": turn.message}
                        for turn in probe.conversation_turns
                    ],
                }
                for probe in probes
            ],
        })
    return {"schema_version": SCHEMA_VERSION, "packs": packs}


def _yaml_scalar(value: Any, indent: int = 0) -> str:
    text = "" if value is None else str(value)
    return json.dumps(text, ensure_ascii=False)


def _promptfoo_export(pack: str | None) -> str:
    catalog = build_ai_test_case_catalog(pack)
    lines = [
        "# Generated by ShakerScan AI Gate. Treat as a starter eval; wire provider/target details before running.",
        "description: ShakerScan AI red-team probe export",
        "prompts:",
        '  - "{{prompt}}"',
        "tests:",
    ]
    for pack_item in catalog["packs"]:
        for probe in pack_item["probes"]:
            prompt_value = _yaml_scalar(probe["prompt"], indent=8)
            lines.extend([
                f"  - description: {json.dumps(probe['title'])}",
                "    vars:",
                f"      prompt: {prompt_value}",
                "    metadata:",
                f"      shakerscan_pack: {json.dumps(pack_item['id'])}",
                f"      shakerscan_probe_id: {json.dumps(probe['id'])}",
                f"      family: {json.dumps(probe['family'])}",
                f"      owasp: {json.dumps(probe.get('owasp') or '')}",
                f"      expected_safe_behavior: {_yaml_scalar(probe.get('expected_safe_behavior'), indent=8)}",
                "    assert:",
                "      - type: not-contains",
                '        value: "SHOULD_NOT_APPEAR_UNLESS_TARGET_DEFINES_A_CANARY"',
            ])
    return "\n".join(lines) + "\n"


def _pyrit_export(pack: str | None) -> dict[str, Any]:
    catalog = build_ai_test_case_catalog(pack)
    prompts = []
    for pack_item in catalog["packs"]:
        for probe in pack_item["probes"]:
            prompts.append({
                "name": probe["id"],
                "objective": probe.get("expected_attack_success") or probe["title"],
                "prompt": probe["prompt"],
                "metadata": {
                    "shakerscan_pack": pack_item["id"],
                    "family": probe["family"],
                    "owasp": probe.get("owasp"),
                    "technique": probe.get("technique"),
                    "expected_safe_behavior": probe.get("expected_safe_behavior"),
                    "severity_if_success": probe.get("severity_if_success"),
                },
            })
    return {"schema_version": SCHEMA_VERSION, "format": "pyrit-seed-json", "prompts": prompts}


def _garak_export(pack: str | None) -> str:
    catalog = build_ai_test_case_catalog(pack)
    records = []
    for pack_item in catalog["packs"]:
        for probe in pack_item["probes"]:
            records.append({
                "prompt": probe["prompt"],
                "tags": [
                    "shakerscan",
                    pack_item["id"],
                    probe["family"],
                    probe.get("owasp") or "",
                    probe.get("technique") or "",
                ],
                "meta": {
                    "probe_id": probe["id"],
                    "title": probe["title"],
                    "expected_safe_behavior": probe.get("expected_safe_behavior"),
                    "expected_attack_success": probe.get("expected_attack_success"),
                },
            })
    return "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n"


def build_ai_test_case_export(format_name: str, pack: str | None = None) -> tuple[str | dict[str, Any], str, str]:
    normalized = (format_name or "json").strip().lower()
    if normalized == "json":
        return build_ai_test_case_catalog(pack), "application/json", "json"
    if normalized == "promptfoo":
        return _promptfoo_export(pack), "text/yaml; charset=utf-8", "yaml"
    if normalized == "pyrit":
        return _pyrit_export(pack), "application/json", "json"
    if normalized == "garak":
        return _garak_export(pack), "application/x-ndjson; charset=utf-8", "jsonl"
    raise ValueError("Unsupported export format. Use json, promptfoo, pyrit, or garak.")


def build_ai_redteam_report(scan: dict[str, Any], target_metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    scan = _json_safe(scan)
    result = _as_dict(scan.get("result"))
    raw_findings, persisted_findings = _coerce_findings(scan)
    findings_for_report = raw_findings or persisted_findings
    metadata = _as_dict(target_metadata or scan.get("ai_target_metadata") or {})

    report = {
        "schema_version": SCHEMA_VERSION,
        "report_type": "ai_redteam",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "scan": {
            "id": scan.get("id"),
            "status": scan.get("status"),
            "target_url": scan.get("target_url"),
            "target_name": scan.get("target_name"),
            "scan_type": scan.get("scan_type"),
            "run_kind": scan.get("run_kind"),
            "created_at": scan.get("created_at"),
            "started_at": scan.get("started_at"),
            "completed_at": scan.get("completed_at"),
            "duration_seconds": scan.get("duration_seconds"),
            "score": scan.get("score"),
            "grade": scan.get("grade"),
        },
        "scope": _result_scope(scan, result, metadata),
        "severity_counts": _severity_counts(findings_for_report),
        "calibration_summary": _build_calibration_summary(scan, findings_for_report, metadata),
        "control_evidence": _summarize_control_evidence(result),
        "model_intake": _summarize_model_intake(result),
        "capstone_checklist": list(CAPSTONE_CHECKLIST),
        "evidence_items": _build_evidence_items(findings_for_report, persisted_findings),
        "manual_validation_summary": {
            "persisted_findings": len(persisted_findings),
            "validated_findings": sum(
                1
                for finding in persisted_findings
                if finding.get("notes") or str(finding.get("status") or "active") != "active"
            ),
            "statuses": _value_counts([finding.get("status") for finding in persisted_findings], default="active"),
        },
        "reporting_notes": [
            "Treat model output as untrusted evidence and manually validate important findings.",
            "Use persisted finding status and notes to record false positives, accepted risk, remediation, and retest proof.",
            "Map recommendations to deterministic controls: authorization outside the model, retrieval ACLs, least-privilege tools, output validation, logging, monitoring, and human approval for sensitive actions.",
        ],
    }
    return report


def _md_table(rows: list[tuple[Any, Any]]) -> list[str]:
    lines = ["| Field | Value |", "|---|---|"]
    for key, value in rows:
        display_value = str(value if value not in (None, "") else "n/a").replace("|", "\\|")
        lines.append(f"| {key} | {display_value} |")
    return lines


def render_ai_redteam_markdown(report: dict[str, Any]) -> str:
    scan = _as_dict(report.get("scan"))
    scope = _as_dict(report.get("scope"))
    counts = _as_dict(report.get("severity_counts"))
    calibration = _as_dict(report.get("calibration_summary"))
    controls = _as_dict(report.get("control_evidence"))
    model_intake = _as_dict(report.get("model_intake"))
    evidence_items = _as_list(report.get("evidence_items"))

    lines: list[str] = [
        "# ShakerScan AI Red-Team Report",
        "",
        "## Scope",
        *_md_table([
            ("Scan ID", scan.get("id")),
            ("Target", scan.get("target_url")),
            ("Target name", scan.get("target_name")),
            ("Run kind", scan.get("run_kind")),
            ("AI target type", scope.get("ai_target_type")),
            ("Probe pack", scope.get("probe_pack")),
            ("Profile", scope.get("scan_profile")),
            ("Environment", scope.get("environment")),
            ("Status", scan.get("status")),
            ("Completed", scan.get("completed_at")),
        ]),
        "",
        "## Findings Summary",
        *_md_table([
            ("Critical", counts.get("critical", 0)),
            ("High", counts.get("high", 0)),
            ("Medium", counts.get("medium", 0)),
            ("Low", counts.get("low", 0)),
            ("Info", counts.get("info", 0)),
        ]),
        "",
        "## Calibration Summary",
        *_md_table([
            ("Available", calibration.get("available")),
            ("Verdict", calibration.get("verdict")),
            ("Expected", ", ".join(calibration.get("expected") or []) or "n/a"),
            ("Detected", ", ".join(calibration.get("detected") or []) or "n/a"),
            ("Missed", ", ".join(calibration.get("missed") or []) or "none"),
            ("Unexpected", ", ".join(calibration.get("unexpected") or []) or "none"),
            ("Safe fixture failures", calibration.get("safe_fixture_failures", 0)),
        ]),
        "",
        "## Control Evidence",
    ]
    if controls.get("available"):
        summary = _as_dict(controls.get("summary"))
        lines.extend(_md_table([
            ("Risk tier", controls.get("risk_tier")),
            ("Required controls", summary.get("required")),
            ("Present controls", summary.get("present")),
            ("Missing controls", summary.get("missing")),
            ("Evidence ready", summary.get("evidence_ready")),
        ]))
        missing = _as_list(controls.get("missing_required_controls"))
        if missing:
            lines.extend(["", "Missing controls:"])
            for control in missing:
                lines.append(f"- `{control.get('id')}`: {control.get('label')}")
    else:
        lines.append("No AI control evidence pack was present in this scan result.")

    if model_intake.get("available"):
        lines.extend([
            "",
            "## Model Intake",
            *_md_table([
                ("Decision", model_intake.get("decision")),
                ("Failed checks", ", ".join(model_intake.get("failed_checks") or []) or "none"),
            ]),
        ])

    lines.extend(["", "## Evidence Items"])
    if not evidence_items:
        lines.append("No findings were recorded.")
    for item in evidence_items:
        validation = _as_dict(item.get("validation"))
        evidence = _as_dict(item.get("evidence"))
        lines.extend([
            "",
            f"### {item.get('title') or item.get('id')}",
            *_md_table([
                ("Severity", item.get("severity")),
                ("OWASP", item.get("owasp")),
                ("AI verdict", item.get("ai_verdict")),
                ("AI confidence", item.get("ai_confidence")),
                ("Manual status", validation.get("status")),
                ("Analyst notes", validation.get("notes")),
                ("Retest verdict", validation.get("last_verification_verdict")),
                ("Probe ID", evidence.get("probe_id")),
                ("Judge layer", evidence.get("judge_layer")),
                ("Expected finding", evidence.get("expected_finding")),
            ]),
        ])
        if item.get("description"):
            lines.extend(["", str(item.get("description"))])
        if evidence.get("excerpt"):
            lines.extend(["", "Evidence excerpt:", "", "```text", str(evidence.get("excerpt"))[:1000], "```"])

    lines.extend([
        "",
        "## Reporting Notes",
        *[f"- {note}" for note in _as_list(report.get("reporting_notes"))],
        "",
    ])
    return "\n".join(lines)
