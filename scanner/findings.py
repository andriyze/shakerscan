"""
Finding normalization and management.

This module contains functions for normalizing, scoring, and deduplicating
security findings from various tools. Extracted from scanner.py for better
maintainability.
"""
from __future__ import annotations

import hashlib
import json
from urllib.parse import urlparse
from datetime import datetime, UTC
from typing import Any

# Support both package import (from scanner.findings) and script import (python3 findings.py)
try:
    from .constants import (
        TOOL_CONFIDENCE,
        INFO_ONLY_PATTERNS,
        NUCLEI_INFO_TEMPLATES,
        NUCLEI_EXCLUDE_TEMPLATES,
        CWE_DESCRIPTIONS,
    )
    from .grading import (
        calculate_cvss_score,
        apply_context_modifiers,
        validate_severity_cvss,
        map_to_cwe,
        owasp_mapping,
        soc2_mapping,
        get_cwe_url,
    )
except ImportError:
    from constants import (
        TOOL_CONFIDENCE,
        INFO_ONLY_PATTERNS,
        NUCLEI_INFO_TEMPLATES,
        NUCLEI_EXCLUDE_TEMPLATES,
        CWE_DESCRIPTIONS,
    )
    from grading import (
        calculate_cvss_score,
        apply_context_modifiers,
        validate_severity_cvss,
        map_to_cwe,
        owasp_mapping,
        soc2_mapping,
        get_cwe_url,
    )


def now_utc_iso() -> str:
    """Get current UTC time in ISO format."""
    return datetime.now(UTC).isoformat()


def calculate_confidence(tool: str, evidence: dict, severity: str) -> float:
    """Calculate finding confidence based on tool, evidence, and severity.

    Args:
        tool: Name of the tool that produced the finding
        evidence: Evidence dictionary from the finding
        severity: Severity level of the finding

    Returns:
        Confidence score from 0.0 to 1.0
    """
    # Start with tool base confidence
    base = TOOL_CONFIDENCE.get(tool, 0.60)

    # Evidence quality modifiers
    evidence_str = str(evidence).lower()

    # Strong positive indicators (increase confidence)
    if "exploit" in evidence_str or "payload executed" in evidence_str:
        base = min(0.95, base + 0.15)
    if "data extracted" in evidence_str or "sensitive data" in evidence_str:
        base = min(0.95, base + 0.10)
    if evidence.get("verified") or evidence.get("confirmed"):
        base = min(0.95, base + 0.10)
    if evidence.get("response_diff") or evidence.get("behavior_change"):
        base = min(0.95, base + 0.05)

    # Weak indicators (decrease confidence)
    if "possible" in evidence_str or "potential" in evidence_str:
        base = max(0.30, base - 0.10)
    if "error-based" in evidence_str and "time-based" not in evidence_str:
        base = max(0.40, base - 0.05)
    if evidence.get("heuristic_only"):
        base = max(0.35, base - 0.15)

    # Severity-based adjustments
    if severity == "critical" and base < 0.70:
        base = max(0.35, base - 0.10)
    elif severity == "info":
        base = min(0.60, base)

    return round(base, 2)


def get_confidence_tier(confidence: float) -> str:
    """Get confidence tier label from confidence score.

    Args:
        confidence: Confidence score from 0.0 to 1.0

    Returns:
        Tier label: verified, high, medium, low, or uncertain
    """
    if confidence >= 0.90:
        return "verified"
    elif confidence >= 0.80:
        return "high"
    elif confidence >= 0.65:
        return "medium"
    elif confidence >= 0.50:
        return "low"
    else:
        return "uncertain"


SEVERITY_CONFIDENCE_THRESHOLDS = {
    "critical": 0.85,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.35,
    "info": 0.0,
}


def _max_severity_for_confidence(confidence: float) -> str:
    for severity in ("critical", "high", "medium", "low"):
        if confidence >= SEVERITY_CONFIDENCE_THRESHOLDS[severity]:
            return severity
    return "info"


def _cap_severity(finding: dict[str, Any], max_severity: str) -> None:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    current = str(finding.get("severity") or "info").lower()
    if order.get(current, 0) > order[max_severity]:
        finding.setdefault("precision_policy", {})["original_severity"] = current
        finding["severity"] = max_severity
        finding["cvss_score"] = min(
            float(finding.get("cvss_score") or 0.0),
            {"info": 0.0, "low": 3.0, "medium": 6.0, "high": 8.0}[max_severity],
        )
        finding.setdefault("precision_policy", {})["severity_downgraded"] = True


def _cap_confidence_for_precision(
    finding: dict[str, Any],
    max_confidence: float,
    reason: str,
) -> None:
    policy = finding.setdefault("precision_policy", {})
    current_confidence = float(finding.get("confidence") or 0.5)
    if current_confidence > max_confidence:
        policy.setdefault("original_confidence", current_confidence)
        finding["confidence"] = round(max_confidence, 2)
        policy["confidence_capped"] = True
    else:
        finding["confidence"] = round(current_confidence, 2)
    policy["confidence_cap_reason"] = reason
    finding["confidence_tier"] = get_confidence_tier(float(finding["confidence"]))
    _cap_severity(finding, _max_severity_for_confidence(float(finding["confidence"])))


def _evidence_value(finding: dict[str, Any], key: str) -> Any:
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        return evidence.get(key)
    return None


def _is_vendor_or_framework_js(file_url: str) -> bool:
    if not file_url:
        return False
    parsed = urlparse(file_url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    vendor_hosts = (
        "clerk.",
        "stripe.com",
        "googletagmanager.com",
        "google-analytics.com",
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "unpkg.com",
    )
    framework_paths = (
        "/_next/static/chunks/",
        "/_next/static/runtime/",
        "/static/chunks/",
        "/webpack/",
    )
    return any(marker in host for marker in vendor_hosts) or any(marker in path for marker in framework_paths)


def apply_dast_precision_policy(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Downgrade unproven DAST heuristics so reports distinguish leads from bugs.

    This preserves the evidence for manual review while preventing static or
    contradictory signals from driving high-severity findings and grades.
    """
    for finding in findings:
        tool = str(finding.get("tool") or "").lower()
        title = str(finding.get("title") or "").lower()
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        validation = finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
        poe_result = finding.get("poe_result") if isinstance(finding.get("poe_result"), dict) else {}
        verified = (
            finding.get("verified") is True
            or evidence.get("verified") is True
            or evidence.get("confirmed") is True
            or validation.get("verified") is True
            or validation.get("poe_proven") is True
            or poe_result.get("proven") is True
        )
        finding["verified"] = bool(verified)
        if verified:
            validation["evidence_level"] = validation.get("evidence_level") or "confirmed_exploit"
            if validation:
                finding["validation"] = validation
            finding["suspected"] = False
            finding["needs_verification"] = False
            finding.pop("verification_reason", None)
            proof_present = (
                finding.get("proof_of_exploitation") is True
                or evidence.get("proof_of_exploitation") is True
                or validation.get("poe_proven") is True
                or bool(evidence.get("extraction_evidence"))
                or bool(finding.get("extraction_evidence"))
            )
            min_confidence = 0.95 if proof_present else 0.90
            current_confidence = float(finding.get("confidence") or 0)
            finding["confidence"] = max(current_confidence, min_confidence)
            finding["confidence_tier"] = get_confidence_tier(finding["confidence"])

        if verified:
            continue

        if tool == "bfla":
            if _evidence_value(finding, "path") is None or _evidence_value(finding, "status_code") is None:
                finding["suspected"] = True
                finding["needs_verification"] = True
                finding["verification_reason"] = "BFLA evidence is missing path/status; likely frontend shell or inconclusive route probe"
                _cap_confidence_for_precision(finding, 0.49, "missing_path_or_status")

        elif tool == "ssti":
            finding["suspected"] = True
            finding["needs_verification"] = True
            finding["verification_reason"] = "SSTI requires differential template evaluation proof"
            _cap_confidence_for_precision(finding, 0.64, "missing_differential_template_proof")

        elif tool == "dom_xss":
            finding["suspected"] = True
            finding["needs_verification"] = True
            finding["verification_reason"] = "DOM XSS static source/sink lead without payload execution"
            file_url = str(_evidence_value(finding, "file") or "")
            vendor_static_sink = _is_vendor_or_framework_js(file_url)
            _cap_confidence_for_precision(
                finding,
                0.34 if vendor_static_sink else 0.49,
                "vendor_or_framework_static_sink" if vendor_static_sink else "static_sink_without_execution",
            )

        elif tool == "client_side":
            finding["suspected"] = True
            finding["needs_verification"] = True
            if "prototype pollution" in title or _evidence_value(finding, "type") == "prototype_pollution_sink":
                finding["verification_reason"] = "Prototype pollution heuristic lacks attacker-controlled merge proof"
                _cap_confidence_for_precision(finding, 0.49, "missing_attacker_controlled_merge_proof")
            elif "postmessage" in title:
                finding["verification_reason"] = "postMessage static handler lead lacks exploitability proof"
                _cap_confidence_for_precision(finding, 0.49, "missing_postmessage_exploitability_proof")

        elif tool == "cache_poisoning":
            cacheable = bool(_evidence_value(finding, "cacheable"))
            details = _evidence_value(finding, "details") or []
            poison_confirmed = any(isinstance(item, dict) and item.get("poison_confirmed") for item in details)
            if not poison_confirmed:
                finding["suspected"] = True
                finding["needs_verification"] = True
                finding["verification_reason"] = "Header reflection observed without poisoned same-key cache hit"
                _cap_confidence_for_precision(
                    finding,
                    0.49 if cacheable else 0.34,
                    "missing_poisoned_same_key_cache_hit",
                )

        elif tool == "2fa_bypass":
            method = str(_evidence_value(finding, "method") or "").lower()
            if method == "no_rate_limiting":
                finding["needs_verification"] = True
                finding["verification_reason"] = "Missing OTP throttling is a brute-force hardening gap, not a confirmed 2FA bypass"
                _cap_confidence_for_precision(finding, 0.64, "otp_rate_limit_gap_not_bypass")

        confidence = float(finding.get("confidence") or 0.5)
        finding["confidence_tier"] = get_confidence_tier(confidence)

    return findings


def normalize_finding(
    tool: str,
    title: str,
    severity: str,
    evidence: dict,
    cwe: str | None = None
) -> dict[str, Any]:
    """Normalize a security finding to standard format.

    This function creates a consistent finding structure with:
    - Deterministic ID for deduplication
    - CVSS scoring with context modifiers
    - Compliance mappings (CWE, OWASP, SOC2)
    - Confidence scoring

    Args:
        tool: Name of the tool that produced the finding
        title: Title/description of the finding
        severity: Severity level (critical, high, medium, low, info)
        evidence: Evidence dictionary with details
        cwe: Optional explicit CWE ID

    Returns:
        Normalized finding dictionary
    """
    # Generate deterministic ID
    finding_key = (title + json.dumps(evidence, sort_keys=True, default=str)).encode()
    finding_id = f"{tool}:{hashlib.sha256(finding_key).hexdigest()[:16]}"

    finding: dict[str, Any] = {
        "id": finding_id,
        "tool": tool,
        "title": title,
        "severity": severity,
        "cwe": cwe,
        "evidence": evidence,
        "first_seen": now_utc_iso()
    }

    # Promote key fields to top-level for verification phase
    for key in ("type", "url", "param", "payload", "method", "technique", "dbms",
                "content_type", "body", "request_headers"):
        if key in evidence and evidence[key] is not None:
            finding[key] = evidence[key]

    # Infer type from tool name if not provided
    if "type" not in finding:
        if "sqli" in tool.lower():
            finding["type"] = "SQLi"
        elif "xss" in tool.lower():
            finding["type"] = "XSS"

    # Check if this is an informational-only finding
    title_lower = title.lower()
    is_info_only = False
    downgrade_reason = None

    # Check title against known informational patterns
    for pattern in INFO_ONLY_PATTERNS:
        if pattern in title_lower:
            is_info_only = True
            downgrade_reason = f"Informational finding (matched: {pattern})"
            break

    # Check Nuclei template patterns
    if tool == "nuclei" and not is_info_only:
        template_id = str(evidence.get("template_id", "")).lower()
        for info_template in NUCLEI_INFO_TEMPLATES:
            if info_template in template_id:
                is_info_only = True
                downgrade_reason = f"Nuclei template is informational ({info_template})"
                break

    # Check for excluded templates
    if tool == "nuclei":
        template_id = str(evidence.get("template_id", "")).lower()
        template_tags = str(evidence.get("tags", "")).lower()
        for exclude_pattern in NUCLEI_EXCLUDE_TEMPLATES:
            if exclude_pattern in template_id or exclude_pattern in template_tags:
                finding["excluded"] = True
                finding["exclude_reason"] = f"Template excluded (matched: {exclude_pattern})"
                break

    # Apply info-only downgrade
    if is_info_only:
        original_sev = finding["severity"]  # Capture BEFORE overwrite
        finding["severity"] = "info"
        finding["cvss_score"] = 0.0
        finding["noise_reduction"] = {
            "downgraded": True,
            "reason": downgrade_reason,
            "original_severity": original_sev
        }
    else:
        # Calculate CVSS score
        passed_cvss = evidence.get("cvss_score")
        if passed_cvss and isinstance(passed_cvss, (int, float)) and passed_cvss > 0:
            base_cvss = float(passed_cvss)
        else:
            base_cvss = calculate_cvss_score(finding)

        # Apply context-aware modifiers
        adjusted_cvss = apply_context_modifiers(finding, base_cvss)
        finding["cvss_score"] = adjusted_cvss

        if adjusted_cvss != base_cvss:
            finding["cvss_context_adjusted"] = True
            finding["cvss_base_score"] = base_cvss

        # Validate severity against CVSS
        finding["severity"] = validate_severity_cvss(severity, finding["cvss_score"])

    # Add compliance mappings
    finding["cwe"] = map_to_cwe(finding) if not cwe else cwe
    finding["owasp"] = owasp_mapping(finding)
    finding["soc2"] = soc2_mapping(finding)

    # Add CWE metadata
    if finding["cwe"]:
        finding["cwe_name"] = CWE_DESCRIPTIONS.get(finding["cwe"], "")
        finding["cwe_url"] = get_cwe_url(finding["cwe"])
    else:
        finding["cwe_name"] = ""
        finding["cwe_url"] = ""

    # Calculate confidence
    confidence = calculate_confidence(tool, evidence, finding["severity"])
    finding["confidence"] = confidence
    finding["confidence_tier"] = get_confidence_tier(confidence)

    return finding


def deduplicate_findings(findings: list[dict], aggressive: bool = False) -> list[dict]:
    """Deduplicate findings using the deduplication engine.

    This function consolidates related findings from multiple tools into
    unified, evidence-rich reports.

    Features:
    - Cross-tool deduplication (dalfox + nuclei XSS -> single finding)
    - Same-endpoint consolidation
    - Evidence merging
    - Severity promotion (keeps highest severity)

    Args:
        findings: List of raw findings
        aggressive: If True, use more aggressive deduplication

    Returns:
        Deduplicated list of findings
    """
    if not findings:
        return []

    try:
        # Use the deduplication engine if available
        from scanner_tools.deduplication_engine import run_deduplication_pipeline
        return run_deduplication_pipeline(findings, aggressive=aggressive)
    except ImportError:
        # Fallback to basic deduplication
        # CORS dedup: keep finding with most evidence
        cors_findings = [f for f in findings if 'cors' in f.get('tool', '').lower()]
        if len(cors_findings) > 1:
            cors_findings.sort(key=lambda x: len(str(x.get('evidence', {}))), reverse=True)
            cors_to_keep = cors_findings[0]
            findings = [f for f in findings if 'cors' not in f.get('tool', '').lower() or f is cors_to_keep]

        return findings


def filter_low_confidence(findings: list[dict], min_confidence: float = 0.35) -> list[dict]:
    """Filter out findings below minimum confidence threshold.

    Args:
        findings: List of findings
        min_confidence: Minimum confidence threshold (default 0.35)

    Returns:
        Filtered list of findings
    """
    return [f for f in findings if f.get("confidence", 0.5) >= min_confidence]


def filter_excluded(findings: list[dict]) -> list[dict]:
    """Filter out excluded findings.

    Args:
        findings: List of findings

    Returns:
        Filtered list without excluded findings
    """
    return [f for f in findings if not f.get("excluded")]


def sort_findings_by_severity(findings: list[dict]) -> list[dict]:
    """Sort findings by severity (critical first).

    Args:
        findings: List of findings

    Returns:
        Sorted list of findings
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def sort_key(f: dict) -> tuple:
        sev = severity_order.get(f.get("severity", "info"), 5)
        cvss = -f.get("cvss_score", 0)  # Negative for descending
        conf = -f.get("confidence", 0)
        return (sev, cvss, conf)

    return sorted(findings, key=sort_key)


def group_findings_by_severity(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by severity level.

    Args:
        findings: List of findings

    Returns:
        Dictionary mapping severity to list of findings
    """
    groups: dict[str, list[dict]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": []
    }

    for finding in findings:
        severity = finding.get("severity", "info")
        if severity in groups:
            groups[severity].append(finding)
        else:
            groups["info"].append(finding)

    return groups


def count_findings_by_severity(findings: list[dict]) -> dict[str, int]:
    """Count findings by severity level.

    Args:
        findings: List of findings

    Returns:
        Dictionary mapping severity to count
    """
    groups = group_findings_by_severity(findings)
    return {sev: len(f_list) for sev, f_list in groups.items()}


def get_unique_cwes(findings: list[dict]) -> list[str]:
    """Get unique CWE IDs from findings.

    Args:
        findings: List of findings

    Returns:
        Sorted list of unique CWE IDs
    """
    cwes = set()
    for f in findings:
        cwe = f.get("cwe")
        if cwe:
            cwes.add(cwe)
    return sorted(list(cwes))


def get_unique_tools(findings: list[dict]) -> list[str]:
    """Get unique tool names from findings.

    Args:
        findings: List of findings

    Returns:
        Sorted list of unique tool names
    """
    tools = set()
    for f in findings:
        tool = f.get("tool")
        if tool:
            tools.add(tool)
    return sorted(list(tools))


def merge_finding_evidence(findings: list[dict]) -> dict[str, Any]:
    """Merge evidence from multiple related findings.

    Args:
        findings: List of related findings to merge

    Returns:
        Merged evidence dictionary
    """
    if not findings:
        return {}

    # Start with first finding's evidence
    merged = dict(findings[0].get("evidence", {}))

    # Add tool metadata from all findings
    tool_metadata = []
    for f in findings:
        tool_metadata.append({
            "tool": f.get("tool"),
            "confidence": f.get("confidence"),
            "evidence": f.get("evidence", {}),
        })

    merged["tool_metadata"] = tool_metadata
    merged["tools_detected_by"] = [f.get("tool") for f in findings]

    return merged
