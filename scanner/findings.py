"""
Finding normalization and management.

This module contains functions for normalizing, scoring, and deduplicating
security findings from various tools. Extracted from scanner.py for better
maintainability.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlparse
from datetime import datetime, UTC
from typing import Any

_UUID_SEG_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_SEG_RE = re.compile(r"^[0-9a-fA-F]+$")
# Evidence keys that may hold the finding's endpoint URL/path.
_ENDPOINT_EVIDENCE_KEYS = (
    "url", "endpoint", "affected_url", "target", "path",
    "consumer_endpoint", "producer_endpoint",
)
# Evidence keys naming the injected/affected parameter (kept in identity so two
# different params on the same endpoint stay distinct).
_PARAM_EVIDENCE_KEYS = ("parameter", "param", "object_id_key", "injection_point", "param_name")
# Proof-state vocabulary (_CONFIRMED_EVIDENCE_LEVELS, _DETERMINISTIC_PROOF_TYPES,
# _BROWSER_EXECUTION_MARKERS) and the _truthy / _has_browser_execution_proof helpers
# are defined ONCE in ai_verdict_policy and imported below, so the "one proof
# taxonomy" guarantee can't silently drift across copies (audit follow-up).


def template_path(path: str) -> str:
    """Template volatile id segments so /orders/1 and /orders/2 share an identity.

    Conservative — mirrors api/asm_inventory.normalize_path: only all-digit, UUID,
    and long-hex segments are templated, so literal route names (``/users``,
    ``/profile``) are never collapsed (docs proposed-next-steps §5).
    """
    if not path:
        return "/"
    out: list[str] = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg)
        elif seg.isdigit():
            out.append("{id}")
        elif _UUID_SEG_RE.match(seg):
            out.append("{uuid}")
        elif len(seg) >= 24 and _HEX_SEG_RE.match(seg):
            out.append("{hash}")
        else:
            out.append(seg)
    return "/".join(out) or "/"


def templated_finding_identity(finding: dict) -> str | None:
    """ID/payload-insensitive identity for an *endpoint* finding (docs §5).

    Collapses the count-explosion — one templated BOLA route reported once per
    object id, one SQLi param reported once per payload variant — by keying on
    ``vuln_type | method | templated_path | sorted(param names)`` rather than the
    concrete object id, query value, or payload. Returns None for findings with no
    endpoint URL (TLS / headers / DNS / config), which keep their existing identity.

    Distinct real vulns STAY distinct: a different path template, parameter,
    method, or vuln class (CWE) yields a different key. Only same-endpoint,
    same-param, same-class findings differing solely by id/payload collapse.
    """
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    raw_url = finding.get("url") or ""
    if not raw_url:
        for k in _ENDPOINT_EVIDENCE_KEYS:
            v = evidence.get(k)
            if isinstance(v, str) and v:
                raw_url = v
                break
    if not isinstance(raw_url, str) or not raw_url:
        return None
    try:
        parsed = urlparse(raw_url)
    except Exception:
        return None
    path = parsed.path or "/"
    if not path.startswith("/"):
        return None  # not a real endpoint path (e.g. a title string captured as url)
    tpath = template_path(path)

    params: set[str] = set()
    if parsed.query:
        for pair in parsed.query.split("&"):
            name = pair.split("=", 1)[0].strip()
            if name:
                params.add(name)
    for k in _PARAM_EVIDENCE_KEYS:
        v = evidence.get(k)
        if isinstance(v, str) and v.strip():
            params.add(v.strip())

    method = str(evidence.get("method") or finding.get("method") or "GET").upper()
    # vuln class: CWE is the stable discriminator; fall back to tool so distinct
    # detectors don't collapse when CWE is absent.
    vuln = str(finding.get("cwe") or "").strip() or str(finding.get("tool") or "").strip() or "generic"
    return f"{vuln}|{method}|{tpath}|{','.join(sorted(params))}"


def _has_deterministic_proof(
    finding: dict[str, Any],
    evidence: dict[str, Any],
    validation: dict[str, Any],
    poe: dict[str, Any],
    poe_result: dict[str, Any],
) -> bool:
    """Typed proof predicate for the verified tier.

    Generic ``verified=True`` is too ambiguous: older emitters used it for
    reachability, heuristic confidence, or AI support. The verified tier now
    requires explicit exploit/proof provenance.
    """
    evidence_level = str(validation.get("evidence_level") or "").strip().lower()
    proof_type = str(
        finding.get("proof_type")
        or evidence.get("proof_type")
        or validation.get("proof_type")
        or validation.get("poe_technique")
        or ""
    ).strip().lower()
    return (
        _truthy(validation.get("poe_proven"))
        or _truthy(poe.get("proven"))
        or _truthy(poe_result.get("proven"))
        or _truthy(finding.get("proof_of_exploitation"))
        or _truthy(evidence.get("proof_of_exploitation"))
        or _truthy(evidence.get("payload_executed"))
        or _truthy(evidence.get("executed"))
        or bool(finding.get("extraction_evidence") or evidence.get("extraction_evidence"))
        or bool(finding.get("extracted_data") or evidence.get("extracted_data"))
        or _has_browser_execution_proof(finding, evidence)
        or proof_type in _DETERMINISTIC_PROOF_TYPES
        or (_truthy(validation.get("verified")) and evidence_level in _CONFIRMED_EVIDENCE_LEVELS)
    )

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
    from .ai_verdict_policy import (
        ai_confidence,
        is_trusted_ai_false_positive,
        is_trusted_ai_true_positive,
        _has_browser_execution_proof,
        _truthy,
        _CONFIRMED_EVIDENCE_LEVELS,
        _DETERMINISTIC_PROOF_TYPES,
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
    from ai_verdict_policy import (
        ai_confidence,
        is_trusted_ai_false_positive,
        is_trusted_ai_true_positive,
        _has_browser_execution_proof,
        _truthy,
        _CONFIRMED_EVIDENCE_LEVELS,
        _DETERMINISTIC_PROOF_TYPES,
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
    """Display label for a finding's confidence score.

    This is a *user-facing* tier (verified/high/medium/low/uncertain) that
    governs how findings are grouped in the UI. It is intentionally distinct
    from `SEVERITY_CONFIDENCE_THRESHOLDS` below, which caps severity bands.

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


# Severity ceiling for a given confidence. Looser than `get_confidence_tier`
# on purpose: a "medium" tier finding can still legitimately ship at medium
# severity, while only a confident-enough finding may claim critical/high.
# If you change one ladder, document why the other should (or should not)
# move with it.
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


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Conservative CVSS ceiling applied when a finding is capped down to a band.
# Preserves the historical clamping (info=0, low=3, medium=6, high=8) and adds
# a `critical` entry so callers passing it don't KeyError.
_SEVERITY_CVSS_CEIL = {
    "info": 0.0,
    "low": 3.0,
    "medium": 6.0,
    "high": 8.0,
    "critical": 10.0,
}


def _cap_severity(finding: dict[str, Any], max_severity: str) -> None:
    if max_severity not in _SEVERITY_CVSS_CEIL:
        # Defensive fallback: callers should pass a known label, but a typo
        # should not raise — leave the finding unchanged.
        return
    current = str(finding.get("severity") or "info").lower()
    if _SEVERITY_ORDER.get(current, 0) > _SEVERITY_ORDER[max_severity]:
        policy = finding.setdefault("precision_policy", {})
        # Preserve the *earliest* recorded severity across chained downgrades
        # (e.g. critical → high → low) so the UI can show the full delta.
        policy.setdefault("original_severity", current)
        # Canonical, pipeline-agnostic audit field: whichever pipeline first
        # downgrades records it here so consumers have one place to read the
        # pre-downgrade severity (see also noise_reduction / validation).
        finding.setdefault("original_severity", current)
        if "original_cvss_score" not in policy and finding.get("cvss_score") is not None:
            policy["original_cvss_score"] = float(finding["cvss_score"])
        finding["severity"] = max_severity
        finding["cvss_score"] = min(
            float(finding.get("cvss_score") or 0.0),
            _SEVERITY_CVSS_CEIL[max_severity],
        )
        policy["severity_downgraded"] = True


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


def _is_vendor_or_framework_js(file_url: str, target_host: str | None = None) -> bool:
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
    if any(marker in host for marker in vendor_hosts):
        return True
    # Framework chunk paths like /_next/static/chunks/ also serve application
    # code in modern bundlers. Only treat them as vendor when the script is
    # served from a different host than the scan target (i.e. a true CDN).
    framework_paths = (
        "/_next/static/chunks/",
        "/_next/static/runtime/",
        "/static/chunks/",
        "/webpack/",
    )
    if not any(marker in path for marker in framework_paths):
        return False
    if not target_host:
        return False
    target_host = target_host.lower().split(":", 1)[0]
    return bool(host) and host != target_host


def apply_dast_precision_policy(
    findings: list[dict[str, Any]],
    target_host: str | None = None,
) -> list[dict[str, Any]]:
    """Downgrade unproven DAST heuristics so reports distinguish leads from bugs.

    This preserves the evidence for manual review while preventing static or
    contradictory signals from driving high-severity findings and grades.
    """
    for finding in findings:
        tool = str(finding.get("tool") or "").lower()
        title = str(finding.get("title") or "").lower()
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        validation = finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
        poe = finding.get("poe") if isinstance(finding.get("poe"), dict) else {}
        poe_result = finding.get("poe_result") if isinstance(finding.get("poe_result"), dict) else {}

        ai_confidence_score = ai_confidence(finding)
        ai_true_positive = is_trusted_ai_true_positive(finding)
        ai_false_positive = is_trusted_ai_false_positive(finding)

        generic_verified_signal = (
            _truthy(finding.get("verified"))
            or _truthy(evidence.get("verified"))
            or _truthy(evidence.get("confirmed"))
            or _truthy(validation.get("verified"))
        )
        heuristic_verified = _has_deterministic_proof(finding, evidence, validation, poe, poe_result)

        # AI verdict adjusts heuristic gating, but NEVER promotes to `verified`
        # (docs proposed-next-steps §8 — one proof taxonomy: AI is supporting
        # signal, only deterministic proof is `verified`/exploited):
        #   - A high-confidence false_positive overrides heuristic "verified=True"
        #     so a confidently-misclassified finding is not bumped to
        #     confirmed_exploit by static gates.
        #   - A high-confidence true_positive does NOT set verified; it keeps an
        #     AI-validated finding visible at its severity as a `likely_vulnerable`
        #     suspected lead (handled below) instead of being buried by the
        #     heuristic downgrade ladder.
        if ai_false_positive and heuristic_verified:
            heuristic_verified = False
            policy = finding.setdefault("precision_policy", {})
            policy["ai_overrode_verified"] = True
            policy["ai_overrode_reason"] = "ai_false_positive_high_confidence"

        verified = heuristic_verified  # deterministic proof only — AI never promotes
        finding["verified"] = bool(verified)
        if verified:
            validation["evidence_level"] = validation.get("evidence_level") or "confirmed_exploit"
            if validation:
                finding["validation"] = validation
            finding["proof_state"] = "exploited"
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
            # Keep validation.confidence in sync so consumers reading either
            # field see the same number.
            if isinstance(finding.get("validation"), dict):
                finding["validation"]["confidence"] = finding["confidence"]

        if verified:
            continue

        if generic_verified_signal:
            policy = finding.setdefault("precision_policy", {})
            policy["generic_verified_ignored"] = True
            finding["suspected"] = True
            finding["needs_verification"] = True
            finding["proof_state"] = "likely_vulnerable"
            finding.setdefault(
                "verification_reason",
                "Generic verified flag is not deterministic exploit proof",
            )

        # AI true_positive is a supporting signal, not deterministic proof (§8).
        # Keep the AI-validated finding visible at its assessed severity as a
        # `likely_vulnerable` suspected lead that still needs deterministic proof,
        # instead of letting the per-tool heuristic ladder bury it. It does NOT
        # count as verified for the grade/benchmark gates.
        if ai_true_positive and not ai_false_positive:
            finding["suspected"] = True
            finding["needs_verification"] = True
            finding["proof_state"] = "likely_vulnerable"
            policy = finding.setdefault("precision_policy", {})
            policy["ai_supported_likely"] = True
            finding["verification_reason"] = (
                f"AI judged true_positive with {ai_confidence_score:.0%} confidence "
                "(likely vulnerable — not deterministic proof)"
            )
            continue

        # If AI judged this a false positive with high confidence, downgrade
        # immediately rather than falling into per-tool heuristic ladders.
        if ai_false_positive:
            finding["suspected"] = True
            finding["needs_verification"] = True
            finding["verification_reason"] = (
                f"AI judged false_positive with {ai_confidence_score:.0%} confidence"
            )
            _cap_confidence_for_precision(finding, 0.34, "ai_false_positive")
            confidence = float(finding.get("confidence") or 0.5)
            finding["confidence_tier"] = get_confidence_tier(confidence)
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
            vendor_static_sink = _is_vendor_or_framework_js(file_url, target_host)
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

        elif tool == "smart_bola":
            evidence_level = str(validation.get("evidence_level") or "").lower()
            weak_or_suspected = (
                finding.get("suspected") is True
                or finding.get("needs_verification") is True
                or evidence_level in {"weak_indicator", "strong_indicator"}
            )
            if weak_or_suspected:
                finding["suspected"] = True
                finding["needs_verification"] = True
                finding["verification_reason"] = (
                    finding.get("verification_reason")
                    or "BOLA/IDOR lead lacks deterministic owner-vs-attacker replay proof"
                )
                _cap_confidence_for_precision(
                    finding,
                    0.64,
                    "bola_lead_without_cross_principal_proof",
                )

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
        # Canonical, pipeline-agnostic audit field (see _cap_severity).
        finding.setdefault("original_severity", original_sev)
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


def summarize_verification(findings: list[dict]) -> dict[str, Any]:
    """§10: confidence/verification distribution so reports distinguish verified
    exploitable bugs from review-needed signals. Surfaces unproven High/Critical
    explicitly so suspected findings aren't mistaken for proven exploitation.
    """
    by_tier: dict[str, int] = {}
    verified = suspected = 0
    unproven_high = unproven_critical = 0
    for f in findings:
        sev = str(f.get("severity") or "").lower()
        is_verified = bool(f.get("verified"))
        if is_verified:
            verified += 1
        # "suspected" = explicitly flagged, or a High/Critical without verification.
        is_suspected = bool(f.get("suspected")) or (sev in ("high", "critical") and not is_verified)
        if is_suspected:
            suspected += 1
        # Verification Depth D (calibration): a deterministically-proven finding belongs
        # in the 'verified' tier regardless of the generic confidence cap that may have
        # left its score in the 'high' band — proof beats the heuristic cap.
        tier = "verified" if is_verified else str(f.get("confidence_tier") or "unknown")
        by_tier[tier] = by_tier.get(tier, 0) + 1
        if not is_verified:
            if sev == "critical":
                unproven_critical += 1
            elif sev == "high":
                unproven_high += 1
    return {
        "verified": verified,
        "suspected": suspected,
        "by_confidence_tier": by_tier,
        "unproven_high": unproven_high,
        "unproven_critical": unproven_critical,
        "total": len(findings),
    }


def compute_quality_metrics(
    findings: list[dict],
    *,
    coverage_status: str = "complete",
    checks_skipped: Any = 0,
    ai_enabled: bool = False,
) -> dict[str, Any]:
    """Compute the ``quality_metrics`` report block from one canonical finding list.

    Extracted from ``scanner.build_report`` so the parallel-merge path
    (``api/worker.py``) can recompute quality_metrics from the union of all shards +
    recon instead of leaving the base shard's stale block while ``findings[]`` grew
    (docs proposed-next-steps §2 — every report block must derive from the SAME
    canonical finding set). The single-scan path calls this same function, so both
    paths produce identical numbers for the same finding list.
    """
    findings_list = findings or []
    checks_skipped_count = (
        checks_skipped if isinstance(checks_skipped, int) else len(checks_skipped or [])
    )

    confidence_distribution = {"verified": 0, "high": 0, "medium": 0, "low": 0, "uncertain": 0}
    for f in findings_list:
        tier = f.get("confidence_tier", "medium")
        if tier in confidence_distribution:
            confidence_distribution[tier] += 1

    ai_verdicts = {"true_positive": 0, "false_positive": 0, "unclear": 0}
    for f in findings_list:
        verdict = f.get("ai_verdict", "")
        if verdict in ai_verdicts:
            ai_verdicts[verdict] += 1

    tools_with_findings = set()
    for f in findings_list:
        tool = f.get("tool", "")
        if tool:
            tools_with_findings.add(tool)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings_list:
        sev = str(f.get("severity") or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    quality_score = 100
    if coverage_status != "complete":
        quality_score -= 20
    if checks_skipped_count:
        quality_score -= checks_skipped_count * 5
    if ai_verdicts["true_positive"] + ai_verdicts["false_positive"] > 0:
        quality_score += 10

    total_findings = len(findings_list)
    if total_findings > 0:
        uncertain_ratio = confidence_distribution["uncertain"] / total_findings
        low_conf_ratio = (
            confidence_distribution["uncertain"] + confidence_distribution["low"]
        ) / total_findings
        if uncertain_ratio > 0.3:
            quality_score -= 15
        elif uncertain_ratio > 0.2:
            quality_score -= 10
        if low_conf_ratio > 0.5:
            quality_score -= 25
        elif low_conf_ratio > 0.3:
            quality_score -= 15

    if total_findings > 0:
        high_conf_ratio = (
            confidence_distribution["verified"] + confidence_distribution["high"]
        ) / total_findings
        if high_conf_ratio > 0.7:
            quality_score += 10
        elif high_conf_ratio > 0.5:
            quality_score += 5

    confirmed_count = sum(1 for f in findings_list if f.get("verified") is True)
    suspected_high_count = sum(
        1
        for f in findings_list
        if f.get("severity") in ("high", "critical") and f.get("verified") is not True
    )
    needs_verification_count = sum(1 for f in findings_list if f.get("needs_verification"))
    if total_findings and confirmed_count == 0:
        quality_score -= 10
    if suspected_high_count:
        quality_score -= min(25, suspected_high_count * 8)
    if needs_verification_count:
        quality_score -= min(20, needs_verification_count * 3)

    quality_score = max(0, min(100, quality_score))

    if quality_score >= 90:
        quality_grade = "A"
    elif quality_score >= 80:
        quality_grade = "B"
    elif quality_score >= 70:
        quality_grade = "C"
    elif quality_score >= 60:
        quality_grade = "D"
    else:
        quality_grade = "F"

    reliability_notes: list[str] = []
    if coverage_status != "complete":
        reliability_notes.append(
            f"Some tools did not complete successfully (coverage: {coverage_status})"
        )
    if confidence_distribution["uncertain"] > 0:
        reliability_notes.append(
            f"{confidence_distribution['uncertain']} finding(s) have uncertain confidence - manual review recommended"
        )
    if confidence_distribution["low"] > 0:
        reliability_notes.append(
            f"{confidence_distribution['low']} finding(s) have low confidence - validate before treating as exploitable"
        )
    if total_findings and confirmed_count == 0:
        reliability_notes.append("No findings were confirmed by proof or verification")
    if suspected_high_count:
        reliability_notes.append(
            f"{suspected_high_count} high/critical finding(s) are suspected, not confirmed"
        )
    if ai_verdicts["false_positive"] > 0:
        reliability_notes.append(
            f"{ai_verdicts['false_positive']} finding(s) marked as likely false positive by AI"
        )
    if checks_skipped_count:
        reliability_notes.append(
            f"{checks_skipped_count} check(s) were skipped due to scan configuration"
        )

    return {
        "quality_score": quality_score,
        "quality_grade": quality_grade,
        "total_findings": total_findings,
        "severity_distribution": severity_counts,
        "confidence_distribution": confidence_distribution,
        "ai_validation": {
            "enabled": ai_enabled,
            "verdicts": ai_verdicts,
        },
        "tools_with_findings": sorted(list(tools_with_findings)),
        "coverage_status": coverage_status,
        "reliability_notes": reliability_notes,
    }


def check_report_invariants(report: dict) -> list[str]:
    """Return a list of report-block reconciliation violations (empty == consistent).

    Every count that is meant to describe the same canonical finding set must agree:
    ``findings[]`` length, ``quality_metrics.total_findings``,
    ``verification_summary.total``, and the sum of ``severity_distribution`` (over
    findings carrying a recognized severity). Triage buckets are intentionally
    overlapping denominators, so they are only bounds-checked, never summed
    (docs proposed-next-steps §2). Used by the report-invariant test and the
    benchmark runner so a parent/shard merge that desyncs blocks fails loudly.
    """
    violations: list[str] = []
    if not isinstance(report, dict):
        return ["report is not a dict"]

    findings = report.get("findings")
    if not isinstance(findings, list):
        return violations  # degraded/partial reports without a findings list are exempt
    total = len(findings)

    qm = report.get("quality_metrics")
    if isinstance(qm, dict):
        qm_total = qm.get("total_findings")
        if isinstance(qm_total, int) and qm_total != total:
            violations.append(
                f"quality_metrics.total_findings={qm_total} != len(findings)={total}"
            )
        sev_dist = qm.get("severity_distribution")
        if isinstance(sev_dist, dict):
            buckets = {"critical", "high", "medium", "low", "info"}
            expected = sum(
                1 for f in findings
                if isinstance(f, dict) and str(f.get("severity") or "info").lower() in buckets
            )
            sev_sum = sum(v for v in sev_dist.values() if isinstance(v, int))
            if sev_sum != expected:
                violations.append(
                    f"severity_distribution sum={sev_sum} != findings-with-severity={expected}"
                )

    vs = report.get("verification_summary")
    if isinstance(vs, dict):
        vs_total = vs.get("total")
        if isinstance(vs_total, int) and vs_total != total:
            violations.append(
                f"verification_summary.total={vs_total} != len(findings)={total}"
            )

    triage = report.get("triage")
    if isinstance(triage, dict):
        for bucket, data in triage.items():
            if isinstance(data, dict) and isinstance(data.get("count"), int):
                if data["count"] > total:
                    violations.append(
                        f"triage.{bucket}.count={data['count']} > len(findings)={total}"
                    )

    # --- Proof-state consistency (docs §1/§8) ---------------------------------
    # The verified count and the proof state must agree across blocks and per
    # finding, so a scan can't claim more proven exploitation than it has.
    verified_findings = [f for f in findings if isinstance(f, dict) and f.get("verified") is True]
    if isinstance(vs, dict) and isinstance(vs.get("verified"), int):
        if vs["verified"] != len(verified_findings):
            violations.append(
                f"verification_summary.verified={vs['verified']} != "
                f"findings(verified=True)={len(verified_findings)}"
            )
    # A finding cannot be both deterministically verified and a suspected lead.
    contradictory = [
        f for f in verified_findings if f.get("suspected") is True or f.get("needs_verification") is True
    ]
    if contradictory:
        violations.append(
            f"{len(contradictory)} finding(s) are both verified and suspected/needs_verification"
        )
    # AI never promotes (§8): a verified finding must rest on deterministic proof,
    # never on an AI true_positive alone.
    ai_only_verified = [
        f for f in verified_findings
        if (f.get("precision_policy") or {}).get("ai_supported_likely") is True
        or str(f.get("proof_state") or "") == "likely_vulnerable"
    ]
    if ai_only_verified:
        violations.append(
            f"{len(ai_only_verified)} finding(s) marked verified but only AI-supported (§8: AI never promotes)"
        )

    # --- Active-execution honesty (docs §1/§6) --------------------------------
    meta = report.get("scan_metadata") if isinstance(report.get("scan_metadata"), dict) else {}
    result = report.get("result") if isinstance(report.get("result"), dict) else {}
    if meta.get("active_execution_failed") is True and result.get("grade_reliable") is True:
        violations.append("active_execution_failed=True but result.grade_reliable=True")
    # An incomplete-marked grade (trailing '*') must not also claim reliability.
    grade = str(result.get("grade") or "")
    if grade.endswith("*") and result.get("grade_reliable") is True:
        violations.append(f"grade '{grade}' marked incomplete but grade_reliable=True")

    return violations


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
