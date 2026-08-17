"""
Grading and scoring logic for scan results.

This module contains functions for calculating security grades, CVSS scores,
and compliance mappings. Extracted from scanner.py for better maintainability.
"""
from __future__ import annotations

import re
from datetime import datetime, UTC
from typing import Any

# Support both package import (from scanner.grading) and script import (python3 grading.py)
try:
    from .constants import (
        FINDING_CVSS_SCORES,
        SHORT_CVSS_PATTERNS,
        SEVERITY_BASE_SCORES,
        OWASP_WEIGHT,
        OWASP_MAPPING,
        CWE_MAPPING,
        CWE_DESCRIPTIONS,
        SOC2_CRITERIA_MAP,
        EndpointPatterns,
    )
    from .target_context import is_local_or_private_scan_target
    from .ai_verdict_policy import has_deterministic_exploit_proof, is_trusted_ai_false_positive
except ImportError:
    from constants import (
        FINDING_CVSS_SCORES,
        SHORT_CVSS_PATTERNS,
        SEVERITY_BASE_SCORES,
        OWASP_WEIGHT,
        OWASP_MAPPING,
        CWE_MAPPING,
        CWE_DESCRIPTIONS,
        SOC2_CRITERIA_MAP,
        EndpointPatterns,
    )
    from target_context import is_local_or_private_scan_target
    from ai_verdict_policy import has_deterministic_exploit_proof, is_trusted_ai_false_positive


def hsts_preload_readiness(hsts: str | None) -> dict[str, Any]:
    """Check if HSTS header is ready for preload submission.

    Args:
        hsts: The HSTS header value

    Returns:
        Dictionary with 'ready' boolean and 'issues' list
    """
    if not hsts:
        return {"ready": False, "issues": ["HSTS missing."]}

    issues = []
    ready = True

    # Check max-age (must be at least 1 year = 31536000 seconds)
    m = re.search(r"max-age=(\d+)", hsts, re.I)
    if not m or int(m.group(1)) < 31536000:
        ready = False
        issues.append("HSTS max-age < 1 year.")

    # Check includeSubDomains
    if "includesubdomains" not in hsts.lower():
        ready = False
        issues.append("HSTS includeSubDomains missing.")

    # Check preload token
    if "preload" not in hsts.lower():
        ready = False
        issues.append("HSTS preload token missing.")

    return {"ready": ready, "issues": issues}


def calculate_cvss_score(finding: dict[str, Any]) -> float:
    """Calculate CVSS v3.1 score for a finding using per-finding lookup table.

    Args:
        finding: The finding dictionary with title, tool, severity, evidence

    Returns:
        CVSS score from 0.0 to 10.0
    """
    title = finding.get("title", "").lower()
    tool = finding.get("tool", "").lower()
    severity = finding.get("severity", "medium").lower()

    # Info-level findings should always have CVSS 0.0
    if severity == "info":
        return 0.0

    def pattern_matches(pattern: str, text: str) -> bool:
        """Check if pattern matches text, using word boundaries for short patterns."""
        if pattern in SHORT_CVSS_PATTERNS:
            # Use word boundary matching for short patterns
            regex = r'(?:^|[^a-z0-9])' + re.escape(pattern) + r'(?:[^a-z0-9]|[-_]|$)'
            return bool(re.search(regex, text))
        else:
            return pattern in text

    # Try to match against known finding types
    for pattern, score in FINDING_CVSS_SCORES.items():
        if pattern_matches(pattern, title) or pattern_matches(pattern, tool):
            # Graduated exploit availability bonus based on maturity
            evidence = finding.get("evidence", {})
            details = finding.get("details", {})
            exploit_maturity = evidence.get("exploit_maturity") or details.get("exploit_maturity")

            if exploit_maturity == "poc":
                return min(10.0, round(score + 0.5, 1))
            elif exploit_maturity == "functional":
                return min(10.0, round(score + 0.75, 1))
            elif exploit_maturity in ("weaponized", "high"):
                return min(10.0, round(score + 1.0, 1))
            elif evidence.get("exploit_available") or details.get("exploit_available"):
                return min(10.0, round(score + 0.5, 1))
            return score

    # Fallback to severity-based scoring
    return SEVERITY_BASE_SCORES.get(severity, 5.0)


def apply_context_modifiers(finding: dict[str, Any], cvss_score: float) -> float:
    """Apply context-aware modifiers to CVSS score based on finding location.

    Context factors that increase severity:
    - Finding on authentication/login endpoints
    - Finding on payment/checkout endpoints
    - Finding on admin/dashboard endpoints

    Context factors that decrease severity:
    - Finding on static assets
    - Finding on development/test endpoints

    Args:
        finding: The finding dict with evidence
        cvss_score: The base CVSS score

    Returns:
        Adjusted CVSS score
    """
    if cvss_score <= 0:
        return cvss_score

    evidence = finding.get("evidence", {})
    title = finding.get("title", "").lower()

    # Extract endpoint from evidence
    endpoint = ""
    if isinstance(evidence, dict):
        endpoint = str(
            evidence.get("url", "") or
            evidence.get("endpoint", "") or
            evidence.get("path", "")
        ).lower()

    modifier = 0.0

    # Check for sensitive endpoint matches (increase severity)
    if EndpointPatterns.is_auth_endpoint(endpoint):
        modifier += 0.5
    elif EndpointPatterns.is_payment_endpoint(endpoint):
        modifier += 0.5
    elif EndpointPatterns.is_admin_endpoint(endpoint):
        modifier += 0.3
    elif EndpointPatterns.is_api_endpoint(endpoint):
        modifier += 0.2

    # Check for non-sensitive endpoints (decrease severity)
    is_static = EndpointPatterns.is_static_asset(endpoint)
    is_dev = EndpointPatterns.is_dev_endpoint(endpoint)

    if is_static and finding.get("severity", "").lower() in ("low", "info"):
        modifier -= 0.5

    if is_dev:
        modifier -= 0.3

    # Specific vulnerability type context adjustments
    vuln_type = finding.get("tool", "").lower()

    # CORS on public unauthenticated endpoints is less severe
    if "cors" in title or "cors" in vuln_type:
        if not EndpointPatterns.is_sensitive_endpoint(endpoint):
            modifier -= 0.5

    # XSS on admin pages is more severe
    if "xss" in title or "xss" in vuln_type:
        if EndpointPatterns.is_admin_endpoint(endpoint):
            modifier += 0.3

    # Open redirect on login pages enables phishing
    if "redirect" in title:
        if EndpointPatterns.is_auth_endpoint(endpoint):
            modifier += 0.5

    # CSRF on state-changing endpoints is more severe
    if "csrf" in title:
        if EndpointPatterns.is_auth_endpoint(endpoint) or EndpointPatterns.is_payment_endpoint(endpoint):
            modifier += 0.5

    # Apply modifier with bounds
    adjusted = cvss_score + modifier
    return max(0.0, min(10.0, round(adjusted, 1)))


def validate_severity_cvss(severity: str, cvss_score: float) -> str:
    """Validate and correct severity based on CVSS score.

    CVSS ranges:
    - Critical: 9.0-10.0
    - High: 7.0-8.9
    - Medium: 4.0-6.9
    - Low: 0.1-3.9
    - Info: 0

    Args:
        severity: Original severity string
        cvss_score: Calculated CVSS score

    Returns:
        Validated severity string
    """
    if cvss_score >= 9.0:
        expected = "critical"
    elif cvss_score >= 7.0:
        expected = "high"
    elif cvss_score >= 4.0:
        expected = "medium"
    elif cvss_score > 0:
        expected = "low"
    else:
        expected = "info"

    # Map input severity to canonical form
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "none": "info"
    }
    canonical_severity = severity_map.get(severity.lower().strip(), severity.lower().strip())

    # Return expected severity based on CVSS
    if canonical_severity != expected:
        return expected

    return canonical_severity


def map_to_cwe(finding: dict[str, Any]) -> str | None:
    """Map a finding to its CWE identifier.

    Args:
        finding: The finding dictionary

    Returns:
        CWE ID string (e.g., "CWE-79") or None
    """
    title = finding.get("title", "").lower()
    tool = finding.get("tool", "").lower()

    # Check title and tool against CWE mapping
    for pattern, cwe in CWE_MAPPING.items():
        if pattern in title or pattern in tool:
            return cwe

    return None


def get_cwe_description(cwe: str) -> str:
    """Get the description for a CWE identifier.

    Args:
        cwe: CWE ID (e.g., "CWE-79")

    Returns:
        Description string or empty string if not found
    """
    return CWE_DESCRIPTIONS.get(cwe, "")


def get_cwe_url(cwe: str) -> str:
    """Get the MITRE CWE URL for a CWE identifier.

    Args:
        cwe: CWE ID (e.g., "CWE-79")

    Returns:
        URL string
    """
    cwe_id = cwe.replace("CWE-", "")
    return f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"


def owasp_mapping(finding: dict[str, Any]) -> str | None:
    """Map a finding to OWASP Top 10 2021 category.

    Args:
        finding: The finding dictionary

    Returns:
        OWASP category string or None
    """
    title = finding.get("title", "").lower()
    tool = finding.get("tool", "").lower()

    for pattern, owasp in OWASP_MAPPING.items():
        if pattern in title or pattern in tool:
            return owasp

    return None


def soc2_mapping(finding: dict[str, Any]) -> list[str]:
    """Map a finding to SOC 2 Trust Services Criteria.

    Args:
        finding: The finding dictionary

    Returns:
        List of SOC 2 criteria codes (e.g., ["CC6.1", "CC6.7"])
    """
    title = finding.get("title", "").lower()
    tool = finding.get("tool", "").lower()
    combined = title + " " + tool

    matched_criteria = set()

    for criteria, keywords in SOC2_CRITERIA_MAP.items():
        for keyword in keywords:
            if keyword in combined:
                matched_criteria.add(criteria)
                break

    return sorted(list(matched_criteria))


def grade(report: dict[str, Any]) -> dict[str, Any]:
    """Calculate security grade for a scan report.

    This is the main grading function that evaluates all aspects of the scan
    and produces a final grade, score, and recommendations.

    Args:
        report: The full scan report dictionary

    Returns:
        Dictionary with score, grade, notes, remediation, cvss_metrics, compliance
    """
    score = 100
    notes = []
    remediation = []
    cvss_scores = []
    compliance_issues = {"owasp": set(), "cwe": set(), "soc2": set()}
    max_severity = "info"

    tls = report.get("tls", {})
    http = report.get("http", {})
    dns = report.get("dns", {})
    findings = report.get("findings", [])
    input_info = report.get("input", {}) or {}
    target_host = input_info.get("normalized_host") or input_info.get("target") or http.get("final_url")
    local_private_target = is_local_or_private_scan_target(target_host)
    if local_private_target:
        notes.append("Local/private target detected; public DNS/TLS delivery controls were not graded.")

    # TLS version normalization helper
    def normalize_tls_version(v: str) -> str | None:
        """Normalize TLS version string to canonical format."""
        if not v:
            return None
        s = str(v).lower().strip()
        if s in ("tls13", "tls1.3", "tlsv1.3", "tls 1.3", "1.3"):
            return "1.3"
        if s in ("tls12", "tls1.2", "tlsv1.2", "tls 1.2", "1.2"):
            return "1.2"
        if s in ("tls11", "tls1.1", "tlsv1.1", "tls 1.1", "1.1"):
            return "1.1"
        if s in ("tls10", "tls1.0", "tlsv1.0", "tls 1.0", "tls1", "tlsv1", "1.0"):
            return "1.0"
        if "sslv3" in s or s == "ssl3":
            return "ssl3"
        if "sslv2" in s or s == "ssl2":
            return "ssl2"
        m = re.search(r"(\d+)\.(\d+)", s)
        if m:
            return f"{m.group(1)}.{m.group(2)}"
        return None

    # Extract TLS versions
    raw_versions = [e.get("tlsversion") for e in tls.get("endpoints", []) if e.get("tlsversion")]
    versions = set()
    for v in raw_versions:
        normalized = normalize_tls_version(v)
        if normalized:
            versions.add(normalized)

    cipher_suites = tls.get("cipher_suites") or {}
    for proto_key in cipher_suites.keys():
        normalized = normalize_tls_version(proto_key)
        if normalized:
            versions.add(normalized)

    # TLS scoring
    if any(v in versions for v in ("ssl2", "ssl3", "1.0", "1.1")) and not local_private_target:
        score -= 25
        notes.append("Legacy TLS enabled (<=1.1).")

    has_modern_tls = any(v in versions for v in ("1.2", "1.3")) or tls.get("testssl", {}).get("supports_tls13")
    if not has_modern_tls and not local_private_target:
        score -= 30
        notes.append("Modern TLS (1.2/1.3) not detected.")

    # Certificate expiration
    exp_days = tls.get("certificate", {}).get("not_after")
    days = None
    if exp_days:
        try:
            dt = datetime.fromisoformat(exp_days.replace("Z", "+00:00"))
            days = int((dt - datetime.now(UTC)).total_seconds() // 86400)
        except Exception:
            pass

    if isinstance(days, int):
        if days < 0:
            score -= 40
            notes.append("Certificate expired.")
        elif days < 14:
            score -= 20
            notes.append("Certificate expires in <14 days.")
        elif days < 30:
            score -= 10
            notes.append("Certificate expires in <30 days.")

    # OCSP stapling (minor)
    if not tls.get("ocsp", {}).get("stapled") and not local_private_target:
        score -= 1
        notes.append("OCSP stapling not detected.")

    # TLS issues from tools
    if tls.get("nmap", {}).get("weak_indicators") and not local_private_target:
        score -= 8
        notes.append("Potentially weak cipher indicators found (nmap).")

    high_issues = [i for i in tls.get("testssl", {}).get("issues", []) if i.get("severity") in ("HIGH", "CRITICAL")]
    if high_issues and not local_private_target:
        score -= 10
        notes.append("High/critical TLS issues detected by testssl.sh.")

    # HTTP security headers
    sec = http.get("security_headers", {})

    if not sec.get("hsts") and not local_private_target:
        score -= 10
        notes.append("HSTS missing.")
    elif sec.get("hsts"):
        pre = hsts_preload_readiness(sec["hsts"])
        if not pre["ready"]:
            score -= 3
            notes.extend([f"HSTS: {x}" for x in pre["issues"]])

    if not sec.get("x_frame_options"):
        score -= 4
        notes.append("X-Frame-Options missing.")

    if (sec.get("x_content_type_options") or "").lower() != "nosniff":
        score -= 4
        notes.append("X-Content-Type-Options not 'nosniff'.")

    if not sec.get("referrer_policy"):
        score -= 2
        notes.append("Referrer-Policy missing.")

    # CSP evaluation
    csp_eval = http.get("csp_evaluation", {})
    csp_penalty = 0

    if not csp_eval.get("present"):
        csp_penalty = 12
        notes.append("CSP missing.")
    else:
        csp_penalty = int((100 - csp_eval.get("score", 100)) * 0.15)
        if csp_eval.get("issues"):
            notes.extend([f"CSP: {i}" for i in csp_eval["issues"][:6]])

        directives = csp_eval.get("directives", {}) or {}
        missing_default = "default-src" not in directives
        missing_script = "script-src" not in directives
        if missing_default and missing_script:
            csp_penalty += 8
            notes.append("CSP critical gap: default-src and script-src both missing.")
        elif missing_script:
            csp_penalty += 5
            notes.append("CSP missing script-src.")

    score -= min(20, csp_penalty)

    # Cookie issues
    ck = http.get("cookies", {})
    if ck.get("issues"):
        score -= min(8, len(ck["issues"]) * 2)
        notes.extend([f"Cookie: {i}" for i in ck["issues"]])

    # Email security (only if domain has MX records)
    mx_records = dns.get("mx") or []
    has_email_capability = isinstance(mx_records, list) and len(mx_records) > 0

    dmarc_f = dns.get("dmarc", {}) or {}
    dmarc_fields = dmarc_f.get("fields", {}) or {}
    pol = (dmarc_fields.get("p") or "").lower()

    if local_private_target:
        pass
    elif has_email_capability:
        if not dns.get("spf"):
            score -= 6
            notes.append("SPF missing.")
        if not pol:
            score -= 8
            notes.append("DMARC missing.")
        elif pol == "none":
            score -= 5
            notes.append("DMARC policy 'none'. Prefer 'quarantine' or 'reject'.")
        if not dmarc_fields.get("rua"):
            notes.append("DMARC rua not set (optional but recommended).")
    else:
        if not dns.get("spf"):
            notes.append("SPF missing (informational - no MX records detected).")
        if not pol:
            notes.append("DMARC missing (informational - no MX records detected).")

    # DNSSEC
    dnssec_status = (dns.get("dnssec", {}) or {}).get("status") or ""
    if local_private_target:
        pass
    elif dnssec_status.lower() == "bogus":
        score -= 6
        notes.append("DNSSEC validation failure (bogus).")
    elif dnssec_status.lower() != "secure":
        notes.append("DNSSEC not validated (informational).")

    # HTTPS redirect
    if http.get("scheme_redirect") == "none" and not local_private_target:
        score -= 5
        notes.append("Does not redirect to HTTPS.")

    # HTTP/2 and HTTP/3
    http2_support = http.get("http2")
    http3_support = http.get("http3")
    http3_advertised = http.get("http3_advertised", False)
    has_modern_http = http2_support or http3_support is True or http3_advertised

    if local_private_target:
        pass
    elif http3_support is None:
        if not http2_support:
            score -= 2
            notes.append("No HTTP/2 detected (HTTP/3 unknown).")
    elif not has_modern_http:
        score -= 3
        notes.append("No HTTP/2 or HTTP/3.")

    # Process findings
    critical_findings = [f for f in findings if f.get("severity") == "critical"]
    high_findings = [f for f in findings if f.get("severity") == "high"]
    medium_findings = [f for f in findings if f.get("severity") == "medium"]

    total_fp_count = sum(1 for f in findings if is_trusted_ai_false_positive(f))

    def _has_grade_ceiling_evidence(finding: dict[str, Any]) -> bool:
        """Return True when evidence is strong enough to cap the letter grade."""
        if is_trusted_ai_false_positive(finding):
            return False
        validation = finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
        if has_deterministic_exploit_proof(finding):
            return True
        if finding.get("suspected") or finding.get("needs_verification"):
            return False
        try:
            confidence = float(finding.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        evidence_level = str(validation.get("evidence_level") or "").lower()
        return confidence >= 0.80 or evidence_level == "strong_indicator"

    # Track max severity for letter ceilings. Weak/suspected leads still affect
    # score via weighted penalties but do not cap the entire grade.
    non_fp_critical = [f for f in critical_findings if _has_grade_ceiling_evidence(f)]
    non_fp_high = [f for f in high_findings if _has_grade_ceiling_evidence(f)]
    non_fp_medium = [f for f in medium_findings if _has_grade_ceiling_evidence(f)]

    if non_fp_critical:
        max_severity = "critical"
    elif non_fp_high:
        max_severity = "high"
    elif non_fp_medium:
        max_severity = "medium"

    # Collect CVSS scores and compliance data
    raw_cvss_scores = []
    for finding in findings:
        cvss = finding.get("cvss_score", 0)
        if cvss > 0:
            raw_cvss_scores.append(cvss)
            owasp_cat = finding.get("owasp", "")[:8] if finding.get("owasp") else ""
            weight = OWASP_WEIGHT.get(owasp_cat, 1.0)
            weighted_cvss = min(10.0, cvss * weight)
            cvss_scores.append(weighted_cvss)

        if finding.get("cwe"):
            compliance_issues["cwe"].add(finding["cwe"])
        if finding.get("owasp"):
            compliance_issues["owasp"].add(finding["owasp"])
        soc2_criteria = finding.get("soc2", [])
        if isinstance(soc2_criteria, list):
            for criteria in soc2_criteria:
                compliance_issues["soc2"].add(criteria)

    avg_cvss = round(sum(raw_cvss_scores) / len(raw_cvss_scores), 1) if raw_cvss_scores else 0
    max_cvss = max(raw_cvss_scores) if raw_cvss_scores else 0

    def _confidence_weight(finding: dict[str, Any]) -> float:
        """Weight grade impact by verification quality."""
        if is_trusted_ai_false_positive(finding):
            return 0.0
        if has_deterministic_exploit_proof(finding):
            return 1.0
        if finding.get("suspected") or finding.get("needs_verification"):
            return 0.25
        confidence = finding.get("confidence")
        try:
            confidence_f = float(confidence)
        except (TypeError, ValueError):
            confidence_f = 0.6
        if confidence_f < 0.5:
            return 0.25
        if confidence_f < 0.65:
            return 0.5
        if confidence_f < 0.8:
            return 0.75
        return 1.0

    def calc_weighted_penalty(findings_list: list, per_finding: int, max_penalty: int) -> int:
        """Calculate confidence-aware penalty excluding likely false positives."""
        penalty = sum(per_finding * _confidence_weight(f) for f in findings_list)
        return min(max_penalty, int(round(penalty)))

    # Finding penalties
    if critical_findings:
        penalty = calc_weighted_penalty(critical_findings, 15, 45)
        score -= penalty
        fp_in_crit = sum(1 for f in critical_findings if is_trusted_ai_false_positive(f))
        fp_note = f" ({fp_in_crit} likely FP)" if fp_in_crit else ""
        notes.append(f"{len(critical_findings)} critical vulnerability(ies) found{fp_note} (max CVSS: {max_cvss}, penalty: -{penalty}).")
        remediation.append("URGENT: Address critical vulnerabilities immediately.")

    if high_findings:
        penalty = calc_weighted_penalty(high_findings, 10, 30)
        score -= penalty
        fp_in_high = sum(1 for f in high_findings if is_trusted_ai_false_positive(f))
        fp_note = f" ({fp_in_high} likely FP)" if fp_in_high else ""
        notes.append(f"{len(high_findings)} high severity issue(s) found{fp_note} (penalty: -{penalty}).")
        remediation.append("HIGH PRIORITY: Fix high severity issues.")

    if medium_findings:
        penalty = calc_weighted_penalty(medium_findings, 4, 20)
        score -= penalty
        fp_in_med = sum(1 for f in medium_findings if is_trusted_ai_false_positive(f))
        fp_note = f" ({fp_in_med} likely FP)" if fp_in_med else ""
        notes.append(f"{len(medium_findings)} medium severity issue(s) found{fp_note} (penalty: -{penalty}).")

    # Remediation suggestions
    if not tls.get("ocsp", {}).get("stapled"):
        remediation.append("Enable OCSP stapling in your web server configuration.")
    if not sec.get("hsts"):
        remediation.append("Add Strict-Transport-Security header with max-age=31536000; includeSubDomains; preload")
    if csp_eval.get("grade") in ["C", "D", "F"]:
        remediation.append("Improve CSP by removing 'unsafe-inline' and using nonces/hashes for scripts.")
    if not dns.get("spf"):
        remediation.append("Add SPF record: v=spf1 include:YOUR_EMAIL_PROVIDER ~all")
    if not pol:
        remediation.append("Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com")

    # Final score and grade
    score = max(0, min(100, score))

    if max_severity == "critical":
        letter = "D" if score >= 55 else "F"
    elif max_severity == "high":
        letter = "C" if score >= 70 else "D" if score >= 55 else "F"
    else:
        letter = (
            "A" if score >= 90 else
            "B" if score >= 80 else
            "C" if score >= 70 else
            "D" if score >= 55 else
            "F"
        )

    unproven_high_critical = [
        finding for finding in findings
        if str(finding.get("severity") or "").lower() in {"high", "critical"}
        and not has_deterministic_exploit_proof(finding)
        and not is_trusted_ai_false_positive(finding)
    ]
    grade_reliable = not unproven_high_critical
    published_letter = f"{letter}*" if not grade_reliable else letter
    summary_prefix = "[REVIEW REQUIRED] " if not grade_reliable else ""
    if unproven_high_critical:
        notes.append(
            f"{len(unproven_high_critical)} high/critical finding(s) remain unproven; "
            "the headline grade is provisional."
        )

    return {
        "score": score,
        "grade": published_letter,
        "original_grade": letter if not grade_reliable else None,
        "grade_reliable": grade_reliable,
        "grade_warning": (
            "High/critical findings require deterministic verification before the grade is reliable"
            if not grade_reliable else None
        ),
        "suspected_high_critical_count": len(unproven_high_critical),
        "notes": notes,
        "remediation": remediation[:10],
        "summary": summary_prefix + f"Security Grade: {published_letter} ({score}/100) - {len(findings)} issue(s) found" + (f" ({total_fp_count} likely FP)" if total_fp_count else ""),
        "cvss_metrics": {
            "average": avg_cvss,
            "maximum": max_cvss,
            "scores": sorted(raw_cvss_scores, reverse=True)[:10]
        },
        "compliance": {
            "owasp_top10": sorted(list(compliance_issues["owasp"])),
            "cwe_ids": sorted(list(set(str(cwe).upper() for cwe in compliance_issues["cwe"] if cwe))),
            "soc2_criteria": sorted(list(compliance_issues["soc2"]))
        }
    }
