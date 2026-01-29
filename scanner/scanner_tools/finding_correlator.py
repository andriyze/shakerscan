"""
Finding Correlation Engine

Analyzes scan findings to identify correlations that increase overall risk:
- Multiple vulnerabilities that chain together
- Configuration weaknesses that amplify vulnerability impact
- Technology stack issues that enable exploitation

Correlation patterns elevate finding severity when combined:
- reflected_xss + weak_csp = elevated_xss_impact
- sqli_confirmed + admin_panel_found = potential_admin_compromise
- ssrf_detected + cloud_metadata_accessible = critical_cloud_breach
- jwt_weak + missing_expiry = token_forgery_risk
- idor + sequential_ids = mass_data_breach_risk

IMPORTANT: This module is for DEFENSIVE security analysis - helping
organizations understand the compound risk of multiple findings.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CorrelationPattern:
    """Defines a correlation pattern between findings"""
    name: str
    description: str
    required_findings: list[str]  # Findings that can trigger this pattern
    optional_findings: list[str]  # Boost confidence if present
    severity_elevation: str  # Elevated severity for the correlation
    risk_multiplier: float  # How much to multiply risk score
    business_impact: str
    remediation_priority: list[str]  # Which findings to fix first
    min_required: int = 1  # Minimum required findings to trigger (prevents single-finding inflation)
    require_optional: bool = False  # If True, at least one optional must also match


@dataclass
class Correlation:
    """A detected correlation between findings"""
    pattern_name: str
    description: str
    severity: str
    matched_findings: list[str]
    supporting_findings: list[str]
    business_impact: str
    remediation_priority: list[str]
    confidence: float  # 0-1
    evidence: dict[str, Any] = field(default_factory=dict)


# Define correlation patterns
CORRELATION_PATTERNS = [
    # XSS + Cookie Security = Session Hijacking Risk
    CorrelationPattern(
        name="xss_session_hijacking_risk",
        description="XSS combined with weak cookie security enables session theft",
        required_findings=["reflected_xss", "stored_xss", "dom_xss", "xss"],
        optional_findings=["missing_httponly", "missing_secure_flag", "missing_samesite", "weak_csp", "csp_unsafe_inline"],
        severity_elevation="critical",
        risk_multiplier=2.0,
        business_impact="Attackers can steal user sessions via XSS, leading to account takeover",
        remediation_priority=["Fix XSS vulnerabilities", "Enable HttpOnly on session cookies", "Implement Content Security Policy"],
    ),

    # XSS + Weak CSP = Elevated XSS Impact
    CorrelationPattern(
        name="elevated_xss_impact",
        description="XSS with weak or missing CSP has higher exploitability",
        required_findings=["reflected_xss", "stored_xss", "dom_xss", "xss"],
        optional_findings=["weak_csp", "csp_missing", "csp_unsafe_inline", "csp_unsafe_eval"],
        severity_elevation="high",
        risk_multiplier=1.5,
        business_impact="Weak CSP makes XSS easier to exploit with complex payloads",
        remediation_priority=["Implement strict Content Security Policy", "Fix XSS vulnerabilities"],
    ),

    # SQLi + Admin Panel = Admin Compromise
    # Requires SQLi AND admin panel to trigger (not just SQLi alone)
    CorrelationPattern(
        name="sqli_admin_compromise",
        description="SQL injection with exposed admin panel enables admin account takeover",
        required_findings=["sqli_confirmed", "sqli_error_based", "sqli_time_based", "sqli_union"],
        optional_findings=["admin_panel_found", "admin_interface_exposed", "cms_admin_found"],
        severity_elevation="critical",
        risk_multiplier=2.5,
        business_impact="Attackers can extract admin credentials via SQLi and login to admin panel",
        remediation_priority=["Fix SQL injection", "Restrict admin panel access", "Implement MFA for admins"],
        min_required=1,
        require_optional=True,  # Must have SQLi AND admin panel
    ),

    # SQLi + Weak Password Hashing = Credential Compromise
    CorrelationPattern(
        name="sqli_credential_compromise",
        description="SQL injection with weak password hashing enables mass credential theft",
        required_findings=["sqli_confirmed", "sqli_union", "sqli_error_based"],
        optional_findings=["weak_password_hashing", "md5_hashing", "sha1_hashing", "no_salt"],
        severity_elevation="critical",
        risk_multiplier=2.0,
        business_impact="Extracted password hashes can be cracked quickly if using weak hashing",
        remediation_priority=["Fix SQL injection", "Upgrade to bcrypt/Argon2", "Force password resets"],
    ),

    # SSRF + Cloud Metadata = Cloud Breach
    # Requires SSRF AND cloud metadata evidence to trigger critical elevation
    CorrelationPattern(
        name="ssrf_cloud_breach",
        description="SSRF accessing cloud metadata service enables IAM credential theft",
        required_findings=["ssrf_confirmed", "ssrf_internal_access"],
        optional_findings=["cloud_metadata_exposed", "aws_metadata_accessible", "gcp_metadata_accessible", "azure_metadata_accessible"],
        severity_elevation="critical",
        risk_multiplier=3.0,
        business_impact="Cloud IAM credentials can be stolen, compromising entire cloud infrastructure",
        remediation_priority=["Fix SSRF vulnerability", "Block metadata endpoint access", "Use IMDSv2"],
        min_required=1,
        require_optional=True,  # Must have SSRF AND cloud metadata indicator
    ),

    # SSRF + Internal Services = Internal Network Compromise
    CorrelationPattern(
        name="ssrf_internal_network",
        description="SSRF reaching internal services enables lateral movement",
        required_findings=["ssrf_confirmed", "ssrf_internal_access"],
        optional_findings=["internal_service_exposed", "internal_api_accessible", "redis_accessible", "elasticsearch_accessible"],
        severity_elevation="critical",
        risk_multiplier=2.5,
        business_impact="Internal services can be accessed and exploited from external SSRF",
        remediation_priority=["Fix SSRF", "Implement network segmentation", "Add authentication to internal services"],
    ),

    # LFI + Sensitive Files = Credential Exposure
    CorrelationPattern(
        name="lfi_credential_exposure",
        description="LFI with accessible sensitive files exposes credentials",
        required_findings=["lfi_confirmed", "path_traversal"],
        optional_findings=["env_file_exposed", "config_file_exposed", "source_code_disclosure", "passwd_readable"],
        severity_elevation="critical",
        risk_multiplier=2.0,
        business_impact="Configuration files with credentials can be read, enabling further attacks",
        remediation_priority=["Fix LFI vulnerability", "Move secrets to secure vault", "Restrict file permissions"],
    ),

    # IDOR + Predictable IDs = Mass Data Breach
    # Requires IDOR AND predictability indicator to trigger critical elevation
    CorrelationPattern(
        name="idor_mass_breach",
        description="IDOR with sequential/predictable IDs enables mass data extraction",
        required_findings=["idor_confirmed", "bola_confirmed", "broken_access_control"],
        optional_findings=["sequential_ids", "predictable_ids", "api_enumerable_ids", "no_rate_limiting"],
        severity_elevation="critical",
        risk_multiplier=2.5,
        business_impact="All user records can be enumerated and extracted via IDOR",
        remediation_priority=["Implement authorization checks", "Use UUIDs", "Add rate limiting"],
        min_required=1,
        require_optional=True,  # Must have IDOR AND predictability indicator
    ),

    # JWT Vulnerabilities = Token Forgery
    CorrelationPattern(
        name="jwt_token_forgery",
        description="JWT weaknesses enable token forgery and user impersonation",
        required_findings=["jwt_none_algorithm", "jwt_weak_secret", "jwt_algorithm_confusion"],
        optional_findings=["jwt_missing_expiry", "jwt_kid_injection", "jwt_jku_spoofing"],
        severity_elevation="critical",
        risk_multiplier=2.5,
        business_impact="Attackers can forge valid JWTs to impersonate any user including admins",
        remediation_priority=["Use strong algorithms (RS256/ES256)", "Validate algorithm server-side", "Set token expiry"],
    ),

    # CORS + Credentials = Data Theft
    CorrelationPattern(
        name="cors_data_theft",
        description="CORS misconfiguration with credentials allows cross-origin data theft",
        required_findings=["cors_wildcard", "cors_null_origin", "cors_arbitrary_origin"],
        optional_findings=["cors_credentials_exposed", "sensitive_data_in_response", "auth_tokens_in_response"],
        severity_elevation="high",
        risk_multiplier=1.8,
        business_impact="Authenticated user data can be stolen via malicious websites",
        remediation_priority=["Implement strict CORS policy", "Use explicit origin allowlist", "Remove credentials from CORS"],
    ),

    # Authentication Bypass + Admin = Full Compromise
    CorrelationPattern(
        name="auth_bypass_admin_compromise",
        description="Authentication bypass with admin access enables full system compromise",
        required_findings=["auth_bypass", "authentication_bypass", "broken_authentication"],
        optional_findings=["admin_panel_found", "admin_access_gained", "privileged_function_exposed"],
        severity_elevation="critical",
        risk_multiplier=3.0,
        business_impact="Full administrative access without credentials",
        remediation_priority=["Fix authentication bypass", "Implement MFA", "Add access logging"],
    ),

    # Open Redirect + OAuth = Account Takeover
    CorrelationPattern(
        name="open_redirect_oauth_ato",
        description="Open redirect in OAuth flow enables authorization code theft",
        required_findings=["open_redirect", "unvalidated_redirect"],
        optional_findings=["oauth_detected", "oauth_redirect_uri_manipulation", "authorization_code_exposure"],
        severity_elevation="high",
        risk_multiplier=2.0,
        business_impact="OAuth authorization codes can be stolen via redirect, enabling account takeover",
        remediation_priority=["Fix open redirect", "Validate redirect_uri strictly", "Use state parameter"],
        require_optional=True,  # Require OAuth context signal to avoid false positives
    ),

    # Information Disclosure + Technology = Targeted Attacks
    CorrelationPattern(
        name="info_disclosure_targeted_attack",
        description="Detailed error messages with version info enable targeted exploits",
        required_findings=["stack_trace_exposed", "error_message_disclosure", "debug_mode_enabled"],
        optional_findings=["version_disclosure", "technology_fingerprint", "outdated_software"],
        severity_elevation="medium",
        risk_multiplier=1.3,
        business_impact="Attackers can craft targeted exploits using disclosed technology details",
        remediation_priority=["Disable debug mode", "Implement generic error pages", "Update software"],
    ),

    # Multiple Critical = Systemic Risk
    CorrelationPattern(
        name="systemic_critical_risk",
        description="Multiple critical vulnerabilities indicate systemic security issues",
        required_findings=["sqli_confirmed", "rce_confirmed", "ssrf_confirmed", "auth_bypass"],
        optional_findings=["xss", "lfi_confirmed", "idor_confirmed", "xxe_confirmed"],
        severity_elevation="critical",
        risk_multiplier=3.0,
        business_impact="Multiple critical vulnerabilities suggest fundamental security gaps",
        remediation_priority=["Engage security team immediately", "Conduct full security audit", "Implement SDLC security"],
        min_required=2,  # Require at least two critical signals
    ),

    # Insecure Deserialization + Known Framework = RCE
    CorrelationPattern(
        name="deserialization_rce",
        description="Insecure deserialization in known framework enables RCE",
        required_findings=["insecure_deserialization", "java_deserialization", "php_deserialization", "python_deserialization"],
        optional_findings=["java_detected", "php_detected", "python_detected", "known_gadget_chain"],
        severity_elevation="critical",
        risk_multiplier=2.5,
        business_impact="Remote code execution via deserialization gadget chains",
        remediation_priority=["Disable unsafe deserialization", "Implement input validation", "Update frameworks"],
    ),

    # XXE + Internal Network = Data Exfiltration
    CorrelationPattern(
        name="xxe_data_exfiltration",
        description="XXE with internal network access enables file and data exfiltration",
        required_findings=["xxe_confirmed", "xml_external_entity"],
        optional_findings=["internal_file_read", "ssrf_via_xxe", "out_of_band_xxe"],
        severity_elevation="critical",
        risk_multiplier=2.0,
        business_impact="Internal files and data can be exfiltrated via XXE",
        remediation_priority=["Disable external entities", "Update XML parsers", "Implement input validation"],
    ),
]


def normalize_finding_type(finding_type: str) -> str:
    """Normalize finding type for matching."""
    return finding_type.lower().replace(" ", "_").replace("-", "_")


def extract_finding_types(findings: list[dict]) -> tuple[set[str], dict[str, list[dict]]]:
    """
    Extract and normalize finding types from findings list.

    Args:
        findings: List of finding dictionaries

    Returns:
        Tuple of (set of normalized types, dict mapping types to findings)
    """
    types = set()
    type_to_findings = {}

    for finding in findings:
        # Get primary type
        finding_type = finding.get("type", finding.get("name", finding.get("vulnerability_type", "")))
        if finding_type:
            normalized = normalize_finding_type(finding_type)
            types.add(normalized)
            type_to_findings.setdefault(normalized, []).append(finding)

        # Extract additional types from description
        description = finding.get("description", "").lower()
        severity = finding.get("severity", "").lower()

        # XSS patterns
        if "xss" in description or "cross-site scripting" in description:
            types.add("xss")
            if "reflected" in description:
                types.add("reflected_xss")
            if "stored" in description:
                types.add("stored_xss")
            if "dom" in description:
                types.add("dom_xss")

        # SQLi patterns
        if "sql injection" in description or "sqli" in normalized:
            types.add("sqli_confirmed")
            if "union" in description:
                types.add("sqli_union")
            if "time" in description or "blind" in description:
                types.add("sqli_time_based")
            if "error" in description:
                types.add("sqli_error_based")

        # SSRF patterns
        if "ssrf" in description or "server-side request" in description:
            types.add("ssrf_confirmed")
            if "internal" in description or "localhost" in description:
                types.add("ssrf_internal_access")
            if "metadata" in description or "169.254" in description:
                types.add("cloud_metadata_exposed")

        # LFI patterns
        if "local file" in description or "path traversal" in description:
            types.add("lfi_confirmed")
            types.add("path_traversal")
            if ".env" in description or "config" in description:
                types.add("config_file_exposed")

        # IDOR patterns
        if "idor" in description or "insecure direct object" in description or "bola" in description:
            types.add("idor_confirmed")
            types.add("bola_confirmed")
            types.add("broken_access_control")

        # JWT patterns
        if "jwt" in description:
            if "none" in description:
                types.add("jwt_none_algorithm")
            if "weak" in description:
                types.add("jwt_weak_secret")
            if "expir" in description:
                types.add("jwt_missing_expiry")

        # Cookie patterns
        if "httponly" in description and "missing" in description:
            types.add("missing_httponly")
        if "secure" in description and "flag" in description and "missing" in description:
            types.add("missing_secure_flag")
        if "samesite" in description and "missing" in description:
            types.add("missing_samesite")

        # CSP patterns
        if "csp" in description or "content-security-policy" in description:
            if "missing" in description:
                types.add("csp_missing")
                types.add("weak_csp")
            if "unsafe-inline" in description:
                types.add("csp_unsafe_inline")
                types.add("weak_csp")
            if "unsafe-eval" in description:
                types.add("csp_unsafe_eval")
                types.add("weak_csp")

        # CORS patterns
        if "cors" in description:
            if "wildcard" in description or '"*"' in description:
                types.add("cors_wildcard")
            if "null" in description:
                types.add("cors_null_origin")
            if "arbitrary" in description or "reflected" in description:
                types.add("cors_arbitrary_origin")

        # Admin patterns
        if "admin" in description:
            if "panel" in description or "interface" in description:
                types.add("admin_panel_found")

        # Auth patterns
        if "authentication" in description and "bypass" in description:
            types.add("auth_bypass")
            types.add("broken_authentication")

        # XXE patterns
        if "xxe" in description or "xml external entity" in description:
            types.add("xxe_confirmed")

        # Deserialization patterns
        if "deserialization" in description:
            types.add("insecure_deserialization")
            if "java" in description:
                types.add("java_deserialization")
            if "php" in description:
                types.add("php_deserialization")
            if "python" in description:
                types.add("python_deserialization")

        # Redirect patterns
        if "redirect" in description and ("open" in description or "unvalidated" in description):
            types.add("open_redirect")
            types.add("unvalidated_redirect")

        # Error disclosure
        if "stack trace" in description or "error message" in description:
            types.add("error_message_disclosure")
            if "stack" in description:
                types.add("stack_trace_exposed")
        if "debug" in description and ("enabled" in description or "mode" in description):
            types.add("debug_mode_enabled")

    return types, type_to_findings


def match_correlation_pattern(
    pattern: CorrelationPattern,
    found_types: set[str],
    type_to_findings: dict[str, list[dict]],
) -> Correlation | None:
    """
    Check if a correlation pattern matches the found vulnerability types.

    Args:
        pattern: Correlation pattern to check
        found_types: Set of found vulnerability types
        type_to_findings: Mapping of types to their findings

    Returns:
        Correlation if pattern matches, None otherwise
    """
    # Check required findings (must meet minimum threshold)
    matched_required = [f for f in pattern.required_findings if f in found_types]

    # Must have at least min_required matches (prevents single-finding inflation)
    if len(matched_required) < pattern.min_required:
        return None

    # Check optional findings
    matched_optional = [f for f in pattern.optional_findings if f in found_types]

    # If require_optional is True, at least one optional must match
    if pattern.require_optional and not matched_optional:
        return None

    # Calculate confidence based on matches
    # Base confidence scales with how many required findings matched
    base_confidence = 0.4 + (0.2 * min(len(matched_required), 3))
    confidence = base_confidence

    # Bonus for multiple required matches
    if len(matched_required) > 1:
        confidence += 0.1 * min(len(matched_required) - 1, 2)

    # Bonus for optional matches
    if pattern.optional_findings and matched_optional:
        confidence += (len(matched_optional) / len(pattern.optional_findings)) * 0.2

    confidence = min(confidence, 0.95)

    # Gather evidence from matched findings
    evidence = {"matched_findings_details": []}
    for finding_type in matched_required + matched_optional:
        for finding in type_to_findings.get(finding_type, []):
            evidence["matched_findings_details"].append({
                "type": finding.get("type", finding.get("name")),
                "severity": finding.get("severity"),
                "url": finding.get("url", finding.get("location")),
            })

    return Correlation(
        pattern_name=pattern.name,
        description=pattern.description,
        severity=pattern.severity_elevation,
        matched_findings=matched_required,
        supporting_findings=matched_optional,
        business_impact=pattern.business_impact,
        remediation_priority=pattern.remediation_priority,
        confidence=confidence,
        evidence=evidence,
    )


def identify_correlations(findings: list[dict]) -> list[Correlation]:
    """
    Identify all correlations in a list of findings.

    Args:
        findings: List of vulnerability findings

    Returns:
        List of identified correlations
    """
    if not findings:
        return []

    found_types, type_to_findings = extract_finding_types(findings)

    if not found_types:
        return []

    correlations = []

    for pattern in CORRELATION_PATTERNS:
        correlation = match_correlation_pattern(pattern, found_types, type_to_findings)
        if correlation:
            correlations.append(correlation)

    # Sort by severity and confidence
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    correlations.sort(key=lambda c: (severity_order.get(c.severity, 4), -c.confidence))

    return correlations


def elevate_finding_severities(
    findings: list[dict],
    correlations: list[Correlation],
) -> list[dict]:
    """
    Create a new findings list with elevated severities based on correlations.

    Args:
        findings: Original findings list
        correlations: Identified correlations

    Returns:
        New findings list with severity adjustments
    """
    # Build set of types that should be elevated
    elevation_map = {}  # finding_type -> new_severity

    for correlation in correlations:
        for finding_type in correlation.matched_findings:
            current = elevation_map.get(finding_type)
            if current is None or severity_rank(correlation.severity) < severity_rank(current):
                elevation_map[finding_type] = correlation.severity

    # Create new findings list with elevations
    elevated_findings = []

    for finding in findings:
        new_finding = finding.copy()
        finding_type = normalize_finding_type(
            finding.get("type", finding.get("name", finding.get("vulnerability_type", "")))
        )

        if finding_type in elevation_map:
            original_severity = finding.get("severity", "medium")
            new_severity = elevation_map[finding_type]

            if severity_rank(new_severity) < severity_rank(original_severity):
                new_finding["original_severity"] = original_severity
                new_finding["severity"] = new_severity
                new_finding["severity_elevated"] = True
                new_finding["elevation_reason"] = f"Elevated due to correlation: {finding_type} combined with other findings"

        elevated_findings.append(new_finding)

    return elevated_findings


def severity_rank(severity: str) -> int:
    """Get numeric rank for severity (lower is more severe)."""
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return ranks.get(severity.lower(), 5)


def format_correlation_report(correlations: list[Correlation]) -> str:
    """Format correlations into a readable report."""
    if not correlations:
        return "No cross-finding correlations detected."

    lines = []
    lines.append("=" * 70)
    lines.append("CROSS-FINDING CORRELATION ANALYSIS")
    lines.append("=" * 70)
    lines.append(f"\nIdentified {len(correlations)} correlation(s):\n")

    for i, corr in enumerate(correlations, 1):
        lines.append(f"\n{'─' * 60}")
        lines.append(f"Correlation #{i}: {corr.pattern_name.replace('_', ' ').title()}")
        lines.append(f"{'─' * 60}")
        lines.append(f"Severity: {corr.severity.upper()}")
        lines.append(f"Confidence: {corr.confidence * 100:.0f}%")
        lines.append(f"\nDescription:\n{corr.description}")
        lines.append(f"\nBusiness Impact:\n{corr.business_impact}")

        lines.append("\nMatched Vulnerabilities:")
        for vuln in corr.matched_findings:
            lines.append(f"  [PRIMARY] {vuln}")
        for vuln in corr.supporting_findings:
            lines.append(f"  [SUPPORTING] {vuln}")

        lines.append("\nRemediation Priority:")
        for j, rem in enumerate(corr.remediation_priority, 1):
            lines.append(f"  {j}. {rem}")

    return "\n".join(lines)


def correlations_to_dict(correlations: list[Correlation]) -> list[dict]:
    """Convert correlations to dictionary format."""
    return [
        {
            "pattern_name": c.pattern_name,
            "description": c.description,
            "severity": c.severity,
            "confidence": c.confidence,
            "matched_findings": c.matched_findings,
            "supporting_findings": c.supporting_findings,
            "business_impact": c.business_impact,
            "remediation_priority": c.remediation_priority,
            "evidence": c.evidence,
        }
        for c in correlations
    ]


# Main entry point for scanner integration
def analyze_finding_correlations(findings: list[dict]) -> dict[str, Any]:
    """
    Main entry point for finding correlation analysis.

    Args:
        findings: List of vulnerability findings from scan

    Returns:
        Dict with correlations, elevated findings, report, and summary
    """
    correlations = identify_correlations(findings)
    elevated_findings = elevate_finding_severities(findings, correlations)

    # Count elevations
    elevations = sum(1 for f in elevated_findings if f.get("severity_elevated"))

    return {
        "correlations": correlations_to_dict(correlations),
        "elevated_findings": elevated_findings,
        "report": format_correlation_report(correlations),
        "summary": {
            "total_correlations": len(correlations),
            "critical_correlations": sum(1 for c in correlations if c.severity == "critical"),
            "high_correlations": sum(1 for c in correlations if c.severity == "high"),
            "findings_elevated": elevations,
            "correlation_types": [c.pattern_name for c in correlations],
        },
    }


# Integration with attack chains
def combine_with_attack_chains(
    correlations: list[Correlation],
    attack_chains: list[dict],
) -> dict[str, Any]:
    """
    Combine correlation analysis with attack chain analysis.

    Args:
        correlations: List of correlations
        attack_chains: List of attack chains from attack_chains module

    Returns:
        Combined risk assessment
    """
    # Calculate overall risk score
    correlation_risk = sum(
        (3.0 if c.severity == "critical" else 2.0 if c.severity == "high" else 1.0) * c.confidence
        for c in correlations
    )

    chain_risk = sum(
        (3.0 if c.get("severity") == "critical" else 2.0 if c.get("severity") == "high" else 1.0) * c.get("completeness", 0.5)
        for c in attack_chains
    )

    total_risk = correlation_risk + chain_risk

    # Determine overall risk level
    if total_risk > 10:
        risk_level = "critical"
    elif total_risk > 5:
        risk_level = "high"
    elif total_risk > 2:
        risk_level = "medium"
    elif total_risk > 0:
        risk_level = "low"
    else:
        risk_level = "minimal"

    return {
        "overall_risk_level": risk_level,
        "risk_score": total_risk,
        "correlation_risk": correlation_risk,
        "attack_chain_risk": chain_risk,
        "total_correlations": len(correlations),
        "total_attack_chains": len(attack_chains),
        "immediate_concerns": [
            c.pattern_name for c in correlations if c.severity == "critical"
        ] + [
            c.get("name") for c in attack_chains if c.get("severity") == "critical"
        ],
    }
