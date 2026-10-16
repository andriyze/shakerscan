"""Calibrated severity for Scan findings, with the reason recorded next to the evidence.

A check states the severity of its class (``producer_severity``). Some classes were rated above
common practice: a certificate issued for another name is a configuration defect that browsers
already refuse, not a high-severity vulnerability, and a missing ``Referrer-Policy`` is a
hardening recommendation. This module applies one rule per class, using only facts the finding's
own evidence records (the requested host, the pinned address, the negotiated cipher, whether a
secret was proven), and writes ``evidence.severity_basis`` so the finding page can say why.

Rules never consult target cohorts or labels: those organize views and never change results. A
rule never lowers a finding whose evidence proves more than the class default (an exposure with a
proven secret keeps its severity). Findings persisted before this module keep their stored
severity until a later Scan observes them again; their page states the current rule instead.
"""

from __future__ import annotations

from typing import Any, Mapping

SEVERITY_BASIS_SCHEMA = "severity-basis/v1"
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

# The finalizer's severity-derived CVSS placeholder (``_base_finding``); a calibrated finding
# keeps the placeholder consistent with its new severity.
_PLACEHOLDER_CVSS = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0}

_WEAK_CIPHER_BROKEN_MARKERS = ("NULL", "EXPORT", "ANON", "ADH", "AECDH")

# Rule id -> (calibrated default, reason), independent of target labels and network placement.
CLASS_RULES: Mapping[str, tuple[str, str]] = {
    "tls_certificate_hostname_mismatch": (
        "medium",
        "Browsers and TLS clients refuse a certificate issued for another name, so users see an "
        "error instead of being silently exposed. It still trains users to click through "
        "warnings and breaks clients that verify, and an attacker in the network path can "
        "present their own certificate to clients that skip the check.",
    ),
    "tls_certificate_untrusted": (
        "medium",
        "Clients that verify certificates refuse the connection; clients that are configured "
        "to skip verification cannot tell this server from an interceptor.",
    ),
    "tls_certificate_expired": (
        "medium",
        "Clients refuse the expired certificate. The impact is a broken or warning-laden "
        "service and users trained to accept warnings, not direct data exposure.",
    ),
    "tls_certificate_not_yet_valid": (
        "medium",
        "Clients refuse a certificate before its start date; usually a clock or deployment "
        "mistake.",
    ),
    "tls_certificate_expiring": (
        "low",
        "Nothing is broken yet; this is an early warning so the renewal happens before clients "
        "start refusing the certificate.",
    ),
    "tls_legacy_protocol": (
        "medium",
        "The server's best protocol is TLS 1.0/1.1, deprecated by RFC 8996 and refused by "
        "current browsers; attacks on these versions need a network position and specific "
        "conditions.",
    ),
    "tls_weak_cipher": (
        "medium",
        "The negotiated cipher is weak (3DES/RC4 or under 128 bits): practical attacks need a "
        "network position and large amounts of captured traffic.",
    ),
    "tls_weak_cipher_broken": (
        "high",
        "The negotiated cipher provides no encryption or no server authentication (NULL, "
        "EXPORT or anonymous suites): traffic can be read or intercepted directly.",
    ),
    "tls_certificate_weak_signature": (
        "medium",
        "The certificate is signed with SHA-1, which publicly trusted CAs no longer issue and "
        "browsers reject; forging such a signature is expensive but demonstrated.",
    ),
    "tls_certificate_weak_signature_md5": (
        "high",
        "The certificate is signed with MD5; colliding MD5 certificate signatures is practical.",
    ),
    "tls_certificate_weak_public_key": (
        "medium",
        "The certificate key is shorter than current minimums (RSA 2048 / EC 224 bits).",
    ),
    "tls_certificate_weak_public_key_broken": (
        "high",
        "The certificate's RSA key is under 1024 bits, within reach of public factoring work.",
    ),
    "missing_header_content-security-policy": (
        "low",
        "Without a Content-Security-Policy an injected script runs with the page's full "
        "privileges; the header limits damage, it does not cause a vulnerability by itself.",
    ),
    "missing_header_strict-transport-security": (
        "low",
        "Without HSTS a user's first plain-HTTP request can be downgraded by an attacker in the "
        "network path before the redirect to HTTPS.",
    ),
    "missing_header_referrer-policy": (
        "info",
        "Browsers already default to strict-origin-when-cross-origin, which drops paths and "
        "query strings from cross-site referrers; an explicit policy is a hardening "
        "recommendation.",
    ),
    "missing_header_permissions-policy": (
        "info",
        "A Permissions-Policy narrows browser features the page could use; without one nothing "
        "is exposed unless the page is otherwise compromised.",
    ),
    "exposure_directory_listing": (
        "medium",
        "A browsable directory reveals file names and structure. Files proven sensitive are "
        "reported as their own findings at their own severity.",
    ),
    "exposure_metrics_endpoint": (
        "medium",
        "Unauthenticated metrics reveal internal names, versions, routes and load figures that "
        "help an attacker plan; no credential or user data was proven in the response.",
    ),
    "exposure_verbose_error_disclosure": (
        "low",
        "A stack trace or framework error reveals versions, file paths and code structure. It "
        "helps an attacker aim other attacks but grants no access by itself; a credential proven "
        "in the same response keeps the higher severity.",
    ),
    "session_cookie_missing_httponly": (
        "low",
        "Scripts can read the session cookie, so a separate script-injection flaw could steal "
        "the session. The missing attribute does not expose the cookie by itself.",
    ),
    "session_cookie_missing_secure": (
        "low",
        "The browser would also send the session cookie over plain HTTP, where a network "
        "attacker can read it; exploiting it needs a network position and a plain-HTTP request.",
    ),
}

# Producers whose class severity is already the calibrated one: recorded, not changed.
_PRODUCER_REASONS: Mapping[str, str] = {
    "shakerscan_sqli_proof": (
        "A repeated payload/control differential with a database error signature proves the "
        "parameter reaches the query engine."
    ),
    "shakerscan_exposure_probe": (
        "The exposure class sets the severity: secret material outranks structural disclosure, "
        "and a proven provider secret raises any class."
    ),
    "dalfox": (
        "Script executed in a real browser from a request parameter: it runs with the victim's "
        "session on this origin (account actions, data theft). High, not critical, because a "
        "victim must open a crafted link or page."
    ),
    "shakerscan_browser_proof": (
        "Script executed in a real browser on this origin: it runs with the victim's session "
        "(account actions, data theft). High, not critical, because a victim must load the page."
    ),
    "shakerscan_nosqli_verify": (
        "Operator injection changes the database query; an authentication bypass is critical, "
        "other query changes are high."
    ),
    "shakerscan_graphql_probe": (
        "A GraphQL hardening gap: it eases schema discovery or resource exhaustion but exposes no "
        "data by itself."
    ),
    "subdomain_takeover": (
        "A verified unclaimed resource lets anyone serve content on this name (phishing, cookie "
        "theft on the parent domain): high. A dangling CNAME whose claimability is unproven is "
        "medium."
    ),
    "smart_authz": (
        "One principal read another principal's object: broken object-level authorization on "
        "user data is high."
    ),
    "shakerscan_authz_surface": (
        "Medium until someone confirms the function is meant to be private: anonymous and "
        "authenticated users receive the same data, which is only a flaw on a private function."
    ),
    "sqlmap": (
        "Rated by the impact of SQL injection if it is real (high); it is a candidate until the "
        "payload/control proof runs, which the proof state shows separately."
    ),
    "request_sqli_differential": (
        "Rated by the impact of SQL injection if it is real (high); a database error alone is a "
        "candidate, which the proof state shows separately."
    ),
    "request_xss_differential": (
        "Rated by the impact of cross-site scripting if it executes (high); reflection alone is a "
        "candidate, which the proof state shows separately."
    ),
    "nuclei": (
        "The matching template's author set this severity for the issue the template detects; "
        "a template match is a candidate until a deterministic proof confirms it."
    ),
}


PRODUCER_REASONS = _PRODUCER_REASONS


def rule_for(finding: Mapping[str, Any]) -> str | None:
    """The calibration rule id this finding falls under, or None (producer severity stands)."""
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), Mapping) else {}
    tool = str(finding.get("tool") or "")
    check = str(evidence.get("check") or "")
    if tool == "tls.inspect" and check:
        if check == "tls_weak_cipher":
            cipher = str(evidence.get("cipher") or "").upper()
            if any(marker in cipher for marker in _WEAK_CIPHER_BROKEN_MARKERS):
                return "tls_weak_cipher_broken"
        if check == "tls_certificate_weak_signature":
            certificate = evidence.get("certificate") if isinstance(evidence.get("certificate"), Mapping) else {}
            if str(certificate.get("signature_hash") or "").lower() == "md5":
                return "tls_certificate_weak_signature_md5"
        if check == "tls_certificate_weak_public_key":
            certificate = evidence.get("certificate") if isinstance(evidence.get("certificate"), Mapping) else {}
            bits = certificate.get("public_key_bits")
            if "RSA" in str(certificate.get("public_key_type") or "").upper() and isinstance(bits, int) and bits < 1024:
                return "tls_certificate_weak_public_key_broken"
        return check if check in CLASS_RULES else None
    if tool == "http_baseline" and check.startswith(("missing_header_", "session_cookie_missing_")):
        return check if check in CLASS_RULES else None
    if tool == "shakerscan_exposure_probe":
        rule = f"exposure_{evidence.get('exposure_class')}"
        return rule if rule in CLASS_RULES else None
    return None


def _proven_secret(evidence: Mapping[str, Any]) -> bool:
    return any(
        isinstance(item, Mapping) and item.get("category")
        for item in evidence.get("exposure_fingerprints") or ()
    )


def calibrate_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Apply this finding's rule in place and record ``evidence.severity_basis``."""
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        return finding
    rule = rule_for(finding)
    previous = evidence.get("severity_basis")
    producer = str(finding.get("severity") or "info").lower()
    if (isinstance(previous, Mapping) and previous.get("schema") == SEVERITY_BASIS_SCHEMA
            and previous.get("rule") == rule and previous.get("severity") == producer
            and previous.get("producer_severity") in SEVERITY_ORDER):
        producer = previous["producer_severity"]
    if rule is None:
        reason = _PRODUCER_REASONS.get(str(finding.get("tool") or ""))
        if reason:
            evidence["severity_basis"] = {
                "schema": SEVERITY_BASIS_SCHEMA,
                "rule": f"producer:{finding.get('tool')}",
                "severity": producer,
                "producer_severity": producer,
                "reason": reason,
                "factors": [],
            }
        return finding
    default, reason = CLASS_RULES[rule]
    if rule.startswith("exposure_") and _proven_secret(evidence):
        # A proven secret is what the producer rated; never calibrate it down.
        evidence["severity_basis"] = {
            "schema": SEVERITY_BASIS_SCHEMA,
            "rule": rule,
            "severity": producer,
            "producer_severity": producer,
            "reason": "The response contained proven secret material, which keeps the producer's severity.",
            "factors": [{"factor": "proven_secret", "text": "A provider secret or secret-named value was proven in the response."}],
        }
        return finding
    # Private placement or requesting an IP does not reduce a demonstrated TLS defect.
    factors: list[dict[str, str]] = []
    severity = default
    if severity != producer:
        finding["severity"] = severity
        if finding.get("cvss_score") == _PLACEHOLDER_CVSS.get(producer):
            finding["cvss_score"] = _PLACEHOLDER_CVSS.get(severity)
    evidence["severity_basis"] = {
        "schema": SEVERITY_BASIS_SCHEMA,
        "rule": rule,
        "severity": severity,
        "producer_severity": producer,
        "class_default": default,
        "reason": reason,
        "factors": factors,
    }
    return finding


def calibrate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for finding in findings:
        if isinstance(finding, dict):
            calibrate_finding(finding)
    return findings


def current_rule_severity(finding: Mapping[str, Any]) -> dict[str, Any] | None:
    """What the current rule would assign a stored finding, without changing it (read path)."""
    copy = dict(finding)
    evidence = finding.get("evidence")
    copy["evidence"] = dict(evidence) if isinstance(evidence, Mapping) else {}
    if rule_for(copy) is None:
        return None
    calibrate_finding(copy)
    basis = copy["evidence"].get("severity_basis")
    return dict(basis) if isinstance(basis, Mapping) else None


__all__ = [
    "CLASS_RULES",
    "PRODUCER_REASONS",
    "SEVERITY_BASIS_SCHEMA",
    "calibrate_finding",
    "calibrate_findings",
    "current_rule_severity",
    "rule_for",
]
