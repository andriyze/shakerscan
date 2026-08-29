"""Pure Scan report assembly from terminal action results and observations."""

from __future__ import annotations

import hashlib
import json
import urllib.parse
from collections import Counter
from typing import Any, Mapping, Sequence

from .action_plan import ScanActionPlan
from .capability_result import CapabilityResultReference, CapabilityResultStatus
from .continuation import (
    ScanContinuationError,
    ScanPlanRevision,
    root_scan_plan_revision,
)


SCAN_REPORT_SCHEMA = "canonical-scan-report/v2"
_SEVERITY_WEIGHT = {
    "critical": 20,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0,
}
# The best score a scan can hold once a finding of this severity exists. Grade bands are
# A>=90, B>=80, C>=70, D>=60, F<60 -- so one critical is an F however few findings there are, one
# high cannot exceed C, and one medium cannot exceed B. Low and informational have no ceiling: a
# single low-severity issue is not a reason to fail an application, though it still costs weight.
# Reported as missing when absent from a response, so the report says what is not there rather
# than only what is.
_EXPECTED_SECURITY_HEADERS: tuple[str, ...] = (
    "content-security-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
)
_SEVERITY_SCORE_CEILING = {
    "critical": 40,
    "high": 70,
    "medium": 85,
}
_ACTIVE_VERIFIER_CAPABILITIES = frozenset({
    "templates.scan", "xss.verify", "sqli.verify", "authz.verify",
    "templates.active_batch", "xss.verify_batch", "sqli.verify_batch",
    "xss.request_verify", "sqli.request_verify", "browser.proof",
    "xss.request_verify_batch", "sqli.request_verify_batch", "sqli.prove_batch",
    "xss.browser_prove_batch", "exposure.verify_batch", "nosqli.verify_batch",
    "authz_surface.verify_batch",
})
_TRAFFIC_BUDGETS = frozenset({
    "http_requests", "state_changing_requests", "browser_actions",
    "tcp_ports_attempted", "hosts_attempted",
})
# Every selected-family capability collapsed to the canonical family it serves,
# so coverage and grade reliability are reported per resolved family.
# Proof escalation runs over the candidates a verifier already attempted, so it
# is part of the family's authority but not part of its execution coverage.
# Folding the two together counted the same candidates twice and let a proof
# action that was correctly skipped as not_applicable mark a fully-executed
# family incomplete -- raising a selected-family gap and making the whole grade
# unreliable for work that had succeeded.
# A skip for one of these means the escalation was never able to run, not that
# it ran and produced nothing.
_PROOF_UNAVAILABLE_REASONS = frozenset({
    "insufficient_plan_budget",
    "placement_unavailable",
})
_PROOF_CAPABILITIES = frozenset({
    "xss.browser_prove_batch",
    "sqli.prove_batch",
})
_FAMILY_BY_CAPABILITY = {
    "xss.verify_batch": "xss",
    "xss.request_verify_batch": "xss",
    "xss.browser_prove_batch": "xss",
    "sqli.verify_batch": "sqli",
    "sqli.request_verify_batch": "sqli",
    "sqli.prove_batch": "sqli",
    "templates.passive_batch": "nuclei_passive",
    "templates.active_batch": "nuclei_active",
    "exposure.verify_batch": "sensitive_exposure",
    "nosqli.verify_batch": "nosqli",
    "authz_surface.verify_batch": "authz_surface",
    "authz.verify": "bola",
}


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
        "http.request": {"http_observation"},
        "xss.verify": {"xss_alert"},
        "xss.verify_batch": {"candidate_attempt", "xss_alert"},
        "sqli.verify": {"sqli_finding"},
        "sqli.verify_batch": {
            "candidate_attempt", "sqli_finding", "sqli_dbms_fingerprint",
        },
        "xss.request_verify": {"request_body_verification"},
        "sqli.request_verify": {"request_body_verification"},
        "xss.request_verify_batch": {"candidate_attempt", "request_body_verification"},
        "sqli.request_verify_batch": {"candidate_attempt", "request_body_verification"},
        "sqli.prove_batch": {"candidate_attempt", "sqli_proof"},
        "xss.browser_prove_batch": {"candidate_attempt", "xss_browser_proof"},
        "exposure.verify_batch": {"candidate_attempt", "sensitive_exposure_proof"},
        "nosqli.verify_batch": {"candidate_attempt", "nosqli_proof"},
        "authz_surface.verify_batch": {"candidate_attempt", "authz_surface_proof"},
        "authz.verify": {"authz_differential"},
        "templates.scan": {"template_match"},
        "templates.passive_scan": {"template_match"},
        "templates.active_batch": {"candidate_attempt", "template_match"},
        "templates.passive_batch": {"candidate_attempt", "template_match"},
        "tls.inspect": {"tls_protocol"},
    }.get(result.capability_name, set())
    for raw in observations:
        item = dict(raw)
        kind = str(item.get("kind") or "")
        if kind not in allowed_kinds:
            continue
        if kind == "candidate_attempt":
            continue
        if kind == "http_observation" and result.action_id == "baseline.http":
            request = (
                dict(item.get("request") or {})
                if isinstance(item.get("request"), Mapping) else {}
            )
            response = (
                dict(item.get("response") or {})
                if isinstance(item.get("response"), Mapping) else {}
            )
            headers = (
                dict(response.get("selected_headers") or {})
                if isinstance(response.get("selected_headers"), Mapping) else {}
            )
            status = response.get("status")
            if (
                headers
                and isinstance(status, int)
                and 200 <= status < 400
            ):
                origin = request.get("origin") or response.get("final_url")
                scheme = urllib.parse.urlsplit(str(origin or "")).scheme.lower()
                expected_headers = [
                    ("content-security-policy", "Content Security Policy"),
                    ("referrer-policy", "Referrer Policy"),
                    ("permissions-policy", "Permissions Policy"),
                ]
                if scheme == "https":
                    expected_headers.append((
                        "strict-transport-security", "HTTP Strict Transport Security",
                    ))
                for header_name, display_name in expected_headers:
                    if str(headers.get(header_name) or "").strip():
                        continue
                    finding = _base_finding(
                        tool="http_baseline",
                        title=f"Missing {display_name} header",
                        severity="low",
                        cwe="CWE-693",
                        url=origin,
                        evidence={
                            "url": origin,
                            "status": status,
                            "header": header_name,
                            "pinned_address": request.get("pinned_address"),
                            "canonical_capability": "http.request",
                            "capability_receipt": receipt,
                        },
                    )
                    finding.update({
                        "verified": True,
                        "suspected": False,
                        "needs_verification": False,
                        "proof_state": "verified",
                        "verification_reason": (
                            "Pinned deterministic HTTP response omitted the header"
                        ),
                    })
                    findings.append(finding)
        elif kind == "xss_alert" and item.get("proof_state") == "verified":
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
                    "canonical_capability": result.capability_name,
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
        elif (
            kind == "xss_browser_proof"
            and item.get("proof_state") == "verified"
            and item.get("finding_verdict") == "verified"
            and item.get("proof_producer") == "shakerscan"
            and item.get("evidence_type") in {"dom_execution", "browser_execution"}
            and str(item.get("technique") or "").startswith("headless_xss_")
        ):
            finding = _base_finding(
                tool="shakerscan_browser_proof",
                title="Verified cross-site scripting",
                severity="high",
                cwe="CWE-79",
                url=None,
                evidence={
                    "candidate_id": item.get("candidate_id"),
                    "parameter_name": item.get("parameter_name"),
                    "payload_sha256": item.get("payload_sha256"),
                    "marker_sha256": item.get("marker_sha256"),
                    "proof_producer": "shakerscan",
                    "evidence_type": item.get("evidence_type"),
                    "technique": item.get("technique"),
                    "event_transcript": list(item.get("event_transcript") or ()),
                    "dom_marker_executed": item.get("dom_marker_executed"),
                    "sanitized_screenshot_sha256": item.get(
                        "sanitized_screenshot_sha256"
                    ),
                    "browser_build": item.get("browser_build"),
                    "canonical_capability": result.capability_name,
                    "capability_receipt": receipt,
                },
            )
            finding.update({
                "verified": True, "suspected": False,
                "needs_verification": False, "proof_state": "verified",
                "verification_reason": "Canonical headless browser execution proof satisfied",
            })
            findings.append(finding)
        elif kind == "request_body_verification":
            family = str(item.get("family") or "").strip().lower()
            proof_status = str(item.get("proof_status") or "").strip().lower()
            expected_family = (
                "xss" if result.capability_name in {
                    "xss.request_verify", "xss.request_verify_batch",
                }
                else "sqli"
            )
            expected_proof = (
                "reflected_candidate_only"
                if expected_family == "xss" else "db_error_candidate_only"
            )
            if (
                family != expected_family
                or proof_status != expected_proof
                or item.get("finding_verdict") != "suspected"
            ):
                continue
            finding = _base_finding(
                tool=f"request_{expected_family}_differential",
                title=(
                    "Potential reflected cross-site scripting"
                    if expected_family == "xss"
                    else "Potential SQL injection"
                ),
                severity="high",
                cwe="CWE-79" if expected_family == "xss" else "CWE-89",
                url=None,
                evidence={
                    "candidate_id": item.get("candidate_id"),
                    "request_ref_id": item.get("request_ref_id"),
                    "method": item.get("method"),
                    "body_encoding": item.get("body_encoding"),
                    "field_path": item.get("field_path"),
                    "control_status": item.get("control_status"),
                    "candidate_status": item.get("candidate_status"),
                    "control_response_sha256": item.get(
                        "control_response_sha256"
                    ),
                    "candidate_response_sha256": item.get(
                        "candidate_response_sha256"
                    ),
                    "proof_contract": item.get("proof_contract"),
                    "proof_status": proof_status,
                    "canonical_capability": result.capability_name,
                    "capability_receipt": receipt,
                },
            )
            finding.update({
                "verified": False,
                "suspected": True,
                "needs_verification": True,
                "proof_state": "likely_vulnerable",
                "verification_reason": (
                    "Request mutation differential requires execution proof"
                    if expected_family == "xss"
                    else "Request mutation produced a candidate-only database error"
                ),
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
                    "canonical_capability": result.capability_name,
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
            kind == "sqli_proof"
            and item.get("proof_state") == "verified"
            and item.get("finding_verdict") == "verified"
            and str(item.get("proof_contract") or "").startswith("sqli_")
            and int(item.get("repetitions") or 0) >= 2
        ):
            auth_bypass = item.get("proof_contract") == "sqli_authentication_bypass/v1"
            finding = _base_finding(
                tool="shakerscan_sqli_proof",
                title=(
                    "Verified SQL injection authentication bypass"
                    if auth_bypass else "Verified SQL injection"
                ),
                # A proven SQL injection is critical whether or not it also
                # bypasses authentication: the proof is a repeated differential
                # carrying a database error signature, which means the parameter
                # reaches the query engine. Rating that "high" understated the
                # most severe class this scanner can prove deterministically.
                severity="critical",
                cwe="CWE-89",
                # The value-free route the proof actually exercised. A verified
                # injection with no location is not actionable for an operator,
                # and cannot be attributed to the endpoint it was proved on.
                url=item.get("canonical_path"),
                evidence={
                    "candidate_id": item.get("candidate_id"),
                    "request_ref_id": item.get("request_ref_id"),
                    "method": item.get("method"),
                    "field_path": item.get("field_path"),
                    "request_class": item.get("request_class"),
                    "proof_contract": item.get("proof_contract"),
                    "technique": item.get("technique"),
                    "repetitions": item.get("repetitions"),
                    "response_pairs": list(item.get("response_pairs") or ()),
                    "database_error_signatures": list(
                        item.get("database_error_signatures") or ()
                    ),
                    "redacted_excerpt": item.get("redacted_excerpt"),
                    "session_state_discarded": item.get(
                        "session_state_discarded"
                    ),
                    "canonical_capability": result.capability_name,
                    "capability_receipt": receipt,
                    "proof_producer": "shakerscan",
                    "evidence_type": "deterministic_differential",
                },
            )
            finding.update({
                "verified": True,
                "suspected": False,
                "needs_verification": False,
                "proof_state": "verified",
                "verification_reason": (
                    "Repeated deterministic SQL injection differential satisfied"
                ),
            })
            findings.append(finding)
        elif (
            kind == "sensitive_exposure_proof"
            and item.get("proof_state") == "verified"
            and item.get("finding_verdict") == "verified"
            and str(item.get("exposure_class") or "")
            and item.get("response_status") == 200
            and str(item.get("response_body_sha256") or "")
        ):
            severity = str(item.get("severity") or "medium")
            if severity not in {"critical", "high", "medium", "low"}:
                severity = "medium"
            exposure_class = str(item.get("exposure_class"))
            secret_material = exposure_class in {
                "private_key_material", "cloud_credential_material",
                "environment_secret_file",
            }
            finding = _base_finding(
                tool="shakerscan_exposure_probe",
                title=f"Sensitive exposure: {exposure_class.replace('_', ' ')}",
                severity=severity,
                cwe="CWE-538" if secret_material else "CWE-200",
                url=item.get("request_url"),
                evidence={
                    "exposure_class": exposure_class,
                    "request_url": item.get("request_url"),
                    "response_status": item.get("response_status"),
                    "content_type": item.get("content_type"),
                    "response_body_sha256": item.get("response_body_sha256"),
                    "matched_signature": item.get("matched_signature"),
                    "redacted_excerpt": item.get("redacted_excerpt"),
                    "discovered_via": item.get("discovered_via"),
                    "canonical_capability": result.capability_name,
                    "capability_receipt": receipt,
                    "proof_producer": "shakerscan",
                    "evidence_type": "deterministic_response_signature",
                },
            )
            finding.update({
                "verified": True,
                "suspected": False,
                "needs_verification": False,
                "proof_state": "verified",
                "verification_reason": (
                    "Deterministic sensitive-exposure response signature satisfied"
                ),
            })
            findings.append(finding)
        elif (
            kind == "nosqli_proof"
            and item.get("proof_state") == "verified"
            and item.get("finding_verdict") == "verified"
            and str(item.get("proof_contract") or "").startswith("nosqli_")
            and int(item.get("repetitions") or 0) >= 2
        ):
            auth_bypass = item.get("technique") == "operator_auth_bypass_repeated"
            finding = _base_finding(
                tool="shakerscan_nosqli_verify",
                title=(
                    "Verified NoSQL injection authentication bypass"
                    if auth_bypass else "Verified NoSQL injection"
                ),
                severity="critical" if auth_bypass else "high",
                cwe="CWE-943",
                # Same as the SQL proof: report the route it was proved on.
                url=item.get("canonical_path"),
                evidence={
                    "candidate_id": item.get("candidate_id"),
                    "request_ref_id": item.get("request_ref_id"),
                    "method": item.get("method"),
                    "field_path": item.get("field_path"),
                    "request_class": item.get("request_class"),
                    "proof_contract": item.get("proof_contract"),
                    "technique": item.get("technique"),
                    "operator": item.get("operator"),
                    "repetitions": item.get("repetitions"),
                    "response_pairs": list(item.get("response_pairs") or ()),
                    "session_state_discarded": item.get("session_state_discarded"),
                    "canonical_capability": result.capability_name,
                    "capability_receipt": receipt,
                    "proof_producer": "shakerscan",
                    "evidence_type": "deterministic_operator_differential",
                },
            )
            finding.update({
                "verified": True,
                "suspected": False,
                "needs_verification": False,
                "proof_state": "verified",
                "verification_reason": (
                    "Repeated deterministic NoSQL operator differential satisfied"
                ),
            })
            findings.append(finding)
        elif (
            kind == "authz_surface_proof"
            and item.get("proof_state") == "verified"
            and item.get("finding_verdict") == "verified"
            and str(item.get("proof_contract") or "").startswith("authz_surface_")
            and item.get("boundary_established") is True
            and str(item.get("request_url") or "")
            and int(item.get("repetitions") or 0) >= 2
        ):
            # What was actually observed is that the endpoint returns the same
            # data with and without credentials. On a privileged function that
            # is broken access control; on a public one -- a product search, a
            # list of security questions -- it is the intended behaviour, and
            # nothing in the differential distinguishes the two. Claiming a
            # verified authorization break here marked ordinary public
            # endpoints as high-severity findings.
            finding = _base_finding(
                tool="shakerscan_authz_surface",
                title="Endpoint serves identical data to anonymous and authenticated principals",
                severity="medium",
                cwe="CWE-862",
                url=item.get("request_url"),
                evidence={
                    "route_id": item.get("route_id"),
                    "request_url": item.get("request_url"),
                    "technique": item.get("technique"),
                    "proof_contract": item.get("proof_contract"),
                    "anonymous_status": item.get("anonymous_status"),
                    "authenticated_status": item.get("authenticated_status"),
                    "response_body_sha256": item.get("response_body_sha256"),
                    "boundary_established": item.get("boundary_established"),
                    "repetitions": item.get("repetitions"),
                    "canonical_capability": result.capability_name,
                    "capability_receipt": receipt,
                    "proof_producer": "shakerscan",
                    "evidence_type": "principal_access_differential",
                },
            )
            finding.update({
                "verified": False,
                "suspected": True,
                "needs_verification": True,
                "proof_state": "likely_vulnerable",
                "verification_reason": (
                    "Anonymous access matched authenticated access, but nothing "
                    "establishes that this particular function is privileged"
                ),
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
                    "canonical_capability": result.capability_name,
                    "capability_receipt": receipt,
                },
            )
            finding.update({
                "verified": False,
                "suspected": True,
                # A template match is candidate evidence at every severity.
                # Severity controls prioritization, not whether the proof
                # contract still needs to be satisfied.
                "needs_verification": True,
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


def _http_origin(value: Any) -> str | None:
    """Return a content-free HTTP origin suitable for scope revalidation."""
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        scheme = parsed.scheme.lower()
        host = str(parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except ValueError:
        return None
    if scheme not in {"http", "https"} or not host:
        return None
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    authority = display_host if port in (None, default_port) else f"{display_host}:{port}"
    return urllib.parse.urlunsplit((scheme, authority, "", "", ""))


def _runtime_destinations(
    *,
    action_id: str,
    capability_name: str,
    observations: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Project content-free destination evidence from manifest-bound observations."""
    destinations: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for observation_index, raw in enumerate(observations):
        item = dict(raw)
        request = item.get("request") if isinstance(item.get("request"), Mapping) else {}
        response = item.get("response") if isinstance(item.get("response"), Mapping) else {}
        url_values: list[Any] = [
            request.get("origin"), request.get("url"), item.get("origin"),
            item.get("url"), item.get("request_url"), item.get("final_url"),
            item.get("matched_at"), item.get("consumer_url"),
            item.get("producer_url"), response.get("final_url"),
            response.get("location"),
        ]
        for hop in item.get("redirect_chain") or ():
            if isinstance(hop, Mapping):
                url_values.extend((hop.get("url"), hop.get("location"), hop.get("final_url")))
            else:
                url_values.append(hop)
        origins = list(dict.fromkeys(
            origin for value in url_values if (origin := _http_origin(value))
        ))
        if not origins:
            continue
        raw_ips: list[Any] = [
            request.get("pinned_address"), request.get("connected_address"),
            response.get("remote_ip"), item.get("pinned_address"),
            item.get("connected_address"), item.get("remote_ip"),
            item.get("host_ip"),
        ]
        if isinstance(item.get("resolved_ips"), (list, tuple)):
            raw_ips.extend(item["resolved_ips"])
        resolved_ips = tuple(dict.fromkeys(
            str(value).strip() for value in raw_ips if str(value or "").strip()
        ))
        for origin_index, origin in enumerate(origins):
            key = (origin, resolved_ips)
            if key in seen:
                continue
            seen.add(key)
            destination = {
                "label": f"{action_id}:{observation_index}:{origin_index}",
                "url": origin,
                "final_url": origin,
                "source": capability_name,
                "resolved_host": urllib.parse.urlsplit(origin).hostname,
                "resolved_ips": list(resolved_ips),
            }
            destinations.append(destination)
    return destinations


def _score(findings: Sequence[Mapping[str, Any]]) -> tuple[int, str]:
    """Score a scan so the worst thing found sets the ceiling and the count moves it within.

    Subtracting a weight per finding from 100 made severity a dent rather than a verdict: one
    proven critical injection scored 80 and graded B, one high scored 90 and graded A. On a
    deliberately vulnerable application that produced pages of A grades beside proven injections.
    A security grade has to answer "how bad is the worst thing here", so severity caps the score
    and the subtractive weight then differentiates within that cap.
    """
    severities = [str(item.get("severity") or "info").strip().lower() for item in findings]
    score = max(0, 100 - sum(_SEVERITY_WEIGHT.get(name, 0) for name in severities))
    ceiling = min(
        (_SEVERITY_SCORE_CEILING[name] for name in severities if name in _SEVERITY_SCORE_CEILING),
        default=100,
    )
    score = min(score, ceiling)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return score, grade


# The report contract the UI and AGENTS.md both name, mapped from the header the
# capability actually captured.
_UI_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("hsts", "strict-transport-security"),
    ("x_frame_options", "x-frame-options"),
    ("x_content_type_options", "x-content-type-options"),
    ("referrer_policy", "referrer-policy"),
    ("permissions_policy", "permissions-policy"),
    ("coop", "cross-origin-opener-policy"),
    ("corp", "cross-origin-resource-policy"),
    ("coep", "cross-origin-embedder-policy"),
    ("csp", "content-security-policy"),
)


def _common_name(distinguished_name: Any) -> str | None:
    """Return the CN from an RFC 4514 DN, or None when there is none to read."""
    for part in str(distinguished_name or "").split(","):
        name, sep, value = part.partition("=")
        if sep and name.strip().upper() == "CN" and value.strip():
            return value.strip()
    return None


def _certificate_section(row: Mapping[str, Any]) -> dict[str, Any]:
    """Gather the flat `certificate_*` observation fields into the documented shape.

    The observation names its fields for the X.509 structure it read; the report names
    them for the reader (`key_size`, `key_algo`, `sig_algo`). Both are kept: the
    documented names so the report renders, and the source names so nothing is lost.
    """
    flat = {
        key[len("certificate_"):]: value
        for key, value in row.items()
        if key.startswith("certificate_") and value is not None
    }
    if not flat:
        return {}
    dns_names = [str(name) for name in flat.get("dns_names") or ()]
    certificate = dict(flat)
    certificate["subject_dn"] = flat.get("subject")
    certificate["subject"] = _common_name(flat.get("subject")) or flat.get("subject")
    if flat.get("public_key_bits") is not None:
        certificate["key_size"] = flat["public_key_bits"]
    if flat.get("public_key_type") is not None:
        certificate["key_algo"] = flat["public_key_type"]
    if flat.get("signature_algorithm") is not None:
        certificate["sig_algo"] = flat.get("signature_hash") or flat["signature_algorithm"]
    if flat.get("serial_hex") is not None:
        certificate["serial"] = flat["serial_hex"]
    if flat.get("sha256"):
        certificate["fingerprints"] = {"sha256": flat["sha256"]}
    if dns_names:
        # Published under both names: `dns_names` is what the observation calls it and
        # `sans` is what the report contract and the UI read. Emitting only the former
        # meant the SAN list was collected and never displayed.
        certificate["sans"] = list(dns_names)
        certificate["wildcard"] = any(name.startswith("*.") for name in dns_names)
    return certificate


def _dns_section(row: Mapping[str, Any]) -> dict[str, Any]:
    """Project a DNS posture observation into the documented per-record-type shape.

    A query that timed out is reported as a timeout, never as "not configured": the
    two look identical in an empty record list and only one of them is a finding.
    """
    records = row.get("records") if isinstance(row.get("records"), Mapping) else {}
    addresses = row.get("bound_addresses") if isinstance(row.get("bound_addresses"), Mapping) else {}
    failed = {
        str(item).split(":", 1)[0]
        for item in row.get("errors") or ()
        if ":" in str(item)
    }

    def answered(name: str) -> list[Any]:
        return [item for item in records.get(name) or () if item not in (None, "")]

    section: dict[str, Any] = {
        "records": dict(records),
        "bound_addresses": dict(addresses),
        "query_count": row.get("query_count"),
        "errors": list(row.get("errors") or ()),
    }
    if addresses.get("A"):
        section["a"] = list(addresses["A"])
    if addresses.get("AAAA"):
        section["aaaa"] = list(addresses["AAAA"])
    if answered("host_mx"):
        section["mx"] = answered("host_mx")
    if answered("host_caa"):
        section["caa"] = answered("host_caa")
    spf = next(
        (str(item) for item in answered("host_txt") if str(item).lower().startswith("v=spf1")),
        None,
    )
    if spf:
        section["spf"] = spf
    if answered("dmarc"):
        section["dmarc"] = {"record": str(answered("dmarc")[0])}
    if "host_dnskey" in failed:
        section["dnssec"] = {"status": "timeout"}
    elif "host_dnskey" in records:
        section["dnssec"] = {"status": "secure" if answered("host_dnskey") else "unsigned"}
    for key, query in (("mta_sts", "mta_sts"), ("tls_rpt", "tls_rpt")):
        if query in failed:
            continue
        if query in records:
            section[key] = {"enabled": bool(answered(query))}
    return section


def _posture_sections(
    observations: Mapping[str, Sequence[Mapping[str, Any]]],
) -> dict[str, Any]:
    """Project the recon observations into the documented report posture sections.

    The V2 report carried only score and grade, so `result.tls.certificate`,
    `result.http.security_headers`, `result.dns` and `result.discovery.tech` -- all documented in
    AGENTS.md and all present in 0.8.18 -- silently disappeared. The data was never lost: the
    baseline HTTP, TLS, DNS and probe actions all record it. It was simply never projected. This
    reads what those actions already produced; it performs no network, filesystem or clock access,
    exactly like the rest of finalization.
    """
    http_section: dict[str, Any] = {}
    tls_section: dict[str, Any] = {}
    dns_section: dict[str, Any] = {}
    technologies: list[dict[str, Any]] = []
    server_versions: dict[str, Any] = {}
    seen_tech: set[str] = set()

    for action_id, rows in observations.items():
        for row in rows or ():
            if not isinstance(row, Mapping):
                continue
            kind = str(row.get("kind") or "")
            if kind == "http_observation" and str(action_id) == "baseline.http":
                response = row.get("response") if isinstance(row.get("response"), Mapping) else {}
                headers = (
                    response.get("security_headers")
                    if isinstance(response.get("security_headers"), Mapping) else {}
                )
                # A request that never completed observed nothing. Reporting its empty
                # header set as `missing_security_headers` published five confirmed
                # findings from a failure -- the UI renders each one red -- so posture is
                # published only behind an observed status. Absent is not failing; that
                # rule already governed the TLS and CSP sections and this one skipped it.
                if response.get("status") in (None, ""):
                    continue
                http_section = {
                    "status": response.get("status"),
                    "security_headers": {
                        key: headers[header]
                        for key, header in _UI_SECURITY_HEADERS
                        if header in headers
                    },
                    "observed_headers": dict(headers),
                    "missing_security_headers": sorted(
                        name for name in _EXPECTED_SECURITY_HEADERS if name not in headers
                    ),
                    # Only a policy that exists gets graded: an absent CSP rendered as a
                    # scoring card reading "/100", which states nothing. Its absence is
                    # carried by the missing-header list instead.
                    **(
                        {"csp_evaluation": _evaluate_csp(headers["content-security-policy"])}
                        if headers.get("content-security-policy") else {}
                    ),
                    # The capability puts cookie posture in the response summary, so that
                    # is where it is read from; the observation root never carried it.
                    "set_cookie_metadata": list(response.get("set_cookie_metadata") or ()),
                }
            elif kind == "tls_protocol":
                candidate = {
                    key: row.get(key) for key in (
                        "protocol", "cipher", "cipher_bits", "weak_cipher",
                        "alpn_protocol", "origin", "port", "status",
                    ) if row.get(key) is not None
                }
                certificate = _certificate_section(row)
                if certificate:
                    candidate["certificate"] = certificate
                # A scan inspects several origins; keep the first successful handshake and let a
                # later one replace only an unsuccessful record.
                if candidate and (
                    not tls_section or (
                        str(tls_section.get("status")) != "success"
                        and str(candidate.get("status")) == "success"
                    )
                ):
                    tls_section = candidate
            elif kind == "dns_posture":
                dns_section = _dns_section(row)
            elif kind == "http_fingerprint":
                for item in row.get("technologies") or ():
                    name = str((item or {}).get("name") if isinstance(item, Mapping) else item)
                    if name and name not in seen_tech:
                        seen_tech.add(name)
                        technologies.append(
                            dict(item) if isinstance(item, Mapping)
                            # The probe observed this in the response; it assigns no
                            # numeric confidence, and inventing one would be a claim the
                            # scanner never made.
                            else {"name": name, "confidence_label": "observed"}
                        )
                if row.get("webserver"):
                    banner = str(row["webserver"])
                    server_versions[str(row.get("url") or "server")] = banner
                    if banner not in seen_tech:
                        seen_tech.add(banner)
                        technologies.append({
                            "name": banner, "source": "webserver",
                            "confidence_label": "observed",
                        })

    sections: dict[str, Any] = {}
    if http_section:
        sections["http"] = http_section
    if tls_section:
        sections["tls"] = tls_section
    if dns_section:
        sections["dns"] = dns_section
    if technologies or server_versions:
        discovery: dict[str, Any] = {}
        if technologies:
            discovery["tech"] = {"items": technologies}
        if server_versions:
            discovery["server_versions"] = server_versions
        sections["discovery"] = discovery
    return sections


def _evaluate_csp(policy: Any) -> dict[str, Any]:
    """Grade a Content-Security-Policy without network or clock access.

    Absent is reported as absent rather than as a failing grade: the two are different findings and
    conflating them makes a site with no policy look like one with a broken policy.
    """
    text = str(policy or "").strip()
    if not text:
        return {"present": False, "grade": None, "score": None, "issues": []}
    lowered = text.lower()
    directives = {
        part.split()[0]: part.split()[1:]
        for part in (item.strip() for item in lowered.split(";")) if part
    }
    issues: list[str] = []
    if "'unsafe-inline'" in lowered:
        issues.append("script-src allows 'unsafe-inline'")
    if "'unsafe-eval'" in lowered:
        issues.append("script-src allows 'unsafe-eval'")
    if "default-src" not in directives and "script-src" not in directives:
        issues.append("no default-src or script-src directive")
    if any("*" == value for values in directives.values() for value in values):
        issues.append("a directive allows any origin")
    if "object-src" not in directives and "default-src" not in directives:
        issues.append("no object-src or default-src directive")
    score = max(0, 100 - 20 * len(issues))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return {
        "present": True,
        "grade": grade,
        "score": score,
        "issues": issues,
        "directives": {name: list(values) for name, values in directives.items()},
    }


def finalize_scan_report(
    *,
    plan: ScanActionPlan,
    target_url: str,
    action_results: Mapping[str, CapabilityResultReference],
    observations: Mapping[str, Sequence[Mapping[str, Any]]],
    work_manifest_references: Sequence[Mapping[str, Any]] = (),
    plan_revision: ScanPlanRevision | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the final report without network, process, filesystem, or clock access."""
    try:
        revision = (
            plan_revision
            if isinstance(plan_revision, ScanPlanRevision)
            else ScanPlanRevision.from_dict(plan_revision)
            if isinstance(plan_revision, Mapping)
            else root_scan_plan_revision(plan)
        )
    except (ScanContinuationError, TypeError, ValueError) as exc:
        raise ScanFinalizationError("plan revision is invalid") from exc
    if revision.scan_id != plan.scan_id or revision.plan_digest != plan.plan_digest:
        raise ScanFinalizationError("plan revision differs from finalization plan")
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
    runtime_destinations: list[dict[str, Any]] = []
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
        runtime_destinations.extend(_runtime_destinations(
            action_id=action.action_id,
            capability_name=action.capability_name,
            observations=rows,
        ))
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

    # Family-aware coverage: every selected family (one that produced a batch or
    # verifier action) is reported with attempts, findings, budget, and a status.
    # A selected family that attempted nothing while candidates existed, or whose
    # required action did not complete, makes the grade unreliable — a scan can no
    # longer report a reliable grade while a chosen family did no work.
    family_coverage: dict[str, dict[str, Any]] = {}
    for action in expected_actions:
        family = _FAMILY_BY_CAPABILITY.get(action.capability_name)
        if family is None:
            continue
        result = action_results[action.action_id]
        raw_slice = action.capability_args.get("slice")
        planned = (
            int(raw_slice.get("count") or 0)
            if isinstance(raw_slice, Mapping) else 0
        )
        attempts = {
            str(item.get("attempt_id") or "")
            for item in observations.get(action.action_id, ())
            if isinstance(item, Mapping)
            and item.get("kind") == "candidate_attempt"
            and str(item.get("attempt_id") or "")
        }
        row = family_coverage.setdefault(family, {
            "family": family, "selected": True, "required": False,
            "batch_actions": 0, "planned_candidates": 0, "attempted_candidates": 0,
            "verified_findings": 0, "suspected_findings": 0,
            "budget_reserved": {}, "budget_consumed": {}, "_statuses": [],
            # Per-capability manifest size vs what the plan actually scheduled. A capability whose
            # manifest holds more entries than its slices cover has work that was never attempted,
            # and comparing attempts with slices alone reports that as complete coverage.
            "_manifest_entries": {}, "_scheduled_entries": {},
            "proof_escalation": {
                "actions": 0, "attempted_candidates": 0,
                "_statuses": [], "_reasons": [],
            },
        })
        row["required"] = row["required"] or bool(action.required)
        if action.capability_name in _PROOF_CAPABILITIES:
            # Escalation over candidates the verifier already counted: record it
            # separately so it can neither double-count nor fail its family.
            proof = row["proof_escalation"]
            proof["actions"] += 1
            proof["attempted_candidates"] += len(attempts)
            proof["_statuses"].append(result.status.value)
            if result.reason_code is not None:
                proof["_reasons"].append(result.reason_code.value)
        else:
            row["batch_actions"] += 1
            row["planned_candidates"] += planned
            row["attempted_candidates"] += len(attempts)
            row["_statuses"].append(result.status.value)
            declared = action.capability_args.get("manifest_entries")
            if isinstance(declared, int) and not isinstance(declared, bool) and declared >= 0:
                # Every slice of one capability declares the same manifest size.
                row["_manifest_entries"][action.capability_name] = max(
                    int(row["_manifest_entries"].get(action.capability_name, 0)), declared,
                )
            row["_scheduled_entries"][action.capability_name] = (
                int(row["_scheduled_entries"].get(action.capability_name, 0)) + planned
            )
        # Budget is real spend either way and stays aggregated for the family.
        for name, amount in result.budget_reserved.items():
            row["budget_reserved"][name] = row["budget_reserved"].get(name, 0) + int(amount)
        for name, amount in result.budget_consumed.items():
            row["budget_consumed"][name] = row["budget_consumed"].get(name, 0) + int(amount)
    for finding in findings:
        capability = str(
            (finding.get("evidence") or {}).get("canonical_capability") or ""
        )
        family = _FAMILY_BY_CAPABILITY.get(capability)
        row = family_coverage.get(family) if family else None
        if row is None:
            continue
        if finding.get("verified") is True:
            row["verified_findings"] += 1
        elif finding.get("suspected") is True:
            row["suspected_findings"] += 1
    selected_family_gaps: list[str] = []
    for family, row in family_coverage.items():
        statuses = row.pop("_statuses")
        proof = row["proof_escalation"]
        proof_statuses = proof.pop("_statuses")
        proof_reasons = proof.pop("_reasons")
        if not proof_statuses:
            # The family planned no escalation at all.
            proof["status"] = "not_planned"
            proof["reason"] = None
        elif all(status == "success" for status in proof_statuses):
            proof["status"] = "complete"
            proof["reason"] = None
        elif any(status == "partial" for status in proof_statuses):
            proof["status"] = "partial"
            proof["reason"] = (sorted(set(proof_reasons)) or ["proof_incomplete"])[0]
        elif all(
            status == "skipped" and reason == "not_applicable"
            for status, reason in zip(proof_statuses, proof_reasons or proof_statuses)
        ):
            # Nothing was eligible to escalate. That is a clean outcome for the
            # escalation and says nothing about whether the family ran.
            proof["status"] = "not_applicable"
            proof["reason"] = "no_proof_eligible_candidate"
        elif all(
            status == "skipped" and reason in _PROOF_UNAVAILABLE_REASONS
            for status, reason in zip(proof_statuses, proof_reasons or proof_statuses)
        ):
            # The escalation could not be placed or funded -- an endpoint shard
            # carries no browser budget, for instance. That is a real limit on
            # what was proved and must be stated, but it is not a failure of the
            # verifier and not evidence that the family did not run.
            proof["status"] = "unavailable"
            proof["reason"] = (sorted(set(proof_reasons)) or ["proof_unavailable"])[0]
        else:
            proof["status"] = "failed"
            proof["reason"] = (sorted(set(proof_reasons)) or ["proof_incomplete"])[0]
        row["unattempted_candidates"] = max(
            0, row["planned_candidates"] - row["attempted_candidates"],
        )
        # Manifest entries the plan never scheduled at all. These never became a slice, so they
        # cannot appear in unattempted_candidates, and a family carrying them has not covered its
        # surface however cleanly its scheduled slices ran.
        manifest_entries = row.pop("_manifest_entries", {}) or {}
        scheduled_entries = row.pop("_scheduled_entries", {}) or {}
        row["manifest_candidates"] = sum(int(value) for value in manifest_entries.values())
        row["unscheduled_candidates"] = sum(
            max(0, int(total) - int(scheduled_entries.get(capability, 0)))
            for capability, total in manifest_entries.items()
        )
        action_incomplete = any(status != "success" for status in statuses)
        zero_attempts = (
            row["planned_candidates"] > 0 and row["attempted_candidates"] == 0
        )
        if row["batch_actions"] == 0:
            # Only escalation was planned for this family, so nothing established
            # its execution coverage. Reporting it complete would overstate work
            # that never ran.
            row["coverage_status"] = "partial"
            row["reason"] = "no_verifier_action"
            if row["required"]:
                selected_family_gaps.append(family)
        elif action_incomplete or zero_attempts:
            row["coverage_status"] = "partial"
            row["reason"] = "zero_attempts" if zero_attempts else "action_incomplete"
            if row["required"]:
                selected_family_gaps.append(family)
        elif row["unscheduled_candidates"] > 0:
            row["coverage_status"] = "partial"
            row["reason"] = "manifest_entries_unscheduled"
            # A REQUIRED family that left work unscheduled has not covered its surface, so the
            # grade computed over it is not reliable. Marking the family partial while leaving the
            # top-level rollup clean reported `coverage: complete` and `grade_reliable: true` over
            # a plan that ran a fraction of its manifest.
            if row["required"]:
                selected_family_gaps.append(family)
        elif row["unattempted_candidates"] > 0:
            row["coverage_status"] = "partial"
            row["reason"] = "candidates_unattempted"
            if row["required"]:
                selected_family_gaps.append(family)
        else:
            row["coverage_status"] = "complete"
            row["reason"] = None
    selected_family_gaps.sort()

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
      | ({"selected_family_incomplete"} if selected_family_gaps else set())
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
    principal_contexts = sorted({
        str(item.get("lane"))
        for rows in observations.values()
        for item in rows
        if isinstance(item, Mapping)
        and item.get("kind") == "principal_context"
        and item.get("authenticated") is True
        and item.get("source") == "server_runtime"
        and str(item.get("lane")) in {"primary", "secondary"}
    })
    auth_states_tested = [
        {"primary": "user1", "secondary": "user2"}[lane]
        for lane in principal_contexts
    ]
    batch_families = {
        "xss.verify_batch": "xss",
        "sqli.verify_batch": "sqli",
        "templates.passive_batch": "nuclei_passive",
        "templates.active_batch": "nuclei_active",
        "xss.request_verify_batch": "xss_body",
        "sqli.request_verify_batch": "sqli_body",
        "sqli.prove_batch": "sqli_proof",
        "xss.browser_prove_batch": "xss_browser_proof",
        "exposure.verify_batch": "sensitive_exposure",
        "nosqli.verify_batch": "nosqli",
        "authz_surface.verify_batch": "authz_surface",
    }
    candidate_coverage: dict[str, dict[str, Any]] = {}
    for action in expected_actions:
        family = batch_families.get(action.capability_name)
        if family is None:
            continue
        raw_slice = action.capability_args.get("slice")
        planned = (
            int(raw_slice.get("count") or 0)
            if isinstance(raw_slice, Mapping) else 0
        )
        attempt_rows = {
            str(item.get("attempt_id") or ""): str(item.get("status") or "").lower()
            for item in observations.get(action.action_id, ())
            if isinstance(item, Mapping)
            and item.get("kind") == "candidate_attempt"
            and str(item.get("attempt_id") or "")
        }
        completed = {
            attempt_id for attempt_id, status in attempt_rows.items()
            if status in {"success", "succeeded", "completed"}
        }
        failed_attempts = {
            attempt_id for attempt_id, status in attempt_rows.items()
            if status not in {"success", "succeeded", "completed"}
        }
        row = candidate_coverage.setdefault(family, {
            "planned_candidates": 0,
            "attempted_candidates": 0,
            "completed_candidates": 0,
            "incomplete_candidates": 0,
            "unattempted_candidates": 0,
            "batch_actions": 0,
            "status": "complete",
        })
        row["planned_candidates"] += planned
        row["attempted_candidates"] += len(attempt_rows)
        row["completed_candidates"] += len(completed)
        row["incomplete_candidates"] += len(failed_attempts)
        row["batch_actions"] += 1
    for row in candidate_coverage.values():
        row["unattempted_candidates"] = max(
            0, row["planned_candidates"] - row["attempted_candidates"],
        )
        if row["unattempted_candidates"] or row["incomplete_candidates"]:
            row["status"] = "partial"
    if zero_attempt_actions and coverage_status == "complete":
        coverage_status = "partial"
    verified = sum(1 for item in findings if item.get("verified") is True)
    suspected = sum(1 for item in findings if item.get("suspected") is True)
    report = {
        "schema_version": SCAN_REPORT_SCHEMA,
        "target": str(target_url),
        "runtime_destinations": runtime_destinations,
        "findings": findings,
        "result": {
            "score": score,
            "grade": rendered_grade,
            "grade_reliable": grade_reliable,
            "score_policy": "verified_and_suspected_severity_ceiling/v2",
        },
        # Posture belongs on the envelope, not inside the nested "result": the stored
        # `result_json` IS what a client reads as `scan.result`, so a section nested one
        # level deeper is documented as `result.tls` and served as `result.result.tls`.
        **_posture_sections(observations),
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
            "candidate_coverage": candidate_coverage,
            "family_coverage": sorted(
                family_coverage.values(), key=lambda row: row["family"],
            ),
            "selected_family_gaps": selected_family_gaps,
        },
        "verification_summary": {
            "verified": verified,
            "suspected": suspected,
            "unproven_critical_high": unproven_critical_high,
        },
        "smart_coverage": {
            "auth_states_tested": auth_states_tested,
            "principal_contexts_exercised": principal_contexts,
            "principal_context_semantics": (
                "server_observed_authenticated_target_traffic"
            ),
        },
        "canonical_action_execution": {
            "schema_version": "canonical-scan-action-execution/v1",
            "plan_digest": plan.plan_digest,
            "execution_plan_digest": plan.execution_plan_digest,
            "target_binding_digest": plan.target_binding_digest,
            "plan_revision": revision.canonical_dict(),
            "actions": action_rows,
            "status_matrix": {
                **{
                    row["action_id"]: row["status"] for row in action_rows
                },
                finalization_action.action_id: "success",
            },
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
    report["report_digest"] = hashlib.sha256(json.dumps(
        report,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")).hexdigest()
    return report
