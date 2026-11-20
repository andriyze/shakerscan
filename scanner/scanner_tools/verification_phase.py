"""
Verification Phase - Proof of Exploitation for High-Severity Findings

This module implements Phase V of the smart scan workflow: verification
and reproduction of detected vulnerabilities before reporting them as
confirmed High/Critical findings.

Philosophy: "No High/Critical finding without reproducible evidence"

Verification Types:
- XSS: Browser execution proof (dialog/console/DOM)
- SQLi (blind): Statistical timing proof with multiple samples
- SQLi (error-based): Data extraction proof
- BOLA: Differential authorization proof
- SSRF: OOB callback proof (if callback server available)
"""

import sys
from typing import Any


SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _normalize_min_severity(value: str | None, default: str = "high") -> str:
    severity = str(value or "").strip().lower()
    if severity in SEVERITY_ORDER:
        return severity
    return default


def _mark_verification_skipped(finding: dict, reason: str) -> dict:
    finding = dict(finding)
    finding["verification_attempted"] = False
    finding["verification_skipped"] = True
    finding["verification_reason"] = reason
    evidence = finding.get("evidence", [])
    if isinstance(evidence, list):
        evidence.append(f"Verification skipped: {reason}")
    finding["evidence"] = evidence
    return finding


async def verify_high_severity_findings(
    findings: list[dict],
    auth_session: Any | None = None,
    verify_xss: bool = True,
    verify_sqli: bool = True,
    max_verification_attempts: int = 3,
    min_severity: str = "high",
    include_summary: bool = False,
    max_findings: int | None = None,
) -> list[dict] | tuple[list[dict], dict]:
    """
    Attempt to verify findings at/above the configured severity before final report.

    Findings that cannot be verified are downgraded where supported and:
    - Marked with verification_attempted=True

    Findings that are verified are:
    - Marked with verified=True
    - Given higher confidence scores

    Args:
        findings: List of finding dicts from active testing
        auth_session: AuthSession for authenticated requests
        verify_xss: Whether to verify XSS findings with browser proof
        verify_sqli: Whether to verify SQLi findings with statistical timing
        max_verification_attempts: Max verification attempts per finding
        min_severity: Lowest severity eligible for verification (critical/high/medium/low/info)

    Returns:
        List of findings with verification status and adjusted severity/confidence.
        If include_summary=True, returns (findings, summary_dict).
    """
    # Import verification tools (with graceful degradation)
    provers: dict[str, Any] = {}
    legacy_prove_xss_headless = None
    try:
        from . import proof_of_exploit as _proof_module
    except ImportError:
        _proof_module = None

    if _proof_module is not None:
        legacy_prove_xss_headless = getattr(_proof_module, "prove_xss_headless", None)
        prover_names = (
            "prove_xss",
            "prove_xss_headless",
            "prove_sqli",
            "prove_ssrf",
            "prove_ssrf_oob",
            "prove_path_traversal",
            "prove_open_redirect",
            "prove_cors",
            "prove_command_injection",
            "prove_ssti",
            "prove_xxe",
            "prove_jwt",
            "prove_bola",
            "prove_exposed_file",
            "prove_nosqli",
        )
        for name in prover_names:
            fn = getattr(_proof_module, name, None)
            if callable(fn):
                provers[name] = fn

    from .verification_engine import (
        verify_finding as _engine_verify,
        normalize_finding_type,
        get_ladder,
        downgrade_finding,
    )

    verified_findings = []
    normalized_min_severity = _normalize_min_severity(min_severity, default="high")
    min_rank = SEVERITY_ORDER[normalized_min_severity]
    eligible_count = 0
    attempted_count = 0
    skipped_count = 0
    # Bound how many findings get the EXPENSIVE per-finding proof (browser/timing)
    # at scan time. Without this, a large scan with many high/critical findings runs
    # verification for tens of minutes with no progress, and the finalize phase gets
    # reaped as stale (losing all results). Deferred findings keep suspected/
    # needs_verification status and are picked up by the worker's async auto-retest.
    verify_budget_used = 0

    # When a scan-time verification budget (max_findings) applies, verify the
    # high-value families first so noisy findings can't consume the budget before
    # SQLi/XSS/BOLA/SSRF get proofed. Stable sort; below-threshold findings keep
    # their relative order and aren't affected (they're passed through unverified).
    if max_findings is not None:
        _VERIFY_FAMILY_RANK = {"sqli": 0, "bola": 0, "idor": 0, "ssrf": 1, "xss": 1,
                               "command_injection": 1, "rce": 1, "xxe": 1,
                               "path_traversal": 2, "open_redirect": 3}
        def _verify_priority(f: dict) -> int:
            t = normalize_finding_type(str(f.get("type", "")).lower()) or ""
            if t in _VERIFY_FAMILY_RANK:
                return _VERIFY_FAMILY_RANK[t]
            hay = (str(f.get("title", "")) + " " + str(f.get("tool", ""))).lower()
            for kw, rank in (("bola", 0), ("idor", 0), ("object authorization", 0),
                             ("sql", 0), ("xss", 1), ("ssrf", 1)):
                if kw in hay:
                    return rank
            return 5
        findings = sorted(findings, key=_verify_priority)

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        vuln_type = finding.get("type", "").lower()

        # Verify findings at or above configured severity threshold.
        if SEVERITY_ORDER.get(severity, 0) < min_rank:
            verified_findings.append(finding)
            continue

        eligible_count += 1

        # Skip if already verified
        if finding.get("verified"):
            if finding.get("verification_attempted"):
                attempted_count += 1
            if finding.get("verification_skipped"):
                skipped_count += 1
            verified_findings.append(finding)
            continue

        # Determine finding type and attempt ladder via shared engine
        finding_type = normalize_finding_type(vuln_type)
        if not finding_type:
            # Try to infer from title / tool
            title = str(finding.get("title", "")).lower()
            tool = str(finding.get("tool", "")).lower()
            for probe, ft in [
                # NoSQL + BFLA MUST come before the generic sqli/bola checks: "sql
                # injection" is a substring of "nosql injection", and BFLA titles
                # don't contain "bola". First match wins.
                ("nosql", "nosqli"), ("no sql", "nosqli"),
                ("broken function level", "bola"), ("broken access control", "bola"),
                ("function level authorization", "bola"), ("bfla", "bola"),
                ("xss", "xss"), ("cross-site scripting", "xss"),
                ("sqli", "sqli"), ("sql injection", "sqli"), ("sql-injection", "sqli"),
                ("ssrf", "ssrf"), ("server-side request forgery", "ssrf"),
                ("path traversal", "path_traversal"), ("lfi", "path_traversal"),
                ("open redirect", "open_redirect"),
                ("cors", "cors"),
                ("command injection", "command_injection"), ("rce", "command_injection"),
                ("ssti", "ssti"), ("template injection", "ssti"),
                ("broken object level", "bola"), ("bola", "bola"),
                # Exposed-file harvest ("Sensitive file exposed: X") + forced
                # browsing, so unproven exposures downgrade instead of lingering
                # as unverified highs. Primary route is finding["type"], this is
                # the title/tool fallback.
                ("file exposed", "exposed_file"), ("exposed file", "exposed_file"),
                ("exposed_file", "exposed_file"), ("forced_browsing", "exposed_file"),
            ]:
                if probe in title or probe in tool:
                    finding_type = ft
                    break

        ladder = get_ladder(finding_type) if finding_type else []

        if finding_type == "xss" and not verify_xss:
            verified_findings.append(finding)
            continue
        if finding_type == "sqli" and not verify_sqli:
            verified_findings.append(finding)
            continue

        # Scan-time verification budget: spend it ONLY on findings that will actually
        # attempt an expensive proof (a known finding_type with a prover ladder).
        # Untyped/no-prover findings don't consume budget, so noisy high/critical
        # signals can't starve SQLi/XSS/BOLA proofs. Once exhausted, defer the rest
        # (kept suspected + needs_verification for the worker's async auto-retest).
        if finding_type and max_findings is not None:
            if verify_budget_used >= max_findings:
                finding["needs_verification"] = True
                finding["suspected"] = True
                finding["verification_skipped"] = True
                finding.setdefault("verification_reason", "scan_verification_budget_exhausted")
                skipped_count += 1
                verified_findings.append(finding)
                continue
            verify_budget_used += 1

        if finding_type == "sqli":
            try:
                from .finding_validator import validate_sqli

                validation = validate_sqli(finding)
                if validation.verified:
                    finding = dict(finding)
                    finding["verified"] = True
                    finding["verification_verdict"] = "exploited"
                    finding["confidence"] = max(
                        float(finding.get("confidence") or 0),
                        float(validation.confidence or 0),
                    )
                    if validation.evidence:
                        finding["verification_evidence"] = validation.evidence
                    verified_findings.append(finding)
                    continue
            except Exception as validate_err:
                # Surface SQLi validator failures rather than swallowing them.
                # Fall through to the regular verification path so downstream
                # provers still get a chance, but record the error so it is
                # visible in reports/logs.
                print(
                    f"[verification] SQLi validator error: {validate_err}",
                    file=sys.stderr,
                )
                finding = dict(finding)
                finding["verification_attempted"] = True
                finding["verification_error"] = (
                    f"sqli validator: {validate_err}"
                )

        if finding_type == "xss" and verify_xss:
            xss_prover = provers.get("prove_xss_headless") or legacy_prove_xss_headless
            if xss_prover is None:
                finding = _mark_verification_skipped(finding, "No XSS prover available")
            else:
                try:
                    finding = await _verify_xss_finding(
                        finding,
                        xss_prover,
                        max_attempts=max_verification_attempts,
                    )
                except Exception as legacy_err:
                    finding["verification_attempted"] = True
                    finding["verification_error"] = str(legacy_err)
                    if finding.get("severity") in ("high", "critical"):
                        finding = downgrade_finding(finding)
        elif finding_type and ladder and provers:
            # Use shared verification engine with attempt ladder
            url = str(finding.get("url") or finding.get("finding_url") or "")
            param = str(finding.get("param") or finding.get("parameter") or "")
            payload = str(finding.get("payload") or "")
            evidence_dict = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}

            try:
                result = await _engine_verify(
                    finding_type=finding_type,
                    ladder=ladder,
                    url=url,
                    param=param,
                    payload=payload or None,
                    evidence=evidence_dict,
                    skip_ai=True,
                    provers=provers,
                )

                finding["verification_attempted"] = True
                if result.proven:
                    finding["verified"] = True
                    finding["verification_verdict"] = "exploited"
                    if result.confidence is not None:
                        finding["confidence"] = result.confidence
                    if result.proof:
                        finding["poe"] = result.proof.to_dict() if hasattr(result.proof, "to_dict") else result.proof
                else:
                    # Unverified: downgrade severity
                    if finding.get("severity") in ("high", "critical"):
                        finding = downgrade_finding(finding)
            except Exception as eng_err:
                print(f"[verification] Engine error for {finding_type}: {eng_err}", file=sys.stderr)
                finding["verification_attempted"] = True
                finding["verification_error"] = str(eng_err)
                if finding.get("severity") in ("high", "critical"):
                    finding = downgrade_finding(finding)
        elif finding_type:
            # Supported type but no provers available — mark as skipped
            finding = _mark_verification_skipped(finding, f"No provers available for {finding_type}")

        if finding.get("verification_attempted"):
            attempted_count += 1
        if finding.get("verification_skipped"):
            skipped_count += 1
        verified_findings.append(finding)

    # Report verification stats
    verified_count = sum(1 for f in verified_findings if f.get("verified"))
    downgraded_count = sum(1 for f in verified_findings if f.get("verification_attempted") and not f.get("verified"))
    summary = {
        "min_severity": normalized_min_severity,
        "eligible_findings": eligible_count,
        "attempted": attempted_count,
        "verified": verified_count,
        "downgraded": downgraded_count,
        "skipped": skipped_count,
    }

    if verified_count > 0 or downgraded_count > 0:
        print(
            f"[verification] Verified {verified_count} findings, downgraded {downgraded_count} (scope: {normalized_min_severity}+)",
            file=sys.stderr
        )

    if include_summary:
        return verified_findings, summary

    return verified_findings


async def _verify_xss_finding(
    finding: dict,
    prove_xss_headless,
    max_attempts: int = 3
) -> dict:
    """Verify XSS finding using headless browser proof."""
    url = finding.get("url", "")
    param = finding.get("param", "")
    payload = finding.get("payload", "")

    if not url or not param or not payload:
        return _mark_verification_skipped(finding, "missing url/param/payload for XSS verification")

    finding = dict(finding)  # Don't mutate original
    finding["verification_attempted"] = True

    try:
        proof = await prove_xss_headless(
            url=url,
            param=param,
            payload=payload,
            screenshot_dir=None
        )

        if proof and proof.proven:
            finding["verified"] = True
            finding["confidence"] = proof.confidence
            evidence = finding.get("evidence", [])
            if isinstance(evidence, list):
                evidence.append(f"Browser verified: {proof.technique}")
                if proof.extracted_data:
                    evidence.append(f"Proof: {proof.extracted_data}")
            finding["evidence"] = evidence
            finding["browser_proof"] = proof.to_dict()
        else:
            # Downgrade unverified high findings
            if finding.get("severity") == "high":
                finding["severity"] = "medium"
                finding["confidence"] = 0.65
            elif finding.get("severity") == "critical":
                finding["severity"] = "high"
                finding["confidence"] = 0.70
            evidence = finding.get("evidence", [])
            if isinstance(evidence, list):
                evidence.append("Browser verification failed - no execution confirmed")
            finding["evidence"] = evidence

    except Exception as e:
        # Don't fail verification, just note the error
        evidence = finding.get("evidence", [])
        if isinstance(evidence, list):
            evidence.append(f"Browser verification error: {str(e)[:100]}")
        finding["evidence"] = evidence

    return finding

