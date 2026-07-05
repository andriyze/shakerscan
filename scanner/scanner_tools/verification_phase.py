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

import asyncio
import sys
from typing import Any

from .common import run, get_auth_curl_args

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


def _coerce_header_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value if v is not None)
    return str(value)


def _header_map_from_args(args: list[str]) -> dict[str, tuple[str, str]]:
    headers: dict[str, tuple[str, str]] = {}
    i = 0
    while i < len(args) - 1:
        if args[i] == "-H":
            name, _, value = args[i + 1].partition(":")
            name = name.strip()
            value = value.strip()
            if name:
                headers[name.lower()] = (name, value)
            i += 2
            continue
        i += 1
    return headers


def _header_args_from_map(headers: dict[str, tuple[str, str]]) -> list[str]:
    header_args: list[str] = []
    for name, value in headers.values():
        if value:
            header_args.extend(["-H", f"{name}: {value}"])
    return header_args


def _guess_content_type(body: str, current: str) -> str:
    if current:
        return current
    if not body:
        return ""
    stripped = body.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "application/json"
    return "application/x-www-form-urlencoded"


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


async def _verify_sqli_timing(
    finding: dict,
    auth_session: Any | None,
    max_samples: int = 3
) -> dict:
    """Verify time-based SQLi using statistical timing analysis.

    Supports both GET (query params) and POST/PUT/PATCH (body params).
    """
    import copy
    import json
    import time
    import urllib.parse

    url = finding.get("url", "")
    param = finding.get("param", "")
    payload = finding.get("payload", "")
    method = finding.get("method", "GET").upper()
    content_type = finding.get("content_type", "")
    original_body = finding.get("body", "")

    if not url or not param or not payload:
        return _mark_verification_skipped(finding, "missing url/param/payload for SQLi timing verification")

    finding = dict(finding)  # Don't mutate original
    finding["verification_attempted"] = True

    try:
        from .active_checks import statistical_timing_test
    except ImportError:
        # Can't verify without statistical test
        return finding

    if method in ("POST", "PUT", "PATCH"):
        if not original_body:
            return _mark_verification_skipped(finding, "missing request body for SQLi timing verification")
        content_type = _guess_content_type(original_body, content_type)
        if not content_type:
            return _mark_verification_skipped(finding, "missing content type for SQLi timing verification")

    auth_args = get_auth_curl_args(auth_session)
    request_headers = finding.get("request_headers") or finding.get("headers")
    header_map = _header_map_from_args(auth_args)
    if isinstance(request_headers, dict):
        for name, value in request_headers.items():
            key = str(name).strip()
            if not key:
                continue
            header_map[key.lower()] = (key, _coerce_header_value(value).strip())

    def _apply_json_param(body_data: Any, param_name: str, param_value: str) -> Any:
        if isinstance(body_data, list):
            updated = copy.deepcopy(body_data)
            if not updated:
                return [{}] if param_name != "__item__" else [param_value]
            if isinstance(updated[0], dict):
                updated[0][param_name] = param_value
            else:
                updated[0] = param_value
            return updated
        if isinstance(body_data, dict):
            updated = dict(body_data)
            updated[param_name] = param_value
            return updated
        return {param_name: param_value}

    def _build_curl_args(inject_payload: bool) -> list[str]:
        """Build curl args for GET or POST/PUT/PATCH requests."""
        base_args = ["curl", "-sS", "-L", "-k", "--max-time", "15"]
        headers = dict(header_map)

        if method == "GET":
            # GET: inject into query params
            parsed = urllib.parse.urlparse(url)
            query_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            if inject_payload:
                query_params[param] = payload
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(query_params))
            )
            header_args = _header_args_from_map(headers)
            return base_args + header_args + [test_url]

        elif method in ("POST", "PUT", "PATCH"):
            # POST/PUT/PATCH: inject into body
            curl_args = base_args + ["-X", method]

            if "json" in content_type.lower():
                # JSON body injection
                headers.setdefault("content-type", ("Content-Type", content_type or "application/json"))
                try:
                    body_data = json.loads(original_body) if original_body else {}
                except json.JSONDecodeError:
                    body_data = {}
                if inject_payload:
                    body_data = _apply_json_param(body_data, param, payload)
                curl_args += _header_args_from_map(headers) + ["-d", json.dumps(body_data)]
            else:
                # Form-encoded body injection
                headers.setdefault("content-type", ("Content-Type", "application/x-www-form-urlencoded"))
                if original_body:
                    body_params = dict(urllib.parse.parse_qsl(original_body, keep_blank_values=True))
                else:
                    body_params = {}
                if inject_payload:
                    body_params[param] = payload
                curl_args += _header_args_from_map(headers) + ["-d", urllib.parse.urlencode(body_params)]

            return curl_args + [url]
        else:
            # Fallback: treat as GET
            header_args = _header_args_from_map(headers)
            return base_args + header_args + [url]

    # Collect baseline samples (without payload)
    baseline_times = []
    for _ in range(max_samples):
        start = time.time()
        await run(_build_curl_args(inject_payload=False), timeout=17)
        baseline_times.append(time.time() - start)
        await asyncio.sleep(0.1)  # Small delay between samples

    # Collect payload samples (with timing payload)
    payload_times = []
    for _ in range(max_samples):
        start = time.time()
        await run(_build_curl_args(inject_payload=True), timeout=17)
        payload_times.append(time.time() - start)
        await asyncio.sleep(0.1)

    # Statistical test
    result = statistical_timing_test(
        baseline_times=baseline_times,
        payload_times=payload_times,
        expected_delay=2.0,  # Standard SLEEP(2)
        significance_level=0.05
    )

    evidence = finding.get("evidence", [])
    if isinstance(evidence, list):
        evidence.append(
            f"Statistical timing: baseline_median={result.get('baseline_median', 0):.2f}s, "
            f"payload_median={result.get('payload_median', 0):.2f}s, "
            f"delay={result.get('delay_observed', 0):.2f}s"
        )
        if result.get("p_value"):
            evidence.append(f"Mann-Whitney p-value={result.get('p_value')}")

    if result.get("confirmed"):
        finding["verified"] = True
        finding["confidence"] = result.get("confidence", 0.85)
        finding["statistical_proof"] = result
    else:
        # Downgrade unverified finding
        if finding.get("severity") == "high":
            finding["severity"] = "medium"
            finding["confidence"] = 0.60
        elif finding.get("severity") == "critical":
            finding["severity"] = "high"
            finding["confidence"] = 0.65
        evidence.append("Statistical timing verification failed")
        finding["statistical_proof"] = result

    finding["evidence"] = evidence
    return finding


async def _verify_sqli_extraction(
    finding: dict,
    auth_session: Any | None
) -> dict:
    """Verify error-based/union SQLi by attempting data extraction.

    Supports both GET (query params) and POST/PUT/PATCH (body params).
    """
    import copy
    import json
    import urllib.parse

    url = finding.get("url", "")
    param = finding.get("param", "")
    dbms = finding.get("dbms", "").lower()
    method = finding.get("method", "GET").upper()
    content_type = finding.get("content_type", "")
    original_body = finding.get("body", "")

    if not url or not param:
        return _mark_verification_skipped(finding, "missing url/param for SQLi extraction verification")

    finding = dict(finding)  # Don't mutate original
    finding["verification_attempted"] = True

    # If we already have extracted data, it's verified
    if finding.get("extracted_data"):
        finding["verified"] = True
        return finding

    if method in ("POST", "PUT", "PATCH"):
        if not original_body:
            return _mark_verification_skipped(finding, "missing request body for SQLi extraction verification")
        content_type = _guess_content_type(original_body, content_type)
        if not content_type:
            return _mark_verification_skipped(finding, "missing content type for SQLi extraction verification")

    # Attempt version extraction as proof
    auth_args = get_auth_curl_args(auth_session)
    request_headers = finding.get("request_headers") or finding.get("headers")
    header_map = _header_map_from_args(auth_args)
    if isinstance(request_headers, dict):
        for name, value in request_headers.items():
            key = str(name).strip()
            if not key:
                continue
            header_map[key.lower()] = (key, _coerce_header_value(value).strip())

    version_payloads = {
        "mysql": "' UNION SELECT NULL,@@version,NULL-- -",
        "postgresql": "' UNION SELECT NULL,version(),NULL-- -",
        "sqlite": "' UNION SELECT NULL,sqlite_version(),NULL-- -",
        "mssql": "' UNION SELECT NULL,@@VERSION,NULL-- -",
        "oracle": "' UNION SELECT NULL,banner,NULL FROM v$version WHERE ROWNUM=1-- -",
    }

    payload = version_payloads.get(dbms, version_payloads.get("mysql"))

    # Build curl command based on HTTP method
    base_args = ["curl", "-sS", "-L", "-k", "--max-time", "10"]

    def _apply_json_param(body_data: Any, param_name: str, param_value: str) -> Any:
        if isinstance(body_data, list):
            updated = copy.deepcopy(body_data)
            if not updated:
                return [{}] if param_name != "__item__" else [param_value]
            if isinstance(updated[0], dict):
                updated[0][param_name] = param_value
            else:
                updated[0] = param_value
            return updated
        if isinstance(body_data, dict):
            updated = dict(body_data)
            updated[param_name] = param_value
            return updated
        return {param_name: param_value}

    if method == "GET":
        # GET: inject into query params
        parsed = urllib.parse.urlparse(url)
        query_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        query_params[param] = payload
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(query_params))
        )
        curl_args = base_args + _header_args_from_map(header_map) + [test_url]

    elif method in ("POST", "PUT", "PATCH"):
        # POST/PUT/PATCH: inject into body
        curl_args = base_args + ["-X", method]

        if "json" in content_type.lower():
            # JSON body injection
            header_map.setdefault("content-type", ("Content-Type", content_type or "application/json"))
            try:
                body_data = json.loads(original_body) if original_body else {}
            except json.JSONDecodeError:
                body_data = {}
            body_data = _apply_json_param(body_data, param, payload)
            curl_args += _header_args_from_map(header_map) + ["-d", json.dumps(body_data)]
        else:
            # Form-encoded body injection
            header_map.setdefault("content-type", ("Content-Type", "application/x-www-form-urlencoded"))
            if original_body:
                body_params = dict(urllib.parse.parse_qsl(original_body, keep_blank_values=True))
            else:
                body_params = {}
            body_params[param] = payload
            curl_args += _header_args_from_map(header_map) + ["-d", urllib.parse.urlencode(body_params)]

        curl_args += [url]
    else:
        # Fallback: treat as GET
        curl_args = base_args + _header_args_from_map(header_map) + [url]

    out, _, rc = await run(curl_args, timeout=12)

    evidence = finding.get("evidence", [])

    if rc == 0 and out:
        # Look for version strings
        import re
        version_patterns = [
            r"(\d+\.\d+\.\d+[-\w]*)",  # Generic version
            r"MySQL (\d+\.\d+)",
            r"PostgreSQL (\d+\.\d+)",
            r"Microsoft SQL Server",
            r"Oracle Database",
            r"SQLite version (\d+\.\d+)",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, out)
            if match:
                finding["verified"] = True
                finding["confidence"] = 0.95
                finding["extracted_data"] = match.group(0)
                if isinstance(evidence, list):
                    evidence.append(f"Data extraction confirmed: {match.group(0)}")
                break

    if not finding.get("verified"):
        # Downgrade if extraction failed
        if finding.get("severity") == "critical":
            finding["severity"] = "high"
            finding["confidence"] = 0.75
        if isinstance(evidence, list):
            evidence.append("Data extraction verification failed")

    finding["evidence"] = evidence
    return finding
