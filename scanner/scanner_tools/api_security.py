"""
API Security Testing Module

Provides HTTP method tampering, Content-Type manipulation, and other API-specific
security tests based on modern penetration testing methodologies.
"""

import asyncio
import json
import re
import urllib.parse
from typing import Any

import httpx

from .common import get_auth_curl_args, run


# HTTP methods to test for method tampering
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"]

# Content types for manipulation testing
CONTENT_TYPES = [
    "application/json",
    "application/xml",
    "application/x-www-form-urlencoded",
    "text/plain",
    "text/xml",
    "multipart/form-data",
]


async def test_http_method_tampering(
    url: str,
    auth_session: Any | None = None,
    expected_methods: list[str] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """
    Test all HTTP methods on a given endpoint to detect method tampering vulnerabilities.

    Checks if an endpoint accepts unexpected HTTP methods that could lead to:
    - Bypassing access controls (GET allowed but DELETE also works)
    - Method override vulnerabilities
    - Unprotected administrative actions

    Args:
        url: Target URL to test
        auth_session: Optional authentication session
        expected_methods: List of expected allowed methods (from OPTIONS or prior knowledge)
        timeout: Request timeout in seconds

    Returns:
        Dict with findings and method availability.
    """
    results: dict[str, Any] = {
        "url": url,
        "methods_tested": [],
        "methods_allowed": [],
        "methods_unexpected": [],
        "findings": [],
        "options_response": None,
    }

    auth_args = get_auth_curl_args(auth_session)

    # First, try OPTIONS to get declared allowed methods
    options_cmd = [
        "curl", "-sS", "-X", "OPTIONS", "-k", "--max-time", str(timeout),
        "-w", "\n%{http_code}",
        "-D", "-",  # Include headers in output
    ] + auth_args + [url]

    out, err, rc = await run(options_cmd, timeout=int(timeout) + 5)

    declared_methods: set[str] = set()
    if rc == 0 and out:
        lines = out.split("\n")
        for line in lines:
            if line.lower().startswith("allow:"):
                allow_value = line.split(":", 1)[1].strip()
                declared_methods = {m.strip().upper() for m in allow_value.split(",")}
                results["options_response"] = {"allow": list(declared_methods)}
                break

    # Test each HTTP method
    for method in HTTP_METHODS:
        results["methods_tested"].append(method)

        cmd = [
            "curl", "-sS", "-X", method, "-k", "--max-time", str(timeout),
            "-w", "\n%{http_code}\n%{content_type}",
            "-o", "/dev/null",  # We only need status code for tampering detection
        ] + auth_args + [url]

        out, err, rc = await run(cmd, timeout=int(timeout) + 5)

        if rc != 0:
            continue

        lines = out.strip().split("\n")
        try:
            status_code = int(lines[-2]) if len(lines) >= 2 else 0
        except (ValueError, IndexError):
            continue

        # Determine if method is accepted
        # 2xx = success, 3xx = redirect (often accepted), 401/403 = auth required (method exists)
        method_accepted = status_code in range(200, 400) or status_code in (401, 403)

        if method_accepted:
            results["methods_allowed"].append({
                "method": method,
                "status_code": status_code,
            })

            # Check if this method was unexpected
            if expected_methods:
                if method.upper() not in [m.upper() for m in expected_methods]:
                    results["methods_unexpected"].append(method)
            elif declared_methods:
                if method.upper() not in declared_methods:
                    results["methods_unexpected"].append(method)

    # Generate findings for unexpected methods
    for method in results["methods_unexpected"]:
        severity = "high" if method in ("DELETE", "PUT", "PATCH") else "medium"

        # DELETE on a resource endpoint is particularly dangerous
        if method == "DELETE":
            finding = {
                "type": "HTTP Method Tampering",
                "severity": "high",
                "title": f"Unexpected DELETE method accepted",
                "description": f"Endpoint {url} accepts DELETE requests which may allow unauthorized data deletion.",
                "method": method,
                "recommendation": "Ensure DELETE method is properly protected with authentication and authorization checks.",
            }
        elif method == "TRACE":
            finding = {
                "type": "HTTP Method Tampering",
                "severity": "medium",
                "title": "TRACE method enabled",
                "description": f"Endpoint {url} accepts TRACE requests which can be used for Cross-Site Tracing (XST) attacks.",
                "method": method,
                "recommendation": "Disable TRACE method on the server.",
            }
        elif method in ("PUT", "PATCH"):
            finding = {
                "type": "HTTP Method Tampering",
                "severity": "high",
                "title": f"Unexpected {method} method accepted",
                "description": f"Endpoint {url} accepts {method} requests which may allow unauthorized data modification.",
                "method": method,
                "recommendation": f"Ensure {method} method is properly protected with authentication and authorization checks.",
            }
        else:
            finding = {
                "type": "HTTP Method Tampering",
                "severity": severity,
                "title": f"Unexpected {method} method accepted",
                "description": f"Endpoint {url} accepts {method} requests which was not declared in OPTIONS Allow header.",
                "method": method,
                "recommendation": "Review method handling and ensure only necessary methods are allowed.",
            }

        results["findings"].append(finding)

    return results


async def test_content_type_manipulation(
    url: str,
    original_content_type: str = "application/json",
    test_data: dict[str, Any] | None = None,
    auth_session: Any | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """
    Test if an endpoint accepts Content-Types other than expected.

    Content-Type manipulation can lead to:
    - Parser confusion attacks
    - WAF bypass
    - Mass assignment vulnerabilities
    - XXE if XML is unexpectedly accepted

    Args:
        url: Target URL to test
        original_content_type: The expected Content-Type for this endpoint
        test_data: Sample data to send in the request body
        auth_session: Optional authentication session
        timeout: Request timeout in seconds

    Returns:
        Dict with findings and accepted content types.
    """
    results: dict[str, Any] = {
        "url": url,
        "original_content_type": original_content_type,
        "content_types_tested": [],
        "content_types_accepted": [],
        "findings": [],
    }

    if test_data is None:
        test_data = {"test": "value", "id": "1"}

    auth_args = get_auth_curl_args(auth_session)

    # Prepare different content type payloads
    payloads: dict[str, str] = {
        "application/json": json.dumps(test_data),
        "application/x-www-form-urlencoded": urllib.parse.urlencode(test_data),
        "text/plain": json.dumps(test_data),  # JSON in plain text
        "application/xml": _dict_to_xml(test_data),
        "text/xml": _dict_to_xml(test_data),
    }

    # Get baseline response with original content type
    baseline_status = None
    baseline_body_length = 0

    baseline_cmd = [
        "curl", "-sS", "-X", "POST", "-k", "--max-time", str(timeout),
        "-H", f"Content-Type: {original_content_type}",
        "-d", payloads.get(original_content_type, json.dumps(test_data)),
        "-w", "\n%{http_code}\n%{size_download}",
    ] + auth_args + [url]

    out, err, rc = await run(baseline_cmd, timeout=int(timeout) + 5)
    if rc == 0 and out:
        lines = out.strip().split("\n")
        try:
            baseline_body_length = int(lines[-1])
            baseline_status = int(lines[-2])
        except (ValueError, IndexError):
            pass

    # Test each content type
    for content_type in CONTENT_TYPES:
        if content_type == original_content_type:
            continue

        results["content_types_tested"].append(content_type)

        payload = payloads.get(content_type, json.dumps(test_data))

        cmd = [
            "curl", "-sS", "-X", "POST", "-k", "--max-time", str(timeout),
            "-H", f"Content-Type: {content_type}",
            "-d", payload,
            "-w", "\n%{http_code}\n%{size_download}",
        ] + auth_args + [url]

        out, err, rc = await run(cmd, timeout=int(timeout) + 5)

        if rc != 0:
            continue

        lines = out.strip().split("\n")
        try:
            body_length = int(lines[-1])
            status_code = int(lines[-2])
            response_body = "\n".join(lines[:-2])
        except (ValueError, IndexError):
            continue

        # Check if this content type was accepted
        # 2xx = success, similar response size to baseline = parsed correctly
        content_accepted = status_code in range(200, 300)

        # Also consider 4xx responses that indicate parsing (not 415 Unsupported Media Type)
        if status_code == 415:
            # Proper rejection of unsupported content type
            continue

        if content_accepted or (status_code in (400, 422) and status_code != 415):
            accepted_info = {
                "content_type": content_type,
                "status_code": status_code,
                "response_length": body_length,
            }
            results["content_types_accepted"].append(accepted_info)

            # Generate findings for unexpected content types
            if content_type != original_content_type and status_code in range(200, 300):
                severity = "medium"
                finding_type = "Content-Type Confusion"

                # XML acceptance is higher severity due to XXE risk
                if "xml" in content_type.lower():
                    severity = "high"
                    finding_type = "Potential XXE Vector"
                    finding = {
                        "type": finding_type,
                        "severity": severity,
                        "title": f"Endpoint accepts {content_type}",
                        "description": (
                            f"Endpoint {url} accepts XML content which may be vulnerable to "
                            f"XXE (XML External Entity) attacks if not properly configured."
                        ),
                        "content_type": content_type,
                        "status_code": status_code,
                        "recommendation": "Disable XML parsing or configure it securely to prevent XXE.",
                    }
                else:
                    finding = {
                        "type": finding_type,
                        "severity": severity,
                        "title": f"Endpoint accepts unexpected Content-Type: {content_type}",
                        "description": (
                            f"Endpoint {url} accepts {content_type} in addition to {original_content_type}. "
                            f"This could allow parser confusion attacks or WAF bypass."
                        ),
                        "content_type": content_type,
                        "status_code": status_code,
                        "recommendation": "Strictly validate Content-Type and reject unexpected types with 415.",
                    }

                results["findings"].append(finding)

    return results


def _dict_to_xml(data: dict[str, Any], root_name: str = "data") -> str:
    """Convert a dictionary to simple XML format."""
    def _value_to_xml(key: str, value: Any) -> str:
        if isinstance(value, dict):
            inner = "".join(_value_to_xml(k, v) for k, v in value.items())
            return f"<{key}>{inner}</{key}>"
        elif isinstance(value, list):
            items = "".join(f"<item>{v}</item>" for v in value)
            return f"<{key}>{items}</{key}>"
        else:
            return f"<{key}>{value}</{key}>"

    content = "".join(_value_to_xml(k, v) for k, v in data.items())
    return f"<?xml version=\"1.0\"?><{root_name}>{content}</{root_name}>"


async def test_method_override(
    url: str,
    auth_session: Any | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """
    Test for HTTP method override vulnerabilities.

    Some frameworks allow overriding the HTTP method via headers like:
    - X-HTTP-Method-Override
    - X-Method-Override
    - X-HTTP-Method
    - _method query parameter

    This can be used to bypass WAFs or access controls.

    Args:
        url: Target URL to test
        auth_session: Optional authentication session
        timeout: Request timeout in seconds

    Returns:
        Dict with findings.
    """
    results: dict[str, Any] = {
        "url": url,
        "override_methods_tested": [],
        "vulnerable_overrides": [],
        "findings": [],
    }

    auth_args = get_auth_curl_args(auth_session)

    override_headers = [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
        "_method",  # Also test as header
    ]

    target_methods = ["DELETE", "PUT", "PATCH"]

    # First, get baseline response for POST
    baseline_cmd = [
        "curl", "-sS", "-X", "POST", "-k", "--max-time", str(timeout),
        "-w", "\n%{http_code}",
        "-d", "{}",
        "-H", "Content-Type: application/json",
    ] + auth_args + [url]

    out, err, rc = await run(baseline_cmd, timeout=int(timeout) + 5)
    baseline_status = None
    if rc == 0 and out:
        try:
            baseline_status = int(out.strip().split("\n")[-1])
        except (ValueError, IndexError):
            pass

    # Test method override via headers
    for header in override_headers:
        for target_method in target_methods:
            test_key = f"{header}:{target_method}"
            results["override_methods_tested"].append(test_key)

            cmd = [
                "curl", "-sS", "-X", "POST", "-k", "--max-time", str(timeout),
                "-H", f"{header}: {target_method}",
                "-H", "Content-Type: application/json",
                "-d", "{}",
                "-w", "\n%{http_code}",
            ] + auth_args + [url]

            out, err, rc = await run(cmd, timeout=int(timeout) + 5)

            if rc != 0:
                continue

            try:
                status_code = int(out.strip().split("\n")[-1])
            except (ValueError, IndexError):
                continue

            # If we get a different (non-error) response than baseline, override might work
            if status_code in range(200, 400) and status_code != baseline_status:
                results["vulnerable_overrides"].append({
                    "header": header,
                    "method": target_method,
                    "status_code": status_code,
                })

    # Test method override via query parameter
    for target_method in target_methods:
        test_key = f"_method_param:{target_method}"
        results["override_methods_tested"].append(test_key)

        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        query_params["_method"] = [target_method]
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        override_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

        cmd = [
            "curl", "-sS", "-X", "POST", "-k", "--max-time", str(timeout),
            "-H", "Content-Type: application/json",
            "-d", "{}",
            "-w", "\n%{http_code}",
        ] + auth_args + [override_url]

        out, err, rc = await run(cmd, timeout=int(timeout) + 5)

        if rc != 0:
            continue

        try:
            status_code = int(out.strip().split("\n")[-1])
        except (ValueError, IndexError):
            continue

        if status_code in range(200, 400) and status_code != baseline_status:
            results["vulnerable_overrides"].append({
                "header": "_method (query param)",
                "method": target_method,
                "status_code": status_code,
            })

    # Generate findings
    for override in results["vulnerable_overrides"]:
        severity = "high" if override["method"] == "DELETE" else "medium"
        results["findings"].append({
            "type": "HTTP Method Override Vulnerability",
            "severity": severity,
            "title": f"Method override to {override['method']} via {override['header']}",
            "description": (
                f"Endpoint {url} accepts HTTP method override via {override['header']} header/param. "
                f"A POST request can be converted to {override['method']}. "
                f"This could allow bypassing WAFs or access controls."
            ),
            "method": override["method"],
            "override_mechanism": override["header"],
            "recommendation": "Disable method override functionality or restrict it to authenticated users only.",
        })

    return results


async def run_api_security_tests(
    endpoints: list[dict[str, Any]],
    auth_session: Any | None = None,
    test_method_tampering: bool = True,
    test_content_type: bool = True,
    test_method_override: bool = True,
    max_endpoints: int = 50,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """
    Run comprehensive API security tests on a list of endpoints.

    Args:
        endpoints: List of endpoint dicts with url, method, content_type keys
        auth_session: Optional authentication session
        test_method_tampering: Enable HTTP method tampering tests
        test_content_type: Enable Content-Type manipulation tests
        test_method_override: Enable method override tests
        max_endpoints: Maximum number of endpoints to test
        timeout: Request timeout in seconds

    Returns:
        Dict with all findings and test results.
    """
    results: dict[str, Any] = {
        "endpoints_tested": 0,
        "method_tampering_results": [],
        "content_type_results": [],
        "method_override_results": [],
        "findings": [],
    }

    # Deduplicate endpoints by URL
    seen_urls: set[str] = set()
    unique_endpoints = []
    for ep in endpoints:
        url = ep.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            unique_endpoints.append(ep)

    # Limit endpoints
    test_endpoints = unique_endpoints[:max_endpoints]
    results["endpoints_tested"] = len(test_endpoints)

    # Run tests
    for endpoint in test_endpoints:
        url = endpoint.get("url", "")
        if not url:
            continue

        expected_methods = endpoint.get("allowed_methods")
        content_type = endpoint.get("content_type", "application/json")

        tasks = []

        if test_method_tampering:
            tasks.append(test_http_method_tampering(url, auth_session, expected_methods, timeout))

        if test_content_type and endpoint.get("method", "GET").upper() in ("POST", "PUT", "PATCH"):
            tasks.append(test_content_type_manipulation(url, content_type, None, auth_session, timeout))

        if test_method_override:
            tasks.append(test_method_override(url, auth_session, timeout))

        if tasks:
            task_results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(task_results):
                if isinstance(result, Exception):
                    continue

                if test_method_tampering and i == 0:
                    results["method_tampering_results"].append(result)
                    results["findings"].extend(result.get("findings", []))
                elif test_content_type and endpoint.get("method", "GET").upper() in ("POST", "PUT", "PATCH"):
                    idx = 1 if test_method_tampering else 0
                    if i == idx:
                        results["content_type_results"].append(result)
                        results["findings"].extend(result.get("findings", []))
                    elif i == idx + 1 and test_method_override:
                        results["method_override_results"].append(result)
                        results["findings"].extend(result.get("findings", []))
                elif test_method_override:
                    idx = (1 if test_method_tampering else 0) + (1 if test_content_type and endpoint.get("method", "GET").upper() in ("POST", "PUT", "PATCH") else 0)
                    if i == idx:
                        results["method_override_results"].append(result)
                        results["findings"].extend(result.get("findings", []))

    return results
