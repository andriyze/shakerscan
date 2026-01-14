"""
Logging and Monitoring Security Checks

OWASP A09:2021 - Security Logging and Monitoring Failures

Detects:
- Exposed logging/monitoring endpoints
- Log injection vulnerabilities (CRLF injection)
- Sensitive data in error responses
- Missing security event logging indicators
"""

import asyncio
import re
import urllib.parse
from typing import Any

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    aiohttp = None  # type: ignore


# Common logging/monitoring endpoints to check
LOGGING_ENDPOINTS = [
    "/logs",
    "/log",
    "/admin/logs",
    "/api/logs",
    "/api/v1/logs",
    "/debug/logs",
    "/debug",
    "/debug/vars",
    "/debug/pprof",
    "/_debug",
    "/actuator",
    "/actuator/logfile",
    "/actuator/loggers",
    "/actuator/env",
    "/actuator/health",
    "/actuator/info",
    "/actuator/metrics",
    "/actuator/trace",
    "/actuator/dump",
    "/actuator/heapdump",
    "/actuator/threaddump",
    "/metrics",
    "/stats",
    "/status",
    "/monitoring",
    "/admin/monitoring",
    "/grafana",
    "/kibana",
    "/elasticsearch",
    "/_cat",
    "/_cluster",
    "/_nodes",
    "/phpinfo.php",
    "/info.php",
    "/server-info",
    "/server-status",
    "/.well-known/security.txt",
    "/trace",
    "/api/trace",
]

# Sensitive data patterns that shouldn't appear in error responses
SENSITIVE_PATTERNS = [
    (r"password['\"]?\s*[:=]\s*['\"]?[^'\"]+", "password in response"),
    (r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}", "API key in response"),
    (r"secret['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}", "secret in response"),
    (r"token['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}", "token in response"),
    (r"AWS[A-Z0-9]{16,}", "AWS key in response"),
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----", "private key in response"),
    (r"mysql://[^\s]+", "database connection string"),
    (r"postgresql://[^\s]+", "database connection string"),
    (r"mongodb://[^\s]+", "database connection string"),
]

# CRLF injection payloads for log injection testing
CRLF_PAYLOADS = [
    "%0d%0aInjected-Header:%20test",
    "%0aInjected-Log-Entry",
    "\r\nInjected-Header: test",
    "%0d%0a%0d%0a<script>alert(1)</script>",
]


async def check_logging_monitoring(
    session: "aiohttp.ClientSession",
    base_url: str,
    urls: list[str],
    quick_mode: bool = False
) -> list[dict[str, Any]]:
    """
    Check for logging and monitoring security issues.

    Args:
        session: aiohttp client session
        base_url: Target base URL
        urls: List of discovered URLs to test
        quick_mode: If True, run faster with reduced checks

    Note:
        Requires aiohttp to be installed. Returns empty list if not available.

    Returns:
        List of findings with OWASP A09 mappings
    """
    # Early return if aiohttp is not available
    if not HAS_AIOHTTP:
        return []

    findings: list[dict[str, Any]] = []

    # Parse base URL
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Check for exposed logging endpoints
    exposed = await check_exposed_logging_endpoints(session, base, quick_mode)
    findings.extend(exposed)

    # Check for sensitive data in error responses
    if not quick_mode:
        sensitive = await check_sensitive_data_exposure(session, base)
        findings.extend(sensitive)

    # Check for log injection vulnerabilities
    if not quick_mode and urls:
        log_injection = await check_log_injection(session, urls[:5])  # Limit to 5 URLs
        findings.extend(log_injection)

    return findings


async def check_exposed_logging_endpoints(
    session: aiohttp.ClientSession,
    base_url: str,
    quick_mode: bool = False
) -> list[dict[str, Any]]:
    """Check for exposed logging/monitoring endpoints."""
    findings: list[dict[str, Any]] = []
    endpoints_to_check = LOGGING_ENDPOINTS[:20] if quick_mode else LOGGING_ENDPOINTS

    async def check_endpoint(endpoint: str) -> dict[str, Any] | None:
        url = f"{base_url}{endpoint}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=False) as resp:
                if resp.status == 200:
                    content = await resp.text()

                    # Check if this looks like a real logging/monitoring endpoint
                    indicators = [
                        "log", "debug", "trace", "actuator", "metrics",
                        "status", "health", "dump", "heap", "thread",
                        "env", "info", "pprof", "stats"
                    ]

                    content_lower = content.lower()
                    if any(ind in content_lower for ind in indicators):
                        # Determine severity based on endpoint type
                        severity = "high"
                        if ("actuator" in endpoint and any(x in endpoint for x in ["heapdump", "threaddump", "env"])) or "debug" in endpoint or "pprof" in endpoint:
                            severity = "critical"
                        elif "health" in endpoint or "status" in endpoint:
                            severity = "medium"

                        return {
                            "title": f"Exposed monitoring endpoint: {endpoint}",
                            "severity": severity,
                            "tool": "logging_checks",
                            "cwe": "CWE-200",
                            "owasp": "A09:2021 - Security Logging and Monitoring Failures",
                            "evidence": {
                                "url": url,
                                "status": resp.status,
                                "content_preview": content[:500] if len(content) > 500 else content
                            }
                        }
        except Exception:
            pass
        return None

    tasks = [check_endpoint(ep) for ep in endpoints_to_check]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, dict):
            findings.append(result)

    return findings


async def check_sensitive_data_exposure(
    session: aiohttp.ClientSession,
    base_url: str
) -> list[dict[str, Any]]:
    """Check for sensitive data in error responses."""
    findings: list[dict[str, Any]] = []

    # Test URLs that commonly expose errors
    error_urls = [
        f"{base_url}/nonexistent-page-12345",
        f"{base_url}/api/v1/undefined",
        f"{base_url}/?id=999999999",
        f"{base_url}/admin/undefined",
    ]

    for url in error_urls:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content = await resp.text()

                for pattern, desc in SENSITIVE_PATTERNS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        findings.append({
                            "title": f"Sensitive data exposure: {desc}",
                            "severity": "high",
                            "tool": "logging_checks",
                            "cwe": "CWE-532",
                            "owasp": "A09:2021 - Security Logging and Monitoring Failures",
                            "evidence": {
                                "url": url,
                                "pattern": desc,
                                "match_count": len(matches)
                            }
                        })
                        break  # One finding per URL

                # Check for stack traces
                stack_patterns = [
                    r"Traceback \(most recent call last\):",
                    r"at .+\(.+:\d+\)",
                    r"Exception in thread",
                    r"java\.lang\.\w+Exception",
                    r"PHP Fatal error:",
                    r"Fatal error: Uncaught",
                ]

                for pattern in stack_patterns:
                    if re.search(pattern, content):
                        findings.append({
                            "title": "Stack trace exposed in error response",
                            "severity": "medium",
                            "tool": "logging_checks",
                            "cwe": "CWE-209",
                            "owasp": "A09:2021 - Security Logging and Monitoring Failures",
                            "evidence": {
                                "url": url,
                                "pattern": pattern
                            }
                        })
                        break

        except Exception:
            pass

    return findings


async def check_log_injection(
    session: aiohttp.ClientSession,
    urls: list[str]
) -> list[dict[str, Any]]:
    """Check for CRLF/log injection vulnerabilities."""
    findings: list[dict[str, Any]] = []

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            continue

        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            continue

        # Test first parameter with CRLF payload
        first_param = list(params.keys())[0]

        for payload in CRLF_PAYLOADS[:2]:  # Limit payloads
            try:
                test_url = url.replace(
                    f"{first_param}={params[first_param][0]}",
                    f"{first_param}={payload}"
                )

                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    # Check if CRLF was reflected in headers
                    for header_name, header_value in resp.headers.items():
                        if "injected" in header_name.lower() or "injected" in header_value.lower():
                            findings.append({
                                "title": "CRLF injection (log injection possible)",
                                "severity": "high",
                                "tool": "logging_checks",
                                "cwe": "CWE-117",
                                "owasp": "A09:2021 - Security Logging and Monitoring Failures",
                                "evidence": {
                                    "url": test_url,
                                    "reflected_header": f"{header_name}: {header_value}"
                                }
                            })
                            return findings  # One finding is enough

            except Exception:
                pass

    return findings


async def check_security_logging_headers(
    session: aiohttp.ClientSession,
    base_url: str
) -> list[dict[str, Any]]:
    """Check for security logging indicators in response headers."""
    findings: list[dict[str, Any]] = []

    try:
        async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Check for common security headers that indicate monitoring
            monitoring_headers = [
                "x-request-id",
                "x-correlation-id",
                "x-trace-id",
                "x-amzn-requestid",
                "cf-ray",
            ]

            has_request_tracking = any(h in headers for h in monitoring_headers)

            if not has_request_tracking:
                findings.append({
                    "title": "No request tracking headers detected",
                    "severity": "info",
                    "tool": "logging_checks",
                    "cwe": "CWE-778",
                    "owasp": "A09:2021 - Security Logging and Monitoring Failures",
                    "evidence": {
                        "note": "Consider adding X-Request-ID or similar for log correlation"
                    }
                })

    except Exception:
        pass

    return findings
