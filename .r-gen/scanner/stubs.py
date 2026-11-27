"""
Stub/dummy function factories for disabled tools.

This module replaces the 106 nested dummy functions in scanner.py
with a factory pattern, reducing code duplication and improving maintainability.
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable


def create_dummy_result(
    tool_name: str,
    reason: str = "Tool disabled or not applicable",
    extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Create standard dummy result for disabled/skipped tools.

    Args:
        tool_name: Name of the skipped tool
        reason: Why the tool was skipped
        extra: Additional fields to include in result

    Returns:
        Standard dummy result dictionary
    """
    result: dict[str, Any] = {
        "tool": tool_name,
        "scan_completed": False,
        "vulnerable": False,
        "findings": [],
        "skipped": True,
        "reason": reason,
    }
    if extra:
        result.update(extra)
    return result


def dummy_factory(
    tool_name: str,
    reason: str = "Tool disabled or not applicable",
    extra: dict[str, Any] | None = None
) -> Callable[[], Awaitable[dict[str, Any]]]:
    """Create async dummy function for a tool.

    This factory replaces manually defined dummy functions like:
        async def dummy_nmap(): return {"vulnerable": False, "findings": []}

    With:
        nmap_task = dummy_factory("nmap") if skip_nmap else nmap_quick_scan

    Args:
        tool_name: Name of the tool
        reason: Why the tool is being skipped
        extra: Additional fields for the result

    Returns:
        Async function that returns a dummy result
    """
    async def dummy() -> dict[str, Any]:
        return create_dummy_result(tool_name, reason, extra)
    return dummy


def dummy_discovery_factory(
    tool_name: str,
    reason: str = "Discovery disabled"
) -> Callable[[], Awaitable[dict[str, Any]]]:
    """Create async dummy function for discovery tools.

    Args:
        tool_name: Name of the discovery tool
        reason: Why discovery is being skipped

    Returns:
        Async function that returns a dummy discovery result
    """
    async def dummy() -> dict[str, Any]:
        return {
            "tool": tool_name,
            "completed": False,
            "endpoints": [],
            "parameters": [],
            "technologies": [],
            "skipped": True,
            "reason": reason,
        }
    return dummy


def dummy_browser_factory(
    reason: str = "Browser crawl disabled"
) -> Callable[[], Awaitable[dict[str, Any]]]:
    """Create async dummy function for browser-based tools.

    Returns:
        Async function that returns a dummy browser result
    """
    async def dummy() -> dict[str, Any]:
        return {
            "tool": "browser",
            "completed": False,
            "har_data": None,
            "captured_requests": [],
            "websocket_endpoints": [],
            "tech_stack": [],
            "page_urls": [],
            "api_endpoints": [],
            "js_routes": [],
            "skipped": True,
            "reason": reason,
        }
    return dummy


def dummy_nuclei_factory(
    reason: str = "Nuclei scan disabled"
) -> Callable[[], Awaitable[dict[str, Any]]]:
    """Create async dummy function for Nuclei scans.

    Returns:
        Async function that returns a dummy Nuclei result
    """
    async def dummy() -> dict[str, Any]:
        return {
            "tool": "nuclei",
            "scan_completed": False,
            "vulnerabilities": [],
            "errors": [],
            "skipped": True,
            "reason": reason,
            "waves_completed": 0,
            "total_duration_seconds": 0,
        }
    return dummy


def dummy_tls_factory(
    reason: str = "TLS scan disabled"
) -> Callable[[], Awaitable[dict[str, Any]]]:
    """Create async dummy function for TLS tools.

    Returns:
        Async function that returns a dummy TLS result
    """
    async def dummy() -> dict[str, Any]:
        return {
            "tool": "tls",
            "scan_completed": False,
            "issues": [],
            "certificate": {},
            "cipher_suites": {},
            "protocols": [],
            "skipped": True,
            "reason": reason,
        }
    return dummy


def dummy_active_test_factory(
    test_type: str,
    reason: str = "Active testing disabled"
) -> Callable[[], Awaitable[dict[str, Any]]]:
    """Create async dummy function for active security tests (XSS, SQLi).

    Args:
        test_type: Type of active test (xss, sqli, etc.)
        reason: Why the test is being skipped

    Returns:
        Async function that returns a dummy active test result
    """
    async def dummy() -> dict[str, Any]:
        return {
            "tool": test_type,
            "scan_completed": False,
            "vulnerable": False,
            "findings": [],
            "endpoints_tested": 0,
            "params_tested": 0,
            "skipped": True,
            "reason": reason,
        }
    return dummy


# Pre-built dummy functions for common tools
# These can be used directly instead of calling the factory

async def dummy_nmap() -> dict[str, Any]:
    """Dummy result for nmap."""
    return create_dummy_result("nmap", "Port scanning disabled")


async def dummy_testssl() -> dict[str, Any]:
    """Dummy result for testssl."""
    return create_dummy_result("testssl", "TLS testing disabled")


async def dummy_sslyze() -> dict[str, Any]:
    """Dummy result for sslyze."""
    return create_dummy_result("sslyze", "SSL analysis disabled")


async def dummy_nuclei() -> dict[str, Any]:
    """Dummy result for nuclei."""
    return {
        "tool": "nuclei",
        "scan_completed": False,
        "vulnerabilities": [],
        "errors": [],
        "skipped": True,
        "reason": "Nuclei scan disabled",
    }


async def dummy_dalfox() -> dict[str, Any]:
    """Dummy result for dalfox (XSS)."""
    return create_dummy_result("dalfox", "XSS testing disabled")


async def dummy_sqlmap() -> dict[str, Any]:
    """Dummy result for sqlmap (SQLi)."""
    return create_dummy_result("sqlmap", "SQLi testing disabled")


async def dummy_cors() -> dict[str, Any]:
    """Dummy result for CORS check."""
    return create_dummy_result("cors_check", "CORS testing disabled")


async def dummy_csrf() -> dict[str, Any]:
    """Dummy result for CSRF check."""
    return create_dummy_result("csrf_check", "CSRF testing disabled")


async def dummy_dns() -> dict[str, Any]:
    """Dummy result for DNS checks."""
    return create_dummy_result("dns", "DNS analysis disabled")


async def dummy_graphql() -> dict[str, Any]:
    """Dummy result for GraphQL checks."""
    return create_dummy_result("graphql", "GraphQL testing disabled")


async def dummy_jwt() -> dict[str, Any]:
    """Dummy result for JWT checks."""
    return create_dummy_result("jwt", "JWT testing disabled")


async def dummy_oauth() -> dict[str, Any]:
    """Dummy result for OAuth checks."""
    return create_dummy_result("oauth", "OAuth testing disabled")


async def dummy_websocket() -> dict[str, Any]:
    """Dummy result for WebSocket checks."""
    return create_dummy_result("websocket", "WebSocket testing disabled")


async def dummy_discovery() -> dict[str, Any]:
    """Dummy result for discovery."""
    return {
        "tool": "discovery",
        "completed": False,
        "endpoints": [],
        "parameters": [],
        "technologies": [],
        "skipped": True,
        "reason": "Discovery disabled",
    }


async def dummy_browser() -> dict[str, Any]:
    """Dummy result for browser crawl."""
    return {
        "tool": "browser",
        "completed": False,
        "har_data": None,
        "captured_requests": [],
        "websocket_endpoints": [],
        "tech_stack": [],
        "page_urls": [],
        "api_endpoints": [],
        "skipped": True,
        "reason": "Browser crawl disabled",
    }


# Mapping of tool names to their dummy functions
DUMMY_FUNCTIONS: dict[str, Callable[[], Awaitable[dict[str, Any]]]] = {
    "nmap": dummy_nmap,
    "testssl": dummy_testssl,
    "sslyze": dummy_sslyze,
    "nuclei": dummy_nuclei,
    "dalfox": dummy_dalfox,
    "sqlmap": dummy_sqlmap,
    "cors": dummy_cors,
    "csrf": dummy_csrf,
    "dns": dummy_dns,
    "graphql": dummy_graphql,
    "jwt": dummy_jwt,
    "oauth": dummy_oauth,
    "websocket": dummy_websocket,
    "discovery": dummy_discovery,
    "browser": dummy_browser,
}


def get_dummy_for_tool(tool_name: str) -> Callable[[], Awaitable[dict[str, Any]]]:
    """Get the appropriate dummy function for a tool.

    Args:
        tool_name: Name of the tool

    Returns:
        Async dummy function for the tool
    """
    if tool_name in DUMMY_FUNCTIONS:
        return DUMMY_FUNCTIONS[tool_name]
    return dummy_factory(tool_name)
