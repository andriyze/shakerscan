"""
Tool Health Check Module

Validates that all required security scanning tools are installed and working.
Should be run on container startup or before each scan.

Also provides network/connectivity validation for targets.
"""

import asyncio
import logging
import os
import re
import shutil
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .common import run


@dataclass
class ToolStatus:
    """Status of a single tool"""
    name: str
    available: bool
    version: str | None
    path: str | None
    error: str | None
    required: bool


async def check_tool(
    name: str,
    commands: list[list[str]],
    version_pattern: str | None = None,
    required: bool = True,
    timeout: int = 15
) -> ToolStatus:
    """
    Check if a tool is available and get its version.

    Args:
        name: Tool name for reporting
        commands: List of command variants to try (e.g., [["sslyze", "--version"], ["python3", "-m", "sslyze", "--version"]])
        version_pattern: Regex pattern to extract version from output (optional)
        required: Whether this tool is required for scanning
        timeout: Command timeout in seconds

    Returns:
        ToolStatus with availability info
    """
    import re

    for cmd in commands:
        try:
            # First check if binary exists
            binary = cmd[0]
            if binary.startswith("/"):
                if not os.path.exists(binary):
                    continue
            else:
                # Check PATH
                if not shutil.which(binary):
                    # Try /opt/tools
                    opt_path = f"/opt/tools/{binary}"
                    if os.path.exists(opt_path):
                        cmd = [opt_path] + cmd[1:]
                    else:
                        continue

            out, err, rc = await run(cmd, timeout=timeout)

            if rc == 0 or (out or err):  # Some tools return non-zero for --version
                output = out or err or ""
                version = None

                if version_pattern:
                    match = re.search(version_pattern, output)
                    if match:
                        version = match.group(1)
                else:
                    # Try to extract first version-like string
                    match = re.search(r'(\d+\.\d+(?:\.\d+)?)', output)
                    if match:
                        version = match.group(1)

                return ToolStatus(
                    name=name,
                    available=True,
                    version=version,
                    path=cmd[0],
                    error=None,
                    required=required
                )

        except Exception:
            continue

    return ToolStatus(
        name=name,
        available=False,
        version=None,
        path=None,
        error="Tool not found or not working",
        required=required
    )


async def run_health_check(include_optional: bool = True) -> dict[str, Any]:
    """
    Run health check on all scanner tools.

    Returns dict with:
    - status: "healthy" | "degraded" | "failed"
    - tools: dict of tool statuses
    - required_available: count of available required tools
    - optional_available: count of available optional tools
    - issues: list of problems found
    """

    # Define tools to check
    # Format: (name, command_variants, version_pattern, required)
    required_tools = [
        ("sslyze", [
            ["sslyze", "-h"],  # SSLyze doesn't support --version
            ["python3", "-m", "sslyze", "-h"],
            ["/opt/tools/sslyze", "-h"],
        ], r"sslyze\s+(\d+\.\d+)", True),

        ("nmap", [
            ["nmap", "--version"],
            ["/usr/bin/nmap", "--version"],
        ], r"Nmap version\s+(\d+\.\d+)", True),

        ("curl", [
            ["curl", "--version"],
        ], r"curl\s+(\d+\.\d+\.\d+)", True),

        ("openssl", [
            ["openssl", "version"],
        ], r"OpenSSL\s+(\d+\.\d+\.\d+)", True),

        ("dig", [
            ["dig", "-v"],
            ["/usr/bin/dig", "-v"],
        ], r"DiG\s+(\d+\.\d+)", True),
    ]

    optional_tools = [
        ("nuclei", [
            ["nuclei", "-version"],
            ["/opt/tools/nuclei", "-version"],
        ], r"(\d+\.\d+\.\d+)", False),

        ("dalfox", [
            ["dalfox", "version"],
            ["/opt/tools/dalfox", "version"],
        ], r"(\d+\.\d+\.\d+)", False),

        ("sqlmap", [
            ["sqlmap", "--version"],
            ["python3", "-m", "sqlmap", "--version"],
        ], r"(\d+\.\d+(?:\.\d+)?)", False),

        ("httpx", [
            ["httpx", "-version"],
            ["/opt/tools/httpx", "-version"],
        ], r"(\d+\.\d+\.\d+)", False),

        ("katana", [
            ["katana", "-version"],
            ["/opt/tools/katana", "-version"],
        ], r"(\d+\.\d+\.\d+)", False),

        ("testssl.sh", [
            ["/opt/testssl.sh/testssl.sh", "--version"],
            ["testssl.sh", "--version"],
        ], r"testssl\.sh\s+(\d+\.\d+)", False),

        ("tlsx", [
            ["tlsx", "-version"],
            ["/opt/tools/tlsx", "-version"],
        ], r"(\d+\.\d+\.\d+)", False),

        ("subfinder", [
            ["subfinder", "-version"],
            ["/opt/tools/subfinder", "-version"],
        ], r"(\d+\.\d+\.\d+)", False),
    ]

    tools_to_check = required_tools + (optional_tools if include_optional else [])

    # Run all checks concurrently
    tasks = [
        check_tool(name, commands, pattern, required)
        for name, commands, pattern, required in tools_to_check
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    tools = {}
    issues = []
    required_available = 0
    required_total = 0
    optional_available = 0
    optional_total = 0

    for i, result in enumerate(results):
        name = tools_to_check[i][0]
        required = tools_to_check[i][3]

        if isinstance(result, Exception):
            tool_status = ToolStatus(
                name=name,
                available=False,
                version=None,
                path=None,
                error=str(result),
                required=required
            )
        else:
            tool_status = result

        tools[name] = {
            "available": tool_status.available,
            "version": tool_status.version,
            "path": tool_status.path,
            "error": tool_status.error,
            "required": tool_status.required
        }

        if tool_status.required:
            required_total += 1
            if tool_status.available:
                required_available += 1
            else:
                issues.append(f"Required tool '{name}' is not available: {tool_status.error}")
        else:
            optional_total += 1
            if tool_status.available:
                optional_available += 1
            else:
                issues.append(f"Optional tool '{name}' is not available")

    # Determine overall status
    if required_available == required_total:
        if optional_available == optional_total:
            status = "healthy"
        else:
            status = "degraded"  # Required OK, some optional missing
    else:
        status = "failed"  # Required tools missing

    return {
        "status": status,
        "required_available": f"{required_available}/{required_total}",
        "optional_available": f"{optional_available}/{optional_total}",
        "tools": tools,
        "issues": issues
    }


async def validate_nuclei_templates() -> dict[str, Any]:
    """
    Validate that nuclei templates are available and up to date.

    Returns:
        Dict with template count and status
    """
    try:
        out, err, rc = await run(["nuclei", "-tl"], timeout=60)
        if rc != 0:
            # Try /opt/tools path
            out, err, rc = await run(["/opt/tools/nuclei", "-tl"], timeout=60)

        if rc == 0 and out:
            template_count = len(out.strip().splitlines())
            return {
                "available": True,
                "template_count": template_count,
                "sufficient": template_count >= 500,  # Should have at least 500 templates
                "warning": None if template_count >= 500 else f"Only {template_count} templates found (expected 500+)"
            }
        else:
            return {
                "available": False,
                "template_count": 0,
                "sufficient": False,
                "warning": "Failed to list nuclei templates"
            }
    except Exception as e:
        return {
            "available": False,
            "template_count": 0,
            "sufficient": False,
            "warning": f"Error checking templates: {e}"
        }


async def full_health_check() -> dict[str, Any]:
    """
    Run comprehensive health check including tool availability and template validation.
    """
    # Run checks concurrently
    tool_check, nuclei_templates = await asyncio.gather(
        run_health_check(include_optional=True),
        validate_nuclei_templates(),
        return_exceptions=True
    )

    if isinstance(tool_check, Exception):
        tool_check = {"status": "error", "error": str(tool_check), "tools": {}, "issues": [str(tool_check)]}
    if isinstance(nuclei_templates, Exception):
        nuclei_templates = {"available": False, "error": str(nuclei_templates)}

    return {
        "tools": tool_check,
        "nuclei_templates": nuclei_templates,
        "overall_status": tool_check.get("status", "unknown"),
        "ready_to_scan": tool_check.get("status") in ("healthy", "degraded")
    }


# Convenience function for logging health check on startup
def log_health_check_results(results: dict[str, Any]) -> None:
    """Log health check results in a readable format."""
    status = results.get("overall_status", "unknown")

    if status == "healthy":
        logging.info("Health check passed: All tools available")
    elif status == "degraded":
        logging.warning("Health check degraded: Some optional tools missing")
    else:
        logging.error("Health check FAILED: Required tools missing")

    # Log tool versions for debugging
    tools = results.get("tools", {}).get("tools", {})
    for name, info in tools.items():
        if info.get("available"):
            logging.info(f"  {name}: v{info.get('version', 'unknown')} at {info.get('path', 'unknown')}")
        elif info.get("required"):
            logging.error(f"  {name}: NOT AVAILABLE (required)")
        else:
            logging.debug(f"  {name}: not available (optional)")

    # Log nuclei template status
    templates = results.get("nuclei_templates", {})
    if templates.get("available"):
        count = templates.get("template_count", 0)
        logging.info(f"  nuclei templates: {count} templates available")
        if templates.get("warning"):
            logging.warning(f"    {templates['warning']}")
    else:
        logging.warning("  nuclei templates: not available")

    # Log any issues
    issues = results.get("tools", {}).get("issues", [])
    for issue in issues:
        logging.warning(f"  Issue: {issue}")


# =============================================================================
# Network/Connectivity Validation
# =============================================================================

async def validate_target_connectivity(target: str, timeout: int = 15) -> dict[str, Any]:
    """
    Validate network connectivity to a target before scanning.

    Checks:
    1. DNS resolution - can we resolve the hostname?
    2. Port connectivity - can we reach the target port (or 443/80 if not specified)?
    3. HTTP response - do we get a valid response over HTTP/HTTPS?

    Args:
        target: URL or hostname to validate
        timeout: Timeout for checks in seconds

    Returns:
        Dict with:
        - reachable: bool - whether target is reachable (DNS + HTTP response)
        - dns_ok: bool - DNS resolution worked
        - port_443_open: bool - port 443 is reachable
        - port_80_open: bool - port 80 is reachable
        - target_port_open: bool - custom port from URL is reachable (if specified)
        - http_ok: bool - HTTP request succeeded
        - issues: list of problems found
        - details: additional diagnostic info
    """
    issues = []
    details = {}

    # Parse target to extract hostname and port
    target_port = None  # Custom port from URL, if any
    if target.startswith('http://') or target.startswith('https://'):
        parsed = urlparse(target)
        hostname = parsed.hostname or parsed.netloc
        target_port = parsed.port  # Will be None if not specified
        scheme = parsed.scheme
    else:
        hostname = target
        # Check if hostname contains a port
        if ':' in hostname:
            hostname, port_str = hostname.rsplit(':', 1)
            try:
                target_port = int(port_str)
            except ValueError:
                pass
        scheme = 'https'

    details["hostname"] = hostname
    details["scheme"] = scheme
    if target_port:
        details["target_port"] = target_port

    # 1. DNS Resolution
    dns_ok = False
    ip_addresses = []
    try:
        # Use dig for detailed DNS info
        out, err, rc = await run(["dig", "+short", hostname], timeout=timeout)
        if rc == 0 and out:
            ip_addresses = [ip.strip() for ip in out.strip().split('\n') if ip.strip() and not ip.startswith(';')]
            # Filter out CNAME records (they don't look like IPs)
            ip_addresses = [ip for ip in ip_addresses if re.match(r'^[\d.]+$|^[a-f0-9:]+$', ip, re.I)]
            dns_ok = len(ip_addresses) > 0
            details["ip_addresses"] = ip_addresses

        if not dns_ok:
            # Fallback to socket resolution
            try:
                result = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
                ip_addresses = list(set([r[4][0] for r in result]))
                dns_ok = len(ip_addresses) > 0
                details["ip_addresses"] = ip_addresses
                details["dns_method"] = "socket_fallback"
            except socket.gaierror as e:
                issues.append(f"DNS resolution failed: {e}")
                details["dns_error"] = str(e)
    except Exception as e:
        issues.append(f"DNS check failed: {e}")
        details["dns_error"] = str(e)

    if not dns_ok:
        issues.append(f"Cannot resolve hostname: {hostname}")

    # 2. Port Connectivity (only if DNS worked)
    port_443_open = False
    port_80_open = False
    target_port_open = False

    async def check_port(host: str, port: int) -> bool:
        """Check if a port is open using nc or socket fallback."""
        try:
            out, err, rc = await run(
                ["nc", "-zv", "-w", str(min(timeout, 5)), host, str(port)],
                timeout=timeout
            )
            return rc == 0 or "succeeded" in (out + err).lower() or "open" in (out + err).lower()
        except Exception:
            # Fallback: try direct socket connection
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(min(timeout, 5))
                result = sock.connect_ex((host, port))
                sock.close()
                return result == 0
            except Exception:
                return False

    if dns_ok:
        # If a custom port is specified in the URL, check it first
        if target_port and target_port not in (80, 443):
            target_port_open = await check_port(hostname, target_port)
            details["target_port_open"] = target_port_open
            if not target_port_open:
                issues.append(f"Port {target_port} is not reachable on {hostname}")

        # Always check standard ports too (for fallback/info)
        port_443_open = await check_port(hostname, 443)
        port_80_open = await check_port(hostname, 80)

        # Only complain about standard ports if no custom port was specified or open
        if not target_port_open and not port_443_open and not port_80_open:
            if target_port:
                issues.append(f"Neither port {target_port}, 443 nor 80 is reachable on {hostname}")
            else:
                issues.append(f"Neither port 443 nor 80 is reachable on {hostname}")

    # 3. HTTP Response Check (DNS required)
    http_ok = False
    http_status = None
    http_url = None
    any_port_open = target_port_open or port_443_open or port_80_open

    if dns_ok:
        candidate_urls = []
        if target_port:
            candidate_urls.append(f"{scheme}://{hostname}:{target_port}")
            # Try the opposite scheme too; non-standard ports are often misconfigured.
            if scheme == "https":
                candidate_urls.append(f"http://{hostname}:{target_port}")
            else:
                candidate_urls.append(f"https://{hostname}:{target_port}")
        else:
            # Prefer the requested scheme, then fall back.
            if scheme == "https":
                candidate_urls = [f"https://{hostname}", f"http://{hostname}"]
            else:
                candidate_urls = [f"http://{hostname}", f"https://{hostname}"]

        seen_urls = set()
        last_url = None
        for url in candidate_urls:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            last_url = url
            try:
                out, err, rc = await run(
                    ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}",
                     "--connect-timeout", str(min(timeout, 10)),
                     "-L", "-k", url],
                    timeout=timeout + 5
                )
                if rc == 0 and out:
                    try:
                        status_code = int(out.strip())
                        if 100 <= status_code < 600:
                            http_ok = True
                            http_status = status_code
                            http_url = url
                            break
                    except ValueError:
                        details["http_raw"] = out[:100]
            except Exception as e:
                details["http_error"] = str(e)

        if http_status is not None:
            details["http_status"] = http_status
            details["http_url"] = http_url
        elif last_url:
            details["http_url"] = last_url

        if not http_ok and last_url:
            issues.append(f"HTTP request to {last_url} failed or returned invalid status")

    # Calculate overall reachability
    # Target is reachable if DNS works and we can get a valid HTTP response.
    reachable = dns_ok and http_ok

    return {
        "reachable": reachable,
        "dns_ok": dns_ok,
        "port_443_open": port_443_open,
        "port_80_open": port_80_open,
        "target_port_open": target_port_open if target_port else None,
        "target_port": target_port,
        "http_ok": http_ok,
        "issues": issues,
        "details": details,
        "recommendation": None if reachable else _get_connectivity_recommendation(dns_ok, port_443_open, port_80_open, http_ok, target_port_open, target_port)
    }


def _get_connectivity_recommendation(dns_ok: bool, port_443: bool, port_80: bool, http_ok: bool, target_port_open: bool = False, target_port: int | None = None) -> str:
    """Generate a recommendation based on connectivity check results."""
    if not dns_ok:
        return "Check DNS configuration. The hostname may not exist or DNS servers may be unreachable."
    if not port_443 and not port_80 and not target_port_open:
        if target_port:
            return f"Port {target_port} is not reachable. Check if the service is running and firewall rules allow access."
        return "Target host is not accepting connections. Check if the host is online and firewall rules allow access."
    if not http_ok:
        return "HTTP service not responding. The server may be down or blocking requests."
    return "Unknown connectivity issue."


async def pre_scan_validation(target: str) -> dict[str, Any]:
    """
    Run pre-scan validation to ensure we can reach the target.

    This should be called before starting a scan to detect network issues early.

    Returns:
        Dict with validation results and whether scanning should proceed
    """
    connectivity = await validate_target_connectivity(target)

    return {
        "target": target,
        "connectivity": connectivity,
        "can_proceed": connectivity["reachable"],
        "warnings": connectivity["issues"],
        "recommendation": connectivity.get("recommendation")
    }
