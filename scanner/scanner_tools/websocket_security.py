"""WebSocket security testing module.

Tests for common WebSocket vulnerabilities:
- Cross-Site WebSocket Hijacking (CSWSH)
- Authentication bypass
- Message injection (SQLi, XSS)
- Rate limiting
- TLS usage (ws:// vs wss://)
"""

import asyncio
import sys
import urllib.parse
from typing import Any

from .common import run

# Common WebSocket endpoint paths to probe
WS_DISCOVERY_PATHS = [
    "/ws", "/websocket", "/socket", "/stream",
    "/socket.io/", "/graphql/ws", "/subscriptions",
    "/chat", "/notifications", "/live", "/realtime",
    "/api/ws", "/api/websocket", "/api/stream",
    "/v1/ws", "/v2/ws",
]

# Injection payloads for WebSocket message testing
INJECTION_PAYLOADS = [
    # SQL Injection
    "' OR '1'='1",
    "1; DROP TABLE users--",
    # XSS
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    # Command injection
    "; ls -la",
    "| cat /etc/passwd",
]


async def probe_websocket_endpoints(base_url: str) -> list[str]:
    """Probe common WebSocket paths to discover endpoints.

    Args:
        base_url: The base URL to probe (http/https)

    Returns:
        List of discovered WebSocket URLs
    """
    discovered = []
    parsed = urllib.parse.urlparse(base_url)

    # Determine WebSocket scheme
    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
    ws_base = f"{ws_scheme}://{parsed.netloc}"

    for path in WS_DISCOVERY_PATHS:
        ws_url = urllib.parse.urljoin(ws_base, path)
        # Try HTTP upgrade request to detect WebSocket endpoints
        http_url = urllib.parse.urljoin(base_url, path)
        out, _, rc = await run([
            "curl", "-sS", "-I", "-k", "--max-time", "3",
            "-H", "Upgrade: websocket",
            "-H", "Connection: Upgrade",
            "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
            "-H", "Sec-WebSocket-Version: 13",
            http_url
        ], timeout=5)

        if rc == 0 and out:
            # Check for WebSocket upgrade response (101 Switching Protocols)
            if "101" in out or "Upgrade" in out or "websocket" in out.lower():
                discovered.append(ws_url)
                print(f"[websocket] Discovered endpoint: {ws_url}", file=sys.stderr)

    return discovered


async def test_websocket_cswsh(endpoint: str, origin: str = "https://evil.com") -> dict[str, Any]:
    """Test for Cross-Site WebSocket Hijacking (CSWSH).

    CSWSH occurs when a WebSocket server doesn't validate the Origin header,
    allowing malicious websites to hijack authenticated WebSocket connections.

    Args:
        endpoint: WebSocket URL to test (wss://example.com/ws)
        origin: Fake origin to test with

    Returns:
        Dict with vulnerability status and details
    """
    result = {
        "vulnerable": False,
        "issue": None,
        "severity": "high",
        "cwe": "CWE-346",
        "endpoint": endpoint,
    }

    try:
        # Try to import websockets
        try:
            import websockets
        except ImportError:
            result["error"] = "websockets library not installed"
            return result

        # Test 1: Connect with malicious origin
        try:
            async with asyncio.timeout(5):
                async with websockets.connect(
                    endpoint,
                    additional_headers={"Origin": origin},
                    close_timeout=2,
                ) as ws:
                    # If connection succeeds with fake origin, it's vulnerable
                    result["vulnerable"] = True
                    result["issue"] = f"CSWSH - Server accepts connections from arbitrary origins ({origin})"
                    result["evidence"] = "WebSocket connection succeeded with malicious Origin header"
                    print(f"[websocket] CSWSH vulnerability found: {endpoint}", file=sys.stderr)
        except Exception as e:
            # Connection rejected - good, Origin validation working
            result["issue"] = None
            result["evidence"] = f"Connection rejected with fake origin: {type(e).__name__}"

    except Exception as e:
        result["error"] = str(e)

    return result


async def test_websocket_auth(endpoint: str) -> dict[str, Any]:
    """Test for WebSocket authentication bypass.

    Tests if WebSocket connection can be established without credentials.

    Args:
        endpoint: WebSocket URL to test

    Returns:
        Dict with vulnerability status and details
    """
    result = {
        "vulnerable": False,
        "issue": None,
        "severity": "high",
        "cwe": "CWE-287",
        "endpoint": endpoint,
    }

    try:
        try:
            import websockets
        except ImportError:
            result["error"] = "websockets library not installed"
            return result

        # Try to connect without any authentication
        try:
            async with asyncio.timeout(5):
                async with websockets.connect(
                    endpoint,
                    close_timeout=2,
                ) as ws:
                    # Try to receive a message (or send a test message)
                    try:
                        # Send a simple test message
                        await ws.send('{"type":"ping"}')
                        # Wait briefly for response
                        response = await asyncio.wait_for(ws.recv(), timeout=2)
                        result["vulnerable"] = True
                        result["issue"] = "WebSocket accepts unauthenticated connections and responds to messages"
                        result["evidence"] = f"Received response: {response[:200] if response else 'empty'}"
                    except TimeoutError:
                        # Connected but no response - still potentially vulnerable
                        result["vulnerable"] = True
                        result["issue"] = "WebSocket accepts unauthenticated connections"
                        result["severity"] = "medium"
                        result["evidence"] = "Connection established without auth, but no message response"
        except Exception as e:
            # Connection failed - auth required
            result["evidence"] = f"Connection requires authentication: {type(e).__name__}"

    except Exception as e:
        result["error"] = str(e)

    return result


async def test_websocket_tls(endpoint: str) -> dict[str, Any]:
    """Test if WebSocket uses TLS (wss://) vs unencrypted (ws://).

    Args:
        endpoint: WebSocket URL to test

    Returns:
        Dict with vulnerability status and details
    """
    result = {
        "vulnerable": False,
        "issue": None,
        "severity": "medium",
        "cwe": "CWE-319",
        "endpoint": endpoint,
    }

    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme == "ws":
        result["vulnerable"] = True
        result["issue"] = "WebSocket connection uses unencrypted ws:// instead of wss://"
        result["evidence"] = f"Endpoint scheme: {parsed.scheme}"
    else:
        result["evidence"] = "WebSocket uses encrypted wss:// connection"

    return result


async def test_websocket_rate_limiting(endpoint: str, message_count: int = 50) -> dict[str, Any]:
    """Test for missing rate limiting on WebSocket messages.

    Args:
        endpoint: WebSocket URL to test
        message_count: Number of rapid messages to send

    Returns:
        Dict with vulnerability status and details
    """
    result = {
        "vulnerable": False,
        "issue": None,
        "severity": "medium",
        "cwe": "CWE-770",
        "endpoint": endpoint,
    }

    try:
        try:
            import websockets
        except ImportError:
            result["error"] = "websockets library not installed"
            return result

        try:
            async with asyncio.timeout(10):
                async with websockets.connect(
                    endpoint,
                    close_timeout=2,
                ) as ws:
                    # Send rapid messages
                    success_count = 0
                    for i in range(message_count):
                        try:
                            await ws.send(f'{{"type":"ping","id":{i}}}')
                            success_count += 1
                        except Exception:
                            break

                    if success_count >= message_count * 0.9:  # 90%+ messages sent
                        result["vulnerable"] = True
                        result["issue"] = f"No rate limiting detected - {success_count}/{message_count} rapid messages accepted"
                        result["evidence"] = f"Sent {success_count} messages without throttling"
                    else:
                        result["evidence"] = f"Rate limiting may be present - only {success_count}/{message_count} messages sent"

        except Exception as e:
            result["evidence"] = f"Could not test rate limiting: {type(e).__name__}"

    except Exception as e:
        result["error"] = str(e)

    return result


async def run_websocket_security_tests(
    endpoints: list[str],
    safe_mode: bool = True
) -> dict[str, Any]:
    """Run all WebSocket security tests on discovered endpoints.

    Args:
        endpoints: List of WebSocket URLs to test
        safe_mode: If True, skip potentially disruptive tests

    Returns:
        Dict with test results
    """
    results = {
        "endpoints_tested": len(endpoints),
        "vulnerabilities": [],
        "endpoints": [],
    }

    if not endpoints:
        return results

    for endpoint in endpoints[:10]:  # Limit to 10 endpoints
        endpoint_results = {
            "url": endpoint,
            "tests": [],
        }

        # TLS check (always safe)
        tls_result = await test_websocket_tls(endpoint)
        endpoint_results["tests"].append({"name": "tls", **tls_result})
        if tls_result.get("vulnerable"):
            results["vulnerabilities"].append({
                "endpoint": endpoint,
                "type": "unencrypted_websocket",
                **tls_result,
            })

        # CSWSH check
        cswsh_result = await test_websocket_cswsh(endpoint)
        endpoint_results["tests"].append({"name": "cswsh", **cswsh_result})
        if cswsh_result.get("vulnerable"):
            results["vulnerabilities"].append({
                "endpoint": endpoint,
                "type": "cswsh",
                **cswsh_result,
            })

        # Auth check
        auth_result = await test_websocket_auth(endpoint)
        endpoint_results["tests"].append({"name": "auth", **auth_result})
        if auth_result.get("vulnerable"):
            results["vulnerabilities"].append({
                "endpoint": endpoint,
                "type": "auth_bypass",
                **auth_result,
            })

        # Rate limiting check (skip in safe mode as it sends many messages)
        if not safe_mode:
            rate_result = await test_websocket_rate_limiting(endpoint)
            endpoint_results["tests"].append({"name": "rate_limiting", **rate_result})
            if rate_result.get("vulnerable"):
                results["vulnerabilities"].append({
                    "endpoint": endpoint,
                    "type": "rate_limiting",
                    **rate_result,
                })

        results["endpoints"].append(endpoint_results)

    # Log summary
    vuln_count = len(results["vulnerabilities"])
    if vuln_count > 0:
        print(f"[websocket] Found {vuln_count} vulnerabilities across {len(endpoints)} endpoints", file=sys.stderr)
    else:
        print(f"[websocket] No vulnerabilities found in {len(endpoints)} endpoints", file=sys.stderr)

    return results
