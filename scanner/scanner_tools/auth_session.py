"""
Authenticated Session Management for DAST Scanning.

This module provides authentication session management for authenticated
security scanning. It supports multiple authentication methods:
- Cookie injection (session cookies provided by user)
- Header authentication (Bearer tokens, API keys, custom headers)
- Session validation and expiry detection

Phase 2.1a of the Authenticated DAST Foundation.

Usage:
    session = AuthSession(
        cookies={"session_id": "abc123"},
        headers={"Authorization": "Bearer token123"}
    )

    # Use in HTTP requests
    response = await session.request("GET", "https://example.com/api/profile")

    # Check session validity
    if not session.is_valid():
        # Session expired, need re-authentication
        pass
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin

# Try to import aiohttp, but make it optional
try:
    import ssl

    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None
    ssl = None


# Session expiry indicators - responses that suggest session is no longer valid.
# 401 is the canonical "no/expired session" signal. 403 is RBAC ("you are
# authenticated but lack permission") and on its own should NOT force a
# credential replay — that risks account lockout and audit-log noise when the
# scanner crawls into a protected admin path. We keep a small 403 weight so it
# can combine with a body indicator (e.g. 403 + "session expired"), but no
# single 403 reaches the default 0.7 threshold.
SESSION_EXPIRY_INDICATORS = [
    # Status codes
    {"type": "status", "value": 401, "weight": 1.0},
    {"type": "status", "value": 403, "weight": 0.3},

    # Response body patterns (login redirects, session expired messages)
    {"type": "body_pattern", "value": r"(?i)session\s*(has\s*)?expired", "weight": 1.0},
    {"type": "body_pattern", "value": r"(?i)please\s*(re-?)?login", "weight": 0.9},
    {"type": "body_pattern", "value": r"(?i)authentication\s*required", "weight": 0.9},
    {"type": "body_pattern", "value": r"(?i)unauthorized", "weight": 0.7},
    {"type": "body_pattern", "value": r"(?i)access\s*denied", "weight": 0.6},
    {"type": "body_pattern", "value": r"(?i)invalid\s*(session|token)", "weight": 1.0},
    {"type": "body_pattern", "value": r"(?i)token\s*(has\s*)?expired", "weight": 1.0},

    # Redirect to login page patterns
    {"type": "redirect_pattern", "value": r"(?i)/login", "weight": 0.8},
    {"type": "redirect_pattern", "value": r"(?i)/signin", "weight": 0.8},
    {"type": "redirect_pattern", "value": r"(?i)/auth", "weight": 0.7},
    {"type": "redirect_pattern", "value": r"(?i)/sso", "weight": 0.7},

    # Header patterns
    {"type": "header_pattern", "name": "www-authenticate", "value": r".*", "weight": 0.9},
    {"type": "header_pattern", "name": "x-auth-error", "value": r".*", "weight": 1.0},
]

# Common authenticated endpoints to test session validity
SESSION_CHECK_ENDPOINTS = [
    "/api/me",
    "/api/user",
    "/api/profile",
    "/api/account",
    "/api/v1/me",
    "/api/v1/user",
    "/user/profile",
    "/account",
    "/dashboard",
    "/home",
]


async def _run_command(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a command asynchronously and return stdout, stderr, returncode."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode('utf-8', errors='replace'), stderr.decode('utf-8', errors='replace'), proc.returncode or 0
    except TimeoutError:
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        return "", "timeout", -1
    except asyncio.CancelledError:
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        raise
    except Exception as e:
        return "", str(e), -1


@dataclass
class SessionState:
    """Tracks the current state of an authentication session."""
    valid: bool = True
    last_check: float = field(default_factory=time.time)
    check_count: int = 0
    expiry_score: float = 0.0
    expiry_indicators: list[str] = field(default_factory=list)
    cookies_received: dict[str, str] = field(default_factory=dict)
    last_response_status: int | None = None


@dataclass
class AuthConfig:
    """Configuration for authentication session."""
    # Cookie-based auth
    cookies: dict[str, str] = field(default_factory=dict)

    # Header-based auth (Bearer tokens, API keys, etc.)
    headers: dict[str, str] = field(default_factory=dict)

    # Session validation settings
    validate_session: bool = True
    validation_endpoint: str | None = None
    validation_interval: int = 60  # seconds between validation checks
    expiry_threshold: float = 0.7  # Score threshold to consider session expired

    # Request settings
    timeout: int = 30
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = True

    # Cookie handling
    preserve_cookies: bool = True  # Store cookies from responses
    cookie_domain: str | None = None  # Restrict cookies to domain


class AuthSession:
    """
    Manages authenticated HTTP sessions for security scanning.

    Provides:
    - Cookie and header injection into all requests
    - Automatic session validation
    - Session expiry detection
    - Cookie preservation from responses

    Uses curl subprocess for compatibility (aiohttp if available for performance).
    """

    def __init__(
        self,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        config: AuthConfig | None = None,
        base_url: str | None = None
    ):
        """
        Initialize an authenticated session.

        Args:
            cookies: Session cookies to inject (e.g., {"session_id": "abc123"})
            headers: Auth headers to inject (e.g., {"Authorization": "Bearer token"})
            config: Full configuration object (overrides cookies/headers if provided)
            base_url: Base URL for the target application
        """
        if config:
            self.config = config
        else:
            self.config = AuthConfig(
                cookies=cookies or {},
                headers=headers or {}
            )

        self.base_url = base_url
        self.state = SessionState()
        self._aiohttp_session = None
        self._lock = asyncio.Lock()
        self._refresh_callback: Callable[[], Awaitable["AuthSession | None"]] | None = None
        self._refresh_lock = asyncio.Lock()
        self._refresh_cooldown = 60
        self._last_refresh = 0.0
        self._refresh_failures = 0
        self._refresh_max_failures = 3

        # Track request history for analysis
        self._request_history: list[dict[str, Any]] = []
        self._max_history = 100

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def close(self):
        """Close the session."""
        if AIOHTTP_AVAILABLE and self._aiohttp_session and not self._aiohttp_session.closed:
            await self._aiohttp_session.close()
            self._aiohttp_session = None

    def _build_cookie_string(self, extra_cookies: dict[str, str] | None = None) -> str:
        """Build cookie string for requests."""
        cookies = dict(self.config.cookies)

        # Add cookies received from responses
        if self.config.preserve_cookies:
            cookies.update(self.state.cookies_received)

        # Add extra cookies
        if extra_cookies:
            cookies.update(extra_cookies)

        if not cookies:
            return ""

        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def _build_headers(self, extra_headers: dict[str, str] | None = None) -> dict[str, str]:
        """Build request headers including auth headers."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        # Add configured auth headers
        headers.update(self.config.headers)

        # Add extra headers (can override)
        if extra_headers:
            headers.update(extra_headers)

        return headers

    async def _request_curl(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        cookie_string: str,
        data: Any | None = None,
        json_data: dict[str, Any] | None = None,
        timeout: int = 30
    ) -> dict[str, Any]:
        """Make HTTP request using curl subprocess."""
        cmd = [
            "curl", "-s", "-S",
            "-X", method,
            "-w", "\n---HTTP_CODE:%{http_code}---EFFECTIVE_URL:%{url_effective}---",
            "-D", "-",  # Write headers to stdout
            "--max-time", str(timeout),
            "--max-redirs", str(self.config.max_redirects),
        ]

        if self.config.follow_redirects:
            cmd.append("-L")

        if not self.config.verify_ssl:
            cmd.append("-k")

        # Add headers
        for name, value in headers.items():
            cmd.extend(["-H", f"{name}: {value}"])

        # Add cookies
        if cookie_string:
            cmd.extend(["-H", f"Cookie: {cookie_string}"])

        # Add data
        if json_data:
            cmd.extend(["-H", "Content-Type: application/json"])
            cmd.extend(["-d", json.dumps(json_data)])
        elif data:
            if isinstance(data, dict):
                cmd.extend(["-d", "&".join(f"{k}={v}" for k, v in data.items())])
            else:
                cmd.extend(["-d", str(data)])

        cmd.append(url)

        start_time = time.time()
        stdout, stderr, returncode = await _run_command(cmd, timeout + 5)
        elapsed = time.time() - start_time

        if returncode != 0 and not stdout:
            return {
                "status": 0,
                "error": stderr or f"curl failed with code {returncode}",
                "elapsed": elapsed,
                "session_valid": self.state.valid
            }

        # Parse response
        return self._parse_curl_response(stdout, url, method, elapsed)

    def _parse_curl_response(self, output: str, request_url: str, method: str, elapsed: float) -> dict[str, Any]:
        """Parse curl output into structured response."""
        result = {
            "status": 0,
            "headers": {},
            "body": "",
            "url": request_url,
            "redirects": [],
            "elapsed": elapsed,
            "method": method,
            "request_url": request_url
        }

        # Extract metadata from -w output
        http_code_match = re.search(r"---HTTP_CODE:(\d+)---", output)
        # Use non-greedy match up to the closing --- to handle URLs with hyphens
        effective_url_match = re.search(r"---EFFECTIVE_URL:(.+?)---$", output)

        if http_code_match:
            result["status"] = int(http_code_match.group(1))

        if effective_url_match:
            result["url"] = effective_url_match.group(1).strip()

        # Remove metadata from output
        # Use .* instead of [^-]+ to handle hyphenated URLs correctly
        output = re.sub(r"\n---HTTP_CODE:\d+---EFFECTIVE_URL:.*---$", "", output)

        # Split headers and body
        # curl with -D - outputs headers first, then body
        parts = output.split("\r\n\r\n", 1)
        if len(parts) == 2:
            header_section, body = parts
        else:
            # Try alternative split
            parts = output.split("\n\n", 1)
            if len(parts) == 2:
                header_section, body = parts
            else:
                header_section = ""
                body = output

        result["body"] = body.strip()

        # Parse headers (may have multiple response headers due to redirects)
        header_blocks = re.split(r"HTTP/[\d.]+\s+\d+", header_section)
        status_matches = re.findall(r"HTTP/[\d.]+\s+(\d+)", header_section)

        # Process redirect chain
        for i, status in enumerate(status_matches[:-1] if len(status_matches) > 1 else []):
            result["redirects"].append({"status": int(status)})

        # Parse final headers
        if header_blocks:
            final_headers = header_blocks[-1] if header_blocks else ""
            for line in final_headers.strip().split("\n"):
                if ":" in line:
                    name, value = line.split(":", 1)
                    name = name.strip().lower()
                    value = value.strip()
                    result["headers"][name] = value

                    # Extract cookies from Set-Cookie header
                    if name == "set-cookie" and self.config.preserve_cookies:
                        cookie_match = re.match(r"([^=]+)=([^;]*)", value)
                        if cookie_match:
                            self.state.cookies_received[cookie_match.group(1)] = cookie_match.group(2)

        return result

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        data: Any | None = None,
        json_data: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
        allow_redirects: bool | None = None,
        timeout: int | None = None
    ) -> dict[str, Any]:
        """
        Make an authenticated HTTP request.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL to request (absolute or relative to base_url)
            headers: Additional headers (merged with auth headers)
            cookies: Additional cookies (merged with session cookies)
            data: Form data to send
            json_data: JSON data to send
            params: URL query parameters
            allow_redirects: Override redirect behavior
            timeout: Override timeout

        Returns:
            Dict containing response data:
            {
                "status": 200,
                "headers": {...},
                "body": "...",
                "url": "final URL after redirects",
                "redirects": [...],
                "elapsed": 0.123,
                "session_valid": True
            }
        """
        # Resolve URL
        if self.base_url and not url.startswith(('http://', 'https://')):
            url = urljoin(self.base_url, url)

        # Add query params
        if params:
            separator = "&" if "?" in url else "?"
            url = url + separator + "&".join(f"{k}={v}" for k, v in params.items())

        # Build headers and cookies
        req_headers = self._build_headers(headers)
        cookie_string = self._build_cookie_string(cookies)
        req_timeout = timeout or self.config.timeout

        # Temporarily override redirect setting if specified
        original_redirect = self.config.follow_redirects
        if allow_redirects is not None:
            self.config.follow_redirects = allow_redirects

        try:
            result = await self._request_curl(
                method, url, req_headers, cookie_string,
                data=data, json_data=json_data, timeout=req_timeout
            )
        finally:
            self.config.follow_redirects = original_redirect

        # Update session state
        self.state.last_response_status = result.get("status", 0)

        # Check for session expiry indicators
        expiry_score = self._check_expiry_indicators(result)
        if expiry_score >= self.config.expiry_threshold:
            self.state.valid = False
            self.state.expiry_score = expiry_score
            if self._refresh_callback:
                await self.refresh_if_needed(force=True, skip_validation=True, reason="expiry_indicator")

        result["session_valid"] = self.state.valid

        # Add to history
        self._add_to_history(result)

        return result

    def set_refresh_callback(
        self,
        callback: Callable[[], Awaitable["AuthSession | None"]],
        cooldown_seconds: int = 60,
        max_failures: int = 3
    ):
        """Register an async callback to refresh authentication when sessions expire."""
        self._refresh_callback = callback
        self._refresh_cooldown = max(5, cooldown_seconds)
        self._refresh_max_failures = max(1, max_failures)

    async def refresh_if_needed(
        self,
        force: bool = False,
        skip_validation: bool = False,
        reason: str | None = None
    ) -> bool:
        """Refresh authentication if the session is invalid or expired."""
        if not self._refresh_callback:
            return self.state.valid

        if not skip_validation and not force and self.needs_validation():
            try:
                await self.validate_session()
            except Exception:
                pass

        if not force and self.state.valid:
            return True

        if self._refresh_failures >= self._refresh_max_failures:
            return False

        now = time.time()
        if not force and (now - self._last_refresh) < self._refresh_cooldown:
            return self.state.valid

        async with self._refresh_lock:
            now = time.time()
            if not force and (now - self._last_refresh) < self._refresh_cooldown:
                return self.state.valid

            self._last_refresh = now
            try:
                refreshed = await self._refresh_callback()
            except Exception:
                self._refresh_failures += 1
                return False

            if not isinstance(refreshed, AuthSession):
                self._refresh_failures += 1
                return False

            self._adopt_session(refreshed)
            self._refresh_failures = 0
            return True

    def _adopt_session(self, refreshed: "AuthSession"):
        """Adopt cookies/headers from a refreshed AuthSession."""
        if refreshed is self:
            return
        self.config.cookies = dict(refreshed.config.cookies)
        self.config.headers = dict(refreshed.config.headers)
        self.state.cookies_received = dict(refreshed.state.cookies_received)
        self.state.valid = True
        self.state.expiry_score = 0.0
        self.state.expiry_indicators = []
        self.state.last_check = time.time()

    async def get(self, url: str, **kwargs) -> dict[str, Any]:
        """Make authenticated GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> dict[str, Any]:
        """Make authenticated POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> dict[str, Any]:
        """Make authenticated PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> dict[str, Any]:
        """Make authenticated DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> dict[str, Any]:
        """Make authenticated PATCH request."""
        return await self.request("PATCH", url, **kwargs)

    def _check_expiry_indicators(self, response: dict[str, Any]) -> float:
        """
        Check response for session expiry indicators.

        Returns a score from 0.0 to 1.0 indicating likelihood of session expiry.

        Body-pattern indicators only count on non-2xx responses. A 200 page
        that happens to contain "please re-login" in help text, an admin
        docs page describing the logout flow, or an HTML error envelope
        rendered alongside the real content should not trigger a credential
        replay.
        """
        score = 0.0
        indicators_found = []

        status = response.get("status", 0)
        body = response.get("body", "")
        headers = response.get("headers", {})
        redirects = response.get("redirects", [])
        final_url = response.get("url", "")
        # 2xx responses (including the 200 default for some non-HTTP captures)
        # are treated as successful page loads. Body-pattern matching only
        # applies when the server returned an error.
        body_patterns_allowed = not (200 <= int(status or 0) < 300)

        for indicator in SESSION_EXPIRY_INDICATORS:
            ind_type = indicator["type"]
            weight = indicator["weight"]

            if ind_type == "status":
                if status == indicator["value"]:
                    score = max(score, weight)
                    indicators_found.append(f"Status {status}")

            elif ind_type == "body_pattern":
                if not body_patterns_allowed:
                    continue
                pattern = indicator["value"]
                if re.search(pattern, body):
                    score = max(score, weight)
                    indicators_found.append(f"Body pattern: {pattern[:30]}")

            elif ind_type == "redirect_pattern":
                pattern = indicator["value"]
                # Check final URL and redirect chain
                urls_to_check = [final_url]
                for r in redirects:
                    if isinstance(r, dict) and "url" in r:
                        urls_to_check.append(r["url"])
                for url in urls_to_check:
                    if re.search(pattern, url):
                        score = max(score, weight)
                        indicators_found.append(f"Redirect to: {url[:50]}")
                        break

            elif ind_type == "header_pattern":
                header_name = indicator.get("name", "").lower()
                pattern = indicator["value"]
                for name, value in headers.items():
                    if name.lower() == header_name and re.search(pattern, str(value)):
                        score = max(score, weight)
                        indicators_found.append(f"Header: {name}")

        self.state.expiry_indicators = indicators_found
        return score

    async def validate_session(self, endpoint: str | None = None) -> bool:
        """
        Validate the session is still active.

        Args:
            endpoint: Specific endpoint to check (or auto-detect)

        Returns:
            True if session appears valid, False otherwise
        """
        self.state.check_count += 1
        self.state.last_check = time.time()

        # Use configured endpoint or try common ones
        endpoints_to_try = []
        if endpoint:
            endpoints_to_try = [endpoint]
        elif self.config.validation_endpoint:
            endpoints_to_try = [self.config.validation_endpoint]
        else:
            endpoints_to_try = SESSION_CHECK_ENDPOINTS[:5]

        for ep in endpoints_to_try:
            response = await self.get(ep)

            # Success responses indicate valid session
            if 200 <= response.get("status", 0) < 300:
                self.state.valid = True
                self.state.expiry_score = 0.0
                return True

            # Check if we got a clear auth failure
            if response.get("status") == 401:
                self.state.valid = False
                self.state.expiry_score = 1.0
                return False

        # Ambiguous result - use expiry score
        return self.state.valid

    def is_valid(self) -> bool:
        """Check if the session is currently considered valid."""
        return self.state.valid

    def needs_validation(self) -> bool:
        """Check if session should be re-validated."""
        if not self.config.validate_session:
            return False

        elapsed = time.time() - self.state.last_check
        return elapsed >= self.config.validation_interval

    def _add_to_history(self, response: dict[str, Any]):
        """Add response to request history."""
        entry = {
            "timestamp": time.time(),
            "method": response.get("method"),
            "url": response.get("request_url"),
            "status": response.get("status"),
            "elapsed": response.get("elapsed"),
            "session_valid": response.get("session_valid")
        }

        self._request_history.append(entry)

        # Trim history
        if len(self._request_history) > self._max_history:
            self._request_history = self._request_history[-self._max_history:]

    def get_stats(self) -> dict[str, Any]:
        """Get session statistics."""
        total_requests = len(self._request_history)
        successful = sum(1 for r in self._request_history if 200 <= r.get("status", 0) < 400)
        failed = sum(1 for r in self._request_history if r.get("status", 0) >= 400)

        return {
            "session_valid": self.state.valid,
            "expiry_score": self.state.expiry_score,
            "expiry_indicators": self.state.expiry_indicators,
            "validation_checks": self.state.check_count,
            "total_requests": total_requests,
            "successful_requests": successful,
            "failed_requests": failed,
            "cookies_active": len(self.config.cookies) + len(self.state.cookies_received),
            "headers_active": len(self.config.headers),
            "last_status": self.state.last_response_status
        }

    def export_session(self) -> dict[str, Any]:
        """Export session data for persistence."""
        return {
            "cookies": {**self.config.cookies, **self.state.cookies_received},
            "headers": self.config.headers,
            "base_url": self.base_url,
            "valid": self.state.valid,
            "exported_at": datetime.now(UTC).isoformat()
        }

    @classmethod
    def from_export(cls, data: dict[str, Any]) -> "AuthSession":
        """Create session from exported data."""
        return cls(
            cookies=data.get("cookies", {}),
            headers=data.get("headers", {}),
            base_url=data.get("base_url")
        )


def parse_cookie_string(cookie_string: str) -> dict[str, str]:
    """
    Parse a cookie string (from browser dev tools) into a dict.

    Args:
        cookie_string: Cookie string like "name1=value1; name2=value2"

    Returns:
        Dict of cookie name -> value
    """
    cookies = {}

    if not cookie_string:
        return cookies

    # Split by semicolon
    parts = cookie_string.split(";")

    for part in parts:
        part = part.strip()
        if "=" in part:
            name, value = part.split("=", 1)
            cookies[name.strip()] = value.strip()

    return cookies


def parse_auth_header(header_string: str) -> tuple[str, str]:
    """
    Parse an Authorization header value.

    Args:
        header_string: Header value like "Bearer token123" or "Basic base64=="

    Returns:
        Tuple of (auth_type, credentials)
    """
    parts = header_string.split(" ", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return "Unknown", header_string


async def create_authenticated_session(
    base_url: str,
    cookies: str | None = None,
    cookie_dict: dict[str, str] | None = None,
    auth_header: str | None = None,
    custom_headers: dict[str, str] | None = None,
    validate: bool = True
) -> AuthSession:
    """
    Create an authenticated session with convenience options.

    Args:
        base_url: Target application base URL
        cookies: Cookie string from browser (e.g., "session=abc; token=xyz")
        cookie_dict: Cookies as dict (alternative to string)
        auth_header: Authorization header value (e.g., "Bearer token123")
        custom_headers: Additional custom headers
        validate: Whether to validate session immediately

    Returns:
        Configured AuthSession

    Example:
        session = await create_authenticated_session(
            "https://app.example.com",
            cookies="session_id=abc123; csrf_token=xyz",
            auth_header="Bearer eyJhbGciOiJ..."
        )
    """
    # Parse cookies
    final_cookies = {}
    if cookies:
        final_cookies.update(parse_cookie_string(cookies))
    if cookie_dict:
        final_cookies.update(cookie_dict)

    # Build headers
    final_headers = {}
    if auth_header:
        final_headers["Authorization"] = auth_header
    if custom_headers:
        final_headers.update(custom_headers)

    # Create session
    session = AuthSession(
        cookies=final_cookies,
        headers=final_headers,
        base_url=base_url
    )

    # Optionally validate
    if validate and (final_cookies or final_headers):
        await session.validate_session()

    return session


async def test_auth_session(
    base_url: str,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    test_endpoints: list[str] | None = None
) -> dict[str, Any]:
    """
    Test authentication credentials against a target.

    Args:
        base_url: Target base URL
        cookies: Session cookies
        headers: Auth headers
        test_endpoints: Endpoints to test (or use defaults)

    Returns:
        Test results dict
    """
    results = {
        "base_url": base_url,
        "authenticated": False,
        "session_valid": False,
        "endpoints_tested": [],
        "successful_endpoints": [],
        "failed_endpoints": [],
        "cookies_provided": len(cookies or {}),
        "headers_provided": len(headers or {}),
        "findings": []
    }

    if not cookies and not headers:
        results["findings"].append({
            "type": "warning",
            "message": "No authentication credentials provided"
        })
        return results

    async with AuthSession(cookies=cookies, headers=headers, base_url=base_url) as session:
        endpoints = test_endpoints or SESSION_CHECK_ENDPOINTS

        for endpoint in endpoints:
            response = await session.get(endpoint)
            status = response.get("status", 0)

            endpoint_result = {
                "endpoint": endpoint,
                "status": status,
                "session_valid": response.get("session_valid", False)
            }

            results["endpoints_tested"].append(endpoint_result)

            if 200 <= status < 300:
                results["successful_endpoints"].append(endpoint)
                results["authenticated"] = True
                results["session_valid"] = True
            elif status in [401, 403]:
                results["failed_endpoints"].append(endpoint)

        # Get session stats
        results["session_stats"] = session.get_stats()

    # Generate findings
    if results["authenticated"]:
        results["findings"].append({
            "type": "success",
            "message": f"Authentication successful - {len(results['successful_endpoints'])} endpoint(s) accessible"
        })
    else:
        results["findings"].append({
            "type": "error",
            "message": "Authentication failed - no endpoints returned success response"
        })

    return results


# Export main classes and functions
__all__ = [
    "AIOHTTP_AVAILABLE",
    "AuthConfig",
    "AuthSession",
    "SessionState",
    "create_authenticated_session",
    "parse_auth_header",
    "parse_cookie_string",
    "test_auth_session",
]
