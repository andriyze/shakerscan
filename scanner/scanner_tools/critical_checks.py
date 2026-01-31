"""
Critical Security Checks - Phase 1 Implementation

This module contains high-priority security checks for:
- CSRF (Cross-Site Request Forgery)
- IDOR/BOLA (Insecure Direct Object References / Broken Object Level Authorization)
- Path Traversal
- Default Credentials
- Deserialization Vulnerabilities

All functions follow async patterns and return structured dictionaries.
"""

import asyncio
import base64
import difflib
import hashlib
import json
import math
import random
import re
import urllib.parse
from typing import Any

from dataclasses import dataclass

from .common import detect_spa_catch_all, get_auth_curl_args, run
from .access_control_checks import SPA_FRAMEWORK_INDICATORS


# =============================================================================
# AUTH RESPONSE PARSING (for default credential detection)
# =============================================================================


@dataclass
class AuthResponse:
    """Parsed HTTP response for auth detection."""

    status_code: int | None
    content_type: str
    location: str | None  # Redirect location
    set_cookies: list[str]  # Session cookies
    body: str
    is_json: bool  # Content-Type is application/json

    @property
    def has_session_cookie(self) -> bool:
        """
        Check if response sets a session-like cookie.

        Parses cookie name (before '=') and checks against session patterns,
        excluding CSRF/XSRF tokens which are not session indicators.
        """
        session_patterns = ["session", "auth", "token", "jwt", "sid", "ssid"]
        csrf_patterns = ["csrf", "xsrf", "_csrf", "_xsrf"]

        for cookie in self.set_cookies:
            # Parse cookie name (everything before '=')
            if "=" not in cookie:
                continue
            cookie_name = cookie.split("=", 1)[0].strip().lower()

            # Skip CSRF/XSRF tokens - these are not session indicators
            if any(p in cookie_name for p in csrf_patterns):
                continue

            # Check if cookie name matches session patterns
            if any(p in cookie_name for p in session_patterns):
                return True
        return False


_AUTH_META_PATTERN = re.compile(r"__SHAKERSCAN_AUTH__(\d{3})__SHAKERSCAN_AUTH__$")


def _parse_auth_response(raw: str) -> AuthResponse:
    """
    Parse curl output with -i (headers) and -w (status) flags.

    Expected format:
    - Headers (including HTTP status line)
    - Blank line separator
    - Body content
    - __SHAKERSCAN_AUTH__<status_code>__SHAKERSCAN_AUTH__ marker at end

    Handles HTTP 100 Continue and multi-block headers by parsing the final
    header block (the one before the actual body).
    """
    if not raw:
        return AuthResponse(None, "", None, [], "", False)

    # Extract status from marker
    status_code = None
    if "__SHAKERSCAN_AUTH__" in raw:
        match = _AUTH_META_PATTERN.search(raw.strip())
        if match:
            status_code = int(match.group(1))
            raw = raw[: match.start()]

    # Handle HTTP 100 Continue and multi-block headers
    # Split all header/body blocks, then find the final headers
    # Pattern: headers are separated from body/next-headers by blank line
    sep = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    parts = raw.split(sep)

    # Find the final header block (skip 100 Continue responses)
    headers = ""
    body = ""
    for i, part in enumerate(parts):
        first_line = part.split("\n", 1)[0].strip()
        # Check if this looks like HTTP headers (starts with HTTP/ or has : in first few lines)
        is_http_status = first_line.startswith("HTTP/")
        is_100_continue = is_http_status and " 100 " in first_line

        if is_100_continue:
            # Skip 100 Continue blocks
            continue
        elif is_http_status:
            # This is the final response headers
            headers = part
            # Everything after is the body
            body = sep.join(parts[i + 1 :]) if i + 1 < len(parts) else ""
            break
        else:
            # Not headers, must be body from earlier split
            if not headers:
                # No headers found yet, treat whole thing as body
                body = raw
            break

    # If we didn't find HTTP headers, fall back to simple split
    if not headers and sep in raw:
        headers, body = raw.split(sep, 1)

    # Parse headers
    content_type = ""
    location = None
    set_cookies: list[str] = []

    for line in headers.split("\n"):
        line_lower = line.lower().strip()
        if line_lower.startswith("content-type:"):
            content_type = line.split(":", 1)[1].strip()
        elif line_lower.startswith("location:"):
            location = line.split(":", 1)[1].strip()
        elif line_lower.startswith("set-cookie:"):
            set_cookies.append(line.split(":", 1)[1].strip())

    is_json = "application/json" in content_type.lower()

    return AuthResponse(status_code, content_type, location, set_cookies, body, is_json)


def _strip_xssi_prefix(body: str) -> str:
    """Strip common XSSI/anti-hijacking prefixes from JSON responses."""
    stripped = body.lstrip()
    # Common prefixes used by Google, Facebook, Angular, etc.
    prefixes = [
        ")]}'\n", ")]}',\n", ")]}'", ")]}\n", ")]}",
        "while(1);", "for(;;);", "while(true);",
        "])}while(1);</x>",
    ]
    for prefix in prefixes:
        if stripped.startswith(prefix):
            return stripped[len(prefix):].lstrip()
    return stripped


def _looks_like_json(body: str) -> bool:
    """Check if body looks like JSON (starts with { or [), handling XSSI prefixes."""
    stripped = _strip_xssi_prefix(body)
    return stripped.startswith("{") or stripped.startswith("[")


def _is_valid_json_auth_success(resp: AuthResponse) -> tuple[bool, str]:
    """
    Validate JSON authentication response.

    Returns (is_success, reason).
    Requires: status < 400, JSON content-type (or JSON-like body), parsed JSON with token field.
    """
    # Gate 1: Status code must be success (2xx/3xx)
    if resp.status_code is not None and resp.status_code >= 400:
        return False, f"status_{resp.status_code}"

    # Gate 2: Must be JSON content-type OR body that looks like JSON
    # Some APIs return JSON with text/plain or no content-type
    is_json_body = resp.is_json or _looks_like_json(resp.body)
    if not is_json_body:
        return False, "not_json_content_type"

    # Gate 3: Must parse as valid JSON with token-like field
    # Strip XSSI prefix before parsing (e.g., ")]}'" or "while(1);")
    body_to_parse = _strip_xssi_prefix(resp.body)
    try:
        data = json.loads(body_to_parse)
        if not isinstance(data, dict):
            return False, "json_not_object"
    except json.JSONDecodeError:
        return False, "invalid_json"

    # Gate 4: Check for token field in parsed JSON (not substring match!)
    token_fields = ["token", "access_token", "jwt", "session_id", "id_token", "auth_token"]
    has_token_field = any(
        field in data and data[field] for field in token_fields  # Field exists and is truthy
    )

    # Also accept explicit success indicators
    success_fields = [
        ("success", True),
        ("authenticated", True),
        ("loggedIn", True),
        ("status", "ok"),
    ]
    has_success_field = any(data.get(field) == value for field, value in success_fields)

    if has_token_field or has_success_field:
        return True, "json_auth_success"

    return False, "no_token_or_success_field"


def _is_valid_form_auth_success(resp: AuthResponse, login_path: str) -> tuple[bool, str]:
    """
    Validate form-based authentication response.

    Returns (is_success, reason).
    Requires: redirect away from login OR session cookie, no error signals.

    Args:
        resp: Parsed auth response
        login_path: The original login URL/path (used to detect redirect back to login)
    """
    # Gate 1: Status code check
    if resp.status_code is not None and resp.status_code >= 400:
        return False, f"status_{resp.status_code}"

    # Gate 2: Check for error signals in body
    body_lower = resp.body.lower()
    error_signals = [
        "invalid",
        "incorrect",
        "failed",
        "error",
        "unauthorized",
        "not found",
        "404",
        "forbidden",
        "denied",
        "wrong password",
        "bad credentials",
        "login failed",
        "authentication failed",
    ]
    if any(sig in body_lower for sig in error_signals):
        return False, "error_signal_found"

    # Success criteria: redirect away from login OR session cookie
    has_redirect_away = False
    if resp.location:
        loc_lower = resp.location.lower()

        # Extract path from login_path for comparison
        login_path_lower = login_path.lower()
        # Remove protocol and host if present
        if "://" in login_path_lower:
            login_path_lower = "/" + login_path_lower.split("://", 1)[1].split("/", 1)[-1]
        # Remove query string for comparison
        login_path_base = login_path_lower.split("?")[0].rstrip("/")

        # Extract path from redirect location
        redirect_path = loc_lower
        if "://" in redirect_path:
            redirect_path = "/" + redirect_path.split("://", 1)[1].split("/", 1)[-1]
        redirect_path_base = redirect_path.split("?")[0].rstrip("/")

        # Redirect is "away" if it goes to a different path than the login path
        is_same_path = redirect_path_base == login_path_base

        # Detect redirects to other login/auth pages (also a failure signal)
        # Match paths that end with login markers or have them as path segments
        # e.g., /signin, /user/login, /auth/login but NOT /login-success, /login-complete
        login_page_pattern = r"(^|/)(login|signin|sign-in|auth|authenticate)(/|$|\?)"
        is_redirect_to_login = bool(re.search(login_page_pattern, redirect_path_base))

        # Fix: is_success_path must NOT override same-path check
        # A redirect to /admin/login?error=1 should NOT be treated as success
        # Redirects to other login pages (/signin) are also failures
        has_redirect_away = not is_same_path and not is_redirect_to_login

    has_session = resp.has_session_cookie

    # Session cookie alone is weak evidence - many apps set anonymous session
    # cookies on failed logins. Require positive body signals as confirmation.
    success_signals = ["welcome", "logged in", "success", "hello", "authenticated"]
    has_positive_body = any(sig in body_lower for sig in success_signals)

    if has_redirect_away:
        return True, "form_auth_redirect"

    if has_session and has_positive_body:
        return True, "form_auth_session"

    return False, "no_redirect_or_confirmed_session"


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {}
    for char in value:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _shannon_entropy_bytes(value: bytes) -> float:
    if not value:
        return 0.0
    freq = {}
    for byte in value:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _looks_like_jwt(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    return all(parts) and all(re.fullmatch(r"[A-Za-z0-9_-]+", part) for part in parts)


def _is_probable_base64(value: str) -> bool:
    if len(value) < 16:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", value):
        return False
    return True


def _decode_base64_bytes(value: str) -> bytes | None:
    try:
        padded = value + ("=" * (-len(value) % 4))
        return base64.urlsafe_b64decode(padded.encode("utf-8"))
    except Exception:
        return None


def _looks_like_session_cookie(name: str) -> bool:
    name_lower = name.lower()
    return any(token in name_lower for token in ["session", "sid", "sess", "token", "auth", "jwt", "jsessionid"])


def _normalize_login_response(text: str) -> str:
    if not text:
        return ""
    cleaned = re.sub(r'(?i)name=["\']?csrf[^"\']*["\']?\s+value=["\'][^"\']+["\']', "csrf", text)
    cleaned = re.sub(r'(?i)[a-f0-9]{16,}', "", cleaned)
    cleaned = re.sub(r'(?i)[A-Za-z0-9+/]{16,}={0,2}', "", cleaned)
    cleaned = re.sub(r'\d+', "0", cleaned)
    cleaned = re.sub(r'\s+', " ", cleaned)
    cleaned = cleaned.strip()
    if len(cleaned) > 20000:
        cleaned = cleaned[:20000]
    return cleaned


async def test_csrf(url: str, discovered_urls: list[str] | None = None, auth_session: Any | None = None) -> dict[str, Any]:
    """
    Test for CSRF (Cross-Site Request Forgery) vulnerabilities.

    Checks performed:
    1. Forms without CSRF tokens
    2. Missing SameSite cookie attributes
    3. Referer/Origin header validation (safe testing only)

    Args:
        url: Base URL to test
        discovered_urls: Additional URLs to check for forms (optional)
        auth_session: AuthSession for authenticated requests (optional)

    Returns:
        Dict containing:
        - vulnerable: bool
        - forms_without_tokens: list of vulnerable forms
        - missing_samesite: list of cookies without SameSite
        - tested_forms: int (count)
        - tested_endpoints: int (count)
        - evidence: detailed findings
    """
    results = {
        "vulnerable": False,
        "forms_without_tokens": [],
        "missing_samesite": [],
        "referer_not_validated": [],
        "tested_forms": 0,
        "tested_endpoints": 0,
        "evidence": []
    }

    # Step 1: Find forms via HTML parsing
    auth_args = get_auth_curl_args(auth_session)
    html_out, html_err, html_rc = await run(
        ["curl", "-sS", "-L", "-k", "--max-time", "10", "-H", "User-Agent: Mozilla/5.0"] + auth_args + [url],
        timeout=15
    )

    if html_rc == 0 and html_out:
        # Extract forms using regex (handles most common HTML patterns)
        # Pattern captures: <form...>...</form>
        forms = re.findall(
            r'<form[^>]*?action=["\'](.*?)["\'][^>]*?>(.*?)</form>',
            html_out,
            re.DOTALL | re.IGNORECASE
        )

        # Also try to find forms without explicit action attribute
        forms_no_action = re.findall(
            r'<form[^>]*?>(.*?)</form>',
            html_out,
            re.DOTALL | re.IGNORECASE
        )

        # Track processed forms to avoid duplicates
        seen_forms = set()

        # CSRF token patterns (defined once for reuse)
        csrf_token_patterns = [
            r'csrf[-_]?token',
            r'_token',
            r'authenticity[-_]?token',
            r'anti[-_]?forgery',
            r'xsrf[-_]?token',
            r'__requestverificationtoken',
            r'csrfmiddlewaretoken',
        ]

        # Process forms with action attributes
        for action, form_body in forms:
            # Create a signature from form body to detect duplicates
            form_signature = form_body[:150]  # Use first 150 chars as unique signature
            if form_signature in seen_forms:
                continue
            seen_forms.add(form_signature)

            results["tested_forms"] += 1

            has_csrf = any(
                re.search(pattern, form_body, re.IGNORECASE)
                for pattern in csrf_token_patterns
            )

            if not has_csrf:
                # Check if it's a state-changing form (POST/PUT/DELETE/PATCH method)
                method_match = re.search(
                    r'method=["\'](post|put|delete|patch)["\']',
                    form_body,
                    re.IGNORECASE
                )

                # Also check parent form tag for method
                if not method_match:
                    # Look in the opening form tag before action (try both quote styles)
                    form_tag_start = html_out.find(f'action="{action}"')
                    if form_tag_start < 0:
                        form_tag_start = html_out.find(f"action='{action}'")
                    if form_tag_start > 0:
                        form_tag = html_out[max(0, form_tag_start - 200):form_tag_start]
                        method_match = re.search(
                            r'method=["\'](post|put|delete|patch)["\']',
                            form_tag,
                            re.IGNORECASE
                        )

                # If POST/PUT/DELETE/PATCH and no CSRF token, it's vulnerable
                if method_match:
                    results["vulnerable"] = True

                    # Resolve relative action URLs
                    if action.startswith('/'):
                        full_action = urllib.parse.urljoin(url, action)
                    elif action.startswith('http'):
                        full_action = action
                    else:
                        # Let urljoin handle relative paths correctly
                        full_action = urllib.parse.urljoin(url, action)

                    results["forms_without_tokens"].append({
                        "action": full_action,
                        "method": method_match.group(1).upper(),
                        "page_url": url,
                        "form_preview": form_body[:200] + "..." if len(form_body) > 200 else form_body
                    })

        # Process forms without action attribute (they submit to current page)
        for form_body in forms_no_action:
            # Skip if we already processed this form
            form_signature = form_body[:150]
            if form_signature in seen_forms:
                continue
            seen_forms.add(form_signature)

            results["tested_forms"] += 1

            # Check for CSRF tokens
            has_csrf = any(
                re.search(pattern, form_body, re.IGNORECASE)
                for pattern in csrf_token_patterns
            )

            if not has_csrf:
                method_match = re.search(
                    r'method=["\'](post|put|delete|patch)["\']',
                    form_body,
                    re.IGNORECASE
                )

                if method_match:
                    results["vulnerable"] = True
                    results["forms_without_tokens"].append({
                        "action": url,  # Submits to current page
                        "method": method_match.group(1).upper(),
                        "page_url": url,
                        "form_preview": form_body[:200] + "..." if len(form_body) > 200 else form_body
                    })

    # Step 2: Check SameSite cookie attributes
    cookie_out, cookie_err, cookie_rc = await run(
        ["curl", "-sS", "-I", "-L", "-k", "--max-time", "5", "-H", "User-Agent: Mozilla/5.0"] + auth_args + [url],
        timeout=10
    )

    if cookie_rc == 0 and cookie_out:
        # Extract all Set-Cookie headers
        set_cookies = [
            line.strip() for line in cookie_out.splitlines()
            if line.lower().startswith('set-cookie:')
        ]

        for cookie_line in set_cookies:
            # Check if SameSite attribute is present
            if 'samesite=' not in cookie_line.lower():
                results["vulnerable"] = True

                # Extract cookie name for reporting
                cookie_name_match = re.search(
                    r'set-cookie:\s*([^=]+)=',
                    cookie_line,
                    re.IGNORECASE
                )
                cookie_name = cookie_name_match.group(1) if cookie_name_match else "unknown"

                results["missing_samesite"].append({
                    "cookie_name": cookie_name,
                    "cookie_header": cookie_line[:200]  # Truncate for safety
                })
            elif 'samesite=none' in cookie_line.lower():
                # SameSite=None without Secure is also vulnerable
                if 'secure' not in cookie_line.lower():
                    results["vulnerable"] = True

                    cookie_name_match = re.search(
                        r'set-cookie:\s*([^=]+)=',
                        cookie_line,
                        re.IGNORECASE
                    )
                    cookie_name = cookie_name_match.group(1) if cookie_name_match else "unknown"

                    results["missing_samesite"].append({
                        "cookie_name": cookie_name,
                        "issue": "SameSite=None without Secure flag",
                        "cookie_header": cookie_line[:200]
                    })

    # Step 3: Test Referer/Origin validation (SAFE test - just check if headers are validated)
    # We'll do this by checking if the server responds differently without these headers
    # This is a passive test that doesn't actually attempt CSRF
    results["tested_endpoints"] += 1

    # Normal request with proper Referer
    normal_out, normal_err, normal_rc = await run([
        "curl", "-sS", "-I", "-L", "-k",
        "-H", f"Referer: {url}",
        "-H", f"Origin: {urllib.parse.urlparse(url).scheme}://{urllib.parse.urlparse(url).netloc}",
        "-H", "User-Agent: Mozilla/5.0",
        "--max-time", "5"
    ] + auth_args + [url], timeout=10)

    # Request without Referer/Origin (to see if server validates)
    no_referer_out, no_referer_err, no_referer_rc = await run([
        "curl", "-sS", "-I", "-L", "-k",
        "-H", "User-Agent: Mozilla/5.0",
        "--max-time", "5"
    ] + auth_args + [url], timeout=10)

    # If both requests succeed identically, Referer validation might not be enforced
    # This is informational, not definitive proof of vulnerability
    if normal_rc == 0 and no_referer_rc == 0:
        if normal_out and no_referer_out:
            normal_status = normal_out.splitlines()[0] if normal_out else ""
            no_referer_status = no_referer_out.splitlines()[0] if no_referer_out else ""

            # If status codes are the same, server may not be validating Referer
            if normal_status == no_referer_status and "200" in normal_status:
                results["referer_not_validated"].append({
                    "url": url,
                    "note": "Server responds identically with and without Referer header (informational)"
                })

    # Build evidence summary
    if results["vulnerable"]:
        results["evidence"] = []

        if results["forms_without_tokens"]:
            results["evidence"].append({
                "type": "missing_csrf_tokens",
                "severity": "high",
                "count": len(results["forms_without_tokens"]),
                "description": f"Found {len(results['forms_without_tokens'])} form(s) without CSRF tokens"
            })

        if results["missing_samesite"]:
            results["evidence"].append({
                "type": "missing_samesite",
                "severity": "medium",
                "count": len(results["missing_samesite"]),
                "description": f"Found {len(results['missing_samesite'])} cookie(s) without proper SameSite attribute"
            })

    return results


async def test_idor_bola(api_endpoints: list[str], base_url: str = "", auth_session: Any | None = None) -> dict[str, Any]:
    """
    Test for IDOR (Insecure Direct Object References) and BOLA
    (Broken Object Level Authorization) vulnerabilities.

    Checks performed:
    1. Sequential ID manipulation (e.g., /api/user/1 -> /api/user/2)
    2. UUID predictability testing
    3. Object access without authentication

    Args:
        api_endpoints: List of API endpoint URLs to test
        base_url: Base URL for constructing full URLs (optional)
        auth_session: AuthSession for authenticated requests (optional)

    Returns:
        Dict containing:
        - vulnerable: bool
        - vulnerable_endpoints: list of endpoints with IDOR
        - accessible_ids: list of IDs that were accessible
        - tested_endpoints: int (count)
        - evidence: detailed findings
    """
    results = {
        "vulnerable": False,
        "vulnerable_endpoints": [],
        "accessible_ids": [],
        "tested_endpoints": 0,
        "tested_ids": 0,
        "evidence": []
    }

    # Extract endpoints with ID parameters (numeric or UUID)
    id_pattern_numeric = re.compile(r'/(\d+)/?(?:\?.*)?$')
    id_pattern_uuid = re.compile(r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/?(?:\?.*)?$', re.IGNORECASE)

    id_endpoints = []
    for ep in api_endpoints:
        # Check for numeric IDs
        numeric_match = id_pattern_numeric.search(ep)
        if numeric_match:
            id_endpoints.append({
                'url': ep,
                'id': numeric_match.group(1),
                'id_type': 'numeric',
                'base': ep[:numeric_match.start(1)]
            })
            continue

        # Check for UUIDs
        uuid_match = id_pattern_uuid.search(ep)
        if uuid_match:
            id_endpoints.append({
                'url': ep,
                'id': uuid_match.group(1),
                'id_type': 'uuid',
                'base': ep[:uuid_match.start(1)]
            })

    # Limit testing to avoid excessive requests
    id_endpoints = id_endpoints[:10]
    auth_args = get_auth_curl_args(auth_session)

    for endpoint_info in id_endpoints:
        results["tested_endpoints"] += 1

        current_id = endpoint_info['id']
        id_type = endpoint_info['id_type']
        base_path = endpoint_info['base']

        if id_type == 'numeric':
            # Test sequential IDs
            try:
                current_id_int = int(current_id)
            except ValueError:
                continue

            # Test IDs: current-1, current+1, current+10, 1
            test_ids = [
                str(current_id_int - 1) if current_id_int > 1 else None,
                str(current_id_int + 1),
                str(current_id_int + 10),
                "1" if current_id_int != 1 else None
            ]

            for test_id in test_ids:
                if test_id is None or int(test_id) <= 0:
                    continue

                results["tested_ids"] += 1

                # Construct test URL
                test_url = f"{base_path}{test_id}"

                # Try accessing with optional authentication
                out, err, rc = await run([
                    "curl", "-sS", "-I", "-k", "--max-time", "5",
                    "-H", "User-Agent: Mozilla/5.0"
                ] + auth_args + [test_url], timeout=10)

                if rc == 0 and out:
                    first_line = out.splitlines()[0] if out else ""

                    # Check if we got a successful response (200 OK)
                    if "200" in first_line:
                        # Further check: is this different from a 404?
                        # Try a definitely invalid ID to compare
                        invalid_url = f"{base_path}999999999"
                        invalid_out, _, invalid_rc = await run([
                            "curl", "-sS", "-I", "-k", "--max-time", "3",
                            "-H", "User-Agent: Mozilla/5.0"
                        ] + auth_args + [invalid_url], timeout=8)

                        invalid_status = ""
                        if invalid_rc == 0 and invalid_out:
                            invalid_status = invalid_out.splitlines()[0] if invalid_out else ""

                        # If invalid ID returns different status, this is likely vulnerable
                        if "404" in invalid_status or "403" in invalid_status:
                            results["vulnerable"] = True
                            results["accessible_ids"].append(test_id)

                            if test_url not in [e['url'] for e in results["vulnerable_endpoints"]]:
                                results["vulnerable_endpoints"].append({
                                    "url": test_url,
                                    "original_id": current_id,
                                    "accessible_id": test_id,
                                    "id_type": "numeric",
                                    "status_code": "200",
                                    "description": "Sequential ID accessible without authentication"
                                })

        elif id_type == 'uuid':
            # For UUIDs, we can't easily predict other valid IDs
            # Instead, we just check if the current ID is accessible
            results["tested_ids"] += 1

            out, err, rc = await run([
                "curl", "-sS", "-I", "-k", "--max-time", "5",
                "-H", "User-Agent: Mozilla/5.0"
            ] + auth_args + [endpoint_info['url']], timeout=10)

            if rc == 0 and out:
                first_line = out.splitlines()[0] if out else ""

                # If accessible without auth, it's a potential BOLA issue
                if "200" in first_line:
                    # Note: This is informational - we can't prove BOLA without valid auth
                    results["evidence"].append({
                        "type": "uuid_accessible_without_auth",
                        "url": endpoint_info['url'],
                        "note": "UUID-based endpoint accessible without authentication (informational)"
                    })

    # Build evidence summary
    if results["vulnerable"]:
        results["evidence"].append({
            "type": "idor_sequential",
            "severity": "critical",
            "count": len(results["vulnerable_endpoints"]),
            "description": f"Found {len(results['vulnerable_endpoints'])} endpoint(s) with sequential ID access vulnerability"
        })

    return results


async def test_path_traversal(url: str, discovered_urls: list[str] | None = None, auth_session: Any | None = None) -> dict[str, Any]:
    """
    Test for path traversal vulnerabilities.

    Checks performed:
    1. Linux path traversal (../../../etc/passwd)
    2. Windows path traversal (..\\..\\windows\\win.ini)
    3. URL encoding variants
    4. Double encoding

    Args:
        url: Base URL to test
        discovered_urls: Additional URLs with parameters to test (optional)
        auth_session: AuthSession for authenticated requests (optional)

    Returns:
        Dict containing:
        - vulnerable: bool
        - vulnerable_parameters: list of vulnerable parameters
        - payloads_tested: int (count)
        - evidence: detailed findings
    """
    results = {
        "vulnerable": False,
        "vulnerable_parameters": [],
        "payloads_tested": 0,
        "tested_urls": 0,
        "evidence": []
    }

    # Path traversal payloads
    payloads = [
        # Linux
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",

        # Windows
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\win.ini",

        # Encoded
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",

        # Double encoded
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",

        # Mixed encodings
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//etc/passwd",

        # Absolute paths
        "/etc/passwd",
        "/var/www/../../etc/passwd",

        # Null byte (older systems)
        "../../../etc/passwd%00",
    ]

    # Success indicators
    linux_indicators = [
        "root:x:", "root:0:", "/bin/bash", "/bin/sh",
        "daemon:", "nobody:", "bin:x:"
    ]

    windows_indicators = [
        "[boot loader]", "[operating systems]",
        "[fonts]", "[extensions]", "MAPI"
    ]

    # Compile test URLs
    test_urls = [url]
    if discovered_urls:
        test_urls.extend(discovered_urls[:20])  # Limit to avoid excessive testing

    auth_args = get_auth_curl_args(auth_session)

    for test_url in test_urls:
        # Only test URLs with parameters
        if '?' not in test_url:
            continue

        results["tested_urls"] += 1

        # Parse URL to get parameters
        try:
            parsed = urllib.parse.urlparse(test_url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            continue

        # Test each parameter
        for param_name in params.keys():
            for payload in payloads:
                results["payloads_tested"] += 1

                # Replace parameter value with payload
                test_params = params.copy()
                test_params[param_name] = [payload]

                # Reconstruct URL
                malicious_query = urllib.parse.urlencode(test_params, doseq=True)
                malicious_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{malicious_query}"

                # Send request
                out, err, rc = await run([
                    "curl", "-sS", "-L", "-k", "--max-time", "5",
                    "-H", "User-Agent: Mozilla/5.0"
                ] + auth_args + [malicious_url], timeout=10)

                if rc == 0 and out:
                    # Check for Linux path traversal success
                    if any(indicator in out for indicator in linux_indicators):
                        results["vulnerable"] = True
                        results["vulnerable_parameters"].append({
                            "url": test_url,
                            "parameter": param_name,
                            "payload": payload,
                            "type": "linux_path_traversal",
                            "evidence": out[:500],  # Truncate for safety
                            "indicators_found": [ind for ind in linux_indicators if ind in out]
                        })
                        # Stop testing this parameter once we find vulnerability
                        break

                    # Check for Windows path traversal success
                    elif any(indicator in out for indicator in windows_indicators):
                        results["vulnerable"] = True
                        results["vulnerable_parameters"].append({
                            "url": test_url,
                            "parameter": param_name,
                            "payload": payload,
                            "type": "windows_path_traversal",
                            "evidence": out[:500],
                            "indicators_found": [ind for ind in windows_indicators if ind in out]
                        })
                        break

    # Build evidence summary
    if results["vulnerable"]:
        results["evidence"].append({
            "type": "path_traversal",
            "severity": "critical",
            "count": len(results["vulnerable_parameters"]),
            "description": f"Found {len(results['vulnerable_parameters'])} parameter(s) vulnerable to path traversal"
        })

    return results


async def test_default_credentials(
    url: str,
    login_endpoints: list[str] | None = None,
    auth_session: Any | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for default credentials on login forms.

    ⚠️ SECURITY WARNING ⚠️
    This function tests common default credentials. Only use on systems you
    own or have explicit authorization to test. Unauthorized testing may be
    illegal and unethical.

    SAFE MODE (default=True):
    - Tests only 3 extremely common defaults (admin/admin, root/root, administrator/administrator)
    - Limits to 3 attempts per endpoint
    - Adds 2-second delays between attempts to avoid lockouts
    - Maximum 5 endpoints tested

    Args:
        url: Base URL to test
        login_endpoints: List of login endpoint URLs (optional, auto-detected if not provided)
        safe_mode: Enable safe mode (default: True, RECOMMENDED)

    Returns:
        Dict containing:
        - vulnerable: bool
        - vulnerable_endpoints: list of endpoints with default creds
        - tested_endpoints: int (count)
        - tested_combinations: int (count)
        - evidence: detailed findings
        - warning: security warning message
    """
    results = {
        "vulnerable": False,
        "vulnerable_endpoints": [],
        "tested_endpoints": 0,
        "tested_combinations": 0,
        "evidence": [],
        "warning": "⚠️ Only test on systems you own or have authorization to test. Unauthorized access attempts may be illegal."
    }

    # SAFE default credentials (extremely common only)
    safe_defaults = [
        ("admin", "admin"),
        ("root", "root"),
        ("administrator", "administrator"),
    ]

    # Use safe defaults only (we don't implement aggressive mode for security)
    defaults = safe_defaults
    auth_args = get_auth_curl_args(auth_session)

    # Auto-detect login endpoints if not provided
    if not login_endpoints:
        login_endpoints = []

        # Common login paths
        common_paths = [
            "/login", "/admin", "/admin/login", "/administrator",
            "/api/login", "/api/auth/login", "/auth/login",
            "/wp-admin", "/wp-login.php",
            "/user/login", "/account/login"
        ]

        for path in common_paths:
            endpoint = urllib.parse.urljoin(url, path)

            # Quick check if endpoint exists (HEAD request)
            head_out, head_err, head_rc = await run([
                "curl", "-sS", "-I", "-k", "--max-time", "3",
                "-H", "User-Agent: Mozilla/5.0"
            ] + auth_args + [endpoint], timeout=5)

            if head_rc == 0 and head_out:
                status_line = head_out.splitlines()[0] if head_out else ""
                # If we get 200, 401, or 403, the endpoint likely exists
                if any(code in status_line for code in ["200", "401", "403"]):
                    login_endpoints.append(endpoint)

            # Limit auto-detection to avoid excessive requests
            if len(login_endpoints) >= 5:
                break

    # Limit endpoints to test
    login_endpoints = login_endpoints[:5]  # Maximum 5 endpoints

    for endpoint in login_endpoints:
        results["tested_endpoints"] += 1

        for username, password in defaults:
            results["tested_combinations"] += 1

            # Add delay to avoid lockouts and rate limiting
            await asyncio.sleep(2)

            # Try JSON authentication (common for APIs)
            json_payload = f'{{"username":"{username}","password":"{password}"}}'

            auth_out, auth_err, auth_rc = await run([
                "curl", "-sS", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", json_payload,
                "-k", "--max-time", "10",
                "-i",  # Include headers for parsing
                "-w", "__SHAKERSCAN_AUTH__%{http_code}__SHAKERSCAN_AUTH__",
                "-H", "User-Agent: Mozilla/5.0"
            ] + auth_args + [endpoint], timeout=15)

            success = False
            auth_method = "json"

            if auth_rc == 0 and auth_out:
                # Use structured response parsing to avoid false positives
                resp = _parse_auth_response(auth_out)
                is_success, _reason = _is_valid_json_auth_success(resp)
                success = is_success

            # If JSON failed, try form data
            if not success:
                form_payload = f"username={username}&password={password}"

                form_out, form_err, form_rc = await run([
                    "curl", "-sS", "-X", "POST",
                    "-H", "Content-Type: application/x-www-form-urlencoded",
                    "-d", form_payload,
                    "-k", "--max-time", "10",
                    "-i",  # Include headers for parsing
                    "-w", "__SHAKERSCAN_AUTH__%{http_code}__SHAKERSCAN_AUTH__",
                    "-H", "User-Agent: Mozilla/5.0"
                ] + auth_args + [endpoint], timeout=15)

                if form_rc == 0 and form_out:
                    # Use structured response parsing to avoid false positives
                    resp = _parse_auth_response(form_out)
                    is_success, _reason = _is_valid_form_auth_success(resp, endpoint)
                    if is_success:
                        success = True
                        auth_method = "form"

            if success:
                # SECURITY: Never store actual credentials - only hash
                cred_hash = hashlib.sha256(
                    f"{username}:{password}".encode()
                ).hexdigest()[:16]

                results["vulnerable"] = True
                results["vulnerable_endpoints"].append({
                    "endpoint": endpoint,
                    "credential_hash": cred_hash,  # NOT the actual credentials
                    "username": username,  # Username only (for reporting)
                    "auth_method": auth_method,
                    # DO NOT include password in results
                    "note": f"Default credentials detected using {username}:*** (hash: {cred_hash})"
                })

                # Stop testing this endpoint if we found working creds
                break

    # Build evidence summary
    if results["vulnerable"]:
        results["evidence"].append({
            "type": "default_credentials",
            "severity": "critical",
            "count": len(results["vulnerable_endpoints"]),
            "description": f"Found {len(results['vulnerable_endpoints'])} endpoint(s) with default credentials",
            "remediation": [
                "Change default credentials immediately",
                "Implement strong password policies",
                "Consider multi-factor authentication",
                "Monitor for unauthorized access attempts"
            ]
        })

    return results


async def test_deserialization(url: str, auth_session: Any | None = None, safe_mode: bool = True) -> dict[str, Any]:
    """
    Test for insecure deserialization vulnerabilities.

    ⚠️ SECURITY WARNING ⚠️
    This function tests for deserialization issues. Only use on systems you
    own or have explicit authorization to test.

    SAFE MODE (default=True):
    - Detection only (no exploitation)
    - Looks for serialized object patterns in responses
    - Tests for error-based detection
    - Uses harmless detection payloads

    UNSAFE MODE:
    - NOT IMPLEMENTED (requires explicit authorization and ysoserial)

    Args:
        url: Base URL to test
        safe_mode: Enable safe mode (default: True, RECOMMENDED)

    Returns:
        Dict containing:
        - vulnerable: bool
        - vulnerable_endpoints: list of endpoints with deserialization
        - deserialization_types: list of detected types (java, python, php)
        - tested_types: int (count)
        - evidence: detailed findings
    """
    results = {
        "vulnerable": False,
        "vulnerable_endpoints": [],
        "deserialization_types": [],
        "tested_types": 0,
        "evidence": []
    }

    if not safe_mode:
        # Unsafe mode not implemented for security reasons
        results["error"] = "Unsafe mode not implemented - requires explicit authorization and ysoserial"
        return results

    # SAFE MODE: Detection only
    auth_args = get_auth_curl_args(auth_session)

    # 1. Check for Java serialized objects
    results["tested_types"] += 1

    # Check Content-Type header for Java serialization
    resp_out, resp_err, resp_rc = await run([
        "curl", "-sS", "-I", "-k", "--max-time", "5",
        "-H", "User-Agent: Mozilla/5.0"
    ] + auth_args + [url], timeout=10)

    if resp_rc == 0 and resp_out:
        if "application/x-java-serialized-object" in resp_out.lower():
            results["vulnerable"] = True
            results["deserialization_types"].append("java")
            results["vulnerable_endpoints"].append({
                "url": url,
                "type": "java",
                "evidence": "Java serialization Content-Type detected in headers",
                "detection_method": "header_inspection"
            })

    # 2. Test for Python pickle (SAFE - detection only via errors)
    results["tested_types"] += 1

    # Harmless pickle pattern that will cause an error if deserialized
    pickle_test_payload = "cos\nsystem\n(S'echo test'\ntR."  # Obvious pattern

    pickle_out, pickle_err, pickle_rc = await run([
        "curl", "-sS", "-X", "POST",
        "-H", "Content-Type: application/octet-stream",
        "-d", pickle_test_payload,
        "-k", "--max-time", "5",
        "-H", "User-Agent: Mozilla/5.0"
    ] + auth_args + [url], timeout=10)

    if pickle_rc == 0 and (pickle_out or pickle_err):
        combined_output = (pickle_out or "") + (pickle_err or "")

        # Look for pickle-related errors (indicates deserialization attempt)
        pickle_indicators = [
            "pickle", "Unpickling", "cPickle",
            "UnpicklingError", "bad marshal data",
            "invalid load key", "pickle protocol"
        ]

        if any(indicator in combined_output for indicator in pickle_indicators):
            results["vulnerable"] = True
            if "python_pickle" not in results["deserialization_types"]:
                results["deserialization_types"].append("python_pickle")
            results["vulnerable_endpoints"].append({
                "url": url,
                "type": "python_pickle",
                "evidence": "Pickle deserialization detected via error message",
                "detection_method": "error_based",
                "indicators_found": [ind for ind in pickle_indicators if ind in combined_output]
            })

    # 3. PHP serialization detection
    results["tested_types"] += 1

    # Harmless PHP serialized object
    php_payload = 'O:8:"stdClass":1:{s:4:"test";s:5:"value";}'

    php_out, php_err, php_rc = await run([
        "curl", "-sS", "-X", "POST",
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "-d", f"data={urllib.parse.quote(php_payload)}",
        "-k", "--max-time", "5",
        "-H", "User-Agent: Mozilla/5.0"
    ] + auth_args + [url], timeout=10)

    if php_rc == 0 and (php_out or php_err):
        combined_output = (php_out or "") + (php_err or "")

        # Look for PHP unserialize errors
        php_indicators = [
            "unserialize", "Serialization",
            "Notice: unserialize", "Warning: unserialize",
            "unserialization", "serialize()"
        ]

        if any(indicator in combined_output for indicator in php_indicators):
            results["vulnerable"] = True
            if "php" not in results["deserialization_types"]:
                results["deserialization_types"].append("php")
            results["vulnerable_endpoints"].append({
                "url": url,
                "type": "php",
                "evidence": "PHP unserialization detected via error message",
                "detection_method": "error_based",
                "indicators_found": [ind for ind in php_indicators if ind in combined_output]
            })

    # 4. .NET deserialization detection
    results["tested_types"] += 1

    # Check for .NET BinaryFormatter patterns
    dotnet_out, dotnet_err, dotnet_rc = await run([
        "curl", "-sS", "-I", "-k", "--max-time", "5",
        "-H", "Accept: application/octet-stream",
        "-H", "User-Agent: Mozilla/5.0"
    ] + auth_args + [url], timeout=10)

    if dotnet_rc == 0 and dotnet_out:
        if "application/x-dotnet-serialized" in dotnet_out.lower():
            results["vulnerable"] = True
            results["deserialization_types"].append("dotnet")
            results["vulnerable_endpoints"].append({
                "url": url,
                "type": "dotnet",
                "evidence": ".NET serialization Content-Type detected",
                "detection_method": "header_inspection"
            })

    # Build evidence summary
    if results["vulnerable"]:
        results["evidence"].append({
            "type": "insecure_deserialization",
            "severity": "critical",
            "count": len(results["vulnerable_endpoints"]),
            "types_detected": results["deserialization_types"],
            "description": f"Found {len(results['vulnerable_endpoints'])} endpoint(s) with potential deserialization issues",
            "remediation": [
                "Avoid deserializing untrusted data",
                "Use safe serialization formats (JSON, XML with schema validation)",
                "Implement input validation and integrity checks",
                "Consider using allowlists for deserialization classes"
            ]
        })

    return results


# ============================================================================
# PHASE 2: ACCESS CONTROL & AUTHENTICATION CHECKS
# ============================================================================

async def test_rate_limiting(
    url: str,
    sensitive_endpoints: list[str] | None = None,
    requests_per_second: int = 20,
    auth_session: Any | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for rate limiting on sensitive endpoints.

    ⚠️ SECURITY WARNING: Only test on authorized systems.
    Safe mode limits requests to prevent DoS.

    Checks:
    - Login endpoints for brute force protection
    - Registration endpoints for spam protection
    - Password reset for abuse protection
    - API endpoints for throttling
    - 2FA verification for bypass attempts

    Args:
        url: Base URL to test
        sensitive_endpoints: List of endpoints to test (auto-detected if None)
        requests_per_second: Number of requests to send (default: 20, max: 100 in safe mode)
        safe_mode: Limit requests to prevent actual DoS (default: True)

    Returns:
        Dict with vulnerable endpoints, response codes, rate limit detection

    Mapping:
        OWASP: A07:2021 - Identification and Authentication Failures
        CWE: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
        MITRE: T1110 (Brute Force)
    """
    import time

    auth_args = get_auth_curl_args(auth_session)
    results = {
        "vulnerable": False,
        "vulnerable_endpoints": [],
        "tested_endpoints": 0,
        "total_requests_sent": 0,
        "evidence": [],
        "spa_detected": False
    }

    # SPA DETECTION: Skip if site uses catch-all routing (returns same page for all paths)
    # This causes false positives since all endpoint checks return 200
    try:
        spa_result = await detect_spa_catch_all(url, timeout=10)
        if spa_result.get("is_spa_catch_all"):
            results["spa_detected"] = True
            results["evidence"].append({
                "type": "info",
                "message": "SPA detected with catch-all routing - skipping rate limiting tests"
            })
            return results
    except Exception:
        pass  # Continue if SPA detection fails

    # Safe mode enforcement
    if safe_mode and requests_per_second > 100:
        requests_per_second = 100
        results["evidence"].append({
            "type": "info",
            "message": "Safe mode: Limited requests to 100 to prevent DoS"
        })

    # Auto-detect sensitive endpoints if not provided
    if not sensitive_endpoints:
        from urllib.parse import urljoin
        sensitive_endpoints = [
            urljoin(url, "/api/login"),
            urljoin(url, "/api/auth/login"),
            urljoin(url, "/login"),
            urljoin(url, "/api/register"),
            urljoin(url, "/api/auth/register"),
            urljoin(url, "/register"),
            urljoin(url, "/api/password-reset"),
            urljoin(url, "/api/auth/password-reset"),
            urljoin(url, "/forgot-password"),
            urljoin(url, "/api/2fa/verify"),
            urljoin(url, "/api/auth/2fa"),
        ]

    # Limit to first 5 endpoints to prevent excessive testing
    test_endpoints = sensitive_endpoints[:5]

    for endpoint in test_endpoints:
        results["tested_endpoints"] += 1

        # Preflight check - skip non-existent endpoints
        preflight_out, _, preflight_rc = await run([
            "curl", "-sS", "-k", "--max-time", "5",
            "-X", "HEAD",
            "-w", "%{http_code}",
            "-o", "/dev/null"
        ] + auth_args + [endpoint], timeout=8)

        if preflight_rc == 0 and preflight_out:
            try:
                preflight_code = int(preflight_out.strip())
                if preflight_code in [404, 410]:
                    results["evidence"].append({
                        "endpoint": endpoint,
                        "status": "skipped",
                        "message": f"Endpoint returned {preflight_code} - does not exist"
                    })
                    continue  # Skip to next endpoint
            except ValueError:
                pass

        # Track response codes and timing
        response_codes = []
        response_times = []
        rate_limited = False

        # Send burst of requests
        start_time = time.time()

        for i in range(requests_per_second):
            request_start = time.time()

            # Send POST request with dummy credentials
            out, err, rc = await run([
                "curl", "-sS", "-k", "--max-time", "3",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", '{"username":"test","password":"test"}',
                "-w", "%{http_code}",
                "-o", "/dev/null"
            ] + auth_args + [endpoint], timeout=5)

            request_end = time.time()
            response_times.append(request_end - request_start)
            results["total_requests_sent"] += 1

            if rc == 0 and out:
                try:
                    http_code = int(out.strip())
                    response_codes.append(http_code)

                    # Check for rate limiting indicators
                    if http_code in [429, 503]:  # Too Many Requests, Service Unavailable
                        rate_limited = True
                except ValueError:
                    pass

            # Small delay to prevent completely overwhelming the server
            if safe_mode:
                await asyncio.sleep(0.05)  # 50ms delay

        end_time = time.time()
        total_time = end_time - start_time

        # Analysis
        if not rate_limited and len(response_codes) > 0:
            # No 429/503 responses detected = potential vulnerability
            # Count requests that were PROCESSED (not rate-limited, not non-existent)
            # Exclude: 429/503 (rate limited), 404/410 (endpoint doesn't exist)
            # 401/403 still means the request was processed, just rejected for auth reasons
            requests_processed = sum(1 for code in response_codes if code not in [429, 503, 404, 410])

            if requests_processed >= requests_per_second * 0.8:  # 80%+ got through
                results["vulnerable"] = True
                results["vulnerable_endpoints"].append({
                    "endpoint": endpoint,
                    "requests_sent": len(response_codes),
                    "requests_processed": requests_processed,
                    "response_codes": response_codes[:10],  # First 10 for brevity
                    "average_response_time": sum(response_times) / len(response_times) if response_times else 0,
                    "total_time_seconds": total_time,
                    "rate_limit_detected": False
                })
                results["evidence"].append({
                    "endpoint": endpoint,
                    "issue": f"No rate limiting detected - {requests_processed}/{len(response_codes)} requests processed without throttling",
                    "recommendation": "Implement rate limiting (e.g., 5 requests per minute)"
                })
        else:
            # Rate limiting detected (good!)
            results["evidence"].append({
                "endpoint": endpoint,
                "status": "protected",
                "message": "Rate limiting detected (429/503 responses)"
            })

    # Add summary evidence
    if results["vulnerable"]:
        results["evidence"].append({
            "type": "summary",
            "description": f"Found {len(results['vulnerable_endpoints'])} endpoint(s) without proper rate limiting",
            "remediation": [
                "Implement rate limiting on all authentication endpoints",
                "Use 429 Too Many Requests status code",
                "Implement exponential backoff",
                "Consider IP-based rate limiting",
                "Use CAPTCHA for excessive failed attempts"
            ]
        })

    return results


async def test_2fa_bypass(
    url: str,
    login_endpoint: str | None = None,
    auth_session: Any | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for 2FA/MFA bypass vulnerabilities.

    ⚠️ SECURITY WARNING: Only test on authorized systems.
    Detection-only mode - no actual bypass exploitation.

    Checks:
    - Direct access to post-2FA pages
    - Response manipulation possibilities
    - Null/empty OTP acceptance
    - Missing 2FA enforcement
    - Rate limiting on OTP verification

    Args:
        url: Base URL to test
        login_endpoint: Specific login endpoint (auto-detected if None)
        safe_mode: Detection only, no exploitation (default: True)

    Returns:
        Dict with potential 2FA bypass issues

    Mapping:
        OWASP: A07:2021 - Identification and Authentication Failures
        CWE: CWE-287 (Improper Authentication)
        MITRE: T1078 (Valid Accounts)
    """
    from urllib.parse import urljoin

    auth_args = get_auth_curl_args(auth_session)
    results = {
        "vulnerable": False,
        "bypass_methods_detected": [],
        "tested_methods": 0,
        "evidence": [],
        "spa_detected": False
    }

    # SPA DETECTION: Skip if site uses catch-all routing
    try:
        spa_result = await detect_spa_catch_all(url, timeout=10)
        if spa_result.get("is_spa_catch_all"):
            results["spa_detected"] = True
            results["evidence"].append({
                "type": "info",
                "message": "SPA detected with catch-all routing - skipping 2FA bypass tests"
            })
            return results
    except Exception:
        pass

    # Safe mode enforcement
    if not safe_mode:
        results["evidence"].append({
            "type": "error",
            "message": "Unsafe mode not implemented for security reasons"
        })
        return results

    # Auto-detect login endpoint
    if not login_endpoint:
        login_endpoint = urljoin(url, "/login")

    # Test 1: Check for 2FA presence
    results["tested_methods"] += 1
    out, err, rc = await run([
        "curl", "-sS", "-L", "-k", "--max-time", "10"
    ] + auth_args + [login_endpoint], timeout=15)

    if rc == 0 and out:
        # Look for 2FA indicators in HTML
        twofa_indicators = [
            "2fa", "two-factor", "two factor", "mfa", "multi-factor",
            "authentication code", "verification code", "otp", "totp",
            "authenticator", "google authenticator", "authy"
        ]

        has_2fa = any(indicator in out.lower() for indicator in twofa_indicators)

        if not has_2fa:
            results["evidence"].append({
                "method": "2fa_detection",
                "status": "info",
                "message": "No 2FA indicators found in login page (may not be enabled)"
            })
        else:
            results["evidence"].append({
                "method": "2fa_detection",
                "status": "detected",
                "message": "2FA appears to be implemented"
            })

    # Test 2: Check for common post-2FA endpoints
    results["tested_methods"] += 1
    post_2fa_endpoints = [
        urljoin(url, "/dashboard"),
        urljoin(url, "/account"),
        urljoin(url, "/profile"),
        urljoin(url, "/admin"),
        urljoin(url, "/api/user/profile"),
    ]

    for endpoint in post_2fa_endpoints[:3]:  # Test first 3
        # Fetch with body to validate it's actual account content (not SPA shell)
        out, err, rc = await run([
            "curl", "-sS", "-k", "--max-time", "5",
            "-w", "\n---HTTP_CODE---%{http_code}",
        ] + auth_args + [endpoint], timeout=8)

        if rc == 0 and out:
            try:
                # Split body from status code
                parts = out.rsplit("---HTTP_CODE---", 1)
                body = parts[0] if len(parts) > 1 else ""
                http_code = int(parts[-1].strip()) if parts else 0

                # If we get 200 without authentication, verify it's not just SPA shell
                if http_code == 200:
                    body_lower = body[:5000].lower()
                    is_html = "<!doctype html" in body_lower or "<html" in body_lower

                    # For non-HTML responses (JSON APIs), check for error indicators
                    if not is_html:
                        # Skip if response indicates auth failure/error
                        # Note: '"error"' alone is too broad - catches {"error": null, "data": {...}}
                        # Use specific patterns that indicate actual auth errors
                        json_error_indicators = [
                            '"error":"', '"error":{',  # error with string/object value
                            '"unauthorized"', '"forbidden"',
                            '"unauthenticated"', '"login required"',
                            '"access denied"', '"not authenticated"',
                            '"invalid token"', '"session expired"',
                            '"authentication required"', '"not authorized"',
                            '"status":401', '"status":403', '"status": 401', '"status": 403',
                            '"code":401', '"code":403', '"code": 401', '"code": 403',
                            '"statuscode":401', '"statuscode":403',
                        ]
                        is_json_error = any(ind in body_lower for ind in json_error_indicators)
                        if is_json_error:
                            continue  # Not a bypass - API returned auth error

                        # JSON responses without auth error are likely vulnerable
                        results["vulnerable"] = True
                        results["bypass_methods_detected"].append({
                            "method": "direct_access",
                            "endpoint": endpoint,
                            "http_code": http_code,
                            "description": "Post-2FA endpoint accessible without authentication"
                        })
                        results["evidence"].append({
                            "method": "direct_access",
                            "endpoint": endpoint,
                            "issue": f"HTTP {http_code} - Accessible without authentication",
                            "severity": "critical"
                        })
                        continue

                    # For HTML responses, require positive evidence of authenticated content
                    # to avoid false positives from catch-all pages

                    # SPA shell indicators - definitely a catch-all route
                    # Use same indicators as access_control_checks for consistency
                    has_spa_shell = any(ind.lower() in body_lower for ind in SPA_FRAMEWORK_INDICATORS)

                    # Actual account/dashboard content indicators - positive evidence
                    # These must be specific to authenticated content, not generic pages
                    content_indicators = [
                        # User identification (specific)
                        "user_id", "userid", "user-id", "account_id", "accountid",
                        "customer_id", "customerid", "member_id",
                        # Account data (specific)
                        "balance", "credit", "subscription", "billing",
                        "order history", "purchase history", "transaction",
                        # Session indicators (logout/signout implies logged in)
                        "logout", "sign out", "signout", "log out",
                        # Personal content markers (specific)
                        "my profile", "my account", "my settings", "my dashboard",
                        "my orders", "my purchases", "my subscriptions",
                        "your profile", "your account", "your settings",
                        # Personalized greetings (must include user context)
                        "logged in as", "signed in as", "welcome back,",
                        # JSON data markers (user-specific fields)
                        '"email":', '"username":', '"user":', '"profile":',
                        '"firstname":', '"lastname":', '"phone":',
                        '"accountid":', '"userid":', '"customerid":',
                        # Server-rendered dashboard elements (specific class/id names)
                        "dashboard-header", "user-avatar", "account-nav",
                        "profile-menu", "user-dropdown", "settings-link",
                        "account-balance", "user-info", "member-since",
                    ]
                    has_content = any(ind in body_lower for ind in content_indicators)

                    # Flag if: has authenticated content AND no SPA shell
                    # Requires positive evidence - pages without content indicators are skipped
                    # (this avoids FPs from generic catch-all pages, login pages, 404s)
                    should_flag = has_content and not has_spa_shell

                    if should_flag:
                        results["vulnerable"] = True
                        results["bypass_methods_detected"].append({
                            "method": "direct_access",
                            "endpoint": endpoint,
                            "http_code": http_code,
                            "description": "Post-2FA endpoint accessible without authentication"
                        })
                        results["evidence"].append({
                            "method": "direct_access",
                            "endpoint": endpoint,
                            "issue": f"HTTP {http_code} - Accessible without authentication",
                            "severity": "critical"
                        })
            except ValueError:
                pass

    # Test 3: Check for 2FA verification endpoint rate limiting
    results["tested_methods"] += 1
    twofa_verify_endpoints = [
        urljoin(url, "/api/2fa/verify"),
        urljoin(url, "/api/auth/2fa"),
        urljoin(url, "/verify-otp"),
    ]

    for verify_endpoint in twofa_verify_endpoints[:2]:  # Test first 2
        # Preflight check - skip non-existent endpoints
        preflight_out, _, preflight_rc = await run([
            "curl", "-sS", "-k", "--max-time", "5",
            "-X", "HEAD",
            "-w", "%{http_code}",
            "-o", "/dev/null"
        ] + auth_args + [verify_endpoint], timeout=8)

        if preflight_rc == 0 and preflight_out:
            try:
                preflight_code = int(preflight_out.strip())
                if preflight_code in [404, 410]:
                    results["evidence"].append({
                        "method": "2fa_rate_limit_check",
                        "endpoint": verify_endpoint,
                        "status": "skipped",
                        "message": f"Endpoint returned {preflight_code} - does not exist"
                    })
                    continue  # Skip to next endpoint
            except ValueError:
                pass

        # Send 10 rapid requests to check for rate limiting
        response_codes = []
        for i in range(10):
            out, err, rc = await run([
                "curl", "-sS", "-k", "--max-time", "3",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", '{"otp":"123456"}',
                "-w", "%{http_code}",
                "-o", "/dev/null"
            ] + auth_args + [verify_endpoint], timeout=5)

            if rc == 0 and out:
                try:
                    http_code = int(out.strip())
                    response_codes.append(http_code)
                except ValueError:
                    pass

        # Check if rate limiting is present
        if response_codes and 429 not in response_codes and 503 not in response_codes:
            # No rate limiting detected - count requests that were processed (not rate-limited, not non-existent)
            # Exclude: 429/503 (rate limited), 404/410 (endpoint doesn't exist)
            # 401/403 on OTP endpoint still means the server accepted the request for processing
            requests_processed = sum(1 for code in response_codes if code not in [429, 503, 404, 410])
            if requests_processed >= 8:  # 80%+ requests went through without rate limiting
                results["vulnerable"] = True
                results["bypass_methods_detected"].append({
                    "method": "no_rate_limiting",
                    "endpoint": verify_endpoint,
                    "requests_sent": len(response_codes),
                    "requests_processed": requests_processed,
                    "description": "No rate limiting on 2FA verification - brute force possible"
                })
                results["evidence"].append({
                    "method": "no_rate_limiting",
                    "endpoint": verify_endpoint,
                    "issue": f"Sent {len(response_codes)} requests without rate limiting ({requests_processed} processed)",
                    "severity": "high"
                })

    # Add summary evidence
    if results["vulnerable"]:
        results["evidence"].append({
            "type": "summary",
            "description": f"Found {len(results['bypass_methods_detected'])} potential 2FA bypass method(s)",
            "remediation": [
                "Enforce 2FA on all authenticated endpoints",
                "Implement rate limiting on OTP verification (max 3-5 attempts)",
                "Use secure session management after 2FA",
                "Implement account lockout after failed OTP attempts",
                "Consider using WebAuthn/FIDO2 for stronger 2FA"
            ]
        })

    return results


async def test_password_reset(
    url: str,
    reset_endpoints: list[str] | None = None,
    auth_session: Any | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for password reset vulnerabilities.

    ⚠️ SECURITY WARNING: Only test on authorized systems.
    Detection-only mode - no actual account takeover.

    Checks:
    - Token length and entropy
    - Token expiration
    - Rate limiting on reset requests
    - Host header injection
    - Token leakage in responses

    Args:
        url: Base URL to test
        reset_endpoints: Password reset endpoints (auto-detected if None)
        safe_mode: Detection only (default: True)

    Returns:
        Dict with password reset vulnerabilities

    Mapping:
        OWASP: A07:2021 - Identification and Authentication Failures
        CWE: CWE-640 (Weak Password Recovery Mechanism)
        MITRE: T1078 (Valid Accounts)
    """
    from urllib.parse import urljoin

    auth_args = get_auth_curl_args(auth_session)
    results = {
        "vulnerable": False,
        "vulnerabilities_found": [],
        "tested_checks": 0,
        "evidence": [],
        "spa_detected": False
    }

    # SPA DETECTION: Skip if site uses catch-all routing
    try:
        spa_result = await detect_spa_catch_all(url, timeout=10)
        if spa_result.get("is_spa_catch_all"):
            results["spa_detected"] = True
            results["evidence"].append({
                "type": "info",
                "message": "SPA detected with catch-all routing - skipping password reset tests"
            })
            return results
    except Exception:
        pass

    # Safe mode enforcement
    if not safe_mode:
        results["evidence"].append({
            "type": "error",
            "message": "Unsafe mode not implemented for security reasons"
        })
        return results

    # Auto-detect reset endpoints
    if not reset_endpoints:
        reset_endpoints = [
            urljoin(url, "/api/password-reset"),
            urljoin(url, "/api/auth/password-reset"),
            urljoin(url, "/forgot-password"),
            urljoin(url, "/reset-password"),
        ]

    # Test 1: Check for rate limiting on reset requests
    results["tested_checks"] += 1
    for endpoint in reset_endpoints[:3]:  # Test first 3
        response_codes = []

        # Send 5 reset requests
        for i in range(5):
            out, err, rc = await run([
                "curl", "-sS", "-k", "--max-time", "5",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", '{"email":"test@example.com"}',
                "-w", "%{http_code}",
                "-o", "/dev/null"
            ] + auth_args + [endpoint], timeout=8)

            if rc == 0 and out:
                try:
                    http_code = int(out.strip())
                    response_codes.append(http_code)
                except ValueError:
                    pass

        # Check for rate limiting
        if response_codes and 429 not in response_codes:
            if len([c for c in response_codes if c in [200, 201]]) >= 4:
                results["vulnerable"] = True
                results["vulnerabilities_found"].append({
                    "type": "no_rate_limiting",
                    "endpoint": endpoint,
                    "description": "No rate limiting on password reset - email flooding possible"
                })
                results["evidence"].append({
                    "check": "rate_limiting",
                    "endpoint": endpoint,
                    "issue": f"Sent {len(response_codes)} reset requests without rate limiting",
                    "severity": "medium"
                })

    # Test 2: Check for host header injection
    results["tested_checks"] += 1
    for endpoint in reset_endpoints[:2]:  # Test first 2
        out, err, rc = await run([
            "curl", "-sS", "-k", "--max-time", "5",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-H", "Host: evil.com",
            "-d", '{"email":"test@example.com"}'
        ] + auth_args + [endpoint], timeout=8)

        if rc == 0 and out:
            # Check if evil.com appears in response
            if "evil.com" in out.lower():
                results["vulnerable"] = True
                results["vulnerabilities_found"].append({
                    "type": "host_header_injection",
                    "endpoint": endpoint,
                    "description": "Host header injection possible - could lead to account takeover"
                })
                results["evidence"].append({
                    "check": "host_header_injection",
                    "endpoint": endpoint,
                    "issue": "Malicious host header reflected in response",
                    "severity": "high"
                })

    # Test 3: Check for token in response (information disclosure)
    results["tested_checks"] += 1
    for endpoint in reset_endpoints[:2]:  # Test first 2
        out, err, rc = await run([
            "curl", "-sS", "-k", "--max-time", "5",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", '{"email":"test@example.com"}'
        ] + auth_args + [endpoint], timeout=8)

        if rc == 0 and out:
            # Look for token patterns in response
            token_patterns = [
                r'token["\']?\s*:\s*["\']([a-zA-Z0-9]{20,})',
                r'reset_token["\']?\s*:\s*["\']([a-zA-Z0-9]{20,})',
                r'resetToken["\']?\s*:\s*["\']([a-zA-Z0-9]{20,})',
            ]

            for pattern in token_patterns:
                matches = re.findall(pattern, out)
                if matches:
                    results["vulnerable"] = True
                    results["vulnerabilities_found"].append({
                        "type": "token_disclosure",
                        "endpoint": endpoint,
                        "description": "Password reset token leaked in API response"
                    })
                    results["evidence"].append({
                        "check": "token_disclosure",
                        "endpoint": endpoint,
                        "issue": "Reset token found in response body",
                        "severity": "critical",
                        "token_sample": matches[0][:10] + "..." if len(matches[0]) > 10 else matches[0]
                    })
                    break

    # Add summary evidence
    if results["vulnerable"]:
        results["evidence"].append({
            "type": "summary",
            "description": f"Found {len(results['vulnerabilities_found'])} password reset vulnerability(s)",
            "remediation": [
                "Implement rate limiting (max 3 requests per hour per email)",
                "Use cryptographically secure tokens (min 32 bytes entropy)",
                "Implement token expiration (15-60 minutes)",
                "Never include tokens in API responses",
                "Validate Host header to prevent injection",
                "Implement CAPTCHA for reset requests"
            ]
        })

    return results


async def test_session_management(
    url: str,
    auth_session: Any | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Test for session management vulnerabilities.

    ⚠️ SECURITY WARNING: Only test on authorized systems.
    Detection-only mode.

    Checks:
    - Session token entropy
    - Session token in URL
    - Secure/HttpOnly flags on cookies
    - SameSite attribute
    - Session fixation

    Args:
        url: Base URL to test
        safe_mode: Detection only (default: True)

    Returns:
        Dict with session management issues

    Mapping:
        OWASP: A07:2021 - Identification and Authentication Failures
        CWE: CWE-384 (Session Fixation), CWE-614 (Sensitive Cookie Without Secure)
        MITRE: T1539 (Steal Web Session Cookie)
    """
    auth_args = get_auth_curl_args(auth_session)
    results = {
        "vulnerable": False,
        "issues_found": [],
        "tested_checks": 0,
        "evidence": [],
        "spa_detected": False
    }

    # SPA DETECTION: Skip if site uses catch-all routing
    try:
        spa_result = await detect_spa_catch_all(url, timeout=10)
        if spa_result.get("is_spa_catch_all"):
            results["spa_detected"] = True
            results["evidence"].append({
                "type": "info",
                "message": "SPA detected with catch-all routing - skipping session management tests"
            })
            return results
    except Exception:
        pass

    # Safe mode enforcement
    if not safe_mode:
        results["evidence"].append({
            "type": "error",
            "message": "Unsafe mode not implemented for security reasons"
        })
        return results

    # Test 1: Check cookies for security flags
    results["tested_checks"] += 1
    out, err, rc = await run([
        "curl", "-sS", "-L", "-k", "--max-time", "10",
        "-v",
        "-c", "-"  # Output cookies
    ] + auth_args + [url], timeout=15)

    if rc == 0 and (out or err):
        response = out + "\n" + err

        # Look for Set-Cookie headers
        cookie_pattern = r'Set-Cookie:\s*([^=]+)=([^;]+)(.*)'
        cookies = re.findall(cookie_pattern, response, re.IGNORECASE)

        for cookie_name, cookie_value, cookie_attrs in cookies:
            cookie_name = cookie_name.strip()
            cookie_attrs_lower = cookie_attrs.lower()

            # Skip non-session cookies
            if cookie_name.lower() in ['_ga', '_gid', '_gat', '__utm']:
                continue

            issues = []

            # Check for Secure flag
            if 'secure' not in cookie_attrs_lower:
                issues.append("missing Secure flag")

            # Check for HttpOnly flag
            if 'httponly' not in cookie_attrs_lower:
                issues.append("missing HttpOnly flag")

            # Check for SameSite attribute
            if 'samesite' not in cookie_attrs_lower:
                issues.append("missing SameSite attribute")

            if issues:
                results["vulnerable"] = True
                results["issues_found"].append({
                    "type": "insecure_cookie",
                    "cookie_name": cookie_name,
                    "issues": issues,
                    "severity": "medium" if len(issues) == 1 else "high",
                    "discovered_via": "redirect_chain"  # Cookie found during redirect following, may not be in initial response
                })
                results["evidence"].append({
                    "check": "cookie_security",
                    "cookie": cookie_name,
                    "issues": ", ".join(issues),
                    "severity": "medium" if len(issues) == 1 else "high",
                    "note": "Cookie discovered during full request (including redirects); may not appear in initial HTTP response"
                })

            # Session token entropy check (lightweight heuristic)
            if _looks_like_session_cookie(cookie_name):
                if _looks_like_jwt(cookie_value):
                    continue
                decoded = _decode_base64_bytes(cookie_value) if _is_probable_base64(cookie_value) else None
                if decoded:
                    entropy = _shannon_entropy_bytes(decoded)
                    token_length = len(decoded)
                else:
                    entropy = _shannon_entropy(cookie_value)
                    token_length = len(cookie_value)
                bits = entropy * token_length
                if token_length < 16 or bits < 64:
                    results["vulnerable"] = True
                    severity = "high" if bits < 48 or token_length < 12 else "medium"
                    if token_length >= 32 and bits < 64:
                        severity = "low"
                    results["issues_found"].append({
                        "type": "low_entropy_session_token",
                        "cookie_name": cookie_name,
                        "token_length": token_length,
                        "entropy_bits": round(bits, 2),
                        "severity": severity,
                    })
                    results["evidence"].append({
                        "check": "session_entropy",
                        "cookie": cookie_name,
                        "token_length": token_length,
                        "entropy_bits": round(bits, 2),
                        "severity": severity,
                    })

    # Test 2: Check for session token in URL
    results["tested_checks"] += 1
    out, err, rc = await run([
        "curl", "-sS", "-L", "-k", "--max-time", "10",
        "-w", "%{url_effective}",
        "-o", "/dev/null"
    ] + auth_args + [url], timeout=15)

    if rc == 0 and out:
        # Look for session tokens in URL
        session_patterns = [
            r'sessionid=([a-zA-Z0-9]+)',
            r'session=([a-zA-Z0-9]+)',
            r'sid=([a-zA-Z0-9]+)',
            r'token=([a-zA-Z0-9]+)',
            r'jsessionid=([a-zA-Z0-9]+)',
        ]

        for pattern in session_patterns:
            if re.search(pattern, out, re.IGNORECASE):
                results["vulnerable"] = True
                results["issues_found"].append({
                    "type": "session_in_url",
                    "description": "Session token exposed in URL",
                    "severity": "high"
                })
                results["evidence"].append({
                    "check": "session_in_url",
                    "issue": "Session token found in URL (vulnerable to referrer leakage)",
                    "severity": "high"
                })
                break

    # Add summary evidence
    if results["vulnerable"]:
        results["evidence"].append({
            "type": "summary",
            "description": f"Found {len(results['issues_found'])} session management issue(s)",
            "remediation": [
                "Use Secure flag on all cookies over HTTPS",
                "Use HttpOnly flag to prevent XSS cookie theft",
                "Use SameSite=Strict or SameSite=Lax",
                "Never include session tokens in URLs",
                "Implement proper session timeout",
                "Regenerate session ID after login"
            ]
        })
    return results


async def test_password_policy(
    url: str,
    discovered_urls: list[str] | None = None,
    auth_session: Any | None = None
) -> dict[str, Any]:
    """
    Detect weak or missing password policy indicators on registration forms.
    Passive check based on HTML attributes and visible hints.
    """
    results = {
        "vulnerable": False,
        "issues": [],
        "observations": [],
        "tested_endpoints": 0,
    }

    auth_args = get_auth_curl_args(auth_session)
    common_paths = [
        "/register", "/signup", "/sign-up", "/create-account",
        "/user/register", "/account/register", "/auth/register",
        "/users/new", "/signup/new",
    ]

    urls_to_test = []
    if discovered_urls:
        for u in discovered_urls:
            if any(k in u.lower() for k in ["register", "signup", "sign-up", "create-account"]):
                urls_to_test.append(u)
    if not urls_to_test:
        urls_to_test = [urllib.parse.urljoin(url, p) for p in common_paths]

    for endpoint in urls_to_test[:8]:
        results["tested_endpoints"] += 1
        out, _, rc = await run(
            ["curl", "-sS", "-L", "-k", "--max-time", "8"] + auth_args + [endpoint],
            timeout=12
        )
        if rc != 0 or not out:
            continue

        password_inputs = re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', out, re.IGNORECASE)
        if not password_inputs:
            continue

        for tag in password_inputs:
            minlen_match = re.search(r'minlength=["\']?(\d+)', tag, re.IGNORECASE)
            pattern_match = re.search(r'pattern=["\']([^"\']+)', tag, re.IGNORECASE)
            autocomplete_match = re.search(r'autocomplete=["\']([^"\']+)', tag, re.IGNORECASE)

            if minlen_match:
                minlen = int(minlen_match.group(1))
                if minlen < 8:
                    results["vulnerable"] = True
                    results["issues"].append({
                        "type": "weak_min_length",
                        "endpoint": endpoint,
                        "minlength": minlen,
                        "severity": "medium",
                        "detail": "Password minlength below 8 characters"
                    })
                else:
                    results["observations"].append({
                        "type": "min_length",
                        "endpoint": endpoint,
                        "minlength": minlen,
                    })
            else:
                results["observations"].append({
                    "type": "min_length_missing",
                    "endpoint": endpoint,
                })

            if pattern_match:
                results["observations"].append({
                    "type": "pattern_present",
                    "endpoint": endpoint,
                    "pattern": pattern_match.group(1)[:80],
                })

            if autocomplete_match:
                results["observations"].append({
                    "type": "autocomplete",
                    "endpoint": endpoint,
                    "value": autocomplete_match.group(1),
                })

        # Check for visible policy hints
        hint_match = re.search(r'password[^<]{0,80}(?:minimum|at least)\s*(\d+)', out, re.IGNORECASE)
        if hint_match:
            minlen_hint = int(hint_match.group(1))
            if minlen_hint < 8:
                results["vulnerable"] = True
                results["issues"].append({
                    "type": "weak_policy_hint",
                    "endpoint": endpoint,
                    "minlength_hint": minlen_hint,
                    "severity": "medium",
                    "detail": "Password policy text indicates length below 8",
                })
            else:
                results["observations"].append({
                    "type": "policy_hint",
                    "endpoint": endpoint,
                    "minlength_hint": minlen_hint,
                })

    return results


async def test_account_enumeration(
    url: str,
    discovered_urls: list[str] | None = None,
    auth_session: Any | None = None
) -> dict[str, Any]:
    """
    Check for account enumeration via explicit error messages or response diffs.
    """
    results = {
        "vulnerable": False,
        "issues": [],
        "tested_endpoints": 0,
    }

    auth_args = get_auth_curl_args(auth_session)
    common_login_paths = [
        "/login", "/signin", "/auth/login", "/api/login", "/api/auth/login",
    ]
    urls_to_test = []
    if discovered_urls:
        for u in discovered_urls:
            if any(k in u.lower() for k in ["login", "signin", "auth"]):
                urls_to_test.append(u)
    if not urls_to_test:
        urls_to_test = [urllib.parse.urljoin(url, p) for p in common_login_paths]

    enum_patterns = [
        r"user\s+not\s+found",
        r"unknown\s+user",
        r"no\s+account",
        r"email\s+not\s+registered",
        r"account\s+does\s+not\s+exist",
        r"invalid\s+username",
    ]
    meta_pattern = re.compile(r"__SHAKERSCAN_META__(\d{3});([0-9.]+)__SHAKERSCAN_META__$")

    def parse_curl_meta(raw: str) -> tuple[str, int | None, float | None]:
        if not raw:
            return "", None, None
        match = meta_pattern.search(raw.strip())
        if not match:
            return raw, None, None
        body = raw[:match.start()]
        return body, int(match.group(1)), float(match.group(2))

    for endpoint in urls_to_test[:6]:
        results["tested_endpoints"] += 1
        usernames = ["admin", "nonexistentuser123456", "nonexistentuser654321"]
        responses: dict[str, dict[str, Any]] = {}

        for username in usernames:
            payload_json = json.dumps({"username": username, "password": "WrongPass123!"})
            out, _, rc = await run(
                [
                    "curl", "-sS", "-L", "-k", "--max-time", "8",
                    "-H", "Content-Type: application/json", "-d", payload_json,
                    "-w", "__SHAKERSCAN_META__%{http_code};%{time_total}__SHAKERSCAN_META__"
                ] + auth_args + [endpoint],
                timeout=12
            )
            if rc == 0 and out is not None:
                body, status_code, time_total = parse_curl_meta(out)
                responses[username] = {
                    "body": body or "",
                    "status": status_code,
                    "time": time_total,
                }

        for username, resp in responses.items():
            body = resp.get("body") or ""
            if not body:
                continue
            for pattern in enum_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    results["vulnerable"] = True
                    results["issues"].append({
                        "type": "explicit_enumeration",
                        "endpoint": endpoint,
                        "pattern": pattern,
                        "username_tested": username,
                        "severity": "medium",
                    })
                    break

        admin_resp = responses.get("admin")
        random_resps = [responses.get(u) for u in usernames[1:]]
        if admin_resp and all(r and r.get("body") for r in random_resps):
            admin_body = _normalize_login_response(admin_resp["body"])
            random_bodies = [_normalize_login_response(r["body"]) for r in random_resps]
            sim_random = difflib.SequenceMatcher(None, random_bodies[0], random_bodies[1]).ratio()
            sim_admin = min(
                difflib.SequenceMatcher(None, admin_body, random_bodies[0]).ratio(),
                difflib.SequenceMatcher(None, admin_body, random_bodies[1]).ratio(),
            )

            signals = []
            random_statuses = [r.get("status") for r in random_resps]
            if admin_resp.get("status") is not None and all(s is not None for s in random_statuses):
                if len(set(random_statuses)) == 1 and admin_resp["status"] != random_statuses[0]:
                    signals.append("status_code")

            len_admin = len(admin_resp["body"] or "")
            len_random_a = len(random_resps[0]["body"] or "")
            len_random_b = len(random_resps[1]["body"] or "")
            min_admin_diff = min(abs(len_admin - len_random_a), abs(len_admin - len_random_b))
            max_random_len = max(len_random_a, len_random_b, 1)
            random_len_ratio = abs(len_random_a - len_random_b) / max_random_len
            admin_len_ratio = min_admin_diff / max(len_admin, len_random_a, len_random_b, 1)

            if sim_random >= 0.9 and sim_admin <= 0.75:
                signals.append("body_similarity")
            if random_len_ratio <= 0.05 and admin_len_ratio >= 0.2 and min_admin_diff > 200:
                signals.append("length_diff")

            time_admin = admin_resp.get("time")
            time_randoms = [r.get("time") for r in random_resps]
            if time_admin is not None and all(t is not None for t in time_randoms):
                time_spread = max(time_randoms) - min(time_randoms)
                if time_spread <= 0.2 and abs(time_admin - sum(time_randoms) / 2) >= 0.6:
                    signals.append("timing_diff")

            if len(signals) >= 2:
                results["vulnerable"] = True
                results["issues"].append({
                    "type": "response_diff",
                    "endpoint": endpoint,
                    "signals": signals,
                    "similarity_random": round(sim_random, 3),
                    "similarity_admin": round(sim_admin, 3),
                    "severity": "low",
                    "detail": "Login responses differ between usernames",
                })

    return results


async def test_bruteforce_protection(
    url: str,
    discovered_urls: list[str] | None = None,
    auth_session: Any | None = None
) -> dict[str, Any]:
    """
    Light brute-force protection check via repeated invalid logins.
    """
    results = {
        "vulnerable": False,
        "issues": [],
        "protections_detected": [],
        "tested_endpoints": 0,
    }

    auth_args = get_auth_curl_args(auth_session)
    common_login_paths = [
        "/login", "/signin", "/auth/login", "/api/login", "/api/auth/login",
    ]
    urls_to_test = []
    if discovered_urls:
        for u in discovered_urls:
            if any(k in u.lower() for k in ["login", "signin", "auth"]):
                urls_to_test.append(u)
    if not urls_to_test:
        urls_to_test = [urllib.parse.urljoin(url, p) for p in common_login_paths]

    lockout_markers = [
        "too many", "try again later", "locked", "account locked",
        "captcha", "verify you are human", "rate limit", "slow down",
    ]
    meta_pattern = re.compile(r"__SHAKERSCAN_META__(\d{3})__SHAKERSCAN_META__$")

    def parse_curl_meta(raw: str) -> tuple[str, int | None]:
        if not raw:
            return "", None
        match = meta_pattern.search(raw.strip())
        if not match:
            return raw, None
        body = raw[:match.start()]
        return body, int(match.group(1))

    def split_headers_body(raw: str) -> tuple[str, str]:
        if "\r\n\r\n" in raw:
            parts = raw.split("\r\n\r\n")
        elif "\n\n" in raw:
            parts = raw.split("\n\n")
        else:
            return "", raw
        if len(parts) >= 2:
            return parts[-2], parts[-1]
        return parts[0], ""

    for endpoint in urls_to_test[:5]:
        results["tested_endpoints"] += 1
        statuses = []
        bodies = []
        rate_limited = False
        for attempt in range(4):
            payload = json.dumps({"username": "invalid_user", "password": "WrongPass123!"})
            out, _, rc = await run(
                [
                    "curl", "-sS", "-L", "-k", "--max-time", "8", "-i",
                    "-H", "Content-Type: application/json", "-d", payload,
                    "-w", "__SHAKERSCAN_META__%{http_code}__SHAKERSCAN_META__"
                ] + auth_args + [endpoint],
                timeout=12
            )
            if rc == 0:
                body_part, status_code = parse_curl_meta(out or "")
                headers, body = split_headers_body(body_part or "")
                bodies.append(body or "")
                if status_code is not None:
                    statuses.append(status_code)

                retry_match = re.search(r"(?im)^retry-after:\s*([0-9]+)", headers or "")
                if retry_match:
                    results["protections_detected"].append({
                        "endpoint": endpoint,
                        "indicator": "retry_after",
                        "retry_after": int(retry_match.group(1)),
                    })
                    rate_limited = True
                    break
                if status_code in (429, 423):
                    results["protections_detected"].append({
                        "endpoint": endpoint,
                        "indicator": "rate_limit_status",
                        "statuses": statuses,
                    })
                    rate_limited = True
                    break

            base_delay = 0.5 + (attempt * 0.5)
            await asyncio.sleep(base_delay + random.uniform(0.1, 0.4))

        protection_found = rate_limited
        for body in bodies:
            if any(marker in body.lower() for marker in lockout_markers):
                protection_found = True
                results["protections_detected"].append({
                    "endpoint": endpoint,
                    "indicator": "lockout_or_captcha",
                })
                break
        if any(code in statuses for code in [429, 423]):
            protection_found = True

        if not protection_found and bodies:
            results["vulnerable"] = True
            results["issues"].append({
                "type": "no_bruteforce_protection_detected",
                "endpoint": endpoint,
                "severity": "low",
                "detail": "No lockout/CAPTCHA indicators after repeated invalid logins",
            })

    return results


async def test_http_methods(
    url: str,
    discovered_urls: list[str] | None = None,
    auth_session: Any | None = None
) -> dict[str, Any]:
    """
    Check for risky HTTP methods via OPTIONS and TRACE echo.
    """
    results = {
        "vulnerable": False,
        "allowed_methods": [],
        "risky_methods": [],
        "trace_enabled": False,
        "trace_evidence": {},
    }

    auth_args = get_auth_curl_args(auth_session)
    urls_to_test = [url]
    base_netloc = urllib.parse.urlparse(url).netloc
    if discovered_urls:
        for u in discovered_urls:
            if not u:
                continue
            if urllib.parse.urlparse(u).netloc == base_netloc:
                urls_to_test.append(u)
    urls_to_test = list(dict.fromkeys(urls_to_test))[:6]

    for endpoint in urls_to_test:
        out, _, rc = await run(
            ["curl", "-sS", "-i", "-X", "OPTIONS", "-L", "-k", "--max-time", "8"] + auth_args + [endpoint],
            timeout=12
        )
        if rc != 0 or not out:
            continue
        allow_methods = set()
        for line in out.splitlines():
            if line.lower().startswith("allow:"):
                allow_methods.update(m.strip().upper() for m in line.split(":", 1)[1].split(","))
            if line.lower().startswith("access-control-allow-methods:"):
                allow_methods.update(m.strip().upper() for m in line.split(":", 1)[1].split(","))
        if allow_methods:
            results["allowed_methods"].append({
                "url": endpoint,
                "methods": sorted(allow_methods),
            })
            risky = sorted(m for m in allow_methods if m in {"PUT", "DELETE", "TRACE", "CONNECT"})
            if risky:
                results["vulnerable"] = True
                results["risky_methods"].append({
                    "url": endpoint,
                    "methods": risky,
                    "detail": "Potentially dangerous methods advertised via OPTIONS",
                })

    # TRACE echo test (base URL only)
    trace_header = "X-Trace-Test: shakerscan"
    trace_out, _, trace_rc = await run(
        ["curl", "-sS", "-i", "-X", "TRACE", "-H", trace_header, "-L", "-k", "--max-time", "8"] + auth_args + [url],
        timeout=12
    )
    if trace_rc == 0 and trace_out:
        header_block = trace_out
        body_block = ""
        if "\r\n\r\n" in trace_out:
            header_block, body_block = trace_out.split("\r\n\r\n", 1)
        elif "\n\n" in trace_out:
            header_block, body_block = trace_out.split("\n\n", 1)

        first_line = header_block.splitlines()[0] if header_block.splitlines() else ""
        if re.match(r"^HTTP/\d(?:\.\d)?\s+200\b", first_line):
            if trace_header.lower() in (body_block or "").lower():
                results["vulnerable"] = True
                results["trace_enabled"] = True
                results["trace_evidence"] = {
                    "header": trace_header,
                    "response_snippet": (body_block or trace_out)[:300],
                }

    return results
