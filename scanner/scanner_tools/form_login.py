"""
Form-Based Login Authentication for DAST Scanning.

This module provides automatic form-based authentication for security scanning.
It detects login forms, injects credentials, and captures session cookies/tokens.

Phase 2.1b of the Authenticated DAST Foundation.

Features:
- Login form detection (username/password fields)
- CSRF token extraction and injection
- Multi-step login support (username → password pages)
- Session cookie capture after successful login
- Login success/failure detection

Usage:
    # Auto-detect and login
    session = await form_login(
        base_url="https://app.example.com",
        username="user@example.com",
        password="password123"
    )

    # With explicit login URL
    session = await form_login(
        base_url="https://app.example.com",
        login_url="/login",
        username="user@example.com",
        password="password123"
    )
"""

import re
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

# Import auth session for making requests
from .auth_session import AuthConfig, AuthSession


def _registrable_domain(host: str) -> str:
    """Return the last two host labels (eTLD+1 approximation).

    Good-enough for "same registrable domain" checks: avoids the full PSL
    dependency and accepts the common case of subdomain login flows like
    `app.example.com` → `auth.example.com`. Hostnames with fewer than two
    labels (`localhost`, raw IPs) are returned as-is.
    """
    host = (host or "").strip().lower()
    if not host:
        return ""
    # Strip port if present and any IPv6 brackets.
    host = host.split(":", 1)[0].strip("[]")
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def _is_action_safe_for_credentials(action_url: str, base_url: str) -> bool:
    """Return True iff submitting credentials to `action_url` is safe.

    Safe when:
      - The action URL is a relative path (urljoin gave us same-origin).
      - The action's host shares a registrable domain with `base_url`.
      - The action uses a scheme that won't downgrade from https → http.
    """
    if not action_url:
        return False
    action_parsed = urlparse(action_url)
    base_parsed = urlparse(base_url)

    # Relative action (no scheme/host) — same origin by construction.
    if not action_parsed.scheme and not action_parsed.netloc:
        return True

    base_scheme = (base_parsed.scheme or "https").lower()
    action_scheme = (action_parsed.scheme or "").lower()
    if action_scheme not in {"http", "https"}:
        return False
    if base_scheme == "https" and action_scheme == "http":
        # Prevent silent TLS downgrade of credential POST.
        return False

    base_host = base_parsed.hostname or ""
    action_host = action_parsed.hostname or ""
    if not base_host or not action_host:
        return False

    return _registrable_domain(action_host) == _registrable_domain(base_host)

# Common login URL patterns
LOGIN_URL_PATTERNS = [
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/auth/signin",
    "/user/login",
    "/users/sign_in",
    "/account/login",
    "/accounts/login",
    "/session/new",
    "/api/auth/login",
    "/api/login",
    "/wp-login.php",
    "/admin/login",
    "/administrator",
]

# Common username field names
USERNAME_FIELD_NAMES = [
    "username", "user", "email", "mail", "login", "user_login",
    "user_name", "userid", "user_id", "account", "name",
    "j_username", "login_email", "signin_email", "user[email]",
    "user[login]", "session[email]", "session[login]",
]

# Common password field names
PASSWORD_FIELD_NAMES = [
    "password", "pass", "pwd", "passwd", "user_password",
    "user_pass", "secret", "j_password", "login_password",
    "signin_password", "user[password]", "session[password]",
]

# Common CSRF token field names
CSRF_FIELD_NAMES = [
    "csrf_token", "csrf", "_csrf", "csrfmiddlewaretoken",
    "authenticity_token", "_token", "token", "__RequestVerificationToken",
    "antiforgery", "_antiforgery", "xsrf_token", "_xsrf",
]

# Login success indicators (in response body/headers)
LOGIN_SUCCESS_INDICATORS = [
    {"type": "redirect", "pattern": r"(?i)/(dashboard|home|account|profile|my|app)", "weight": 0.8},
    {"type": "redirect", "pattern": r"(?i)/[^/]*\?.*success", "weight": 0.6},
    {"type": "body", "pattern": r"(?i)welcome\s+(back|to)", "weight": 0.7},
    {"type": "body", "pattern": r"(?i)logged\s+in\s+(successfully|as)", "weight": 0.9},
    {"type": "body", "pattern": r"(?i)sign\s*out|log\s*out", "weight": 0.6},
    {"type": "cookie", "name": r"(?i)(session|auth|token|jwt|sid)", "weight": 0.8},
    {"type": "header", "name": "authorization", "weight": 0.9},
    {"type": "status", "value": 302, "redirect_not_login": True, "weight": 0.5},
]

# Login failure indicators
LOGIN_FAILURE_INDICATORS = [
    {"type": "body", "pattern": r"(?i)invalid\s+(username|password|credentials|login)", "weight": 0.9},
    {"type": "body", "pattern": r"(?i)incorrect\s+(username|password)", "weight": 0.9},
    {"type": "body", "pattern": r"(?i)login\s+failed", "weight": 0.9},
    {"type": "body", "pattern": r"(?i)authentication\s+failed", "weight": 0.9},
    {"type": "body", "pattern": r"(?i)wrong\s+(username|password)", "weight": 0.8},
    {"type": "body", "pattern": r"(?i)user\s+not\s+found", "weight": 0.8},
    {"type": "body", "pattern": r"(?i)account\s+locked", "weight": 0.7},
    {"type": "body", "pattern": r"(?i)too\s+many\s+(attempts|tries)", "weight": 0.7},
    {"type": "redirect", "pattern": r"(?i)/(login|signin|auth).*[?&](error|failed)", "weight": 0.8},
    {"type": "status", "value": 401, "weight": 0.9},
    {"type": "status", "value": 403, "weight": 0.7},
]


class FormParser(HTMLParser):
    """Parse HTML to extract form elements."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.in_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str]]):
        attrs_dict = dict(attrs)

        if tag == "form":
            self.in_form = True
            self.current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "POST").upper(),
                "id": attrs_dict.get("id"),
                "name": attrs_dict.get("name"),
                "inputs": [],
                "buttons": []
            }

        elif self.in_form and tag == "input":
            input_data = {
                "type": attrs_dict.get("type", "text").lower(),
                "name": attrs_dict.get("name"),
                "id": attrs_dict.get("id"),
                "value": attrs_dict.get("value", ""),
                "placeholder": attrs_dict.get("placeholder", ""),
                "required": "required" in attrs_dict,
                "autocomplete": attrs_dict.get("autocomplete", ""),
            }
            self.current_form["inputs"].append(input_data)

        elif self.in_form and tag == "button":
            button_data = {
                "type": attrs_dict.get("type", "submit").lower(),
                "name": attrs_dict.get("name"),
                "value": attrs_dict.get("value", ""),
            }
            self.current_form["buttons"].append(button_data)

    def handle_endtag(self, tag: str):
        if tag == "form" and self.in_form:
            self.in_form = False
            if self.current_form:
                self.forms.append(self.current_form)
            self.current_form = None


@dataclass
class LoginForm:
    """Represents a detected login form."""
    url: str
    action: str
    method: str
    username_field: str | None = None
    password_field: str | None = None
    csrf_field: str | None = None
    csrf_value: str | None = None
    hidden_fields: dict[str, str] = field(default_factory=dict)
    confidence: float = 0.0
    form_id: str | None = None


@dataclass
class LoginResult:
    """Result of a login attempt."""
    success: bool
    session: AuthSession | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    redirect_url: str | None = None
    error: str | None = None
    attempts: int = 0
    login_url: str | None = None
    form_used: LoginForm | None = None


def parse_forms(html: str) -> list[dict[str, Any]]:
    """Parse HTML and extract all forms."""
    parser = FormParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.forms


def identify_login_form(forms: list[dict[str, Any]], page_url: str) -> LoginForm | None:
    """
    Identify which form is likely a login form.

    Returns the most likely login form with field mappings.
    """
    best_form = None
    best_score = 0.0

    for form in forms:
        score = 0.0
        username_field = None
        password_field = None
        csrf_field = None
        csrf_value = None
        hidden_fields = {}

        inputs = form.get("inputs", [])

        # Look for password field (strong indicator)
        for inp in inputs:
            if inp.get("type") == "password":
                password_field = inp.get("name")
                score += 0.4
                break

        if not password_field:
            continue  # Not a login form without password field

        # Look for username/email field
        for inp in inputs:
            inp_type = inp.get("type", "text")
            inp_name = (inp.get("name") or "").lower()
            inp_id = (inp.get("id") or "").lower()
            inp_autocomplete = (inp.get("autocomplete") or "").lower()

            # Check by type
            if inp_type == "email":
                username_field = inp.get("name")
                score += 0.3
                break

            # Check by name/id
            for pattern in USERNAME_FIELD_NAMES:
                if pattern in inp_name or pattern in inp_id:
                    username_field = inp.get("name")
                    score += 0.2
                    break

            # Check by autocomplete
            if inp_autocomplete in ["username", "email"]:
                username_field = inp.get("name")
                score += 0.2
                break

            if username_field:
                break

        # If no username field found, use first text input before password
        if not username_field:
            for inp in inputs:
                if inp.get("type") in ["text", "email"] and inp.get("name"):
                    username_field = inp.get("name")
                    score += 0.1
                    break

        # Look for CSRF token
        for inp in inputs:
            if inp.get("type") == "hidden":
                inp_name = (inp.get("name") or "").lower()
                for csrf_pattern in CSRF_FIELD_NAMES:
                    if csrf_pattern in inp_name:
                        csrf_field = inp.get("name")
                        csrf_value = inp.get("value")
                        score += 0.1
                        break

                # Store all hidden fields
                if inp.get("name"):
                    hidden_fields[inp.get("name")] = inp.get("value", "")

        # Check form action for login indicators
        action = (form.get("action") or "").lower()
        for pattern in ["/login", "/signin", "/auth", "/session"]:
            if pattern in action:
                score += 0.1
                break

        # Update best form
        if score > best_score and username_field and password_field:
            best_score = score
            action_url = form.get("action", "")
            if not action_url or action_url.startswith("#"):
                action_url = page_url
            elif not action_url.startswith(("http://", "https://")):
                action_url = urljoin(page_url, action_url)

            best_form = LoginForm(
                url=page_url,
                action=action_url,
                method=form.get("method", "POST"),
                username_field=username_field,
                password_field=password_field,
                csrf_field=csrf_field,
                csrf_value=csrf_value,
                hidden_fields=hidden_fields,
                confidence=min(score, 1.0),
                form_id=form.get("id")
            )

    return best_form


async def find_login_page(base_url: str, session: AuthSession) -> str | None:
    """
    Find the login page URL by trying common patterns.

    Returns the URL of a page containing a login form, or None.

    Candidate pages are *scored* rather than first-match: a settings page at
    `/account` with a "change password" field would otherwise win over the
    real `/login`, causing the scanner to submit credentials to the wrong
    form. We prefer pages that look like genuine login forms (exactly one
    password field, a username/email field, login keywords, login-shaped URL)
    and short-circuit only on a high-confidence match.
    """
    candidates: list[tuple[float, str]] = []

    # URLs to probe: known login patterns first, then the base URL.
    probe_urls = [urljoin(base_url, pattern) for pattern in LOGIN_URL_PATTERNS]
    probe_urls.append(base_url)

    for url in probe_urls:
        response = await session.get(url)
        if response.get("status") != 200:
            continue
        body = response.get("body", "")
        if not re.search(r'<input[^>]*type=["\']password["\']', body, re.IGNORECASE):
            continue
        score = _score_login_page(url, body)
        candidates.append((score, url))
        # Strong, unambiguous match — stop early to avoid extra requests.
        if score >= 0.9:
            return url

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _score_login_page(url: str, body: str) -> float:
    """Heuristic 0.0-1.0 score that `url` is a genuine login page.

    Higher when the page has exactly one password field (login forms rarely
    have two; change-password/registration forms usually do), a username/email
    field, login keywords, and a login-shaped URL.
    """
    score = 0.0
    body_lower = body.lower()

    password_fields = len(re.findall(r'<input[^>]*type=["\']password["\']', body, re.IGNORECASE))
    if password_fields == 1:
        score += 0.4
    elif password_fields >= 2:
        # Two+ password inputs strongly implies change-password / registration
        # / confirm-password, not a login form.
        score -= 0.3

    # Username / email field present.
    if re.search(r'<input[^>]*type=["\']email["\']', body, re.IGNORECASE) or re.search(
        r'name=["\'](?:user(?:name)?|email|login|j_username)["\']', body, re.IGNORECASE
    ):
        score += 0.25

    # Login-shaped URL.
    path = urlparse(url).path.lower()
    if any(token in path for token in ("login", "signin", "sign-in", "session", "auth")):
        score += 0.25

    # De-prioritize URLs/pages that look like account settings / registration /
    # password change, which also carry password inputs.
    negative_tokens = ("change-password", "reset", "register", "signup", "sign-up", "settings", "account")
    if any(token in path for token in negative_tokens):
        score -= 0.25
    if any(kw in body_lower for kw in ("change password", "current password", "new password", "confirm password", "create account", "register")):
        score -= 0.2

    # Login keywords in body.
    if any(kw in body_lower for kw in ("sign in", "log in", "login")):
        score += 0.1

    return score


def check_login_success(
    response: dict[str, Any],
    pre_login_cookies: set[str],
    login_url: str
) -> tuple[bool, float, list[str]]:
    """
    Check if login was successful based on response.

    Returns: (success, confidence, indicators_found)
    """
    success_score = 0.0
    failure_score = 0.0
    indicators = []

    status = response.get("status", 0)
    body = response.get("body", "")
    headers = response.get("headers", {})
    final_url = response.get("url", "")
    redirects = response.get("redirects", [])

    # Check success indicators
    for indicator in LOGIN_SUCCESS_INDICATORS:
        ind_type = indicator["type"]
        weight = indicator["weight"]

        if ind_type == "redirect":
            pattern = indicator["pattern"]
            if re.search(pattern, final_url):
                # Make sure we didn't redirect back to login
                if not re.search(r"(?i)/(login|signin|auth)", final_url):
                    success_score += weight
                    indicators.append(f"Redirect to: {final_url[:50]}")

        elif ind_type == "body":
            pattern = indicator["pattern"]
            if re.search(pattern, body):
                success_score += weight
                indicators.append(f"Body pattern: {pattern[:30]}")

        elif ind_type == "cookie":
            name_pattern = indicator["name"]
            for cookie_name in response.get("cookies_received", {}).keys():
                if re.search(name_pattern, cookie_name, re.IGNORECASE):
                    if cookie_name not in pre_login_cookies:
                        success_score += weight
                        indicators.append(f"New cookie: {cookie_name}")
                        break

        elif ind_type == "status":
            if status == indicator["value"]:
                if indicator.get("redirect_not_login"):
                    # 302 is success only if not redirecting to login
                    if not re.search(r"(?i)/(login|signin|auth)", final_url):
                        success_score += weight
                        indicators.append(f"Status {status} + redirect")

    # Check failure indicators
    for indicator in LOGIN_FAILURE_INDICATORS:
        ind_type = indicator["type"]
        weight = indicator["weight"]

        if ind_type == "body":
            pattern = indicator["pattern"]
            if re.search(pattern, body):
                failure_score += weight
                indicators.append(f"Failure: {pattern[:30]}")

        elif ind_type == "redirect":
            pattern = indicator["pattern"]
            if re.search(pattern, final_url):
                failure_score += weight
                indicators.append(f"Redirect to error: {final_url[:50]}")

        elif ind_type == "status":
            if status == indicator["value"]:
                failure_score += weight
                indicators.append(f"Status {status}")

    # Determine success
    if failure_score > 0.5:
        return False, failure_score, indicators

    if success_score > 0.3:
        return True, success_score, indicators

    # Ambiguous - check if we got new session cookies
    new_cookies = set(response.get("cookies_received", {}).keys()) - pre_login_cookies
    if new_cookies:
        return True, 0.5, indicators + [f"New cookies: {new_cookies}"]

    return False, 0.0, indicators


async def form_login(
    base_url: str,
    username: str,
    password: str,
    login_url: str | None = None,
    username_field: str | None = None,
    password_field: str | None = None,
    extra_fields: dict[str, str] | None = None,
    max_attempts: int = 2,
    follow_redirects: bool = True,
    timeout: int = 30
) -> LoginResult:
    """
    Perform form-based login and return authenticated session.

    Args:
        base_url: Target application base URL
        username: Username/email to login with
        password: Password to login with
        login_url: Explicit login page URL (auto-detected if not provided)
        username_field: Explicit username field name (auto-detected if not provided)
        password_field: Explicit password field name (auto-detected if not provided)
        extra_fields: Additional form fields to submit
        max_attempts: Maximum login attempts
        follow_redirects: Whether to follow redirects after login
        timeout: Request timeout in seconds

    Returns:
        LoginResult with authenticated session if successful
    """
    result = LoginResult(success=False, attempts=0)

    # Create initial session
    config = AuthConfig(timeout=timeout, follow_redirects=follow_redirects)
    session = AuthSession(config=config, base_url=base_url)

    try:
        # Find login page if not provided
        if not login_url:
            login_url = await find_login_page(base_url, session)
            if not login_url:
                result.error = "Could not find login page"
                return result

        result.login_url = login_url

        # Fetch login page
        login_response = await session.get(login_url)
        if login_response.get("status", 0) != 200:
            result.error = f"Failed to fetch login page: status {login_response.get('status')}"
            return result

        login_html = login_response.get("body", "")

        # Parse forms and find login form
        forms = parse_forms(login_html)
        login_form = identify_login_form(forms, login_url)

        if not login_form:
            result.error = "Could not identify login form"
            return result

        # Override field names if provided
        if username_field:
            login_form.username_field = username_field
        if password_field:
            login_form.password_field = password_field

        result.form_used = login_form

        # SECURITY: Refuse to submit credentials to a host different from the
        # scan target. A misidentified or tampered login page could carry
        # `action="https://attacker.example/steal"` and exfiltrate the supplied
        # username/password. Subdomains of the target are allowed (a common
        # legitimate pattern: `https://app.example.com` posts to
        # `https://auth.example.com/login`).
        if not _is_action_safe_for_credentials(login_form.action, base_url):
            result.error = (
                f"Refusing to submit credentials cross-origin: login form action "
                f"{login_form.action!r} is not on the same registrable domain as "
                f"{base_url!r}"
            )
            return result

        # Record pre-login cookies
        pre_login_cookies = set(session.state.cookies_received.keys())

        # Attempt login
        for attempt in range(max_attempts):
            result.attempts = attempt + 1

            # Build form data
            form_data = dict(login_form.hidden_fields)

            # Add CSRF token if present
            if login_form.csrf_field and login_form.csrf_value:
                form_data[login_form.csrf_field] = login_form.csrf_value

            # Add credentials
            form_data[login_form.username_field] = username
            form_data[login_form.password_field] = password

            # Add extra fields
            if extra_fields:
                form_data.update(extra_fields)

            # Submit login form
            login_submit = await session.request(
                method=login_form.method,
                url=login_form.action,
                data=form_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            # Add cookies received to response for checking
            login_submit["cookies_received"] = session.state.cookies_received

            # Check if login succeeded
            success, confidence, indicators = check_login_success(
                login_submit, pre_login_cookies, login_url
            )

            if success:
                result.success = True
                result.session = session
                result.cookies = dict(session.state.cookies_received)
                result.redirect_url = login_submit.get("url")
                return result

            # If CSRF token might have changed, re-fetch login page
            if attempt < max_attempts - 1 and login_form.csrf_field:
                login_response = await session.get(login_url)
                login_html = login_response.get("body", "")
                forms = parse_forms(login_html)
                new_form = identify_login_form(forms, login_url)
                if new_form and new_form.csrf_value:
                    login_form.csrf_value = new_form.csrf_value

        result.error = "Login failed after maximum attempts"
        return result

    except Exception as e:
        result.error = f"Login error: {e!s}"
        return result


async def detect_login_form(
    url: str,
    timeout: int = 30
) -> LoginForm | None:
    """
    Detect login form on a page without attempting to login.

    Args:
        url: URL to check for login form
        timeout: Request timeout

    Returns:
        LoginForm if found, None otherwise
    """
    session = AuthSession(base_url=url)

    try:
        response = await session.get(url)
        if response.get("status") != 200:
            return None

        html = response.get("body", "")
        forms = parse_forms(html)
        return identify_login_form(forms, url)

    except Exception:
        return None
    finally:
        await session.close()


async def test_form_login(
    base_url: str,
    username: str,
    password: str,
    login_url: str | None = None
) -> dict[str, Any]:
    """
    Test form-based login and return detailed results.

    Returns diagnostic information about the login attempt.
    """
    results = {
        "base_url": base_url,
        "login_url": login_url,
        "success": False,
        "form_detected": False,
        "form_details": None,
        "cookies_captured": {},
        "redirect_url": None,
        "error": None,
        "attempts": 0,
        "indicators": []
    }

    login_result = await form_login(
        base_url=base_url,
        username=username,
        password=password,
        login_url=login_url
    )

    results["success"] = login_result.success
    results["login_url"] = login_result.login_url
    results["attempts"] = login_result.attempts
    results["error"] = login_result.error
    results["redirect_url"] = login_result.redirect_url
    results["cookies_captured"] = login_result.cookies

    if login_result.form_used:
        results["form_detected"] = True
        results["form_details"] = {
            "action": login_result.form_used.action,
            "method": login_result.form_used.method,
            "username_field": login_result.form_used.username_field,
            "password_field": login_result.form_used.password_field,
            "csrf_field": login_result.form_used.csrf_field,
            "confidence": login_result.form_used.confidence
        }

    if login_result.session:
        results["session_stats"] = login_result.session.get_stats()
        await login_result.session.close()

    return results


# =============================================================================
# PLAYWRIGHT-BASED LOGIN (for JavaScript-heavy SPAs)
# =============================================================================

# Try to import Playwright
try:
    import os as _os
    if not _os.environ.get("PLAYWRIGHT_BROWSERS_PATH") and _os.path.exists("/ms-playwright"):
        _os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "/ms-playwright"
        _os.environ["PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD"] = "1"
    from playwright.async_api import TimeoutError as PlaywrightTimeout, async_playwright
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False
    async_playwright = None
    PlaywrightTimeout = Exception


@dataclass
class PlaywrightLoginResult:
    """Result of Playwright-based login."""
    success: bool = False
    cookies: dict[str, str] = field(default_factory=dict)
    local_storage: dict[str, str] = field(default_factory=dict)
    session_storage: dict[str, str] = field(default_factory=dict)
    auth_headers: dict[str, str] = field(default_factory=dict)
    final_url: str = ""
    screenshot_b64: str | None = None
    error: str | None = None
    login_duration_ms: float = 0


async def playwright_login(
    login_url: str,
    username: str,
    password: str,
    username_selector: str | None = None,
    password_selector: str | None = None,
    submit_selector: str | None = None,
    success_indicator: str | None = None,
    headless: bool = True,
    timeout: int = 30000,
    wait_after_login: int = 3000,
    capture_screenshot: bool = False
) -> PlaywrightLoginResult:
    """
    Perform login using Playwright browser automation.

    Handles JavaScript-heavy SPAs, React/Vue/Angular apps, and
    multi-step login flows.

    Args:
        login_url: URL of the login page
        username: Username/email to login with
        password: Password to login with
        username_selector: CSS selector for username field (auto-detected if None)
        password_selector: CSS selector for password field (auto-detected if None)
        submit_selector: CSS selector for submit button (auto-detected if None)
        success_indicator: CSS selector that appears after successful login
        headless: Run browser in headless mode
        timeout: Timeout in milliseconds
        wait_after_login: Time to wait after clicking login (for JS redirects)
        capture_screenshot: Capture screenshot after login attempt

    Returns:
        PlaywrightLoginResult with cookies and storage data
    """
    result = PlaywrightLoginResult()

    if not HAS_PLAYWRIGHT:
        result.error = "Playwright not installed"
        return result

    start_time = time.time()

    try:
        async with async_playwright() as p:
            # Launch browser
            browser = await p.chromium.launch(
                headless=headless,
                args=["--no-sandbox", "--disable-setuid-sandbox"]
            )

            # Create context with common browser settings
            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )

            page = await context.new_page()

            try:
                # Navigate to login page
                await page.goto(login_url, timeout=timeout, wait_until="networkidle")

                # Auto-detect selectors if not provided
                if not username_selector:
                    username_selector = await _find_username_field(page)
                if not password_selector:
                    password_selector = await _find_password_field(page)
                if not submit_selector:
                    submit_selector = await _find_submit_button(page)

                if not username_selector or not password_selector:
                    result.error = "Could not find username or password field"
                    return result

                # Fill username
                await page.fill(username_selector, username)
                await page.wait_for_timeout(300)  # Small delay for JS validation

                # Fill password
                await page.fill(password_selector, password)
                await page.wait_for_timeout(300)

                # Click submit or press Enter
                if submit_selector:
                    await page.click(submit_selector)
                else:
                    await page.press(password_selector, "Enter")

                # Wait for navigation or success indicator
                try:
                    if success_indicator:
                        await page.wait_for_selector(success_indicator, timeout=timeout)
                    else:
                        # Wait for URL change or network idle
                        await page.wait_for_load_state("networkidle", timeout=timeout)
                        await page.wait_for_timeout(wait_after_login)
                except PlaywrightTimeout:
                    pass  # Continue anyway, might still have succeeded

                # Capture final URL
                result.final_url = page.url

                # Check for login success
                success = await _check_playwright_login_success(page, login_url)
                result.success = success

                # Capture cookies
                cookies = await context.cookies()
                result.cookies = {c["name"]: c["value"] for c in cookies}

                # Capture localStorage and sessionStorage
                try:
                    result.local_storage = await page.evaluate("""
                        () => {
                            let items = {};
                            for (let i = 0; i < localStorage.length; i++) {
                                let key = localStorage.key(i);
                                items[key] = localStorage.getItem(key);
                            }
                            return items;
                        }
                    """)

                    result.session_storage = await page.evaluate("""
                        () => {
                            let items = {};
                            for (let i = 0; i < sessionStorage.length; i++) {
                                let key = sessionStorage.key(i);
                                items[key] = sessionStorage.getItem(key);
                            }
                            return items;
                        }
                    """)
                except Exception:
                    pass  # Storage access might fail on some pages

                # Look for JWT tokens in storage
                for storage in [result.local_storage, result.session_storage]:
                    for key, value in storage.items():
                        if any(t in key.lower() for t in ["token", "jwt", "auth", "bearer"]):
                            if value and len(value) > 20:
                                result.auth_headers["Authorization"] = f"Bearer {value}"
                                break

                # Capture screenshot if requested
                if capture_screenshot:
                    screenshot = await page.screenshot()
                    result.screenshot_b64 = base64.b64encode(screenshot).decode()

            except PlaywrightTimeout as e:
                result.error = f"Timeout: {e!s}"
            except Exception as e:
                result.error = f"Login error: {e!s}"
            finally:
                await context.close()
                await browser.close()

    except Exception as e:
        result.error = f"Browser error: {e!s}"

    result.login_duration_ms = (time.time() - start_time) * 1000
    return result


async def _find_username_field(page) -> str | None:
    """Auto-detect username/email input field."""
    selectors = [
        'input[type="email"]',
        'input[name*="email" i]',
        'input[name*="user" i]',
        'input[name*="login" i]',
        'input[id*="email" i]',
        'input[id*="user" i]',
        'input[autocomplete="username"]',
        'input[autocomplete="email"]',
        'input[placeholder*="email" i]',
        'input[placeholder*="user" i]',
        'input[type="text"]:first-of-type',
    ]

    for selector in selectors:
        try:
            element = await page.query_selector(selector)
            if element and await element.is_visible():
                return selector
        except Exception:
            pass

    return None


async def _find_password_field(page) -> str | None:
    """Auto-detect password input field."""
    selectors = [
        'input[type="password"]',
        'input[name*="pass" i]',
        'input[id*="pass" i]',
        'input[autocomplete="current-password"]',
    ]

    for selector in selectors:
        try:
            element = await page.query_selector(selector)
            if element and await element.is_visible():
                return selector
        except Exception:
            pass

    return None


async def _find_submit_button(page) -> str | None:
    """Auto-detect submit/login button."""
    selectors = [
        'button[type="submit"]',
        'input[type="submit"]',
        'button:has-text("Log in")',
        'button:has-text("Login")',
        'button:has-text("Sign in")',
        'button:has-text("Submit")',
        'a:has-text("Log in")',
        'a:has-text("Login")',
        '[role="button"]:has-text("Log in")',
    ]

    for selector in selectors:
        try:
            element = await page.query_selector(selector)
            if element and await element.is_visible():
                return selector
        except Exception:
            pass

    return None


async def _check_playwright_login_success(page, original_login_url: str) -> bool:
    """Check if Playwright login succeeded."""
    current_url = page.url
    parsed_original = urlparse(original_login_url)
    parsed_current = urlparse(current_url)

    # URL changed to non-login page
    if parsed_current.path != parsed_original.path:
        if not any(x in parsed_current.path.lower() for x in ["/login", "/signin", "/auth"]):
            return True

    # Check for logout/signout links (indicates logged in)
    try:
        logout_selectors = [
            'a:has-text("Log out")',
            'a:has-text("Logout")',
            'a:has-text("Sign out")',
            'button:has-text("Log out")',
            '[aria-label*="logout" i]',
            '[aria-label*="sign out" i]',
        ]
        for selector in logout_selectors:
            element = await page.query_selector(selector)
            if element and await element.is_visible():
                return True
    except Exception:
        pass

    # Check for error messages (indicates failure)
    try:
        error_selectors = [
            '.error',
            '.alert-danger',
            '[role="alert"]',
            '.login-error',
        ]
        for selector in error_selectors:
            element = await page.query_selector(selector)
            if element and await element.is_visible():
                text = await element.text_content()
                if text and any(x in text.lower() for x in ["invalid", "incorrect", "failed", "error"]):
                    return False
    except Exception:
        pass

    # Default: assume success if we have cookies
    return True


async def create_authenticated_session(
    base_url: str,
    username: str,
    password: str,
    login_url: str | None = None,
    use_playwright: bool = False,
    **kwargs
) -> tuple[AuthSession | None, dict[str, Any]]:
    """
    Create an authenticated session using the best available method.

    Tries form-based login first, falls back to Playwright if needed.

    Args:
        base_url: Target application base URL
        username: Username/email
        password: Password
        login_url: Explicit login URL (auto-detected if not provided)
        use_playwright: Force Playwright usage
        **kwargs: Additional arguments for login functions

    Returns:
        Tuple of (AuthSession or None, diagnostic info dict)
    """
    diagnostics = {
        "method": None,
        "success": False,
        "error": None,
        "cookies_captured": 0,
        "duration_ms": 0
    }

    start = time.time()

    # Try Playwright if requested or if form login fails
    if use_playwright and HAS_PLAYWRIGHT:
        diagnostics["method"] = "playwright"
        result = await playwright_login(
            login_url=login_url or urljoin(base_url, "/login"),
            username=username,
            password=password,
            **kwargs
        )

        diagnostics["success"] = result.success
        diagnostics["error"] = result.error
        diagnostics["cookies_captured"] = len(result.cookies)
        diagnostics["duration_ms"] = result.login_duration_ms

        if result.success:
            # Create session with captured credentials
            session = AuthSession(
                cookies=result.cookies,
                headers=result.auth_headers,
                base_url=base_url
            )
            return session, diagnostics

    # Try form-based login
    diagnostics["method"] = "form"
    result = await form_login(
        base_url=base_url,
        username=username,
        password=password,
        login_url=login_url,
        **{k: v for k, v in kwargs.items() if k in ["username_field", "password_field", "extra_fields", "max_attempts"]}
    )

    diagnostics["success"] = result.success
    diagnostics["error"] = result.error
    diagnostics["cookies_captured"] = len(result.cookies)
    diagnostics["duration_ms"] = (time.time() - start) * 1000

    if result.success and result.session:
        return result.session, diagnostics

    # If form login failed and Playwright available, try Playwright
    if not result.success and HAS_PLAYWRIGHT and not use_playwright:
        diagnostics["method"] = "playwright_fallback"
        pw_result = await playwright_login(
            login_url=result.login_url or urljoin(base_url, "/login"),
            username=username,
            password=password
        )

        if pw_result.success:
            diagnostics["success"] = True
            diagnostics["cookies_captured"] = len(pw_result.cookies)
            diagnostics["duration_ms"] = (time.time() - start) * 1000

            session = AuthSession(
                cookies=pw_result.cookies,
                headers=pw_result.auth_headers,
                base_url=base_url
            )
            return session, diagnostics

    return None, diagnostics


# Export main functions
__all__ = [
    "HAS_PLAYWRIGHT",
    "LoginForm",
    "LoginResult",
    "PlaywrightLoginResult",
    "create_authenticated_session",
    "detect_login_form",
    "find_login_page",
    "form_login",
    "identify_login_form",
    "parse_forms",
    "playwright_login",
    "test_form_login",
]
