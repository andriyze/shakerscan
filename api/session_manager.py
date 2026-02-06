"""
Interactive Session Manager for AI-Assisted Security Testing.

This module manages interactive browser sessions for collaborative security
testing between Claude AI and users. It provides:
- Browser session lifecycle management
- Screenshot capture
- Browser action execution (navigate, click, fill, etc.)
- Network traffic capture for endpoint discovery
- Multi-user authentication for BOLA testing

Usage:
    session = await InteractiveSessionManager.create_session("https://example.com")
    screenshot = await session.screenshot()
    await session.action({"action": "navigate", "url": "/login"})
    result = await session.test_endpoint("/api/users/1", "GET", as_user="user2")
    await session.close()
"""

import asyncio
import base64
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

# Try playwright import - it's optional for session management
try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    async_playwright = None
    Browser = None
    BrowserContext = None
    Page = None


# Session timeout (30 minutes of inactivity)
SESSION_TIMEOUT_SECONDS = 30 * 60

# Maximum concurrent sessions per instance
MAX_SESSIONS = 10

# Memory caps to prevent unbounded growth
MAX_DISCOVERED_ENDPOINTS = 500
MAX_NETWORK_LOG_ENTRIES = 1000
MAX_DISCOVERED_IDS_PER_TYPE = 100

# Allow cross-origin static assets to avoid breaking modern apps (CSP/CORS still apply)
CROSS_ORIGIN_ALLOWED_RESOURCE_TYPES = {
    "image",
    "stylesheet",
    "font",
    "script",
    "media",
    "texttrack",
    "manifest",
}


@dataclass
class DiscoveredEndpoint:
    """An API endpoint discovered during session interaction."""
    url: str
    method: str
    path: str
    status_code: int | None = None
    content_type: str | None = None
    has_auth: bool = False
    params: dict[str, Any] = field(default_factory=dict)
    response_sample: str | None = None


@dataclass
class UserSession:
    """Authentication state for a user within an interactive session."""
    name: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    is_authenticated: bool = False
    auth_method: str | None = None  # "cookie", "jwt", "basic"
    token: str | None = None


@dataclass
class SessionState:
    """Current state of an interactive session."""
    session_id: str
    target_url: str
    created_at: datetime
    last_activity: datetime
    current_url: str | None = None
    users: dict[str, UserSession] = field(default_factory=dict)
    discovered_endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    discovered_ids: dict[str, list[str]] = field(default_factory=dict)  # resource_type -> [ids]
    screenshots_dir: Path | None = None


class InteractiveSession:
    """
    Manages an interactive browser session for security testing.

    Provides browser automation, network capture, and multi-user
    authentication support for testing access control vulnerabilities.
    """

    def __init__(self, session_id: str, target_url: str, results_dir: Path | None = None):
        self.session_id = session_id
        self.target_url = target_url
        self.results_dir = results_dir or Path("/results")

        self.state = SessionState(
            session_id=session_id,
            target_url=target_url,
            created_at=datetime.utcnow(),
            last_activity=datetime.utcnow(),
            screenshots_dir=self.results_dir / "sessions" / session_id
        )

        self._playwright = None
        self._browser: Browser | None = None
        self._contexts: dict[str, BrowserContext] = {}  # user_name -> context
        self._pages: dict[str, Page] = {}  # user_name -> page
        self._user_allowed_origins: dict[str, set[tuple[str, str, int]]] = {}  # user_name -> allowed origins
        self._network_log: list[dict] = []
        self._lock = asyncio.Lock()

    async def start(self) -> dict[str, Any]:
        """Launch browser and navigate to target."""
        if not PLAYWRIGHT_AVAILABLE:
            return {
                "success": False,
                "error": "Playwright not available. Install with: pip install playwright && playwright install chromium"
            }

        start_error: str | None = None
        async with self._lock:
            try:
                # Create screenshots directory
                if self.state.screenshots_dir:
                    self.state.screenshots_dir.mkdir(parents=True, exist_ok=True)

                # Launch playwright
                self._playwright = await async_playwright().start()
                self._browser = await self._playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--disable-web-security",  # Allow cross-origin for testing
                        "--ignore-certificate-errors",
                    ]
                )

                # Create default context and page
                await self._create_user_context("default")

                # Navigate to target
                page = self._pages["default"]
                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=30000)
                self.state.current_url = page.url

                self._update_activity()

                return {
                    "success": True,
                    "session_id": self.session_id,
                    "target": self.target_url,
                    "current_url": self.state.current_url,
                    "message": "Session started successfully"
                }

            except Exception as e:
                start_error = str(e)

        # Cleanup outside lock to avoid re-entrant deadlock on self.close().
        await self.close()
        return {
            "success": False,
            "error": f"Failed to start session: {start_error or 'unknown error'}"
        }

    async def _create_user_context(self, user_name: str) -> BrowserContext:
        """Create a new browser context for a user."""
        context = await self._browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

        # Set up network interception
        page = await context.new_page()

        # Initialize allowed origins for this user (additional origins beyond target)
        self._user_allowed_origins[user_name] = set()

        # Global route handler to block cross-origin requests (SSRF prevention)
        # This catches redirects, form submissions, and any other navigation
        async def route_handler(route):
            request_url = route.request.url
            # Allow data/blob/about URLs (inline resources)
            if request_url.startswith(("data:", "blob:", "about:")):
                await route.continue_()
                return

            # Always allow same-origin
            if self._is_in_scope(request_url):
                await route.continue_()
                return

            # Allow explicitly permitted origins for this user
            origin_key = self._origin_key(request_url)
            if origin_key and origin_key in self._user_allowed_origins.get(user_name, set()):
                await route.continue_()
                return

            # Allow cross-origin static assets to avoid breaking app rendering
            if route.request.resource_type in CROSS_ORIGIN_ALLOWED_RESOURCE_TYPES:
                await route.continue_()
                return

            # Block cross-origin navigation/requests by default
            await route.abort("blockedbyclient")

        await page.route("**/*", route_handler)

        async def on_response(response):
            try:
                url = response.url
                if self._is_in_scope(url):
                    endpoint = DiscoveredEndpoint(
                        url=url,
                        method=response.request.method,
                        path=urlparse(url).path,
                        status_code=response.status,
                        content_type=response.headers.get("content-type"),
                        has_auth="authorization" in {k.lower() for k in response.request.headers.keys()}
                    )

                    # Extract IDs from URL path
                    self._extract_ids_from_url(url)

                    # Add to discovered endpoints if unique (with cap)
                    if len(self.state.discovered_endpoints) < MAX_DISCOVERED_ENDPOINTS:
                        if not any(e.path == endpoint.path and e.method == endpoint.method
                                  for e in self.state.discovered_endpoints):
                            self.state.discovered_endpoints.append(endpoint)

                    # Log network traffic (with cap - drop oldest if full)
                    if len(self._network_log) >= MAX_NETWORK_LOG_ENTRIES:
                        self._network_log.pop(0)
                    self._network_log.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "user": user_name,
                        "method": response.request.method,
                        "url": url,
                        "status": response.status,
                    })
            except Exception:
                pass

        page.on("response", on_response)

        self._contexts[user_name] = context
        self._pages[user_name] = page

        if user_name not in self.state.users:
            self.state.users[user_name] = UserSession(name=user_name)

        return context

    def _get_effective_origin(self, parsed_url) -> tuple[str, str, int]:
        """Get normalized origin (scheme, host, port) with default port handling."""
        scheme = parsed_url.scheme.lower()
        host = (parsed_url.hostname or "").lower()
        port = parsed_url.port
        # Normalize default ports
        if port is None:
            port = 443 if scheme == "https" else 80
        elif (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            port = 443 if scheme == "https" else 80
        return (scheme, host, port)

    def _origin_key(self, url: str) -> tuple[str, str, int] | None:
        """Return normalized origin tuple for http/https URLs."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                return None
            return self._get_effective_origin(parsed)
        except Exception:
            return None

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope (same origin as target, with port normalization)."""
        try:
            target_parsed = urlparse(self.target_url)
            url_parsed = urlparse(url)
            return self._get_effective_origin(target_parsed) == self._get_effective_origin(url_parsed)
        except Exception:
            return False

    def _extract_ids_from_url(self, url: str):
        """Extract potential resource IDs from URL path."""
        path = urlparse(url).path

        # Common ID patterns
        patterns = [
            (r"/(\d+)(?:/|$)", "numeric_id"),
            (r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)", "uuid"),
            (r"/([a-zA-Z0-9]{20,})(?:/|$)", "token_id"),
        ]

        for pattern, id_type in patterns:
            matches = re.findall(pattern, path, re.IGNORECASE)
            for match in matches:
                if id_type not in self.state.discovered_ids:
                    self.state.discovered_ids[id_type] = []
                # Cap IDs per type to prevent memory bloat
                if len(self.state.discovered_ids[id_type]) < MAX_DISCOVERED_IDS_PER_TYPE:
                    if match not in self.state.discovered_ids[id_type]:
                        self.state.discovered_ids[id_type].append(match)

    def _update_activity(self):
        """Update last activity timestamp."""
        self.state.last_activity = datetime.utcnow()

    def is_expired(self) -> bool:
        """Check if session has timed out."""
        elapsed = (datetime.utcnow() - self.state.last_activity).total_seconds()
        return elapsed > SESSION_TIMEOUT_SECONDS

    async def screenshot(self, full_page: bool = False, user: str = "default") -> dict[str, Any]:
        """Capture screenshot of current page."""
        async with self._lock:
            try:
                page = self._pages.get(user)
                if not page:
                    return {"success": False, "error": f"No page for user '{user}'"}

                screenshot_bytes = await page.screenshot(full_page=full_page)
                screenshot_b64 = base64.b64encode(screenshot_bytes).decode()

                # Optionally save to disk (don't fail if disk write fails)
                saved_path = None
                if self.state.screenshots_dir:
                    try:
                        self.state.screenshots_dir.mkdir(parents=True, exist_ok=True)
                        filename = f"{int(time.time())}_{user}.png"
                        filepath = self.state.screenshots_dir / filename
                        filepath.write_bytes(screenshot_bytes)
                        saved_path = str(filepath)
                    except Exception:
                        pass  # Disk write is best-effort

                self._update_activity()

                result = {
                    "success": True,
                    "format": "base64",
                    "data": screenshot_b64,
                    "url": page.url,
                    "user": user
                }
                if saved_path:
                    result["saved_path"] = saved_path
                return result

            except Exception as e:
                return {"success": False, "error": f"Screenshot failed: {str(e)}"}

    async def screenshot_raw(self, full_page: bool = False, user: str = "default") -> bytes | None:
        """Capture screenshot and return raw PNG bytes (or None on error)."""
        async with self._lock:
            try:
                page = self._pages.get(user)
                if not page:
                    return None

                screenshot_bytes = await page.screenshot(full_page=full_page)
                self._update_activity()
                return screenshot_bytes

            except Exception:
                return None

    async def action(self, action_data: dict[str, Any]) -> dict[str, Any]:
        """
        Execute a browser action.

        Supported actions:
        - navigate: Go to URL
        - click: Click element by selector
        - fill: Fill input field
        - register: Register new user account
        - login: Login with credentials
        - submit: Submit current form
        - wait: Wait for selector or timeout
        - extract: Extract data from page
        """
        async with self._lock:
            action_type = action_data.get("action")
            user = action_data.get("user", "default")
            data = action_data.get("data", {})

            page = self._pages.get(user)
            if not page:
                # Create context for new user
                await self._create_user_context(user)
                page = self._pages[user]
                # Navigate to target
                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=30000)

            try:
                result = {"success": True, "action": action_type, "user": user}

                if action_type == "navigate":
                    url = data.get("url", "")
                    if not url.startswith(("http://", "https://")):
                        url = urljoin(self.target_url, url)
                    # Check scope - route handler will also enforce this
                    allow_out_of_scope = data.get("allow_out_of_scope", False)
                    if not allow_out_of_scope and not self._is_in_scope(url):
                        return {
                            "success": False,
                            "error": f"URL '{url}' is out of scope. Use relative paths or set allow_out_of_scope=True.",
                            "action": action_type
                        }
                    # Update allowed origins (enables cross-origin navigation when explicitly allowed)
                    if allow_out_of_scope:
                        origin_key = self._origin_key(url)
                        if origin_key:
                            self._user_allowed_origins[user] = {origin_key}
                    else:
                        self._user_allowed_origins[user] = set()
                    await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                    result["url"] = page.url
                    self.state.current_url = page.url

                elif action_type == "click":
                    selector = data.get("selector")
                    if not selector:
                        return {"success": False, "error": "No selector provided"}
                    await page.click(selector, timeout=10000)
                    result["selector"] = selector

                elif action_type == "fill":
                    selector = data.get("selector")
                    value = data.get("value", "")
                    if not selector:
                        return {"success": False, "error": "No selector provided"}
                    await page.fill(selector, value, timeout=10000)
                    result["selector"] = selector

                elif action_type == "register":
                    result = await self._handle_register(page, user, data)

                elif action_type == "login":
                    result = await self._handle_login(page, user, data)

                elif action_type == "submit":
                    selector = data.get("selector", "form")
                    form = await page.query_selector(selector)
                    if form:
                        await page.evaluate("(form) => form.submit()", form)
                        await page.wait_for_load_state("domcontentloaded", timeout=10000)
                    result["url"] = page.url

                elif action_type == "wait":
                    selector = data.get("selector")
                    timeout = data.get("timeout", 5000)
                    if selector:
                        await page.wait_for_selector(selector, timeout=timeout)
                    else:
                        await asyncio.sleep(timeout / 1000)
                    result["waited"] = True

                elif action_type == "extract":
                    selector = data.get("selector")
                    attribute = data.get("attribute")
                    if selector:
                        elements = await page.query_selector_all(selector)
                        values = []
                        for el in elements:
                            if attribute:
                                val = await el.get_attribute(attribute)
                            else:
                                val = await el.text_content()
                            values.append(val)
                        result["values"] = values
                    else:
                        # Extract page content
                        result["html"] = await page.content()

                else:
                    return {"success": False, "error": f"Unknown action: {action_type}"}

                self._update_activity()
                return result

            except Exception as e:
                return {"success": False, "error": f"Action failed: {str(e)}", "action": action_type}

    async def _handle_register(self, page: Page, user: str, data: dict) -> dict[str, Any]:
        """Handle user registration action."""
        email = data.get("email")
        password = data.get("password")
        extra_fields = data.get("extra_fields", {})

        if not email or not password:
            return {"success": False, "error": "Email and password required"}

        # Common registration form selectors
        email_selectors = [
            'input[type="email"]',
            'input[name="email"]',
            'input[name="username"]',
            'input[id="email"]',
            '#email',
        ]
        password_selectors = [
            'input[type="password"]',
            'input[name="password"]',
            '#password',
        ]
        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Register")',
            'button:has-text("Sign up")',
            'button:has-text("Create")',
        ]

        try:
            # Try to find and fill email
            for selector in email_selectors:
                try:
                    el = await page.query_selector(selector)
                    if el:
                        await el.fill(email)
                        break
                except Exception:
                    continue

            # Fill password and confirm password
            password_inputs = await page.query_selector_all('input[type="password"]')
            for inp in password_inputs:
                await inp.fill(password)

            # Fill extra fields
            for name, value in extra_fields.items():
                try:
                    await page.fill(f'input[name="{name}"]', value)
                except Exception:
                    pass

            # Submit form
            for selector in submit_selectors:
                try:
                    btn = await page.query_selector(selector)
                    if btn:
                        await btn.click()
                        await page.wait_for_load_state("networkidle", timeout=10000)
                        break
                except Exception:
                    continue

            # Update user session
            self.state.users[user] = UserSession(
                name=user,
                is_authenticated=False,  # Not yet logged in
            )

            return {
                "success": True,
                "action": "register",
                "user": user,
                "email": email,
                "url": page.url
            }

        except Exception as e:
            return {"success": False, "error": f"Registration failed: {str(e)}"}

    async def _handle_login(self, page: Page, user: str, data: dict) -> dict[str, Any]:
        """Handle user login action."""
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return {"success": False, "error": "Email and password required"}

        # Common login form selectors
        email_selectors = [
            'input[type="email"]',
            'input[name="email"]',
            'input[name="username"]',
            'input[id="email"]',
            '#email',
        ]
        password_selectors = [
            'input[type="password"]',
            'input[name="password"]',
            '#password',
        ]
        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Login")',
            'button:has-text("Sign in")',
            'button:has-text("Log in")',
        ]

        try:
            # Fill email
            for selector in email_selectors:
                try:
                    el = await page.query_selector(selector)
                    if el:
                        await el.fill(email)
                        break
                except Exception:
                    continue

            # Fill password
            for selector in password_selectors:
                try:
                    el = await page.query_selector(selector)
                    if el:
                        await el.fill(password)
                        break
                except Exception:
                    continue

            # Submit
            for selector in submit_selectors:
                try:
                    btn = await page.query_selector(selector)
                    if btn:
                        await btn.click()
                        await page.wait_for_load_state("networkidle", timeout=10000)
                        break
                except Exception:
                    continue

            # Capture cookies and detect auth
            context = self._contexts[user]
            cookies = await context.cookies()
            cookie_dict = {c["name"]: c["value"] for c in cookies}

            # Look for auth tokens in localStorage
            token = None
            try:
                token = await page.evaluate("() => localStorage.getItem('token') || localStorage.getItem('access_token') || localStorage.getItem('jwt')")
            except Exception:
                pass

            # Update user session
            auth_method = None
            if token:
                auth_method = "jwt"
            elif any(name.lower() in ["session", "sessionid", "sid", "auth"] for name in cookie_dict.keys()):
                auth_method = "cookie"

            self.state.users[user] = UserSession(
                name=user,
                cookies=cookie_dict,
                headers={"Authorization": f"Bearer {token}"} if token else {},
                is_authenticated=bool(token or auth_method == "cookie"),
                auth_method=auth_method,
                token=token
            )

            return {
                "success": True,
                "action": "login",
                "user": user,
                "email": email,
                "is_authenticated": self.state.users[user].is_authenticated,
                "auth_method": auth_method,
                "url": page.url,
                "cookies_count": len(cookie_dict)
            }

        except Exception as e:
            return {"success": False, "error": f"Login failed: {str(e)}"}

    async def test_endpoint(
        self,
        endpoint: str,
        method: str = "GET",
        as_user: str | None = None,
        body: dict | None = None,
        allow_out_of_scope: bool = False
    ) -> dict[str, Any]:
        """
        Test a specific endpoint with optional user authentication.

        This is the core BOLA testing function - it makes a request to an
        endpoint using one user's session to test access control.

        By default, only same-origin requests are allowed to prevent SSRF.
        Set allow_out_of_scope=True to test cross-origin endpoints (use with caution).
        """
        async with self._lock:
            try:
                # Build full URL
                if not endpoint.startswith(("http://", "https://")):
                    url = urljoin(self.target_url, endpoint)
                else:
                    url = endpoint

                # Enforce same-origin by default to prevent SSRF
                if not allow_out_of_scope and not self._is_in_scope(url):
                    return {
                        "success": False,
                        "error": f"Endpoint '{endpoint}' is out of scope (different origin than {self.target_url}). "
                                 "Use relative paths or set allow_out_of_scope=True if cross-origin testing is intended.",
                        "endpoint": endpoint,
                        "method": method,
                        "as_user": as_user
                    }

                # Get user session for authentication
                user_session = None
                if as_user and as_user in self.state.users:
                    user_session = self.state.users[as_user]

                user_key = as_user or "default"
                # Use page context for the request to leverage cookies
                page = self._pages.get(user_key)
                if not page:
                    await self._create_user_context(user_key)
                    page = self._pages[user_key]

                # Make the request using page.evaluate (fetch API)
                headers = {}
                if user_session and user_session.headers:
                    headers.update(user_session.headers)

                fetch_options = {
                    "method": method,
                    "headers": headers,
                    "credentials": "include",  # Include cookies
                }

                if body and method in ["POST", "PUT", "PATCH"]:
                    fetch_options["body"] = json.dumps(body)
                    fetch_options["headers"]["Content-Type"] = "application/json"

                # Temporarily allow cross-origin fetch if explicitly requested
                original_allowed = set(self._user_allowed_origins.get(user_key, set()))
                if allow_out_of_scope:
                    origin_key = self._origin_key(url)
                    if origin_key:
                        updated_allowed = set(original_allowed)
                        updated_allowed.add(origin_key)
                        self._user_allowed_origins[user_key] = updated_allowed

                try:
                    # Execute fetch via browser
                    result = await page.evaluate("""
                        async ({url, options}) => {
                            try {
                                const response = await fetch(url, options);
                                const text = await response.text();
                                let json = null;
                                try { json = JSON.parse(text); } catch {}
                                return {
                                    status: response.status,
                                    statusText: response.statusText,
                                    headers: Object.fromEntries(response.headers.entries()),
                                    body: text.substring(0, 5000),
                                    json: json,
                                    ok: response.ok
                                };
                            } catch (e) {
                                return { error: e.message };
                            }
                        }
                    """, {"url": url, "options": fetch_options})
                finally:
                    # Restore original allowed origins
                    self._user_allowed_origins[user_key] = original_allowed

                self._update_activity()

                if "error" in result:
                    return {
                        "success": False,
                        "error": result["error"],
                        "endpoint": endpoint,
                        "method": method,
                        "as_user": as_user
                    }

                return {
                    "success": True,
                    "endpoint": endpoint,
                    "method": method,
                    "as_user": as_user,
                    "status": result.get("status"),
                    "status_text": result.get("statusText"),
                    "headers": result.get("headers", {}),
                    "body": result.get("body"),
                    "json": result.get("json"),
                    "accessible": result.get("ok", False)
                }

            except Exception as e:
                return {
                    "success": False,
                    "error": f"Request failed: {str(e)}",
                    "endpoint": endpoint,
                    "method": method,
                    "as_user": as_user
                }

    async def get_state(self) -> dict[str, Any]:
        """Get current session state."""
        return {
            "session_id": self.state.session_id,
            "target_url": self.state.target_url,
            "current_url": self.state.current_url,
            "created_at": self.state.created_at.isoformat(),
            "last_activity": self.state.last_activity.isoformat(),
            "users": {
                name: {
                    "is_authenticated": user.is_authenticated,
                    "auth_method": user.auth_method,
                    "cookies_count": len(user.cookies)
                }
                for name, user in self.state.users.items()
            },
            "discovered_endpoints_count": len(self.state.discovered_endpoints),
            "discovered_endpoints": [
                {"path": e.path, "method": e.method, "status": e.status_code}
                for e in self.state.discovered_endpoints[:20]
            ],
            "discovered_ids": self.state.discovered_ids,
            "network_log_count": len(self._network_log)
        }

    async def close(self):
        """Close the session and cleanup resources."""
        async with self._lock:
            try:
                for context in self._contexts.values():
                    try:
                        await context.close()
                    except Exception:
                        pass

                if self._browser:
                    try:
                        await self._browser.close()
                    except Exception:
                        pass

                if self._playwright:
                    try:
                        await self._playwright.stop()
                    except Exception:
                        pass

            except Exception:
                pass

            self._browser = None
            self._playwright = None
            self._contexts.clear()
            self._pages.clear()


class InteractiveSessionManager:
    """
    Global manager for interactive sessions.

    Handles session lifecycle, cleanup, and provides thread-safe access.
    """

    _instance = None
    _lock = asyncio.Lock()

    def __init__(self):
        self.sessions: dict[str, InteractiveSession] = {}
        self._cleanup_task: asyncio.Task | None = None

    @classmethod
    async def get_instance(cls) -> "InteractiveSessionManager":
        """Get singleton instance."""
        async with cls._lock:
            if cls._instance is None:
                cls._instance = InteractiveSessionManager()
            return cls._instance

    async def create_session(self, target_url: str, results_dir: Path | None = None) -> InteractiveSession:
        """Create a new interactive session."""
        if len(self.sessions) >= MAX_SESSIONS:
            # Clean up expired sessions first
            await self._cleanup_expired()
            if len(self.sessions) >= MAX_SESSIONS:
                raise RuntimeError(f"Maximum sessions ({MAX_SESSIONS}) reached")

        session_id = secrets.token_urlsafe(16)
        session = InteractiveSession(session_id, target_url, results_dir)
        self.sessions[session_id] = session

        # Start cleanup task if not running
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        return session

    async def get_session(self, session_id: str) -> InteractiveSession | None:
        """Get session by ID."""
        session = self.sessions.get(session_id)
        if session and session.is_expired():
            await self.close_session(session_id)
            return None
        return session

    async def close_session(self, session_id: str) -> bool:
        """Close and remove a session."""
        session = self.sessions.pop(session_id, None)
        if session:
            await session.close()
            return True
        return False

    async def _cleanup_expired(self):
        """Remove expired sessions."""
        expired = [sid for sid, session in self.sessions.items() if session.is_expired()]
        for sid in expired:
            await self.close_session(sid)

    async def _cleanup_loop(self):
        """Background task to cleanup expired sessions."""
        while self.sessions:
            await asyncio.sleep(60)  # Check every minute
            await self._cleanup_expired()
