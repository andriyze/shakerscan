import asyncio
import os
import re
import secrets
import sys
import urllib.parse
from contextlib import asynccontextmanager
from typing import Any

from .common import run, normalize_hash_route_url

# Optional Playwright
try:
    # Ensure browsers path is set if preinstalled path exists
    # Base image mcr.microsoft.com/playwright/python:v1.54.0-jammy has browsers at /ms-playwright
    if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH") and os.path.exists("/ms-playwright"):
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "/ms-playwright"
        os.environ["PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD"] = "1"
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False


_BROWSER_CRAWL_STATIC_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".map",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".avi",
    ".mov", ".zip", ".tar", ".gz", ".rar", ".7z", ".pdf",
}


def _redirect_chain_from_header_blocks(start_url: str, blocks: list[str]) -> list[str]:
    """Recover each concrete Location hop from curl's followed header blocks."""
    current = str(start_url or "").strip()
    chain: list[str] = []
    for block in blocks:
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if not lines or not lines[0].startswith("HTTP/"):
            continue
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            continue
        if status < 300 or status >= 400:
            continue
        location = None
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if sep and name.strip().lower() == "location":
                location = value.strip()
                break
        if not location:
            continue
        destination = urllib.parse.urljoin(current, location)
        if destination and destination not in chain:
            chain.append(destination)
        current = destination or current
    return chain


async def curl_headers(url: str, http3: bool = False) -> dict[str, Any]:
    cmd = ["curl", "-sS", "-I", "-L", "-k", "--max-redirs", "5", url]
    if http3:
        cmd.insert(-1, "--http3")
    out, err, rc = await run(cmd, timeout=45)
    blocks = [b for b in re.split(r"\r?\n\r?\n", out) if b.strip()] if out else []
    redirect_chain = _redirect_chain_from_header_blocks(url, blocks)
    headers: dict[str, list[str]] = {}
    status = None
    if blocks:
        last = blocks[-1]
        lines = [l for l in last.splitlines() if l]
        if lines:
            status = lines[0].strip()
            for l in lines[1:]:
                if ":" in l:
                    k, v = l.split(":", 1)
                    headers.setdefault(k.strip().lower(), []).append(v.strip())
    # Fallback: if HEAD returns 405 or no status, retry GET and parse headers
    if (not status) or (" 405" in status):
        get_out, _, get_rc = await run(["curl", "-sS", "-i", "-L", "-k", "--max-redirs", "5", url], timeout=45)
        if get_rc == 0 and get_out:
            blocks2 = [b for b in re.split(r"\r?\n\r?\n", get_out) if b.strip()]
            redirect_chain = _redirect_chain_from_header_blocks(url, blocks2)
            if blocks2:
                # Find the last header block (line starts with HTTP/)
                header_block = None
                for blk in reversed(blocks2):
                    first = blk.splitlines()[0] if blk else ""
                    if first.startswith("HTTP/"):
                        header_block = blk
                        break
                if header_block:
                    lines2 = [l for l in header_block.splitlines() if l]
                    status = lines2[0].strip()
                    headers = {}
                    for l in lines2[1:]:
                        if ":" in l:
                            k, v = l.split(":", 1)
                            headers.setdefault(k.strip().lower(), []).append(v.strip())
    out2, _, _ = await run([
        "curl", "-sS", "-o", "/dev/null", "-w", "%{url_effective}\\n%{remote_ip}",
        "-L", "-k", "--max-redirs", "5", url,
    ])
    effective_lines = [line.strip() for line in str(out2 or "").splitlines()]
    final_url = effective_lines[0] if effective_lines and effective_lines[0] else url
    remote_ip = effective_lines[1] if len(effective_lines) > 1 and effective_lines[1] else None
    if final_url != url and final_url not in redirect_chain:
        redirect_chain.append(final_url)
    # HTTP/3 advertisement via alt-svc
    alt_svc = ",".join(headers.get("alt-svc", [])) if headers else ""
    advertises_h3 = "h3=" in alt_svc.lower() if alt_svc else False
    return {
        "status": status,
        "headers": headers,
        "request_url": url,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "remote_ip": remote_ip,
        "raw": out,
        "advertises_h3": advertises_h3,
    }


async def supports_http2(url: str) -> bool:
    out, err, rc = await run(["curl", "-sS", "-I", "--http2", "-k", url])
    return rc == 0 and ("HTTP/2" in out or "HTTP/2" in err or " h2" in out)


async def supports_http3(url: str) -> bool | None:
    """
    Check if server actually supports HTTP/3.

    Returns:
        True: HTTP/3 connection succeeded
        False: HTTP/3 connection explicitly failed
        None: Cannot determine (curl doesn't support --http3)

    Note: Most curl installations don't have HTTP/3 support compiled in.
    Use advertises_h3 from curl_headers() for alt-svc based detection.
    """
    # First check if curl supports --http3
    version_out, _, _ = await run(["curl", "--version"])
    if "HTTP3" not in version_out and "http3" not in version_out.lower():
        # Curl doesn't have HTTP/3 support compiled in
        return None

    out, err, rc = await run(["curl", "-sS", "-I", "--http3", "-k", "--max-time", "5", url])
    if rc != 0:
        # Check if it's a capability issue vs actual failure
        if "not supported" in (err or "").lower() or "unknown option" in (err or "").lower():
            return None
        return False

    # Only return True if we actually see HTTP/3 in the response
    return "HTTP/3" in out or "HTTP/3" in err


def parse_security_headers(h: dict[str, list[str]]) -> dict[str, Any]:
    def get1(k: str):
        v = h.get(k, []) or h.get(k.lower(), [])
        return v[0] if v else None

    return {
        "hsts": get1("strict-transport-security"),
        "csp": get1("content-security-policy"),
        "x_frame_options": get1("x-frame-options"),
        "x_content_type_options": get1("x-content-type-options"),
        "referrer_policy": get1("referrer-policy"),
        "permissions_policy": get1("permissions-policy") or get1("feature-policy"),
        "x_xss_protection": get1("x-xss-protection"),
        "coep": get1("cross-origin-embedder-policy"),
        "coop": get1("cross-origin-opener-policy"),
        "corp": get1("cross-origin-resource-policy"),
        "server": get1("server"),
    }


def analyze_csp(csp: str | None) -> dict[str, Any]:
    if not csp:
        return {"present": False, "grade": "F", "score": 0, "issues": ["CSP header missing."]}
    issues: list[str] = []
    score = 100
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        k, *vals = part.split()
        directives[k.lower()] = [v.strip() for v in vals]

    def has_any(d: str, *vals: str) -> bool:
        vs = [v.lower() for v in directives.get(d, [])]
        return any(v in vs for v in vals)

    missing_default = "default-src" not in directives
    missing_script = "script-src" not in directives
    if missing_default:
        score -= 15
        issues.append("Missing default-src.")
    else:
        if has_any("default-src", "*", "data:", "blob:"):
            score -= 10
            issues.append("default-src overly broad (*, data:, or blob:).")
        if has_any("default-src", "'none'"):
            score += 2

    if missing_script:
        score -= 12
        issues.append("Missing script-src.")

    if has_any("script-src", "'unsafe-inline'"):
        score -= 20
        issues.append("script-src allows 'unsafe-inline'. Consider nonces/hashes.")
    if has_any("script-src", "'unsafe-eval'"):
        score -= 10
        issues.append("script-src allows 'unsafe-eval'.")
    if has_any("script-src", "*"):
        score -= 8
        issues.append("script-src wildcard *.")
    if has_any("style-src", "'unsafe-inline'"):
        score -= 6
        issues.append("style-src allows 'unsafe-inline'.")
    if "object-src" not in directives or has_any("object-src", "*"):
        score -= 6
        issues.append("object-src missing or wildcard. Prefer 'none'.")
    if "frame-ancestors" not in directives:
        score -= 6
        issues.append("frame-ancestors missing.")
    elif has_any("frame-ancestors", "*"):
        score -= 8
        issues.append("frame-ancestors wildcard *.")
    if "upgrade-insecure-requests" not in directives:
        issues.append("upgrade-insecure-requests missing (optional).")
    if not has_any("require-trusted-types-for", "'script'"):
        issues.append("Trusted Types not required (optional).")

    if missing_default and missing_script:
        # Apply an additional penalty when both core directives are missing
        score -= 10
        issues.append("Critical: both default-src and script-src missing.")

    score = max(0, min(100, score))
    grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 75 else "C" if score >= 65 else "D" if score >= 50 else "F"
    return {"present": True, "grade": grade, "score": score, "issues": issues, "directives": directives}


def analyze_cookies(h: dict[str, list[str]]) -> dict[str, Any]:
    sets = h.get("set-cookie", []) + h.get("Set-Cookie", [])
    issues: list[str] = []
    details = []
    for raw in sets:
        flags = {"secure": "secure" in raw.lower(), "httponly": "httponly" in raw.lower(), "samesite": None}
        m = re.search(r"(?i)samesite=(lax|strict|none)", raw)
        if m:
            flags["samesite"] = m.group(1).lower()
        if not flags["secure"]:
            issues.append("Cookie without Secure.")
        if not flags["httponly"]:
            issues.append("Cookie without HttpOnly.")
        if flags["samesite"] is None:
            issues.append("Cookie without SameSite.")
        details.append({"raw": raw[:400], **flags})
    return {"count": len(sets), "issues": sorted(set(issues)), "details": details[:20]}


async def fetch_security_txt(base_url: str) -> dict[str, Any]:
    if not base_url.startswith("http"):
        base_url = "https://" + base_url
    u = urllib.parse.urljoin(base_url, "/.well-known/security.txt")
    out, err, rc = await run(["curl", "-sS", "-L", "-k", u])
    body = (out or "").strip()
    # RFC9116: treat present only if recognizable directives appear
    directive_markers = (
        "contact:", "expires:", "acknowledgments:", "encryption:",
        "preferred-languages:", "policy:", "hiring:", "canonical:"
    )
    present = rc == 0 and body and any(m in body.lower() for m in directive_markers)
    return {"present": present, "url": u, "sample": (body[:500] if present else None)}


@asynccontextmanager
async def _pw():
    if not HAS_PLAYWRIGHT:
        import sys
        print("[_pw] Playwright not available, yielding None", file=sys.stderr)
        yield None
        return
    try:
        p = await async_playwright().start()
        browser = await p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-blink-features=AutomationControlled", "--disable-web-security"], headless=True)
    except Exception as e:
        import sys
        print(f"[_pw] Failed to launch browser: {type(e).__name__}: {e}", file=sys.stderr)
        raise
    try:
        yield browser
    finally:
        await browser.close()
        await p.stop()


async def browser_fetch(
    url: str,
    screenshot_dir: str = "/tmp",
    no_browser: bool = False,
    auth_session: Any | None = None,
    crawl: bool = False,
    max_pages: int = 6,
    max_depth: int = 2,
    max_links_per_page: int = 40,
    seed_urls: list[str] | None = None
) -> dict:
    async def curl_fallback(reason: str = "unknown"):
        print(f"[browser_fetch] Using curl fallback ({reason}) - no network capture available", file=sys.stderr)
        out, err, rc = await run(["curl", "-sS", "-I", "-L", "-k", url])
        headers = {}
        status = None
        if out:
            lines = out.splitlines()
            if lines:
                status = lines[0]
                for line in lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = [v.strip()]
        if not status:
            status = "HTTP/? 0"
        return {
            "headers": headers,
            "status": status,
            "title": "Unknown (Browser not available)",
            "http_version": "?",
            "csp": headers.get("content-security-policy", [None])[0],
            "screenshot_path": None,
            "tech_stack": [],
            "captured_requests": [],
            "api_endpoints": [],
            "websocket_endpoints": [],
            "page_urls": [url],
            "crawl_stats": None,
        }

    if no_browser:
        return await curl_fallback("no_browser=True")
    if not HAS_PLAYWRIGHT:
        return await curl_fallback("Playwright not installed")
    try:
        async with _pw() as browser:
            if browser is None:
                return await curl_fallback("browser launch returned None")
            print(f"[browser_fetch] Using Playwright browser for {url} - network capture enabled", file=sys.stderr)
            ctx_kwargs: dict[str, Any] = {
                "ignore_https_errors": True,
                "user_agent": "Mozilla/5.0",
            }
            auth_cookies: list[dict[str, Any]] = []
            if auth_session:
                try:
                    exported = auth_session.export_session()
                    headers = exported.get("headers", {}) or {}
                    headers = {k: v for k, v in headers.items() if str(k).lower() != "cookie"}
                    if headers:
                        ctx_kwargs["extra_http_headers"] = headers
                    cookie_map = exported.get("cookies", {}) or {}
                    if cookie_map:
                        base_domain = urllib.parse.urlparse(url).hostname or urllib.parse.urlparse(url).netloc
                        if base_domain:
                            for name, value in cookie_map.items():
                                auth_cookies.append({
                                    "name": name,
                                    "value": value,
                                    "domain": base_domain,
                                    "path": "/",
                                })
                except Exception:
                    auth_cookies = []

            ctx = await browser.new_context(**ctx_kwargs)
            if auth_cookies:
                try:
                    await ctx.add_cookies(auth_cookies)
                except Exception:
                    pass
            page = await ctx.new_page()
            status_line = None
            http_version = "?"
            tech_stack: list[str] = []

            # Network capture for API endpoint discovery
            captured_requests: list[dict[str, Any]] = []
            seen_urls: set = set()

            # Resource types to skip (static assets)
            skip_types = {"image", "stylesheet", "font", "media", "manifest", "other"}

            def handle_request(request):
                """Capture outgoing requests with full context for replay."""
                try:
                    resource_type = request.resource_type
                    req_url = request.url

                    # Skip static assets and already-seen URLs
                    if resource_type in skip_types:
                        return
                    if req_url in seen_urls:
                        return
                    seen_urls.add(req_url)

                    # Parse URL to extract path and query params
                    parsed = urllib.parse.urlparse(req_url)

                    # Focus on XHR/fetch requests (most likely API calls)
                    is_api_call = (
                        resource_type in ("xhr", "fetch") or
                        "/api/" in parsed.path.lower() or
                        parsed.path.endswith((".json", ".graphql")) or
                        "graphql" in parsed.path.lower()
                    )

                    # Extract relevant headers
                    req_headers = request.headers
                    auth_header = req_headers.get("authorization", "")
                    content_type = req_headers.get("content-type", "")

                    # Capture POST/PUT/PATCH body for replay
                    post_data = None
                    try:
                        post_data = request.post_data
                    except Exception:
                        pass

                    captured_requests.append({
                        "url": req_url,
                        "method": request.method,
                        "resource_type": resource_type,
                        "path": parsed.path,
                        "query": parsed.query,
                        "is_api_call": is_api_call,
                        "has_auth": bool(auth_header),
                        "content_type": content_type,
                        "headers": dict(req_headers),  # Full headers for replay
                        "post_data": post_data,  # Request body for replay
                    })
                except Exception:
                    pass  # Don't let capture errors break the scan

            def handle_response(response):
                """Capture response metadata for captured requests."""
                try:
                    resp_url = response.url
                    # Find matching request and add response info
                    for req in captured_requests:
                        if req["url"] == resp_url and "status" not in req:
                            req["status"] = response.status
                            resp_headers = response.headers
                            req["response_content_type"] = resp_headers.get("content-type", "")
                            break
                except Exception:
                    pass

            # WebSocket endpoint detection
            websocket_endpoints: list[str] = []
            seen_ws_urls: set = set()

            def handle_websocket(ws):
                """Capture WebSocket connections for security testing."""
                try:
                    ws_url = ws.url
                    if ws_url not in seen_ws_urls:
                        seen_ws_urls.add(ws_url)
                        websocket_endpoints.append(ws_url)
                        print(f"[browser_fetch] WebSocket detected: {ws_url}", file=sys.stderr)
                except Exception:
                    pass

            base_parsed = urllib.parse.urlparse(url)
            base_netloc = base_parsed.netloc

            def normalize_link(raw: str, current_url: str) -> str | None:
                if not raw or not isinstance(raw, str):
                    return None
                cleaned = raw.strip().strip('"').strip("'")
                if not cleaned or cleaned.startswith(("javascript:", "mailto:", "data:")):
                    return None
                # Preserve hash routes that look like SPA paths (#/ or #!/)
                if cleaned.startswith("#"):
                    return normalize_hash_route_url(cleaned, current_url)
                resolved = urllib.parse.urljoin(current_url, cleaned)
                parsed = urllib.parse.urlparse(resolved)
                if parsed.netloc and parsed.netloc != base_netloc:
                    return None
                if os.path.splitext(parsed.path.lower())[1] in _BROWSER_CRAWL_STATIC_EXTS:
                    return None
                # Preserve fragment for hash routes
                frag = parsed.fragment
                if frag and (frag.startswith("/") or frag.startswith("!/")):
                    return urllib.parse.urlunparse(parsed)  # Keep fragment
                return urllib.parse.urlunparse(parsed._replace(fragment=""))

            async def interactive_crawl(max_interactions: int = 40) -> int:
                """Click through SPA elements to trigger API calls.

                Returns the number of successful interactions.
                """
                interactions = 0

                # Selectors for clickable navigation elements
                nav_selectors = [
                    'nav a:not([href^="http"]):not([href^="mailto"])',
                    'nav button',
                    '[role="navigation"] a',
                    '.navbar a', '.nav-link',
                    '[data-testid*="nav"]', '[data-cy*="nav"]',
                ]

                # Selectors for dropdowns/menus
                dropdown_selectors = [
                    '[aria-haspopup="true"]',
                    '.dropdown-toggle',
                    '[data-toggle="dropdown"]',
                    '[data-bs-toggle="dropdown"]',
                ]

                # Selectors for tabs/accordions
                tab_selectors = [
                    '[role="tab"]',
                    '.tab', '.nav-tab',
                    '[data-toggle="tab"]',
                    '[data-bs-toggle="tab"]',
                ]

                # Selectors for buttons that might trigger API calls
                action_selectors = [
                    'button[type="button"]:not([disabled])',
                    '[role="button"]:not([disabled])',
                ]

                # SPA-specific selectors (Material UI, Ant Design, etc.)
                spa_selectors = [
                    # Material UI (MUI)
                    '.MuiListItem-root', '.MuiMenuItem-root', '.MuiTab-root',
                    '.MuiButton-root:not([disabled])', '.MuiIconButton-root',
                    '.MuiCard-root', '.MuiCardActionArea-root',
                    # Ant Design
                    '.ant-menu-item', '.ant-tabs-tab', '.ant-card',
                    '.ant-btn:not([disabled])', '.ant-list-item',
                    # Sidebar navigation
                    '[class*="sidebar"] a', '[class*="Sidebar"] a',
                    '[class*="side-nav"] a', '[class*="sidenav"] a',
                    '.menu-item', '.menu-link',
                    # Data tables and lists
                    '[class*="table"] tr[data-row-key]',
                    '[class*="list"] [class*="item"]',
                    '.data-row', '.clickable-row',
                    # Cards and tiles
                    '[class*="card"]:not(.MuiCard-root):not(.ant-card)',
                    '[class*="tile"]', '[class*="panel"]',
                    # React Router / SPA Links
                    'a[href^="/"]', '[class*="link"]',
                ]

                all_selectors = nav_selectors + dropdown_selectors + tab_selectors + action_selectors + spa_selectors

                # Denylist for destructive/risky actions - skip elements matching these
                risky_keywords = [
                    "logout", "log out", "sign out", "signout",
                    "delete", "remove", "destroy", "erase",
                    "cancel", "deactivate", "disable", "revoke",
                    "reset", "clear all", "wipe",
                    "unsubscribe", "close account", "terminate",
                ]

                async def is_safe_to_click(element) -> bool:
                    """Check if element is safe to click (not a destructive action)."""
                    try:
                        # Get text content and attributes
                        text = (await element.text_content() or "").lower().strip()
                        aria_label = (await element.get_attribute("aria-label") or "").lower()
                        title = (await element.get_attribute("title") or "").lower()
                        data_action = (await element.get_attribute("data-action") or "").lower()
                        class_name = (await element.get_attribute("class") or "").lower()

                        # Check all attributes for risky keywords
                        all_text = f"{text} {aria_label} {title} {data_action} {class_name}"
                        for keyword in risky_keywords:
                            if keyword in all_text:
                                return False
                        return True
                    except Exception:
                        return True  # If we can't check, assume it's safe

                for selector in all_selectors:
                    if interactions >= max_interactions:
                        break
                    try:
                        elements = await page.query_selector_all(selector)
                        for el in elements[:8]:  # Limit clicks per selector
                            if interactions >= max_interactions:
                                break
                            try:
                                # Check if element is visible and not already clicked
                                is_visible = await el.is_visible()
                                if not is_visible:
                                    continue

                                # Safe click filter: skip destructive actions
                                if not await is_safe_to_click(el):
                                    continue

                                await el.click(timeout=2000)
                                interactions += 1

                                # Wait briefly for any API calls to trigger
                                try:
                                    await page.wait_for_load_state("networkidle", timeout=2000)
                                except Exception:
                                    await asyncio.sleep(0.3)

                            except Exception:
                                continue
                    except Exception:
                        continue

                return interactions

            async def crawl_pages(start_url: str, extra_seed_urls: list[str] | None = None) -> tuple[list[str], dict[str, Any]]:
                if max_pages < 2:
                    return [start_url], {"pages_visited": 1, "depth_reached": 0, "interactions": 0}

                visited: set[str] = set()
                queue: list[tuple[str, int]] = [(start_url, 0)]

                # Add extra seed URLs (e.g., from JS bundle analysis) at depth 1
                # These are high-priority routes that should be visited early
                if extra_seed_urls:
                    for seed_url in extra_seed_urls:
                        normalized = normalize_link(seed_url, start_url)
                        if normalized and normalized != start_url:
                            queue.append((normalized, 1))
                    print(f"[browser_fetch] Added {len(extra_seed_urls)} seed URLs to crawl queue", file=sys.stderr)

                max_depth_reached = 0
                total_interactions = 0

                while queue and len(visited) < max_pages:
                    current_url, depth = queue.pop(0)
                    if current_url in visited:
                        continue
                    visited.add(current_url)
                    max_depth_reached = max(max_depth_reached, depth)

                    if depth > 0:
                        try:
                            await page.goto(current_url, wait_until="domcontentloaded", timeout=20000)
                        except Exception:
                            continue

                    # Interactive crawl: click through SPA elements to trigger API calls
                    # Only do this on first few pages to avoid excessive time
                    if len(visited) <= 5:
                        try:
                            interactions = await asyncio.wait_for(
                                interactive_crawl(max_interactions=20),
                                timeout=50  # 50s timeout per page interactive crawl
                            )
                            total_interactions += interactions
                        except (asyncio.TimeoutError, Exception):
                            pass

                    if depth >= max_depth:
                        continue

                    try:
                        raw_links = await page.evaluate(
                            """
                            () => {
                                const links = new Set();
                                document.querySelectorAll('a[href]').forEach(a => links.add(a.getAttribute('href')));
                                document.querySelectorAll('form[action]').forEach(f => links.add(f.getAttribute('action')));
                                return Array.from(links);
                            }
                            """
                        )
                    except Exception:
                        continue

                    added = 0
                    for link in raw_links or []:
                        if added >= max_links_per_page:
                            break
                        normalized = normalize_link(link, current_url)
                        if normalized and normalized not in visited:
                            queue.append((normalized, depth + 1))
                            added += 1

                return list(visited), {
                    "pages_visited": len(visited),
                    "depth_reached": max_depth_reached,
                    "queue_remaining": len(queue),
                    "interactions": total_interactions,
                }

            page.on("request", handle_request)
            page.on("response", handle_response)
            page.on("websocket", handle_websocket)
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            if resp:
                headers = resp.headers
                # Detect HTTP version from response characteristics
                http_version = "?"
                try:
                    if any(h.lower() in headers for h in ["alt-svc", ":status"]):
                        if "h3" in headers.get("alt-svc", "").lower():
                            http_version = "3"
                        else:
                            http_version = "2"
                    else:
                        http_version = "1.1"
                except Exception:
                    http_version = "?"
                # Build status line with detected version
                status_line = f"HTTP/{http_version} {resp.status}"
            else:
                headers = {}
                http_version = "?"
                status_line = "HTTP/? 0"
            try:
                tech_info = await page.evaluate(
                    """
                    () => {
                        const techs = [];
                        const versions = {};

                        // Helper to safely get version
                        const tryGet = (fn) => { try { return fn(); } catch(e) { return null; } };

                        // === CORE FRAMEWORKS ===
                        if (window.jQuery) {
                            techs.push('jQuery');
                            const v = tryGet(() => window.jQuery.fn?.jquery || window.$?.fn?.jquery);
                            if (v) versions.jquery = v;
                        }

                        // === REACT DETECTION (Enhanced for Production) ===
                        // Method 1: window.React (dev only)
                        if (window.React) {
                            techs.push('React');
                            const v = tryGet(() => window.React.version);
                            if (v) versions.react = v;
                        }

                        // Method 2: DOM markers (works in production!)
                        if (!techs.includes('React')) {
                            // Check for React root markers
                            const reactRoot = document.querySelector('[data-reactroot]') ||
                                              document.querySelector('[data-reactid]');
                            if (reactRoot) {
                                techs.push('React');
                                versions.react = 'detected';
                            }

                            // Check for React 18+ fiber nodes (they add __reactFiber$ or __reactContainer$ to DOM)
                            const anyElement = document.body?.firstElementChild;
                            if (anyElement) {
                                const reactFiberKey = Object.keys(anyElement).find(key =>
                                    key.startsWith('__reactFiber$') ||
                                    key.startsWith('__reactContainer$') ||
                                    key.startsWith('__reactProps$')
                                );
                                if (reactFiberKey && !techs.includes('React')) {
                                    techs.push('React');
                                    versions.react = '18+';
                                }
                            }
                        }

                        if (window.Vue || window.__VUE__) {
                            techs.push('Vue.js');
                            const v = tryGet(() => window.Vue?.version || window.__VUE__?.version);
                            if (v) versions.vue = v;
                        }

                        // AngularJS (1.x)
                        if (window.angular?.version) {
                            techs.push('AngularJS');
                            versions.angularjs = window.angular.version.full;
                        }

                        // Angular (2+)
                        const ngEl = document.querySelector('[ng-version]');
                        if (ngEl) {
                            techs.push('Angular');
                            versions.angular = ngEl.getAttribute('ng-version');
                        }

                        // === NEXT.JS DETECTION (Enhanced) ===
                        let nextBuildId = null;

                        if (window.next) {
                            techs.push('Next.js');
                            if (window.next.version) versions.nextjs = window.next.version;
                        }

                        const nextDataEl = document.getElementById('__NEXT_DATA__');
                        if (nextDataEl) {
                            if (!techs.includes('Next.js')) techs.push('Next.js');
                            try {
                                const data = JSON.parse(nextDataEl.textContent);
                                if (data.buildId) {
                                    nextBuildId = data.buildId;
                                    versions.next_build_id = data.buildId;
                                }
                                // Extract additional Next.js metadata
                                if (data.props?.pageProps?.__N_SSG) versions.next_render = 'SSG';
                                if (data.props?.pageProps?.__N_SSP) versions.next_render = 'SSP';
                                if (data.isPreview) versions.next_preview = true;
                                // Try to get Next.js version from runtimeConfig if exposed
                                if (data.runtimeConfig?.nextVersion) {
                                    versions.nextjs = data.runtimeConfig.nextVersion;
                                }
                            } catch(e) {}
                        }

                        // Check for /_next/ script patterns to confirm Next.js and extract buildId
                        if (!nextBuildId) {
                            const nextScript = document.querySelector('script[src*="/_next/static/"]');
                            if (nextScript) {
                                if (!techs.includes('Next.js')) techs.push('Next.js');
                                // Extract buildId from URL: /_next/static/[buildId]/...
                                const match = nextScript.src.match(/\\/_next\\/static\\/([^/]+)\\//);
                                if (match && match[1] !== 'chunks' && match[1] !== 'css') {
                                    versions.next_build_id = match[1];
                                }
                            }
                        }

                        if (window.__NUXT__) {
                            techs.push('Nuxt.js');
                            versions.nuxtjs = 'detected';
                        }

                        if (window.___gatsby) {
                            techs.push('Gatsby');
                            versions.gatsby = 'detected';
                        }

                        // === UTILITY LIBRARIES ===
                        if (window._?.VERSION) {
                            techs.push('Lodash');
                            versions.lodash = window._.VERSION;
                        }

                        if (window.moment?.version) {
                            techs.push('Moment.js');
                            versions.moment = window.moment.version;
                        }

                        if (window.dayjs?.version) {
                            techs.push('Day.js');
                            versions.dayjs = window.dayjs.version;
                        }

                        if (window.axios?.VERSION) {
                            techs.push('Axios');
                            versions.axios = window.axios.VERSION;
                        }

                        // === UI FRAMEWORKS ===
                        const bsVersion = tryGet(() => window.bootstrap?.Tooltip?.VERSION || window.jQuery?.fn?.tooltip?.Constructor?.VERSION);
                        if (bsVersion) {
                            techs.push('Bootstrap');
                            versions.bootstrap = bsVersion;
                        }

                        // === VISUALIZATION ===
                        if (window.d3?.version) {
                            techs.push('D3.js');
                            versions.d3 = window.d3.version;
                        }

                        if (window.Chart?.version) {
                            techs.push('Chart.js');
                            versions.chartjs = window.Chart.version;
                        }

                        if (window.THREE?.REVISION) {
                            techs.push('Three.js');
                            versions.threejs = 'r' + window.THREE.REVISION;
                        }

                        if (window.Highcharts?.version) {
                            techs.push('Highcharts');
                            versions.highcharts = window.Highcharts.version;
                        }

                        if (window.L?.version) {
                            techs.push('Leaflet');
                            versions.leaflet = window.L.version;
                        }

                        // === ANIMATION ===
                        if (window.gsap?.version) {
                            techs.push('GSAP');
                            versions.gsap = window.gsap.version;
                        }

                        // === LEGACY/VULNERABLE ===
                        if (window.Backbone?.VERSION) {
                            techs.push('Backbone.js');
                            versions.backbone = window.Backbone.VERSION;
                        }

                        if (window.Ember?.VERSION) {
                            techs.push('Ember.js');
                            versions.ember = window.Ember.VERSION;
                        }

                        if (window.ko?.version) {
                            techs.push('Knockout');
                            versions.knockout = window.ko.version;
                        }

                        if (window.Handlebars?.VERSION) {
                            techs.push('Handlebars');
                            versions.handlebars = window.Handlebars.VERSION;
                        }

                        if (window.Prototype?.Version) {
                            techs.push('Prototype');
                            versions.prototype = window.Prototype.Version;
                        }

                        if (window.MooTools?.version) {
                            techs.push('MooTools');
                            versions.mootools = window.MooTools.version;
                        }

                        if (window.YUI?.version) {
                            techs.push('YUI');
                            versions.yui = window.YUI.version;
                        }

                        if (window.dojo?.version) {
                            techs.push('Dojo');
                            versions.dojo = window.dojo.version;
                        }

                        // === COMMUNICATION ===
                        if (window.io?.protocol) {
                            techs.push('Socket.io');
                            versions.socketio = 'protocol-' + window.io.protocol;
                        }

                        if (window.firebase?.SDK_VERSION) {
                            techs.push('Firebase');
                            versions.firebase = window.firebase.SDK_VERSION;
                        }

                        // === EDITORS ===
                        if (window.tinymce?.majorVersion) {
                            techs.push('TinyMCE');
                            versions.tinymce = window.tinymce.majorVersion + '.' + window.tinymce.minorVersion;
                        }

                        if (window.CKEDITOR?.version) {
                            techs.push('CKEditor');
                            versions.ckeditor = window.CKEDITOR.version;
                        }

                        if (window.Quill?.version) {
                            techs.push('Quill');
                            versions.quill = window.Quill.version;
                        }

                        // === MEDIA ===
                        if (window.videojs?.VERSION) {
                            techs.push('Video.js');
                            versions.videojs = window.videojs.VERSION;
                        }

                        if (window.Plyr?.version) {
                            techs.push('Plyr');
                            versions.plyr = window.Plyr.version;
                        }

                        // === ALPINE/HTMX ===
                        if (window.Alpine?.version) {
                            techs.push('Alpine.js');
                            versions.alpine = window.Alpine.version;
                        }

                        if (window.htmx?.version) {
                            techs.push('htmx');
                            versions.htmx = window.htmx.version;
                        }

                        // === CMS Detection ===
                        if (window.wp) techs.push('WordPress');
                        if (window.Drupal) techs.push('Drupal');

                        // Generator meta tags
                        document.querySelectorAll('meta[name="generator"]').forEach(m => {
                            if (m.content) techs.push(m.content);
                        });

                        // === ADDITIONAL FRAMEWORK MARKERS ===
                        // Svelte detection
                        if (window.__svelte || document.querySelector('[class*="svelte-"]')) {
                            techs.push('Svelte');
                            if (window.__svelte?.version) versions.svelte = window.__svelte.version;
                            else versions.svelte = 'detected';
                        }

                        // Remix detection
                        if (window.__remixManifest || window.__remixRouteModules) {
                            techs.push('Remix');
                            versions.remix = 'detected';
                        }

                        // Solid.js detection
                        if (window._$HY || document.querySelector('[data-hk]')) {
                            techs.push('Solid.js');
                            versions.solidjs = 'detected';
                        }

                        // Qwik detection
                        if (window.qwikloader || document.querySelector('[q\\\\:container]')) {
                            techs.push('Qwik');
                            versions.qwik = 'detected';
                        }

                        // Astro detection (via data attribute or astro-island component)
                        if (document.querySelector('[data-astro-cid]') || document.querySelector('astro-island')) {
                            techs.push('Astro');
                            versions.astro = 'detected';
                        }

                        // Vue scoped styles detection (production marker)
                        if (!techs.includes('Vue.js') && document.querySelector('[data-v-]')) {
                            techs.push('Vue.js');
                            versions.vue = 'detected';
                        }

                        return { techs, versions };
                    }
                    """
                )
                tech_stack = tech_info.get("techs", []) if isinstance(tech_info, dict) else tech_info
                browser_versions = tech_info.get("versions", {}) if isinstance(tech_info, dict) else {}
            except Exception:
                tech_stack = []
                browser_versions = {}
            body_title = await page.title()
            safe_name = re.sub(r"[^a-zA-Z0-9]+", "_", urllib.parse.urlparse(url).netloc)
            path = os.path.join(screenshot_dir, f"{safe_name}.png")
            try:
                await page.screenshot(path=path, full_page=True)
            except Exception:
                path = None

            page_urls = [url]
            crawl_stats = None
            initial_interactions = 0

            # Interactive crawl on initial page to trigger SPA API calls
            try:
                initial_interactions = await asyncio.wait_for(
                    interactive_crawl(max_interactions=40),
                    timeout=50  # 50s timeout for initial interactive crawl
                )
                if initial_interactions > 0:
                    print(
                        f"[browser_fetch] Interactive crawl: {initial_interactions} element interactions",
                        file=sys.stderr
                    )
            except asyncio.TimeoutError:
                print("[browser_fetch] Interactive crawl timed out (50s), continuing", file=sys.stderr)
            except Exception:
                pass

            if crawl:
                print(
                    f"[browser_fetch] Headless crawl enabled: max_pages={max_pages} depth={max_depth}",
                    file=sys.stderr
                )
                try:
                    page_urls, crawl_stats = await asyncio.wait_for(
                        crawl_pages(url, extra_seed_urls=seed_urls),
                        timeout=180  # 180s timeout for entire crawl
                    )
                except asyncio.TimeoutError:
                    # On timeout, infer visited pages from captured network requests
                    # Document requests indicate pages that were navigated to
                    # Filter to same-origin only to avoid inflating metrics with cross-origin navigations
                    def normalize_origin(u: str) -> str:
                        """Normalize origin (scheme+host+port) per same-origin policy."""
                        parsed = urllib.parse.urlparse(u)
                        scheme = parsed.scheme.lower()
                        host = (parsed.hostname or "").lower()
                        port = parsed.port
                        # Strip default port only for matching scheme
                        if port is None or (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
                            return f"{scheme}://{host}"
                        return f"{scheme}://{host}:{port}"

                    start_origin = normalize_origin(url)
                    visited_from_requests = {url}  # Always include start URL
                    for req in captured_requests:
                        req_url = req.get("url", "")
                        if req_url and req.get("resource_type") == "document":
                            if normalize_origin(req_url) == start_origin:
                                visited_from_requests.add(req_url.split("?")[0])
                    page_urls = list(visited_from_requests)
                    print(f"[browser_fetch] Crawl timed out (180s), recovered {len(page_urls)} pages from {len(captured_requests)} requests", file=sys.stderr)
                    crawl_stats = {
                        "pages_visited": len(page_urls),
                        "depth_reached": 0,  # Unknown on timeout
                        "timed_out": True,
                        "requests_captured": len(captured_requests)
                    }
                if crawl_stats:
                    crawl_stats["initial_interactions"] = initial_interactions

            await ctx.close()
            h_norm: dict[str, list[str]] = {}
            for k, v in headers.items():
                h_norm.setdefault(k.lower(), []).append(v if isinstance(v, str) else str(v))

            # Extract API endpoints from captured traffic
            api_endpoints: list[dict[str, Any]] = []
            seen_api_paths: set = set()
            for req in captured_requests:
                if req.get("is_api_call") and req.get("path"):
                    # Normalize path for deduplication (remove query params, trailing slashes)
                    path_key = (req["method"], req["path"].rstrip("/"))
                    if path_key not in seen_api_paths:
                        seen_api_paths.add(path_key)
                        api_endpoints.append({
                            "url": req["url"].split("?")[0],  # Base URL without query
                            "method": req["method"],
                            "path": req["path"],
                            "has_auth": req.get("has_auth", False),
                            "status": req.get("status"),
                            "content_type": req.get("response_content_type", ""),
                        })

            # Log capture summary
            api_count = len(api_endpoints)
            total_count = len(captured_requests)
            ws_count = len(websocket_endpoints)
            if api_count > 0 or ws_count > 0:
                print(f"[browser_fetch] Network capture: {total_count} requests, {api_count} API endpoints, {ws_count} WebSocket endpoints", file=sys.stderr)
            else:
                print(f"[browser_fetch] Network capture: {total_count} requests, no API/WebSocket endpoints detected", file=sys.stderr)

            return {
                "headers": h_norm,
                "status": status_line,
                "title": body_title,
                "http_version": http_version,
                "csp": h_norm.get("content-security-policy", [None])[0],
                "screenshot_path": path,
                "tech_stack": tech_stack,
                "browser_versions": browser_versions,
                "captured_requests": captured_requests,
                "api_endpoints": api_endpoints,
                "websocket_endpoints": websocket_endpoints,
                "page_urls": page_urls,
                "crawl_stats": crawl_stats,
            }
    except Exception as e:
        print(f"[browser_fetch] Exception occurred, falling back to curl: {type(e).__name__}: {e}", file=sys.stderr)
        return await curl_fallback(f"exception: {type(e).__name__}")


# =============================================================================
# RATE LIMIT DETECTION
# =============================================================================

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
    "x-retry-after",
]


async def detect_rate_limits(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    requests_count: int = 30,
    timeout: int = 10,
) -> dict[str, Any]:
    """
    Detect and report API rate limiting configuration.

    Sends a burst of requests to identify:
    1. Presence of rate limit headers
    2. Rate limit thresholds
    3. Missing rate limiting (security concern)

    Args:
        url: Target URL to test
        method: HTTP method
        headers: Request headers (including auth)
        requests_count: Number of requests to send
        timeout: Request timeout

    Returns:
        Dict with rate limit detection results:
        - detected: bool - whether rate limiting was detected
        - headers: dict - rate limit headers found
        - limit: int|None - detected request limit
        - remaining: int|None - remaining requests
        - reset: int|None - reset time (seconds or epoch)
        - rate_limited_count: int - number of 429 responses
        - findings: list - security findings
    """
    results = {
        "detected": False,
        "headers": {},
        "limit": None,
        "remaining": None,
        "reset": None,
        "window": None,
        "rate_limited_count": 0,
        "total_requests": requests_count,
        "findings": [],
    }

    request_headers = headers.copy() if headers else {}

    async def single_request(request_id: int) -> dict:
        """Send a single request and capture rate limit info."""
        import aiohttp
        try:
            client_timeout = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.request(method, url, headers=request_headers, ssl=False) as response:
                    resp_headers = {k.lower(): v for k, v in response.headers.items()}
                    return {
                        "status": response.status,
                        "headers": resp_headers,
                        "request_id": request_id,
                    }
        except Exception as e:
            return {"status": None, "headers": {}, "error": str(e), "request_id": request_id}

    # Send burst of requests
    tasks = [single_request(i) for i in range(requests_count)]
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    # Analyze responses
    for resp in responses:
        if isinstance(resp, Exception):
            continue

        status = resp.get("status")
        resp_headers = resp.get("headers", {})

        # Count 429 responses
        if status == 429:
            results["rate_limited_count"] += 1

        # Extract rate limit headers
        for header in RATE_LIMIT_HEADERS:
            if header in resp_headers:
                results["detected"] = True
                results["headers"][header] = resp_headers[header]

                # Parse specific header values
                if "limit" in header and results["limit"] is None:
                    try:
                        results["limit"] = int(resp_headers[header])
                    except (ValueError, TypeError):
                        pass
                elif "remaining" in header and results["remaining"] is None:
                    try:
                        results["remaining"] = int(resp_headers[header])
                    except (ValueError, TypeError):
                        pass
                elif "reset" in header and results["reset"] is None:
                    try:
                        results["reset"] = int(resp_headers[header])
                    except (ValueError, TypeError):
                        pass
                elif header == "retry-after" or header == "x-retry-after":
                    try:
                        results["window"] = int(resp_headers[header])
                    except (ValueError, TypeError):
                        pass

    # Calculate window from limit and remaining if not directly available
    if results["limit"] and results["remaining"] is not None and results["window"] is None:
        # Estimate window based on requests sent vs remaining
        requests_consumed = results["limit"] - results["remaining"]
        if requests_consumed > 0:
            # Rough estimate: if we consumed X requests in our burst, window might be ~60s
            results["window"] = 60  # Default assumption

    # Generate findings
    if results["rate_limited_count"] > 0:
        # Rate limiting is working
        results["findings"].append({
            "type": "rate_limit_active",
            "severity": "info",
            "endpoint": url,
            "method": method,
            "evidence": {
                "rate_limited_responses": results["rate_limited_count"],
                "limit": results["limit"],
                "headers": results["headers"],
            },
            "description": f"Rate limiting is active. {results['rate_limited_count']}/{requests_count} requests were rate limited.",
        })
    elif not results["detected"]:
        # No rate limiting detected - security concern
        results["findings"].append({
            "type": "missing_rate_limiting",
            "severity": "medium",
            "endpoint": url,
            "method": method,
            "evidence": {
                "requests_sent": requests_count,
                "all_succeeded": True,
                "no_rate_limit_headers": True,
            },
            "description": f"No rate limiting detected. Sent {requests_count} requests without throttling.",
            "remediation": "Implement rate limiting to prevent brute-force and DoS attacks.",
            "cwe": "CWE-770",
        })
    elif results["detected"] and results["rate_limited_count"] == 0:
        # Headers present but no actual limiting
        results["findings"].append({
            "type": "rate_limit_headers_only",
            "severity": "low",
            "endpoint": url,
            "method": method,
            "evidence": {
                "headers": results["headers"],
                "limit": results["limit"],
                "requests_sent": requests_count,
            },
            "description": f"Rate limit headers present (limit={results['limit']}) but not enforced after {requests_count} requests.",
            "remediation": "Ensure rate limiting is actively enforced, not just headers.",
        })

    return results


async def detect_rate_limits_per_endpoint(
    base_url: str,
    endpoints: list[str],
    headers: dict[str, str] | None = None,
    requests_per_endpoint: int = 20,
) -> dict[str, Any]:
    """
    Test rate limiting across multiple endpoints.

    Some APIs have per-endpoint rate limits that differ from global limits.

    Args:
        base_url: Base URL
        endpoints: List of endpoint paths to test
        headers: Request headers
        requests_per_endpoint: Requests per endpoint

    Returns:
        Dict with per-endpoint rate limit results
    """
    from urllib.parse import urljoin

    results = {
        "endpoints_tested": len(endpoints),
        "endpoints_with_rate_limiting": 0,
        "endpoints_without_rate_limiting": [],
        "per_endpoint_results": {},
        "findings": [],
    }

    for endpoint in endpoints:
        url = urljoin(base_url, endpoint)
        endpoint_result = await detect_rate_limits(
            url=url,
            headers=headers,
            requests_count=requests_per_endpoint,
        )

        results["per_endpoint_results"][endpoint] = {
            "detected": endpoint_result["detected"],
            "rate_limited_count": endpoint_result["rate_limited_count"],
            "limit": endpoint_result["limit"],
        }

        if endpoint_result["detected"] or endpoint_result["rate_limited_count"] > 0:
            results["endpoints_with_rate_limiting"] += 1
        else:
            results["endpoints_without_rate_limiting"].append(endpoint)

        results["findings"].extend(endpoint_result["findings"])

    return results


# =============================================================================
# HTTP VERB TAMPERING TESTS
# =============================================================================

async def test_verb_tampering(
    url: str,
    expected_allowed_methods: list[str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """
    Test HTTP method/verb access control bypass.

    Tests if the application properly restricts HTTP methods:
    1. Tests unusual methods (TRACE, OPTIONS, HEAD, PATCH)
    2. Tests method override headers
    3. Identifies methods allowed without proper authorization

    Args:
        url: Target URL to test
        expected_allowed_methods: Methods that should be allowed (for comparison)
        headers: Request headers (including auth)
        timeout: Request timeout

    Returns:
        Dict with verb tampering test results
    """
    import aiohttp

    results = {
        "vulnerable": False,
        "findings": [],
        "methods_tested": [],
        "methods_allowed": [],
        "methods_denied": [],
        "override_headers_work": [],
    }

    request_headers = headers.copy() if headers else {}

    # Methods to test
    test_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

    # Method override headers (for bypassing method restrictions)
    override_headers = [
        ("X-HTTP-Method-Override", "DELETE"),
        ("X-HTTP-Method-Override", "PUT"),
        ("X-HTTP-Method", "DELETE"),
        ("X-HTTP-Method", "PUT"),
        ("X-Method-Override", "DELETE"),
        ("X-Method-Override", "PUT"),
    ]

    async def test_method(method: str) -> dict:
        """Test a single HTTP method."""
        try:
            client_timeout = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.request(method, url, headers=request_headers, ssl=False) as response:
                    body = ""
                    try:
                        body = await response.text()
                    except Exception:
                        pass
                    return {
                        "method": method,
                        "status": response.status,
                        "allowed": response.status < 400,
                        "body_length": len(body),
                    }
        except Exception as e:
            return {"method": method, "status": None, "allowed": False, "error": str(e)}

    async def test_trace_echo() -> dict:
        """Test TRACE with header echo verification (XST check)."""
        trace_header = "X-ShakerScan-Trace-Test"
        trace_value = f"xst-probe-{secrets.token_hex(4)}"
        trace_headers = request_headers.copy()
        trace_headers[trace_header] = trace_value
        try:
            client_timeout = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.request("TRACE", url, headers=trace_headers, ssl=False) as response:
                    body = ""
                    try:
                        body = await response.text()
                    except Exception:
                        pass
                    body_lower = body.lower() if body else ""
                    echoed = trace_value.lower() in body_lower or trace_header.lower() in body_lower
                    return {
                        "method": "TRACE",
                        "status": response.status,
                        "allowed": response.status < 400,
                        "echoed": echoed,
                        "trace_header": trace_header,
                        "trace_value": trace_value,
                        "body_sample": body[:200],
                    }
        except Exception as e:
            return {"method": "TRACE", "status": None, "allowed": False, "echoed": False, "error": str(e)}

    # Test each method
    for method in test_methods:
        if method == "TRACE":
            trace_result = await test_trace_echo()
            results["methods_tested"].append(trace_result["method"])

            if trace_result["allowed"]:
                results["methods_allowed"].append(trace_result["method"])
            else:
                results["methods_denied"].append(trace_result["method"])

            if trace_result["allowed"] and trace_result.get("echoed"):
                results["vulnerable"] = True
                results["findings"].append({
                    "type": "trace_method_enabled",
                    "severity": "medium",
                    "endpoint": url,
                    "method": "TRACE",
                    "status": trace_result.get("status"),
                    "description": "HTTP TRACE echoes request headers (XST risk).",
                    "remediation": "Disable TRACE method on the server.",
                    "cwe": "CWE-693",
                    "evidence": {
                        "header": trace_result.get("trace_header"),
                        "value": trace_result.get("trace_value"),
                        "body_sample": trace_result.get("body_sample"),
                    },
                })
            continue

        result = await test_method(method)
        results["methods_tested"].append(result["method"])

        if result["allowed"]:
            results["methods_allowed"].append(result["method"])
        else:
            results["methods_denied"].append(result["method"])

        # Check for sensitive methods allowed without proper response
        if method in ["DELETE", "PUT", "PATCH"] and result["allowed"]:
            if expected_allowed_methods and method not in expected_allowed_methods:
                # Method allowed but not expected
                results["vulnerable"] = True
                results["findings"].append({
                    "type": "unexpected_method_allowed",
                    "severity": "medium",
                    "endpoint": url,
                    "method": method,
                    "status": result["status"],
                    "description": f"HTTP {method} method is allowed but may not be intended.",
                    "remediation": f"Restrict {method} method if not needed for this endpoint.",
                    "cwe": "CWE-650",
                })

    # Test method override headers
    for header_name, override_value in override_headers:
        override_request_headers = request_headers.copy()
        override_request_headers[header_name] = override_value

        try:
            client_timeout = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                # Send POST with override header to simulate DELETE/PUT
                async with session.post(url, headers=override_request_headers, ssl=False) as response:
                    if response.status < 400:
                        results["override_headers_work"].append({
                            "header": header_name,
                            "value": override_value,
                            "status": response.status,
                        })

                        # Check if this is exploitable
                        if override_value in ["DELETE", "PUT"]:
                            # If DELETE/PUT via override works, it's a bypass
                            if "DELETE" in results["methods_denied"] or "PUT" in results["methods_denied"]:
                                results["vulnerable"] = True
                                results["findings"].append({
                                    "type": "method_override_bypass",
                                    "severity": "high",
                                    "endpoint": url,
                                    "header": header_name,
                                    "override_value": override_value,
                                    "status": response.status,
                                    "description": f"Method restriction bypass via {header_name}: {override_value}",
                                    "remediation": "Ignore method override headers or ensure they respect authorization.",
                                    "cwe": "CWE-650",
                                })
        except Exception:
            pass

    return results


async def test_verb_tampering_authenticated(
    url: str,
    authenticated_headers: dict[str, str],
    unauthenticated_headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """
    Test if authentication is properly enforced across all HTTP methods.

    Some endpoints may check auth for GET but not for DELETE/PUT.

    Args:
        url: Target URL
        authenticated_headers: Headers with valid authentication
        unauthenticated_headers: Headers without authentication
        timeout: Request timeout

    Returns:
        Dict with findings about per-method auth enforcement
    """
    results = {
        "vulnerable": False,
        "findings": [],
        "auth_required_methods": [],
        "auth_not_required_methods": [],
    }

    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

    for method in methods:
        # Test with auth
        auth_result = await test_verb_tampering(
            url=url,
            headers=authenticated_headers,
            timeout=timeout,
        )

        # Test without auth
        noauth_result = await test_verb_tampering(
            url=url,
            headers=unauthenticated_headers,
            timeout=timeout,
        )

        # Check if method requires auth
        auth_allowed = method in auth_result["methods_allowed"]
        noauth_allowed = method in noauth_result["methods_allowed"]

        if auth_allowed and not noauth_allowed:
            results["auth_required_methods"].append(method)
        elif noauth_allowed:
            results["auth_not_required_methods"].append(method)

            # Check for auth bypass on sensitive methods
            if method in ["DELETE", "PUT", "PATCH", "POST"]:
                results["vulnerable"] = True
                results["findings"].append({
                    "type": "auth_bypass_method",
                    "severity": "high",
                    "endpoint": url,
                    "method": method,
                    "description": f"HTTP {method} does not require authentication.",
                    "remediation": f"Require authentication for {method} method on this endpoint.",
                    "cwe": "CWE-306",
                })

    return results


# =============================================================================
# INTERACTIVE BROWSER CRAWL
# =============================================================================

async def interactive_browser_crawl(
    url: str,
    auth_session: Any | None = None,
    max_pages: int = 20,
    interaction_level: str = "medium",
    screenshot_dir: str = "/tmp",
) -> dict[str, Any]:
    """
    Enhanced browser crawl with automatic interaction.

    Goes beyond passive network capture to actively interact with the page:
    1. Clicks buttons and links
    2. Fills and submits forms
    3. Scrolls to trigger lazy loading
    4. Opens dropdowns and modals
    5. Captures all network traffic during interactions

    Interaction Levels:
    - low: Navigate and capture network only
    - medium: Click buttons, scroll, fill forms
    - high: Full interaction including dropdowns, modals, tabs

    Args:
        url: Target URL
        auth_session: AuthSession for authenticated crawling
        max_pages: Maximum pages to visit
        interaction_level: Level of interaction (low, medium, high)
        screenshot_dir: Directory for screenshots

    Returns:
        Dict with discovered endpoints and interaction results
    """
    if not HAS_PLAYWRIGHT:
        return {
            "error": "Playwright not installed",
            "endpoints": [],
            "interactions": [],
            "forms_found": [],
        }

    results = {
        "endpoints": [],
        "interactions": [],
        "forms_found": [],
        "buttons_clicked": 0,
        "forms_submitted": 0,
        "scroll_events": 0,
        "pages_visited": 0,
        "api_endpoints": [],
        "captured_requests": [],
    }

    seen_endpoints = set()
    captured_requests = []

    try:
        async with _pw() as browser:
            if browser is None:
                return {"error": "Browser launch failed", **results}

            # Set up browser context
            ctx_kwargs = {
                "ignore_https_errors": True,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            }

            auth_cookies = []
            if auth_session:
                try:
                    exported = auth_session.export_session()
                    headers = exported.get("headers", {}) or {}
                    headers = {k: v for k, v in headers.items() if str(k).lower() != "cookie"}
                    if headers:
                        ctx_kwargs["extra_http_headers"] = headers
                    cookie_map = exported.get("cookies", {}) or {}
                    if cookie_map:
                        base_domain = urllib.parse.urlparse(url).hostname
                        if base_domain:
                            for name, value in cookie_map.items():
                                auth_cookies.append({
                                    "name": name,
                                    "value": value,
                                    "domain": base_domain,
                                    "path": "/",
                                })
                except Exception:
                    pass

            ctx = await browser.new_context(**ctx_kwargs)
            if auth_cookies:
                try:
                    await ctx.add_cookies(auth_cookies)
                except Exception:
                    pass

            page = await ctx.new_page()

            # Set up network capture
            def handle_request(request):
                try:
                    req_url = request.url
                    if req_url not in seen_endpoints:
                        seen_endpoints.add(req_url)
                        parsed = urllib.parse.urlparse(req_url)
                        is_api = (
                            request.resource_type in ("xhr", "fetch") or
                            "/api/" in parsed.path.lower() or
                            parsed.path.endswith((".json", ".graphql"))
                        )
                        captured_requests.append({
                            "url": req_url,
                            "method": request.method,
                            "path": parsed.path,
                            "is_api": is_api,
                            "resource_type": request.resource_type,
                        })
                except Exception:
                    pass

            page.on("request", handle_request)

            # Navigate to URL
            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
                results["pages_visited"] += 1
            except Exception as e:
                print(f"[interactive_crawl] Navigation error: {e}", file=sys.stderr)

            # Interaction based on level
            if interaction_level in ["medium", "high"]:
                # Scroll to trigger lazy loading
                try:
                    await page.evaluate("""
                        async () => {
                            await new Promise(resolve => {
                                let totalHeight = 0;
                                const distance = 300;
                                const timer = setInterval(() => {
                                    window.scrollBy(0, distance);
                                    totalHeight += distance;
                                    if (totalHeight >= document.body.scrollHeight || totalHeight > 5000) {
                                        clearInterval(timer);
                                        resolve();
                                    }
                                }, 100);
                            });
                        }
                    """)
                    results["scroll_events"] += 1
                    await page.wait_for_timeout(500)
                except Exception:
                    pass

                # Find and click visible buttons (non-submit)
                try:
                    buttons = await page.query_selector_all("button:not([type='submit']), [role='button']")
                    for btn in buttons[:5]:  # Limit to prevent infinite loops
                        try:
                            if await btn.is_visible():
                                await btn.click()
                                results["buttons_clicked"] += 1
                                await page.wait_for_timeout(300)
                        except Exception:
                            pass
                except Exception:
                    pass

                # Find forms and extract information
                try:
                    forms = await page.query_selector_all("form")
                    for form in forms[:10]:
                        try:
                            action = await form.get_attribute("action") or ""
                            method = await form.get_attribute("method") or "GET"

                            # Get input fields
                            inputs = await form.query_selector_all("input, select, textarea")
                            fields = []
                            for inp in inputs:
                                inp_name = await inp.get_attribute("name") or ""
                                inp_type = await inp.get_attribute("type") or "text"
                                fields.append({"name": inp_name, "type": inp_type})

                            results["forms_found"].append({
                                "action": action,
                                "method": method.upper(),
                                "fields": fields,
                            })

                            # Auto-fill form fields for discovery (medium level)
                            for inp in inputs[:10]:
                                try:
                                    inp_type = await inp.get_attribute("type") or "text"
                                    inp_name = (await inp.get_attribute("name") or "").lower()

                                    if inp_type == "hidden":
                                        continue

                                    if await inp.is_visible():
                                        if inp_type == "email" or "email" in inp_name:
                                            await inp.fill("test@example.com")
                                        elif inp_type == "password" or "password" in inp_name:
                                            await inp.fill("TestPassword123!")
                                        elif inp_type in ["text", "search"]:
                                            await inp.fill("test")
                                        elif inp_type == "tel":
                                            await inp.fill("1234567890")
                                        elif inp_type == "number":
                                            await inp.fill("42")
                                except Exception:
                                    pass

                        except Exception:
                            pass
                except Exception:
                    pass

            if interaction_level == "high":
                # Click dropdown menus
                try:
                    dropdowns = await page.query_selector_all("select, [role='listbox'], [role='combobox']")
                    for dd in dropdowns[:5]:
                        try:
                            if await dd.is_visible():
                                await dd.click()
                                await page.wait_for_timeout(200)
                                # Try to select first option
                                options = await dd.query_selector_all("option")
                                if options and len(options) > 1:
                                    await options[1].click()
                        except Exception:
                            pass
                except Exception:
                    pass

                # Click tabs and navigation items
                try:
                    tabs = await page.query_selector_all("[role='tab'], .tab, .nav-tab, .nav-link")
                    for tab in tabs[:5]:
                        try:
                            if await tab.is_visible():
                                await tab.click()
                                results["interactions"].append({"type": "tab_click"})
                                await page.wait_for_timeout(300)
                        except Exception:
                            pass
                except Exception:
                    pass

                # Try to open modals
                try:
                    modal_triggers = await page.query_selector_all("[data-toggle='modal'], [data-bs-toggle='modal']")
                    for trigger in modal_triggers[:3]:
                        try:
                            if await trigger.is_visible():
                                await trigger.click()
                                results["interactions"].append({"type": "modal_open"})
                                await page.wait_for_timeout(500)
                                # Try to close modal
                                close_btn = await page.query_selector(".modal .close, .modal [data-dismiss='modal']")
                                if close_btn and await close_btn.is_visible():
                                    await close_btn.click()
                        except Exception:
                            pass
                except Exception:
                    pass

            # Final wait for any pending requests
            await page.wait_for_timeout(1000)

            await ctx.close()

    except Exception as e:
        results["error"] = str(e)

    # Process captured requests
    results["captured_requests"] = captured_requests
    results["api_endpoints"] = [r for r in captured_requests if r.get("is_api")]
    results["endpoints"] = list(seen_endpoints)

    print(f"[interactive_crawl] Completed: {len(results['endpoints'])} endpoints, "
          f"{results['buttons_clicked']} buttons clicked, {len(results['forms_found'])} forms found",
          file=sys.stderr)

    return results
