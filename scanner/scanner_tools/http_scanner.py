import os
import re
import sys
import urllib.parse
from contextlib import asynccontextmanager
from typing import Any

from .common import run

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


async def curl_headers(url: str, http3: bool = False) -> dict[str, Any]:
    cmd = ["curl", "-sS", "-I", "-L", "-k", "--max-redirs", "5", url]
    if http3:
        cmd.insert(-1, "--http3")
    out, err, rc = await run(cmd, timeout=45)
    blocks = [b for b in out.split("\r\n\r\n") if b.strip()] if out else []
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
            blocks2 = [b for b in get_out.split("\r\n\r\n") if b.strip()]
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
    out2, _, _ = await run(["curl", "-sS", "-o", "/dev/null", "-w", "%{url_effective}", "-L", "-k", url])
    # HTTP/3 advertisement via alt-svc
    alt_svc = ",".join(headers.get("alt-svc", [])) if headers else ""
    advertises_h3 = "h3=" in alt_svc.lower() if alt_svc else False
    return {"status": status, "headers": headers, "final_url": (out2.strip() if out2 else url), "raw": out, "advertises_h3": advertises_h3}


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
    max_links_per_page: int = 40
) -> dict:
    async def curl_fallback(reason: str = "unknown"):
        print(f"[browser_fetch] Using curl fallback ({reason}) - no network capture available", file=sys.stderr)
        out, err, rc = await run(["curl", "-sS", "-I", "-L", "-k", url])
        headers = {}
        status = "HTTP/? 200"
        if out:
            lines = out.splitlines()
            if lines:
                status = lines[0]
                for line in lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = [v.strip()]
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
                if not cleaned or cleaned.startswith(("#", "javascript:", "mailto:", "data:")):
                    return None
                resolved = urllib.parse.urljoin(current_url, cleaned)
                parsed = urllib.parse.urlparse(resolved)
                if parsed.netloc and parsed.netloc != base_netloc:
                    return None
                if os.path.splitext(parsed.path.lower())[1] in _BROWSER_CRAWL_STATIC_EXTS:
                    return None
                return urllib.parse.urlunparse(parsed._replace(fragment=""))

            async def interactive_crawl(max_interactions: int = 15) -> int:
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

                all_selectors = nav_selectors + dropdown_selectors + tab_selectors + action_selectors

                for selector in all_selectors:
                    if interactions >= max_interactions:
                        break
                    try:
                        elements = await page.query_selector_all(selector)
                        for el in elements[:3]:  # Limit clicks per selector
                            if interactions >= max_interactions:
                                break
                            try:
                                # Check if element is visible and not already clicked
                                is_visible = await el.is_visible()
                                if not is_visible:
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

            async def crawl_pages(start_url: str) -> tuple[list[str], dict[str, Any]]:
                if max_pages < 2:
                    return [start_url], {"pages_visited": 1, "depth_reached": 0, "interactions": 0}

                visited: set[str] = set()
                queue: list[tuple[str, int]] = [(start_url, 0)]
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
                            interactions = await interactive_crawl(max_interactions=10)
                            total_interactions += interactions
                        except Exception:
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
                initial_interactions = await interactive_crawl(max_interactions=15)
                if initial_interactions > 0:
                    print(
                        f"[browser_fetch] Interactive crawl: {initial_interactions} element interactions",
                        file=sys.stderr
                    )
            except Exception:
                pass

            if crawl:
                print(
                    f"[browser_fetch] Headless crawl enabled: max_pages={max_pages} depth={max_depth}",
                    file=sys.stderr
                )
                page_urls, crawl_stats = await crawl_pages(url)
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
