import asyncio
import hashlib
import json
import os
import re
import secrets
import sys
import urllib.parse
from typing import Any

import httpx

try:
    from packaging import version as pkg_version
    HAS_PACKAGING = True
except ImportError:
    HAS_PACKAGING = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from .common import get_auth_curl_args, run
from .http_scanner import HAS_PLAYWRIGHT, _pw


# =============================================================================
# DISCOVERY CONFIGURATION - Scan Type Profiles
# =============================================================================
DISCOVERY_CONFIG = {
    "quick": {
        "katana_depth": 2,
        "ffuf_wordlist": "minimal",  # ~500 paths
        "parameter_discovery": False,
        "js_parsing": False,
        "browser_fallback": False,
        "recursive_fuzzing": False,
        "max_urls": 100,
        "api_probe_limit": 120,
        "common_probe_limit": 60,
        "api_root_resource_limit": 20,
        "json_link_seed_limit": 20,
        "json_link_total_limit": 60,
        "json_link_depth": 1,
        "options_method_limit": 60,
    },
    "standard": {
        "katana_depth": 3,
        "ffuf_wordlist": "common",  # ~2k paths
        "parameter_discovery": False,
        "js_parsing": True,
        "browser_fallback": True,
        "recursive_fuzzing": False,
        "max_urls": 300,
        "api_probe_limit": 250,
        "common_probe_limit": 120,
        "api_root_resource_limit": 30,
        "json_link_seed_limit": 40,
        "json_link_total_limit": 120,
        "json_link_depth": 1,
        "options_method_limit": 120,
    },
    "deep": {
        "katana_depth": 4,
        "ffuf_wordlist": "common",  # ~2k paths
        "parameter_discovery": True,
        "js_parsing": True,
        "browser_fallback": True,
        "recursive_fuzzing": False,
        "max_urls": 500,
        "api_probe_limit": 450,
        "common_probe_limit": 200,
        "api_root_resource_limit": 40,
        "json_link_seed_limit": 60,
        "json_link_total_limit": 200,
        "json_link_depth": 2,
        "options_method_limit": 200,
    },
    "full": {
        "katana_depth": 5,
        "ffuf_wordlist": "comprehensive",  # ~10k paths
        "parameter_discovery": True,
        "js_parsing": True,
        "browser_fallback": True,
        "recursive_fuzzing": True,
        "max_urls": 1000,
        "api_probe_limit": 800,
        "common_probe_limit": 300,
        "api_root_resource_limit": 60,
        "json_link_seed_limit": 80,
        "json_link_total_limit": 300,
        "json_link_depth": 2,
        "options_method_limit": 300,
    },
    "aggressive": {
        "katana_depth": 6,
        "ffuf_wordlist": "extended",  # ~20k paths
        "parameter_discovery": True,
        "js_parsing": True,
        "browser_fallback": True,
        "recursive_fuzzing": True,
        "max_urls": 2000,
        "api_probe_limit": 1200,
        "common_probe_limit": 400,
        "api_root_resource_limit": 80,
        "json_link_seed_limit": 100,
        "json_link_total_limit": 500,
        "json_link_depth": 2,
        "options_method_limit": 400,
    },
    "smart": {
        "katana_depth": 4,
        "ffuf_wordlist": "common",  # Start moderate, expand based on signals
        "parameter_discovery": True,
        "js_parsing": True,  # Critical for finding hidden API endpoints
        "browser_fallback": True,
        "recursive_fuzzing": True,  # Adaptive depth based on findings
        "max_urls": 1000,
        "api_probe_limit": 600,
        "common_probe_limit": 250,
        "api_root_resource_limit": 50,
        "json_link_seed_limit": 80,
        "json_link_total_limit": 300,
        "json_link_depth": 2,
        "options_method_limit": 250,
    },
}

# Common parameters to try on endpoints (for parameter discovery)
COMMON_PARAMS = [
    "id", "q", "query", "search", "page", "limit", "offset",
    "user", "username", "email", "name", "file", "path", "url",
    "callback", "redirect", "next", "return", "ref", "action",
    "sort", "order", "filter", "category", "type", "format",
    "token", "key", "api_key", "debug", "test", "admin",
]

# Endpoint-specific parameters (for smart parameter inference)
ENDPOINT_PARAMS = {
    "search": ["q", "query", "search", "s", "keyword", "term", "text"],
    "login": ["username", "user", "email", "password", "pass", "login"],
    "product": ["id", "pid", "product_id", "item", "sku", "product"],
    "user": ["id", "uid", "user_id", "username", "user", "email"],
    "order": ["id", "order_id", "oid", "ref", "order"],
    "file": ["file", "path", "filename", "document", "name", "f"],
    "page": ["page", "p", "offset", "limit", "per_page", "size"],
    "api": ["id", "token", "key", "callback", "format", "version"],
    "admin": ["id", "user", "action", "cmd", "command"],
    "download": ["file", "path", "name", "id", "doc"],
    "image": ["id", "file", "path", "src", "url"],
    "report": ["id", "type", "format", "date", "range"],
}

WORDLIST_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "wordlists"))
WORDLIST_PATHS = {
    "api_prefixes": os.path.join(WORDLIST_DIR, "api-prefixes.txt"),
    "api_resources": os.path.join(WORDLIST_DIR, "api-resources.txt"),
    "common": os.path.join(WORDLIST_DIR, "common.txt"),
    "admin": os.path.join(WORDLIST_DIR, "admin-common.txt"),
}


def _read_wordlist(path: str, limit: int | None = None) -> list[str]:
    if not path or not os.path.exists(path):
        return []
    entries = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(line)
            if limit is not None and len(entries) >= limit:
                break
    return entries


def _unique_preserve_order(items: list[str]) -> list[str]:
    seen = set()
    ordered: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def _normalize_candidate_path(path: str) -> str | None:
    if not path:
        return None
    cleaned = path.strip()
    if not cleaned:
        return None
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        return cleaned
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    return cleaned


def _is_api_candidate_path(target_url: str) -> bool:
    if not target_url:
        return False
    parsed = urllib.parse.urlparse(target_url)
    path = (parsed.path or "").lower()
    if not path or path == "/":
        return False
    api_markers = [
        "/api", "/rest", "/graphql", "/gql", "/v1", "/v2", "/v3",
        "/auth", "/oauth", "/login", "/token", "/users", "/user", "/account"
    ]
    return any(marker in path for marker in api_markers)


def _looks_like_api_error(body: str) -> bool:
    if not body:
        return False
    sample = body[:2000].lower()
    keywords = [
        "missing", "required", "invalid", "validation", "unauthorized",
        "forbidden", "not allowed", "method not allowed", "token",
        "jwt", "authentication", "authorization", "access denied",
        "permission", "bad request", "unsupported", "field",
    ]
    json_keys = ["\"error\"", "\"message\"", "\"detail\"", "\"errors\"", "\"code\""]
    return any(k in sample for k in keywords) or any(k in sample for k in json_keys)


def _is_html_response(body: str, content_type: str) -> bool:
    if content_type and "html" in content_type.lower():
        return True
    if not body:
        return False
    sample = body[:2000].lower()
    html_indicators = ["<!doctype", "<html", "<head", "<body", "<script", "<title"]
    return sum(1 for ind in html_indicators if ind in sample) >= 2


def _is_json_response(body: str, content_type: str) -> bool:
    if content_type and "json" in content_type.lower():
        return True
    if not body:
        return False
    sample = body.lstrip()
    return sample.startswith("{") or sample.startswith("[")


def _normalize_json_link(link: str, base_url: str, current_url: str | None = None) -> str | None:
    if not link or not isinstance(link, str):
        return None
    cleaned = link.strip().strip('"').strip("'")
    if not cleaned or cleaned.startswith(("#", "javascript:", "mailto:", "data:")):
        return None

    # Strip URI template query suffixes like "{?page,size}"
    cleaned = re.sub(r"\{\?.*?\}", "", cleaned)
    # Replace path params like "/users/{id}" -> "/users/1"
    cleaned = re.sub(r"\{[^/}]+\}", "1", cleaned)
    # Replace colon params like "/users/:id" -> "/users/1"
    cleaned = re.sub(r"/:[^/]+", "/1", cleaned)

    resolved = urllib.parse.urljoin(current_url or base_url, cleaned)
    parsed = urllib.parse.urlparse(resolved)
    base_netloc = urllib.parse.urlparse(base_url).netloc
    if parsed.netloc and parsed.netloc != base_netloc:
        return None

    path = parsed.path or "/"
    ext = os.path.splitext(path.lower())[1]
    static_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".js", ".map",
        ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".avi", ".mov",
        ".zip", ".tar", ".gz", ".rar", ".7z", ".pdf",
    }
    if ext in static_exts:
        return None

    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, ""))


def _extract_links_from_json(obj: Any, base_url: str, current_url: str | None = None, max_nodes: int = 2000) -> list[str]:
    links: list[str] = []
    nodes_seen = 0

    def _walk(item: Any):
        nonlocal nodes_seen
        if nodes_seen >= max_nodes:
            return
        nodes_seen += 1

        if isinstance(item, dict):
            for key, value in item.items():
                key_lower = str(key).lower()
                if isinstance(value, str):
                    if key_lower in {"href", "url", "uri", "link", "self", "next", "prev"} or key_lower.endswith(("_url", "_uri")):
                        normalized = _normalize_json_link(value, base_url, current_url)
                        if normalized:
                            links.append(normalized)
                if isinstance(value, (dict, list)):
                    _walk(value)
        elif isinstance(item, list):
            for entry in item:
                _walk(entry)
        elif isinstance(item, str):
            normalized = _normalize_json_link(item, base_url, current_url)
            if normalized:
                links.append(normalized)

    _walk(obj)
    return links


async def follow_json_links(
    base_url: str,
    seed_urls: list[str],
    auth_session: Any | None = None,
    max_seeds: int = 60,
    max_total: int = 200,
    max_depth: int = 2,
    timeout: float = 8.0,
    concurrency: int = 8,
) -> dict[str, Any]:
    base_netloc = urllib.parse.urlparse(base_url).netloc
    if not seed_urls:
        return {"links": [], "seed_count": 0, "visited": 0, "depth_reached": 0}

    seeds: list[str] = []
    for url in seed_urls:
        if not url or not isinstance(url, str):
            continue
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc and parsed.netloc != base_netloc:
            continue
        if _is_api_candidate_path(url) or url.endswith(".json") or "/graphql" in url.lower():
            seeds.append(url)
    seeds = _unique_preserve_order(seeds)[:max_seeds]
    if not seeds:
        return {"links": [], "seed_count": 0, "visited": 0, "depth_reached": 0}

    session_headers: dict[str, str] = {}
    session_cookies: dict[str, str] = {}
    if auth_session:
        try:
            exported = auth_session.export_session()
            session_headers = exported.get("headers", {}) or {}
            session_cookies = exported.get("cookies", {}) or {}
        except Exception:
            session_headers = {}
            session_cookies = {}

    if "Accept" not in session_headers:
        session_headers["Accept"] = "application/json"

    discovered: set[str] = set()
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(seed, 0) for seed in seeds]
    max_depth_reached = 0

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        sem = asyncio.Semaphore(concurrency)

        async def fetch_and_extract(target_url: str, depth: int):
            async with sem:
                try:
                    resp = await client.get(
                        target_url,
                        headers=session_headers,
                        cookies=session_cookies
                    )
                except Exception:
                    return []

            content_type = resp.headers.get("content-type", "")
            body = resp.text or ""
            if not _is_json_response(body, content_type):
                return []

            try:
                data = resp.json()
            except Exception:
                try:
                    data = json.loads(body)
                except Exception:
                    return []

            return _extract_links_from_json(data, base_url, target_url)

        while queue and len(discovered) < max_total:
            target_url, depth = queue.pop(0)
            if target_url in visited:
                continue
            visited.add(target_url)
            max_depth_reached = max(max_depth_reached, depth)

            new_links = await fetch_and_extract(target_url, depth)
            for link in new_links:
                if link in discovered or link in visited:
                    continue
                discovered.add(link)
                if depth + 1 <= max_depth and len(discovered) < max_total:
                    queue.append((link, depth + 1))
                if len(discovered) >= max_total:
                    break

    return {
        "links": sorted(discovered),
        "seed_count": len(seeds),
        "visited": len(visited),
        "depth_reached": max_depth_reached,
    }


async def discover_allowed_methods(
    base_url: str,
    urls: list[str],
    auth_session: Any | None = None,
    max_urls: int = 150,
    timeout: float = 8.0,
    concurrency: int = 10,
) -> dict[str, Any]:
    base_netloc = urllib.parse.urlparse(base_url).netloc
    if not urls:
        return {"methods_by_url": {}, "tested": 0}

    normalized_urls: list[str] = []
    for url in urls:
        if not url or not isinstance(url, str):
            continue
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc and parsed.netloc != base_netloc:
            continue
        normalized = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
        normalized_urls.append(normalized)
    normalized_urls = _unique_preserve_order(normalized_urls)[:max_urls]

    session_headers: dict[str, str] = {}
    session_cookies: dict[str, str] = {}
    if auth_session:
        try:
            exported = auth_session.export_session()
            session_headers = exported.get("headers", {}) or {}
            session_cookies = exported.get("cookies", {}) or {}
        except Exception:
            session_headers = {}
            session_cookies = {}

    methods_by_url: dict[str, list[str]] = {}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        sem = asyncio.Semaphore(concurrency)

        async def fetch_options(target_url: str):
            async with sem:
                try:
                    resp = await client.options(
                        target_url,
                        headers=session_headers,
                        cookies=session_cookies
                    )
                except Exception:
                    return target_url, []

            allow_header = resp.headers.get("allow") or resp.headers.get("Allow") or ""
            acam_header = resp.headers.get("access-control-allow-methods") or ""
            raw = ",".join([allow_header, acam_header])
            if not raw:
                return target_url, []
            methods = []
            for token in raw.split(","):
                method = token.strip().upper()
                if method and method not in methods:
                    methods.append(method)
            return target_url, methods

        tasks = [fetch_options(u) for u in normalized_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for item in results:
        if isinstance(item, Exception):
            continue
        target_url, methods = item
        if methods:
            methods_by_url[target_url] = methods

    return {
        "methods_by_url": methods_by_url,
        "tested": len(normalized_urls),
    }


def _build_api_probe_candidates(
    api_probe_limit: int,
    common_probe_limit: int,
    api_root_resource_limit: int
) -> list[str]:
    prefixes = _read_wordlist(WORDLIST_PATHS["api_prefixes"])
    resources = _read_wordlist(WORDLIST_PATHS["api_resources"])
    common = _read_wordlist(WORDLIST_PATHS["common"], limit=common_probe_limit)

    root_resources = resources[:api_root_resource_limit] if api_root_resource_limit > 0 else []

    candidates: list[str] = []
    candidates.extend(prefixes)
    candidates.extend(root_resources)

    # Interleave prefixes per resource so early truncation still covers multiple API bases.
    for resource in resources:
        for prefix in prefixes:
            candidates.append(f"{prefix.rstrip('/')}/{resource.lstrip('/')}")

    candidates.extend(common)
    candidates = [_normalize_candidate_path(c) for c in candidates]
    candidates = [c for c in candidates if c]
    candidates = _unique_preserve_order(candidates)
    if api_probe_limit and len(candidates) > api_probe_limit:
        candidates = candidates[:api_probe_limit]
    return candidates


async def _probe_api_candidates(
    base_url: str,
    candidates: list[str],
    timeout: float = 5.0,
    concurrency: int = 12
) -> list[str]:
    if not candidates:
        return []

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            "Accept": "application/json, */*;q=0.1",
        }
    ) as client:
        baseline_path = f"/__probe_{secrets.token_hex(4)}"
        baseline_url = urllib.parse.urljoin(base_url, baseline_path)
        baseline_body = ""
        baseline_status = None
        baseline_signature = None
        try:
            baseline_resp = await client.get(baseline_url)
            baseline_body = baseline_resp.text or ""
            baseline_ct = baseline_resp.headers.get("content-type", "")
            baseline_status = baseline_resp.status_code
            baseline_signature = (
                baseline_status,
                baseline_ct.split(";")[0].strip().lower(),
                hashlib.sha256(baseline_body[:4000].encode("utf-8", errors="ignore")).hexdigest()[:12],
            )
        except Exception:
            baseline_ct = ""
            baseline_signature = None

        sem = asyncio.Semaphore(concurrency)
        discovered: list[str] = []

        async def fetch(candidate: str) -> None:
            target_url = candidate
            if not candidate.startswith("http://") and not candidate.startswith("https://"):
                target_url = urllib.parse.urljoin(base_url, candidate)

            async with sem:
                try:
                    resp = await client.get(target_url)
                except Exception:
                    return

            status = resp.status_code
            body = resp.text or ""
            content_type = resp.headers.get("content-type", "")
            allow = resp.headers.get("allow", "")
            www_auth = resp.headers.get("www-authenticate", "")
            location = resp.headers.get("location", "")

            is_html = _is_html_response(body, content_type)
            is_json = _is_json_response(body, content_type)
            signature = (
                status,
                content_type.split(";")[0].strip().lower(),
                hashlib.sha256(body[:4000].encode("utf-8", errors="ignore")).hexdigest()[:12],
            )
            matches_baseline = baseline_signature and signature == baseline_signature and status == baseline_status
            if matches_baseline and status in (401, 403, 405):
                if not (www_auth or allow or _is_api_candidate_path(target_url)):
                    return
            elif matches_baseline:
                return

            if status in (200, 201, 202, 204):
                if is_json or not is_html:
                    discovered.append(target_url)
                return

            if status in (301, 302, 307, 308):
                if location or is_json:
                    discovered.append(target_url)
                return

            if status == 405:
                if allow or is_json or (not is_html and _looks_like_api_error(body)):
                    discovered.append(target_url)
                return

            if status in (400, 401, 403, 409, 422, 429, 500):
                if is_json or (not is_html and _looks_like_api_error(body)) or www_auth:
                    discovered.append(target_url)
                return

        tasks = [fetch(candidate) for candidate in candidates]
        if tasks:
            await asyncio.gather(*tasks)

    return _unique_preserve_order(discovered)


def safe_version_compare(version_str: str, threshold: str) -> bool:
    """Compare versions safely using semantic versioning.

    Args:
        version_str: The version to check (e.g., "1.9", "2.4.50")
        threshold: The threshold version (e.g., "1.20", "2.4.49")

    Returns:
        True if version_str < threshold, False otherwise or on error
    """
    if not version_str or not threshold:
        return False
    try:
        if HAS_PACKAGING:
            return pkg_version.parse(version_str) < pkg_version.parse(threshold)
        else:
            # Fallback: split by dots and compare as integers
            # Handle pre-release versions (e.g., "1.2.3-beta", "v1.2.3")
            def normalize_version(v: str) -> list:
                # Strip leading 'v' or 'V'
                v = v.lstrip('vV')
                # Strip pre-release suffix
                for sep in ['-', '+', '_']:
                    if sep in v:
                        v = v.split(sep)[0]
                # Parse numeric parts
                parts = []
                for x in v.split('.'):
                    # Extract leading digits
                    digits = ''
                    for c in x:
                        if c.isdigit():
                            digits += c
                        else:
                            break
                    if digits:
                        parts.append(int(digits))
                return parts

            v1_parts = normalize_version(version_str)
            v2_parts = normalize_version(threshold)

            if not v1_parts or not v2_parts:
                return False

            # Pad shorter list with zeros
            while len(v1_parts) < len(v2_parts):
                v1_parts.append(0)
            while len(v2_parts) < len(v1_parts):
                v2_parts.append(0)
            return v1_parts < v2_parts
    except Exception:
        return False


async def enhanced_tech_fingerprinting(url: str, headers: dict[str, list[str]], content: str | None = None) -> dict[str, Any]:
    tech_stack: list[dict[str, Any]] = []
    cve_candidates: list[str] = []

    server_header = headers.get("server", [None])[0]
    if server_header:
        server_patterns = [(r"nginx/([\d.]+)", "nginx"), (r"Apache/([\d.]+)", "Apache"), (r"Microsoft-IIS/([\d.]+)", "IIS"), (r"openresty/([\d.]+)", "OpenResty"), (r"cloudflare", "Cloudflare")]
        for pattern, tech_name in server_patterns:
            match = re.search(pattern, server_header, re.I)
            if match:
                version = match.group(1) if match.groups() else None
                tech_stack.append({"name": tech_name, "version": version})
                if version:
                    if tech_name == "nginx" and safe_version_compare(version, "1.20"):
                        cve_candidates.append("CVE-2021-23017")
                    elif tech_name == "Apache" and safe_version_compare(version, "2.4.49"):
                        cve_candidates.append("CVE-2021-41773")

    framework_headers = {
        "x-powered-by": [(r"PHP/([\d.]+)", "PHP"), (r"ASP\.NET", "ASP.NET"), (r"Express", "Express.js")],
        "x-aspnet-version": [(r"([\d.]+)", "ASP.NET")],
        "x-drupal-cache": [(r".*", "Drupal")],
        "x-generator": [(r"WordPress ([\d.]+)", "WordPress")],
    }
    for header_name, patterns in framework_headers.items():
        header_value = headers.get(header_name, [None])[0]
        if header_value:
            for pattern, tech_name in patterns:
                match = re.search(pattern, header_value, re.I)
                if match:
                    version = match.group(1) if match.groups() else None
                    tech_stack.append({"name": tech_name, "version": version})

    if content:
        # Extract Next.js version from __NEXT_DATA__ script tag or X-Powered-By header
        nextjs_version = None
        nextjs_detected = False

        # Check X-Powered-By header for Next.js version
        x_powered_by = headers.get("x-powered-by", [None])[0]
        if x_powered_by and "next" in x_powered_by.lower():
            nextjs_detected = True
            version_match = re.search(r'Next\.js[/ ]?(\d+\.\d+(?:\.\d+)?)', x_powered_by, re.I)
            if version_match:
                nextjs_version = version_match.group(1)

        # Check for Next.js patterns in content
        if re.search(r'_next/static|__NEXT_DATA__', content[:50000], re.I):
            nextjs_detected = True
            # Try to extract version from __NEXT_DATA__ script tag
            next_data_match = re.search(r'<script[^>]+id="__NEXT_DATA__"[^>]*>([^<]+)</script>', content[:100000], re.I)
            if next_data_match and not nextjs_version:
                try:
                    next_data = json.loads(next_data_match.group(1))
                    # Try common version locations in __NEXT_DATA__
                    if next_data.get("nextVersion"):
                        nextjs_version = next_data["nextVersion"]
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass

        if nextjs_detected:
            tech_stack.append({"name": "Next.js", "version": nextjs_version})

        # Content patterns (excluding Next.js which is handled above)
        content_patterns = [(r"wp-content|wp-includes", "WordPress"), (r"Joomla", "Joomla"), (r"sites/default|/drupal", "Drupal"), (r"React\.createElement", "React"), (r"ng-app|AngularJS", "AngularJS"), (r"Vue\.js|v-for|v-if", "Vue.js"), (r"ember\.js", "Ember.js"), (r"jquery|jQuery", "jQuery"), (r"bootstrap\.min", "Bootstrap"), (r"tailwind", "Tailwind CSS")]
        for pattern, tech_name in content_patterns:
            if re.search(pattern, content[:10000], re.I) if len(content) > 10000 else re.search(pattern, content, re.I):
                tech_stack.append({"name": tech_name, "version": None})

    seen = set()
    unique_stack = []
    for tech in tech_stack:
        key = tech["name"]
        if key not in seen:
            seen.add(key)
            unique_stack.append(tech)
    return {"technologies": unique_stack, "cve_candidates": cve_candidates, "fingerprint": hashlib.md5(json.dumps(unique_stack, sort_keys=True).encode()).hexdigest()}


async def fetch_sitemap_urls(base_url: str) -> list[str]:
    urls: list[str] = []
    try:
        sitemap_url = urllib.parse.urljoin(base_url, "/sitemap.xml")
        out, err, rc = await run(["curl", "-sS", "-L", "-k", "--max-time", "10", sitemap_url])
        if rc == 0 and out:
            url_pattern = re.compile(r"<loc>(.*?)</loc>", re.I)
            urls = url_pattern.findall(out)[:100]
    except Exception:
        pass
    return urls


async def browser_crawl_fallback(url: str) -> list[str]:
    urls: list[str] = []
    if not HAS_PLAYWRIGHT:
        return urls
    try:
        async with _pw() as browser:
            ctx = await browser.new_context(ignore_https_errors=True, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            page = await ctx.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            links = await page.evaluate(
                """
                () => {
                    const links = [];
                    document.querySelectorAll('a[href]').forEach(a => {
                        const href = a.href;
                        if (href && !href.startsWith('javascript:') && !href.startsWith('#')) { links.push(href); }
                    });
                    document.querySelectorAll('form[action]').forEach(form => {
                        const action = new URL(form.action, window.location.href).href;
                        links.push(action);
                    });
                    return [...new Set(links)];
                }
                """
            )
            urls = links[:200] if isinstance(links, list) else []
            await ctx.close()
    except Exception:
        pass
    return urls


async def pd_httpx_probe(host: str, port: int | None = None) -> list[dict]:
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0",
    ]
    target_host = host
    if port and port not in [80, 443]:
        target_host = f"{host}:{port}"
    for ua in user_agents:
        httpx_cmd = "/opt/tools/httpx" if os.path.exists("/opt/tools/httpx") else "httpx"
        out, err, rc = await run([httpx_cmd, "-json", "-tech-detect", "-title", "-status-code", "-follow-host-redirects", "-H", f"User-Agent: {ua}", "-timeout", "30", "-threads", "10", "-u", f"https://{target_host}", "-u", f"http://{target_host}"], timeout=120)
        rows = []
        if rc == 0 and out:
            for line in out.splitlines():
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
            if rows:
                return rows
    fallback_urls = []
    for scheme in ["https", "http"]:
        out, err, rc = await run(["curl", "-sS", "-I", "-L", "-k", "--max-time", "10", f"{scheme}://{target_host}"])
        if rc == 0:
            fallback_urls.append({"url": f"{scheme}://{target_host}", "status_code": 200, "tech": []})
    return fallback_urls


async def discover_endpoint_parameters(url: str) -> list[str]:
    """
    Discover which parameters an endpoint accepts by testing common params.

    Uses response analysis to detect:
    1. Response differs from baseline (param accepted)
    2. Error message mentions param name
    3. JSON response structure changes

    Args:
        url: The endpoint URL to test (without query params)

    Returns:
        List of parameter names that appear to be accepted
    """
    accepted_params: list[str] = []

    # Get baseline response
    baseline_out, _, baseline_rc = await run([
        "curl", "-sS", "-L", "-k", "--max-time", "3",
        "-w", "\n---STATUS:%{http_code}---SIZE:%{size_download}---",
        url
    ], timeout=5)

    if baseline_rc != 0:
        return []

    # Parse baseline metrics
    baseline_size = 0
    baseline_status = "000"
    if "---STATUS:" in baseline_out:
        try:
            baseline_status = baseline_out.split("---STATUS:")[1].split("---")[0]
            baseline_size = int(baseline_out.split("---SIZE:")[1].split("---")[0])
        except (IndexError, ValueError):
            pass

    # Determine which params to try based on URL pattern
    params_to_try = list(COMMON_PARAMS)  # Start with common params

    # Add endpoint-specific params based on URL
    url_lower = url.lower()
    for pattern, specific_params in ENDPOINT_PARAMS.items():
        if pattern in url_lower:
            params_to_try = specific_params + params_to_try  # Prioritize specific params

    # Test each parameter (limit to first 15 to avoid slowdown)
    for param in params_to_try[:15]:
        test_url = f"{url}?{param}=test123"
        out, _, rc = await run([
            "curl", "-sS", "-L", "-k", "--max-time", "2",
            "-w", "\n---STATUS:%{http_code}---SIZE:%{size_download}---",
            test_url
        ], timeout=3)

        if rc != 0:
            continue

        # Parse test metrics
        test_size = 0
        test_status = "000"
        if "---STATUS:" in out:
            try:
                test_status = out.split("---STATUS:")[1].split("---")[0]
                test_size = int(out.split("---SIZE:")[1].split("---")[0])
            except (IndexError, ValueError):
                continue

        # Detection logic
        param_accepted = False

        # 1. Status code changed significantly (but not to error)
        if test_status != baseline_status and test_status not in ["404", "400", "500", "502", "503"]:
            param_accepted = True

        # 2. Response size changed significantly (>10% or >100 bytes)
        if baseline_size > 0:
            size_diff = abs(test_size - baseline_size)
            size_pct = (size_diff / baseline_size) * 100
            if size_diff > 100 or size_pct > 10:
                param_accepted = True

        # 3. Parameter name appears in response (error message, reflection)
        response_body = out.split("---STATUS:")[0] if "---STATUS:" in out else out
        if param in response_body.lower() or "test123" in response_body:
            param_accepted = True

        # 4. JSON response structure changed (new keys)
        if response_body.strip().startswith("{") or response_body.strip().startswith("["):
            try:
                test_json = json.loads(response_body)
                if isinstance(test_json, dict) and param in str(test_json).lower():
                    param_accepted = True
            except json.JSONDecodeError:
                pass

        if param_accepted:
            accepted_params.append(param)

    return accepted_params


async def enhanced_url_discovery(url: str, scan_type: str = "standard") -> dict[str, Any]:
    """
    Multi-level URL discovery with configurable depth based on scan type.

    Args:
        url: Target URL to crawl
        scan_type: One of 'quick', 'standard', 'deep', 'full', 'aggressive'

    Returns:
        Dict with discovered URLs, forms, API endpoints, and parameters
    """
    config = DISCOVERY_CONFIG.get(scan_type, DISCOVERY_CONFIG["standard"])
    depth = config["katana_depth"]
    max_urls = config["max_urls"]
    use_browser = config["browser_fallback"]
    do_param_discovery = config["parameter_discovery"]
    do_js_parsing = config.get("js_parsing", False)
    ffuf_wordlist = config.get("ffuf_wordlist", "common")
    do_recursive_fuzzing = config.get("recursive_fuzzing", False)
    api_probe_limit = config.get("api_probe_limit", 0)
    common_probe_limit = config.get("common_probe_limit", 0)
    api_root_resource_limit = config.get("api_root_resource_limit", 0)

    print(f"[discovery] Starting {scan_type} discovery (depth={depth}, max_urls={max_urls}, js_parsing={do_js_parsing}, recursive={do_recursive_fuzzing})", file=sys.stderr)

    discovered_urls: list[str] = []
    forms: list[dict] = []
    api_endpoints: list[str] = []
    discovered_params: dict[str, list[str]] = {}  # URL -> list of discovered params
    js_bundle_analysis: dict[str, Any] | None = None

    katana_cmd = "/opt/tools/katana" if os.path.exists("/opt/tools/katana") else "katana"
    out, err, rc = await run([
        katana_cmd, "-u", url, "-jsonl", "-silent",
        "-depth", str(depth),  # Use configured depth
        "-aff", "-fx", "-kf",
        "-ef", "jpg,png,svg,gif,ico,css,woff,woff2,ttf,eot",
        "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        "-timeout", "30",
        "-concurrency", "10",  # Increased concurrency for deeper crawls
        "-delay", "200",  # Reduced delay for faster crawling
        "-form-extraction"
    ], timeout=300)  # Longer timeout for deeper crawls
    if rc == 0 and out:
        for l in out.splitlines():
            try:
                j = json.loads(l)
                # Katana JSONL format: {"request": {"endpoint": "url"}} or {"url": "url"}
                req = j.get("request", {})
                u = req.get("endpoint") or req.get("url") if isinstance(req, dict) else j.get("url")
                if u:
                    discovered_urls.append(u)
                    if any(api_pattern in u for api_pattern in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
                        api_endpoints.append(u)
                if "form" in j:
                    forms.append(j["form"])
            except Exception:
                pass
    # Extract JS/CSS from HTML directly (for SPAs that katana misses)
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                html = resp.text
                # Extract script src
                script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
                for src in script_srcs:
                    if src.startswith("http"):
                        discovered_urls.append(src)
                    elif src.startswith("//"):
                        discovered_urls.append("https:" + src)
                    elif src.startswith("/"):
                        discovered_urls.append(urllib.parse.urljoin(url, src))
                    else:
                        discovered_urls.append(urllib.parse.urljoin(url, "/" + src))
                if script_srcs:
                    print(f"[discovery] Extracted {len(script_srcs)} script URLs from HTML", file=sys.stderr)
    except Exception as e:
        print(f"[discovery] HTML script extraction failed: {e}", file=sys.stderr)

    # Browser fallback for SPAs (if configured and few URLs found)
    if use_browser and len(discovered_urls) < 10:
        print(f"[discovery] Few URLs found ({len(discovered_urls)}), trying browser crawl", file=sys.stderr)
        browser_urls = await browser_crawl_fallback(url)
        discovered_urls.extend(browser_urls)
        print(f"[discovery] Browser crawl found {len(browser_urls)} additional URLs", file=sys.stderr)

    # Sitemap parsing
    sitemap_urls = await fetch_sitemap_urls(url)
    discovered_urls.extend(sitemap_urls)
    robots_url = urllib.parse.urljoin(url, "/robots.txt")
    out, err, rc = await run(["curl", "-sS", "-L", "-k", "--max-time", "5", robots_url])
    if rc == 0 and out:
        for line in out.splitlines():
            if line.startswith("Disallow:") or line.startswith("Allow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    discovered_urls.append(urllib.parse.urljoin(url, path))
    # Expanded API and OpenAPI discovery paths
    # Generic patterns that work across different frameworks - no app-specific endpoints
    common_api_paths = [
        # HIGH-VALUE injection targets (search, login - most commonly vulnerable)
        "/search?q=test", "/api/search?q=test", "/rest/search?q=test",
        "/login", "/api/login", "/rest/login", "/auth/login",
        "/api/users", "/rest/users", "/api/user", "/rest/user",
        "/api/products", "/rest/products", "/api/items", "/rest/items",

        # Common CRUD endpoints (generic patterns)
        "/api/orders", "/rest/orders", "/api/order",
        "/api/cart", "/rest/cart", "/api/basket", "/rest/basket",
        "/api/comments", "/rest/comments", "/api/feedback", "/rest/feedback",
        "/api/reviews", "/rest/reviews",

        # Auth and session endpoints
        "/api/register", "/rest/register", "/auth/register",
        "/api/logout", "/rest/logout", "/auth/logout",
        "/api/me", "/rest/me", "/api/profile", "/rest/profile",
        "/api/account", "/rest/account",
        "/api/password/reset", "/rest/password/reset",
        "/api/token", "/auth/token", "/oauth/token",

        # Admin endpoints
        "/api/admin", "/rest/admin", "/admin/api",
        "/api/config", "/rest/config", "/api/settings",
        "/admin", "/administrator", "/manage",

        # File and upload endpoints
        "/api/upload", "/rest/upload", "/upload",
        "/api/file", "/rest/file", "/files", "/api/files",
        "/api/download", "/download",

        # Data endpoints
        "/api/data", "/rest/data",
        "/api/export", "/api/import", "/api/backup",

        # API base endpoints
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/rest/v2",
        "/graphql", "/query", "/health", "/status", "/metrics",
        "/.well-known/health", "/actuator/health",

        # OpenAPI/Swagger - standard locations
        "/openapi.json", "/openapi.yaml",
        "/swagger.json", "/swagger.yaml",
        "/v2/api-docs", "/v3/api-docs",
        "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
        "/api-docs", "/api-docs.json",
        "/docs", "/redoc",
        "/swagger-ui.html", "/swagger-ui/",
        "/swagger-resources",
        "/swagger-resources/configuration/ui",
        "/api/openapi.json", "/api/swagger.json",
        "/api/v1/openapi.json", "/api/v2/openapi.json",
        "/.well-known/openapi.json",
        "/.openapi.json", "/.swagger.json",
        "/graphql/schema", "/graphql/playground",

        # Common sensitive file paths
        "/ftp", "/backup", "/backups",
        "/.git/config", "/.env", "/.htaccess",
        "/wp-config.php.bak", "/config.php.bak",
    ]
    if api_probe_limit:
        api_candidates = list(common_api_paths)
        api_candidates.extend(
            _build_api_probe_candidates(
                api_probe_limit=api_probe_limit,
                common_probe_limit=common_probe_limit,
                api_root_resource_limit=api_root_resource_limit
            )
        )
        probed_endpoints = await _probe_api_candidates(url, api_candidates, timeout=5.0, concurrency=12)
        if probed_endpoints:
            discovered_urls.extend(probed_endpoints)
            api_endpoints.extend(probed_endpoints)
    unique_urls = sorted(set(discovered_urls))[:max_urls]

    # JS parsing - extract endpoints from JavaScript files
    if do_js_parsing:
        js_urls = [u for u in unique_urls if u.endswith(".js") or ".js?" in u][:20]
        if js_urls:
            print(f"[discovery] Parsing {len(js_urls)} JS files for endpoints", file=sys.stderr)
            js_endpoints = await analyze_js_bundles(url, js_urls, max_bundles=20)
            js_bundle_analysis = js_endpoints
            for endpoint in js_endpoints.get("api_endpoints", []):
                # Normalize: strip quotes, ensure leading slash for relative paths
                endpoint = endpoint.strip("'\"` ")
                if not endpoint:
                    continue
                # Skip common false positives
                if endpoint in ("", "/", "//") or len(endpoint) < 2:
                    continue
                # Add leading slash if missing (relative path from JS)
                if not endpoint.startswith("/") and not endpoint.startswith("http"):
                    endpoint = "/" + endpoint
                if endpoint.startswith("/"):
                    full_url = urllib.parse.urljoin(url, endpoint)
                    if full_url not in unique_urls:
                        unique_urls.append(full_url)
                        api_endpoints.append(full_url)
            print(f"[discovery] JS parsing found {len(js_endpoints.get('api_endpoints', []))} additional endpoints", file=sys.stderr)

    # FFUF-based directory fuzzing with appropriate wordlist
    if ffuf_wordlist and ffuf_wordlist != "minimal":
        # Map wordlist names to actual wordlists
        wordlist_paths = {
            "common": "/usr/share/wordlists/dirb/common.txt",
            "comprehensive": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "extended": "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
        }
        wordlist_path = wordlist_paths.get(ffuf_wordlist)
        if not wordlist_path or not os.path.exists(wordlist_path):
            local_common = WORDLIST_PATHS.get("common")
            if local_common and os.path.exists(local_common):
                wordlist_path = local_common
                print("[discovery] System wordlist missing, using bundled common wordlist", file=sys.stderr)
        if wordlist_path and os.path.exists(wordlist_path):
            print(f"[discovery] Running ffuf with {ffuf_wordlist} wordlist", file=sys.stderr)
            ffuf_cmd = "/opt/tools/ffuf" if os.path.exists("/opt/tools/ffuf") else "ffuf"
            ffuf_out, _, ffuf_rc = await run([
                ffuf_cmd, "-u", f"{url.rstrip('/')}/FUZZ", "-w", wordlist_path,
                "-mc", "200,201,204,301,302,307,401,403",
                "-t", "20", "-timeout", "5", "-o", "/dev/stdout", "-of", "json",
                "-s"  # Silent mode
            ], timeout=180)
            if ffuf_rc == 0 and ffuf_out:
                try:
                    ffuf_data = json.loads(ffuf_out)
                    for result in ffuf_data.get("results", []):
                        found_url = result.get("url", "")
                        if found_url and found_url not in unique_urls:
                            unique_urls.append(found_url)
                    print(f"[discovery] ffuf found {len(ffuf_data.get('results', []))} paths", file=sys.stderr)
                except json.JSONDecodeError:
                    pass

    # Recursive directory fuzzing for deeper discovery
    # Skip if scan_type is "smart" - smart_discovery does its own recursive phase
    if do_recursive_fuzzing and scan_type != "smart":
        print(f"[discovery] Running recursive directory discovery", file=sys.stderr)
        # Collect directory paths from discovered URLs
        initial_dirs = [u for u in unique_urls if u.endswith("/")]
        # Also add common starting points
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        initial_dirs.extend([f"{base}/", f"{base}/api/", f"{base}/admin/"])
        initial_dirs = list(set(initial_dirs))[:20]  # Dedupe and limit
        recursive_result = await recursive_directory_discovery(url, initial_paths=initial_dirs, max_depth=3, max_paths_per_level=20)
        for path in recursive_result.get("paths", []):
            full_url = urllib.parse.urljoin(url, path)
            if full_url not in unique_urls:
                unique_urls.append(full_url)
        print(f"[discovery] Recursive discovery found {len(recursive_result.get('paths', []))} additional paths", file=sys.stderr)

    # Categorize URLs after all discovery phases complete
    parameterized_urls = [u for u in unique_urls if "?" in u]
    form_urls = [u for u in unique_urls if any(form_pattern in u.lower() for form_pattern in ["login", "register", "signup", "signin", "contact", "search"])]

    # Parameter discovery for endpoints without parameters (full/aggressive scans)
    if do_param_discovery:
        print(f"[discovery] Running parameter discovery on {len(unique_urls)} URLs", file=sys.stderr)
        # Find URLs without query params that might accept them
        # Fixed: Added parentheses to fix precedence - must not have "?" AND must be API/REST endpoint
        candidate_urls = [u for u in unique_urls if "?" not in u and ("/api" in u.lower() or "/rest" in u.lower())][:50]
        for candidate_url in candidate_urls:
            found_params = await discover_endpoint_parameters(candidate_url)
            if found_params:
                discovered_params[candidate_url] = found_params
                # Add parameterized versions to the URL list
                for param in found_params[:3]:  # Top 3 params
                    param_url = f"{candidate_url}?{param}=test"
                    if param_url not in unique_urls:
                        unique_urls.append(param_url)
                        parameterized_urls.append(param_url)
        print(f"[discovery] Parameter discovery found params on {len(discovered_params)} endpoints", file=sys.stderr)

    # Re-cap to max_urls after all discovery phases (JS/ffuf/recursive may have exceeded limit)
    # Prioritize high-value endpoints: API, parameterized, then alphabetically for determinism
    if len(unique_urls) > max_urls:
        def url_priority(url: str) -> tuple:
            has_params = "?" in url
            is_api = any(p in url.lower() for p in ["/api/", "/rest/", "/graphql", "/v1/", "/v2/"])
            return (0 if is_api else 1, 0 if has_params else 1, url)
        unique_urls = sorted(unique_urls, key=url_priority)[:max_urls]
        # Also filter parameterized_urls to only include URLs in the capped list
        url_set = set(unique_urls)
        parameterized_urls = [u for u in parameterized_urls if u in url_set]
        form_urls = [u for u in form_urls if u in url_set]
        api_endpoints = [u for u in api_endpoints if u in url_set]

    print(f"[discovery] Discovery complete: {len(unique_urls)} URLs, {len(parameterized_urls)} with params, {len(api_endpoints)} API endpoints", file=sys.stderr)

    return {
        "all_urls": unique_urls,
        "parameterized_urls": parameterized_urls,
        "api_endpoints": list(set(api_endpoints)),
        "form_urls": form_urls,
        "forms": forms[:20],
        "discovered_params": discovered_params,
        "js_bundle_analysis": js_bundle_analysis,
        "scan_type": scan_type,
        "config": config,
    }


async def katana_crawl(url: str, scan_type: str = "standard") -> list[str]:
    """
    Wrapper for enhanced_url_discovery that returns just the URL list.

    Args:
        url: Target URL to crawl
        scan_type: One of 'quick', 'standard', 'deep', 'full', 'aggressive'

    Returns:
        List of discovered URLs
    """
    config = DISCOVERY_CONFIG.get(scan_type, DISCOVERY_CONFIG["standard"])
    max_urls = config["max_urls"]
    discovery = await enhanced_url_discovery(url, scan_type)
    return discovery.get("all_urls", [])[:max_urls]

async def schemathesis_run(schema_url: str, token: str | None = None, base_url: str | None = None) -> dict:
    headers: list[str] = []
    if token:
        headers += ["-H", f"Authorization: Bearer {token}"]
    cmd = [
        "schemathesis",
        "run",
        "--checks",
        "all",
        "--stateful",
        "links",
        "--hypothesis-deadline=200",
        "--hypothesis-max-examples=50",
    ]
    if base_url:
        cmd += ["--base-url", base_url]
    cmd += headers + [schema_url, "--report", "json"]
    out, err, rc = await run(cmd, timeout=900)
    try:
        rep = json.loads(out) if (rc == 0 and out) else {"error": err or "schemathesis failed", "rc": rc}
    except Exception:
        rep = {"error": "failed to parse schemathesis output", "rc": rc}
    return rep


# OpenAPI discovery paths for auto-discovery
OPENAPI_DISCOVERY_PATHS = [
    # Standard OpenAPI/Swagger paths
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    "/v2/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api-docs", "/api-docs.json",
    "/api/openapi.json", "/api/swagger.json",
    "/api/v1/openapi.json", "/api/v2/openapi.json",
    "/.well-known/openapi.json",
    # FastAPI/Starlette defaults
    "/docs", "/openapi",
    "/docs/openapi.json",
    # ReDoc
    "/redoc",
    # Django REST Framework
    "/api/schema", "/api/schema.json", "/api/schema.yaml",
    "/api/v1/schema", "/api/v2/schema",
    "/schema", "/schema.json", "/schema.yaml",
    # Springfox/SpringDoc
    "/api/swagger-resources", "/swagger-resources",
    "/swagger-ui/swagger.json",
    "/v3/api-docs/swagger-config",
    # Express/Node.js common paths
    "/api/documentation", "/api/docs",
    "/_api/docs", "/_api/openapi.json",
    # Microservice/API gateway patterns
    "/api/v1/docs", "/api/v2/docs", "/api/v3/docs",
    "/service/api-docs",
    # GraphQL schema
    "/graphql/schema",
    # Common API base prefixes (for apps like crAPI)
    "/community/api-docs", "/community/openapi.json",
    "/identity/api-docs", "/identity/openapi.json",
    "/workshop/api-docs", "/workshop/openapi.json",
]


def _parse_openapi_spec(raw_text: str) -> dict[str, Any] | None:
    if not raw_text:
        return None
    try:
        parsed = json.loads(raw_text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        if HAS_YAML:
            try:
                parsed = yaml.safe_load(raw_text)
                return parsed if isinstance(parsed, dict) else None
            except Exception:
                return None
    return None


def _default_value_from_schema(prop: dict[str, Any]) -> Any:
    if not isinstance(prop, dict):
        return "test"
    if "example" in prop:
        return prop["example"]
    if "default" in prop:
        return prop["default"]
    schema_format = prop.get("format")
    if schema_format == "email":
        return "invalid@example.com"
    if schema_format == "uuid":
        return "00000000-0000-0000-0000-000000000000"
    schema_type = prop.get("type")
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1.0
    if schema_type == "boolean":
        return False
    if schema_type == "array":
        return []
    if schema_type == "object":
        return {}
    return "test"


def _extract_schema_details(schema: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    required = []
    defaults: dict[str, Any] = {}
    if not isinstance(schema, dict):
        return required, defaults
    if isinstance(schema.get("required"), list):
        required = list(schema.get("required", []))
    properties = schema.get("properties", {})
    if isinstance(properties, dict):
        for name, prop in properties.items():
            if isinstance(prop, dict):
                defaults[name] = _default_value_from_schema(prop)
    return required, defaults


def extract_openapi_endpoints(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract endpoints from an OpenAPI/Swagger specification.

    Extracts both query/path parameters and POST body parameters for injection testing.
    """
    endpoints = []
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method.lower() not in ["get", "post", "put", "delete", "patch", "options", "head"]:
                continue
            if not isinstance(details, dict):
                continue

            # Extract query/path parameters
            query_params = []
            for p in details.get("parameters", []):
                if isinstance(p, dict) and "name" in p:
                    query_params.append(p["name"])

            # Extract POST body parameters from requestBody (OpenAPI 3.x)
            body_params = []
            body_required_params = []
            body_param_defaults: dict[str, Any] = {}
            content_type = None
            request_body = details.get("requestBody", {})
            if isinstance(request_body, dict):
                content = request_body.get("content", {})
                # Prioritize application/json
                for ct in ["application/json", "application/x-www-form-urlencoded", "multipart/form-data"]:
                    if ct in content:
                        content_type = ct
                        schema_def = content[ct]
                        if isinstance(schema_def, dict):
                            schema = schema_def.get("schema", {})
                            # Handle inline schema
                            if "properties" in schema:
                                body_params = list(schema.get("properties", {}).keys())
                                body_required_params, body_param_defaults = _extract_schema_details(schema)
                            # Handle $ref to components/schemas
                            elif "$ref" in schema:
                                ref_path = schema["$ref"]  # e.g., "#/components/schemas/LoginRequest"
                                if ref_path.startswith("#/components/schemas/"):
                                    schema_name = ref_path.split("/")[-1]
                                    components = spec.get("components", {}).get("schemas", {})
                                    ref_schema = components.get(schema_name, {})
                                    body_params = list(ref_schema.get("properties", {}).keys())
                                    body_required_params, body_param_defaults = _extract_schema_details(ref_schema)
                        break

            # Swagger 2.x uses 'body' parameter type
            for p in details.get("parameters", []):
                if isinstance(p, dict) and p.get("in") == "body":
                    schema = p.get("schema", {})
                    if "properties" in schema:
                        body_params = list(schema.get("properties", {}).keys())
                        body_required_params, body_param_defaults = _extract_schema_details(schema)
                    elif "$ref" in schema:
                        ref_path = schema["$ref"]
                        if ref_path.startswith("#/definitions/"):
                            def_name = ref_path.split("/")[-1]
                            definitions = spec.get("definitions", {})
                            ref_schema = definitions.get(def_name, {})
                            body_params = list(ref_schema.get("properties", {}).keys())
                            body_required_params, body_param_defaults = _extract_schema_details(ref_schema)
                    content_type = "application/json"
                    break

            endpoints.append({
                "path": path,
                "method": method.upper(),
                "parameters": query_params,  # Kept for backwards compatibility
                "query_params": query_params,
                "body_params": body_params,
                "body_required_params": body_required_params,
                "body_param_defaults": body_param_defaults,
                "content_type": content_type or "application/json",
                "auth_required": bool(details.get("security")),
                "summary": details.get("summary", ""),
            })
    return endpoints


async def fetch_openapi_schema(schema_url: str, auth_session: Any | None = None) -> dict[str, Any] | None:
    """Fetch and parse a schema from a specific OpenAPI/Swagger URL."""
    auth_args = get_auth_curl_args(auth_session)
    cmd = ["curl", "-sS", "-L", "-k", "--max-time", "5"] + auth_args + [schema_url]
    out, _, rc = await run(cmd, timeout=8)
    if rc != 0 or not out:
        return None

    spec = _parse_openapi_spec(out)
    if not isinstance(spec, dict):
        return None
    if not ("openapi" in spec or "swagger" in spec or "paths" in spec):
        return None

    version = spec.get("openapi") or spec.get("swagger") or "unknown"
    endpoints = extract_openapi_endpoints(spec)
    return {
        "url": schema_url,
        "version": version,
        "title": spec.get("info", {}).get("title", ""),
        "endpoints": endpoints,
        "endpoint_count": len(endpoints),
        "auth_schemes": list(spec.get("components", {}).get("securitySchemes", {}).keys()) if "components" in spec else [],
        "spec": spec,
    }


async def discover_openapi_schema(base_url: str, auth_session: Any | None = None) -> dict[str, Any] | None:
    """Auto-discover and parse OpenAPI/Swagger schema from common paths.

    Args:
        base_url: The base URL to scan for OpenAPI schemas
        auth_session: Optional authenticated session for protected schema endpoints

    Returns:
        Dict with schema info if found, None otherwise
    """
    import sys

    for path in OPENAPI_DISCOVERY_PATHS:
        url = urllib.parse.urljoin(base_url, path)
        schema = await fetch_openapi_schema(url, auth_session=auth_session)
        if schema:
            print(
                f"[discovery] Auto-discovered OpenAPI schema at {url} "
                f"(version {schema.get('version')}, {schema.get('endpoint_count', 0)} endpoints)",
                file=sys.stderr
            )
            return schema
    return None


async def deep_discovery_scan(base_url: str) -> dict[str, Any]:
    """Complete mode: Deep discovery using ffuf and other tools.

    Moved from scanner.py to keep discovery logic modularized.
    """
    results: dict[str, Any] = {
        "directories": [],
        "files": [],
        "parameters": [],
        "scan_completed": False,
    }

    # Use ffuf for directory fuzzing
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        local_common = WORDLIST_PATHS.get("common")
        if local_common and os.path.exists(local_common):
            wordlist = local_common
        else:
            wordlist = "/tmp/common.txt"
            # Create basic wordlist if doesn't exist
            common_paths = [
                "admin", "api", "backup", "config", "dashboard", "data", "db", "debug",
                "docs", "download", "files", "login", "logs", "private", "public",
                "secret", "test", "tmp", "upload", "users", "wp-admin", "wp-content",
            ]
            with open(wordlist, "w", encoding="utf-8") as f:
                f.write("\n".join(common_paths))

    cmd = [
        "ffuf", "-u", f"{base_url}/FUZZ",
        "-w", wordlist,
        "-mc", "200,301,302,401,403",
        "-t", "10",
        "-timeout", "10",
        "-sf",  # Smart filter
        "-o", "/tmp/ffuf.json",
        "-of", "json",
    ]

    out, err, rc = await run(cmd, timeout=300)

    if rc == 0 and os.path.exists("/tmp/ffuf.json"):
        try:
            with open("/tmp/ffuf.json") as f:
                ffuf_data = json.load(f)
                for result in ffuf_data.get("results", [])[:50]:  # Limit results
                    results["directories"].append({
                        "path": result.get("input", {}).get("FUZZ", ""),
                        "status": result.get("status"),
                        "size": result.get("length"),
                    })
            results["scan_completed"] = True
        except Exception:
            pass

    return results


async def check_cors(url: str) -> dict[str, Any]:
    results = {"vulnerable": False, "issues": []}
    test_origins = ["https://evil.com", "null"]
    for origin in test_origins:
        out, err, rc = await run(["curl", "-sS", "-I", "-H", f"Origin: {origin}", "-H", "Access-Control-Request-Method: GET", url], timeout=30)
        if rc == 0 and out:
            if f"access-control-allow-origin: {origin}" in out.lower():
                results["vulnerable"] = True
                results["issues"].append(f"Reflects origin: {origin}")
            elif "access-control-allow-origin: *" in out.lower():
                results["vulnerable"] = True
                results["issues"].append("Wildcard CORS (Access-Control-Allow-Origin: *)")
    # De-duplicate repeated issues
    if results["issues"]:
        results["issues"] = sorted(list(set(results["issues"])))
    return results


async def detect_cloud_services(host: str, headers: dict[str, list[str]]) -> dict[str, Any]:
    results: dict[str, Any] = {"provider": None, "services": [], "cdn": None, "misconfigurations": []}
    server_header = " ".join(headers.get("server", [])).lower()
    x_headers = {k: v for k, v in headers.items() if k.startswith("x-")}
    aws_indicators = [("x-amz-", "AWS Service"), ("x-amzn-", "AWS Service"), ("awselb", "AWS Elastic Load Balancer"), ("amazonws", "AWS"), ("cloudfront", "AWS CloudFront CDN")]
    for indicator, service in aws_indicators:
        if any(indicator in k.lower() for k in headers) or indicator in server_header:
            results["provider"] = "AWS"
            results["services"].append(service)
            if "cloudfront" in service.lower():
                results["cdn"] = "CloudFront"
    if "s3.amazonaws.com" in host or "s3-website" in host:
        results["provider"] = "AWS"
        results["services"].append("S3 Bucket")
        s3_url = f"https://{host}"
        out, err, rc = await run(["curl", "-sS", "-I", s3_url], timeout=10)
        if rc == 0 and "200 OK" in out:
            list_out, _, list_rc = await run(["curl", "-sS", s3_url], timeout=10)
            if list_rc == 0 and "<ListBucketResult" in list_out:
                results["misconfigurations"].append({"type": "s3_public_list", "severity": "high", "details": "S3 bucket allows public listing"})
    azure_indicators = [("x-ms-", "Azure Service"), ("x-azure-", "Azure Service"), ("azurewebsites", "Azure Web Apps"), ("blob.core.windows", "Azure Blob Storage"), ("azureedge", "Azure CDN"), ("cloudapp.azure", "Azure Cloud App")]
    for indicator, service in azure_indicators:
        if any(indicator in k.lower() for k in headers) or indicator in host:
            results["provider"] = "Azure"
            results["services"].append(service)
            if "azureedge" in indicator:
                results["cdn"] = "Azure CDN"
    gcp_indicators = [("x-goog-", "GCP Service"), ("x-guploader-", "GCP Storage"), ("googleapis", "Google APIs"), ("googleusercontent", "GCP"), ("appspot.com", "Google App Engine"), ("cloudfunctions.net", "Google Cloud Functions"), ("run.app", "Google Cloud Run")]
    for indicator, service in gcp_indicators:
        if any(indicator in k.lower() for k in headers) or indicator in host:
            results["provider"] = "GCP"
            results["services"].append(service)
    cdn_indicators = [("cloudflare", "Cloudflare"), ("cf-ray", "Cloudflare"), ("fastly", "Fastly"), ("x-served-by", "Fastly"), ("akamai", "Akamai"), ("x-akamai", "Akamai"), ("keycdn", "KeyCDN"), ("maxcdn", "MaxCDN"), ("stackpath", "StackPath"), ("bunny", "BunnyCDN"), ("sucuri", "Sucuri")]
    for indicator, cdn_name in cdn_indicators:
        if any(indicator in k.lower() for k in headers) or indicator in server_header:
            results["cdn"] = cdn_name
            if cdn_name == "Cloudflare":
                if "cf-connecting-ip" in x_headers:
                    results["misconfigurations"].append({"type": "cloudflare_ip_leak", "severity": "medium", "details": "Real server IP might be exposed"})
    if results["cdn"] and not results["misconfigurations"]:
        if "x-forwarded-for" in headers or "x-real-ip" in headers:
            results["misconfigurations"].append({"type": "origin_ip_leak", "severity": "medium", "details": "Origin server IP might be exposed through headers"})
    return results


async def detect_waf(url: str, headers: dict[str, list[str]]) -> dict[str, Any]:
    results: dict[str, Any] = {"waf_detected": False, "waf_products": [], "confidence": "none", "bypass_techniques": []}
    waf_signatures = {
        "cloudflare": [("cf-ray", "header"), ("cf-cache-status", "header"), ("__cfduid", "cookie"), ("cloudflare", "server")],
        "akamai": [("akamai", "header"), ("akamai-origin-hop", "header"), ("x-akamai", "header")],
        "aws_waf": [("x-amzn-requestid", "header"), ("x-amzn-trace-id", "header"), ("awselb", "cookie")],
        "sucuri": [("x-sucuri-id", "header"), ("sucuri", "server"), ("x-sucuri-cache", "header")],
        "incapsula": [("x-iinfo", "header"), ("incap_ses", "cookie"), ("visid_incap", "cookie")],
        "f5_bigip": [("x-wa-info", "header"), ("bigipserver", "cookie"), ("f5-bigip", "server")],
        "barracuda": [("barra", "header"), ("x-barracuda", "header")],
        "modsecurity": [("mod_security", "server"), ("modsecurity", "server")],
        "fortinet": [("fortigate", "server"), ("fortiweb", "header")],
    }
    for waf_name, signatures in waf_signatures.items():
        for sig, sig_type in signatures:
            if sig_type == "header":
                if any(sig.lower() in k.lower() for k in headers):
                    results["waf_detected"] = True
                    results["waf_products"].append(waf_name)
                    break
            elif sig_type == "server":
                server = headers.get("server", [""])[0].lower()
                if sig.lower() in server:
                    results["waf_detected"] = True
                    results["waf_products"].append(waf_name)
                    break
    waf_test_payloads = [
        ("XSS", "<script>alert(1)</script>"),
        ("SQLi", "' OR '1'='1"),
        ("Path Traversal", "../../../etc/passwd"),
        ("RCE", "<?php system('id'); ?>")
    ]
    blocked_responses = 0
    blocked_details = []
    for payload_type, payload in waf_test_payloads:
        test_url = f"{url}?test={urllib.parse.quote(payload)}"
        out, err, rc = await run(["curl", "-sS", "-L", "-k", "--max-time", "5", "-w", "\n%{http_code}", test_url], timeout=10)
        if rc == 0:
            lines = out.strip().split("\n")
            if lines:
                status_code = lines[-1]
                response_body = "\n".join(lines[:-1]).lower()
                blocked = False
                block_reason = None

                if status_code in ["403", "406", "419", "429", "503"]:
                    blocked = True
                    block_reason = f"HTTP {status_code}"

                blocking_sigs = ["access denied", "forbidden", "blocked", "security", "firewall", "protection", "suspicious", "malicious"]
                for sig in blocking_sigs:
                    if sig in response_body:
                        blocked = True
                        block_reason = f"Response contains '{sig}'"
                        break

                if blocked:
                    blocked_responses += 1
                    blocked_details.append({
                        "payload_type": payload_type,
                        "payload": payload[:50],  # Truncate for readability
                        "status_code": status_code,
                        "block_reason": block_reason,
                        "test_url": test_url[:100]  # Truncate URL
                    })

    if blocked_responses >= 2:
        if results["waf_products"]:
            results["waf_detected"] = True
            results["confidence"] = "high" if blocked_responses >= 3 else "medium"
            results["blocked_details"] = blocked_details
            results["bypass_techniques"] = [
                "Use encoding (URL, Unicode, HTML entity)",
                "Try HTTP parameter pollution",
                "Use HTTP verb tampering",
                "Attempt case variation",
                "Use time delays between requests",
                "Try chunked transfer encoding",
                "Use alternate data streams",
            ]
        else:
            results["input_validation_detected"] = True
            results["blocked_payloads"] = blocked_responses
            results["blocked_details"] = blocked_details
            results["confidence"] = "medium"
            results["waf_detected"] = False
    return results


async def enumerate_virtual_hosts(
    base_url: str,
    host: str,
    ip_addresses: list[str] | None = None,
    candidates: list[str] | None = None,
    max_hosts: int = 12
) -> dict[str, Any]:
    """
    Enumerate potential virtual hosts on the same IP by testing Host headers.
    """
    results: dict[str, Any] = {
        "hosts_tested": 0,
        "potential_vhosts": [],
        "baseline": {},
    }

    if not ip_addresses:
        return results

    parsed = urllib.parse.urlparse(base_url)
    scheme = parsed.scheme or "https"
    port = parsed.port or (443 if scheme == "https" else 80)

    # Determine base domain (strip common prefixes)
    host_parts = host.split(".")
    base_domain = host
    if host_parts and host_parts[0].lower() in {"www", "app", "api", "portal", "dev", "staging"} and len(host_parts) > 2:
        base_domain = ".".join(host_parts[1:])

    prefixes = candidates or [
        "admin", "dev", "staging", "test", "beta", "api", "internal",
        "portal", "app", "old", "preview", "sandbox",
    ]
    candidate_hosts = [f"{p}.{base_domain}" for p in prefixes if f"{p}.{base_domain}" != host]
    candidate_hosts = candidate_hosts[:max_hosts]

    status_marker = "__STATUS__:"
    sem = asyncio.Semaphore(4)

    async def fetch_for_host(target_host: str, ip: str) -> tuple[int | None, str]:
        async with sem:
            host_with_port = target_host
            if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
                host_with_port = f"{target_host}:{port}"
            if scheme == "https":
                cmd = [
                    "curl", "-sS", "-L", "-k", "--max-time", "8",
                    "--resolve", f"{target_host}:{port}:{ip}",
                    "-w", f"\n{status_marker}%{{http_code}}",
                    f"{scheme}://{host_with_port}/",
                ]
            else:
                cmd = [
                    "curl", "-sS", "-L", "--max-time", "8",
                    "-H", f"Host: {target_host}",
                    "-w", f"\n{status_marker}%{{http_code}}",
                    f"{scheme}://{ip}:{port}/",
                ]
            out, _, rc = await run(cmd, timeout=12)
            if rc != 0 or not out or status_marker not in out:
                return None, ""
            body, status_part = out.rsplit(status_marker, 1)
            status_code = int(status_part.strip()) if status_part.strip().isdigit() else None
            return status_code, body

    def summarize_response(status_code: int | None, body: str) -> dict[str, Any]:
        body_text = body or ""
        return {
            "status": status_code,
            "length": len(body_text),
            "hash": hashlib.sha256(body_text[:50000].encode("utf-8", errors="ignore")).hexdigest()[:12] if body_text else "",
        }

    ip = ip_addresses[0]
    baseline_status, baseline_body = await fetch_for_host(host, ip)
    if baseline_status is None or not baseline_body:
        return results

    baseline_summary = summarize_response(baseline_status, baseline_body)
    results["baseline"] = dict(baseline_summary)

    wildcard_host = f"{secrets.token_hex(3)}.{base_domain}"
    wildcard_status, wildcard_body = await fetch_for_host(wildcard_host, ip)
    wildcard_summary = summarize_response(wildcard_status, wildcard_body) if wildcard_status and wildcard_body else None
    if wildcard_summary:
        results["baseline"]["wildcard"] = (
            wildcard_summary["status"] == baseline_summary["status"]
            and wildcard_summary["hash"] == baseline_summary["hash"]
        )
        results["baseline"]["wildcard_status"] = wildcard_summary["status"]
        results["baseline"]["wildcard_hash"] = wildcard_summary["hash"]

    async def test_candidate(candidate: str) -> tuple[str, dict[str, Any] | None]:
        status_code, body = await fetch_for_host(candidate, ip)
        if status_code is None or not body:
            return candidate, None
        return candidate, summarize_response(status_code, body)

    tasks = [test_candidate(candidate) for candidate in candidate_hosts]
    responses = await asyncio.gather(*tasks)
    results["hosts_tested"] = len(candidate_hosts)

    compare_summary = wildcard_summary or baseline_summary
    for candidate, summary in responses:
        if not summary:
            continue
        if summary["status"] not in (200, 301, 302, 403):
            continue
        if compare_summary["hash"] and summary["hash"] == compare_summary["hash"] and summary["status"] == compare_summary["status"]:
            continue
        length_diff = abs(summary["length"] - compare_summary["length"])
        length_ratio = length_diff / max(compare_summary["length"], 1)
        if summary["hash"] != compare_summary["hash"] and (length_diff > 200 or length_ratio > 0.2 or summary["status"] != compare_summary["status"]):
            results["potential_vhosts"].append({
                "host": candidate,
                "ip": ip,
                "status": summary["status"],
                "length": summary["length"],
                "hash": summary["hash"],
            })

    return results


async def api_security_test(url: str) -> dict[str, Any]:
    results: dict[str, Any] = {"api_type": "unknown", "vulnerabilities": [], "endpoints_discovered": [], "authentication": {"required": False, "methods": []}}
    api_indicators = {"rest": ["/api/", "/v1/", "/v2/", "/rest/"], "graphql": ["/graphql", "/gql", "/query"], "soap": [".wsdl", ".asmx", "/soap/"], "grpc": ["/grpc/", ".proto"]}
    for api_type, indicators in api_indicators.items():
        if any(ind in url.lower() for ind in indicators):
            results["api_type"] = api_type
            break
    if "graphql" in url.lower():
        introspection_query = {"query": "{ __schema { types { name fields { name type { name } } } } }"}
        out, err, rc = await run(["curl", "-sS", "-X", "POST", "-L", "-k", "-H", "Content-Type: application/json", "-d", json.dumps(introspection_query), url], timeout=10)
        if rc == 0 and "__schema" in out:
            results["vulnerabilities"].append({"type": "graphql_introspection_enabled", "severity": "medium", "description": "GraphQL introspection is enabled, exposing API schema"})
            try:
                schema_data = json.loads(out)
                if "data" in schema_data and "__schema" in schema_data["data"]:
                    types = schema_data["data"]["__schema"].get("types", [])
                    for type_obj in types:
                        if type_obj.get("name", "").startswith("__"):
                            continue
                        results["endpoints_discovered"].append(type_obj.get("name", "unknown"))
            except Exception:
                pass
        deep_query = {"query": "{" + " ".join(["user { posts {" for _ in range(20)]) + "id" + "}" * 40 + "}"}
        out, err, rc = await run(["curl", "-sS", "-X", "POST", "-L", "-k", "--max-time", "10", "-H", "Content-Type: application/json", "-d", json.dumps(deep_query), url], timeout=15)
        if rc == 124:
            results["vulnerabilities"].append({"type": "graphql_depth_limit_missing", "severity": "high", "description": "No query depth limit, vulnerable to DoS"})
    common_endpoints = ["/api/users", "/api/user", "/api/admin", "/api/config", "/api/v1/users", "/api/v2/users", "/api/swagger", "/api/docs", "/swagger.json", "/openapi.json", "/api-docs"]
    auth_required_endpoints: list[str] = []
    for endpoint in common_endpoints:
        test_url = urllib.parse.urljoin(url, endpoint)
        out, err, rc = await run(["curl", "-sS", "-L", "-k", "--max-time", "5", "-w", "\n%{http_code}", test_url], timeout=10)
        if rc == 0:
            lines = out.strip().split("\n")
            if lines:
                status_code = lines[-1]
                if status_code == "200":
                    response_body = "\n".join(lines[:-1])
                    is_html = any(html_indicator in response_body[:500].lower() for html_indicator in ["<!doctype", "<html", "text/html", "<head>", "<body>"])
                    if not is_html and response_body:
                        has_api_spec = any(api_indicator in response_body[:2000] for api_indicator in ["\"swagger\"", "\"openapi\"", "\"paths\"", "\"components\"", "\"definitions\"", "\"servers\"", "\"info\"", "\"version\"", "swagger:", "openapi:", "paths:", "servers:", "<?xml"])
                        if has_api_spec:
                            results["endpoints_discovered"].append(endpoint)
                            if "\"swagger\"" in response_body or "swagger:" in response_body:
                                results["api_type"] = "swagger"
                            elif "\"openapi\"" in response_body or "openapi:" in response_body:
                                results["api_type"] = "openapi"
                    if any(sensitive in response_body.lower() for sensitive in ["password", "token", "api_key", "secret", "private"]):
                        if not is_html:
                            results["vulnerabilities"].append({"type": "sensitive_data_exposure", "severity": "high", "endpoint": endpoint, "description": "Potential sensitive data exposed in API response"})
                elif status_code in ["401", "403"]:
                    results["authentication"]["required"] = True
                    auth_required_endpoints.append(test_url)
    if not auth_required_endpoints:
        protected_paths = ["/admin", "/api/admin", "/user/profile", "/api/user/profile", "/dashboard", "/api/me"]
        for path in protected_paths:
            test_url = urllib.parse.urljoin(url, path)
            out, err, rc = await run(["curl", "-sS", "-L", "-k", "--max-time", "5", "-w", "\n%{http_code}", test_url], timeout=10)
            if rc == 0:
                lines = out.strip().split("\n")
                if lines and lines[-1] in ["401", "403"]:
                    auth_required_endpoints.append(test_url)
    # Note: auth bypass testing omitted for brevity here; keep in original scanner if required.
    return results


# =============================================================================
# RECURSIVE DIRECTORY DISCOVERY - Deep Fuzzing for Smart Scans
# =============================================================================
# Recursively fuzz discovered directories to find hidden paths and endpoints.


async def _run_ffuf_on_path(
    base_url: str,
    path: str,
    wordlist: str = "common",
    timeout: int = 60
) -> list[str]:
    """
    Run ffuf against a specific path.

    Args:
        base_url: Base URL of the target
        path: Directory path to fuzz (e.g., "/api/")
        wordlist: Wordlist to use
        timeout: Timeout in seconds

    Returns:
        List of discovered paths
    """
    discovered: list[str] = []

    # Select wordlist based on path context
    if "/api/" in path.lower() or "/rest/" in path.lower():
        wordlist_path = "/tmp/api-wordlist.txt"
        api_words = _read_wordlist(WORDLIST_PATHS.get("api_resources", ""), limit=120)
        if not api_words:
            api_words = [
                "users", "user", "admin", "config", "settings", "profile", "account",
                "products", "items", "orders", "search", "auth", "login", "logout",
                "register", "password", "reset", "verify", "status", "health",
                "version", "info", "debug", "test", "docs", "swagger", "openapi",
                "v1", "v2", "v3", "public", "private", "internal", "external",
                "me", "self", "current", "new", "create", "update", "delete",
                "list", "get", "post", "put", "patch", "upload", "download",
                "export", "import", "backup", "restore", "logs", "audit",
            ]
        with open(wordlist_path, "w", encoding="utf-8") as f:
            f.write("\n".join(api_words))
    elif "/admin" in path.lower():
        wordlist_path = "/tmp/admin-wordlist.txt"
        admin_words = _read_wordlist(WORDLIST_PATHS.get("admin", ""), limit=120)
        if not admin_words:
            admin_words = [
                "dashboard", "users", "settings", "config", "logs", "reports",
                "analytics", "backup", "restore", "import", "export", "api",
                "system", "security", "roles", "permissions", "audit", "jobs",
                "queue", "cache", "database", "sql", "console", "terminal",
            ]
        with open(wordlist_path, "w", encoding="utf-8") as f:
            f.write("\n".join(admin_words))
    else:
        # Use standard wordlist
        wordlist_path = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist_path):
            local_common = WORDLIST_PATHS.get("common")
            if local_common and os.path.exists(local_common):
                wordlist_path = local_common
            else:
                wordlist_path = "/tmp/common-wordlist.txt"
                common_words = [
                    "admin", "api", "backup", "config", "dashboard", "data", "db",
                    "debug", "docs", "download", "files", "login", "logs", "private",
                    "public", "secret", "test", "tmp", "upload", "users", "static",
                    "assets", "images", "css", "js", "fonts", "media", "content",
                ]
                with open(wordlist_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(common_words))

    # Build fuzz URL
    fuzz_url = urllib.parse.urljoin(base_url, f"{path.rstrip('/')}/FUZZ")

    cmd = [
        "ffuf", "-u", fuzz_url,
        "-w", wordlist_path,
        "-mc", "200,201,204,301,302,307,401,403",
        "-t", "10",
        "-timeout", "8",
        "-sf",
        "-o", f"/tmp/ffuf_{hashlib.md5(path.encode()).hexdigest()[:8]}.json",
        "-of", "json",
    ]

    out, err, rc = await run(cmd, timeout=timeout)

    output_file = f"/tmp/ffuf_{hashlib.md5(path.encode()).hexdigest()[:8]}.json"
    if rc == 0 and os.path.exists(output_file):
        try:
            with open(output_file) as f:
                ffuf_data = json.load(f)
                for result in ffuf_data.get("results", []):
                    found_path = result.get("input", {}).get("FUZZ", "")
                    if found_path:
                        full_path = f"{path.rstrip('/')}/{found_path}"
                        discovered.append(full_path)
        except Exception:
            pass
        finally:
            try:
                os.remove(output_file)
            except Exception:
                pass

    return discovered


def _prioritize_paths(paths: list[str], signals: dict | None = None) -> list[str]:
    """
    Sort paths by vulnerability likelihood for recursive fuzzing.
    Higher score = fuzz first.
    """
    signals = signals or {}

    def score(path: str) -> int:
        s = 0
        path_lower = path.lower()

        # High-value directories
        if any(x in path_lower for x in ["/api/", "/rest/", "/graphql"]):
            s += 5
        if any(x in path_lower for x in ["/admin/", "/administrator/"]):
            s += 4
        if any(x in path_lower for x in ["/user", "/account", "/profile", "/auth"]):
            s += 3
        if any(x in path_lower for x in ["/search", "/query", "/filter"]):
            s += 3
        if any(x in path_lower for x in ["/upload", "/file", "/download"]):
            s += 2
        if any(x in path_lower for x in ["/config", "/settings", "/debug"]):
            s += 2

        # Boost based on signals
        if signals.get("sql_errors") and any(x in path_lower for x in ["db", "sql", "query"]):
            s += 2
        if signals.get("auth_issues") and any(x in path_lower for x in ["auth", "login", "user"]):
            s += 2

        return s

    return sorted(paths, key=score, reverse=True)


def _is_interesting_path(path: str) -> bool:
    """Filter for paths worth exploring further."""
    # Skip static assets
    static_ext = [".css", ".js", ".png", ".jpg", ".gif", ".ico", ".woff", ".svg", ".map"]
    if any(path.lower().endswith(ext) for ext in static_ext):
        return False

    # Keep interesting patterns
    interesting = [
        "/api", "/rest", "/admin", "/user", "/auth", "/search",
        "/upload", "/file", "/download", "/export", "/import",
        "/config", "/settings", "/debug", "/backup", "/data",
    ]

    # Keep directories and interesting endpoints
    return path.endswith("/") or any(x in path.lower() for x in interesting)


async def recursive_directory_discovery(
    base_url: str,
    initial_paths: list[str],
    signals: dict | None = None,
    max_depth: int = 3,
    max_paths_per_level: int = 20
) -> dict[str, Any]:
    """
    Recursively discover directories by fuzzing at each level.

    Args:
        base_url: Target base URL
        initial_paths: Starting paths to explore (directories ending with /)
        signals: Signals from earlier scan phases (affects prioritization)
        max_depth: Maximum recursion depth
        max_paths_per_level: Max paths to fuzz per depth level

    Returns:
        Dict with all discovered paths and stats
    """
    signals = signals or {}

    all_paths: list[str] = list(initial_paths)
    current_level = [p for p in initial_paths if p.endswith("/") and _is_interesting_path(p)]

    stats = {
        "depth_reached": 0,
        "paths_per_level": [],
        "total_fuzz_calls": 0,
    }

    print(f"[discovery] Starting recursive fuzzing from {len(current_level)} directories (max_depth={max_depth})", file=sys.stderr)

    for depth in range(max_depth):
        if not current_level:
            break

        stats["depth_reached"] = depth + 1
        next_level: list[str] = []

        # Prioritize paths by vulnerability likelihood
        priority_paths = _prioritize_paths(current_level, signals)[:max_paths_per_level]

        print(f"[discovery] Depth {depth + 1}: Fuzzing {len(priority_paths)} directories", file=sys.stderr)

        for dir_path in priority_paths:
            discovered = await _run_ffuf_on_path(base_url, dir_path, timeout=45)
            stats["total_fuzz_calls"] += 1

            for path in discovered:
                if path not in all_paths:
                    all_paths.append(path)
                    # Add directories to next level for recursive fuzzing
                    if path.endswith("/") and _is_interesting_path(path):
                        next_level.append(path)

        stats["paths_per_level"].append({
            "depth": depth + 1,
            "directories_fuzzed": len(priority_paths),
            "paths_found": len(next_level),
        })

        current_level = next_level

    print(f"[discovery] Recursive fuzzing complete: {len(all_paths)} total paths, depth {stats['depth_reached']}", file=sys.stderr)

    return {
        "paths": list(set(all_paths)),
        "stats": stats,
    }


async def analyze_js_bundles(base_url: str, js_urls: list[str], max_bundles: int = 20) -> dict:
    """
    Extract hidden endpoints and routes from JavaScript bundles.

    Analyzes JS files for:
    - API endpoint patterns (fetch, axios, etc.)
    - Route definitions (React Router, Vue Router, etc.)
    - GraphQL operations
    - WebSocket URLs

    Args:
        base_url: Target base URL for resolving relative paths
        js_urls: List of JavaScript file URLs to analyze
        max_bundles: Maximum number of JS files to analyze

    Returns:
        Dict with discovered endpoints, routes, and other patterns
    """
    findings = {
        "api_endpoints": [],
        "routes": [],
        "graphql_ops": [],
        "websocket_urls": [],
        "internal_urls": [],
        "discovered_api_bases": [],
        "analyzed_count": 0,
    }

    # Patterns for API endpoint extraction
    api_patterns = [
        # === HTTP client patterns ===
        r'''fetch\s*\(\s*['"`](/[^'"`\s]+)['"`]''',  # fetch('/api/...')
        r'''axios\.[a-z]+\s*\(\s*['"`](/[^'"`\s]+)['"`]''',  # axios.get('/api/...')
        r'''\.(?:get|post|put|delete|patch)\s*\(\s*['"`](/[^'"`\s]+)['"`]''',  # .get('/...')
        r'''baseURL\s*[+:]\s*['"`](/[^'"`\s]+)['"`]''',  # baseURL + '/path'
        r'''\$http\.[a-z]+\s*\(\s*['"`](/[^'"`\s]+)['"`]''',  # Angular $http.get('/...')
        r'''HttpClient\.[a-z]+\s*\(\s*['"`](/[^'"`\s]+)['"`]''',  # Angular HttpClient
        r'''request\s*\(\s*['"`](/[^'"`\s]+)['"`]''',  # request('/api/...')

        # === With leading slash (traditional) ===
        r'''['"](\/api\/[^'"]+)['"]''',  # '/api/users'
        r'''['"](\/v[0-9]+\/[^'"]+)['"]''',  # '/v1/users'
        r'''['"](\/rest\/[^'"]+)['"]''',  # '/rest/products'
        r'''['"](\/graphql[^'"]*)['"]''',  # '/graphql'
        r'''['"](\/gql[^'"]*)['"]''',  # '/gql'

        # === Without leading slash (React/modern SPAs) ===
        r'''['"`](api\/[^'"`]+)['"`]''',  # 'api/users'
        r'''['"`](v[0-9]+\/[^'"`]+)['"`]''',  # 'v1/users'
        r'''['"`](rest\/[^'"`]+)['"`]''',  # 'rest/products'
        r'''['"`](graphql[^'"`]*)['"`]''',  # 'graphql'

        # === Authentication/OAuth endpoints (capture group excludes quotes) ===
        r'''['"`](\/?(?:auth|oauth|oauth2|sso|saml|login|logout|signin|signup|register|token|session|verify|reset-password|forgot-password|2fa|mfa)(?:\/[^'"`]*)?)['"`]''',

        # === User/Account patterns ===
        r'''['"`](\/?(?:user|users|account|accounts|profile|me|member|members|customer|customers)(?:\/[^'"`]*)?)['"`]''',

        # === Admin/Management patterns ===
        r'''['"`](\/?(?:admin|management|console|dashboard|portal|backoffice|cms|control)(?:\/[^'"`]*)?)['"`]''',
        r'''['"`](\/?(?:actuator|health|metrics|status|info|env)(?:\/[^'"`]*)?)['"`]''',  # Spring Boot actuator

        # === Internal/Backend patterns ===
        r'''['"`](\/?(?:_api|_internal|internal|backend|bff|private|secure|service|services|svc|srv)(?:\/[^'"`]*)?)['"`]''',

        # === Data/CRUD patterns ===
        r'''['"`](\/?(?:data|query|search|filter|crud|resource|resources|entity|entities|objects|items)(?:\/[^'"`]*)?)['"`]''',

        # === File/Upload patterns (often vulnerable) ===
        r'''['"`](\/?(?:upload|uploads|download|downloads|file|files|media|assets|images|documents|attachments|storage)(?:\/[^'"`]*)?)['"`]''',

        # === Webhook/Integration patterns ===
        r'''['"`](\/?(?:webhook|webhooks|hooks|callback|callbacks|integration|integrations|connect|connector|events)(?:\/[^'"`]*)?)['"`]''',

        # === Payment/Commerce (sensitive) ===
        r'''['"`](\/?(?:payment|payments|checkout|cart|order|orders|billing|invoice|stripe|paypal|transaction)(?:\/[^'"`]*)?)['"`]''',

        # === Communication patterns ===
        r'''['"`](\/?(?:notification|notifications|email|sms|push|alert|message|messages|chat|socket)(?:\/[^'"`]*)?)['"`]''',

        # === Reporting/Analytics ===
        r'''['"`](\/?(?:report|reports|analytics|stats|statistics|metrics|logs|audit|export)(?:\/[^'"`]*)?)['"`]''',

        # === Gateway/Proxy patterns ===
        r'''['"`](\/?(?:gateway|proxy|forward|redirect|route|router|dispatch)(?:\/[^'"`]*)?)['"`]''',

        # === RPC patterns ===
        r'''['"`](\/?(?:rpc|jsonrpc|xmlrpc|grpc|action|method|procedure|call|invoke)(?:\/[^'"`]*)?)['"`]''',

        # === Mobile/Client patterns ===
        r'''['"`](\/?(?:mobile|app|ios|android|client|clients|device|devices)(?:\/[^'"`]*)?)['"`]''',

        # === Common vulnerable endpoints ===
        r'''['"`](\/?(?:debug|test|dev|staging|beta|preview|sandbox|demo)(?:\/[^'"`]*)?)['"`]''',
        r'''['"`](\/?(?:config|configuration|settings|preferences|options)(?:\/[^'"`]*)?)['"`]''',
        r'''['"`](\/?(?:import|export|backup|restore|sync|migrate)(?:\/[^'"`]*)?)['"`]''',

        # === ID/lookup patterns (injection targets) ===
        r'''['"`]([^'"`]*(?:\/id\/|\/user_id\/|\/userId\/|\/account_id\/|\?id=|\?user=|\?account=)[^'"`]*)['"`]''',
    ]

    # Patterns for route definitions
    route_patterns = [
        # React Router
        r'''path\s*:\s*['"`](/[^'"`]+)['"`]''',  # path: '/users'
        r'''<Route[^>]+path\s*=\s*['"`](/[^'"`]+)['"`]''',  # <Route path="/users"
        r'''to\s*=\s*['"`](/[^'"`]+)['"`]''',  # to="/users"
        r'''navigate\s*\(\s*['"`](/[^'"`]+)['"`]''',  # navigate('/users')
        r'''useNavigate\s*\(\s*\)\s*\(\s*['"`](/[^'"`]+)['"`]''',  # useNavigate()('/users')
        # Vue Router
        r'''router\.push\s*\(\s*['"`](/[^'"`]+)['"`]''',  # router.push('/users')
        r'''router\.replace\s*\(\s*['"`](/[^'"`]+)['"`]''',  # router.replace('/users')
        r'''\$router\.push\s*\(\s*['"`](/[^'"`]+)['"`]''',  # Vue $router.push
        # Angular Router
        r'''routerLink\s*=\s*['"`](/[^'"`]+)['"`]''',  # routerLink="/users"
        r'''router\.navigate\s*\(\s*\[\s*['"`](/[^'"`]+)['"`]''',  # router.navigate(['/users'])
        # Next.js / general
        r'''href\s*=\s*['"`](/[^'"`]+)['"`]''',  # href="/users"
        r'''Link\s+href\s*=\s*['"`](/[^'"`]+)['"`]''',  # <Link href="/users"
        r'''redirect\s*\(\s*['"`](/[^'"`]+)['"`]''',  # redirect('/users')
        # Dynamic routes with params
        r'''path\s*:\s*['"`](/[^'"`]*:[^'"`]+)['"`]''',  # path: '/users/:id'
        r'''['"`](/[^'"`]*\{[^}]+\}[^'"`]*)['"`]''',  # '/users/{id}'
    ]

    # Template literal patterns (very common in modern JS)
    template_patterns = [
        r'''`/[^`]*\$\{[^}]+\}[^`]*`''',  # `/api/users/${id}`
        r'''`[^`]*api[^`]*\$\{[^}]+\}[^`]*`''',  # `${base}api/users`
    ]

    # Patterns to detect API base URL constants/config
    base_url_patterns = [
        # Common constant names (SCREAMING_SNAKE_CASE)
        r'''(?:API_URL|API_BASE|API_ENDPOINT|API_HOST|BASE_URL|BASE_API|API_ROOT|API_PREFIX)\s*[=:]\s*['"`]([^'"`]+)['"`]''',
        # Common constant names (camelCase)
        r'''(?:apiUrl|apiBase|apiEndpoint|baseUrl|baseAPI|apiRoot|apiPrefix)\s*[=:]\s*['"`]([^'"`]+)['"`]''',
        # Axios/fetch config
        r'''baseURL\s*[=:]\s*['"`]([^'"`]+)['"`]''',  # Full URL capture
        r'''defaults\.baseURL\s*=\s*['"`]([^'"`]+)['"`]''',
        r'''axios\.defaults\.baseURL\s*=\s*['"`]([^'"`]+)['"`]''',
        # Environment variable patterns with fallbacks
        r'''process\.env\.(?:REACT_APP_|NEXT_PUBLIC_)?(?:API_URL|API_BASE|BASE_URL)\s*\|\|\s*['"`]([^'"`]+)['"`]''',
        r'''import\.meta\.env\.(?:VITE_)?(?:API_URL|API_BASE|BASE_URL)\s*(?:\?\?|\|\|)\s*['"`]([^'"`]+)['"`]''',
        # Angular environment files
        r'''(?:apiUrl|baseUrl|apiEndpoint)\s*:\s*['"`]([^'"`]+)['"`]''',
        # Create client/instance patterns
        r'''\.create\s*\(\s*\{\s*baseURL\s*:\s*['"`]([^'"`]+)['"`]''',  # axios.create({baseURL: '...'})
    ]

    # Patterns for GraphQL
    graphql_patterns = [
        r'''(?:query|mutation|subscription)\s+(\w+)''',  # query GetUsers
        r'''gql\s*`[^`]*(?:query|mutation)\s+(\w+)''',  # gql`query GetUsers`
    ]

    # Patterns for WebSocket
    ws_patterns = [
        r'''(?:ws|wss)://[^'"`\s]+''',  # wss://example.com/ws
        r'''WebSocket\s*\(\s*['"`]([^'"`]+)['"`]''',  # new WebSocket('ws://...')
    ]

    # URL patterns for internal endpoints
    url_patterns = [
        r'''['"]((https?:)?//[^'"`\s]+)['"]''',  # Full URLs
    ]

    parsed_base = urllib.parse.urlparse(base_url)
    base_domain = parsed_base.netloc

    for js_url in js_urls[:max_bundles]:
        try:
            # Fetch JS content
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
                resp = await client.get(js_url)
                if resp.status_code != 200:
                    continue
                content = resp.text

            findings["analyzed_count"] += 1

            # Extract API endpoints
            for pattern in api_patterns:
                matches = re.findall(pattern, content)
                findings["api_endpoints"].extend(matches)

            # Extract routes
            for pattern in route_patterns:
                matches = re.findall(pattern, content)
                findings["routes"].extend(matches)

            # Extract template literal URLs (convert to base paths for testing)
            for pattern in template_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    # Extract base path before ${} variable
                    base_path = re.sub(r'\$\{[^}]+\}.*', '', match)
                    base_path = base_path.strip('`').rstrip('/')
                    if base_path and len(base_path) > 1:
                        findings["api_endpoints"].append(base_path)

            # Extract GraphQL operations
            for pattern in graphql_patterns:
                matches = re.findall(pattern, content)
                findings["graphql_ops"].extend(matches)

            # Extract WebSocket URLs
            for pattern in ws_patterns:
                matches = re.findall(pattern, content)
                findings["websocket_urls"].extend(matches)

            # Extract internal URLs (same domain)
            for pattern in url_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    url = match[0] if isinstance(match, tuple) else match
                    if base_domain in url or url.startswith("/"):
                        findings["internal_urls"].append(url)

            # Extract API base URL constants/config
            for pattern in base_url_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    base = match if isinstance(match, str) else (match[0] if match else "")
                    base = base.strip("'\"` ")
                    if base and len(base) > 1:
                        # Only keep paths starting with / or full URLs for same domain
                        if base.startswith("/"):
                            findings["discovered_api_bases"].append(base)
                        elif base_domain in base:
                            # Extract path from full URL
                            try:
                                parsed = urllib.parse.urlparse(base)
                                if parsed.path and parsed.path != "/":
                                    findings["discovered_api_bases"].append(parsed.path)
                            except Exception:
                                pass

        except Exception as e:
            print(f"[discovery] JS analysis error for {js_url}: {e}", file=sys.stderr)
            continue

    # Deduplicate and clean results - normalize paths
    def normalize_path(p):
        """Strip quotes and normalize path."""
        if isinstance(p, tuple):
            p = p[0] if p else ""
        p = str(p).strip("'\"` ")
        # Skip empty or too short
        if not p or len(p) < 2 or p in ("/", "//"):
            return None
        return p

    findings["api_endpoints"] = list(set(filter(None, map(normalize_path, findings["api_endpoints"]))))
    findings["routes"] = list(set(filter(None, map(normalize_path, findings["routes"]))))
    findings["graphql_ops"] = list(set(findings["graphql_ops"]))
    findings["websocket_urls"] = list(set(findings["websocket_urls"]))
    findings["internal_urls"] = list(set(filter(None, map(normalize_path, findings["internal_urls"]))))
    findings["discovered_api_bases"] = list(set(filter(None, map(normalize_path, findings["discovered_api_bases"]))))

    # Prepend discovered API bases to relative endpoints to create combined paths
    # This helps find endpoints like /community/api/v2/... when JS only has /api/v2/...
    if findings["discovered_api_bases"]:
        combined_endpoints = set(findings["api_endpoints"])
        for base in findings["discovered_api_bases"]:
            base = base.rstrip("/")
            for endpoint in findings["api_endpoints"]:
                if endpoint.startswith("/") and not endpoint.startswith(base):
                    # Combine base + endpoint (e.g., /community + /api/v2/users)
                    combined = base + endpoint
                    combined_endpoints.add(combined)
                    # Also try with common API path segments
                    if endpoint.startswith("/api/") or endpoint.startswith("/v"):
                        combined_endpoints.add(combined)
        findings["api_endpoints"] = list(combined_endpoints)

        print(f"[discovery]   Discovered API bases: {findings['discovered_api_bases']}", file=sys.stderr)

    total_found = (
        len(findings["api_endpoints"]) +
        len(findings["routes"]) +
        len(findings["graphql_ops"]) +
        len(findings["websocket_urls"])
    )

    if total_found > 0:
        print(f"[discovery] JS bundle analysis: {total_found} patterns from {findings['analyzed_count']} files", file=sys.stderr)
        print(f"[discovery]   API endpoints: {len(findings['api_endpoints'])}, Routes: {len(findings['routes'])}", file=sys.stderr)

    return findings


async def smart_discovery(
    url: str,
    signals: dict | None = None,
    scan_type: str = "smart"
) -> dict[str, Any]:
    """
    Smart discovery combining enhanced URL discovery with recursive fuzzing.

    This is the main entry point for --smart scan discovery phase.

    Args:
        url: Target URL
        signals: Signals from nuclei/earlier phases
        scan_type: Scan type for config

    Returns:
        Comprehensive discovery results
    """
    signals = signals or {}

    # Start with enhanced URL discovery
    print(f"[discovery] Phase 1: Enhanced URL discovery", file=sys.stderr)
    initial_discovery = await enhanced_url_discovery(url, scan_type=scan_type)

    # Get initial directories for recursive fuzzing
    all_urls = initial_discovery.get("all_urls", [])
    directories = [u for u in all_urls if u.endswith("/")]

    # Also get API base paths
    api_endpoints = initial_discovery.get("api_endpoints", [])
    api_bases = set()
    for endpoint in api_endpoints:
        parsed = urllib.parse.urlparse(endpoint)
        path_parts = parsed.path.split("/")
        if len(path_parts) >= 2:
            api_base = "/".join(path_parts[:3]) + "/"
            if api_base != "/":
                api_bases.add(api_base)

    directories.extend(list(api_bases))
    if not directories:
        directories = [
            "/api/",
            "/api/v1/",
            "/api/v2/",
            "/api/v3/",
            "/v1/",
            "/v2/",
            "/v3/",
            "/rest/",
            "/rest/v1/",
            "/rest/v2/",
        ]
    directories = list(set(directories))

    # Phase 2: Recursive fuzzing
    print(f"[discovery] Phase 2: Recursive directory fuzzing ({len(directories)} base directories)", file=sys.stderr)
    recursive_result = await recursive_directory_discovery(
        url,
        directories,
        signals=signals,
        max_depth=3,
        max_paths_per_level=15
    )

    # Merge results and apply URL cap from config
    config = initial_discovery.get("config", {})
    max_urls = config.get("max_urls", 1000)
    recursive_paths = [
        urllib.parse.urljoin(url, p) for p in (recursive_result.get("paths", []) or [])
    ]
    recursive_paths = sorted(set(recursive_paths))
    all_paths = sorted(set(all_urls + recursive_paths))

    # Prioritize high-value endpoints before capping: API, parameterized, then others
    if len(all_paths) > max_urls:
        def url_priority(url: str) -> tuple:
            # Lower tuple = higher priority (sorted first)
            has_params = "?" in url
            is_api = any(p in url.lower() for p in ["/api/", "/rest/", "/graphql", "/v1/", "/v2/"])
            return (0 if is_api else 1, 0 if has_params else 1, url)
        all_paths = sorted(all_paths, key=url_priority)[:max_urls]

    # Extract endpoints with params
    endpoints_with_params = []
    for path in all_paths:
        if "?" in path:
            parsed = urllib.parse.urlparse(path)
            params = list(urllib.parse.parse_qs(parsed.query).keys())
            endpoints_with_params.append({
                "url": path,
                "params": params,
            })
        else:
            # Infer params from path pattern
            inferred_params = []
            path_lower = path.lower()
            if any(x in path_lower for x in ["/search", "/query"]):
                inferred_params = ["q", "query", "search"]
            elif any(x in path_lower for x in ["/user", "/profile"]):
                inferred_params = ["id", "user", "username"]
            elif any(x in path_lower for x in ["/product", "/item"]):
                inferred_params = ["id", "product_id", "sku"]
            elif "/api/" in path_lower:
                inferred_params = ["id", "token", "limit", "offset"]

            if inferred_params:
                endpoints_with_params.append({
                    "url": path,
                    "params": inferred_params,
                    "inferred": True,
                })

    return {
        "all_urls": all_paths,
        "api_endpoints": list(set(api_endpoints + [p for p in all_paths if "/api/" in p or "/rest/" in p])),
        "parameterized_urls": initial_discovery.get("parameterized_urls", []),
        "endpoints_with_params": endpoints_with_params,
        "forms": initial_discovery.get("forms", []),
        "discovered_params": initial_discovery.get("discovered_params", {}),
        "recursive_paths": recursive_paths,
        "stats": recursive_result.get("stats", {}),
        "config": initial_discovery.get("config", {}),
        "js_bundle_analysis": initial_discovery.get("js_bundle_analysis"),
        "signals_used": signals,
        "tech_stack_guess": [],  # Populated by browser/httpx in main scanner
    }
