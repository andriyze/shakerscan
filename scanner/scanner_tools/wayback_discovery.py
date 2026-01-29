"""
Wayback URL Discovery Module

Collects historical URLs from Wayback Machine, Common Crawl, and other sources.
Useful for discovering:
- Removed endpoints that may still be accessible
- Historical parameters that could be vulnerable
- Backup files and sensitive documents
- Changes in API structure over time
"""

import asyncio
import json
import os
import re
import sys
import urllib.parse
from typing import Any

from .common import run


# File extensions that are particularly interesting for security testing
INTERESTING_EXTENSIONS = {
    # Config/env files
    ".env", ".config", ".cfg", ".ini", ".conf", ".yml", ".yaml", ".toml",
    # Backup files
    ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp",
    # Database files
    ".sql", ".db", ".sqlite", ".mdb", ".dump",
    # Source code
    ".py", ".php", ".asp", ".aspx", ".jsp", ".java", ".rb", ".pl",
    # Archives
    ".zip", ".tar", ".gz", ".rar", ".7z", ".tgz",
    # Documents that may contain sensitive info
    ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".txt", ".log",
    # API specs
    ".json", ".xml", ".wsdl",
}

# Patterns that indicate potentially sensitive URLs
SENSITIVE_PATTERNS = [
    r"/admin",
    r"/api/",
    r"/v[123]/",
    r"/internal",
    r"/debug",
    r"/backup",
    r"/config",
    r"/\.env",
    r"/\.git",
    r"/\.htaccess",
    r"/phpinfo",
    r"/server-status",
    r"/wp-config",
    r"/web\.config",
    r"\?.*password",
    r"\?.*token",
    r"\?.*key",
    r"\?.*secret",
    r"\?.*auth",
    r"\?.*api_key",
    r"\?.*apikey",
    r"/swagger",
    r"/graphql",
    r"/\.well-known",
]


async def fetch_wayback_urls(
    domain: str,
    timeout: int = 60,
    collapse: bool = True,
) -> list[str]:
    """
    Fetch historical URLs from Wayback Machine CDX API.

    Args:
        domain: Target domain
        timeout: Request timeout in seconds
        collapse: Collapse similar URLs to reduce duplicates

    Returns:
        List of unique historical URLs.
    """
    urls: set[str] = set()

    # Wayback Machine CDX API
    cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    if not collapse:
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original"

    cmd = [
        "curl", "-sS", "-L", "--max-time", str(timeout),
        "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        cdx_url,
    ]

    out, err, rc = await run(cmd, timeout=timeout + 10)

    if rc == 0 and out:
        try:
            data = json.loads(out)
            # Skip header row
            for row in data[1:]:
                if row and isinstance(row, list) and row[0]:
                    urls.add(row[0])
        except json.JSONDecodeError:
            # CDX might return newline-separated URLs instead
            for line in out.splitlines():
                line = line.strip()
                if line and line.startswith("http"):
                    urls.add(line)

    return list(urls)


async def fetch_common_crawl_urls(
    domain: str,
    timeout: int = 60,
    index: str = "CC-MAIN-2024-10",
) -> list[str]:
    """
    Fetch URLs from Common Crawl index.

    Args:
        domain: Target domain
        timeout: Request timeout in seconds
        index: Common Crawl index to query

    Returns:
        List of unique URLs from Common Crawl.
    """
    urls: set[str] = set()

    # Common Crawl Index API
    cc_url = f"https://index.commoncrawl.org/{index}-index?url=*.{domain}&output=json"

    cmd = [
        "curl", "-sS", "-L", "--max-time", str(timeout),
        "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        cc_url,
    ]

    out, err, rc = await run(cmd, timeout=timeout + 10)

    if rc == 0 and out:
        for line in out.splitlines():
            try:
                data = json.loads(line)
                if "url" in data:
                    urls.add(data["url"])
            except json.JSONDecodeError:
                continue

    return list(urls)


async def fetch_gau_urls(
    domain: str,
    timeout: int = 120,
    providers: list[str] | None = None,
) -> list[str]:
    """
    Fetch URLs using gau (GetAllUrls) if installed.

    gau combines Wayback, Common Crawl, AlienVault, and URLScan.

    Args:
        domain: Target domain
        timeout: Request timeout in seconds
        providers: List of providers to use (wayback, commoncrawl, otx, urlscan)

    Returns:
        List of unique URLs from gau.
    """
    urls: set[str] = set()

    # Check if gau is installed
    gau_path = "/opt/tools/gau" if os.path.exists("/opt/tools/gau") else "gau"

    cmd = [gau_path, domain, "--timeout", str(timeout)]

    if providers:
        cmd.extend(["--providers", ",".join(providers)])

    out, err, rc = await run(cmd, timeout=timeout + 30)

    if rc == 0 and out:
        for line in out.splitlines():
            line = line.strip()
            if line and line.startswith("http"):
                urls.add(line)

    return list(urls)


async def fetch_waybackurls(
    domain: str,
    timeout: int = 60,
) -> list[str]:
    """
    Fetch URLs using waybackurls if installed.

    Args:
        domain: Target domain
        timeout: Request timeout in seconds

    Returns:
        List of unique historical URLs.
    """
    urls: set[str] = set()

    # Check if waybackurls is installed
    wb_path = "/opt/tools/waybackurls" if os.path.exists("/opt/tools/waybackurls") else "waybackurls"

    # Pass domain via stdin to avoid command injection
    # Domain is passed as input_text, not interpolated into shell command
    cmd = [wb_path]

    out, err, rc = await run(cmd, timeout=timeout + 10, input_text=f"{domain}\n")

    if rc == 0 and out:
        for line in out.splitlines():
            line = line.strip()
            if line and line.startswith("http"):
                urls.add(line)

    return list(urls)


def filter_interesting_urls(urls: list[str]) -> dict[str, list[str]]:
    """
    Filter and categorize URLs by their security relevance.

    Args:
        urls: List of URLs to filter

    Returns:
        Dict with categorized URLs.
    """
    result: dict[str, list[str]] = {
        "sensitive_files": [],
        "backup_files": [],
        "config_files": [],
        "api_endpoints": [],
        "parameters": [],
        "admin_panels": [],
        "other": [],
    }

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        query = parsed.query

        # Get extension
        ext = os.path.splitext(path)[1].lower()

        # Check for backup files
        if ext in {".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp"}:
            result["backup_files"].append(url)
            continue

        # Check for config files
        if ext in {".env", ".config", ".cfg", ".ini", ".conf", ".yml", ".yaml", ".toml"}:
            result["config_files"].append(url)
            continue

        # Check for sensitive patterns
        is_sensitive = False
        for pattern in SENSITIVE_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                is_sensitive = True
                break

        if is_sensitive:
            if "/admin" in path or "/cpanel" in path or "/wp-admin" in path:
                result["admin_panels"].append(url)
            else:
                result["sensitive_files"].append(url)
            continue

        # Check for API endpoints
        if any(p in path for p in ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql"]):
            result["api_endpoints"].append(url)
            continue

        # Check for URLs with parameters (valuable for injection testing)
        if query:
            result["parameters"].append(url)
            continue

        result["other"].append(url)

    return result


def extract_parameters(urls: list[str]) -> dict[str, set[str]]:
    """
    Extract all unique parameters from a list of URLs.

    Args:
        urls: List of URLs

    Returns:
        Dict mapping parameter names to sample values.
    """
    params: dict[str, set[str]] = {}

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        for name, values in query_params.items():
            if name not in params:
                params[name] = set()
            params[name].update(values)

    return params


def extract_endpoints(urls: list[str], base_domain: str) -> list[str]:
    """
    Extract unique endpoint paths from URLs.

    Args:
        urls: List of URLs
        base_domain: Base domain to filter by

    Returns:
        List of unique endpoint paths.
    """
    endpoints: set[str] = set()

    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            netloc = (parsed.hostname or "").lower()
            base_lower = base_domain.lower().rstrip(".")

            # Only include URLs from the target domain (exact match or subdomain)
            # Prevents evil-example.com or notexample.com from matching example.com
            if not netloc or (netloc != base_lower and not netloc.endswith("." + base_lower)):
                continue

            path = parsed.path

            # Skip static resources
            ext = os.path.splitext(path)[1].lower()
            if ext in {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"}:
                continue

            endpoints.add(path)
        except Exception:
            continue

    return sorted(endpoints)


async def discover_wayback_urls(
    domain: str,
    use_gau: bool = True,
    use_wayback_api: bool = True,
    use_common_crawl: bool = False,
    timeout: int = 120,
    max_urls: int = 5000,
) -> dict[str, Any]:
    """
    Comprehensive historical URL discovery using multiple sources.

    Args:
        domain: Target domain
        use_gau: Use gau tool if available
        use_wayback_api: Use Wayback Machine CDX API
        use_common_crawl: Use Common Crawl (slower)
        timeout: Request timeout per source
        max_urls: Maximum total URLs to return

    Returns:
        Dict with discovered URLs, categories, and extracted parameters.
    """
    results: dict[str, Any] = {
        "domain": domain,
        "sources_used": [],
        "total_urls": 0,
        "urls": [],
        "categorized": {},
        "parameters_found": {},
        "endpoints": [],
        "errors": [],
    }

    all_urls: set[str] = set()

    # Try multiple sources concurrently using asyncio.gather
    source_configs = []

    if use_gau:
        source_configs.append(("gau", fetch_gau_urls(domain, timeout)))

    if use_wayback_api:
        source_configs.append(("wayback_api", fetch_wayback_urls(domain, timeout)))

    if use_common_crawl:
        source_configs.append(("common_crawl", fetch_common_crawl_urls(domain, timeout)))

    # Also try waybackurls as fallback
    source_configs.append(("waybackurls", fetch_waybackurls(domain, timeout)))

    print(f"[wayback] Fetching historical URLs for {domain} from {len(source_configs)} sources...", file=sys.stderr)

    # Execute all sources concurrently with individual error handling
    async def fetch_with_error_handling(source_name: str, coro):
        try:
            urls = await coro
            return (source_name, urls, None)
        except Exception as e:
            return (source_name, [], str(e))

    tasks = [fetch_with_error_handling(name, coro) for name, coro in source_configs]
    task_results = await asyncio.gather(*tasks)

    for source_name, urls, error in task_results:
        if error:
            results["errors"].append(f"{source_name}: {error}")
        elif urls:
            all_urls.update(urls)
            results["sources_used"].append(source_name)
            print(f"[wayback] {source_name}: found {len(urls)} URLs", file=sys.stderr)

    # Deduplicate and limit
    unique_urls = sorted(all_urls)[:max_urls]
    results["total_urls"] = len(unique_urls)
    results["urls"] = unique_urls

    # Categorize URLs
    results["categorized"] = filter_interesting_urls(unique_urls)

    # Extract parameters
    results["parameters_found"] = {
        name: list(values)[:10]  # Limit sample values
        for name, values in extract_parameters(unique_urls).items()
    }

    # Extract endpoints
    results["endpoints"] = extract_endpoints(unique_urls, domain)

    # Summary
    print(f"[wayback] Total unique URLs: {results['total_urls']}", file=sys.stderr)
    print(f"[wayback] Sensitive files: {len(results['categorized'].get('sensitive_files', []))}", file=sys.stderr)
    print(f"[wayback] Backup files: {len(results['categorized'].get('backup_files', []))}", file=sys.stderr)
    print(f"[wayback] Config files: {len(results['categorized'].get('config_files', []))}", file=sys.stderr)
    print(f"[wayback] API endpoints: {len(results['categorized'].get('api_endpoints', []))}", file=sys.stderr)
    print(f"[wayback] URLs with parameters: {len(results['categorized'].get('parameters', []))}", file=sys.stderr)
    print(f"[wayback] Unique parameters: {len(results['parameters_found'])}", file=sys.stderr)

    return results


async def verify_historical_urls(
    urls: list[str],
    timeout: float = 5.0,
    concurrency: int = 10,
    max_urls: int = 100,
) -> dict[str, Any]:
    """
    Verify if historical URLs are still accessible.

    Args:
        urls: List of URLs to verify
        timeout: Request timeout per URL
        concurrency: Maximum concurrent requests
        max_urls: Maximum URLs to verify

    Returns:
        Dict with accessible and inaccessible URLs.
    """
    results: dict[str, Any] = {
        "verified": 0,
        "accessible": [],
        "inaccessible": [],
        "redirected": [],
        "auth_required": [],
    }

    urls_to_verify = urls[:max_urls]
    sem = asyncio.Semaphore(concurrency)

    async def check_url(url: str) -> tuple[str, int | None, str | None]:
        async with sem:
            cmd = [
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}|%{redirect_url}",
                "-L", "-k", "--max-time", str(timeout),
                "-H", "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                url,
            ]
            out, err, rc = await run(cmd, timeout=int(timeout) + 5)

            if rc != 0:
                return url, None, None

            parts = out.strip().split("|")
            try:
                status = int(parts[0])
                redirect = parts[1] if len(parts) > 1 and parts[1] else None
                return url, status, redirect
            except (ValueError, IndexError):
                return url, None, None

    tasks = [check_url(url) for url in urls_to_verify]
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    for response in responses:
        if isinstance(response, Exception):
            continue

        url, status, redirect = response
        results["verified"] += 1

        if status is None:
            results["inaccessible"].append({"url": url, "reason": "connection_failed"})
        elif status in (200, 201, 202, 204):
            results["accessible"].append({"url": url, "status": status})
        elif status in (301, 302, 303, 307, 308):
            results["redirected"].append({"url": url, "status": status, "redirect": redirect})
        elif status in (401, 403):
            results["auth_required"].append({"url": url, "status": status})
        elif status == 404:
            results["inaccessible"].append({"url": url, "reason": "not_found", "status": status})
        else:
            results["inaccessible"].append({"url": url, "reason": f"status_{status}", "status": status})

    return results
