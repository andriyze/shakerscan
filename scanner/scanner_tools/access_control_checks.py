"""
Access Control Security Checks - Forced Browsing / Path Enumeration

This module implements forced browsing checks to detect accessible privileged
endpoints that should be protected (CWE-425, CWE-285).

OWASP: A01:2021 - Broken Access Control
CWE-425: Direct Request (Forced Browsing)
CWE-285: Improper Authorization

All functions follow async patterns and return structured dictionaries.
"""

import asyncio
import hashlib
from typing import Any
from urllib.parse import urljoin

from .common import run, detect_spa_catch_all, fetch_homepage_hash, is_same_as_homepage, _compute_content_hash

# =============================================================================
# CONTENT VALIDATION PATTERNS - Validate that responses match expected content
# =============================================================================
# Each category defines what SHOULD be in a valid response (not just HTTP 200)

CATEGORY_CONTENT_VALIDATORS = {
    "admin_panels": {
        # Admin panels should contain admin-specific UI elements
        "required_patterns": [
            "admin", "dashboard", "panel", "login", "sign in", "password",
            "username", "email", "authentication", "logout", "user", "settings",
            "configuration", "manage", "control", "admin panel", "cpanel",
        ],
        "min_matches": 1,
        "reject_if_html_generic": True,  # Reject if it's just a generic homepage
    },
    "api_endpoints": {
        # API endpoints should return JSON or contain API-specific content
        "expected_content_types": ["application/json", "application/xml", "text/xml"],
        "required_patterns": [
            '"', "{", "[", "swagger", "openapi", "graphql", "query", "mutation",
            "api", "endpoint", "docs", '"type":', '"data":', '"error":',
        ],
        "min_matches": 1,
        "reject_if_html_generic": True,
    },
    "management_consoles": {
        "required_patterns": [
            "console", "dashboard", "management", "admin", "login", "sign in",
            "authentication", "phpmyadmin", "database", "mysql", "postgres",
            "mongodb", "redis", "adminer", "pgadmin",
        ],
        "min_matches": 1,
        "reject_if_html_generic": True,
    },
    "debug_dev": {
        # Debug/dev endpoints should contain debug-specific content
        "required_patterns": [
            # Spring Boot Actuator specific
            "actuator", "health", "status", "beans", "mappings", "env",
            "configprops", "metrics", "prometheus", "heapdump",
            # phpinfo specific
            "php version", "configuration", "php variables", "php credits",
            # Generic debug
            "debug", "trace", "stack", "error", "exception", "log", "dump",
            # Vite/webpack dev server specific
            "@fs", "vite", "webpack", "hmr", "hot module", "socket",
            # Next.js dev
            "__nextjs", "__next",
            # Node.js debug
            "node", "process", "v8",
            # Kubernetes health
            '"healthy"', '"ready"', '"live"', "ok", "up",
        ],
        "min_matches": 1,
        "reject_if_html_generic": True,
        # These paths should NEVER return generic HTML app content
        "always_validate": True,
    },
    "sensitive_files": {
        # Sensitive files should NOT be HTML
        "reject_html_always": True,  # .env, .git/config, etc. should never be HTML
        "required_patterns": [
            # Git config
            "[core]", "[remote", "[branch", "repositoryformatversion",
            # Environment files
            "=", "export ", "DB_", "API_", "SECRET", "KEY", "PASSWORD",
            # Config files
            "<?php", "database", "host", "port", "user", "pass",
            "mysql", "postgres", "redis", "mongo",
            # YAML configs
            ":", "server:", "database:", "production:", "development:",
        ],
        "min_matches": 1,
    },
    "backup_files": {
        # Backup files should NOT be HTML
        "reject_html_always": True,
        "expected_content_types": [
            "application/zip", "application/x-tar", "application/gzip",
            "application/sql", "text/plain", "application/octet-stream",
        ],
        "required_patterns": [
            # SQL dumps
            "create table", "insert into", "drop table", "alter table",
            "-- mysql", "-- postgres", "pgdmp",
            # Archive headers
            "pk", "rar!", "7z",
        ],
        "min_matches": 1,
    },
    "user_management": {
        "required_patterns": [
            "user", "account", "profile", "member", "customer",
            "email", "name", "id", "password", "role",
            '"users"', '"accounts"', '"profiles"',
        ],
        "min_matches": 1,
        "reject_if_html_generic": True,
    },
    "logs_monitoring": {
        "reject_html_always": True,
        "expected_content_types": ["text/plain", "application/json"],
        "required_patterns": [
            # Log patterns
            "error", "warn", "info", "debug", "trace",
            "[", "]", "timestamp", "level", "message",
            "exception", "stack", "at ", "line",
        ],
        "min_matches": 1,
    },
    "cloud_metadata": {
        "reject_html_always": True,
        "required_patterns": [
            # AWS
            "aws_access_key", "aws_secret", "region", "s3",
            # Azure
            "azure", "subscription", "tenant",
            # GCP
            "gcp", "project", "service_account",
        ],
        "min_matches": 1,
    },
}

# HTML indicators for detecting generic web pages
HTML_GENERIC_INDICATORS = [
    "<!doctype html", "<html", "<head>", "<body>", "</html>",
    "<meta charset", "<title>", "<script", "<div", "<nav",
    "<header>", "<footer>", "<main>", "<article>",
]

# SPA framework indicators - if present, likely a catch-all route
SPA_FRAMEWORK_INDICATORS = [
    'id="root"',  # React
    'id="app"',   # Vue
    'id="__next"',  # Next.js
    'ng-app',     # Angular
    '__NEXT_DATA__',  # Next.js
    '__NUXT__',   # Nuxt.js
    'data-reactroot',
    'window.__INITIAL_STATE__',
    '<div id="root"></div>',
    '<div id="app"></div>',
]


def _is_generic_html_page(body: str) -> bool:
    """
    Check if response is a generic HTML page (likely homepage or SPA shell).

    Returns True if the body appears to be a generic webpage rather than
    the specific privileged content we're looking for.
    """
    if not body:
        return False

    body_lower = body.lower()[:5000]

    # Count HTML structural indicators
    html_matches = sum(1 for ind in HTML_GENERIC_INDICATORS if ind.lower() in body_lower)

    # If it has significant HTML structure, it's likely a webpage
    if html_matches >= 3:
        return True

    # Check for SPA framework indicators
    for spa_ind in SPA_FRAMEWORK_INDICATORS:
        if spa_ind.lower() in body_lower:
            return True

    return False


def _has_category_content(body: str, content_type: str, category: str) -> tuple[bool, str]:
    """
    Validate that response content matches what we expect for this category.

    Args:
        body: Response body
        content_type: Content-Type header
        category: Path category (admin_panels, debug_dev, etc.)

    Returns:
        (is_valid, reason)
    """
    if not body:
        return False, "empty_body"

    validator = CATEGORY_CONTENT_VALIDATORS.get(category)
    if not validator:
        # No validator defined - assume valid
        return True, "no_validator"

    body_lower = body.lower()[:5000]
    ct_lower = (content_type or "").lower()

    # Check if HTML should always be rejected for this category
    if validator.get("reject_html_always", False):
        if _is_generic_html_page(body):
            return False, "html_rejected_for_category"

    # Check expected content types
    expected_cts = validator.get("expected_content_types", [])
    if expected_cts:
        ct_match = any(ect in ct_lower for ect in expected_cts)
        if ct_match:
            return True, "content_type_match"
        # If content-type doesn't match and it's HTML, likely false positive
        if "text/html" in ct_lower and validator.get("reject_if_html_generic", False):
            if _is_generic_html_page(body):
                return False, "html_generic_rejected"

    # Check for required patterns
    patterns = validator.get("required_patterns", [])
    min_matches = validator.get("min_matches", 1)

    if patterns:
        matches = sum(1 for p in patterns if p.lower() in body_lower)
        if matches >= min_matches:
            return True, f"pattern_match_{matches}"

        # No pattern matches - check if it's generic HTML
        if validator.get("reject_if_html_generic", False) or validator.get("always_validate", False):
            if _is_generic_html_page(body):
                return False, "no_patterns_and_generic_html"

    # If we have patterns defined but didn't match any, it's likely a false positive
    if patterns and validator.get("always_validate", False):
        return False, "required_patterns_missing"

    return True, "default_pass"

# Paths that are intentionally public and should NOT be flagged as vulnerabilities
# These are legitimate public endpoints, not security issues
INTENTIONALLY_PUBLIC_PATHS = {
    # RFC 9116 - security.txt for vulnerability disclosure
    "/.well-known/security.txt",
    # Standard authentication endpoints - public by design
    "/signup", "/sign-up", "/register", "/registration", "/create-account",
    "/login", "/signin", "/sign-in", "/logout", "/signout", "/sign-out",
    "/forgot-password", "/reset-password", "/password-reset",
    # OAuth/OIDC standard endpoints - required to be public
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    # API documentation - often intentionally public
    "/api-docs", "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/redoc", "/docs", "/api/docs",
    # Health check endpoints - intentionally public for monitoring
    "/health", "/healthz", "/healthcheck", "/ready", "/readyz", "/live", "/livez",
    "/ping", "/status", "/_health",
    # Robots and sitemap - SEO standard
    "/robots.txt", "/sitemap.xml",
}

# Privileged paths to test - organized by category
PRIVILEGED_PATHS = {
    "admin_panels": [
        "/admin", "/admin/", "/administrator", "/administrator/",
        "/admin.php", "/admin.html", "/admin.asp", "/admin.aspx",
        "/wp-admin", "/wp-admin/", "/wp-login.php",
        "/admin/login", "/admin/login.php", "/admin/index.php",
        "/adminpanel", "/admincp", "/admin_area", "/admin-console",
        "/admin/dashboard", "/admin/home", "/admin/config",
        "/cpanel", "/controlpanel", "/backend", "/backoffice",
        "/siteadmin", "/webadmin", "/moderator", "/modcp",
        # Laravel admin tools
        "/nova", "/nova/login", "/horizon", "/horizon/dashboard",
        "/telescope", "/telescope/requests", "/pulse",
        # Django admin
        "/django-admin", "/admin/jsi18n/",
        # Rails admin
        "/rails/active_storage", "/rails/conductor", "/sidekiq",
    ],
    "api_endpoints": [
        "/api/admin", "/api/v1/admin", "/api/v2/admin", "/api/v3/admin",
        "/api/internal", "/api/private", "/api/management",
        "/api/users", "/api/user", "/api/accounts",
        "/api/config", "/api/settings", "/api/system",
        "/api/debug", "/api/test", "/api/dev",
        # GraphQL endpoints (expanded)
        "/graphql", "/graphiql", "/altair", "/playground",
        "/graphql/introspect", "/graphql/schema", "/__graphql",
        "/api/graphql", "/v1/graphql", "/query",
        # API documentation
        "/api-docs", "/swagger", "/swagger-ui", "/swagger.json",
        "/openapi.json", "/openapi.yaml", "/api/openapi",
        "/api/docs", "/redoc", "/api/explorer",
        # Well-known endpoints
        "/.well-known/openid-configuration", "/.well-known/security.txt",
        "/.well-known/jwks.json", "/.well-known/oauth-authorization-server",
    ],
    "management_consoles": [
        "/console", "/console/", "/dashboard", "/dashboard/",
        "/manager", "/manager/", "/management", "/management/",
        "/control", "/control-panel", "/portal", "/portal/",
        "/system", "/system/", "/settings", "/settings/",
        "/config", "/configuration", "/setup", "/install",
        "/phpmyadmin", "/pma", "/myadmin", "/mysql",
        "/adminer", "/adminer.php", "/pgadmin", "/mongodb",
    ],
    "debug_dev": [
        "/debug", "/debug/", "/test", "/test/", "/testing",
        "/dev", "/dev/", "/development", "/staging",
        "/phpinfo.php", "/info.php", "/php_info.php",
        "/server-status", "/server-info", "/.well-known/",
        "/trace", "/trace.axd", "/elmah.axd", "/elmah",
        # Spring Boot Actuator (expanded)
        "/actuator", "/actuator/health", "/actuator/env",
        "/actuator/mappings", "/actuator/beans", "/actuator/configprops",
        "/actuator/heapdump", "/actuator/threaddump", "/actuator/loggers",
        "/actuator/metrics", "/actuator/info", "/actuator/scheduledtasks",
        # Kubernetes/Container health endpoints
        "/healthz", "/readyz", "/livez",
        "/metrics", "/metrics/prometheus", "/prometheus", "/prometheus/metrics",
        "/health", "/healthcheck", "/ready", "/live", "/status", "/ping",
        # Node.js/Express debug
        "/_next/static", "/__nextjs_original-stack-frame",
        # Webpack/Vite dev
        "/__webpack_hmr", "/@vite/client", "/@fs/",
    ],
    "sensitive_files": [
        "/.git", "/.git/config", "/.git/HEAD",
        "/.svn", "/.svn/entries", "/.hg",
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/config.php", "/config.inc.php", "/configuration.php",
        "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
        "/settings.py", "/settings.pyc", "/local_settings.py",
        "/config.yml", "/config.yaml", "/config.json",
        "/database.yml", "/secrets.yml", "/credentials.json",
        "/web.config", "/applicationhost.config",
        "/.htaccess", "/.htpasswd", "/apache.conf",
        "/nginx.conf", "/httpd.conf",
    ],
    "backup_files": [
        "/backup", "/backup/", "/backups", "/backups/",
        "/db", "/db/", "/database", "/database/",
        "/sql", "/sql/", "/dump", "/dump/",
        "/export", "/export/", "/data", "/data/",
        "/archive", "/archives", "/old", "/bak",
        "/site.zip", "/backup.zip", "/backup.tar.gz",
        "/db.sql", "/database.sql", "/dump.sql",
        "/backup.sql", "/data.sql",
    ],
    "user_management": [
        "/users", "/users/", "/user", "/user/",
        "/accounts", "/accounts/", "/members", "/members/",
        "/customers", "/profiles", "/profile",
        "/user/admin", "/users/admin", "/user/list",
        "/user/all", "/users/all", "/users/export",
        "/register", "/signup", "/create-account",
    ],
    "logs_monitoring": [
        "/logs", "/logs/", "/log", "/log/",
        "/error_log", "/error.log", "/errors.log",
        "/access_log", "/access.log", "/debug.log",
        "/audit", "/audit/", "/audit.log",
        "/monitoring", "/monitor", "/apm",
        "/trace.log", "/app.log", "/application.log",
    ],
    "cloud_metadata": [
        # AWS metadata endpoint (only accessible from within AWS)
        # "/latest/meta-data/",  # Commented as it's usually blocked externally
        # Azure metadata endpoint
        # "/metadata/instance",  # Commented
        # These paths check for accidental exposure in app:
        "/.aws/credentials", "/.aws/config",
        "/aws-credentials", "/aws.json",
    ],
}


def get_all_paths() -> list[str]:
    """Flatten all privileged paths into a single list."""
    all_paths = []
    for category_paths in PRIVILEGED_PATHS.values():
        all_paths.extend(category_paths)
    return list(set(all_paths))  # Remove duplicates


def categorize_path(path: str) -> str:
    """Return the category for a given path."""
    for category, paths in PRIVILEGED_PATHS.items():
        if path in paths:
            return category
    return "unknown"


def determine_severity(status_code: int, category: str, path: str) -> str:
    """Determine finding severity based on status code and category."""
    # 200 OK = accessible (highest severity)
    if status_code == 200:
        if category in ["admin_panels", "sensitive_files", "debug_dev"]:
            return "critical"
        elif category in ["api_endpoints", "user_management", "management_consoles"] or category in ["backup_files", "logs_monitoring"]:
            return "high"
        else:
            return "medium"

    # 301/302 redirects = may indicate path exists
    if status_code in [301, 302, 307, 308]:
        return "info"

    # 401/403 = exists but protected (informational)
    if status_code in [401, 403]:
        return "info"

    return "info"


async def test_single_path(
    base_url: str,
    path: str,
    timeout: int = 10,
    homepage_hash: str | None = None
) -> dict[str, Any] | None:
    """
    Test a single path for accessibility.

    Args:
        base_url: Base URL to test
        path: Path to test (e.g., "/admin")
        timeout: Request timeout in seconds
        homepage_hash: Optional hash of homepage content for catch-all detection

    Returns None if path returns 404 or error.
    Returns finding dict if path is accessible or protected.
    """
    # Skip intentionally public paths - these are not vulnerabilities
    path_lower = path.lower().rstrip('/')
    if path_lower in INTENTIONALLY_PUBLIC_PATHS or path_lower + '/' in INTENTIONALLY_PUBLIC_PATHS:
        return None

    full_url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
    category = categorize_path(path)

    try:
        # Use HEAD request first for efficiency
        out, err, rc = await run(
            [
                "curl", "-sS", "-k", "-I",
                "--max-time", str(timeout),
                "-o", "/dev/null",
                "-w", "%{http_code}",
                "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                full_url
            ],
            timeout=timeout + 5
        )

        if rc != 0 or not out:
            return None

        try:
            status_code = int(out.strip())
        except ValueError:
            return None

        # Skip 404s and common error codes
        if status_code in [404, 500, 502, 503, 504, 0]:
            return None

        # Interesting status codes: 200, 301, 302, 401, 403, 405
        if status_code in [200, 301, 302, 307, 308, 401, 403, 405]:
            severity = determine_severity(status_code, category, path)

            finding = {
                "path": path,
                "url": full_url,
                "status_code": status_code,
                "category": category,
                "severity": severity,
                "accessible": status_code == 200,
                "protected": status_code in [401, 403],
                "redirects": status_code in [301, 302, 307, 308],
            }

            # For 200 responses, get more details and validate content
            if status_code == 200:
                # Do a quick GET to check content type, HTTP status, and content for false positive detection
                get_out, get_err, get_rc = await run(
                    [
                        "curl", "-sS", "-k", "-L",
                        "--max-time", str(timeout),
                        "-w", "\n---CURL_METADATA---\n%{http_code}|%{content_type}|%{size_download}",
                        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        full_url
                    ],
                    timeout=timeout + 5
                )

                if get_rc == 0 and get_out:
                    # Split response body from metadata
                    parts = get_out.split("---CURL_METADATA---")
                    body = parts[0] if len(parts) > 0 else ""
                    metadata = parts[1].strip() if len(parts) > 1 else ""

                    # Parse metadata (now includes http_code)
                    meta_parts = metadata.split('|')
                    if len(meta_parts) >= 3:
                        try:
                            get_status_code = int(meta_parts[0])
                        except ValueError:
                            get_status_code = 200
                        finding["content_type"] = meta_parts[1]
                        try:
                            finding["content_length"] = int(meta_parts[2])
                        except ValueError:
                            pass

                        # If GET returned auth error, it's not actually accessible
                        if get_status_code in [401, 403]:
                            finding["accessible"] = False
                            finding["protected"] = True
                            finding["severity"] = "info"
                            finding["get_status_code"] = get_status_code
                        elif get_status_code in [404, 500, 502, 503, 504]:
                            # GET failed - not accessible
                            finding["accessible"] = False
                            finding["severity"] = "info"
                            finding["get_status_code"] = get_status_code
                    elif len(meta_parts) == 2:
                        # Fallback for old format
                        finding["content_type"] = meta_parts[0]
                        try:
                            finding["content_length"] = int(meta_parts[1])
                        except ValueError:
                            pass

                    # False positive detection: check for error indicators in body
                    body_lower = body.lower()[:3000]  # Check first 3KB
                    false_positive_indicators = [
                        "404", "not found", "page not found", "file not found",
                        "does not exist", "doesn't exist", "cannot be found",
                        "no such", "invalid", "error 404", "page doesn't exist",
                        "resource not found", "the page you requested",
                        "page could not be found", "sorry, we couldn't find",
                    ]

                    is_soft_404 = any(indicator in body_lower for indicator in false_positive_indicators)

                    # ENHANCED: Homepage comparison for catch-all detection
                    # If response is same as homepage, it's a catch-all route (false positive)
                    if homepage_hash and body:
                        response_hash = _compute_content_hash(body)
                        if response_hash == homepage_hash:
                            is_soft_404 = True
                            finding["same_as_homepage"] = True

                    # ENHANCED: Category-based content validation
                    # Validate that the response actually contains content appropriate for this category
                    content_type = finding.get("content_type", "")
                    is_valid_content, validation_reason = _has_category_content(body, content_type, category)

                    if not is_valid_content:
                        # Content doesn't match what we expect for this category
                        is_soft_404 = True
                        finding["content_validation_failed"] = True
                        finding["validation_reason"] = validation_reason

                    # Legacy check: Also check if response is generic HTML when expecting a specific file
                    # SPAs often return their homepage/app shell for all paths
                    html_indicators = ["<!doctype", "<html", "<head>", "<body>", "<script"]
                    html_matches = sum(1 for ind in html_indicators if ind in body_lower)

                    # If we're looking for a sensitive file but got HTML, it's likely a false positive
                    is_config_file = any(ext in path for ext in [".php", ".yml", ".yaml", ".json", ".xml", ".conf", ".config", ".sql", ".bak", ".env"])
                    is_html_response = html_matches >= 2

                    # For config/sensitive files, HTML response is a false positive
                    if is_config_file and is_html_response:
                        is_soft_404 = True

                    if is_soft_404:
                        # Skip this finding - it's a soft 404 or SPA catch-all
                        finding["false_positive_detected"] = True
                        finding["severity"] = "info"  # Downgrade severity
                        finding["accessible"] = False

            return finding

    except Exception:
        # Log but don't fail on individual path errors
        pass

    return None


async def check_forced_browsing(
    url: str,
    max_concurrent: int = 10,
    categories: list[str] | None = None,
    timeout_per_request: int = 10
) -> dict[str, Any]:
    """
    Test for forced browsing / direct request vulnerabilities.

    Checks privileged endpoints that should not be directly accessible.

    Args:
        url: Base URL to test
        max_concurrent: Maximum concurrent requests (default 10)
        categories: Optional list of categories to test (default all)
        timeout_per_request: Timeout per request in seconds

    Returns:
        Dict containing:
        - vulnerable: bool (any critical/high findings)
        - findings: list of accessible/protected endpoints
        - summary: count by severity
        - categories_tested: list of tested categories
    """
    results = {
        "vulnerable": False,
        "findings": [],
        "summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "info": 0,
        },
        "categories_tested": [],
        "paths_tested": 0,
        "accessible_count": 0,
        "protected_count": 0,
        "spa_detected": False,
    }

    # SPA DETECTION: Check if site uses catch-all routing (returns same page for all paths)
    # This causes massive false positives since every path returns HTTP 200
    try:
        spa_result = await detect_spa_catch_all(url, timeout=timeout_per_request)
        if spa_result.get("is_spa_catch_all"):
            results["spa_detected"] = True
            results["spa_evidence"] = spa_result.get("evidence", {})
            # Skip forced browsing checks - all paths would return same content
            return results
    except Exception:
        pass  # Continue with checks if SPA detection fails

    # ENHANCED: Fetch homepage hash for catch-all detection
    # Even if SPA detection didn't trigger, we compare responses to homepage
    homepage_hash = None
    try:
        homepage_hash = await fetch_homepage_hash(url, timeout=timeout_per_request)
    except Exception:
        pass  # Continue without homepage comparison if fetch fails

    # Determine which paths to test
    if categories:
        paths_to_test = []
        for cat in categories:
            if cat in PRIVILEGED_PATHS:
                paths_to_test.extend(PRIVILEGED_PATHS[cat])
                results["categories_tested"].append(cat)
    else:
        paths_to_test = get_all_paths()
        results["categories_tested"] = list(PRIVILEGED_PATHS.keys())

    results["paths_tested"] = len(paths_to_test)

    # Create semaphore for rate limiting
    semaphore = asyncio.Semaphore(max_concurrent)

    async def test_with_semaphore(path: str) -> dict[str, Any] | None:
        async with semaphore:
            return await test_single_path(url, path, timeout_per_request, homepage_hash)

    # Run all tests concurrently with rate limiting
    tasks = [test_with_semaphore(path) for path in paths_to_test]
    findings = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    for finding in findings:
        if isinstance(finding, Exception):
            continue
        if finding is None:
            continue

        results["findings"].append(finding)

        severity = finding.get("severity", "info")
        results["summary"][severity] = results["summary"].get(severity, 0) + 1

        if finding.get("accessible"):
            results["accessible_count"] += 1
        if finding.get("protected"):
            results["protected_count"] += 1

    # Determine if vulnerable (any critical or high findings)
    if results["summary"]["critical"] > 0 or results["summary"]["high"] > 0:
        results["vulnerable"] = True

    # Sort findings by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    results["findings"].sort(key=lambda x: severity_order.get(x.get("severity", "info"), 99))

    return results


def format_findings_for_scanner(
    forced_browsing_results: dict[str, Any],
    base_url: str
) -> list[dict[str, Any]]:
    """
    Format forced browsing results into scanner finding format.

    Returns list of findings compatible with the main scanner output.
    """
    findings = []

    for fb_finding in forced_browsing_results.get("findings", []):
        if fb_finding.get("severity") == "info":
            # Skip info-level findings (protected endpoints)
            continue

        status = fb_finding.get("status_code", "unknown")
        path = fb_finding.get("path", "unknown")
        category = fb_finding.get("category", "unknown")
        severity = fb_finding.get("severity", "medium")

        # Map category to readable name
        category_names = {
            "admin_panels": "Admin Panel",
            "api_endpoints": "API Endpoint",
            "management_consoles": "Management Console",
            "debug_dev": "Debug/Development Endpoint",
            "sensitive_files": "Sensitive File",
            "backup_files": "Backup File",
            "user_management": "User Management Endpoint",
            "logs_monitoring": "Log/Monitoring Endpoint",
            "cloud_metadata": "Cloud Metadata",
        }

        category_name = category_names.get(category, category.replace("_", " ").title())

        # Use SHA-256 for deterministic finding IDs (consistent across runs)
        path_hash = hashlib.sha256(path.encode()).hexdigest()[:8]
        finding = {
            "id": f"forced_browsing:{path_hash}",
            "tool": "forced_browsing",
            "title": f"Accessible {category_name}: {path}",
            "severity": severity,
            "description": f"The endpoint {path} returned HTTP {status} and appears to be accessible without proper authentication.",
            "evidence": {
                "url": fb_finding.get("url"),
                "path": path,
                "status_code": status,
                "category": category,
                "content_type": fb_finding.get("content_type"),
                "content_length": fb_finding.get("content_length"),
            },
            "remediation": "Implement proper authentication and authorization controls. Consider using role-based access control (RBAC) and ensure all administrative endpoints require authentication.",
            "references": [
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                "https://cwe.mitre.org/data/definitions/425.html",
            ],
        }

        findings.append(finding)

    return findings


# =============================================================================
# MASS ASSIGNMENT DETECTION (CWE-915)
# =============================================================================

# Common privilege escalation parameters
MASS_ASSIGNMENT_PARAMS = {
    "role_escalation": [
        ("role", "admin"),
        ("role", "administrator"),
        ("role", "superuser"),
        ("role", "root"),
        ("user_role", "admin"),
        ("userRole", "admin"),
        ("user_type", "admin"),
        ("userType", "admin"),
        ("type", "admin"),
        ("access_level", "admin"),
        ("accessLevel", "admin"),
        ("permission", "admin"),
        ("permissions", "all"),
        ("group", "admins"),
        ("groups", "administrators"),
    ],
    "admin_flags": [
        ("admin", True),
        ("is_admin", True),
        ("isAdmin", True),
        ("is_superuser", True),
        ("isSuperuser", True),
        ("is_staff", True),
        ("isStaff", True),
        ("superuser", True),
        ("super_user", True),
        ("privileged", True),
        ("elevated", True),
        ("root", True),
        ("is_root", True),
    ],
    "account_status": [
        ("active", True),
        ("is_active", True),
        ("isActive", True),
        ("verified", True),
        ("is_verified", True),
        ("isVerified", True),
        ("email_verified", True),
        ("emailVerified", True),
        ("confirmed", True),
        ("approved", True),
        ("enabled", True),
        ("status", "active"),
        ("account_status", "verified"),
    ],
    "pricing_manipulation": [
        ("price", 0),
        ("amount", 0),
        ("total", 0),
        ("discount", 100),
        ("discount_percent", 100),
        ("discountPercent", 100),
        ("free", True),
        ("is_free", True),
        ("trial", True),
        ("premium", True),
        ("is_premium", True),
        ("plan", "enterprise"),
        ("subscription", "unlimited"),
    ],
}


async def check_mass_assignment(
    base_url: str,
    endpoints: list[str] | None = None,
    auth_session: Any | None = None,
    timeout: int = 10
) -> dict[str, Any]:
    """
    Check for Mass Assignment vulnerabilities (CWE-915, OWASP API Security).

    Tests whether the application accepts and processes parameters that
    should not be user-controllable (privilege escalation, pricing, etc).

    Args:
        base_url: Target base URL
        endpoints: Specific endpoints to test (auto-discovered if None)
        auth_session: Optional authenticated session
        timeout: Request timeout

    Returns:
        Dictionary with findings and statistics
    """
    from .proof_of_exploit import fetch_with_capture

    results = {
        "vulnerable": False,
        "findings": [],
        "endpoints_tested": 0,
        "parameters_tested": 0,
    }

    # Default endpoints to test
    if not endpoints:
        endpoints = [
            "/api/user", "/api/users", "/api/me", "/api/profile",
            "/api/account", "/api/settings", "/api/update",
            "/api/v1/user", "/api/v1/users", "/api/v1/me",
            "/user/update", "/user/profile", "/account/settings",
            "/profile", "/settings", "/account",
        ]

    # Build headers for authenticated requests
    headers = {}
    if auth_session:
        if hasattr(auth_session, 'config'):
            headers.update(auth_session.config.headers or {})
            if auth_session.config.cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in auth_session.config.cookies.items())
                headers["Cookie"] = cookie_str

    headers["Content-Type"] = "application/json"

    for endpoint in endpoints:
        url = urljoin(base_url, endpoint)
        results["endpoints_tested"] += 1

        # First, make a baseline request to see if endpoint exists
        baseline = await fetch_with_capture(url, headers=headers, timeout=timeout)
        if baseline.get("status_code", 0) not in [200, 201, 204, 400, 422]:
            continue  # Endpoint doesn't exist or not accessible

        # Test each category of mass assignment parameters
        for category, params in MASS_ASSIGNMENT_PARAMS.items():
            for param_name, param_value in params:
                results["parameters_tested"] += 1

                # Build test payload
                import json
                payload = json.dumps({param_name: param_value})

                # Try POST
                post_response = await fetch_with_capture(
                    url, method="POST", data=payload, headers=headers, timeout=timeout
                )

                # Try PUT
                put_response = await fetch_with_capture(
                    url, method="PUT", data=payload, headers=headers, timeout=timeout
                )

                # Try PATCH
                patch_response = await fetch_with_capture(
                    url, method="PATCH", data=payload, headers=headers, timeout=timeout
                )

                # Analyze responses for signs of acceptance
                for method, response in [("POST", post_response), ("PUT", put_response), ("PATCH", patch_response)]:
                    status = response.get("status_code", 0)
                    body = response.get("body", "")

                    # Signs the parameter was accepted:
                    # 1. 200/201/204 response
                    # 2. Parameter name appears in response
                    # 3. No "unknown field" or "not allowed" error

                    if status in [200, 201, 204]:
                        # Check if parameter appears in response (echoed back)
                        if param_name in body or str(param_value).lower() in body.lower():
                            # Check it's not an error message
                            if not any(err in body.lower() for err in ["not allowed", "forbidden", "unknown", "invalid field", "unexpected"]):
                                results["vulnerable"] = True
                                path_hash = hashlib.sha256(f"{endpoint}:{param_name}".encode()).hexdigest()[:8]
                                results["findings"].append({
                                    "id": f"mass_assignment:{path_hash}",
                                    "tool": "mass_assignment",
                                    "title": f"Mass Assignment: {param_name} accepted on {endpoint}",
                                    "severity": "high" if category in ["role_escalation", "admin_flags"] else "medium",
                                    "category": category,
                                    "evidence": {
                                        "url": url,
                                        "method": method,
                                        "parameter": param_name,
                                        "value": str(param_value),
                                        "status_code": status,
                                        "response_snippet": body[:500],
                                    },
                                    "description": f"The application accepted the {param_name} parameter which could allow {category.replace('_', ' ')}.",
                                    "remediation": "Implement allowlisting for accepted parameters. Use DTOs or serializers that explicitly define which fields can be mass-assigned.",
                                    "cwe": "CWE-915",
                                    "owasp": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
                                })
                                break  # Found for this param, move to next

    return results


# =============================================================================
# BOLA/IDOR DETECTION WITH AUTHENTICATION CONTEXT
# =============================================================================

async def check_bola(
    base_url: str,
    resource_endpoints: list[dict[str, Any]] | None = None,
    user1_session: Any | None = None,
    user2_session: Any | None = None,
    timeout: int = 10
) -> dict[str, Any]:
    """
    Check for Broken Object Level Authorization (BOLA/IDOR).

    Tests whether users can access resources belonging to other users.
    Requires two authenticated sessions to properly test.

    OWASP API Security: API1:2023 - Broken Object Level Authorization

    Args:
        base_url: Target base URL
        resource_endpoints: List of endpoints with ID parameters to test
            Format: [{"path": "/api/users/{id}", "ids": ["1", "2", "3"]}]
        user1_session: First user's authenticated session
        user2_session: Second user's authenticated session
        timeout: Request timeout

    Returns:
        Dictionary with findings
    """
    from .proof_of_exploit import fetch_with_capture

    results = {
        "vulnerable": False,
        "findings": [],
        "endpoints_tested": 0,
        "access_violations": 0,
    }

    # Default endpoints to test if none provided
    if not resource_endpoints:
        resource_endpoints = [
            {"path": "/api/users/{id}", "ids": ["1", "2", "100", "999"]},
            {"path": "/api/user/{id}", "ids": ["1", "2", "100"]},
            {"path": "/api/orders/{id}", "ids": ["1", "2", "100"]},
            {"path": "/api/documents/{id}", "ids": ["1", "2", "100"]},
            {"path": "/api/files/{id}", "ids": ["1", "2", "100"]},
            {"path": "/api/messages/{id}", "ids": ["1", "2", "100"]},
            {"path": "/api/invoices/{id}", "ids": ["1", "2", "100"]},
            {"path": "/api/accounts/{id}", "ids": ["1", "2", "100"]},
            {"path": "/users/{id}", "ids": ["1", "2", "100"]},
            {"path": "/user/{id}/profile", "ids": ["1", "2", "100"]},
        ]

    def build_headers(session):
        headers = {}
        if session and hasattr(session, 'config'):
            headers.update(session.config.headers or {})
            if session.config.cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in session.config.cookies.items())
                headers["Cookie"] = cookie_str
        return headers

    user1_headers = build_headers(user1_session)
    user2_headers = build_headers(user2_session)

    for endpoint_config in resource_endpoints:
        path_template = endpoint_config.get("path", "")
        ids_to_test = endpoint_config.get("ids", ["1", "2"])

        for resource_id in ids_to_test:
            # Replace {id} placeholder with actual ID
            path = path_template.replace("{id}", str(resource_id))
            url = urljoin(base_url, path)
            results["endpoints_tested"] += 1

            # Test without auth (should fail)
            no_auth_response = await fetch_with_capture(url, timeout=timeout)

            # Test with user1's auth
            user1_response = await fetch_with_capture(url, headers=user1_headers, timeout=timeout) if user1_headers else None

            # Test with user2's auth
            user2_response = await fetch_with_capture(url, headers=user2_headers, timeout=timeout) if user2_headers else None

            # Analysis:
            # 1. If no-auth gets 200 with data = public endpoint or broken auth
            # 2. If user1 gets 200 and user2 gets 200 with SAME data = potential BOLA
            # 3. If user1 gets 200 for resource they don't own = BOLA

            no_auth_status = no_auth_response.get("status_code", 0)
            no_auth_body = no_auth_response.get("body", "")

            # Check if unauthenticated access returns data
            if no_auth_status == 200 and len(no_auth_body) > 50:
                # Check if it looks like actual data (not error/login page)
                if not any(x in no_auth_body.lower() for x in ["login", "sign in", "authenticate", "unauthorized"]):
                    results["vulnerable"] = True
                    results["access_violations"] += 1
                    path_hash = hashlib.sha256(f"{path}:noauth".encode()).hexdigest()[:8]
                    results["findings"].append({
                        "id": f"bola:{path_hash}",
                        "tool": "bola_check",
                        "title": f"BOLA: Unauthenticated access to {path}",
                        "severity": "critical",
                        "evidence": {
                            "url": url,
                            "resource_id": resource_id,
                            "status_code": no_auth_status,
                            "response_length": len(no_auth_body),
                            "response_snippet": no_auth_body[:300],
                        },
                        "description": f"Resource at {path} is accessible without authentication.",
                        "remediation": "Implement proper authentication and authorization. Verify the requesting user owns or has access to the resource.",
                        "cwe": "CWE-639",
                        "owasp": "API1:2023 - Broken Object Level Authorization",
                    })

            # If we have both user sessions, check cross-user access
            if user1_response and user2_response:
                user1_status = user1_response.get("status_code", 0)
                user2_status = user2_response.get("status_code", 0)
                user1_body = user1_response.get("body", "")
                user2_body = user2_response.get("body", "")

                # Both users can access - potential BOLA if they shouldn't both have access
                if user1_status == 200 and user2_status == 200:
                    # If responses are identical and contain data
                    if len(user1_body) > 50 and user1_body == user2_body:
                        # Could be BOLA - both users getting same resource
                        # This needs manual verification but is suspicious
                        path_hash = hashlib.sha256(f"{path}:crossuser".encode()).hexdigest()[:8]
                        results["findings"].append({
                            "id": f"bola_potential:{path_hash}",
                            "tool": "bola_check",
                            "title": f"Potential BOLA: Both users access same resource at {path}",
                            "severity": "medium",
                            "evidence": {
                                "url": url,
                                "resource_id": resource_id,
                                "user1_status": user1_status,
                                "user2_status": user2_status,
                                "responses_identical": True,
                            },
                            "description": f"Both test users can access the same resource at {path}. This may indicate missing authorization checks.",
                            "remediation": "Verify that users can only access resources they own. Implement object-level authorization checks.",
                            "cwe": "CWE-639",
                            "owasp": "API1:2023 - Broken Object Level Authorization",
                        })

    return results


async def check_vertical_privilege_escalation(
    base_url: str,
    admin_endpoints: list[str] | None = None,
    regular_user_session: Any | None = None,
    timeout: int = 10
) -> dict[str, Any]:
    """
    Check for Vertical Privilege Escalation.

    Tests whether a regular user can access admin-only endpoints.

    Args:
        base_url: Target base URL
        admin_endpoints: List of admin endpoints to test
        regular_user_session: Authenticated session for a regular (non-admin) user
        timeout: Request timeout

    Returns:
        Dictionary with findings
    """
    from .proof_of_exploit import fetch_with_capture

    results = {
        "vulnerable": False,
        "findings": [],
        "endpoints_tested": 0,
    }

    if not admin_endpoints:
        admin_endpoints = [
            "/admin", "/admin/dashboard", "/admin/users", "/admin/settings",
            "/api/admin", "/api/admin/users", "/api/admin/config",
            "/api/v1/admin", "/api/v1/admin/users",
            "/management", "/management/users",
            "/internal/admin", "/internal/config",
        ]

    headers = {}
    if regular_user_session and hasattr(regular_user_session, 'config'):
        headers.update(regular_user_session.config.headers or {})
        if regular_user_session.config.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in regular_user_session.config.cookies.items())
            headers["Cookie"] = cookie_str

    for endpoint in admin_endpoints:
        url = urljoin(base_url, endpoint)
        results["endpoints_tested"] += 1

        response = await fetch_with_capture(url, headers=headers, timeout=timeout)
        status = response.get("status_code", 0)
        body = response.get("body", "")

        # A regular user should get 403/401, not 200
        if status == 200 and len(body) > 100:
            # Check if it looks like admin content
            admin_indicators = ["admin", "dashboard", "users list", "configuration", "settings", "management"]
            if any(ind in body.lower() for ind in admin_indicators):
                results["vulnerable"] = True
                path_hash = hashlib.sha256(endpoint.encode()).hexdigest()[:8]
                results["findings"].append({
                    "id": f"privilege_escalation:{path_hash}",
                    "tool": "privilege_check",
                    "title": f"Vertical Privilege Escalation: Regular user can access {endpoint}",
                    "severity": "critical",
                    "evidence": {
                        "url": url,
                        "status_code": status,
                        "response_length": len(body),
                        "response_snippet": body[:300],
                    },
                    "description": f"A regular user can access the admin endpoint {endpoint}.",
                    "remediation": "Implement role-based access control (RBAC). Verify user roles before granting access to admin functionality.",
                    "cwe": "CWE-269",
                    "owasp": "A01:2021 - Broken Access Control",
                })

    return results
