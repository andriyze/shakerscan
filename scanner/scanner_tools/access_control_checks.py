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
import time
from typing import Any
from urllib.parse import urljoin

from .common import run, detect_spa_catch_all, fetch_homepage_hash, is_same_as_homepage, _compute_content_hash

FORCED_BROWSING_MAX_BODY_BYTES = 262_144

# =============================================================================
# CONTENT VALIDATION PATTERNS - Validate that responses match expected content
# =============================================================================
# Each category defines what SHOULD be in a valid response (not just HTTP 200)

CATEGORY_CONTENT_VALIDATORS = {
    "admin_panels": {
        # Admin panels should contain admin-specific UI elements
        # NOTE: These patterns are intentionally more specific to avoid matching
        # generic SPA pages that just mention "login" or "admin" in navigation
        "required_patterns": [
            "admin panel", "admin dashboard", "administrator login",
            "control panel", "cpanel", "webadmin", "site administration",
            "backend login", "admin area", "management console",
            # Specific admin CMS patterns
            "wp-admin", "wp-login", "django admin", "laravel nova",
            "rails admin", "activeadmin", "administrate",
        ],
        "min_matches": 1,
        "reject_if_html_generic": True,
        # Use homepage hash comparison - if response is same as homepage, it's a catch-all
        "compare_to_homepage": True,
    },
    "api_endpoints": {
        # API endpoints should return JSON or contain API-specific content
        "expected_content_types": ["application/json", "application/xml", "text/xml"],
        "required_patterns": [
            # JSON structure (need multiple matches)
            '"type":', '"data":', '"error":', '"status":',
            '"message":', '"result":', '"response":',
            # API documentation
            "swagger", "openapi", "graphql", "query", "mutation",
        ],
        "min_matches": 2,  # Require at least 2 matches to avoid FPs
        "reject_if_html_generic": True,
        "always_validate": True,
        "reject_html_content_type": True,
    },
    "management_consoles": {
        # Management console patterns - more specific
        "required_patterns": [
            "management console", "admin console", "database console",
            "phpmyadmin", "adminer", "pgadmin", "mongodb compass",
            "redis commander", "kibana", "grafana", "prometheus",
            "jenkins", "hudson", "bamboo", "teamcity",
        ],
        "min_matches": 1,
        "reject_if_html_generic": True,
        "compare_to_homepage": True,
    },
    "debug_dev": {
        # Debug/dev endpoints should NEVER return generic HTML
        # They return JSON (actuator), text/plain (metrics), or specific debug output
        "expected_content_types": [
            "application/json",
            "text/plain",
            "application/vnd.spring-boot.actuator",
            "text/event-stream",  # webpack HMR
        ],
        "required_patterns": [
            # Spring Boot Actuator specific (JSON responses)
            '"status":', '"health":', '"beans":', '"mappings":', '"configprops":',
            '"metrics":', '"details":', '"components":',
            # Prometheus metrics format
            "# HELP", "# TYPE", "_total", "_count", "_bucket",
            # Vite/webpack dev server specific (event-stream or JS)
            "hot module", "__webpack_hmr", "webpackHotUpdate",
            # Next.js dev
            "__nextjs_original-stack-frame", "next-router-state-tree",
            # Node.js/V8 debug
            "heapTotal", "heapUsed", "v8.serialize",
            # Kubernetes health (JSON)
            '"healthy":', '"ready":', '"live":',
        ],
        # Highly specific patterns valid in HTML (1 match sufficient)
        "html_safe_patterns_unique": [
            # phpinfo specific (outputs HTML by design) - very unique markers
            "php version", "php variables", "php credits", "phpinfo()",
            "<td class=\"e\">", "configuration file (php.ini) path",
            # Django debug page - unique markers
            "you're seeing this error because", "debug = true in your django settings",
            # Rails error page - unique markers
            "rails.root:", "application trace", "framework trace",
        ],
        # Stack trace patterns that need 2+ matches to confirm (more generic)
        "html_safe_patterns_stacktrace": [
            # Django (need multiple)
            "request method:", "django version:", "exception type:",
            "exception value:", "python path:",
            # Rails (need multiple)
            "full trace", "rails version:", "backtrace",
            # ASP.NET (need multiple)
            "server error in", "[sqlexception", "[httpexception",
            "stack trace:", "source error:", "aspnetcore",
            "version information:", "microsoft .net",
            # Java/Spring (need multiple)
            "java.lang.", "javax.", "org.springframework.",
            "at com.", "caused by:", "exception in thread",
            # Node.js (need multiple)
            "    at ", "node_modules/", "internal/modules",
        ],
        "min_matches": 1,
        "reject_if_html_generic": True,
        # These paths should NEVER return generic HTML app content
        "always_validate": True,
        # Explicitly reject text/html - debug endpoints don't return HTML pages
        # Exception: html_safe_patterns can still match
        "reject_html_content_type": True,
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
        # User management endpoints return JSON data, not HTML pages
        "expected_content_types": ["application/json", "text/json"],
        "required_patterns": [
            # JSON API response patterns (more specific than single words)
            '"user_id":', '"userId":', '"user":', '"account_id":',
            '"email":', '"username":', '"password":', '"role":',
            '"users":', '"accounts":', '"profiles":',
            '"member":', '"customer":', '"total_users":',
            # Admin panel specific
            "user management", "account management", "list users",
        ],
        "min_matches": 1,
        "reject_if_html_generic": True,
        # These endpoints should NEVER return generic HTML app content
        "always_validate": True,
        "reject_html_content_type": True,
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

    body_lower = body[:5000].lower()

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

    body_lower = body[:5000].lower()
    ct_lower = (content_type or "").lower()
    is_html = "text/html" in ct_lower
    is_generic_html = is_html and _is_generic_html_page(body)

    # Check if HTML should always be rejected for this category (e.g., .env files)
    if validator.get("reject_html_always", False):
        if is_generic_html:
            return False, "html_rejected_for_category"

    patterns = validator.get("required_patterns", [])
    min_matches = validator.get("min_matches", 1)

    # Check for html_safe_patterns FIRST - these are valid even in HTML
    if is_html:
        # Unique patterns (1 match sufficient) - phpinfo, Django debug banner, etc.
        unique_patterns = validator.get("html_safe_patterns_unique", [])
        if unique_patterns:
            unique_matches = sum(1 for p in unique_patterns if p.lower() in body_lower)
            if unique_matches >= 1:
                return True, f"html_safe_unique_match_{unique_matches}"

        # Stack trace patterns (2+ matches required) - more generic markers
        stacktrace_patterns = validator.get("html_safe_patterns_stacktrace", [])
        if stacktrace_patterns:
            stack_matches = sum(1 for p in stacktrace_patterns if p.lower() in body_lower)
            if stack_matches >= 2:
                return True, f"html_safe_stacktrace_match_{stack_matches}"

    # For HTML responses, check if category rejects HTML content-type
    # (patterns like "stack trace" in HTML error pages are not valid debug endpoints)
    if validator.get("reject_html_content_type", False) and is_html:
        return False, "html_content_type_rejected"

    # Check for required patterns
    pattern_matches = 0
    if patterns:
        pattern_matches = sum(1 for p in patterns if p.lower() in body_lower)
        if pattern_matches >= min_matches:
            # Pattern matched and not HTML (or HTML already handled above)
            # Still reject if it's a SPA shell with common words
            if is_generic_html:
                # Use the same SPA indicators as _is_generic_html_page for consistency
                if any(ind.lower() in body_lower for ind in SPA_FRAMEWORK_INDICATORS):
                    return False, "spa_shell_with_common_word"
            return True, f"pattern_match_{pattern_matches}"

    # For categories with always_validate, strictly require pattern matches
    if validator.get("always_validate", False):
        if patterns and pattern_matches < min_matches:
            return False, "required_patterns_missing"
        if is_generic_html:
            return False, "generic_html_rejected_for_strict_category"

    # Check expected content types (for non-strict categories)
    expected_cts = validator.get("expected_content_types", [])
    if expected_cts:
        ct_match = any(ect in ct_lower for ect in expected_cts)
        if ct_match:
            return True, "content_type_match"
        # If content-type doesn't match and it's HTML, likely false positive
        if is_html and validator.get("reject_if_html_generic", False):
            if is_generic_html:
                return False, "html_generic_rejected"

    # No pattern matches and reject_if_html_generic - check for generic HTML
    if validator.get("reject_if_html_generic", False):
        if is_generic_html:
            return False, "no_patterns_and_generic_html"

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
    homepage_hash: str | None = None,
    max_body_bytes: int = FORCED_BROWSING_MAX_BODY_BYTES
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
                range_end = max(0, max_body_bytes - 1)
                get_out, get_err, get_rc = await run(
                    [
                        "curl", "-sS", "-k", "-L",
                        "--max-time", str(timeout),
                        "--range", f"0-{range_end}",
                        "--max-filesize", str(max_body_bytes),
                        "-w", "\n---CURL_METADATA---\n%{http_code}|%{content_type}|%{size_download}",
                        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        full_url
                    ],
                    timeout=timeout + 5
                )

                if get_out:
                    # Split response body from metadata
                    parts = get_out.split("---CURL_METADATA---")
                    body = parts[0] if len(parts) > 0 else ""
                    metadata = parts[1].strip() if len(parts) > 1 else ""

                    if max_body_bytes and len(body) > max_body_bytes:
                        body = body[:max_body_bytes]
                        finding["content_truncated"] = True
                    if get_rc != 0:
                        finding["content_fetch_error"] = get_err or f"curl_exit_{get_rc}"

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
                    body_lower = body[:3000].lower()  # Check first 3KB
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
                        response_hash = _compute_content_hash(body[:max_body_bytes] if max_body_bytes else body)
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
    timeout_per_request: int = 10,
    max_total_time: int | None = None,
) -> dict[str, Any]:
    """
    Test for forced browsing / direct request vulnerabilities.

    Checks privileged endpoints that should not be directly accessible.

    Args:
        url: Base URL to test
        max_concurrent: Maximum concurrent requests (default 10)
        categories: Optional list of categories to test (default all)
        timeout_per_request: Timeout per request in seconds
        max_total_time: Optional total time budget in seconds for all tests

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
        "time_budget_exceeded": False,
    }
    start_time = time.monotonic()

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
        if max_total_time is not None and (time.monotonic() - start_time) >= max_total_time:
            return None
        async with semaphore:
            if max_total_time is not None and (time.monotonic() - start_time) >= max_total_time:
                return None
            return await test_single_path(url, path, timeout_per_request, homepage_hash)

    # Run all tests concurrently with rate limiting
    tasks = [test_with_semaphore(path) for path in paths_to_test]
    findings = await asyncio.gather(*tasks, return_exceptions=True)
    if max_total_time is not None and (time.monotonic() - start_time) >= max_total_time:
        results["time_budget_exceeded"] = True

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


# ID patterns commonly used in URLs
ID_PATTERNS = [
    (r'/(\d+)(?:/|$|\?)', 'numeric_id'),      # /123, /users/123
    (r'/([a-f0-9]{24})(?:/|$|\?)', 'mongodb_id'),  # MongoDB ObjectID
    (r'/([a-f0-9-]{36})(?:/|$|\?)', 'uuid'),       # UUID v4
    (r'/([a-zA-Z0-9]{20,})(?:/|$|\?)', 'base64_id'),  # Base64-like IDs
    (r'\?.*?id=(\d+)', 'query_numeric_id'),   # ?id=123
    (r'\?.*?id=([a-f0-9-]+)', 'query_uuid'),  # ?id=uuid
]


async def smart_bola_test(
    base_url: str,
    discovered_urls: list[str],
    user1_session: Any | None = None,
    user2_session: Any | None = None,
    max_endpoints: int = 30,
    timeout: int = 10
) -> dict[str, Any]:
    """
    Smart BOLA/IDOR testing that auto-discovers endpoints with ID patterns.

    This function:
    1. Analyzes discovered URLs to find endpoints with ID parameters
    2. Groups similar endpoints by pattern
    3. Tests ID manipulation (sequential IDs, random IDs)
    4. Compares responses between two authenticated users
    5. Detects unauthorized access based on response analysis

    Args:
        base_url: Target base URL
        discovered_urls: List of discovered URLs from crawling
        user1_session: First user's authenticated session
        user2_session: Second user's authenticated session
        max_endpoints: Maximum unique endpoints to test
        timeout: Request timeout

    Returns:
        Dictionary with findings and statistics
    """
    import re
    import random
    from .proof_of_exploit import fetch_with_capture

    results = {
        "vulnerable": False,
        "findings": [],
        "endpoints_analyzed": 0,
        "id_patterns_found": 0,
        "access_violations": 0,
        "cross_user_violations": 0,
        "method_variations_tested": 0,
    }

    def build_headers(session):
        headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
        if session and hasattr(session, 'config'):
            headers.update(session.config.headers or {})
            if session.config.cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in session.config.cookies.items())
                headers["Cookie"] = cookie_str
        return headers

    user1_headers = build_headers(user1_session)
    user2_headers = build_headers(user2_session)

    # Extract endpoints with ID patterns from discovered URLs
    id_endpoints = {}  # path_template -> {pattern_type, original_ids, base_url}

    for url in discovered_urls:
        for pattern, pattern_type in ID_PATTERNS:
            match = re.search(pattern, url)
            if match:
                original_id = match.group(1)
                # Create a template by replacing the ID with {id}
                template = re.sub(pattern, lambda m: m.group(0).replace(m.group(1), '{id}'), url)

                if template not in id_endpoints:
                    id_endpoints[template] = {
                        'pattern_type': pattern_type,
                        'original_ids': set(),
                        'example_url': url,
                    }
                id_endpoints[template]['original_ids'].add(original_id)
                results["id_patterns_found"] += 1
                break

    print(f"[bola] Found {len(id_endpoints)} unique endpoint templates with ID patterns", file=__import__('sys').stderr)

    # Test each unique endpoint template
    for template, info in list(id_endpoints.items())[:max_endpoints]:
        results["endpoints_analyzed"] += 1
        pattern_type = info['pattern_type']
        original_ids = list(info['original_ids'])

        # Generate test IDs based on pattern type
        test_ids = list(original_ids[:3])  # Start with discovered IDs

        if pattern_type == 'numeric_id' or pattern_type == 'query_numeric_id':
            # Add sequential IDs around the discovered ones
            for orig_id in original_ids[:2]:
                try:
                    orig_int = int(orig_id)
                    test_ids.extend([str(orig_int - 1), str(orig_int + 1), str(orig_int + 10)])
                except ValueError:
                    pass
            # Add common test IDs
            test_ids.extend(['1', '0', '2', '100', '999', '9999'])
        elif pattern_type == 'uuid':
            # For UUIDs, we can only test with known UUIDs (can't easily enumerate)
            pass
        elif pattern_type == 'mongodb_id':
            # For MongoDB IDs, we can try some manipulation
            pass

        # Deduplicate test IDs
        test_ids = list(dict.fromkeys(test_ids))[:10]

        # Test each ID
        for test_id in test_ids:
            # Replace {id} with test ID
            test_url = template.replace('{id}', test_id)

            # Test with user1
            user1_resp = await fetch_with_capture(test_url, headers=user1_headers, timeout=timeout)
            user1_status = user1_resp.get("status_code", 0)
            user1_body = user1_resp.get("body", "")

            # Test with user2 if user2_session is actually provided
            # (cross-user comparison only makes sense with two authenticated users)
            if user2_session is not None:
                user2_resp = await fetch_with_capture(test_url, headers=user2_headers, timeout=timeout)
                user2_status = user2_resp.get("status_code", 0)
                user2_body = user2_resp.get("body", "")

                # Check for cross-user access
                if user1_status == 200 and user2_status == 200:
                    # Both users can access - check if data is user-specific
                    if len(user1_body) > 50 and len(user2_body) > 50:
                        # Compare responses
                        if user1_body == user2_body:
                            # Identical responses - might be public data or BOLA
                            # Look for user-specific indicators
                            user_indicators = ['user_id', 'userId', 'email', 'name', 'profile', 'account']
                            has_user_data = any(ind in user1_body.lower() for ind in user_indicators)

                            if has_user_data:
                                results["vulnerable"] = True
                                results["cross_user_violations"] += 1
                                path_hash = hashlib.sha256(f"{test_url}:crossuser".encode()).hexdigest()[:8]
                                results["findings"].append({
                                    "id": f"smart_bola:{path_hash}",
                                    "tool": "smart_bola",
                                    "title": f"BOLA: Cross-user data access at {template}",
                                    "severity": "high",
                                    "evidence": {
                                        "url": test_url,
                                        "test_id": test_id,
                                        "pattern_type": pattern_type,
                                        "user1_status": user1_status,
                                        "user2_status": user2_status,
                                        "responses_identical": True,
                                        "response_snippet": user1_body[:300],
                                    },
                                    "description": f"Both test users can access resource with ID {test_id}. "
                                                 "If this is user-specific data, this indicates missing authorization.",
                                    "remediation": "Implement object-level authorization. Verify requesting user owns the resource.",
                                    "cwe": "CWE-639",
                                    "owasp": "API1:2023 - Broken Object Level Authorization",
                                })

            # Test without auth
            no_auth_resp = await fetch_with_capture(test_url, timeout=timeout)
            no_auth_status = no_auth_resp.get("status_code", 0)
            no_auth_body = no_auth_resp.get("body", "")

            # If unauthenticated access returns data
            if no_auth_status == 200 and len(no_auth_body) > 50:
                # Check if it looks like actual data
                exclude_patterns = ['login', 'sign in', 'authenticate', 'unauthorized', '<!doctype', '<html']
                if not any(p in no_auth_body.lower() for p in exclude_patterns):
                    results["vulnerable"] = True
                    results["access_violations"] += 1
                    path_hash = hashlib.sha256(f"{test_url}:noauth".encode()).hexdigest()[:8]
                    results["findings"].append({
                        "id": f"smart_bola:{path_hash}",
                        "tool": "smart_bola",
                        "title": f"BOLA: Unauthenticated access to {template}",
                        "severity": "critical",
                        "evidence": {
                            "url": test_url,
                            "test_id": test_id,
                            "pattern_type": pattern_type,
                            "status_code": no_auth_status,
                            "response_length": len(no_auth_body),
                            "response_snippet": no_auth_body[:300],
                        },
                        "description": f"Resource with ID {test_id} is accessible without authentication.",
                        "remediation": "Require authentication for all resource access. Implement proper authorization.",
                        "cwe": "CWE-639",
                        "owasp": "API1:2023 - Broken Object Level Authorization",
                    })

        # Test method variations (PUT, DELETE, PATCH on GET endpoints)
        if user1_headers and results["endpoints_analyzed"] <= 10:  # Limit method testing
            for method in ["PUT", "DELETE", "PATCH"]:
                results["method_variations_tested"] += 1
                # Use the first discovered URL for method testing
                method_url = info['example_url']
                cmd = ["curl", "-sS", "-X", method, "-k", "--max-time", str(timeout)]
                for k, v in user1_headers.items():
                    cmd.extend(["-H", f"{k}: {v}"])
                cmd.extend(["-w", "\n%{http_code}", method_url])

                out, _, rc = await run(cmd, timeout=timeout + 5)
                if rc == 0 and out:
                    lines = out.rsplit("\n", 1)
                    body = lines[0] if len(lines) > 1 else ""
                    try:
                        status = int(lines[-1]) if lines else 0
                    except ValueError:
                        status = 0

                    # If method succeeds when it shouldn't (200 on DELETE/PUT)
                    if status == 200 and method in ["DELETE", "PUT"]:
                        results["vulnerable"] = True
                        path_hash = hashlib.sha256(f"{method_url}:{method}".encode()).hexdigest()[:8]
                        results["findings"].append({
                            "id": f"smart_bola:{path_hash}",
                            "tool": "smart_bola",
                            "title": f"BOLA: Unexpected {method} success at {method_url}",
                            "severity": "high",
                            "evidence": {
                                "url": method_url,
                                "method": method,
                                "status_code": status,
                                "response_snippet": body[:200],
                            },
                            "description": f"HTTP {method} method succeeds. This may allow unauthorized modification/deletion.",
                            "remediation": "Implement proper authorization for all HTTP methods.",
                            "cwe": "CWE-639",
                            "owasp": "API1:2023 - Broken Object Level Authorization",
                        })

    return results


# =============================================================================
# N-USER BOLA/IDOR TESTING
# =============================================================================

async def check_bola_multi_user(
    base_url: str,
    resource_endpoints: list[dict[str, Any]] | None = None,
    user_sessions: list[Any] | None = None,
    user_owned_resources: dict[int, list[str]] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """
    Check for Broken Object Level Authorization with N users.

    Enhanced BOLA testing that supports multiple user sessions for
    comprehensive access control testing across different roles.

    OWASP API Security: API1:2023 - Broken Object Level Authorization

    Args:
        base_url: Target base URL
        resource_endpoints: List of endpoints with ID parameters to test
            Format: [{"path": "/api/users/{id}", "ids": ["1", "2", "3"]}]
        user_sessions: List of authenticated sessions for different users
            Example: [admin_session, manager_session, user_session, guest_session]
        user_owned_resources: Optional mapping of user index to their owned resource IDs
            Example: {0: ["1", "2"], 1: ["3", "4"], 2: ["5", "6"]}
        timeout: Request timeout

    Returns:
        Dictionary with detailed findings including access matrix
    """
    from .proof_of_exploit import fetch_with_capture

    results = {
        "vulnerable": False,
        "findings": [],
        "endpoints_tested": 0,
        "access_violations": 0,
        "users_tested": len(user_sessions) if user_sessions else 0,
        "access_matrix": {},  # endpoint -> {user_idx -> access_result}
    }

    if not user_sessions or len(user_sessions) < 2:
        # Fall back to basic BOLA if not enough users
        results["error"] = "At least 2 user sessions required for multi-user BOLA testing"
        return results

    # Default endpoints to test
    if not resource_endpoints:
        resource_endpoints = [
            {"path": "/api/users/{id}", "ids": ["1", "2", "3", "4", "5"]},
            {"path": "/api/user/{id}", "ids": ["1", "2", "3"]},
            {"path": "/api/user/{id}/profile", "ids": ["1", "2", "3"]},
            {"path": "/api/orders/{id}", "ids": ["1", "2", "3"]},
            {"path": "/api/documents/{id}", "ids": ["1", "2", "3"]},
            {"path": "/api/accounts/{id}", "ids": ["1", "2", "3"]},
            {"path": "/api/messages/{id}", "ids": ["1", "2", "3"]},
            {"path": "/api/payments/{id}", "ids": ["1", "2", "3"]},
        ]

    def build_headers(session):
        headers = {}
        if session is None:
            return headers
        if hasattr(session, 'config'):
            headers.update(session.config.headers or {})
            if session.config.cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in session.config.cookies.items())
                headers["Cookie"] = cookie_str
        elif hasattr(session, 'export_session'):
            exported = session.export_session()
            headers.update(exported.get("headers", {}))
            cookies = exported.get("cookies", {})
            if cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        elif isinstance(session, dict):
            # Direct header dict
            headers.update(session.get("headers", {}))
            if session.get("cookies"):
                headers["Cookie"] = session["cookies"]
        return headers

    # Build headers for each user
    user_headers_list = [build_headers(session) for session in user_sessions]

    # Add unauthenticated as user index -1
    user_headers_list.insert(0, {})  # Index 0 is now unauthenticated
    # Original users are now at indices 1, 2, 3, ...

    for endpoint_config in resource_endpoints:
        path_template = endpoint_config.get("path", "")
        ids_to_test = endpoint_config.get("ids", ["1", "2", "3"])

        for resource_id in ids_to_test:
            path = path_template.replace("{id}", str(resource_id))
            url = urljoin(base_url, path)
            results["endpoints_tested"] += 1

            # Initialize access matrix entry
            matrix_key = f"{path_template}:{resource_id}"
            results["access_matrix"][matrix_key] = {}

            # Test with each user (including unauthenticated at index 0)
            user_responses = []
            for user_idx, headers in enumerate(user_headers_list):
                response = await fetch_with_capture(url, headers=headers, timeout=timeout)
                user_responses.append(response)

                status = response.get("status_code", 0)
                body = response.get("body", "")
                body_len = len(body)

                # Record in access matrix
                user_label = "unauthenticated" if user_idx == 0 else f"user_{user_idx}"
                results["access_matrix"][matrix_key][user_label] = {
                    "status": status,
                    "body_length": body_len,
                    "has_data": status == 200 and body_len > 50,
                }

            # Analyze responses for BOLA
            # Check 1: Unauthenticated access to protected resource
            unauth_response = user_responses[0]
            unauth_status = unauth_response.get("status_code", 0)
            unauth_body = unauth_response.get("body", "")

            if unauth_status == 200 and len(unauth_body) > 50:
                if not any(x in unauth_body.lower() for x in ["login", "sign in", "authenticate", "unauthorized"]):
                    results["vulnerable"] = True
                    results["access_violations"] += 1
                    path_hash = hashlib.sha256(f"{path}:noauth:multi".encode()).hexdigest()[:8]
                    results["findings"].append({
                        "id": f"bola_multi:{path_hash}",
                        "tool": "bola_multi_user",
                        "title": f"BOLA: Unauthenticated access to {path}",
                        "severity": "critical",
                        "evidence": {
                            "url": url,
                            "resource_id": resource_id,
                            "status_code": unauth_status,
                            "response_length": len(unauth_body),
                        },
                        "description": f"Resource at {path} accessible without authentication.",
                        "remediation": "Implement authentication and object-level authorization.",
                        "cwe": "CWE-639",
                        "owasp": "API1:2023 - Broken Object Level Authorization",
                    })

            # Check 2: Cross-user access (any authenticated user accessing another's resources)
            authenticated_responses = user_responses[1:]  # Skip unauthenticated

            # Get responses that returned data
            successful_users = []
            for i, resp in enumerate(authenticated_responses):
                status = resp.get("status_code", 0)
                body = resp.get("body", "")
                if status == 200 and len(body) > 50:
                    successful_users.append((i + 1, body))  # i+1 because we skipped unauth

            # If multiple users can access the same resource with same data
            if len(successful_users) > 1:
                # Check if user_owned_resources is defined to determine ownership
                expected_owner = None
                if user_owned_resources:
                    for owner_idx, owned_ids in user_owned_resources.items():
                        if resource_id in owned_ids:
                            expected_owner = owner_idx
                            break

                # Compare bodies
                bodies = [body for _, body in successful_users]
                if len(set(bodies)) == 1:  # All identical responses
                    accessing_users = [uid for uid, _ in successful_users]

                    # If we know the owner and others can access
                    if expected_owner is not None:
                        unauthorized_users = [u for u in accessing_users if u != expected_owner]
                        if unauthorized_users:
                            results["vulnerable"] = True
                            results["access_violations"] += 1
                            path_hash = hashlib.sha256(f"{path}:crossuser:multi".encode()).hexdigest()[:8]
                            results["findings"].append({
                                "id": f"bola_multi:{path_hash}",
                                "tool": "bola_multi_user",
                                "title": f"BOLA: Unauthorized cross-user access at {path}",
                                "severity": "high",
                                "evidence": {
                                    "url": url,
                                    "resource_id": resource_id,
                                    "expected_owner": f"user_{expected_owner}",
                                    "unauthorized_users": [f"user_{u}" for u in unauthorized_users],
                                    "accessing_users": [f"user_{u}" for u in accessing_users],
                                },
                                "description": f"Users {unauthorized_users} can access resource owned by user_{expected_owner}.",
                                "remediation": "Implement object-level authorization. Verify resource ownership.",
                                "cwe": "CWE-639",
                                "owasp": "API1:2023 - Broken Object Level Authorization",
                            })
                    else:
                        # No ownership defined, flag as potential BOLA
                        path_hash = hashlib.sha256(f"{path}:shared:multi".encode()).hexdigest()[:8]
                        results["findings"].append({
                            "id": f"bola_multi_potential:{path_hash}",
                            "tool": "bola_multi_user",
                            "title": f"Potential BOLA: Multiple users access same resource at {path}",
                            "severity": "medium",
                            "evidence": {
                                "url": url,
                                "resource_id": resource_id,
                                "accessing_users": [f"user_{u}" for u in accessing_users],
                                "responses_identical": True,
                            },
                            "description": f"{len(successful_users)} users can access the same resource. Verify this is intended.",
                            "remediation": "Review access control to ensure only authorized users can access.",
                            "cwe": "CWE-639",
                            "owasp": "API1:2023 - Broken Object Level Authorization",
                        })

    return results


async def check_bola_enumeration(
    base_url: str,
    endpoint_template: str,
    user_session: Any,
    id_range: tuple[int, int] = (1, 100),
    batch_size: int = 20,
    timeout: int = 10,
) -> dict[str, Any]:
    """
    Test for BOLA via ID enumeration attack.

    Systematically tests a range of resource IDs to find accessible resources
    that may not belong to the authenticated user.

    Args:
        base_url: Target base URL
        endpoint_template: Endpoint with {id} placeholder (e.g., "/api/users/{id}")
        user_session: Authenticated session
        id_range: Range of IDs to test (start, end)
        batch_size: Number of concurrent requests per batch
        timeout: Request timeout

    Returns:
        Dictionary with findings and enumerated resources
    """
    from .proof_of_exploit import fetch_with_capture

    results = {
        "vulnerable": False,
        "findings": [],
        "accessible_ids": [],
        "total_tested": 0,
        "access_rate": 0.0,
    }

    def build_headers(session):
        headers = {}
        if session is None:
            return headers
        if hasattr(session, 'config'):
            headers.update(session.config.headers or {})
            if session.config.cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in session.config.cookies.items())
                headers["Cookie"] = cookie_str
        elif hasattr(session, 'export_session'):
            exported = session.export_session()
            headers.update(exported.get("headers", {}))
            cookies = exported.get("cookies", {})
            if cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        return headers

    headers = build_headers(user_session)
    start_id, end_id = id_range

    async def test_id(resource_id: int) -> tuple[int, bool, int]:
        """Test a single ID and return (id, accessible, body_length)."""
        path = endpoint_template.replace("{id}", str(resource_id))
        url = urljoin(base_url, path)
        try:
            response = await fetch_with_capture(url, headers=headers, timeout=timeout)
            status = response.get("status_code", 0)
            body = response.get("body", "")
            accessible = status == 200 and len(body) > 50
            return resource_id, accessible, len(body)
        except Exception:
            return resource_id, False, 0

    # Test in batches
    for batch_start in range(start_id, end_id + 1, batch_size):
        batch_end = min(batch_start + batch_size, end_id + 1)
        batch_ids = range(batch_start, batch_end)

        tasks = [test_id(rid) for rid in batch_ids]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in batch_results:
            if isinstance(result, Exception):
                continue
            resource_id, accessible, body_len = result
            results["total_tested"] += 1
            if accessible:
                results["accessible_ids"].append(resource_id)

    # Calculate access rate
    if results["total_tested"] > 0:
        results["access_rate"] = len(results["accessible_ids"]) / results["total_tested"]

    # Report if high access rate (suggests broken authorization)
    if len(results["accessible_ids"]) > 5 and results["access_rate"] > 0.3:
        results["vulnerable"] = True
        path_hash = hashlib.sha256(f"{endpoint_template}:enumeration".encode()).hexdigest()[:8]
        results["findings"].append({
            "id": f"bola_enum:{path_hash}",
            "tool": "bola_enumeration",
            "title": f"BOLA: Mass resource access via enumeration at {endpoint_template}",
            "severity": "high",
            "evidence": {
                "endpoint": endpoint_template,
                "ids_tested": results["total_tested"],
                "ids_accessible": len(results["accessible_ids"]),
                "access_rate": f"{results['access_rate']:.1%}",
                "sample_accessible_ids": results["accessible_ids"][:10],
            },
            "description": f"User can access {len(results['accessible_ids'])} resources ({results['access_rate']:.1%} of tested). Possible missing authorization.",
            "remediation": "Implement object-level authorization. Verify resource ownership before returning data.",
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
