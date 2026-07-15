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
import base64
import hashlib
import json
import re
import time
import urllib.parse
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .common import run, detect_spa_catch_all, fetch_homepage_hash, is_same_as_homepage, _compute_content_hash
from .cancellation import scanner_cancel_requested
from .bola_comparison import (
    all_responses_equivalent,
    extract_user_specific_signals,
    normalize_response_body,
    response_similarity,
    responses_equivalent,
)

FORCED_BROWSING_MAX_BODY_BYTES = 262_144


def _mark_cooperative_cancel(results: dict[str, Any]) -> bool:
    if not scanner_cancel_requested():
        return False
    results["cancelled"] = True
    results["budget_exceeded"] = True
    results["budget_exhausted_reason"] = "cancelled"
    return True

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
    "rest_api_models": {
        # Auto-CRUD model collections are only a vuln when the unauthenticated
        # response actually leaks sensitive records — a public /api/Products
        # catalog returning 200 JSON is NOT a finding. Require sensitive PII /
        # credential / token field markers so this stays precise and universal
        # (no app-specific knowledge), and reject SPA HTML shells outright.
        "required_patterns": [
            '"email"', '"password"', '"passwordhash"', '"pwd"', '"ssn"',
            '"token"', '"accesstoken"', '"apikey"', '"api_key"', '"secret"',
            '"creditcard"', '"cardnumber"', '"cvv"', '"iban"', '"totpsecret"',
            '"role":"admin"', '"isadmin"', '"is_admin"', '"privatekey"',
            '"securityanswer"', '"sessionid"', '"refreshtoken"',
        ],
        "min_matches": 1,
        "reject_html_always": True,
        "reject_html_content_type": True,
        "always_validate": True,
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
        # Unambiguous debug/actuator/prometheus/dev-server signatures: any ONE confirms a
        # real debug endpoint. The generic JSON tokens in required_patterns above (e.g.
        # "status":, _count, _total) also match ordinary API / JSON-catch-all bodies, so
        # they no longer validate on a single match (min_matches is 2) and only a strong
        # signature short-circuits — preventing a false HIGH exposure on {"status":"ok"}.
        "strong_signature_patterns": [
            "# help", "# type", "_bucket",
            '"beans":', '"mappings":', '"configprops":', '"components":',
            "hot module", "__webpack_hmr", "webpackhotupdate",
            "__nextjs_original-stack-frame", "next-router-state-tree",
            "v8.serialize",
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
        "min_matches": 2,
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

    # Unambiguous signatures validate on a single match; the generic tokens in
    # required_patterns need min_matches (so a JSON catch-all body like {"status":"ok"}
    # with one loose token does not become a false HIGH exposure).
    strong_signatures = validator.get("strong_signature_patterns", [])
    if strong_signatures and any(p in body_lower for p in strong_signatures):
        return True, "strong_signature_match"

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


_PROMETHEUS_SENSITIVE_METRIC_TOKENS = {
    "identity": {"user", "users", "account", "accounts", "customer", "customers", "tenant", "tenants"},
    "commerce": {
        "order", "orders", "payment", "payments", "wallet", "wallets", "balance", "balances",
        "transaction", "transactions", "revenue", "invoice", "invoices",
    },
    "security": {
        "auth", "login", "logins", "token", "tokens", "credential", "credentials", "secret", "secrets",
        "challenge", "challenges",
    },
}
_PROMETHEUS_RUNTIME_METRIC_PREFIXES = (
    "process_",
    "nodejs_",
    "go_",
    "python_",
    "jvm_",
    "dotnet_",
    "runtime_",
    "system_",
    "http_",
    "promhttp_",
    "scrape_",
)


def _prometheus_sensitive_metric_signal(body: str, content_type: str) -> dict[str, Any] | None:
    """Identify business-sensitive metric names without claiming value disclosure."""
    sample = str(body or "")[:262144]
    ct_lower = str(content_type or "").lower()
    if not sample or (
        "text/plain" not in ct_lower
        and "openmetrics" not in ct_lower
        and not ("# help " in sample.lower() and "# type " in sample.lower())
    ):
        return None

    metric_names: set[str] = set()
    for line in sample.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z_:][A-Za-z0-9_:]*)\s*(?:\{|\s)", line)
        if match:
            metric_names.add(match.group(1).lower())

    matched_by_category: dict[str, list[str]] = {}
    for category, tokens in _PROMETHEUS_SENSITIVE_METRIC_TOKENS.items():
        matches = sorted({
            name
            for name in metric_names
            if not name.startswith(_PROMETHEUS_RUNTIME_METRIC_PREFIXES)
            if set(filter(None, re.split(r"[^a-z0-9]+", name))) & tokens
        })
        if matches:
            matched_by_category[category] = matches[:10]

    matched_names = sorted({name for names in matched_by_category.values() for name in names})
    if len(matched_by_category) < 2 or len(matched_names) < 3:
        return None
    return {
        "signal_type": "sensitive_metric_names_exposed",
        "proof_state": "observed",
        "sensitive_metric_categories": sorted(matched_by_category),
        "sensitive_metric_names": matched_names[:20],
        "sensitive_metric_count": len(matched_names),
    }

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
    # Auto-CRUD REST model collections, case-sensitive. Frameworks that auto-expose
    # ORM models as REST endpoints (Express/loopback, Sails Blueprints, Feathers,
    # LoopBack, NestJS CRUD, Strapi) route on the EXACT model class name, so the
    # lowercase /api/users above never matches a PascalCase /api/Users collection.
    # A 200 JSON record array on any of these = anonymous bulk read of admin-only
    # data (BFLA / function-level access control). This is a generic technology
    # wordlist, not app-specific: common model names + case variants.
    "rest_api_models": [
        "/api/Users", "/api/User", "/api/Accounts", "/api/Customers",
        "/api/Orders", "/api/Products", "/api/Cards", "/api/Payments",
        "/api/Addresses", "/api/Feedbacks", "/api/Reviews", "/api/Messages",
        "/api/Files", "/api/Documents", "/api/Tokens", "/api/Sessions",
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
        if category in ["admin_panels", "sensitive_files"]:
            return "critical"
        elif category in ["api_endpoints", "user_management", "management_consoles", "debug_dev"] or category in ["backup_files", "logs_monitoring", "rest_api_models"]:
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
                    finding["validation_reason"] = validation_reason

                    if not is_valid_content:
                        # Content doesn't match what we expect for this category
                        is_soft_404 = True
                        finding["content_validation_failed"] = True
                        finding["validation_reason"] = validation_reason
                    elif category == "debug_dev":
                        sensitive_metrics = _prometheus_sensitive_metric_signal(body, content_type)
                        if sensitive_metrics:
                            finding.update(sensitive_metrics)

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
    spa_content_only = False
    try:
        spa_result = await detect_spa_catch_all(url, timeout=timeout_per_request)
        if spa_result.get("is_spa_catch_all"):
            results["spa_detected"] = True
            results["spa_evidence"] = spa_result.get("evidence", {})
            # Do NOT skip entirely (that silently hid /metrics, /actuator/*, and
            # other real exposures on every Angular/React app). A validated
            # Prometheus/actuator/JSON body provably is NOT the SPA shell, so we
            # restrict to the content-validated categories and let
            # test_single_path's content validation + homepage-hash guard reject
            # the shell. Genuinely-exposed endpoints still surface as verified.
            spa_content_only = True
    except Exception:
        pass  # Continue with checks if SPA detection fails

    # ENHANCED: Fetch homepage hash for catch-all detection
    # Even if SPA detection didn't trigger, we compare responses to homepage
    homepage_hash = None
    try:
        homepage_hash = await fetch_homepage_hash(url, timeout=timeout_per_request)
    except Exception:
        pass  # Continue without homepage comparison if fetch fails

    # Determine which categories to test.
    selected_categories = list(categories) if categories else list(PRIVILEGED_PATHS.keys())
    if spa_content_only:
        # Under an SPA catch-all, only categories with a strict content validator
        # can be told apart from the app shell — restrict to those so we don't
        # re-introduce the 200-everywhere false-positive flood.
        selected_categories = [c for c in selected_categories if c in CATEGORY_CONTENT_VALIDATORS]

    paths_to_test = []
    for cat in selected_categories:
        if cat in PRIVILEGED_PATHS:
            paths_to_test.extend(PRIVILEGED_PATHS[cat])
            results["categories_tested"].append(cat)

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
                "accessible": fb_finding.get("accessible", False),
                # `content_validated` records that response shape passed our FP
                # filters; it is NOT exploit confirmation. The DAST precision
                # policy keeps these as suspected leads until POE or AI review
                # actually proves the resource is sensitive.
                "content_validated": bool(
                    fb_finding.get("accessible")
                    and not fb_finding.get("false_positive_detected")
                    and not fb_finding.get("content_validation_failed")
                ),
                "validation_reason": (
                    fb_finding.get("validation_reason")
                    or "Forced browsing content validation accepted this response"
                ),
                "proof_type": fb_finding.get("proof_type"),
                "proof_state": fb_finding.get("proof_state"),
                "signal_type": fb_finding.get("signal_type"),
                "sensitive_metric_categories": fb_finding.get("sensitive_metric_categories"),
                "sensitive_metric_names": fb_finding.get("sensitive_metric_names"),
                "sensitive_metric_count": fb_finding.get("sensitive_metric_count"),
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
        "endpoint_attempt_schema_version": "active_endpoint_attempt_v1",
        "endpoint_attempts": [],
        "cancelled": False,
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

    expected_parameters = sum(len(params) for params in MASS_ASSIGNMENT_PARAMS.values())
    for endpoint in endpoints:
        if _mark_cooperative_cancel(results):
            break
        url = urljoin(base_url, endpoint)
        results["endpoints_tested"] += 1
        path = urlsplit(url).path or "/"
        attempt = {
            "custom_endpoint": f"POST {path}",
            "family": "mass_assignment",
            "method": "POST",
            "url": url,
            "param_count": expected_parameters,
            "attempted_params_count": 0,
            "completed_params_count": 0,
            "status": "started",
            "proof_observed": False,
        }

        # First, make a baseline request to see if endpoint exists
        baseline = await fetch_with_capture(url, headers=headers, timeout=timeout)
        if baseline.get("status_code", 0) not in [200, 201, 204, 400, 422]:
            attempt["status"] = "skipped"
            attempt["skip_reason"] = "endpoint_not_accessible"
            results["endpoint_attempts"].append(attempt)
            continue  # Endpoint doesn't exist or not accessible

        # Test each category of mass assignment parameters
        for category, params in MASS_ASSIGNMENT_PARAMS.items():
            for param_name, param_value in params:
                if _mark_cooperative_cancel(results):
                    attempt["status"] = "partial"
                    attempt["cancelled"] = True
                    attempt["skip_reason"] = "cancelled"
                    attempt["budget_exhausted_reason"] = "cancelled"
                    results["endpoint_attempts"].append(attempt)
                    return results
                results["parameters_tested"] += 1
                attempt["attempted_params_count"] += 1

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
                attempt["completed_params_count"] += 1

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
                                attempt["proof_observed"] = True
                                attempt.setdefault("proof_types", []).append(
                                    "observed_privilege_field_acceptance"
                                )
                                break  # Found for this param, move to next

        attempt["status"] = (
            "completed"
            if attempt["completed_params_count"] == attempt["attempted_params_count"]
            else "partial"
        )
        results["endpoint_attempts"].append(attempt)

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
        """Snapshot auth headers + cookies for a session.

        Merges `state.cookies_received` (cookies the server set on us during
        login or earlier crawl) with `config.cookies` (operator-supplied
        cookies). Many targets only issue the real session cookie after the
        form-login redirect, so omitting state.cookies_received would send
        BOLA requests with no session — every response would be 401/403 and
        all BOLA findings would be false negatives.
        """
        headers = {}
        if session and hasattr(session, 'config'):
            headers.update(session.config.headers or {})
            cookies = dict(session.config.cookies or {})
            state = getattr(session, "state", None)
            if state is not None:
                cookies.update(getattr(state, "cookies_received", None) or {})
            if cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                headers["Cookie"] = cookie_str
        return headers

    for endpoint_config in resource_endpoints:
        path_template = endpoint_config.get("path", "")
        ids_to_test = endpoint_config.get("ids", ["1", "2"])
        endpoint_no_auth_candidates: list[dict[str, Any]] = []
        endpoint_no_auth_statuses: set[int] = set()
        endpoint_no_auth_fingerprints: set[str] = set()

        for resource_id in ids_to_test:
            # Replace {id} placeholder with actual ID
            path = path_template.replace("{id}", str(resource_id))
            url = urljoin(base_url, path)
            results["endpoints_tested"] += 1

            # Rebuild headers per request so a mid-loop re-authentication
            # (cookies/Authorization mutated by AuthSession._adopt_session)
            # is actually applied. Snapshotting once meant the rest of the
            # BOLA loop kept sending stale cookies after any session refresh.
            user1_headers = build_headers(user1_session)
            user2_headers = build_headers(user2_session)

            # Test without auth (should fail)
            no_auth_response = await fetch_with_capture(url, timeout=timeout, budget_key="bola")

            # Test with user1's auth
            user1_response = await fetch_with_capture(url, headers=user1_headers, timeout=timeout, budget_key="bola") if user1_headers else None

            # Test with user2's auth
            user2_response = await fetch_with_capture(url, headers=user2_headers, timeout=timeout, budget_key="bola") if user2_headers else None

            # Analysis:
            # 1. If no-auth gets 200 with data = public endpoint or broken auth
            # 2. If user1 gets 200 and user2 gets 200 with SAME data = potential BOLA
            # 3. If user1 gets 200 for resource they don't own = BOLA

            no_auth_status = no_auth_response.get("status_code", 0)
            no_auth_body = no_auth_response.get("body", "")
            endpoint_no_auth_statuses.add(no_auth_status)

            # Check if unauthenticated access returns data
            if no_auth_status == 200 and len(no_auth_body) > 50:
                # Check if it looks like actual data (not error/login page)
                if not any(x in no_auth_body.lower() for x in ["login", "sign in", "authenticate", "unauthorized"]):
                    endpoint_no_auth_candidates.append(
                        {
                            "url": url,
                            "path": path,
                            "resource_id": resource_id,
                            "status_code": no_auth_status,
                            "body": no_auth_body,
                        }
                    )
                    endpoint_no_auth_fingerprints.add(_response_body_fingerprint(no_auth_body))

            # If we have both user sessions, check cross-user access
            if user1_response and user2_response:
                user1_status = user1_response.get("status_code", 0)
                user2_status = user2_response.get("status_code", 0)
                user1_body = user1_response.get("body", "")
                user2_body = user2_response.get("body", "")

                # Both users can access - potential BOLA if they shouldn't both have access
                if user1_status == 200 and user2_status == 200:
                    # Equivalence after masking per-request volatile fields
                    # (CSRF/timestamps/request-ids) so a genuine BOLA isn't
                    # missed when the two requests differ only in those.
                    if len(user1_body) > 50 and responses_equivalent(user1_body, user2_body):
                        # Cross-user-equivalent alone can't distinguish BOLA
                        # from shared/public data, so require concrete
                        # user-specific data in the response and emit this as
                        # a suspected lead for verification rather than a
                        # confirmed finding.
                        user_signals = extract_user_specific_signals(user1_body)
                        if user_signals:
                            similarity = response_similarity(user1_body, user2_body)
                            path_hash = hashlib.sha256(f"{path}:crossuser".encode()).hexdigest()[:8]
                            results["findings"].append({
                                "id": f"bola_potential:{path_hash}",
                                "tool": "bola_check",
                                "title": f"Potential BOLA: Both users access same resource at {path}",
                                "severity": "medium",
                                "suspected": True,
                                "needs_verification": True,
                                "verification_reason": (
                                    "Two users received equivalent user-specific data for the same "
                                    "resource ID; confirm the second user does not own the resource."
                                ),
                                "confidence": 0.55,
                                "evidence": {
                                    "url": url,
                                    "resource_id": resource_id,
                                    "user1_status": user1_status,
                                    "user2_status": user2_status,
                                    "responses_equivalent": True,
                                    "response_similarity": round(similarity, 3),
                                    "user_specific_signals": user_signals[:8],
                                },
                                "description": f"Both test users received equivalent user-specific data at {path}. This may indicate missing object-level authorization.",
                                "remediation": "Verify that users can only access resources they own. Implement object-level authorization checks.",
                                "cwe": "CWE-639",
                                "owasp": "API1:2023 - Broken Object Level Authorization",
                            })

        if endpoint_no_auth_candidates:
            sample = endpoint_no_auth_candidates[0]
            sample_body = sample.get("body", "")
            id_sensitive = _id_parameter_affects_response(
                status_codes=endpoint_no_auth_statuses,
                body_fingerprints=endpoint_no_auth_fingerprints,
                total_ids_tested=len(ids_to_test),
            )
            looks_like_resource = _looks_like_bola_resource_response(path_template, sample_body)

            if id_sensitive and looks_like_resource:
                results["vulnerable"] = True
                results["access_violations"] += 1
                path_hash = hashlib.sha256(f"{path_template}:noauth".encode()).hexdigest()[:8]
                successful_ids = [item["resource_id"] for item in endpoint_no_auth_candidates]
                results["findings"].append({
                    "id": f"bola:{path_hash}",
                    "tool": "bola_check",
                    "title": f"BOLA: Unauthenticated access to {path_template}",
                    "severity": "critical",
                    "evidence": {
                        "url": sample.get("url"),
                        "successful_ids": successful_ids[:10],
                        "successful_count": len(successful_ids),
                        "status_codes_observed": sorted(endpoint_no_auth_statuses),
                        "distinct_response_fingerprints": len(endpoint_no_auth_fingerprints),
                        "response_length": len(sample_body),
                        "response_snippet": sample_body[:300],
                    },
                    "description": (
                        "Endpoint appears to expose object/resource data without authentication "
                        "and response behavior changes across tested IDs."
                    ),
                    "remediation": "Implement authentication and object-level authorization checks.",
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
    (r'[?&]id=(\d+)', 'query_numeric_id'),   # ?id=123
    (r'[?&]id=([a-f0-9-]{36})', 'query_uuid'),  # ?id=uuid
    (r'[?&][^=&]*id[^=&]*=(\d+)', 'query_numeric_id'),  # ?vehicleId=123
    (r'[?&][^=&]*id[^=&]*=([a-f0-9-]{36})', 'query_uuid'),  # ?vehicleId=uuid
    (r'[?&][^=&]*id[^=&]*=([a-f0-9]{24})', 'query_mongodb_id'),  # ?objectId=...
]

# Patterns for detecting REST collection endpoints
COLLECTION_ENDPOINT_PATTERNS = [
    r'^(https?://[^/]+)?(/(?:[^/?]+/)*?(?:api|rest)(?:/v\d+)?/[A-Za-z][A-Za-z0-9_-]+(?:s|es|ies))/?$',
    r'^(https?://[^/]+)?(/(?:[^/?]+/)*?(?:api|rest)(?:/v\d+)?/[A-Za-z][A-Za-z0-9_-]+)/?$',
    r'^(https?://[^/]+)?(/v\d+/[A-Za-z][A-Za-z0-9_-]+(?:s|es|ies))/?$',
    r'^(https?://[^/]+)?(/(?:[^/?]+/)*?(?:api|rest)(?:/v\d+)?/[^/]+/\d+/[A-Za-z][A-Za-z0-9_-]+(?:s|es|ies))/?$',
]

COLLECTION_EXCLUSIONS = [
    '/api/docs', '/api/schema', '/api/health', '/api/status',
    '/swagger', '/openapi', '/graphql', '/metrics',
    '.js', '.css', '.html', '.json', '.xml', '.yaml',
]

DEFAULT_SYNTH_IDS = ['1', '2', '3', '100', '999']
QUERY_ID_PARAM_EXCLUSIONS = ['token', 'session', 'csrf']
SYNTH_PATH_SEGMENT_EXCLUSIONS = {
    "auth",
    "login",
    "signin",
    "sign-in",
    "logout",
    "signout",
    "token",
    "session",
    "sessions",
    "register",
    "signup",
    "forgot",
    "reset",
    "oauth",
    "callback",
    "mfa",
    "otp",
    "sso",
}

BOLA_RESOURCE_PATH_SEGMENTS = {
    "user", "users", "account", "accounts", "profile", "profiles",
    "order", "orders", "invoice", "invoices", "document", "documents",
    "file", "files", "message", "messages", "payment", "payments",
    "cart", "carts", "basket", "baskets", "customer", "customers",
    "member", "members", "tenant", "tenants", "project", "projects",
    "organization", "organizations", "org", "company", "companies",
    # Vulnerable-app/API resource names observed in Juice Shop, crAPI, and
    # similar REST labs. These should influence only object-resource heuristics,
    # not operational endpoints such as health/rate-limit.
    "address", "addresses", "addresss", "card", "cards", "wallet", "wallets",
    "vehicle", "vehicles", "mechanic", "mechanics", "report", "reports",
    "service", "services", "shop", "shops", "item", "items", "product",
    "products", "review", "reviews", "feedback", "complaint", "complaints",
    "post", "posts", "comment", "comments", "video", "videos", "coupon",
    "coupons",
}

BOLA_OPERATIONAL_PATH_SEGMENTS = {
    "health", "healthz", "status", "metrics", "ping", "ready", "live",
    "version", "heartbeat", "uptime", "rate-limit", "ratelimit",
    "throttle", "csrf", "captcha", "swagger", "openapi", "docs",
}

BOLA_OPERATIONAL_KEYS = {
    "used", "limit", "remaining", "reset", "resetat", "reset_at",
    "retry_after", "window", "window_seconds", "status", "ok", "success",
    "message", "timestamp", "time", "server_time", "now", "uptime",
    "healthy", "health", "code",
}

BOLA_RESOURCE_STRONG_KEYS = {
    "user_id", "userid", "owner_id", "ownerid", "account_id", "accountid",
    "email", "username", "profile", "order_id", "orderid", "invoice_id",
    "invoiceid", "document_id", "documentid", "payment_id", "paymentid",
    "customer_id", "customerid", "member_id", "memberid",
    "vehicle_id", "vehicleid", "vin", "address_id", "addressid",
    "basket_id", "basketid", "cart_id", "cartid",
}

BOLA_JSON_ENVELOPE_KEYS = {
    "id", "status", "message", "code", "ok", "success", "data", "result", "errors",
}

AUTHZ_PRODUCER_STRONG_SEGMENTS = {
    "me", "dashboard", "profile", "profiles", "account", "accounts",
    "user", "users", "customer", "customers", "member", "members",
    "order", "orders", "invoice", "invoices", "payment", "payments",
    "basket", "baskets", "cart", "carts", "address", "addresses", "addresss",
    "wallet", "wallets", "vehicle", "vehicles", "garage", "garages",
    "service", "services", "booking", "bookings", "appointment", "appointments",
    "report", "reports", "complaint", "complaints", "message", "messages",
    "conversation", "conversations", "thread", "threads", "post", "posts",
    "comment", "comments",
}

AUTHZ_PRODUCER_LOW_VALUE_SEGMENTS = {
    "auth", "login", "logout", "signin", "signup", "register", "token",
    "session", "sessions", "csrf", "captcha", "swagger", "openapi", "docs",
    "health", "status", "metrics", "version", "info", "static", "assets",
    "images", "files", "uploads", "download", "downloads", "search",
    "products", "product", "category", "categories", "catalog", "popular",
    "recommended", "trending", "featured",
}


def _collect_json_keys(value: Any, depth: int = 0, max_depth: int = 2) -> set[str]:
    """Collect lowercase JSON keys from nested objects."""
    if depth > max_depth:
        return set()

    keys: set[str] = set()

    if isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(key, str):
                keys.add(key.lower())
            keys.update(_collect_json_keys(nested, depth=depth + 1, max_depth=max_depth))
    elif isinstance(value, list):
        for nested in value[:5]:
            keys.update(_collect_json_keys(nested, depth=depth + 1, max_depth=max_depth))

    return keys


def _extract_json_keys(body: str) -> set[str]:
    if not body:
        return set()
    try:
        parsed = json.loads(body)
    except Exception:
        return set()
    return _collect_json_keys(parsed)


BOLA_RESOURCE_ID_KEYS = {
    "id", "_id", "uuid", "uid", "object_id", "objectid",
    "user_id", "userid", "owner_id", "ownerid", "account_id", "accountid",
    "customer_id", "customerid", "member_id", "memberid", "order_id", "orderid",
    "invoice_id", "invoiceid", "document_id", "documentid", "payment_id",
    "paymentid", "vehicle_id", "vehicleid", "address_id", "addressid",
    "basket_id", "basketid", "cart_id", "cartid", "product_id", "productid",
    "vin", "vehicle_vin", "vehiclevin", "vin_number", "vinnumber",
    "license_plate", "licenseplate",
}

BOLA_SENSITIVE_FIELD_KEYS = {
    "email", "username", "phone", "mobile", "mobile_num", "mobilenum",
    "address", "street", "zip", "postal_code", "vin", "license_plate",
    "card", "card_number", "credit_card", "token", "jwt", "secret",
    "api_key", "apikey", "password", "ssn", "dob", "balance", "amount",
}


def _parse_json_body(body: str) -> Any | None:
    if not body:
        return None
    try:
        return json.loads(body)
    except Exception:
        return None


def _is_json_like_response(response: dict[str, Any] | None) -> bool:
    if not response:
        return False
    body = str(response.get("body") or "")
    if not body:
        return False
    if _parse_json_body(body) is not None:
        return True
    content_type = ""
    headers = response.get("headers") or {}
    if isinstance(headers, dict):
        content_type = str(headers.get("content-type") or headers.get("Content-Type") or "").lower()
    return "json" in content_type


def _flatten_json_objects(value: Any, *, depth: int = 0, max_depth: int = 4) -> list[dict[str, Any]]:
    """Return object dictionaries from a JSON value without traversing unbounded payloads."""
    if depth > max_depth:
        return []
    objects: list[dict[str, Any]] = []
    if isinstance(value, dict):
        objects.append(value)
        for nested in list(value.values())[:40]:
            objects.extend(_flatten_json_objects(nested, depth=depth + 1, max_depth=max_depth))
    elif isinstance(value, list):
        for nested in value[:80]:
            objects.extend(_flatten_json_objects(nested, depth=depth + 1, max_depth=max_depth))
    return objects


def _safe_scalar_id(value: Any) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate or len(candidate) > 128:
            return None
        lowered = candidate.lower()
        if lowered in {"true", "false", "null", "undefined", "nan"}:
            return None
        if candidate.isdigit():
            return candidate
        import re
        if re.fullmatch(r"[a-f0-9]{24}", candidate, re.IGNORECASE):
            return candidate
        if re.fullmatch(r"[a-f0-9-]{32,36}", candidate, re.IGNORECASE):
            return candidate
        if re.fullmatch(r"[A-Za-z0-9_-]{8,64}", candidate) and any(ch.isdigit() for ch in candidate):
            return candidate
    return None


def _resource_identifier_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def _is_resource_identifier_name(name: str) -> bool:
    normalized = _resource_identifier_name(name)
    if not normalized:
        return False
    normalized_keys = {_resource_identifier_name(key) for key in BOLA_RESOURCE_ID_KEYS}
    return normalized in normalized_keys or normalized.endswith("id")


def _safe_resource_identifier_value(value: Any, key_name: str) -> str | None:
    scalar = _safe_scalar_id(value)
    if scalar:
        return scalar
    normalized_key = _resource_identifier_name(key_name)
    if normalized_key not in {"vin", "vehiclevin", "vinnumber", "licenseplate"}:
        return None
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not (5 <= len(candidate) <= 32):
        return None
    if not re.fullmatch(r"[A-Za-z0-9_-]+", candidate):
        return None
    if not any(ch.isdigit() for ch in candidate) or not any(ch.isalpha() for ch in candidate):
        return None
    return candidate


def _extract_resource_refs_from_json(body: str) -> list[dict[str, Any]]:
    """Extract generic object IDs and sensitive field names from JSON responses."""
    parsed = _parse_json_body(body)
    if parsed is None:
        return []
    refs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for obj in _flatten_json_objects(parsed):
        if not isinstance(obj, dict):
            continue
        sensitive_fields = sorted(
            str(k) for k in obj.keys()
            if isinstance(k, str) and k.strip().lower() in BOLA_SENSITIVE_FIELD_KEYS
        )
        keys_lower = {str(k).strip().lower(): str(k) for k in obj.keys() if isinstance(k, str)}
        for lowered, original_key in keys_lower.items():
            if not _is_resource_identifier_name(lowered):
                continue
            object_id = _safe_resource_identifier_value(obj.get(original_key), original_key)
            if not object_id:
                continue
            key = (lowered, object_id)
            if key in seen:
                continue
            seen.add(key)
            refs.append({
                "object_id": object_id,
                "object_id_key": original_key,
                "object_id_location": "json",
                "sensitive_fields": sensitive_fields[:12],
            })
    return refs[:100]


def _resource_ids_from_response(body: str) -> set[str]:
    return {ref["object_id"] for ref in _extract_resource_refs_from_json(body) if ref.get("object_id")}


# JSON keys whose value identifies the OWNER of a resource / a principal.
_OWNER_IDENTITY_FIELDS = frozenset({
    "email", "username", "user_name", "user_id", "userid", "owner", "owner_id",
    "ownerid", "sub", "account", "account_id", "accountid", "preferred_username",
})


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    """Best-effort decode of a JWT payload (no signature check — identity read only)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(payload).decode("utf-8", "replace")
        claims = json.loads(decoded)
        return claims if isinstance(claims, dict) else {}
    except Exception:
        return {}


def _principal_identity_values(session: Any) -> set[str]:
    """Stable identity strings for a principal, decoded from its JWT bearer token.

    Returns an empty set for non-JWT/opaque auth (so ownership can't be spoofed into
    a false-confirm — the caller stays at the suspected tier when identity is unknown).
    """
    if session is None:
        return set()
    config = getattr(session, "config", None)
    headers = dict(getattr(config, "headers", None) or {}) if config is not None else {}
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    match = re.match(r"bearer\s+(\S+)", str(auth), re.IGNORECASE)
    if not match:
        return set()
    claims = _decode_jwt_claims(match.group(1))
    values: set[str] = set()
    for key in ("email", "sub", "user_id", "userId", "username", "preferred_username", "name"):
        value = claims.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            values.add(str(value).strip().lower())
    return values


def _owner_identity_values(body: str, limit: int = 40) -> set[str]:
    """Identity values from explicit owner/principal fields in a JSON response."""
    values: set[str] = set()
    if not body:
        return values
    try:
        parsed = json.loads(body)
    except Exception:
        return values

    def _walk(node: Any, depth: int = 0) -> None:
        if depth > 6 or len(values) > limit:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, (str, int)) and str(key).lower().replace("-", "_") in _OWNER_IDENTITY_FIELDS:
                    token = str(value).strip().lower()
                    if token:
                        values.add(token)
                else:
                    _walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node[:20]:
                _walk(item, depth + 1)

    _walk(parsed)
    return values


def _confirm_cross_principal_ownership(
    owner_body: str, owner_session: Any, requester_session: Any
) -> bool:
    """Return a paired-owner identity signal, never standalone authorization proof.

    A response email or owner-like field is not enough to establish that the requester
    lacks access. This helper only confirms that the paired owner's identity is present
    and the requester's is absent. Callers must still retain the suspected tier unless
    they also have an independent listing/expectation differential.
    """
    owner_ident = _principal_identity_values(owner_session)
    requester_ident = _principal_identity_values(requester_session)
    if not owner_ident or not requester_ident or owner_ident == requester_ident:
        return False
    body_idents = _owner_identity_values(owner_body)
    return bool(body_idents & owner_ident) and not bool(body_idents & requester_ident)


def _sensitive_fields_from_body(body: str) -> list[str]:
    parsed = _parse_json_body(body)
    if parsed is None:
        return []
    fields: set[str] = set()
    for obj in _flatten_json_objects(parsed):
        for key in obj.keys():
            if isinstance(key, str) and key.strip().lower() in BOLA_SENSITIVE_FIELD_KEYS:
                fields.add(key)
    return sorted(fields)[:20]


def _path_with_resource_id(base_path: str, object_id: str) -> str:
    path = (base_path or "/").rstrip("/")
    if not path:
        path = "/"
    return f"{path}/{object_id}"


def _collection_item_base_path(base_path: str) -> str | None:
    """Infer an item endpoint from collection-listing routes such as /orders/all."""
    path = (base_path or "/").rstrip("/")
    if not path or path == "/":
        return None
    segments = [segment for segment in path.split("/") if segment]
    if len(segments) < 2:
        return None
    terminal = segments[-1].lower()
    if terminal in {
        "all", "list", "listing", "recent", "history", "past", "mine",
        "my", "owned", "search", "results",
    }:
        parent = "/" + "/".join(segments[:-1])
        if parent != path:
            return parent
    return None


def _normalize_authz_url(base_url: str, raw_url: str) -> str | None:
    if not isinstance(raw_url, str):
        return None
    url = raw_url.strip()
    if not url:
        return None
    if url.startswith("//"):
        url = "https:" + url
    if url.startswith("/"):
        return urljoin(base_url.rstrip("/") + "/", url.lstrip("/"))
    if not url.startswith("http"):
        return urljoin(base_url.rstrip("/") + "/", url)
    return url


def _is_resource_placeholder_segment(segment: str) -> bool:
    text = urllib.parse.unquote(str(segment or "")).strip()
    if not text:
        return False
    lowered = text.lower()
    if lowered in {"{id}", ":id", "<id>", "$id"}:
        return True
    if (text.startswith("{") and text.endswith("}")) or (text.startswith("<") and text.endswith(">")):
        inner = text[1:-1].strip().lower()
        return bool(inner) and _is_resource_identifier_name(inner)
    if text.startswith(":"):
        return _is_resource_identifier_name(text[1:])
    return False


def _replace_discovered_consumer_id(url: str, object_id: str) -> dict[str, Any] | None:
    """Return a concrete replay candidate by applying ``object_id`` to a discovered route."""
    if not object_id:
        return None
    try:
        parsed = urlsplit(url)
    except Exception:
        return None
    if parsed.fragment:
        return None
    path = parsed.path or "/"
    segments = path.split("/")
    changed = False
    object_id_location = "path"
    new_segments: list[str] = []
    for segment in segments:
        if not segment:
            new_segments.append(segment)
            continue
        decoded = urllib.parse.unquote(segment)
        if not changed and (_is_resource_placeholder_segment(segment) or _safe_scalar_id(decoded)):
            new_segments.append(urllib.parse.quote(str(object_id), safe=""))
            changed = True
        else:
            new_segments.append(segment)

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs: list[tuple[str, str]] = []
    query_changed = False
    for key, value in query_pairs:
        value_is_placeholder = _is_resource_placeholder_segment(value)
        value_is_id = bool(_safe_scalar_id(value))
        if not changed and not query_changed and _is_probable_id_param(key) and (value == "" or value_is_placeholder or value_is_id):
            new_pairs.append((key, str(object_id)))
            query_changed = True
            object_id_location = "query"
        else:
            new_pairs.append((key, value))

    if not changed and not query_changed:
        return None

    new_path = "/".join(new_segments) or "/"
    query = urlencode(new_pairs, doseq=True)
    concrete_url = urlunsplit((parsed.scheme, parsed.netloc, new_path, query, ""))
    custom_endpoint = f"GET {new_path}?{query}" if query else f"GET {new_path}"
    return {
        "method": "GET",
        "url": concrete_url,
        "object_id_location": object_id_location,
        "custom_endpoint": custom_endpoint,
        "source": "discovered_consumer_template",
    }


def _authz_consumer_templates(base_url: str, discovered_urls: list[str]) -> list[str]:
    """Select discovered routes that can consume owner object IDs during replay."""
    templates: list[str] = []
    seen: set[str] = set()
    for raw_url in discovered_urls or []:
        url = _normalize_authz_url(base_url, raw_url)
        if not url or url in seen:
            continue
        if any(excl in url.lower() for excl in COLLECTION_EXCLUSIONS):
            continue
        if _has_excluded_synth_path_segment(url):
            continue
        try:
            parsed = urlsplit(url)
        except Exception:
            continue
        if parsed.fragment:
            continue
        path_segments = _bola_path_segments(url)
        if not (path_segments & BOLA_RESOURCE_PATH_SEGMENTS):
            continue
        has_path_id = any(
            _is_resource_placeholder_segment(segment) or bool(_safe_scalar_id(urllib.parse.unquote(segment)))
            for segment in (parsed.path or "").split("/")
            if segment
        )
        has_query_id = any(
            _is_probable_id_param(key) and (value == "" or _is_resource_placeholder_segment(value) or bool(_safe_scalar_id(value)))
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        )
        if not has_path_id and not has_query_id:
            continue
        seen.add(url)
        templates.append(url)
    templates.sort(key=lambda item: (_rank_authz_producer_url(item), len(urlsplit(item).path or "")), reverse=True)
    return templates[:80]


def _resource_replay_candidates(
    producer_url: str,
    ref: dict[str, Any],
    *,
    consumer_templates: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Build read-safe candidate consumer URLs from a producer response reference."""
    object_id = str(ref.get("object_id") or "").strip()
    object_key = str(ref.get("object_id_key") or "id")
    if not object_id:
        return []
    try:
        parsed = urlsplit(producer_url)
    except Exception:
        return []
    base_path = parsed.path or "/"
    host = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    candidates: list[dict[str, Any]] = []
    seen_urls: set[str] = set()

    for template_url in consumer_templates or []:
        candidate = _replace_discovered_consumer_id(template_url, object_id)
        if not candidate:
            continue
        candidate_url = str(candidate.get("url") or "")
        if not candidate_url or candidate_url in seen_urls:
            continue
        candidates.append(candidate)
        seen_urls.add(candidate_url)
        if len(candidates) >= 5:
            break

    path_url = host + _path_with_resource_id(base_path, object_id)
    if path_url not in seen_urls:
        candidates.append({
            "method": "GET",
            "url": path_url,
            "object_id_location": "path",
            "custom_endpoint": f"GET {_path_with_resource_id(base_path, object_id)}",
        })
        seen_urls.add(path_url)

    item_base_path = _collection_item_base_path(base_path)
    if item_base_path:
        item_path = _path_with_resource_id(item_base_path, object_id)
        item_url = host + item_path
        if item_url not in seen_urls:
            candidates.append({
                "method": "GET",
                "url": item_url,
                "object_id_location": "path",
                "custom_endpoint": f"GET {item_path}",
            })
            seen_urls.add(item_url)

    query_pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if not _is_probable_id_param(k)]
    query_key = object_key if _is_probable_id_param(object_key) else "id"
    query_pairs.append((query_key, object_id))
    query = urlencode(query_pairs, doseq=True)
    query_url = urlunsplit((parsed.scheme, parsed.netloc, base_path, query, ""))
    if query_url not in seen_urls:
        candidates.append({
            "method": "GET",
            "url": query_url,
            "object_id_location": "query",
            "custom_endpoint": f"GET {base_path}?{query}",
        })
    return candidates[:6]


def _rank_authz_producer_url(url: str) -> int:
    """Score endpoints by likelihood of producing principal-owned resource IDs."""
    try:
        parsed = urlsplit(url)
    except Exception:
        parsed = urlsplit(str(url or "/"))
    path = parsed.path or "/"
    raw_segments = [segment.lower() for segment in path.split("/") if segment]
    # Treat endpoint names such as ``mechanic_report`` and ``return-order`` as
    # semantic resource tokens. Microservice APIs frequently encode the resource
    # noun in a compound leaf segment, and BOLA producer ranking should not miss
    # those just because the route is not slash-delimited.
    segments = set(raw_segments)
    for segment in raw_segments:
        segments.update(token for token in re.split(r"[-_]+", segment) if token)
    score = 0

    if segments & AUTHZ_PRODUCER_STRONG_SEGMENTS:
        score += 40
    if any(segment in {"api", "rest"} or segment.startswith("v") and segment[1:].isdigit() for segment in segments):
        score += 15
    if parsed.query:
        # Query IDs are useful, but discovered apps often produce many synthetic
        # ?id=1/?username=test variants. Keep them competitive without letting
        # them crowd out concrete service-prefixed collection routes.
        score += 2
    if any(segment.endswith(("s", "es", "ies")) for segment in segments):
        score += 8
    if segments & BOLA_RESOURCE_PATH_SEGMENTS:
        score += 10
    if raw_segments and raw_segments[-1] in {"all", "list", "mine", "owned"} and (segments & BOLA_RESOURCE_PATH_SEGMENTS):
        score += 18

    low_value_hits = segments & AUTHZ_PRODUCER_LOW_VALUE_SEGMENTS
    score -= 15 * len(low_value_hits)
    if _is_operational_only_bola_endpoint(url):
        score -= 40
    if any(excl in url.lower() for excl in COLLECTION_EXCLUSIONS):
        score -= 80
    if _has_excluded_synth_path_segment(url):
        score -= 35
    if any(ch in path for ch in "<>{}"):
        score -= 25

    # Authenticated producer discovery is read-only. GET collection-ish
    # endpoints are better producers than deeply nested guessed leaves.
    depth = len(segments)
    if depth <= 4:
        score += 6
    elif depth >= 8:
        score -= 10

    return score


def _authz_producer_path_key(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except Exception:
        parsed = urlsplit(str(url or ""))
    return parsed.path or str(url or "")


def _select_authz_producers(ranked_producers: list[str], limit: int) -> list[str]:
    """Return a diversified producer list from ranked candidates.

    Discovery commonly creates several query variants for one path. Testing all
    of those before moving on wastes the bounded BOLA budget on repeated 404s and
    can starve real collection producers discovered later in the worklist.
    """
    limit = max(1, int(limit or 1))
    selected: list[str] = []
    selected_set: set[str] = set()
    seen_paths: set[str] = set()

    for url in ranked_producers:
        path_key = _authz_producer_path_key(url)
        if path_key in seen_paths:
            continue
        selected.append(url)
        selected_set.add(url)
        seen_paths.add(path_key)
        if len(selected) >= limit:
            return selected

    for url in ranked_producers:
        if url in selected_set:
            continue
        selected.append(url)
        if len(selected) >= limit:
            break
    return selected


def _is_low_value_authz_producer_url(url: str) -> bool:
    """Return True for read targets unlikely to produce owner-scoped IDs."""
    try:
        parsed = urlsplit(url)
    except Exception:
        parsed = urlsplit(str(url or "/"))
    segments = {segment.lower() for segment in (parsed.path or "/").split("/") if segment}
    if not segments:
        return True
    if _is_operational_only_bola_endpoint(url):
        return True
    auth_flow_segments = {
        "auth", "login", "logout", "signin", "signup", "register", "token",
        "tokens", "session", "sessions", "oauth", "oauth2", "verify",
        "reset-password", "reset", "password", "forgot-password", "mfa",
        "2fa", "otp", "captcha",
    }
    if segments & auth_flow_segments:
        return True
    if segments & {"docs", "swagger", "openapi", "health", "status", "metrics"}:
        return True
    public_catalog_segments = {
        "product", "products", "catalog", "category", "categories",
        "popular", "recommended", "trending", "featured", "search",
    }
    if segments & public_catalog_segments and not (segments & {"order", "orders", "basket", "cart", "wallet"}):
        return True
    if any(ch in (parsed.path or "") for ch in "<>{}"):
        return True
    return False


def _new_authz_endpoint_attempt(
    *,
    producer_endpoint: str,
    consumer_endpoint: str,
    object_id_location: str,
    principal_label: str,
    attacker_label: str,
    property_names: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "custom_endpoint": consumer_endpoint,
        "family": "authz",
        "method": "GET",
        "auth_state": attacker_label,
        "principal_label": attacker_label,
        "source_principal": principal_label,
        "attacker_principal": attacker_label,
        "producer_endpoint": producer_endpoint,
        "consumer_endpoint": consumer_endpoint,
        "object_id_location": object_id_location,
        "property_names_tested": list(property_names or []),
        "proof_type": "cross_principal_replay",
        "param_count": 1,
        "attempted_params_count": 0,
        "completed_params_count": 0,
        "status": "started",
    }


def _authz_write_replay_candidate(candidate: dict[str, Any]) -> dict[str, Any] | None:
    """Build a bounded low-impact write probe from a proven object URL."""
    try:
        parsed = urlsplit(str(candidate.get("url") or ""))
    except Exception:
        return None
    if not parsed.scheme or not parsed.netloc:
        return None
    path = parsed.path or "/"
    query = parsed.query
    custom_endpoint = f"PATCH {path}?{query}" if query else f"PATCH {path}"
    return {
        "method": "PATCH",
        "url": urlunsplit((parsed.scheme, parsed.netloc, path, query, "")),
        "object_id_location": candidate.get("object_id_location") or "unknown",
        "custom_endpoint": custom_endpoint,
        "body": "{}",
    }


def _new_authz_write_attempt(
    *,
    producer_endpoint: str,
    consumer_endpoint: str,
    object_id_location: str,
    principal_label: str,
    attacker_label: str,
    property_names: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "custom_endpoint": consumer_endpoint,
        "family": "authz",
        "method": "PATCH",
        "auth_state": attacker_label,
        "principal_label": attacker_label,
        "source_principal": principal_label,
        "attacker_principal": attacker_label,
        "producer_endpoint": producer_endpoint,
        "consumer_endpoint": consumer_endpoint,
        "object_id_location": object_id_location,
        "property_names_tested": list(property_names or []),
        "proof_type": "write_cross_principal_replay",
        "param_count": 1,
        "attempted_params_count": 0,
        "completed_params_count": 0,
        "status": "started",
    }


def _new_authz_producer_attempt(producer_endpoint: str) -> dict[str, Any]:
    return {
        "custom_endpoint": producer_endpoint,
        "family": "authz",
        "method": "GET",
        "auth_state": "user1,user2",
        "principal_label": "user1,user2",
        "source_principal": "user1",
        "attacker_principal": "user2",
        "producer_endpoint": producer_endpoint,
        "consumer_endpoint": producer_endpoint,
        "object_id_location": "producer_response",
        "property_names_tested": [],
        "proof_type": "resource_producer_discovery",
        "param_count": 2,
        "attempted_params_count": 0,
        "completed_params_count": 0,
        "status": "started",
    }


def _bola_path_segments(url_or_template: str) -> set[str]:
    try:
        path = urlsplit(url_or_template).path.lower()
    except Exception:
        path = str(url_or_template).lower()
    segments: set[str] = set()
    for segment in path.split("/"):
        if not segment:
            continue
        segments.add(segment)
        segments.update(token for token in re.split(r"[-_]+", segment) if token)
    return segments


def _is_operational_only_bola_endpoint(url_or_template: str) -> bool:
    """
    Return True for endpoints that look operational/public by design
    (rate-limit, health, metrics, etc.) and not object-resource oriented.
    """
    segments = _bola_path_segments(url_or_template)
    if not segments:
        return False
    has_resource_segment = bool(segments & BOLA_RESOURCE_PATH_SEGMENTS)
    has_operational_segment = bool(segments & BOLA_OPERATIONAL_PATH_SEGMENTS)
    return has_operational_segment and not has_resource_segment


def _looks_like_bola_resource_response(url_or_template: str, body: str) -> bool:
    """
    Heuristic: true when response appears to represent object/resource data,
    not generic operational metadata.
    """
    if not body:
        return False

    if _is_generic_html_page(body):
        return False

    if _is_operational_only_bola_endpoint(url_or_template):
        return False

    json_keys = _extract_json_keys(body)
    path_segments = _bola_path_segments(url_or_template)
    path_looks_resource = bool(path_segments & BOLA_RESOURCE_PATH_SEGMENTS)

    if json_keys:
        if json_keys.issubset(BOLA_OPERATIONAL_KEYS):
            return False
        if json_keys & BOLA_RESOURCE_STRONG_KEYS:
            return True
        if path_looks_resource:
            non_operational_keys = json_keys - BOLA_OPERATIONAL_KEYS - BOLA_JSON_ENVELOPE_KEYS
            if non_operational_keys:
                return True
            return "id" in json_keys
        return False

    body_lower = body[:5000].lower()
    if any(
        marker in body_lower
        for marker in (
            '"user_id"', '"owner_id"', '"account_id"', '"email"',
            '"username"', '"profile"', '"order_id"', '"invoice_id"',
            '"document_id"', '"payment_id"',
        )
    ):
        return True

    operational_markers = (
        "rate limit", "rate_limit", "rate-limit", '"remaining"',
        '"reset"', '"retry_after"', '"uptime"', '"healthy"',
    )
    if any(marker in body_lower for marker in operational_markers):
        return False

    return path_looks_resource


def _response_body_fingerprint(body: str) -> str:
    if not body:
        return ""
    normalized = normalize_response_body(body)
    return hashlib.sha256(normalized[:4000].encode()).hexdigest()


def _id_parameter_affects_response(
    status_codes: set[int],
    body_fingerprints: set[str],
    total_ids_tested: int,
) -> bool:
    """
    Returns True when response behavior changes across tested IDs.
    For single-ID templates (e.g. UUID-only discoveries), allow analysis.
    """
    if len(status_codes) > 1:
        return True
    if len(body_fingerprints) > 1:
        return True
    return total_ids_tested <= 1


def _is_probable_id_param(param_name: str) -> bool:
    if not param_name or not isinstance(param_name, str):
        return False
    name = param_name.strip()
    if not name:
        return False
    lowered = name.lower()
    if any(excl in lowered for excl in QUERY_ID_PARAM_EXCLUSIONS):
        return False
    return _is_resource_identifier_name(lowered)


def _has_excluded_synth_path_segment(url: str) -> bool:
    """Skip synthetic BOLA URL generation for auth/session-style endpoints."""
    try:
        path = urlsplit(url).path.lower()
    except Exception:
        return False

    segments = [seg for seg in path.split("/") if seg]
    return any(seg in SYNTH_PATH_SEGMENT_EXCLUSIONS for seg in segments)


def synthesize_resource_urls_from_collections(
    discovered_urls: list[str],
    max_collections: int = 20,
    ids_to_test: list[str] | None = None,
    max_synthesized_urls: int | None = 60,
) -> list[str]:
    """
    Synthesize resource URLs from REST collection endpoints.
    /api/BasketItems/ -> /api/BasketItems/1, /api/BasketItems/2, etc.
    """
    import re

    if ids_to_test is None:
        ids_to_test = DEFAULT_SYNTH_IDS

    synthesized = []
    collections_found = []
    try:
        max_urls = max(0, int(max_synthesized_urls)) if max_synthesized_urls is not None else None
    except (TypeError, ValueError):
        max_urls = 60

    for url in discovered_urls:
        if max_urls is not None and len(collections_found) * len(ids_to_test) >= max_urls:
            break
        # Skip if URL already has an ID pattern
        if any(re.search(pattern, url) for pattern, _ in ID_PATTERNS):
            continue

        base_url = url.split("?", 1)[0].split("#", 1)[0]

        # Skip excluded paths
        url_lower = base_url.lower()
        if any(excl in url_lower for excl in COLLECTION_EXCLUSIONS):
            continue
        if _has_excluded_synth_path_segment(base_url):
            continue

        # Check if URL matches collection patterns
        for pattern in COLLECTION_ENDPOINT_PATTERNS:
            if re.match(pattern, base_url, re.IGNORECASE):
                collections_found.append(base_url)
                break

    for collection_url in collections_found[:max_collections]:
        base = collection_url.rstrip('/')
        for test_id in ids_to_test:
            if max_urls is not None and len(synthesized) >= max_urls:
                return synthesized
            synthesized.append(f"{base}/{test_id}")

    return synthesized


def synthesize_query_urls_from_param_endpoints(
    base_url: str,
    param_endpoints: list[dict[str, Any]] | None,
    max_endpoints: int = 20,
    ids_to_test: list[str] | None = None,
) -> list[str]:
    """
    Synthesize query URLs for endpoints that expose ID-like parameters.
    /api/v3/mechanic/mechanic_report?id= -> /api/v3/mechanic/mechanic_report?id=1
    """
    import urllib.parse

    if not param_endpoints:
        return []
    if ids_to_test is None:
        ids_to_test = DEFAULT_SYNTH_IDS

    synthesized = []
    seen_urls = set()
    processed = 0

    for entry in param_endpoints:
        if processed >= max_endpoints:
            break
        if not isinstance(entry, dict):
            continue
        raw_url = entry.get("url")
        params = entry.get("params") or []
        if not raw_url or not isinstance(raw_url, str) or not params:
            continue

        url = raw_url.strip()
        if url.startswith("//"):
            url = "https:" + url
        if url.startswith("/"):
            url = urljoin(base_url, url)
        if not url.startswith("http"):
            url = urljoin(base_url + "/", url)

        url_lower = url.lower()
        if any(excl in url_lower for excl in COLLECTION_EXCLUSIONS):
            continue
        if _has_excluded_synth_path_segment(url):
            continue

        id_params = [p for p in params if _is_probable_id_param(p)]
        if not id_params:
            continue

        parsed = urllib.parse.urlsplit(url)
        base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))

        existing_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        keep_pairs = [(k, v) for k, v in existing_pairs if not _is_probable_id_param(k)]

        id_param = id_params[0]
        for test_id in ids_to_test:
            query_pairs = list(keep_pairs)
            query_pairs.append((id_param, str(test_id)))
            query = urllib.parse.urlencode(query_pairs, doseq=True)
            candidate = f"{base}?{query}" if query else base
            if candidate in seen_urls:
                continue
            synthesized.append(candidate)
            seen_urls.add(candidate)

        processed += 1

    return synthesized


def _bola_custom_endpoint(url: str, method: str = "GET") -> str | None:
    try:
        parsed = urlsplit(url)
    except Exception:
        return None
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    method = (method or "GET").upper()
    return f"{method} {path}?{parsed.query}" if parsed.query else f"{method} {path}"


def _new_bola_endpoint_attempt(url: str, *, test_id_count: int) -> dict[str, Any] | None:
    custom_endpoint = _bola_custom_endpoint(url, "GET")
    if not custom_endpoint:
        return None
    return {
        "custom_endpoint": custom_endpoint,
        "family": "bola",
        "method": "GET",
        "url": url,
        "param_count": max(0, int(test_id_count or 0)),
        "attempted_params_count": 0,
        "completed_params_count": 0,
        "status": "started",
    }


def _finish_bola_endpoint_attempt(
    attempt: dict[str, Any] | None,
    *,
    budget_exceeded: bool = False,
    budget_exhausted_reason: str = "time_budget",
) -> dict[str, Any] | None:
    if not attempt:
        return None
    if budget_exceeded:
        attempt["budget_exhausted"] = True
        attempt["budget_exhausted_reason"] = budget_exhausted_reason
    completed = int(attempt.get("completed_params_count") or 0)
    expected = int(attempt.get("param_count") or 0)
    if completed <= 0:
        attempt["status"] = "partial"
    elif budget_exceeded and expected and completed < expected:
        attempt["status"] = "partial"
    else:
        attempt["status"] = "completed"
    return attempt


SAFE_AUTH_PROBE_METHODS = {"GET", "HEAD"}


def _auth_session_headers(session: Any | None) -> dict[str, str]:
    """Snapshot headers/cookies from an AuthSession-like object."""
    headers: dict[str, str] = {}
    if not session or not hasattr(session, "config"):
        return headers
    headers.update(getattr(session.config, "headers", None) or {})
    cookies = dict(getattr(session.config, "cookies", None) or {})
    state = getattr(session, "state", None)
    if state is not None:
        cookies.update(getattr(state, "cookies_received", None) or {})
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return headers


def _endpoint_auth_probe_candidate(base_url: str, endpoint: Any) -> dict[str, Any] | None:
    """Return a read-only URL + inventory replay key for one discovered endpoint."""
    replay_spec: str | None = None
    if isinstance(endpoint, str):
        raw = endpoint.strip()
        method = "GET"
        parts = raw.split(" ", 1)
        if len(parts) == 2 and parts[0].isalpha():
            method = parts[0].upper()
            raw = parts[1].strip()
            replay_spec = endpoint.strip()
        if " " in raw:
            raw = raw.split(" ", 1)[0].strip()
    elif isinstance(endpoint, dict):
        raw = endpoint.get("url") or endpoint.get("path")
        method = str(endpoint.get("method") or "GET").upper()
        replay_spec = endpoint.get("replay_spec") if isinstance(endpoint.get("replay_spec"), str) else None
    else:
        return None
    if not raw or not isinstance(raw, str):
        return None

    try:
        absolute = raw if "://" in raw else urljoin(base_url.rstrip("/") + "/", raw.lstrip("/"))
        parsed = urlsplit(absolute)
    except Exception:
        return None

    path = parsed.path or "/"
    query = parsed.query
    params: list[str] = []
    if isinstance(endpoint, dict):
        params = [str(p) for p in (endpoint.get("params") or []) if p]
    if not query and params and method in SAFE_AUTH_PROBE_METHODS:
        query = urlencode([(p, "1") for p in params], doseq=True)

    test_url = urlunsplit((parsed.scheme, parsed.netloc, path, query, ""))
    custom_endpoint = replay_spec or (f"{method} {path}?{query}" if query else f"{method} {path}")
    return {
        "method": method,
        "url": test_url,
        "custom_endpoint": custom_endpoint,
        "param_count": max(1, len(params)),
    }


def _new_auth_endpoint_attempt(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "custom_endpoint": candidate["custom_endpoint"],
        "family": "auth",
        "method": candidate["method"],
        "url": candidate["url"],
        "param_count": int(candidate.get("param_count") or 1),
        "attempted_params_count": 0,
        "completed_params_count": 0,
        "status": "started",
    }


def _finish_auth_attempt(
    attempt: dict[str, Any],
    *,
    completed: bool,
    skip_reason: str | None = None,
    error_summary: str | None = None,
    cancelled: bool = False,
) -> dict[str, Any]:
    if cancelled:
        attempt["status"] = "partial" if int(attempt.get("attempted_params_count") or 0) else "skipped"
        attempt["skip_reason"] = "cancelled"
        return attempt
    if skip_reason:
        attempt["status"] = "skipped"
        attempt["skip_reason"] = skip_reason
        return attempt
    if error_summary:
        attempt["status"] = "partial"
        attempt["error_summary"] = error_summary
        return attempt
    attempt["status"] = "completed" if completed else "partial"
    return attempt


def _auth_response_status(response: dict[str, Any]) -> int:
    try:
        return int(response.get("status_code") or 0)
    except (TypeError, ValueError):
        return 0


def _looks_like_login_or_error(body: str) -> bool:
    lowered = (body or "")[:4000].lower()
    markers = (
        "login", "log in", "sign in", "signin", "authenticate",
        "unauthorized", "forbidden", "access denied", "permission denied",
    )
    return any(marker in lowered for marker in markers)


async def _fetch_auth_access_probe(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    cmd = [
        "curl", "-sS",
        "-X", method,
        "-L", "--max-redirs", "5",
        "-k",
        "--max-time", str(timeout),
        "-w", "\n__AUTH_META__%{http_code}__END_AUTH_META__",
    ]
    for name, value in (headers or {}).items():
        cmd.extend(["-H", f"{name}: {value}"])
    cmd.append(url)
    stdout, stderr, rc = await run(cmd, timeout=timeout + 5)
    if rc != 0 and not stdout:
        return {"status_code": 0, "body": "", "headers": {}, "error": stderr or f"curl failed with code {rc}"}
    marker = "\n__AUTH_META__"
    if marker not in stdout:
        return {"status_code": 0, "body": stdout or "", "headers": {}, "error": "missing_status_metadata"}
    body, meta = stdout.rsplit(marker, 1)
    status_raw = meta.split("__END_AUTH_META__", 1)[0]
    try:
        status = int(status_raw)
    except (TypeError, ValueError):
        status = 0
    return {"status_code": status, "body": body, "headers": {}, "error": None}


async def smart_auth_access_test(
    base_url: str,
    endpoints: list[Any],
    auth_session: Any | None = None,
    max_endpoints: int = 50,
    timeout: int = 10,
) -> dict[str, Any]:
    """Focused auth/access-control probe with per-endpoint telemetry.

    The first runnable `auth` family check is intentionally read-only: for each
    claimed GET/HEAD endpoint, compare an authenticated request with a truly
    anonymous request. It reports a finding only when authenticated content
    carrying concrete user-specific signals is reachable anonymously with an
    equivalent response. Other public endpoints simply record completed
    telemetry so ASM coverage is truthful without inflating findings.
    """
    results: dict[str, Any] = {
        "vulnerable": False,
        "findings": [],
        "endpoints_analyzed": 0,
        "anonymous_accessible": 0,
        "auth_required": 0,
        "skipped": 0,
        "endpoint_attempts": [],
        "cancelled": False,
        "budget_exceeded": False,
        "budget_exhausted_reason": None,
    }

    auth_headers = _auth_session_headers(auth_session)
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for endpoint in endpoints or []:
        candidate = _endpoint_auth_probe_candidate(base_url, endpoint)
        if not candidate:
            continue
        key = candidate["custom_endpoint"]
        if key in seen:
            continue
        seen.add(key)
        candidates.append(candidate)
        if len(candidates) >= max(1, int(max_endpoints or 1)):
            break

    for candidate in candidates:
        if _mark_cooperative_cancel(results):
            break
        attempt = _new_auth_endpoint_attempt(candidate)
        method = str(candidate.get("method") or "GET").upper()
        if method not in SAFE_AUTH_PROBE_METHODS:
            results["skipped"] += 1
            results["endpoint_attempts"].append(
                _finish_auth_attempt(attempt, completed=False, skip_reason="unsafe_method_not_tested")
            )
            continue
        if not auth_headers:
            results["skipped"] += 1
            results["endpoint_attempts"].append(
                _finish_auth_attempt(attempt, completed=False, skip_reason="auth_missing")
            )
            continue

        attempt["attempted_params_count"] += 1
        auth_resp = await _fetch_auth_access_probe(
            candidate["url"],
            method=method,
            headers=auth_headers,
            timeout=timeout,
        )
        if _mark_cooperative_cancel(results):
            results["endpoint_attempts"].append(
                _finish_auth_attempt(attempt, completed=False, cancelled=True)
            )
            break
        anon_resp = await _fetch_auth_access_probe(
            candidate["url"],
            method=method,
            timeout=timeout,
        )
        auth_error = auth_resp.get("error")
        anon_error = anon_resp.get("error")
        if auth_error or anon_error:
            error_summary = str(auth_error or anon_error or "request_error")[:200]
            results["endpoint_attempts"].append(
                _finish_auth_attempt(attempt, completed=False, error_summary=error_summary)
            )
            continue

        attempt["completed_params_count"] += 1
        results["endpoints_analyzed"] += 1
        auth_status = _auth_response_status(auth_resp)
        anon_status = _auth_response_status(anon_resp)
        auth_body = str(auth_resp.get("body") or "")
        anon_body = str(anon_resp.get("body") or "")
        if anon_status in {401, 403}:
            results["auth_required"] += 1
        elif 200 <= anon_status < 300:
            results["anonymous_accessible"] += 1

        user_signals = extract_user_specific_signals(auth_body)
        if (
            200 <= auth_status < 300
            and 200 <= anon_status < 300
            and user_signals
            and len(auth_body) > 50
            and len(anon_body) > 50
            and not _looks_like_login_or_error(anon_body)
            and responses_equivalent(auth_body, anon_body)
        ):
            results["vulnerable"] = True
            path_hash = hashlib.sha256(f"{candidate['custom_endpoint']}:anon".encode()).hexdigest()[:8]
            similarity = response_similarity(auth_body, anon_body)
            results["findings"].append({
                "id": f"smart_auth:{path_hash}",
                "tool": "smart_auth",
                "title": f"Authentication bypass: anonymous access to {candidate['custom_endpoint']}",
                "severity": "high",
                "confidence": 0.75,
                "evidence": {
                    "url": candidate["url"],
                    "method": method,
                    "auth_status": auth_status,
                    "anonymous_status": anon_status,
                    "responses_equivalent": True,
                    "response_similarity": round(similarity, 3),
                    "user_specific_signals": user_signals[:8],
                    "response_snippet": anon_body[:300],
                },
                "description": (
                    "An endpoint returned equivalent user-specific content with and without "
                    "authentication. Confirm the endpoint is intended to be public."
                ),
                "remediation": "Require authentication for user-specific resources and add anonymous-access regression tests.",
                "cwe": "CWE-306",
                "owasp": "A01:2021 - Broken Access Control",
            })

        results["endpoint_attempts"].append(_finish_auth_attempt(attempt, completed=True))

    return results


async def authz_resource_replay_test(
    base_url: str,
    discovered_urls: list[str],
    user1_session: Any | None,
    user2_session: Any | None,
    *,
    max_producers: int = 25,
    max_replays: int = 80,
    timeout: int = 10,
    max_seconds: float | None = None,
) -> dict[str, Any]:
    """Auth-aware object authorization check built from real producer responses.

    The check is intentionally read-only. It first fetches collection/resource
    producer endpoints as user1 and user2, extracts object IDs from JSON bodies,
    then lets user2 replay only IDs seen in user1's response but not in user2's
    own producer response. A finding requires deterministic proof: user1 and
    user2 both receive equivalent resource-like data for the same object ID, and
    that ID was absent from user2's producer response.
    """
    from .proof_of_exploit import fetch_with_capture

    started = time.monotonic()

    def _deadline_exceeded() -> bool:
        return bool(max_seconds and max_seconds > 0 and (time.monotonic() - started) >= max_seconds)

    results: dict[str, Any] = {
        "vulnerable": False,
        "findings": [],
        "producers_tested": 0,
        "producer_ids_found": 0,
        "replays_attempted": 0,
        "replays_completed": 0,
        "write_replays_attempted": 0,
        "write_replays_completed": 0,
        "cross_principal_violations": 0,
        "write_cross_principal_violations": 0,
        "budget_exceeded": False,
        "cancelled": False,
        "budget_exhausted_reason": None,
        "resource_map": [],
        "endpoint_attempts": [],
    }

    def _stop_requested() -> bool:
        if _mark_cooperative_cancel(results):
            return True
        if _deadline_exceeded():
            results["budget_exceeded"] = True
            results["budget_exhausted_reason"] = "time_budget_exhausted"
            return True
        return False

    user1_headers = _auth_session_headers(user1_session)
    user2_headers = _auth_session_headers(user2_session)
    if not user1_headers or not user2_headers:
        results["skipped"] = True
        results["reason"] = "multi_user_credentials_required"
        return results
    max_write_replays = max(1, min(20, int(max_replays or 1) // 4 or 1))

    producer_candidates: list[str] = []
    seen: set[str] = set()
    for raw_url in discovered_urls or []:
        url = _normalize_authz_url(base_url, raw_url)
        if not url:
            continue
        if any(excl in url.lower() for excl in COLLECTION_EXCLUSIONS):
            continue
        if _has_excluded_synth_path_segment(url):
            continue
        if _is_low_value_authz_producer_url(url):
            continue
        try:
            parsed = urlsplit(url)
        except Exception:
            continue
        if parsed.fragment:
            continue
        # Producer responses should be read-safe. Keep URL-pattern endpoints
        # too because some APIs expose a single resource that can produce nested IDs.
        custom = _bola_custom_endpoint(url, "GET")
        if not custom or custom in seen:
            continue
        seen.add(custom)
        producer_candidates.append(url)

    consumer_templates = _authz_consumer_templates(base_url, discovered_urls or [])
    results["consumer_template_count"] = len(consumer_templates)
    results["consumer_templates_sample"] = [
        _bola_custom_endpoint(url, "GET") or url for url in consumer_templates[:20]
    ]

    producer_limit = max(1, int(max_producers or 1))
    ranked_pairs = sorted(
        enumerate(producer_candidates),
        key=lambda item: (_rank_authz_producer_url(item[1]), -item[0]),
        reverse=True,
    )
    ranked_producers = [url for _idx, url in ranked_pairs]
    producers = _select_authz_producers(ranked_producers, producer_limit)
    selected_producers = set(producers)
    results["producer_candidate_count"] = len(producer_candidates)
    results["producer_selection_strategy"] = "owned_resource_path_rank_diverse_v2"
    results["producer_candidates_sample"] = [
        {
            "url": url,
            "rank": _rank_authz_producer_url(url),
            "selected": url in selected_producers,
        }
        for url in ranked_producers[: min(20, len(ranked_producers))]
    ]

    for producer_url in producers:
        if _stop_requested():
            break
        results["producers_tested"] += 1
        producer_endpoint = _bola_custom_endpoint(producer_url, "GET") or f"GET {producer_url}"
        producer_attempt = _new_authz_producer_attempt(producer_endpoint)
        producer_attempt["attempted_params_count"] = 1
        try:
            user1_resp = await fetch_with_capture(producer_url, headers=user1_headers, timeout=timeout, budget_key="bola")
            if _mark_cooperative_cancel(results):
                producer_attempt["status"] = "partial"
                producer_attempt["skip_reason"] = "cancelled"
                results["endpoint_attempts"].append(producer_attempt)
                break
            producer_attempt["attempted_params_count"] = 2
            user2_listing_resp = await fetch_with_capture(producer_url, headers=user2_headers, timeout=timeout, budget_key="bola")
        except Exception as exc:
            producer_attempt["status"] = "partial"
            producer_attempt["error_summary"] = str(exc)[:200]
            results["endpoint_attempts"].append(producer_attempt)
            continue
        user1_status = _auth_response_status(user1_resp)
        user2_listing_status = _auth_response_status(user2_listing_resp)
        producer_attempt["completed_params_count"] = 2
        producer_attempt["owner_status"] = user1_status
        producer_attempt["attacker_listing_status"] = user2_listing_status
        if not (200 <= user1_status < 300) or not _is_json_like_response(user1_resp):
            producer_attempt["status"] = "partial"
            producer_attempt["skip_reason"] = "producer_not_json_or_not_accessible"
            results["endpoint_attempts"].append(producer_attempt)
            continue
        user1_body = str(user1_resp.get("body") or "")
        user2_listing_body = str(user2_listing_resp.get("body") or "")
        user1_refs = _extract_resource_refs_from_json(user1_body)
        if not user1_refs:
            producer_attempt["status"] = "completed"
            producer_attempt["resource_ids_found"] = 0
            producer_attempt["skip_reason"] = "no_resource_ids_found"
            results["endpoint_attempts"].append(producer_attempt)
            continue
        producer_attempt["status"] = "completed"
        producer_attempt["resource_ids_found"] = len(user1_refs)
        results["endpoint_attempts"].append(producer_attempt)
        user2_ids = (
            _resource_ids_from_response(user2_listing_body)
            if 200 <= user2_listing_status < 300 and _is_json_like_response(user2_listing_resp)
            else set()
        )
        results["producer_ids_found"] += len(user1_refs)

        for ref in user1_refs:
            if _stop_requested():
                break
            object_id = str(ref.get("object_id") or "")
            if not object_id or object_id in user2_ids:
                continue
            candidates = _resource_replay_candidates(
                producer_url,
                ref,
                consumer_templates=consumer_templates,
            )
            if not candidates:
                continue
            results["resource_map"].append({
                "producer_endpoint": producer_endpoint,
                "object_id_key": ref.get("object_id_key"),
                "object_id_location": ref.get("object_id_location"),
                "source_principal": "user1",
                "excluded_from_principal": "user2",
                "consumer_candidates": [c["custom_endpoint"] for c in candidates],
                "sensitive_fields": ref.get("sensitive_fields") or [],
            })
            for candidate in candidates:
                if _stop_requested():
                    break
                if results["replays_attempted"] >= max(1, int(max_replays or 1)):
                    results["budget_exceeded"] = True
                    results["budget_exhausted_reason"] = "replay_budget_exhausted"
                    break
                attempt = _new_authz_endpoint_attempt(
                    producer_endpoint=producer_endpoint,
                    consumer_endpoint=candidate["custom_endpoint"],
                    object_id_location=candidate["object_id_location"],
                    principal_label="user1",
                    attacker_label="user2",
                    property_names=ref.get("sensitive_fields") or [],
                )
                attempt["attempted_params_count"] = 1
                results["replays_attempted"] += 1
                try:
                    owner_resp = await fetch_with_capture(
                        candidate["url"], headers=user1_headers, timeout=timeout, budget_key="bola"
                    )
                    if _mark_cooperative_cancel(results):
                        attempt["status"] = "partial"
                        attempt["skip_reason"] = "cancelled"
                        results["endpoint_attempts"].append(attempt)
                        break
                    attacker_resp = await fetch_with_capture(
                        candidate["url"], headers=user2_headers, timeout=timeout, budget_key="bola"
                    )
                except Exception as exc:
                    attempt["status"] = "partial"
                    attempt["error_summary"] = str(exc)[:200]
                    results["endpoint_attempts"].append(attempt)
                    continue

                owner_status = _auth_response_status(owner_resp)
                attacker_status = _auth_response_status(attacker_resp)
                owner_body = str(owner_resp.get("body") or "")
                attacker_body = str(attacker_resp.get("body") or "")
                attempt["completed_params_count"] = 1
                attempt["status"] = "completed"
                results["replays_completed"] += 1

                sensitive_fields = sorted(set((ref.get("sensitive_fields") or []) + _sensitive_fields_from_body(attacker_body)))[:20]
                equivalent = (
                    200 <= owner_status < 300
                    and 200 <= attacker_status < 300
                    and len(owner_body) > 20
                    and len(attacker_body) > 20
                    and responses_equivalent(owner_body, attacker_body)
                )
                resource_like = _looks_like_bola_resource_response(candidate["url"], attacker_body)
                user_signals = extract_user_specific_signals(attacker_body)
                # CRITICAL authz-proof guard: confirm the attacker actually received the
                # REQUESTED owner object, not their OWN object echoed back by an
                # id-ignoring endpoint (e.g. Juice Shop /rest/saveLoginIp returns the
                # caller's own profile regardless of ?id=). Such endpoints produce
                # equivalent-looking responses that are NOT cross-principal access:
                # the attacker's body carries their own id (686), not the owner's (685).
                attacker_returned_ids = _resource_ids_from_response(attacker_body)
                if not object_id:
                    owner_object_received = True
                elif attacker_returned_ids:
                    owner_object_received = object_id in attacker_returned_ids
                else:
                    owner_object_received = object_id in attacker_body
                if not owner_object_received:
                    attempt["last_verdict"] = "id_ignored_returned_own_object"
                if equivalent and resource_like and owner_object_received and (user_signals or sensitive_fields):
                    results["vulnerable"] = True
                    results["cross_principal_violations"] += 1
                    path_hash = hashlib.sha256(
                        f"{producer_endpoint}:{candidate['custom_endpoint']}:{object_id}:user2".encode()
                    ).hexdigest()[:10]
                    similarity = response_similarity(owner_body, attacker_body)
                    evidence = {
                        "family": "authz",
                        "method": "GET",
                        "producer_endpoint": producer_endpoint,
                        "consumer_endpoint": candidate["custom_endpoint"],
                        "url": candidate["url"],
                        "source_principal": "user1",
                        "attacker_principal": "user2",
                        "object_id_key": ref.get("object_id_key"),
                        "object_id_location": candidate["object_id_location"],
                        "object_id_absent_from_attacker_listing": True,
                        # Proof that the attacker received the OWNER's object, not their own.
                        "requested_object_id": object_id,
                        "attacker_returned_object_ids": sorted(attacker_returned_ids)[:8],
                        "owner_status": owner_status,
                        "attacker_status": attacker_status,
                        "responses_equivalent": True,
                        "response_similarity": round(similarity, 3),
                        "sensitive_fields": sensitive_fields,
                        "user_specific_signals": user_signals[:8],
                        "authz_diff": {
                            "producer_ids_owner_count": len(user1_refs),
                            "producer_ids_attacker_count": len(user2_ids),
                            "replayed_owner_object_missing_from_attacker_listing": True,
                            "owner_resource_equivalent_to_attacker_resource": True,
                        },
                        "proof_type": "cross_principal_replay",
                        "response_snippet": attacker_body[:300],
                    }
                    results["findings"].append({
                        "id": f"smart_authz:{path_hash}",
                        "tool": "smart_authz",
                        "title": f"Broken object authorization: user2 can access user1 object at {candidate['custom_endpoint']}",
                        "severity": "high",
                        "confidence": 0.82,
                        "severity_rationale": (
                            "High: deterministic cross-principal replay returned equivalent "
                            "resource data for an object ID produced by user1 and absent from "
                            "user2's own producer response."
                        ),
                        "evidence": evidence,
                        "description": (
                            "A resource ID observed in user1's authenticated response was not "
                            "present in user2's own listing, but user2 could replay the object "
                            "endpoint and receive equivalent resource data."
                        ),
                        "remediation": (
                            "Authorize every object read against the requesting principal. "
                            "Add regression tests for cross-user object access."
                        ),
                        "cwe": "CWE-639",
                        "owasp": "API1:2023 - Broken Object Level Authorization",
                    })
                results["endpoint_attempts"].append(attempt)
                if results["cross_principal_violations"] >= 10:
                    return results

                if results["write_replays_attempted"] < max_write_replays:
                    write_candidate = _authz_write_replay_candidate(candidate)
                    if write_candidate:
                        if _mark_cooperative_cancel(results):
                            break
                        write_attempt = _new_authz_write_attempt(
                            producer_endpoint=producer_endpoint,
                            consumer_endpoint=write_candidate["custom_endpoint"],
                            object_id_location=write_candidate["object_id_location"],
                            principal_label="user1",
                            attacker_label="user2",
                            property_names=ref.get("sensitive_fields") or [],
                        )
                        write_attempt["attempted_params_count"] = 1
                        results["write_replays_attempted"] += 1
                        write_headers = dict(user2_headers)
                        write_headers["Content-Type"] = "application/json"
                        try:
                            write_resp = await fetch_with_capture(
                                write_candidate["url"],
                                method=write_candidate["method"],
                                data=write_candidate["body"],
                                headers=write_headers,
                                timeout=timeout,
                                budget_key="bola",
                            )
                        except Exception as exc:
                            write_attempt["status"] = "partial"
                            write_attempt["error_summary"] = str(exc)[:200]
                            results["endpoint_attempts"].append(write_attempt)
                            continue

                        write_status = _auth_response_status(write_resp)
                        write_body = str(write_resp.get("body") or "")
                        write_attempt["completed_params_count"] = 1
                        write_attempt["status"] = "completed"
                        write_attempt["attacker_status"] = write_status
                        results["write_replays_completed"] += 1
                        write_returned_ids = _resource_ids_from_response(write_body)
                        # Require the owner's object id as a STRUCTURED resource id in the write
                        # response, not a bare substring (which also matches error text / unrelated
                        # echoes). Unconfirmed -> not a write finding.
                        write_owner_object_received = bool(write_returned_ids) and object_id in write_returned_ids
                        if not write_owner_object_received:
                            write_attempt["last_verdict"] = "owner_object_not_confirmed_in_write_response"

                        write_resource_like = _looks_like_bola_resource_response(write_candidate["url"], write_body)
                        write_user_signals = extract_user_specific_signals(write_body)
                        # Derive sensitive-field signals from the WRITE response only; inheriting
                        # the earlier GET's sensitive_fields would let a read-derived signal satisfy
                        # the write gate (evidence contamination).
                        write_sensitive_fields = sorted(set(_sensitive_fields_from_body(write_body)))[:20]
                        if (
                            200 <= write_status < 300
                            and write_body
                            and _is_json_like_response(write_resp)
                            and write_resource_like
                            and write_owner_object_received
                            and (write_user_signals or write_sensitive_fields)
                        ):
                            results["vulnerable"] = True
                            results["write_cross_principal_violations"] += 1
                            path_hash = hashlib.sha256(
                                f"{producer_endpoint}:{write_candidate['custom_endpoint']}:{object_id}:user2:write".encode()
                            ).hexdigest()[:10]
                            write_evidence = {
                                "family": "authz",
                                "producer_endpoint": producer_endpoint,
                                "consumer_endpoint": write_candidate["custom_endpoint"],
                                "url": write_candidate["url"],
                                "method": write_candidate["method"],
                                "request_body": write_candidate["body"],
                                "source_principal": "user1",
                                "attacker_principal": "user2",
                                "object_id_key": ref.get("object_id_key"),
                                "object_id_location": write_candidate["object_id_location"],
                                "object_id_absent_from_attacker_listing": True,
                                "requested_object_id": object_id,
                                "attacker_returned_object_ids": sorted(write_returned_ids)[:8],
                                "attacker_status": write_status,
                                "sensitive_fields": write_sensitive_fields,
                                "user_specific_signals": write_user_signals[:8],
                                "authz_diff": {
                                    "producer_ids_owner_count": len(user1_refs),
                                    "producer_ids_attacker_count": len(user2_ids),
                                    "replayed_owner_object_missing_from_attacker_listing": True,
                                    "attacker_write_returned_owner_object": True,
                                },
                                "proof_type": "write_cross_principal_replay",
                                "mutation_confirmed": False,
                                "response_snippet": write_body[:300],
                            }
                            results["findings"].append({
                                "id": f"smart_authz_write:{path_hash}",
                                "tool": "smart_authz",
                                "title": f"Broken object authorization: user2 reached user1 object via write-method (PATCH) at {write_candidate['custom_endpoint']}",
                                "severity": "critical",
                                "confidence": 0.84,
                                "severity_rationale": (
                                    "Critical: a second authenticated principal received a successful "
                                    "write-method response for an object ID produced by user1 and absent "
                                    "from user2's own producer response. Cross-principal write ACCESS is "
                                    "confirmed; persistence of a mutation was not separately re-verified."
                                ),
                                "evidence": write_evidence,
                                "description": (
                                    "A resource ID observed in user1's authenticated response was not "
                                    "present in user2's own listing, but user2 could invoke a PATCH "
                                    "request against that object and receive resource data for it."
                                ),
                                "remediation": (
                                    "Authorize every object write against the requesting principal. "
                                    "Add multi-user regression tests for update/delete workflows."
                                ),
                                "cwe": "CWE-639",
                                "owasp": "API1:2023 - Broken Object Level Authorization",
                            })
                        results["endpoint_attempts"].append(write_attempt)
            if results.get("budget_exceeded"):
                break

    return results


async def smart_bola_test(
    base_url: str,
    discovered_urls: list[str],
    user1_session: Any | None = None,
    user2_session: Any | None = None,
    param_endpoints: list[dict[str, Any]] | None = None,
    max_endpoints: int = 30,
    timeout: int = 10,
    max_seconds: float | None = None,
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
        param_endpoints: Endpoints with parameter names for query synthesis
        max_endpoints: Maximum unique endpoints to test
        timeout: Request timeout
        max_seconds: Optional overall wall-clock budget. On a rich app the
            discovered-URL set can be large enough that testing every template
            takes many minutes; when the budget is exceeded we stop the
            endpoint loop gracefully and return the findings gathered so far
            (rather than being hard-cancelled by an external watchdog, which
            would discard partial results).

    Returns:
        Dictionary with findings and statistics
    """
    import re
    import random
    import time as _time
    from .proof_of_exploit import fetch_with_capture

    _deadline = (_time.monotonic() + max_seconds) if max_seconds and max_seconds > 0 else None

    results = {
        "vulnerable": False,
        "findings": [],
        "endpoints_analyzed": 0,
        "id_patterns_found": 0,
        "access_violations": 0,
        "cross_user_violations": 0,
        "write_cross_user_violations": 0,
        "method_variations_tested": 0,
        "synthesized_urls_tested": 0,
        "synthesized_query_urls_tested": 0,
        "budget_exceeded": False,
        "cancelled": False,
        "budget_exhausted_reason": None,
        "endpoint_attempts": [],
    }

    def _stop_requested() -> bool:
        if _mark_cooperative_cancel(results):
            return True
        if _deadline is not None and _time.monotonic() >= _deadline:
            results["budget_exceeded"] = True
            results["budget_exhausted_reason"] = "time_budget_exhausted"
            return True
        return False

    def build_headers(session):
        """Snapshot auth headers + cookies for a session.

        See `check_bola.build_headers` for rationale on merging cookies_received.
        """
        headers = {}
        if session and hasattr(session, 'config'):
            headers.update(session.config.headers or {})
            cookies = dict(session.config.cookies or {})
            state = getattr(session, "state", None)
            if state is not None:
                cookies.update(getattr(state, "cookies_received", None) or {})
            if cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                headers["Cookie"] = cookie_str
        return headers

    if _stop_requested():
        return results

    if user1_session is not None and user2_session is not None:
        authz_results = await authz_resource_replay_test(
            base_url=base_url,
            discovered_urls=discovered_urls,
            user1_session=user1_session,
            user2_session=user2_session,
            max_producers=min(40, max_endpoints),
            max_replays=max(20, max_endpoints * 2),
            timeout=timeout,
            max_seconds=max_seconds * 0.35 if max_seconds and max_seconds > 0 else None,
        )
        results["authz_resource_replay"] = authz_results
        results["findings"].extend(authz_results.get("findings") or [])
        results["endpoint_attempts"].extend(authz_results.get("endpoint_attempts") or [])
        results["cross_user_violations"] += int(authz_results.get("cross_principal_violations") or 0)
        results["write_cross_user_violations"] += int(authz_results.get("write_cross_principal_violations") or 0)
        if authz_results.get("vulnerable"):
            results["vulnerable"] = True
        if authz_results.get("budget_exceeded"):
            results["budget_exceeded"] = True
            results["budget_exhausted_reason"] = authz_results.get("budget_exhausted_reason")
        if authz_results.get("cancelled"):
            results["cancelled"] = True
            return results

    # Synthesize resource URLs from collection endpoints
    synthesized_urls = synthesize_resource_urls_from_collections(
        discovered_urls,
        max_collections=min(20, max_endpoints // 2),
    )
    if synthesized_urls:
        print(
            f"[bola] Synthesized {len(synthesized_urls)} resource URLs from collection endpoints",
            file=__import__('sys').stderr
        )
        results["synthesized_urls_tested"] = len(synthesized_urls)

    synthesized_query_urls = synthesize_query_urls_from_param_endpoints(
        base_url=base_url,
        param_endpoints=param_endpoints,
        max_endpoints=min(20, max_endpoints // 2),
    )
    if synthesized_query_urls:
        print(
            f"[bola] Synthesized {len(synthesized_query_urls)} query URLs from parameter hints",
            file=__import__('sys').stderr
        )
        results["synthesized_query_urls_tested"] = len(synthesized_query_urls)

    all_urls_to_analyze = list(
        dict.fromkeys(list(discovered_urls) + synthesized_urls + synthesized_query_urls)
    )

    # Extract endpoints with ID patterns from discovered URLs
    id_endpoints = {}  # path_template -> {pattern_type, original_ids, base_url}

    for url in all_urls_to_analyze:
        if _stop_requested():
            break
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
        # Respect the overall budget: stop gracefully and keep findings so far
        # instead of being hard-cancelled (which discards partial results).
        if _stop_requested():
            print(
                f"[bola] Stop requested after {results['endpoints_analyzed']} "
                f"endpoints; returning {len(results['findings'])} findings gathered so far",
                file=__import__('sys').stderr,
            )
            break

        if _is_operational_only_bola_endpoint(template):
            continue

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
        attempt = _new_bola_endpoint_attempt(
            info.get("example_url") or template.replace("{id}", test_ids[0] if test_ids else "1"),
            test_id_count=len(test_ids),
        )

        template_no_auth_candidates: list[dict[str, Any]] = []
        template_no_auth_statuses: set[int] = set()
        template_no_auth_fingerprints: set[str] = set()

        # Test each ID
        for test_id in test_ids:
            if _stop_requested():
                break
            # Replace {id} with test ID
            test_url = template.replace('{id}', test_id)
            if attempt is not None:
                attempt["attempted_params_count"] += 1

            # Rebuild headers per request so mid-loop session refresh is honoured.
            user1_headers = build_headers(user1_session)
            user2_headers = build_headers(user2_session)

            # Test with user1
            user1_resp = await fetch_with_capture(test_url, headers=user1_headers, timeout=timeout, budget_key="bola")
            if _mark_cooperative_cancel(results):
                break
            user1_status = user1_resp.get("status_code", 0)
            user1_body = user1_resp.get("body", "")

            # Test with user2 if user2_session is actually provided
            # (cross-user comparison only makes sense with two authenticated users)
            if user2_session is not None:
                user2_resp = await fetch_with_capture(test_url, headers=user2_headers, timeout=timeout, budget_key="bola")
                if _mark_cooperative_cancel(results):
                    break
                user2_status = user2_resp.get("status_code", 0)
                user2_body = user2_resp.get("body", "")

                # Check for cross-user access
                if user1_status == 200 and user2_status == 200:
                    # Both users can access - check if data is user-specific
                    if len(user1_body) > 50 and len(user2_body) > 50:
                        # Equivalence after volatile-field normalization (fixes
                        # missed BOLA when responses embed CSRF/timestamps), and
                        # value-based user-data detection (avoids matching nav
                        # chrome / error envelopes).
                        if responses_equivalent(user1_body, user2_body):
                            user_signals = extract_user_specific_signals(user1_body)
                            if user_signals:
                                # Cross-user-equivalent + user-specific data is a
                                # strong lead but still can't prove user2 lacks
                                # ownership without a control, so mark it for
                                # verification rather than auto-confirming.
                                similarity = response_similarity(user1_body, user2_body)
                                results["cross_user_violations"] += 1
                                path_hash = hashlib.sha256(f"{test_url}:crossuser".encode()).hexdigest()[:8]
                                # A paired-owner identity is supporting evidence only.
                                # The generic ID loop has no attacker-listing or policy
                                # control, so equivalent responses cannot prove user2 is
                                # unauthorized. Deterministic promotion is reserved for
                                # authz_resource_replay_test's listing differential.
                                paired_owner_identity = _confirm_cross_principal_ownership(
                                    user2_body, user1_session, user2_session
                                )
                                finding = {
                                    "id": f"smart_bola:{path_hash}",
                                    "tool": "smart_bola",
                                    "title": f"BOLA: Cross-user data access at {template}",
                                    "cwe": "CWE-639",
                                    "owasp": "API1:2023 - Broken Object Level Authorization",
                                    "evidence": {
                                        "url": test_url,
                                        "method": "GET",
                                        "test_id": test_id,
                                        "pattern_type": pattern_type,
                                        "user1_status": user1_status,
                                        "user2_status": user2_status,
                                        "responses_equivalent": True,
                                        "response_similarity": round(similarity, 3),
                                        "user_specific_signals": user_signals[:8],
                                        "paired_owner_identity_observed": paired_owner_identity,
                                        "response_snippet": user1_body[:300],
                                    },
                                    "severity": "high",
                                    "suspected": True,
                                    "needs_verification": True,
                                    "verification_reason": (
                                        "Both users received equivalent user-specific data for the same "
                                        "resource ID; prove the object is absent from user2's authorized "
                                        "listing or compare against an explicit deny expectation."
                                    ),
                                    "confidence": 0.65 if paired_owner_identity else 0.6,
                                    "description": (
                                        f"Both test users received equivalent user-specific data for resource ID {test_id}. "
                                        "This is a BOLA lead, but the response alone does not prove user2 lacks access."
                                    ),
                                    "remediation": "Implement object-level authorization and verify requesting user owns the resource.",
                                }
                                results["findings"].append(finding)

            # Test without auth
            no_auth_resp = await fetch_with_capture(test_url, timeout=timeout, budget_key="bola")
            if _mark_cooperative_cancel(results):
                break
            no_auth_status = no_auth_resp.get("status_code", 0)
            no_auth_body = no_auth_resp.get("body", "")
            template_no_auth_statuses.add(no_auth_status)

            # If unauthenticated access returns data
            if no_auth_status == 200 and len(no_auth_body) > 50:
                # Check if it looks like actual data
                exclude_patterns = ['login', 'sign in', 'authenticate', 'unauthorized', '<!doctype', '<html']
                if not any(p in no_auth_body.lower() for p in exclude_patterns):
                    template_no_auth_candidates.append(
                        {
                            "url": test_url,
                            "test_id": test_id,
                            "status_code": no_auth_status,
                            "body": no_auth_body,
                        }
                    )
                    template_no_auth_fingerprints.add(_response_body_fingerprint(no_auth_body))
            if attempt is not None:
                attempt["completed_params_count"] += 1

        if results.get("cancelled") or results.get("budget_exceeded"):
            stop_reason = (
                "cancelled"
                if results.get("cancelled")
                else str(results.get("budget_exhausted_reason") or "time_budget_exhausted")
            )
            finished_attempt = _finish_bola_endpoint_attempt(
                attempt,
                budget_exceeded=True,
                budget_exhausted_reason=stop_reason,
            )
            if finished_attempt:
                finished_attempt["skip_reason"] = stop_reason
                results["endpoint_attempts"].append(finished_attempt)
            break

        if template_no_auth_candidates:
            sample = template_no_auth_candidates[0]
            sample_body = sample.get("body", "")
            id_sensitive = _id_parameter_affects_response(
                status_codes=template_no_auth_statuses,
                body_fingerprints=template_no_auth_fingerprints,
                total_ids_tested=len(test_ids),
            )
            looks_like_resource = _looks_like_bola_resource_response(template, sample_body)

            if id_sensitive and looks_like_resource:
                results["vulnerable"] = True
                results["access_violations"] += 1
                path_hash = hashlib.sha256(f"{template}:noauth".encode()).hexdigest()[:8]
                successful_ids = [item["test_id"] for item in template_no_auth_candidates]
                results["findings"].append({
                    "id": f"smart_bola:{path_hash}",
                    "tool": "smart_bola",
                    "title": f"BOLA: Unauthenticated access to {template}",
                    "severity": "critical",
                    "evidence": {
                        "url": sample.get("url"),
                        "method": "GET",
                        "pattern_type": pattern_type,
                        "successful_ids": successful_ids[:10],
                        "successful_count": len(successful_ids),
                        "status_codes_observed": sorted(template_no_auth_statuses),
                        "distinct_response_fingerprints": len(template_no_auth_fingerprints),
                        "response_length": len(sample_body),
                        "response_snippet": sample_body[:300],
                    },
                    "description": (
                        "Endpoint appears to expose object/resource data without authentication "
                        "and response behavior changes across tested IDs."
                    ),
                    "remediation": "Require authentication and enforce object-level authorization checks.",
                    "cwe": "CWE-639",
                    "owasp": "API1:2023 - Broken Object Level Authorization",
                })

        # Test method variations (PUT, DELETE, PATCH on GET endpoints)
        if user1_headers and results["endpoints_analyzed"] <= 10:  # Limit method testing
            for method in ["PUT", "DELETE", "PATCH"]:
                if _stop_requested():
                    break
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

        finished_attempt = _finish_bola_endpoint_attempt(
            attempt,
            budget_exceeded=bool(results.get("budget_exceeded")),
        )
        if finished_attempt:
            results["endpoint_attempts"].append(finished_attempt)

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
        endpoint_no_auth_candidates: list[dict[str, Any]] = []
        endpoint_no_auth_statuses: set[int] = set()
        endpoint_no_auth_fingerprints: set[str] = set()

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
                response = await fetch_with_capture(url, headers=headers, timeout=timeout, budget_key="bola")
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
            endpoint_no_auth_statuses.add(unauth_status)

            if unauth_status == 200 and len(unauth_body) > 50:
                if not any(x in unauth_body.lower() for x in ["login", "sign in", "authenticate", "unauthorized"]):
                    endpoint_no_auth_candidates.append(
                        {
                            "url": url,
                            "path": path,
                            "resource_id": resource_id,
                            "status_code": unauth_status,
                            "body": unauth_body,
                        }
                    )
                    endpoint_no_auth_fingerprints.add(_response_body_fingerprint(unauth_body))

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

                # Compare bodies, tolerating per-request volatile fields.
                bodies = [body for _, body in successful_users]
                if all_responses_equivalent(bodies):  # All equivalent responses
                    accessing_users = [uid for uid, _ in successful_users]

                    # If we know the owner and others can access
                    if expected_owner is not None:
                        unauthorized_users = [u for u in accessing_users if u != expected_owner]
                        if unauthorized_users:
                            # Operator asserted ownership via user_owned_resources,
                            # so unauthorized cross-user access is a confirmed
                            # violation.
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
                        # No ownership defined — equivalent responses across
                        # users can't be distinguished from shared/public data
                        # without it. Require concrete user-specific data and
                        # emit a suspected lead rather than a finding.
                        user_signals = extract_user_specific_signals(bodies[0])
                        if user_signals:
                            path_hash = hashlib.sha256(f"{path}:shared:multi".encode()).hexdigest()[:8]
                            results["findings"].append({
                                "id": f"bola_multi_potential:{path_hash}",
                                "tool": "bola_multi_user",
                                "title": f"Potential BOLA: Multiple users access same resource at {path}",
                                "severity": "medium",
                                "suspected": True,
                                "needs_verification": True,
                                "verification_reason": (
                                    "Multiple users received equivalent user-specific data for the same "
                                    "resource; confirm they are not all legitimate owners/admins."
                                ),
                                "confidence": 0.5,
                                "evidence": {
                                    "url": url,
                                    "resource_id": resource_id,
                                    "accessing_users": [f"user_{u}" for u in accessing_users],
                                    "responses_equivalent": True,
                                    "user_specific_signals": user_signals[:8],
                                },
                                "description": f"{len(successful_users)} users received equivalent user-specific data for the same resource. Verify this is intended.",
                                "remediation": "Review access control to ensure only authorized users can access.",
                                "cwe": "CWE-639",
                                "owasp": "API1:2023 - Broken Object Level Authorization",
                            })

        if endpoint_no_auth_candidates:
            sample = endpoint_no_auth_candidates[0]
            sample_body = sample.get("body", "")
            id_sensitive = _id_parameter_affects_response(
                status_codes=endpoint_no_auth_statuses,
                body_fingerprints=endpoint_no_auth_fingerprints,
                total_ids_tested=len(ids_to_test),
            )
            looks_like_resource = _looks_like_bola_resource_response(path_template, sample_body)

            if id_sensitive and looks_like_resource:
                results["vulnerable"] = True
                results["access_violations"] += 1
                path_hash = hashlib.sha256(f"{path_template}:noauth:multi".encode()).hexdigest()[:8]
                successful_ids = [item["resource_id"] for item in endpoint_no_auth_candidates]
                results["findings"].append({
                    "id": f"bola_multi:{path_hash}",
                    "tool": "bola_multi_user",
                    "title": f"BOLA: Unauthenticated access to {path_template}",
                    "severity": "critical",
                    "evidence": {
                        "url": sample.get("url"),
                        "successful_ids": successful_ids[:10],
                        "successful_count": len(successful_ids),
                        "status_codes_observed": sorted(endpoint_no_auth_statuses),
                        "distinct_response_fingerprints": len(endpoint_no_auth_fingerprints),
                        "response_length": len(sample_body),
                    },
                    "description": (
                        "Endpoint appears to expose object/resource data without authentication "
                        "and response behavior changes across tested IDs."
                    ),
                    "remediation": "Implement authentication and object-level authorization checks.",
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
            response = await fetch_with_capture(url, headers=headers, timeout=timeout, budget_key="bola")
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


def _is_collection_endpoint(url: str) -> bool:
    """True if the URL looks like a REST collection (``/api/Users``, ``/rest/products``)
    and isn't an excluded docs/static/health path. Reuses the shared collection
    patterns so this stays consistent with resource-id synthesis."""
    import re
    low = url.lower()
    if any(excl in low for excl in COLLECTION_EXCLUSIONS):
        return False
    return any(re.match(p, url, re.IGNORECASE) for p in COLLECTION_ENDPOINT_PATTERNS)


async def check_collection_authz(
    base_url: str,
    discovered_urls: list[str] | None = None,
    auth_session: Any | None = None,
    timeout: int = 10,
    max_endpoints: int = 40,
) -> dict[str, Any]:
    """Broken function-level authorization (BFLA) on sensitive COLLECTION endpoints.

    General technique, no app-specific paths: a collection like ``/api/Users``
    that denies anonymous callers (401/403) but returns a bulk array of OTHER
    principals' sensitive records to *any authenticated user* is broken
    function-level authorization — authentication is enforced, authorization is
    not. The anonymous-denied vs authenticated-bulk-data differential IS the
    deterministic proof, so findings are emitted pre-verified.

    Precision guards (avoid flagging an endpoint returning only the caller's own
    record): require the authenticated response to (a) pass the ``rest_api_models``
    sensitive-field content validation (email/role/token markers, HTML rejected)
    and (b) expose cross-principal data — >=2 distinct identities OR a privileged
    (role:admin) record.
    """
    import re

    results: dict[str, Any] = {"vulnerable": False, "findings": [], "endpoints_tested": 0}
    if not auth_session:
        results["skipped_reason"] = "no_auth_session"
        return results

    from .proof_of_exploit import fetch_with_capture

    auth_headers: dict[str, str] = {}
    if hasattr(auth_session, "config"):
        auth_headers.update(getattr(auth_session.config, "headers", {}) or {})
        cookies = getattr(auth_session.config, "cookies", {}) or {}
        if cookies:
            auth_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    if not auth_headers:
        results["skipped_reason"] = "no_auth_headers"
        return results

    # Candidate collections: discovered URLs that match the collection pattern,
    # plus the curated rest_api_models model list so an admin/model API not
    # linked in the SPA is still probed.
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(raw: Any) -> None:
        if not raw:
            return
        u = str(raw)
        full = u if u.startswith("http") else urljoin(base_url.rstrip("/") + "/", u.lstrip("/"))
        path = urlsplit(full).path or "/"
        if path in seen:
            return
        if not _is_collection_endpoint(full):
            return
        seen.add(path)
        candidates.append(full)

    for u in (discovered_urls or []):
        _add(u)
    for p in PRIVILEGED_PATHS.get("rest_api_models", []):
        _add(urljoin(base_url.rstrip("/") + "/", p.lstrip("/")))
    candidates = candidates[:max_endpoints]

    def _content_type(resp: dict[str, Any]) -> str:
        for k, v in (resp.get("headers") or {}).items():
            if str(k).lower() == "content-type":
                return str(v)
        return ""

    for url in candidates:
        results["endpoints_tested"] += 1
        try:
            r_auth = await fetch_with_capture(url, headers=auth_headers, timeout=timeout)
        except Exception:
            continue
        if int(r_auth.get("status_code") or 0) != 200:
            continue
        body_auth = r_auth.get("body") or ""
        ok, _reason = _has_category_content(body_auth, _content_type(r_auth), "rest_api_models")
        if not ok:
            continue
        # Cross-principal guard: bulk data belonging to more than just the caller.
        emails = set(re.findall(r'"email"\s*:\s*"([^"]+)"', body_auth))
        has_privileged = bool(re.search(r'"(?:role|isadmin|is_admin)"\s*:\s*"?(?:admin|true)"?', body_auth, re.I))
        if len(emails) < 2 and not has_privileged:
            continue

        # Anonymous differential.
        try:
            r_anon = await fetch_with_capture(url, timeout=timeout)
        except Exception:
            continue
        s_anon = int(r_anon.get("status_code") or 0)
        anon_denied = s_anon in (401, 403)
        anon_leaks = False
        if s_anon == 200:
            anon_leaks, _ = _has_category_content(r_anon.get("body") or "", _content_type(r_anon), "rest_api_models")

        # BFLA when anonymous is denied but any authenticated user gets the bulk
        # data. If anonymous ALSO leaks it, that is an even worse unauthenticated
        # exposure — still report (forced browsing may also flag it separately).
        if not (anon_denied or (s_anon == 200 and not anon_leaks)):
            continue

        results["vulnerable"] = True
        path = urlsplit(url).path
        principal = "any authenticated user" if anon_denied else "a lower-privileged principal"
        results["findings"].append({
            "tool": "bfla",
            "title": f"Broken function-level authorization: {path} returns bulk user records to {principal}",
            "severity": "high",
            "verified": True,
            "type": "bfla",
            "url": url,
            "evidence": {
                "type": "bfla",
                "url": url,
                "anonymous_status": s_anon,
                "authenticated_status": 200,
                "distinct_identities": len(emails),
                "privileged_record_present": has_privileged,
                "differential": (
                    f"anonymous -> HTTP {s_anon}; authenticated -> HTTP 200 with "
                    f"{len(emails)} distinct user record(s)"
                    + (" incl. a privileged (admin) record" if has_privileged else "")
                ),
                "authenticated_snippet": body_auth[:300],
            },
            "cwe": "CWE-285",
            "owasp": "A01:2021 - Broken Access Control",
        })

    return results
