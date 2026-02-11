"""
Centralized constants for the scanner.

This module consolidates constants that were previously scattered across
scanner.py and other modules, following the DRY principle.
"""
from __future__ import annotations

from dataclasses import dataclass


# =============================================================================
# SMART SCAN BUDGETS
# =============================================================================

@dataclass(frozen=True)
class SmartScanBudgetConfig:
    """Typed defaults for smart scan safety/performance budget limits."""

    smart_bola_max_endpoints: int = 80
    dom_xss_max_files: int = 20
    sqli_extract_max: int = 3
    oob_max_findings: int = 3

    def as_dict(self) -> dict[str, int]:
        """Return budget defaults as a serializable mapping."""
        return {
            "smart_bola_max_endpoints": self.smart_bola_max_endpoints,
            "dom_xss_max_files": self.dom_xss_max_files,
            "sqli_extract_max": self.sqli_extract_max,
            "oob_max_findings": self.oob_max_findings,
        }


SMART_SCAN_BUDGETS = SmartScanBudgetConfig()

SMART_SCAN_BUDGET_DESCRIPTIONS: dict[str, str] = {
    "smart_bola_max_endpoints": "Max endpoints for smart BOLA testing",
    "dom_xss_max_files": "Max JS files for DOM XSS analysis",
    "sqli_extract_max": "Max SQLi findings for data extraction attempts",
    "oob_max_findings": "Max findings for OOB SQLi verification",
}


# =============================================================================
# ENDPOINT PATTERNS
# =============================================================================

@dataclass(frozen=True)
class EndpointPatterns:
    """Endpoint classification patterns for context-aware security analysis."""

    # Authentication-related endpoints (increase severity for vulns here)
    AUTH: frozenset[str] = frozenset([
        "login", "signin", "auth", "oauth", "token", "session",
        "password", "forgot", "reset", "register", "signup"
    ])

    # Payment/financial endpoints (high sensitivity)
    PAYMENT: frozenset[str] = frozenset([
        "payment", "checkout", "billing", "invoice", "subscription",
        "cart", "order", "purchase"
    ])

    # Admin/management endpoints (elevated privileges)
    ADMIN: frozenset[str] = frozenset([
        "admin", "dashboard", "manage", "settings", "config",
        "panel", "console"
    ])

    # API endpoints
    API: frozenset[str] = frozenset([
        "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"
    ])

    # Static asset endpoints (lower severity)
    STATIC: frozenset[str] = frozenset([
        ".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff",
        ".ico", "/static/", "/assets/", "/public/"
    ])

    # Development/test endpoints (lower severity for external reports)
    DEV: frozenset[str] = frozenset([
        "/test", "/debug", "/dev", "/staging", "localhost", "127.0.0.1"
    ])

    @classmethod
    def is_auth_endpoint(cls, path: str) -> bool:
        """Check if path matches an authentication endpoint pattern."""
        path_lower = path.lower()
        return any(p in path_lower for p in cls.AUTH)

    @classmethod
    def is_payment_endpoint(cls, path: str) -> bool:
        """Check if path matches a payment endpoint pattern."""
        path_lower = path.lower()
        return any(p in path_lower for p in cls.PAYMENT)

    @classmethod
    def is_admin_endpoint(cls, path: str) -> bool:
        """Check if path matches an admin endpoint pattern."""
        path_lower = path.lower()
        return any(p in path_lower for p in cls.ADMIN)

    @classmethod
    def is_api_endpoint(cls, path: str) -> bool:
        """Check if path matches an API endpoint pattern."""
        path_lower = path.lower()
        return any(p in path_lower for p in cls.API)

    @classmethod
    def is_static_asset(cls, path: str) -> bool:
        """Check if path is a static asset."""
        path_lower = path.lower()
        return any(p in path_lower for p in cls.STATIC)

    @classmethod
    def is_dev_endpoint(cls, path: str) -> bool:
        """Check if path is a development/test endpoint."""
        path_lower = path.lower()
        return any(p in path_lower for p in cls.DEV)

    @classmethod
    def is_sensitive_endpoint(cls, path: str) -> bool:
        """Check if path is a sensitive endpoint (auth, payment, or admin)."""
        return (
            cls.is_auth_endpoint(path) or
            cls.is_payment_endpoint(path) or
            cls.is_admin_endpoint(path)
        )

    @classmethod
    def get_sensitivity_score(cls, path: str) -> float:
        """Get sensitivity score for endpoint (0.0 to 1.0)."""
        score = 0.5  # Base score
        if cls.is_auth_endpoint(path):
            score += 0.3
        if cls.is_payment_endpoint(path):
            score += 0.3
        if cls.is_admin_endpoint(path):
            score += 0.2
        if cls.is_api_endpoint(path):
            score += 0.1
        if cls.is_static_asset(path):
            score -= 0.3
        if cls.is_dev_endpoint(path):
            score -= 0.2
        return max(0.0, min(1.0, score))


# =============================================================================
# CVSS SCORES
# =============================================================================

# CVSS v3.1 scores for common vulnerability types
# Organized by OWASP Top 10 2021 categories
FINDING_CVSS_SCORES: dict[str, float] = {
    # === A01:2021 - Broken Access Control ===
    "idor": 7.5,
    "bola": 7.5,
    "insecure direct object reference": 7.5,
    "broken object level authorization": 7.5,
    "path traversal": 8.0,
    "directory traversal": 8.0,
    "local file inclusion": 8.0,
    "lfi": 8.0,
    "remote file inclusion": 9.0,
    "rfi": 9.0,
    "privilege escalation": 8.8,
    "authorization bypass": 8.0,
    "access control bypass": 8.0,
    "forced browsing": 5.3,
    "missing function level access": 7.5,

    # === A02:2021 - Cryptographic Failures ===
    "weak cipher": 5.3,
    "weak encryption": 5.3,
    "missing encryption": 7.5,
    "insecure tls": 5.3,
    "ssl vulnerability": 5.3,
    "certificate expired": 5.3,
    "self-signed certificate": 3.7,
    "weak key": 5.3,
    "hardcoded credential": 9.1,
    "hardcoded password": 9.1,
    "hardcoded secret": 9.1,
    "exposed credential": 9.1,
    "credential in url": 7.5,

    # === A03:2021 - Injection ===
    "sql injection": 9.8,
    "sqli": 9.8,
    "blind sql": 8.6,
    "error-based sql": 9.8,
    "time-based sql": 8.6,
    "union-based sql": 9.8,
    "command injection": 9.8,
    "os command injection": 9.8,
    "code injection": 9.8,
    "remote code execution": 10.0,
    "rce": 10.0,
    "ldap injection": 8.0,
    "xpath injection": 8.0,
    "xml injection": 7.5,
    "xxe": 8.0,
    "xml external entity": 8.0,
    "ssti": 9.0,
    "server side template injection": 9.0,
    "nosql injection": 8.0,
    "header injection": 6.1,
    "crlf injection": 6.1,
    "log injection": 5.3,

    # === A04:2021 - Insecure Design ===
    "insecure design": 5.0,
    "business logic flaw": 6.5,
    "race condition": 7.5,
    "toctou": 7.5,

    # === A05:2021 - Security Misconfiguration ===
    "security misconfiguration": 5.3,
    "misconfiguration": 5.3,
    "default credentials": 9.8,
    "default password": 9.8,
    "debug enabled": 5.3,
    "directory listing": 5.3,
    "information disclosure": 5.3,
    "verbose error": 5.3,
    "stack trace": 5.3,
    "exposed admin": 7.5,
    "exposed panel": 6.5,
    "cors misconfiguration": 6.5,
    "permissive cors": 6.5,

    # === A06:2021 - Vulnerable and Outdated Components ===
    "outdated software": 5.3,
    "vulnerable component": 7.5,
    "known vulnerability": 7.5,
    "cve-": 7.5,  # Generic CVE

    # === A07:2021 - Identification and Authentication Failures ===
    "authentication bypass": 9.8,
    "auth bypass": 9.8,
    "session fixation": 7.5,
    "session hijacking": 8.0,
    "weak session": 6.5,
    "insecure session": 6.5,
    "brute force": 7.5,
    "account enumeration": 5.3,
    "user enumeration": 5.3,
    "password reset": 7.5,
    "jwt vulnerability": 7.5,
    "jwt none algorithm": 9.1,
    "jwt weak secret": 7.5,
    "2fa bypass": 8.0,
    "mfa bypass": 8.0,

    # === A08:2021 - Software and Data Integrity Failures ===
    "insecure deserialization": 9.8,
    "deserialization": 9.8,
    "prototype pollution": 7.5,
    "mass assignment": 6.5,
    "cicd vulnerability": 7.5,

    # === A09:2021 - Security Logging and Monitoring Failures ===
    "missing logging": 3.0,
    "insufficient logging": 3.0,

    # === A10:2021 - Server-Side Request Forgery ===
    "ssrf": 8.6,
    "server side request forgery": 8.6,
    "blind ssrf": 7.5,

    # === Cross-Site Scripting (XSS) ===
    "xss": 6.1,
    "cross-site scripting": 6.1,
    "reflected xss": 6.1,
    "stored xss": 8.4,
    "dom xss": 6.1,
    "dom-based xss": 6.1,

    # === CSRF ===
    "csrf": 8.0,
    "cross-site request forgery": 8.0,

    # === Open Redirect ===
    "open redirect": 6.1,
    "url redirect": 6.1,

    # === File Upload ===
    "unrestricted file upload": 9.0,
    "file upload": 7.5,
    "arbitrary file upload": 9.0,

    # === DNS/Email Security ===
    "missing spf": 4.0,
    "spf": 4.0,
    "missing dmarc": 4.0,
    "dmarc": 4.0,
    "missing dkim": 3.0,
    "subdomain takeover": 8.0,
    "dangling dns": 7.5,

    # === Headers/Cookies ===
    "missing hsts": 4.0,
    "hsts": 4.0,
    "missing csp": 4.0,
    "csp": 4.0,
    "cookie without secure": 4.0,
    "cookie without httponly": 4.0,
    "clickjacking": 4.0,
    "missing x-frame-options": 4.0,

    # === Informational ===
    "technology detected": 0.0,
    "version detected": 0.0,
    "information": 0.0,
    "info": 0.0,
}

# Short patterns that need word boundary matching to avoid false positives
SHORT_CVSS_PATTERNS: frozenset[str] = frozenset([
    'rce', 'lfi', 'rfi', 'xss', 'xxe', 'jwt', 'spf', 'ssrf'
])


# =============================================================================
# SEVERITY SCORES
# =============================================================================

# Base CVSS scores by severity level
SEVERITY_BASE_SCORES: dict[str, float] = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}

# CVSS to severity mapping
CVSS_SEVERITY_RANGES: list[tuple[float, float, str]] = [
    (9.0, 10.0, "critical"),
    (7.0, 8.9, "high"),
    (4.0, 6.9, "medium"),
    (0.1, 3.9, "low"),
    (0.0, 0.0, "info"),
]


# =============================================================================
# OWASP TOP 10 2021
# =============================================================================

# OWASP risk weight multipliers
OWASP_WEIGHT: dict[str, float] = {
    "A01:2021": 1.5,  # Broken Access Control - #1 risk
    "A02:2021": 1.3,  # Cryptographic Failures
    "A03:2021": 1.5,  # Injection - high impact
    "A04:2021": 1.0,  # Insecure Design
    "A05:2021": 1.0,  # Security Misconfiguration
    "A06:2021": 1.2,  # Vulnerable Components
    "A07:2021": 1.3,  # Auth Failures
    "A08:2021": 1.0,  # Integrity Failures
    "A09:2021": 0.8,  # Logging Failures
    "A10:2021": 1.2,  # SSRF
}

# Vulnerability to OWASP mapping
OWASP_MAPPING: dict[str, str] = {
    # A01:2021 - Broken Access Control
    "idor": "A01:2021 - Broken Access Control",
    "bola": "A01:2021 - Broken Access Control",
    "path traversal": "A01:2021 - Broken Access Control",
    "directory traversal": "A01:2021 - Broken Access Control",
    "lfi": "A01:2021 - Broken Access Control",
    "rfi": "A01:2021 - Broken Access Control",
    "privilege escalation": "A01:2021 - Broken Access Control",
    "authorization bypass": "A01:2021 - Broken Access Control",
    "access control": "A01:2021 - Broken Access Control",
    "forced browsing": "A01:2021 - Broken Access Control",
    "cors": "A01:2021 - Broken Access Control",

    # A02:2021 - Cryptographic Failures
    "weak cipher": "A02:2021 - Cryptographic Failures",
    "weak encryption": "A02:2021 - Cryptographic Failures",
    "insecure tls": "A02:2021 - Cryptographic Failures",
    "ssl": "A02:2021 - Cryptographic Failures",
    "certificate": "A02:2021 - Cryptographic Failures",
    "hardcoded credential": "A02:2021 - Cryptographic Failures",
    "exposed credential": "A02:2021 - Cryptographic Failures",
    "sensitive data": "A02:2021 - Cryptographic Failures",

    # A03:2021 - Injection
    "sql injection": "A03:2021 - Injection",
    "sqli": "A03:2021 - Injection",
    "command injection": "A03:2021 - Injection",
    "code injection": "A03:2021 - Injection",
    "ldap injection": "A03:2021 - Injection",
    "xpath injection": "A03:2021 - Injection",
    "xxe": "A03:2021 - Injection",
    "ssti": "A03:2021 - Injection",
    "nosql injection": "A03:2021 - Injection",
    "header injection": "A03:2021 - Injection",
    "crlf": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "cross-site scripting": "A03:2021 - Injection",

    # A04:2021 - Insecure Design
    "insecure design": "A04:2021 - Insecure Design",
    "business logic": "A04:2021 - Insecure Design",
    "race condition": "A04:2021 - Insecure Design",

    # A05:2021 - Security Misconfiguration
    "misconfiguration": "A05:2021 - Security Misconfiguration",
    "default credential": "A05:2021 - Security Misconfiguration",
    "debug enabled": "A05:2021 - Security Misconfiguration",
    "directory listing": "A05:2021 - Security Misconfiguration",
    "verbose error": "A05:2021 - Security Misconfiguration",
    "stack trace": "A05:2021 - Security Misconfiguration",
    "exposed admin": "A05:2021 - Security Misconfiguration",

    # A06:2021 - Vulnerable Components
    "outdated": "A06:2021 - Vulnerable and Outdated Components",
    "vulnerable component": "A06:2021 - Vulnerable and Outdated Components",
    "cve-": "A06:2021 - Vulnerable and Outdated Components",
    "known vulnerability": "A06:2021 - Vulnerable and Outdated Components",

    # A07:2021 - Auth Failures
    "authentication bypass": "A07:2021 - Identification and Authentication Failures",
    "session fixation": "A07:2021 - Identification and Authentication Failures",
    "session hijacking": "A07:2021 - Identification and Authentication Failures",
    "brute force": "A07:2021 - Identification and Authentication Failures",
    "account enumeration": "A07:2021 - Identification and Authentication Failures",
    "jwt": "A07:2021 - Identification and Authentication Failures",
    "2fa bypass": "A07:2021 - Identification and Authentication Failures",
    "weak password": "A07:2021 - Identification and Authentication Failures",

    # A08:2021 - Integrity Failures
    "deserialization": "A08:2021 - Software and Data Integrity Failures",
    "prototype pollution": "A08:2021 - Software and Data Integrity Failures",
    "mass assignment": "A08:2021 - Software and Data Integrity Failures",
    "cicd": "A08:2021 - Software and Data Integrity Failures",

    # A09:2021 - Logging Failures
    "missing logging": "A09:2021 - Security Logging and Monitoring Failures",
    "insufficient logging": "A09:2021 - Security Logging and Monitoring Failures",

    # A10:2021 - SSRF
    "ssrf": "A10:2021 - Server-Side Request Forgery",
}


# =============================================================================
# CWE MAPPINGS
# =============================================================================

# CWE descriptions
CWE_DESCRIPTIONS: dict[str, str] = {
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-90": "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-98": "Improper Control of Filename for Include/Require Statement in PHP Program",
    "CWE-117": "Improper Output Neutralization for Logs",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-209": "Generation of Error Message Containing Sensitive Information",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-310": "Cryptographic Issues",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-384": "Session Fixation",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-640": "Weak Password Recovery Mechanism for Forgotten Password",
    "CWE-643": "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
    "CWE-644": "Improper Neutralization of HTTP Headers for Scripting Syntax",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-778": "Insufficient Logging",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-840": "Business Logic Errors",
    "CWE-862": "Missing Authorization",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-943": "Improper Neutralization of Special Elements in Data Query Logic",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
}

# Vulnerability to CWE mapping
CWE_MAPPING: dict[str, str] = {
    # Injection
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "command injection": "CWE-78",
    "os command injection": "CWE-78",
    "code injection": "CWE-94",
    "ldap injection": "CWE-90",
    "xpath injection": "CWE-643",
    "xxe": "CWE-611",
    "xml external entity": "CWE-611",
    "ssti": "CWE-94",
    "nosql injection": "CWE-943",
    "header injection": "CWE-644",
    "crlf injection": "CWE-644",
    "log injection": "CWE-117",

    # Access Control
    "idor": "CWE-639",
    "bola": "CWE-639",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "lfi": "CWE-98",
    "rfi": "CWE-98",
    "authorization bypass": "CWE-862",
    "access control": "CWE-284",
    "privilege escalation": "CWE-269",
    "forced browsing": "CWE-284",

    # Authentication
    "authentication bypass": "CWE-287",
    "session fixation": "CWE-384",
    "brute force": "CWE-307",
    "account enumeration": "CWE-200",
    "weak password": "CWE-521",
    "jwt": "CWE-347",
    "credential exposure": "CWE-522",
    "hardcoded credential": "CWE-798",

    # Cryptographic
    "weak cipher": "CWE-327",
    "weak encryption": "CWE-326",
    "missing encryption": "CWE-311",
    "cleartext": "CWE-319",
    "certificate": "CWE-295",

    # CSRF/SSRF
    "csrf": "CWE-352",
    "ssrf": "CWE-918",

    # Other
    "open redirect": "CWE-601",
    "file upload": "CWE-434",
    "cors": "CWE-942",
    "clickjacking": "CWE-1021",
    "information disclosure": "CWE-200",
    "sensitive data exposure": "CWE-200",
    "error message": "CWE-209",
    "deserialization": "CWE-502",
    "prototype pollution": "CWE-915",
    "mass assignment": "CWE-915",
    "business logic": "CWE-840",
    "race condition": "CWE-362",
    "missing logging": "CWE-778",

    # Headers
    "missing hsts": "CWE-693",
    "missing csp": "CWE-693",
    "x-frame-options": "CWE-1021",
    "cookie secure": "CWE-614",
}


# =============================================================================
# SOC 2 MAPPINGS
# =============================================================================

# SOC 2 Trust Services Criteria mapping
SOC2_CRITERIA_MAP: dict[str, list[str]] = {
    # CC6: Logical and Physical Access Controls
    "CC6.1": ["idor", "bola", "authorization", "access control", "privilege", "path traversal"],
    "CC6.2": ["authentication", "session", "2fa", "mfa", "credential", "password", "jwt", "brute force"],
    "CC6.3": ["encryption", "tls", "ssl", "cipher", "certificate", "hsts"],
    "CC6.6": ["exposed", "information disclosure", "sensitive"],
    "CC6.7": ["input validation", "injection", "xss", "sql", "command"],

    # CC7: System Operations
    "CC7.1": ["monitoring", "logging", "audit"],
    "CC7.2": ["vulnerability", "cve-", "outdated", "patching", "scan"],

    # CC8: Change Management
    "CC8.1": ["cicd", "deployment", "configuration"],
}


# =============================================================================
# TOOL CONFIDENCE
# =============================================================================

# Tool-based confidence scores (0.0 to 1.0)
TOOL_CONFIDENCE: dict[str, float] = {
    # Exploitation tools - very high confidence when they report vulns
    "dalfox": 0.90,
    "sqlmap": 0.90,

    # Specialized scanners - high confidence
    "nuclei": 0.75,
    "testssl": 0.85,
    "sslyze": 0.85,

    # Custom checks - medium-high confidence
    "exposed_files": 0.80,
    "nosql_injection": 0.70,
    "graphql_vulnerability": 0.75,
    "api_security": 0.70,
    "cors_check": 0.75,
    "subdomain_takeover": 0.85,

    # Discovery/fingerprinting - lower confidence (informational)
    "tech_detect": 0.50,
    "waf_detect": 0.50,
    "dns_policy": 0.70,
    "csp_evaluation": 0.80,

    # DOM analysis - medium-high confidence (static source-to-sink analysis)
    "dom_xss": 0.70,
    "client_side": 0.60,
}


# =============================================================================
# NUCLEI TEMPLATE PATTERNS
# =============================================================================

# Patterns for informational-only findings (not vulnerabilities)
INFO_ONLY_PATTERNS: frozenset[str] = frozenset([
    "technology detected",
    "version detected",
    "fingerprint",
    "banner",
    "server header",
    "powered by",
    "generator",
    "cms detected",
    "framework detected",
    "waf detected",
    "cdn detected",
    "hosting provider",
    "ip geolocation",
    "asn lookup",
    "whois",
    "dns record",
    "robots.txt",
    "sitemap.xml",
    "favicon hash",
    "http methods",
    "options method",
    "trace method",
    "cors enabled",
    "x-powered-by",
    "x-aspnet",
    "x-generator",
    "x-drupal",
    "x-wordpress",
])

# Nuclei templates that are purely informational
NUCLEI_INFO_TEMPLATES: frozenset[str] = frozenset([
    "tech-detect",
    "waf-detect",
    "http-missing-security-headers",
    "robots-txt",
    "sitemap",
    "favicon",
    "fingerprint",
    "version-detect",
    "server-status",
    "phpinfo",
])

# Nuclei templates to exclude (too noisy or dangerous)
NUCLEI_EXCLUDE_TEMPLATES: frozenset[str] = frozenset([
    "dos",
    "fuzzing",
    "brute-force",
    "wordpress-enum",
    "joomla-enum",
])

# Nuclei templates that should be promoted from info to low
NUCLEI_PROMOTE_TEMPLATES: frozenset[str] = frozenset([
    "exposed-git",
    "exposed-svn",
    "exposed-env",
    "exposed-config",
    "backup-files",
    "sensitive-files",
    "api-key-exposure",
    "jwt-secret",
    "aws-credentials",
    "azure-credentials",
    "gcp-credentials",
])


# =============================================================================
# DBMS PATTERNS
# =============================================================================

# Database-specific error patterns for DBMS fingerprinting
DBMS_ERROR_PATTERNS: dict[str, list[str]] = {
    "mysql": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysqli_",
        "mysql_fetch",
        "mysql_num_rows",
        "sql syntax.*mysql",
        "valid mysql result",
        "mysqlclient",
        "com.mysql.jdbc",
    ],
    "postgresql": [
        "pg_query",
        "pg_exec",
        "postgresql",
        "psql",
        "org.postgresql",
        "pgsql",
        "unterminated quoted string",
        "syntax error at or near",
    ],
    "mssql": [
        "microsoft sql server",
        "mssql_query",
        "odbc sql server",
        "sqlsrv_",
        "unclosed quotation mark",
        "sql server native client",
        "com.microsoft.sqlserver",
    ],
    "oracle": [
        "ora-[0-9]{5}",
        "oracle error",
        "oracle driver",
        "warning: oci_",
        "quoted string not properly terminated",
        "oracle.jdbc",
    ],
    "sqlite": [
        "sqlite_query",
        "sqlite3::",
        "sqliteexception",
        "sqlite.exception",
        "system.data.sqlite",
        "warning: sqlite_",
        "pdo_sqlite",
    ],
}

# DBMS-specific SQLi payloads
DBMS_SQLI_PAYLOADS: dict[str, list[str]] = {
    "mysql": [
        "' OR '1'='1",
        "' UNION SELECT NULL,NULL,@@version--",
        "' AND SLEEP(5)--",
        "' OR 1=1#",
        "admin'--",
    ],
    "postgresql": [
        "' OR '1'='1",
        "' UNION SELECT NULL,NULL,version()--",
        "'; SELECT pg_sleep(5)--",
        "' OR 1=1--",
    ],
    "mssql": [
        "' OR '1'='1",
        "' UNION SELECT NULL,NULL,@@version--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR 1=1--",
    ],
    "oracle": [
        "' OR '1'='1",
        "' UNION SELECT NULL,NULL,banner FROM v$version--",
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
    ],
    "sqlite": [
        "' OR '1'='1",
        "' UNION SELECT NULL,NULL,sqlite_version()--",
        "' AND 1=randomblob(500000000/2)--",
    ],
}


# =============================================================================
# XSS CONTEXT PATTERNS
# =============================================================================

# XSS reflection context patterns
XSS_CONTEXT_PATTERNS: dict[str, list[str]] = {
    "in_script": [
        r'<script[^>]*>[^<]*CANARY',
        r"var\s+\w+\s*=\s*['\"]CANARY",
        r"function\s*\([^)]*CANARY",
    ],
    "in_attribute": [
        r'<\w+[^>]+\w+=["\'][^"\']*CANARY',
        r'value=["\'][^"\']*CANARY',
        r'href=["\'][^"\']*CANARY',
    ],
    "in_event_handler": [
        r'on\w+=["\'][^"\']*CANARY',
        r'onclick=["\'][^"\']*CANARY',
        r'onerror=["\'][^"\']*CANARY',
    ],
    "in_html": [
        r'<[^>]*>CANARY<',
        r'>CANARY</',
    ],
    "in_comment": [
        r'<!--[^>]*CANARY',
    ],
    "in_style": [
        r'style=["\'][^"\']*CANARY',
        r'<style[^>]*>[^<]*CANARY',
    ],
}

# Context-specific XSS payloads
XSS_CONTEXT_PAYLOADS: dict[str, list[str]] = {
    "in_script": [
        "';alert(1)//",
        "\";alert(1)//",
        "</script><script>alert(1)</script>",
        "'-alert(1)-'",
    ],
    "in_attribute": [
        "\" onmouseover=\"alert(1)\"",
        "' onmouseover='alert(1)'",
        "\" autofocus onfocus=\"alert(1)\"",
    ],
    "in_event_handler": [
        "alert(1)",
        "alert`1`",
        "(alert)(1)",
    ],
    "in_html": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<script>alert(1)</script>",
    ],
    "in_style": [
        "expression(alert(1))",
        "url(javascript:alert(1))",
    ],
}
