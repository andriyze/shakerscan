"""
Credential Breach Monitoring for Security Assessment.

This module provides breach detection and credential leak monitoring using
free-tier APIs and public sources.

Features:
- HIBP (Have I Been Pwned) domain breach search
- Email pattern detection from web pages
- GitHub code search for leaked credentials
- Paste site monitoring (public sources)
- Breach severity scoring

Usage:
    # Check domain for breaches
    results = await check_domain_breaches("example.com")

    # Check specific email
    results = await check_email_breach("user@example.com")

    # Full breach assessment
    results = await breach_assessment("example.com", discovered_emails=["admin@example.com"])

Note: This module uses free-tier APIs with rate limiting.
HIBP API key can be provided for higher rate limits.
"""

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

# Rate limiting for API calls
_last_hibp_call = 0.0
_hibp_rate_limit = 1.5  # seconds between calls (HIBP requires 1.5s for free tier)

# Common email patterns in HTML/JS
EMAIL_PATTERNS = [
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
]

# Patterns that indicate credential exposure
CREDENTIAL_LEAK_PATTERNS = [
    # API keys
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "api_key"),
    (r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "secret_key"),
    # AWS
    (r'AKIA[0-9A-Z]{16}', "aws_access_key"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', "aws_secret_key"),
    # Database connection strings
    (r'(?i)(mongodb|postgres|mysql|redis)://[^\s<>"\']+', "database_url"),
    # Private keys
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "private_key"),
    # JWT tokens
    (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "jwt_token"),
    # Generic passwords in config
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', "hardcoded_password"),
]

# Known breach databases (metadata)
KNOWN_BREACHES_INFO = {
    "LinkedIn": {"year": 2012, "records": 164000000, "data_types": ["email", "password"]},
    "Adobe": {"year": 2013, "records": 153000000, "data_types": ["email", "password", "username"]},
    "Dropbox": {"year": 2012, "records": 68000000, "data_types": ["email", "password"]},
    "MySpace": {"year": 2008, "records": 360000000, "data_types": ["email", "password", "username"]},
    "Canva": {"year": 2019, "records": 137000000, "data_types": ["email", "password", "username"]},
}


@dataclass
class BreachInfo:
    """Information about a single breach."""
    name: str
    title: str
    domain: str
    breach_date: str | None = None
    added_date: str | None = None
    modified_date: str | None = None
    pwn_count: int = 0
    description: str | None = None
    data_classes: list[str] = field(default_factory=list)
    is_verified: bool = False
    is_sensitive: bool = False
    is_retired: bool = False
    logo_path: str | None = None

    @classmethod
    def from_hibp(cls, data: dict[str, Any]) -> "BreachInfo":
        """Create from HIBP API response."""
        return cls(
            name=data.get("Name", ""),
            title=data.get("Title", ""),
            domain=data.get("Domain", ""),
            breach_date=data.get("BreachDate"),
            added_date=data.get("AddedDate"),
            modified_date=data.get("ModifiedDate"),
            pwn_count=data.get("PwnCount", 0),
            description=data.get("Description"),
            data_classes=data.get("DataClasses", []),
            is_verified=data.get("IsVerified", False),
            is_sensitive=data.get("IsSensitive", False),
            is_retired=data.get("IsRetired", False),
            logo_path=data.get("LogoPath"),
        )


@dataclass
class BreachCheckResult:
    """Result of a breach check operation."""
    domain: str
    breaches_found: int = 0
    breaches: list[BreachInfo] = field(default_factory=list)
    emails_discovered: list[str] = field(default_factory=list)
    credential_leaks: list[dict[str, Any]] = field(default_factory=list)
    github_leaks: list[dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "unknown"
    errors: list[str] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


async def _http_get(url: str, headers: dict[str, str] | None = None, timeout: int = 30) -> dict[str, Any]:
    """Make HTTP GET request using curl subprocess."""

    cmd = ["curl", "-s", "-w", "\n%{http_code}", "-X", "GET"]

    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    cmd.append(url)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode("utf-8", errors="replace")

        lines = output.rsplit("\n", 2)
        if len(lines) >= 2:
            body = lines[0]
            status = int(lines[-1]) if lines[-1].isdigit() else 0
        else:
            body = output
            status = 0

        return {"status": status, "body": body}
    except TimeoutError:
        # Kill the subprocess on timeout to prevent orphans
        if proc:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        return {"status": 0, "body": "", "error": "timeout"}
    except asyncio.CancelledError:
        if proc:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        raise
    except Exception as e:
        return {"status": 0, "body": "", "error": str(e)}


async def _rate_limited_hibp_call():
    """Enforce HIBP rate limiting."""
    global _last_hibp_call
    now = time.time()
    elapsed = now - _last_hibp_call
    if elapsed < _hibp_rate_limit:
        await asyncio.sleep(_hibp_rate_limit - elapsed)
    _last_hibp_call = time.time()


async def get_all_breaches(hibp_api_key: str | None = None) -> list[BreachInfo]:
    """
    Get list of all breaches from HIBP.

    This endpoint is free and doesn't require authentication.
    """
    await _rate_limited_hibp_call()

    headers = {
        "User-Agent": "SecurityScanner-BreachCheck",
        "Accept": "application/json",
    }

    if hibp_api_key:
        headers["hibp-api-key"] = hibp_api_key

    response = await _http_get(
        "https://haveibeenpwned.com/api/v3/breaches",
        headers=headers
    )

    if response.get("status") == 200:
        try:
            data = json.loads(response.get("body", "[]"))
            return [BreachInfo.from_hibp(b) for b in data]
        except json.JSONDecodeError:
            return []

    return []


async def check_domain_breaches(
    domain: str,
    hibp_api_key: str | None = None
) -> list[BreachInfo]:
    """
    Check if a domain has been involved in any breaches.

    Uses HIBP's breach database to find breaches associated with the domain.
    Note: This checks if the domain itself was breached, not if emails
    from that domain appear in other breaches.
    """
    # Get all breaches and filter by domain
    all_breaches = await get_all_breaches(hibp_api_key)

    domain_lower = domain.lower()
    matching = []

    for breach in all_breaches:
        # Check if breach domain matches
        if breach.domain.lower() == domain_lower or domain_lower in breach.name.lower() or domain_lower in breach.title.lower():
            matching.append(breach)

    return matching


async def check_email_breach(
    email: str,
    hibp_api_key: str | None = None,
    truncate_response: bool = True
) -> list[BreachInfo]:
    """
    Check if an email address has been involved in any breaches.

    Note: The HIBP v3 API requires an API key for email lookups.
    Without an API key, this function returns an empty list with an error.
    """
    if not hibp_api_key:
        # Can't check individual emails without API key
        return []

    await _rate_limited_hibp_call()

    headers = {
        "User-Agent": "SecurityScanner-BreachCheck",
        "Accept": "application/json",
        "hibp-api-key": hibp_api_key,
    }

    email_encoded = quote(email)
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_encoded}"

    if truncate_response:
        url += "?truncateResponse=true"

    response = await _http_get(url, headers=headers)

    if response.get("status") == 200:
        try:
            data = json.loads(response.get("body", "[]"))
            return [BreachInfo.from_hibp(b) for b in data]
        except json.JSONDecodeError:
            return []
    elif response.get("status") == 404:
        # Email not found in any breaches (good!)
        return []

    return []


async def check_password_pwned(password: str) -> tuple[bool, int]:
    """
    Check if a password has been exposed in breaches using k-anonymity.

    Uses HIBP's Pwned Passwords API with k-anonymity - only sends
    first 5 characters of SHA-1 hash, never the full password.

    Returns: (is_pwned, count) - whether password is pwned and how many times
    """
    # Hash the password
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    await _rate_limited_hibp_call()

    headers = {
        "User-Agent": "SecurityScanner-BreachCheck",
    }

    response = await _http_get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers=headers
    )

    if response.get("status") == 200:
        body = response.get("body", "")
        for line in body.split("\n"):
            line = line.strip()
            if ":" in line:
                hash_suffix, count = line.split(":")
                if hash_suffix.upper() == suffix:
                    return True, int(count)

    return False, 0


def extract_emails_from_text(text: str, domain: str | None = None) -> set[str]:
    """
    Extract email addresses from text content.

    If domain is provided, only returns emails matching that domain.
    """
    emails = set()

    for pattern in EMAIL_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            email = match.lower() if isinstance(match, str) else match[0].lower()
            # Validate email format
            if "@" in email and "." in email.split("@")[1]:
                if domain:
                    if email.endswith(f"@{domain.lower()}"):
                        emails.add(email)
                else:
                    emails.add(email)

    return emails


def detect_credential_leaks(text: str, source_url: str = "") -> list[dict[str, Any]]:
    """
    Detect potential credential leaks in text content.

    Returns list of detected leaks with type and masked value.
    """
    leaks = []

    for pattern, leak_type in CREDENTIAL_LEAK_PATTERNS:
        matches = re.finditer(pattern, text)
        for match in matches:
            value = match.group(0)
            # Mask the sensitive value (show first 4 and last 4 chars)
            if len(value) > 12:
                masked = value[:4] + "*" * (len(value) - 8) + value[-4:]
            else:
                masked = value[:2] + "*" * (len(value) - 2)

            leaks.append({
                "type": leak_type,
                "masked_value": masked,
                "source": source_url,
                "position": match.start(),
                "length": len(value),
            })

    return leaks


async def search_github_leaks(
    domain: str,
    max_results: int = 10,
    github_token: str | None = None
) -> list[dict[str, Any]]:
    """
    Search GitHub for potential credential leaks related to domain.

    Uses GitHub code search API (requires authentication for higher rate limits).

    Note: GitHub search is rate-limited. Without token: 10 requests/minute.
    With token: 30 requests/minute.
    """
    results = []

    # Search queries for common leak patterns
    search_queries = [
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
        f'filename:.env "{domain}"',
        f'filename:config "{domain}" password',
    ]

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SecurityScanner-BreachCheck",
    }

    if github_token:
        headers["Authorization"] = f"token {github_token}"

    for query in search_queries[:3]:  # Limit queries to avoid rate limiting
        encoded_query = quote(query)
        url = f"https://api.github.com/search/code?q={encoded_query}&per_page={max_results}"

        response = await _http_get(url, headers=headers)

        if response.get("status") == 200:
            try:
                data = json.loads(response.get("body", "{}"))
                items = data.get("items", [])

                for item in items[:max_results]:
                    results.append({
                        "repository": item.get("repository", {}).get("full_name"),
                        "file_path": item.get("path"),
                        "file_url": item.get("html_url"),
                        "query": query,
                        "score": item.get("score", 0),
                    })
            except json.JSONDecodeError:
                pass

        # Rate limiting
        await asyncio.sleep(2)

        if len(results) >= max_results:
            break

    # Deduplicate by file URL
    seen = set()
    unique_results = []
    for r in results:
        if r["file_url"] not in seen:
            seen.add(r["file_url"])
            unique_results.append(r)

    return unique_results[:max_results]


def calculate_breach_risk_score(
    breaches: list[BreachInfo],
    credential_leaks: list[dict[str, Any]],
    github_leaks: list[dict[str, Any]]
) -> tuple[float, str]:
    """
    Calculate overall breach risk score (0-100) and risk level.

    Factors:
    - Number and severity of breaches
    - Recency of breaches
    - Types of data exposed
    - Credential leaks found
    - GitHub exposure
    """
    score = 0.0

    # Breach scoring
    for breach in breaches:
        # Base score per breach
        breach_score = 10.0

        # Severity multipliers
        if breach.is_verified:
            breach_score *= 1.5

        # Data type severity
        high_risk_data = ["Passwords", "Credit cards", "Social security numbers", "Bank account numbers"]
        medium_risk_data = ["Email addresses", "Phone numbers", "Physical addresses"]

        for data_class in breach.data_classes:
            if data_class in high_risk_data:
                breach_score += 15
            elif data_class in medium_risk_data:
                breach_score += 5

        # Recency (breaches in last 2 years are more concerning)
        if breach.breach_date:
            try:
                breach_year = int(breach.breach_date[:4])
                current_year = datetime.now().year
                if current_year - breach_year <= 2:
                    breach_score *= 1.5
                elif current_year - breach_year <= 5:
                    breach_score *= 1.2
            except (ValueError, TypeError):
                pass

        # Scale (large breaches are more concerning)
        if breach.pwn_count > 100000000:
            breach_score *= 1.3
        elif breach.pwn_count > 10000000:
            breach_score *= 1.2

        score += breach_score

    # Credential leak scoring
    for leak in credential_leaks:
        leak_type = leak.get("type", "")
        if leak_type in ["aws_access_key", "aws_secret_key", "private_key"]:
            score += 25
        elif leak_type in ["api_key", "secret_key", "database_url"]:
            score += 20
        elif leak_type in ["jwt_token", "hardcoded_password"]:
            score += 15
        else:
            score += 10

    # GitHub leak scoring
    for leak in github_leaks:
        score += 15

    # Cap at 100
    score = min(score, 100.0)

    # Determine risk level
    if score >= 80:
        risk_level = "critical"
    elif score >= 60:
        risk_level = "high"
    elif score >= 40:
        risk_level = "medium"
    elif score >= 20:
        risk_level = "low"
    else:
        risk_level = "minimal"

    return round(score, 1), risk_level


async def breach_assessment(
    domain: str,
    discovered_emails: list[str] | None = None,
    page_content: str | None = None,
    hibp_api_key: str | None = None,
    github_token: str | None = None,
    check_github: bool = True,
    max_emails: int = 10
) -> BreachCheckResult:
    """
    Perform comprehensive breach assessment for a domain.

    Args:
        domain: Domain to assess
        discovered_emails: List of email addresses found during scanning
        page_content: HTML/JS content to scan for emails and credentials
        hibp_api_key: HIBP API key for email lookups (optional)
        github_token: GitHub token for code search (optional)
        check_github: Whether to search GitHub for leaks
        max_emails: Maximum number of emails to check individually

    Returns:
        BreachCheckResult with all findings
    """
    result = BreachCheckResult(domain=domain)

    # Check domain breaches
    try:
        domain_breaches = await check_domain_breaches(domain, hibp_api_key)
        result.breaches = domain_breaches
        result.breaches_found = len(domain_breaches)
    except Exception as e:
        result.errors.append(f"Domain breach check failed: {e}")

    # Extract emails from page content if provided
    if page_content:
        extracted_emails = extract_emails_from_text(page_content, domain)
        if discovered_emails:
            discovered_emails = list(set(discovered_emails) | extracted_emails)
        else:
            discovered_emails = list(extracted_emails)

        # Check for credential leaks in content
        leaks = detect_credential_leaks(page_content)
        result.credential_leaks = leaks

    # Check individual emails (requires API key)
    if discovered_emails and hibp_api_key:
        emails_to_check = discovered_emails[:max_emails]
        for email in emails_to_check:
            try:
                email_breaches = await check_email_breach(email, hibp_api_key)
                # Add unique breaches
                existing_names = {b.name for b in result.breaches}
                for breach in email_breaches:
                    if breach.name not in existing_names:
                        result.breaches.append(breach)
                        existing_names.add(breach.name)
            except Exception as e:
                result.errors.append(f"Email check failed for {email}: {e}")

        result.breaches_found = len(result.breaches)

    result.emails_discovered = discovered_emails or []

    # Search GitHub for leaks
    if check_github:
        try:
            github_leaks = await search_github_leaks(domain, github_token=github_token)
            result.github_leaks = github_leaks
        except Exception as e:
            result.errors.append(f"GitHub search failed: {e}")

    # Calculate risk score
    risk_score, risk_level = calculate_breach_risk_score(
        result.breaches,
        result.credential_leaks,
        result.github_leaks
    )
    result.risk_score = risk_score
    result.risk_level = risk_level

    return result


def generate_breach_findings(result: BreachCheckResult) -> list[dict[str, Any]]:
    """
    Generate scanner findings from breach check results.
    """
    findings = []

    # Domain breach findings
    if result.breaches:
        for breach in result.breaches:
            severity = "high" if breach.is_verified else "medium"
            cvss = 7.5 if breach.is_verified else 5.5

            # Check for password exposure
            if "Passwords" in breach.data_classes:
                severity = "critical"
                cvss = 9.0

            breach_id = hashlib.md5(f"breach_{breach.name}".encode()).hexdigest()[:8]

            finding = {
                "id": f"breach_check:{breach_id}",
                "tool": "breach_check",
                "title": f"Domain involved in '{breach.title}' data breach",
                "severity": severity,
                "cvss_score": cvss,
                "description": breach.description or f"The domain was involved in the {breach.title} breach.",
                "evidence": {
                    "breach_name": breach.name,
                    "breach_date": breach.breach_date,
                    "records_exposed": breach.pwn_count,
                    "data_types": breach.data_classes,
                    "is_verified": breach.is_verified,
                },
                "remediation": "Review affected accounts, force password resets, enable MFA, and monitor for unauthorized access.",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "cwe": "CWE-521",
            }
            findings.append(finding)

    # Credential leak findings
    for leak in result.credential_leaks:
        leak_id = hashlib.md5(f"cred_{leak['type']}_{leak['position']}".encode()).hexdigest()[:8]

        severity_map = {
            "aws_access_key": ("critical", 9.5),
            "aws_secret_key": ("critical", 9.5),
            "private_key": ("critical", 9.5),
            "api_key": ("high", 8.0),
            "secret_key": ("high", 8.0),
            "database_url": ("high", 8.5),
            "jwt_token": ("high", 7.5),
            "hardcoded_password": ("high", 7.5),
        }

        severity, cvss = severity_map.get(leak["type"], ("medium", 6.0))

        finding = {
            "id": f"breach_check:{leak_id}",
            "tool": "breach_check",
            "title": f"Exposed {leak['type'].replace('_', ' ').title()} detected",
            "severity": severity,
            "cvss_score": cvss,
            "description": f"A {leak['type'].replace('_', ' ')} was found exposed in page content.",
            "evidence": {
                "type": leak["type"],
                "masked_value": leak["masked_value"],
                "source": leak.get("source", ""),
            },
            "remediation": "Rotate the exposed credential immediately and review access logs for unauthorized usage.",
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-798",
        }
        findings.append(finding)

    # GitHub leak findings
    for leak in result.github_leaks:
        leak_id = hashlib.md5(f"github_{leak['file_url']}".encode()).hexdigest()[:8]

        finding = {
            "id": f"breach_check:{leak_id}",
            "tool": "breach_check",
            "title": "Potential credential exposure on GitHub",
            "severity": "high",
            "cvss_score": 7.5,
            "description": "Potential credentials related to this domain found in public GitHub repository.",
            "evidence": {
                "repository": leak["repository"],
                "file_path": leak["file_path"],
                "file_url": leak["file_url"],
                "search_query": leak["query"],
            },
            "remediation": "Review the exposed file, rotate any leaked credentials, and request removal from GitHub if necessary.",
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-312",
        }
        findings.append(finding)

    return findings


async def test_breach_check(domain: str) -> dict[str, Any]:
    """
    Test breach checking functionality and return detailed results.
    """
    results = {
        "domain": domain,
        "timestamp": datetime.now(UTC).isoformat(),
        "hibp_accessible": False,
        "github_accessible": False,
        "domain_breaches": [],
        "errors": []
    }

    # Test HIBP accessibility
    try:
        breaches = await get_all_breaches()
        results["hibp_accessible"] = len(breaches) > 0
        results["total_breaches_in_database"] = len(breaches)

        # Check for domain
        domain_breaches = await check_domain_breaches(domain)
        results["domain_breaches"] = [
            {
                "name": b.name,
                "title": b.title,
                "breach_date": b.breach_date,
                "pwn_count": b.pwn_count,
                "data_classes": b.data_classes,
            }
            for b in domain_breaches
        ]
    except Exception as e:
        results["errors"].append(f"HIBP check failed: {e}")

    # Test GitHub accessibility (without token)
    try:
        github_results = await search_github_leaks(domain, max_results=3)
        results["github_accessible"] = True
        results["github_results_count"] = len(github_results)
    except Exception as e:
        results["errors"].append(f"GitHub search failed: {e}")

    return results


# Export main functions
__all__ = [
    "BreachCheckResult",
    "BreachInfo",
    "breach_assessment",
    "check_domain_breaches",
    "check_email_breach",
    "check_password_pwned",
    "detect_credential_leaks",
    "extract_emails_from_text",
    "generate_breach_findings",
    "get_all_breaches",
    "search_github_leaks",
    "test_breach_check",
]
