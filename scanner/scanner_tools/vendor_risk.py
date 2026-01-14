"""
Vendor/Third-Party Risk Scoring Module.

This module analyzes third-party JavaScript dependencies and external resources
to assess supply chain security risks.

Features:
- Third-party JavaScript source inventory
- CDN and external resource detection
- Security posture scoring for dependencies
- Fourth-party dependency detection
- Risk scoring and categorization

Usage:
    result = await vendor_risk_assessment(
        base_url="https://example.com",
        page_content=html_content,
        js_urls=discovered_js_urls
    )
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    aiohttp = None

# Known CDN domains and their risk profiles
KNOWN_CDNS = {
    # Major CDNs (generally trusted)
    "cdnjs.cloudflare.com": {"provider": "Cloudflare", "trust_level": "high"},
    "cdn.jsdelivr.net": {"provider": "jsDelivr", "trust_level": "high"},
    "unpkg.com": {"provider": "Unpkg", "trust_level": "high"},
    "ajax.googleapis.com": {"provider": "Google", "trust_level": "high"},
    "code.jquery.com": {"provider": "jQuery Foundation", "trust_level": "high"},
    "stackpath.bootstrapcdn.com": {"provider": "StackPath", "trust_level": "high"},
    "maxcdn.bootstrapcdn.com": {"provider": "MaxCDN", "trust_level": "high"},
    "cdn.bootcss.com": {"provider": "BootCDN", "trust_level": "medium"},
    "cdn.bootcdn.net": {"provider": "BootCDN", "trust_level": "medium"},
    "lib.baomitu.com": {"provider": "Baomitu", "trust_level": "medium"},

    # Analytics/tracking (privacy concerns)
    "www.google-analytics.com": {"provider": "Google Analytics", "trust_level": "medium", "category": "analytics"},
    "www.googletagmanager.com": {"provider": "Google Tag Manager", "trust_level": "medium", "category": "analytics"},
    "connect.facebook.net": {"provider": "Facebook", "trust_level": "medium", "category": "analytics"},
    "platform.twitter.com": {"provider": "Twitter", "trust_level": "medium", "category": "social"},
    "static.hotjar.com": {"provider": "Hotjar", "trust_level": "medium", "category": "analytics"},
    "cdn.segment.com": {"provider": "Segment", "trust_level": "medium", "category": "analytics"},
    "cdn.amplitude.com": {"provider": "Amplitude", "trust_level": "medium", "category": "analytics"},
    "cdn.mxpnl.com": {"provider": "Mixpanel", "trust_level": "medium", "category": "analytics"},

    # Payment/sensitive (high scrutiny)
    "js.stripe.com": {"provider": "Stripe", "trust_level": "high", "category": "payment"},
    "www.paypalobjects.com": {"provider": "PayPal", "trust_level": "high", "category": "payment"},
    "js.braintreegateway.com": {"provider": "Braintree", "trust_level": "high", "category": "payment"},

    # Chat/support widgets
    "widget.intercom.io": {"provider": "Intercom", "trust_level": "medium", "category": "chat"},
    "embed.tawk.to": {"provider": "Tawk.to", "trust_level": "medium", "category": "chat"},
    "js.driftt.com": {"provider": "Drift", "trust_level": "medium", "category": "chat"},
    "cdn.zendesk.com": {"provider": "Zendesk", "trust_level": "medium", "category": "support"},

    # Authentication providers (trusted - these are legitimate identity services)
    "clerk.accounts.dev": {"provider": "Clerk", "trust_level": "high", "category": "auth"},
    "clerk.com": {"provider": "Clerk", "trust_level": "high", "category": "auth"},
    "clerk-js.com": {"provider": "Clerk", "trust_level": "high", "category": "auth"},
    "accounts.dev": {"provider": "Clerk", "trust_level": "high", "category": "auth"},
    "auth0.com": {"provider": "Auth0", "trust_level": "high", "category": "auth"},
    "cdn.auth0.com": {"provider": "Auth0", "trust_level": "high", "category": "auth"},
    "supabase.co": {"provider": "Supabase", "trust_level": "high", "category": "auth"},
    "supabase.com": {"provider": "Supabase", "trust_level": "high", "category": "auth"},
    "accounts.google.com": {"provider": "Google", "trust_level": "high", "category": "auth"},
    "apis.google.com": {"provider": "Google", "trust_level": "high", "category": "auth"},
    "login.microsoftonline.com": {"provider": "Microsoft", "trust_level": "high", "category": "auth"},
    "login.live.com": {"provider": "Microsoft", "trust_level": "high", "category": "auth"},
    "appleid.apple.com": {"provider": "Apple", "trust_level": "high", "category": "auth"},
    "cognito-idp.amazonaws.com": {"provider": "AWS Cognito", "trust_level": "high", "category": "auth"},
    "kinde.com": {"provider": "Kinde", "trust_level": "high", "category": "auth"},
    "stytch.com": {"provider": "Stytch", "trust_level": "high", "category": "auth"},
    "workos.com": {"provider": "WorkOS", "trust_level": "high", "category": "auth"},
    "descope.com": {"provider": "Descope", "trust_level": "high", "category": "auth"},

    # Security/verification services (trusted)
    "challenges.cloudflare.com": {"provider": "Cloudflare", "trust_level": "high", "category": "security"},
    "www.recaptcha.net": {"provider": "Google reCAPTCHA", "trust_level": "high", "category": "security"},
    "www.gstatic.com": {"provider": "Google Static", "trust_level": "high", "category": "cdn"},
    "hcaptcha.com": {"provider": "hCaptcha", "trust_level": "high", "category": "security"},
    "js.hcaptcha.com": {"provider": "hCaptcha", "trust_level": "high", "category": "security"},
    "www.google.com": {"provider": "Google", "trust_level": "high", "category": "security"},

    # Firebase (Google)
    "firebaseapp.com": {"provider": "Firebase", "trust_level": "high", "category": "backend"},
    "firebase.google.com": {"provider": "Firebase", "trust_level": "high", "category": "backend"},
    "firebaseio.com": {"provider": "Firebase", "trust_level": "high", "category": "backend"},

    # Vercel/Next.js infrastructure
    "vercel.com": {"provider": "Vercel", "trust_level": "high", "category": "hosting"},
    "vercel.app": {"provider": "Vercel", "trust_level": "high", "category": "hosting"},
    "va.vercel-scripts.com": {"provider": "Vercel", "trust_level": "high", "category": "analytics"},

    # Cloudflare services
    "cloudflare.com": {"provider": "Cloudflare", "trust_level": "high", "category": "cdn"},
    "cloudflareinsights.com": {"provider": "Cloudflare", "trust_level": "high", "category": "analytics"},
    "static.cloudflareinsights.com": {"provider": "Cloudflare", "trust_level": "high", "category": "analytics"},

    # Font services
    "fonts.googleapis.com": {"provider": "Google Fonts", "trust_level": "high", "category": "fonts"},
    "fonts.gstatic.com": {"provider": "Google Fonts", "trust_level": "high", "category": "fonts"},
    "use.typekit.net": {"provider": "Adobe Fonts", "trust_level": "high", "category": "fonts"},
    "use.fontawesome.com": {"provider": "Font Awesome", "trust_level": "high", "category": "fonts"},
    "kit.fontawesome.com": {"provider": "Font Awesome", "trust_level": "high", "category": "fonts"},
}

# Patterns for detecting third-party resources in HTML
THIRD_PARTY_PATTERNS = [
    # Script tags
    r'<script[^>]+src=["\']([^"\']+)["\']',
    # Link tags (stylesheets, preload)
    r'<link[^>]+href=["\']([^"\']+)["\']',
    # Image sources
    r'<img[^>]+src=["\']([^"\']+)["\']',
    # Iframe sources
    r'<iframe[^>]+src=["\']([^"\']+)["\']',
]

# Security header requirements for third-party resources
REQUIRED_HEADERS = {
    "strict-transport-security": {"required": True, "weight": 20},
    "content-security-policy": {"required": False, "weight": 15},
    "x-content-type-options": {"required": True, "weight": 10},
    "x-frame-options": {"required": False, "weight": 5},
}


@dataclass
class ThirdPartyResource:
    """Represents a third-party resource."""
    url: str
    domain: str
    resource_type: str  # script, stylesheet, image, iframe
    provider: str | None = None
    category: str | None = None
    trust_level: str = "unknown"
    tls_valid: bool = True
    security_headers: dict[str, str] = field(default_factory=dict)
    security_score: int = 0
    risk_factors: list[str] = field(default_factory=list)
    fourth_parties: list[str] = field(default_factory=list)
    content_hash: str | None = None
    size_bytes: int | None = None


@dataclass
class VendorRiskResult:
    """Result of vendor risk assessment."""
    target: str
    assessed_at: str
    total_third_parties: int
    third_party_domains: list[str]
    resources: list[ThirdPartyResource]
    risk_score: int  # 0-100, higher = more risk
    risk_level: str  # low, medium, high, critical
    findings: list[dict[str, Any]]
    summary: dict[str, Any]


def extract_domain(url: str) -> str:
    """Extract domain from URL, stripping port numbers."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        # Strip port number if present
        if ':' in netloc:
            netloc = netloc.rsplit(':', 1)[0]
        return netloc
    except Exception:
        return ""


# Common multi-part TLDs that need special handling
MULTI_PART_TLDS = {
    'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'plc.uk',
    'co.nz', 'org.nz', 'net.nz', 'govt.nz', 'ac.nz',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
    'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
    'co.kr', 'ne.kr', 'or.kr', 'go.kr', 're.kr',
    'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
    'co.za', 'net.za', 'org.za', 'gov.za', 'edu.za',
    'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
    'com.hk', 'net.hk', 'org.hk', 'gov.hk', 'edu.hk',
    'co.il', 'net.il', 'org.il', 'gov.il', 'ac.il',
}


def get_registrable_domain(domain: str) -> str:
    """
    Get the registrable domain (eTLD+1) handling multi-part TLDs.

    Examples:
        example.co.uk -> example.co.uk (not co.uk)
        sub.example.com -> example.com
        cdn.example.co.uk -> example.co.uk
    """
    parts = domain.lower().split('.')
    if len(parts) < 2:
        return domain

    # Check for multi-part TLDs (last 2 parts)
    potential_tld = '.'.join(parts[-2:])
    if potential_tld in MULTI_PART_TLDS:
        # Need 3 parts for multi-part TLD
        if len(parts) >= 3:
            return '.'.join(parts[-3:])
        return domain

    # Standard TLD - use last 2 parts
    return '.'.join(parts[-2:])


def is_third_party(resource_url: str, base_domain: str) -> bool:
    """Check if a resource is from a third-party domain."""
    # Handle protocol-relative URLs (//cdn.example.com) - these ARE third-party
    if resource_url.startswith('//'):
        # Extract domain from protocol-relative URL
        resource_domain = resource_url[2:].split('/')[0].split('?')[0].lower()
        # Strip port if present
        if ':' in resource_domain:
            resource_domain = resource_domain.rsplit(':', 1)[0]
    else:
        # Handle relative URLs (same origin)
        if resource_url.startswith("/") or resource_url.startswith("./"):
            return False
        resource_domain = extract_domain(resource_url)

    if not resource_domain:
        return False

    # Strip port from base_domain if present
    base_domain_clean = base_domain.lower()
    if ':' in base_domain_clean:
        base_domain_clean = base_domain_clean.rsplit(':', 1)[0]

    # Get registrable domains (handles multi-part TLDs like co.uk)
    base_root = get_registrable_domain(base_domain_clean)
    resource_root = get_registrable_domain(resource_domain)

    return base_root != resource_root


def get_resource_type(url: str, context: str = "") -> str:
    """Determine resource type from URL and context."""
    url_lower = url.lower()

    if ".js" in url_lower or "javascript" in context.lower():
        return "script"
    elif ".css" in url_lower or "stylesheet" in context.lower():
        return "stylesheet"
    elif any(ext in url_lower for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico"]):
        return "image"
    elif "iframe" in context.lower():
        return "iframe"
    elif ".woff" in url_lower or ".ttf" in url_lower or ".eot" in url_lower:
        return "font"
    else:
        return "other"


def extract_third_party_resources(
    html_content: str,
    base_url: str
) -> list[tuple[str, str]]:
    """
    Extract third-party resource URLs from HTML content.

    Returns list of (url, resource_type) tuples.
    """
    base_domain = extract_domain(base_url)
    resources = []
    seen_urls = set()

    # Extract from script tags
    for match in re.finditer(r'<script[^>]*\ssrc=["\']([^"\']+)["\']', html_content, re.IGNORECASE):
        url = match.group(1)
        if url not in seen_urls and is_third_party(url, base_domain):
            resources.append((url, "script"))
            seen_urls.add(url)

    # Extract from link tags
    for match in re.finditer(r'<link[^>]*\shref=["\']([^"\']+)["\']', html_content, re.IGNORECASE):
        url = match.group(1)
        context = match.group(0)
        if url not in seen_urls and is_third_party(url, base_domain):
            rtype = "stylesheet" if "stylesheet" in context.lower() else "other"
            resources.append((url, rtype))
            seen_urls.add(url)

    # Extract from img tags
    for match in re.finditer(r'<img[^>]*\ssrc=["\']([^"\']+)["\']', html_content, re.IGNORECASE):
        url = match.group(1)
        if url not in seen_urls and is_third_party(url, base_domain):
            resources.append((url, "image"))
            seen_urls.add(url)

    # Extract from iframe tags
    for match in re.finditer(r'<iframe[^>]*\ssrc=["\']([^"\']+)["\']', html_content, re.IGNORECASE):
        url = match.group(1)
        if url not in seen_urls and is_third_party(url, base_domain):
            resources.append((url, "iframe"))
            seen_urls.add(url)

    return resources


async def check_resource_security(
    url: str,
    timeout: int = 10
) -> dict[str, Any]:
    """
    Check security posture of a third-party resource.

    Returns security headers, TLS status, and content hash.
    """
    result = {
        "url": url,
        "tls_valid": False,
        "security_headers": {},
        "content_hash": None,
        "size_bytes": None,
        "error": None,
    }

    if not HAS_AIOHTTP:
        result["error"] = "aiohttp not available"
        return result

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=True,
                allow_redirects=True
            ) as response:
                result["tls_valid"] = True
                result["status_code"] = response.status

                # Extract security headers
                headers_to_check = [
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                    "x-xss-protection",
                    "access-control-allow-origin",
                ]
                for header in headers_to_check:
                    value = response.headers.get(header)
                    if value:
                        result["security_headers"][header] = value

                # Get content for hashing (limited to first 1MB)
                content = await response.content.read(1024 * 1024)
                result["size_bytes"] = len(content)
                result["content_hash"] = hashlib.sha256(content).hexdigest()[:16]

    except aiohttp.ClientSSLError as e:
        result["error"] = f"SSL error: {e!s}"
        result["tls_valid"] = False
    except TimeoutError:
        result["error"] = "Timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


def calculate_resource_score(resource: ThirdPartyResource) -> tuple[int, list[str]]:
    """
    Calculate security score for a third-party resource.

    Returns (score, risk_factors) where score is 0-100 (higher = better).
    """
    score = 100
    risk_factors = []

    # Trust level adjustments
    if resource.trust_level == "unknown":
        score -= 20
        risk_factors.append("Unknown/unverified provider")
    elif resource.trust_level == "low":
        score -= 30
        risk_factors.append("Low-trust provider")
    elif resource.trust_level == "medium":
        score -= 10

    # TLS validation
    if not resource.tls_valid:
        score -= 30
        risk_factors.append("Invalid or missing TLS")

    # Security headers
    if "strict-transport-security" not in resource.security_headers:
        score -= 15
        risk_factors.append("Missing HSTS header")

    if "x-content-type-options" not in resource.security_headers:
        score -= 10
        risk_factors.append("Missing X-Content-Type-Options")

    # CORS configuration
    cors = resource.security_headers.get("access-control-allow-origin", "")
    if cors == "*":
        score -= 10
        risk_factors.append("Overly permissive CORS (wildcard)")

    # Category-specific adjustments
    if resource.category == "analytics":
        score -= 5
        risk_factors.append("Analytics/tracking script (privacy concern)")
    elif resource.category == "payment":
        # Payment scripts should have high security
        if score < 80:
            risk_factors.append("Payment script with security concerns")

    # Fourth-party dependencies
    if resource.fourth_parties:
        score -= 5 * min(len(resource.fourth_parties), 5)
        risk_factors.append(f"Loads {len(resource.fourth_parties)} fourth-party resources")

    # Resource type adjustments
    if resource.resource_type == "script":
        # Scripts are highest risk
        if score < 70:
            risk_factors.append("JavaScript with security concerns")
    elif resource.resource_type == "iframe":
        score -= 10
        risk_factors.append("External iframe (potential for clickjacking)")

    return max(0, min(100, score)), risk_factors


def calculate_overall_risk(resources: list[ThirdPartyResource]) -> tuple[int, str]:
    """
    Calculate overall vendor risk score.

    Returns (risk_score, risk_level) where risk_score is 0-100 (higher = more risky).
    """
    if not resources:
        return 0, "low"

    # Aggregate scores (invert because resource score is "good" but risk is "bad")
    scores = [100 - r.security_score for r in resources]

    # Weight scripts more heavily
    weighted_scores = []
    for r in resources:
        weight = 2.0 if r.resource_type == "script" else 1.0
        weight *= 1.5 if r.category == "payment" else 1.0
        weighted_scores.append((100 - r.security_score) * weight)

    avg_risk = sum(weighted_scores) / len(weighted_scores) if weighted_scores else 0

    # Additional risk factors
    num_domains = len(set(r.domain for r in resources))
    if num_domains > 10:
        avg_risk += 10  # Too many third parties

    num_unknown = sum(1 for r in resources if r.trust_level == "unknown")
    if num_unknown > 5:
        avg_risk += 10  # Too many unknown providers

    # Cap at 100
    risk_score = min(100, int(avg_risk))

    # Determine risk level
    if risk_score >= 70:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    return risk_score, risk_level


def generate_vendor_findings(result: VendorRiskResult) -> list[dict[str, Any]]:
    """Generate security findings from vendor risk assessment."""
    findings = []

    # High-risk third parties
    high_risk_resources = [r for r in result.resources if r.security_score < 50]
    if high_risk_resources:
        findings.append({
            "id": f"vendor_risk:high_risk_{hashlib.md5(result.target.encode()).hexdigest()[:8]}",
            "tool": "vendor_risk",
            "title": f"High-risk third-party resources detected ({len(high_risk_resources)})",
            "severity": "high",
            "cvss_score": 6.5,
            "cwe": "CWE-829",
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "description": f"Found {len(high_risk_resources)} third-party resources with security concerns",
            "evidence": {
                "resources": [
                    {
                        "url": r.url,
                        "domain": r.domain,
                        "score": r.security_score,
                        "risk_factors": r.risk_factors[:3]
                    }
                    for r in high_risk_resources[:5]
                ]
            },
            "remediation": "Review and audit high-risk third-party resources. Consider self-hosting critical dependencies or using Subresource Integrity (SRI)."
        })

    # Missing SRI for scripts
    scripts_without_sri = [r for r in result.resources if r.resource_type == "script"]
    if scripts_without_sri:
        findings.append({
            "id": f"vendor_risk:no_sri_{hashlib.md5(result.target.encode()).hexdigest()[:8]}",
            "tool": "vendor_risk",
            "title": "Third-party scripts without Subresource Integrity (SRI)",
            "severity": "medium",
            "cvss_score": 5.3,
            "cwe": "CWE-353",
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "description": f"Found {len(scripts_without_sri)} external scripts that could benefit from SRI hashes",
            "evidence": {
                "scripts": [r.url for r in scripts_without_sri[:10]]
            },
            "remediation": "Add integrity attributes to script tags for third-party resources. Example: <script src='...' integrity='sha384-...' crossorigin='anonymous'>"
        })

    # Unknown providers
    unknown_providers = [r for r in result.resources if r.trust_level == "unknown"]
    if unknown_providers:
        findings.append({
            "id": f"vendor_risk:unknown_providers_{hashlib.md5(result.target.encode()).hexdigest()[:8]}",
            "tool": "vendor_risk",
            "title": f"Resources from unknown/unverified providers ({len(unknown_providers)})",
            "severity": "low",
            "cvss_score": 3.7,
            "cwe": "CWE-829",
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "description": f"Found {len(unknown_providers)} resources from providers not in the known CDN/vendor list",
            "evidence": {
                "domains": list(set(r.domain for r in unknown_providers))[:10]
            },
            "remediation": "Review resources from unknown providers. Consider using well-known CDNs or self-hosting."
        })

    # TLS issues
    tls_issues = [r for r in result.resources if not r.tls_valid]
    if tls_issues:
        findings.append({
            "id": f"vendor_risk:tls_issues_{hashlib.md5(result.target.encode()).hexdigest()[:8]}",
            "tool": "vendor_risk",
            "title": f"Third-party resources with TLS issues ({len(tls_issues)})",
            "severity": "high",
            "cvss_score": 7.5,
            "cwe": "CWE-295",
            "owasp": "A02:2021 - Cryptographic Failures",
            "description": f"Found {len(tls_issues)} third-party resources with invalid or missing TLS",
            "evidence": {
                "resources": [r.url for r in tls_issues[:5]]
            },
            "remediation": "Ensure all third-party resources are loaded over valid HTTPS connections."
        })

    # Excessive third parties
    if result.total_third_parties > 20:
        findings.append({
            "id": f"vendor_risk:excessive_{hashlib.md5(result.target.encode()).hexdigest()[:8]}",
            "tool": "vendor_risk",
            "title": f"Excessive third-party dependencies ({result.total_third_parties})",
            "severity": "low",
            "cvss_score": 3.1,
            "cwe": "CWE-1104",
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "description": f"Page loads resources from {len(result.third_party_domains)} different third-party domains",
            "evidence": {
                "domain_count": len(result.third_party_domains),
                "domains": result.third_party_domains[:20]
            },
            "remediation": "Reduce the number of third-party dependencies to minimize attack surface and improve performance."
        })

    return findings


async def vendor_risk_assessment(
    base_url: str,
    page_content: str | None = None,
    js_urls: list[str] | None = None,
    check_security: bool = True,
    max_resources: int = 50,
    timeout: int = 10
) -> VendorRiskResult:
    """
    Perform vendor/third-party risk assessment.

    Args:
        base_url: The target website URL
        page_content: HTML content of the page (optional, will fetch if not provided)
        js_urls: Additional JavaScript URLs to analyze
        check_security: Whether to check security headers of third parties
        max_resources: Maximum number of resources to analyze
        timeout: Timeout for individual resource checks

    Returns:
        VendorRiskResult with assessment details
    """
    base_domain = extract_domain(base_url)
    resources: list[ThirdPartyResource] = []

    # Fetch page content if not provided
    if page_content is None:
        if HAS_AIOHTTP:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                        page_content = await response.text()
            except Exception:
                page_content = ""
        else:
            page_content = ""

    # Extract third-party resources from HTML
    extracted = extract_third_party_resources(page_content, base_url)

    # Add any additional JS URLs
    if js_urls:
        for url in js_urls:
            if is_third_party(url, base_domain) and (url, "script") not in extracted:
                extracted.append((url, "script"))

    # Limit resources to analyze
    extracted = extracted[:max_resources]

    # Analyze each resource
    for url, resource_type in extracted:
        domain = extract_domain(url)

        # Get CDN info
        cdn_info = KNOWN_CDNS.get(domain, {})

        resource = ThirdPartyResource(
            url=url,
            domain=domain,
            resource_type=resource_type,
            provider=cdn_info.get("provider"),
            category=cdn_info.get("category"),
            trust_level=cdn_info.get("trust_level", "unknown"),
        )

        # Check security if enabled
        if check_security and resource_type in ["script", "stylesheet"]:
            security_info = await check_resource_security(url, timeout)
            resource.tls_valid = security_info.get("tls_valid", False)
            resource.security_headers = security_info.get("security_headers", {})
            resource.content_hash = security_info.get("content_hash")
            resource.size_bytes = security_info.get("size_bytes")

        # Calculate score
        score, risk_factors = calculate_resource_score(resource)
        resource.security_score = score
        resource.risk_factors = risk_factors

        resources.append(resource)

    # Calculate overall risk
    risk_score, risk_level = calculate_overall_risk(resources)

    # Get unique domains
    third_party_domains = sorted(set(r.domain for r in resources))

    # Build result
    result = VendorRiskResult(
        target=base_url,
        assessed_at=datetime.now(UTC).isoformat(),
        total_third_parties=len(resources),
        third_party_domains=third_party_domains,
        resources=resources,
        risk_score=risk_score,
        risk_level=risk_level,
        findings=[],
        summary={
            "total_resources": len(resources),
            "by_type": {},
            "by_trust_level": {},
            "by_category": {},
            "average_score": sum(r.security_score for r in resources) / len(resources) if resources else 0,
        }
    )

    # Calculate summary stats
    for r in resources:
        result.summary["by_type"][r.resource_type] = result.summary["by_type"].get(r.resource_type, 0) + 1
        result.summary["by_trust_level"][r.trust_level] = result.summary["by_trust_level"].get(r.trust_level, 0) + 1
        if r.category:
            result.summary["by_category"][r.category] = result.summary["by_category"].get(r.category, 0) + 1

    # Generate findings
    result.findings = generate_vendor_findings(result)

    return result


# Export
__all__ = [
    "KNOWN_CDNS",
    "ThirdPartyResource",
    "VendorRiskResult",
    "generate_vendor_findings",
    "vendor_risk_assessment",
]
