#!/usr/bin/env python3
"""
Enhanced DNS Security Checks Module

This module provides advanced DNS security checks:
1. DKIM selector enumeration
2. SPF syntax validation
3. Zone transfer (AXFR) testing
4. Dangling DNS record detection (subdomain takeover)

All checks are read-only and non-intrusive.

OWASP Mapping:
- A05:2021 - Security Misconfiguration

CWE Mapping:
- CWE-346: Origin Validation Error
- CWE-284: Improper Access Control
"""

import asyncio
import re
import socket
import subprocess
from typing import Any

# Set global socket timeout
socket.setdefaulttimeout(10)

# ============================================================================
# DKIM SELECTOR ENUMERATION
# ============================================================================

# Common DKIM selectors used by various email providers and services
COMMON_DKIM_SELECTORS = [
    # Generic/Default
    "default", "dkim", "mail", "email", "selector", "key", "k1", "k2",
    "selector1", "selector2", "s1", "s2", "key1", "key2",

    # Google Workspace / Gmail
    "google", "google2048", "20161025", "20230601",

    # Microsoft 365 / Exchange
    "selector1", "selector2",

    # Amazon SES
    "amazonses", "ses",

    # SendGrid
    "sendgrid", "s1", "s2", "smtpapi", "sm",

    # Mailchimp / Mandrill
    "mandrill", "mailchimp", "k1", "mte1", "mte2",

    # Mailgun
    "mailgun", "mg", "mailo",

    # Postmark
    "postmark", "pm", "20230101",

    # Zendesk
    "zendesk1", "zendesk2",

    # Salesforce
    "sf", "salesforce", "s1", "s2",

    # HubSpot
    "hs1", "hs2", "hubspot",

    # Intercom
    "intercom",

    # SparkPost
    "sparkpost", "sp",

    # Constant Contact
    "ctct1", "ctct2",

    # Klaviyo
    "kl", "klaviyo",

    # Brevo (formerly Sendinblue)
    "sib", "sendinblue", "brevo",

    # Customer.io
    "cio",

    # Additional common patterns
    "mx", "smtp", "mail2", "email1", "email2", "dkim1", "dkim2",
]


async def _dns_txt_lookup(query: str, timeout: int = 5) -> str | None:
    """
    Perform DNS TXT record lookup.

    Returns TXT record content or None if not found.
    """
    def _sync_lookup():
        try:
            result = subprocess.run(
                ["dig", "+short", "TXT", query],
                capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0 and result.stdout.strip():
                # Clean up TXT record (remove quotes, join lines)
                txt = result.stdout.strip().replace('"', '').replace('\n', '')
                return txt
            return None
        except Exception:
            return None

    return await asyncio.to_thread(_sync_lookup)


def _parse_dkim_record(record: str) -> dict[str, Any]:
    """
    Parse DKIM record to extract key information.

    Returns:
        {
            "version": "DKIM1",
            "key_type": "rsa",
            "public_key": "MIGf...",
            "key_size_bits": 2048,
            "notes": "..."
        }
    """
    result = {
        "version": None,
        "key_type": "rsa",  # Default
        "public_key": None,
        "key_size_bits": None,
        "notes": None,
        "raw_record": record
    }

    # Parse key-value pairs (separated by semicolons)
    pairs = record.split(';')
    for pair in pairs:
        pair = pair.strip()
        if '=' in pair:
            key, value = pair.split('=', 1)
            key = key.strip().lower()
            value = value.strip()

            if key == 'v':
                result["version"] = value
            elif key == 'k':
                result["key_type"] = value
            elif key == 'p':
                result["public_key"] = value
                # Estimate key size from base64 length
                # RSA public key: ~172 chars = 1024 bits, ~344 chars = 2048 bits
                if value:
                    key_len = len(value)
                    if key_len > 300:
                        result["key_size_bits"] = 2048
                    elif key_len > 150:
                        result["key_size_bits"] = 1024
                    else:
                        result["key_size_bits"] = 512
            elif key == 'n':
                result["notes"] = value

    return result


async def enumerate_dkim_selectors(
    domain: str,
    selectors: list[str] | None = None,
    timeout: int = 5,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Enumerate DKIM selectors for a domain.

    Checks common DKIM selectors and returns valid DKIM records found.

    Args:
        domain: Domain to check (e.g., "example.com")
        selectors: Custom list of selectors to check (uses defaults if None)
        timeout: DNS lookup timeout per selector
        safe_mode: If True, limit concurrent checks

    Returns:
        {
            "domain": "example.com",
            "selectors_found": [
                {
                    "selector": "google",
                    "record": "v=DKIM1; k=rsa; p=MIGf...",
                    "key_type": "rsa",
                    "key_size_bits": 2048,
                    "strength": "strong"
                }
            ],
            "total_checked": int,
            "dkim_configured": bool,
            "recommendations": [...]
        }
    """
    results = {
        "domain": domain,
        "selectors_found": [],
        "total_checked": 0,
        "dkim_configured": False,
        "recommendations": [],
        "cwe": "CWE-346",
        "owasp": "A05:2021 - Security Misconfiguration"
    }

    check_selectors = selectors or COMMON_DKIM_SELECTORS

    # Rate-limited concurrent checking
    max_concurrent = 10 if safe_mode else 20
    semaphore = asyncio.Semaphore(max_concurrent)

    async def check_selector(selector: str):
        async with semaphore:
            query = f"{selector}._domainkey.{domain}"
            txt_record = await _dns_txt_lookup(query, timeout=timeout)

            if txt_record and "v=DKIM1" in txt_record.upper():
                parsed = _parse_dkim_record(txt_record)

                # Determine key strength
                key_bits = parsed.get("key_size_bits", 0)
                if key_bits >= 2048:
                    strength = "strong"
                elif key_bits >= 1024:
                    strength = "acceptable"
                else:
                    strength = "weak"

                return {
                    "selector": selector,
                    "record": txt_record,
                    "key_type": parsed.get("key_type"),
                    "key_size_bits": key_bits,
                    "strength": strength
                }
            return None

    tasks = [check_selector(sel) for sel in check_selectors]
    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in check_results:
        results["total_checked"] += 1
        if result and not isinstance(result, Exception):
            results["selectors_found"].append(result)
            results["dkim_configured"] = True

    # Generate recommendations
    if not results["dkim_configured"]:
        results["recommendations"].append(
            "No DKIM records found. Configure DKIM to prevent email spoofing."
        )
    else:
        weak_keys = [s for s in results["selectors_found"] if s["strength"] == "weak"]
        if weak_keys:
            results["recommendations"].append(
                f"Found {len(weak_keys)} weak DKIM key(s) (<1024 bits). Upgrade to 2048-bit keys."
            )

    return results


# ============================================================================
# SPF SYNTAX VALIDATION
# ============================================================================

async def validate_spf_record(
    domain: str,
    spf_record: str | None = None
) -> dict[str, Any]:
    """
    Validate SPF record syntax and identify weaknesses.

    Checks for:
    - Weak qualifiers (~all, ?all, +all vs -all)
    - Excessive DNS lookups (>10 limit)
    - Overly broad IP ranges
    - Deprecated mechanisms
    - Syntax errors

    Args:
        domain: Domain to check
        spf_record: SPF record string (fetched if not provided)

    Returns:
        {
            "domain": "example.com",
            "spf_record": "v=spf1 ...",
            "valid": bool,
            "strength": "strong" | "weak" | "permissive",
            "issues": [
                {
                    "severity": "critical" | "high" | "medium" | "low",
                    "issue": "description",
                    "recommendation": "how to fix"
                }
            ],
            "dns_lookups": int,
            "qualifier": "pass" | "softfail" | "neutral" | "fail"
        }
    """
    results = {
        "domain": domain,
        "spf_record": spf_record,
        "valid": True,
        "strength": "strong",
        "issues": [],
        "dns_lookups": 0,
        "qualifier": None,
        "mechanisms": [],
        "cwe": "CWE-346",
        "owasp": "A05:2021 - Security Misconfiguration"
    }

    # Fetch SPF record if not provided
    if not spf_record:
        txt_record = await _dns_txt_lookup(domain)
        if txt_record:
            # Find SPF record in TXT records
            if "v=spf1" in txt_record.lower():
                spf_record = txt_record
                results["spf_record"] = spf_record
            else:
                results["valid"] = False
                results["issues"].append({
                    "severity": "high",
                    "issue": "No SPF record found",
                    "recommendation": "Add SPF record to prevent email spoofing"
                })
                return results
        else:
            results["valid"] = False
            results["issues"].append({
                "severity": "high",
                "issue": "Could not fetch TXT records",
                "recommendation": "Verify DNS configuration"
            })
            return results

    spf_lower = spf_record.lower()

    # Check version
    if not spf_lower.startswith("v=spf1"):
        results["valid"] = False
        results["issues"].append({
            "severity": "critical",
            "issue": "Invalid SPF version (must start with v=spf1)",
            "recommendation": "Fix SPF record syntax"
        })
        return results

    # Check qualifier (all mechanism at end)
    if spf_lower.endswith("+all"):
        results["qualifier"] = "pass"
        results["strength"] = "permissive"
        results["issues"].append({
            "severity": "critical",
            "issue": "SPF uses '+all' which allows anyone to send as your domain",
            "recommendation": "Change '+all' to '-all' for strict enforcement"
        })
    elif spf_lower.endswith("?all"):
        results["qualifier"] = "neutral"
        results["strength"] = "weak"
        results["issues"].append({
            "severity": "high",
            "issue": "SPF uses '?all' (neutral) which provides no protection",
            "recommendation": "Change '?all' to '-all' for strict enforcement"
        })
    elif spf_lower.endswith("~all"):
        results["qualifier"] = "softfail"
        results["strength"] = "weak"
        results["issues"].append({
            "severity": "medium",
            "issue": "SPF uses '~all' (softfail) which allows spoofed emails through",
            "recommendation": "Consider changing '~all' to '-all' for strict enforcement"
        })
    elif spf_lower.endswith("-all"):
        results["qualifier"] = "fail"
        results["strength"] = "strong"
    else:
        results["issues"].append({
            "severity": "medium",
            "issue": "SPF record doesn't end with 'all' mechanism",
            "recommendation": "Add '-all' at the end to define default policy"
        })

    # Count DNS lookups (include, a, mx, ptr, exists mechanisms)
    dns_lookup_mechanisms = ['include:', 'a:', 'a/', 'mx:', 'mx/', 'ptr', 'exists:']
    for mech in dns_lookup_mechanisms:
        results["dns_lookups"] += spf_lower.count(mech)

    # Also count bare 'a' and 'mx' (without qualifiers)
    results["dns_lookups"] += len(re.findall(r'\s+a(\s|$)', spf_lower))
    results["dns_lookups"] += len(re.findall(r'\s+mx(\s|$)', spf_lower))

    if results["dns_lookups"] > 10:
        results["issues"].append({
            "severity": "high",
            "issue": f"SPF has {results['dns_lookups']} DNS lookups (max is 10)",
            "recommendation": "Consolidate includes or use ip4/ip6 mechanisms to reduce lookups"
        })

    # Check for overly broad IP ranges
    if "ip4:0.0.0.0/0" in spf_lower:
        results["issues"].append({
            "severity": "critical",
            "issue": "SPF allows all IPv4 addresses (ip4:0.0.0.0/0)",
            "recommendation": "Remove this mechanism and specify actual sending IPs"
        })
    if "ip6:::/0" in spf_lower:
        results["issues"].append({
            "severity": "critical",
            "issue": "SPF allows all IPv6 addresses (ip6:::/0)",
            "recommendation": "Remove this mechanism and specify actual sending IPs"
        })

    # Check for deprecated ptr mechanism
    if " ptr" in spf_lower or "\tptr" in spf_lower:
        results["issues"].append({
            "severity": "medium",
            "issue": "SPF uses deprecated 'ptr' mechanism",
            "recommendation": "Replace 'ptr' with explicit 'a' or 'ip4' mechanisms"
        })

    # Check for excessive includes
    include_count = spf_lower.count("include:")
    if include_count > 5:
        results["issues"].append({
            "severity": "low",
            "issue": f"SPF has {include_count} includes (may be hard to maintain)",
            "recommendation": "Consider consolidating email providers"
        })

    # Update validity based on critical issues
    critical_issues = [i for i in results["issues"] if i["severity"] == "critical"]
    if critical_issues:
        results["valid"] = False
        results["strength"] = "permissive"

    return results


# ============================================================================
# ZONE TRANSFER (AXFR) TESTING
# ============================================================================

async def test_zone_transfer(
    domain: str,
    nameservers: list[str] | None = None,
    timeout: int = 15
) -> dict[str, Any]:
    """
    Test for unauthorized zone transfers (AXFR).

    Zone transfers expose all DNS records, which attackers can use to:
    - Map internal infrastructure
    - Discover hidden subdomains
    - Plan targeted attacks

    Args:
        domain: Domain to test
        nameservers: List of nameservers to test (fetched if not provided)
        timeout: Zone transfer timeout

    Returns:
        {
            "domain": "example.com",
            "vulnerable": bool,
            "nameservers_tested": int,
            "vulnerable_nameservers": [
                {
                    "nameserver": "ns1.example.com",
                    "records_exposed": 150,
                    "record_types": ["A", "CNAME", "MX", "TXT"]
                }
            ],
            "severity": "critical" if vulnerable
        }
    """
    results = {
        "domain": domain,
        "vulnerable": False,
        "nameservers_tested": 0,
        "vulnerable_nameservers": [],
        "severity": "info",
        "cwe": "CWE-284",
        "owasp": "A05:2021 - Security Misconfiguration",
        "recommendation": "Configure DNS servers to restrict zone transfers to authorized IPs only"
    }

    # Get nameservers if not provided
    if not nameservers:
        def _get_ns():
            try:
                result = subprocess.run(
                    ["dig", "+short", "NS", domain],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    return [ns.strip().rstrip('.') for ns in result.stdout.strip().split('\n') if ns.strip()]
                return []
            except Exception:
                return []

        nameservers = await asyncio.to_thread(_get_ns)

    if not nameservers:
        results["error"] = "Could not determine nameservers"
        results["status"] = "inconclusive"
        results["vulnerable"] = None  # Unknown, not False
        return results

    # Test each nameserver
    for ns in nameservers:
        results["nameservers_tested"] += 1

        def _try_axfr(nameserver: str):
            # Valid DNS record types that can appear in zone transfers
            VALID_RECORD_TYPES = {
                'A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT', 'PTR', 'SRV',
                'CAA', 'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'RRSIG', 'TLSA',
                'HINFO', 'NAPTR', 'SPF', 'SSHFP', 'LOC', 'CERT', 'DNAME'
            }

            try:
                result = subprocess.run(
                    ["dig", f"@{nameserver}", domain, "AXFR", "+noall", "+answer"],
                    capture_output=True, text=True, timeout=timeout
                )

                # Check for common failure indicators in both stdout and stderr
                combined_output = (result.stdout + result.stderr).lower()
                failure_indicators = [
                    "transfer failed",
                    "connection refused",
                    "connection timed out",
                    "communications error",
                    "couldn't get address",
                    "no servers could be reached",
                    "query refused",
                    "not authorized",
                    "servfail",
                    "nxdomain"
                ]

                if any(indicator in combined_output for indicator in failure_indicators):
                    return {"success": False, "error": "transfer_denied"}

                # Parse stdout for actual DNS records
                output = result.stdout.strip()
                if not output:
                    return {"success": False, "error": "empty_response"}

                lines = output.split('\n')
                valid_records = []
                record_types = set()
                has_soa = False

                for line in lines:
                    # Skip empty lines and comments
                    line = line.strip()
                    if not line or line.startswith(';'):
                        continue

                    parts = line.split()
                    # Valid DNS record format: name TTL class type rdata
                    # e.g., "example.com. 300 IN A 1.2.3.4"
                    if len(parts) >= 5:
                        # Record type is typically at position 3 (0-indexed)
                        # Format: name TTL class type rdata...
                        record_type = parts[3].upper()

                        # Validate it's a real DNS record type
                        if record_type in VALID_RECORD_TYPES:
                            valid_records.append(line)
                            record_types.add(record_type)
                            if record_type == 'SOA':
                                has_soa = True

                # Zone transfer must include at least SOA record and multiple records
                # A valid zone transfer always starts and ends with SOA
                if has_soa and len(valid_records) >= 3 and len(record_types) >= 2:
                    return {
                        "success": True,
                        "records_exposed": len(valid_records),
                        "record_types": sorted(list(record_types))
                    }

                return {"success": False, "error": "no_valid_records"}
            except subprocess.TimeoutExpired:
                return {"success": False, "error": "timeout"}
            except Exception as e:
                return {"success": False, "error": str(e)}

        axfr_result = await asyncio.to_thread(_try_axfr, ns)

        if axfr_result.get("success"):
            results["vulnerable"] = True
            results["severity"] = "critical"
            results["status"] = "vulnerable"
            results["vulnerable_nameservers"].append({
                "nameserver": ns,
                "records_exposed": axfr_result.get("records_exposed", 0),
                "record_types": axfr_result.get("record_types", [])
            })

    # Set status based on testing outcome
    if results["nameservers_tested"] > 0 and not results.get("status"):
        results["status"] = "protected"  # Tested and not vulnerable

    return results


# ============================================================================
# DANGLING DNS RECORD DETECTION (SUBDOMAIN TAKEOVER)
# ============================================================================

# Services vulnerable to subdomain takeover
TAKEOVER_FINGERPRINTS = {
    # Cloud Providers
    "s3.amazonaws.com": {
        "fingerprint": "NoSuchBucket",
        "service": "AWS S3",
        "severity": "high"
    },
    "cloudfront.net": {
        "fingerprint": "Bad request",
        "service": "AWS CloudFront",
        "severity": "high"
    },
    "elasticbeanstalk.com": {
        "fingerprint": "404 Not Found",
        "service": "AWS Elastic Beanstalk",
        "severity": "high"
    },
    "azurewebsites.net": {
        "fingerprint": "404 Web Site not found",
        "service": "Azure App Service",
        "severity": "high"
    },
    "blob.core.windows.net": {
        "fingerprint": "BlobNotFound",
        "service": "Azure Blob Storage",
        "severity": "high"
    },
    "cloudapp.azure.com": {
        "fingerprint": "404",
        "service": "Azure Cloud App",
        "severity": "high"
    },

    # Hosting Platforms
    "herokuapp.com": {
        "fingerprint": "No such app",
        "service": "Heroku",
        "severity": "high"
    },
    "github.io": {
        "fingerprint": "There isn't a GitHub Pages site here",
        "service": "GitHub Pages",
        "severity": "medium"
    },
    "gitlab.io": {
        "fingerprint": "The page you were looking for doesn't exist",
        "service": "GitLab Pages",
        "severity": "medium"
    },
    "bitbucket.io": {
        "fingerprint": "Repository not found",
        "service": "Bitbucket",
        "severity": "medium"
    },
    "netlify.app": {
        "fingerprint": "Not Found",
        "service": "Netlify",
        "severity": "medium"
    },
    "vercel.app": {
        "fingerprint": "This deployment cannot be found",
        "service": "Vercel",
        "severity": "medium"
    },

    # CMS & E-commerce
    "shopify.com": {
        "fingerprint": "Sorry, this shop is currently unavailable",
        "service": "Shopify",
        "severity": "high"
    },
    "tumblr.com": {
        "fingerprint": "There's nothing here",
        "service": "Tumblr",
        "severity": "low"
    },
    "wordpress.com": {
        "fingerprint": "Do you want to register",
        "service": "WordPress.com",
        "severity": "medium"
    },
    "ghost.io": {
        "fingerprint": "This Ghost publication is no longer available",
        "service": "Ghost",
        "severity": "medium"
    },
    "cargo.site": {
        "fingerprint": "404 Not Found",
        "service": "Cargo",
        "severity": "low"
    },
    "webflow.io": {
        "fingerprint": "The page you are looking for doesn't exist",
        "service": "Webflow",
        "severity": "medium"
    },

    # CDN & DNS
    "fastly.net": {
        "fingerprint": "Fastly error: unknown domain",
        "service": "Fastly",
        "severity": "high"
    },
    "pantheonsite.io": {
        "fingerprint": "404 error unknown site",
        "service": "Pantheon",
        "severity": "medium"
    },
    "zendesk.com": {
        "fingerprint": "Help Center Closed",
        "service": "Zendesk",
        "severity": "medium"
    },
    "intercom.io": {
        "fingerprint": "Uh oh. That page doesn't exist",
        "service": "Intercom",
        "severity": "medium"
    },
}


async def check_dangling_dns(
    subdomains: list[str],
    timeout: int = 10,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Check for dangling DNS records that could allow subdomain takeover.

    A dangling record occurs when:
    1. CNAME points to external service (e.g., example.s3.amazonaws.com)
    2. The external resource no longer exists
    3. Attacker can claim the resource and control the subdomain

    Args:
        subdomains: List of subdomains to check
        timeout: HTTP request timeout
        safe_mode: If True, limit concurrent checks

    Returns:
        {
            "total_checked": int,
            "dangling_records": [
                {
                    "subdomain": "cdn.example.com",
                    "cname": "example.s3.amazonaws.com",
                    "service": "AWS S3",
                    "takeover_possible": True,
                    "severity": "high"
                }
            ],
            "vulnerable_count": int
        }
    """
    results = {
        "total_checked": 0,
        "dangling_records": [],
        "vulnerable_count": 0,
        "cwe": "CWE-284",
        "owasp": "A05:2021 - Security Misconfiguration",
        "recommendation": "Remove or update DNS records pointing to unclaimed external resources"
    }

    max_concurrent = 5 if safe_mode else 10
    semaphore = asyncio.Semaphore(max_concurrent)

    async def check_subdomain(subdomain: str):
        async with semaphore:
            results["total_checked"] += 1

            # Get CNAME record
            def _get_cname():
                try:
                    result = subprocess.run(
                        ["dig", "+short", "CNAME", subdomain],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        return result.stdout.strip().rstrip('.')
                    return None
                except Exception:
                    return None

            cname = await asyncio.to_thread(_get_cname)
            if not cname:
                return None

            # Check if CNAME points to vulnerable service
            for service_domain, info in TAKEOVER_FINGERPRINTS.items():
                if service_domain in cname.lower():
                    # Try to fetch and check for fingerprint
                    def _check_fingerprint():
                        import ssl
                        import urllib.request
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE

                        for scheme in ["https", "http"]:
                            try:
                                url = f"{scheme}://{subdomain}/"
                                req = urllib.request.Request(url, headers={
                                    "User-Agent": "Mozilla/5.0 Security Scanner"
                                })
                                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                                    content = resp.read().decode('utf-8', errors='ignore')
                                    if info["fingerprint"].lower() in content.lower():
                                        return True
                            except urllib.error.HTTPError as e:
                                # Check error page content
                                try:
                                    content = e.read().decode('utf-8', errors='ignore')
                                    if info["fingerprint"].lower() in content.lower():
                                        return True
                                except Exception:
                                    pass
                            except Exception:
                                pass
                        return False

                    is_vulnerable = await asyncio.to_thread(_check_fingerprint)

                    if is_vulnerable:
                        return {
                            "subdomain": subdomain,
                            "cname": cname,
                            "service": info["service"],
                            "takeover_possible": True,
                            "severity": info["severity"],
                            "fingerprint_matched": info["fingerprint"]
                        }
                    else:
                        # CNAME exists but not currently takeover-able
                        return {
                            "subdomain": subdomain,
                            "cname": cname,
                            "service": info["service"],
                            "takeover_possible": False,
                            "severity": "info",
                            "note": "CNAME points to service but resource appears active"
                        }

            return None

    tasks = [check_subdomain(sub) for sub in subdomains]
    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in check_results:
        if result and not isinstance(result, Exception):
            results["dangling_records"].append(result)
            if result.get("takeover_possible"):
                results["vulnerable_count"] += 1

    return results


# ============================================================================
# COMBINED ENHANCED DNS CHECK
# ============================================================================

async def check_enhanced_dns(
    domain: str,
    subdomains: list[str] | None = None,
    spf_record: str | None = None,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Run all enhanced DNS security checks.

    Combines:
    1. DKIM selector enumeration
    2. SPF syntax validation
    3. Zone transfer testing
    4. Dangling DNS detection (if subdomains provided)

    Args:
        domain: Domain to check
        subdomains: Optional list of subdomains for dangling DNS check
        spf_record: Optional SPF record (fetched if not provided)
        safe_mode: Enable rate limiting

    Returns:
        {
            "domain": "example.com",
            "dkim": {...},
            "spf": {...},
            "zone_transfer": {...},
            "dangling_dns": {...},
            "overall_risk": "high" | "medium" | "low",
            "recommendations": [...]
        }
    """
    results = {
        "domain": domain,
        "dkim": None,
        "spf": None,
        "zone_transfer": None,
        "dangling_dns": None,
        "overall_risk": "low",
        "recommendations": []
    }

    # Run checks in parallel
    tasks = [
        enumerate_dkim_selectors(domain, safe_mode=safe_mode),
        validate_spf_record(domain, spf_record),
        test_zone_transfer(domain),
    ]

    if subdomains:
        tasks.append(check_dangling_dns(subdomains, safe_mode=safe_mode))

    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    results["dkim"] = check_results[0] if not isinstance(check_results[0], Exception) else {"error": str(check_results[0])}
    results["spf"] = check_results[1] if not isinstance(check_results[1], Exception) else {"error": str(check_results[1])}
    results["zone_transfer"] = check_results[2] if not isinstance(check_results[2], Exception) else {"error": str(check_results[2])}

    if len(check_results) > 3:
        results["dangling_dns"] = check_results[3] if not isinstance(check_results[3], Exception) else {"error": str(check_results[3])}

    # Determine overall risk
    risk_level = "low"

    # Check for critical issues
    if results["zone_transfer"] and results["zone_transfer"].get("vulnerable"):
        risk_level = "critical"
        results["recommendations"].append("CRITICAL: Zone transfer allowed - restrict AXFR to authorized IPs")

    if results["dangling_dns"] and results["dangling_dns"].get("vulnerable_count", 0) > 0:
        risk_level = max(risk_level, "high") if risk_level != "critical" else risk_level
        results["recommendations"].append(f"HIGH: {results['dangling_dns']['vulnerable_count']} subdomain(s) vulnerable to takeover")

    if results["spf"] and results["spf"].get("strength") == "permissive":
        risk_level = max(risk_level, "high") if risk_level not in ["critical"] else risk_level
        results["recommendations"].append("HIGH: SPF record is too permissive (allows spoofing)")

    if results["spf"] and results["spf"].get("strength") == "weak":
        risk_level = max(risk_level, "medium") if risk_level in ["low"] else risk_level
        results["recommendations"].append("MEDIUM: SPF record uses softfail (~all)")

    if results["dkim"] and not results["dkim"].get("dkim_configured"):
        risk_level = max(risk_level, "medium") if risk_level in ["low"] else risk_level
        results["recommendations"].append("MEDIUM: No DKIM records found - email spoofing possible")

    results["overall_risk"] = risk_level

    return results
