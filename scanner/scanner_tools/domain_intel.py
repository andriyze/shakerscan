#!/usr/bin/env python3
"""
Domain Intelligence Module

Provides domain intelligence and WHOIS-based security assessments:
1. WHOIS data retrieval (registration date, expiration, registrar)
2. Domain age analysis (newly registered domains = higher risk)
3. Expiration monitoring (domains expiring soon = risk)
4. Registrar reputation scoring (privacy-protected, known bad registrars)
5. RDAP protocol support (modern WHOIS replacement)

All checks are read-only and non-intrusive.

OWASP Mapping:
- A05:2021 - Security Misconfiguration

CWE Mapping:
- CWE-200: Exposure of Sensitive Information
"""

import asyncio
import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# ============================================================================
# REGISTRAR REPUTATION DATABASE
# ============================================================================

# Registrars commonly associated with abuse or minimal abuse handling
# NOTE: Mainstream registrars (Namecheap, Porkbun, etc.) are NOT high-risk
# just because of high volume. Only include registrars with documented abuse issues.
HIGH_RISK_REGISTRARS = [
    # Known bulletproof or abuse-tolerant registrars
    "west263",
    "22net",
    "epp.nicproxy",
    "internet.bs",  # Known for bulletproof hosting
    # Note: Removed mainstream registrars - high volume != high risk
]

# Premium registrars with strict verification
LOW_RISK_REGISTRARS = [
    "markmonitor",  # Enterprise brand protection
    "corporatedomains",
    "networksolutions",
    "safenames",
    "comlaude",
    "cscglobal",
    "register.com",
]

# TLDs commonly used for abuse
HIGH_RISK_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs
    ".xyz", ".top", ".work", ".click", ".link",  # Cheap TLDs
    ".buzz", ".surf", ".monster", ".icu",
]

# Premium TLDs with higher trust
LOW_RISK_TLDS = [
    ".gov", ".edu", ".mil",  # Government/Education
    ".bank", ".insurance",  # Verified industry TLDs
]


# ============================================================================
# RDAP ENDPOINTS (Modern WHOIS)
# ============================================================================

RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

# Common RDAP servers by TLD
RDAP_SERVERS = {
    "com": "https://rdap.verisign.com/com/v1",
    "net": "https://rdap.verisign.com/net/v1",
    "org": "https://rdap.publicinterestregistry.org/rdap",
    "io": "https://rdap.nic.io",
    "co": "https://rdap.nic.co",
    "app": "https://rdap.nic.google",
    "dev": "https://rdap.nic.google",
    "edu": "https://rdap.educause.edu",
}


# ============================================================================
# WHOIS PARSING
# ============================================================================

async def _run_whois(domain: str, timeout: int = 30) -> tuple[str, str, int]:
    """Execute whois command and return output."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out_b, err_b = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
        except TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return "", f"timeout after {timeout}s", 124
        except asyncio.CancelledError:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            raise

        return out_b.decode(errors="ignore"), err_b.decode(errors="ignore"), proc.returncode
    except FileNotFoundError:
        return "", "whois command not found", 1
    except Exception as e:
        return "", str(e), 1


def _parse_whois_date(date_str: str) -> datetime | None:
    """Parse various WHOIS date formats into datetime."""
    if not date_str:
        return None

    date_str = date_str.strip()

    # Common date formats in WHOIS responses
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",      # ISO 8601
        "%Y-%m-%dT%H:%M:%S%z",     # ISO 8601 with timezone
        "%Y-%m-%d %H:%M:%S",       # Standard datetime
        "%Y-%m-%d",                 # Date only
        "%d-%b-%Y",                 # 25-Dec-2024
        "%d-%B-%Y",                 # 25-December-2024
        "%Y/%m/%d",                 # 2024/12/25
        "%d %b %Y",                 # 25 Dec 2024
        "%d %B %Y",                 # 25 December 2024
        "%Y%m%d",                   # 20241225
        "%b %d %Y",                 # Dec 25 2024
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(date_str[:len(date_str.split()[0]) + (11 if ' ' in date_str else 0)].strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except (ValueError, IndexError):
            continue

    # Try regex for embedded dates
    date_pattern = r"(\d{4}[-/]\d{2}[-/]\d{2})"
    match = re.search(date_pattern, date_str)
    if match:
        try:
            dt = datetime.strptime(match.group(1).replace('/', '-'), "%Y-%m-%d")
            return dt.replace(tzinfo=UTC)
        except ValueError:
            pass

    return None


def _parse_whois_output(whois_text: str) -> dict[str, Any]:
    """Parse raw WHOIS output into structured data."""
    result = {
        "domain_name": None,
        "registrar": None,
        "registrar_url": None,
        "registrar_iana_id": None,
        "creation_date": None,
        "updated_date": None,
        "expiration_date": None,
        "name_servers": [],
        "status": [],
        "dnssec": None,
        "registrant_organization": None,
        "registrant_country": None,
        "admin_email": None,
        "tech_email": None,
        "privacy_protected": False,
        "raw_text": whois_text,
    }

    # Field mappings (case-insensitive)
    field_patterns = {
        "domain_name": [
            r"Domain Name:\s*(.+)",
            r"domain:\s*(.+)",
        ],
        "registrar": [
            r"Registrar:\s*(.+)",
            r"registrar:\s*(.+)",
            r"Sponsoring Registrar:\s*(.+)",
        ],
        "registrar_url": [
            r"Registrar URL:\s*(.+)",
        ],
        "registrar_iana_id": [
            r"Registrar IANA ID:\s*(\d+)",
        ],
        "creation_date": [
            r"Creation Date:\s*(.+)",
            r"Created:\s*(.+)",
            r"created:\s*(.+)",
            r"Registration Date:\s*(.+)",
            r"registered:\s*(.+)",
        ],
        "updated_date": [
            r"Updated Date:\s*(.+)",
            r"Last Updated:\s*(.+)",
            r"modified:\s*(.+)",
        ],
        "expiration_date": [
            r"Expir(?:y|ation) Date:\s*(.+)",
            r"Registry Expiry Date:\s*(.+)",
            r"paid-till:\s*(.+)",
            r"Expiration Date:\s*(.+)",
        ],
        "dnssec": [
            r"DNSSEC:\s*(.+)",
        ],
        "registrant_organization": [
            r"Registrant Organization:\s*(.+)",
            r"org:\s*(.+)",
        ],
        "registrant_country": [
            r"Registrant Country:\s*(.+)",
            r"Registrant State/Province:\s*(.+)",
        ],
    }

    # Extract fields
    for field, patterns in field_patterns.items():
        for pattern in patterns:
            match = re.search(pattern, whois_text, re.IGNORECASE | re.MULTILINE)
            if match:
                value = match.group(1).strip()
                if value and value.lower() not in ["redacted", "data protected", "not disclosed"]:
                    if "date" in field:
                        result[field] = _parse_whois_date(value)
                    else:
                        result[field] = value
                break

    # Extract name servers
    ns_patterns = [
        r"Name Server:\s*(.+)",
        r"nserver:\s*(.+)",
        r"DNS:\s*(.+)",
    ]
    for pattern in ns_patterns:
        matches = re.findall(pattern, whois_text, re.IGNORECASE | re.MULTILINE)
        if matches:
            result["name_servers"] = [ns.strip().lower().rstrip('.') for ns in matches if ns.strip()]
            break

    # Extract domain status
    status_patterns = [
        r"Domain Status:\s*(.+)",
        r"Status:\s*(.+)",
    ]
    for pattern in status_patterns:
        matches = re.findall(pattern, whois_text, re.IGNORECASE | re.MULTILINE)
        if matches:
            result["status"] = [s.strip().split()[0] for s in matches if s.strip()]
            break

    # Check for privacy protection
    privacy_indicators = [
        "whoisguard", "privacy", "redacted", "data protected",
        "withheld", "contact privacy", "domain privacy",
        "private registration", "identity protection",
    ]
    whois_lower = whois_text.lower()
    result["privacy_protected"] = any(ind in whois_lower for ind in privacy_indicators)

    return result


# ============================================================================
# RDAP LOOKUP (Modern WHOIS)
# ============================================================================

async def _rdap_lookup(domain: str, timeout: int = 10) -> dict[str, Any] | None:
    """
    Query RDAP (Registration Data Access Protocol) for domain info.
    RDAP is the modern replacement for WHOIS with structured JSON responses.
    """
    # Extract TLD
    parts = domain.lower().split('.')
    if len(parts) < 2:
        return None

    tld = parts[-1]

    # Get RDAP server for TLD
    rdap_server = RDAP_SERVERS.get(tld)
    if not rdap_server:
        return None

    def _sync_rdap():
        try:
            url = f"{rdap_server}/domain/{domain}"
            req = Request(url, headers={
                "Accept": "application/rdap+json",
                "User-Agent": "Security Scanner/1.0"
            })
            with urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except (URLError, HTTPError, json.JSONDecodeError):
            return None

    return await asyncio.to_thread(_sync_rdap)


def _parse_rdap_response(rdap_data: dict[str, Any]) -> dict[str, Any]:
    """Parse RDAP JSON response into our standard format."""
    result = {
        "domain_name": rdap_data.get("ldhName"),
        "registrar": None,
        "creation_date": None,
        "updated_date": None,
        "expiration_date": None,
        "name_servers": [],
        "status": rdap_data.get("status", []),
        "dnssec": None,
        "privacy_protected": False,
    }

    # Extract dates from events
    events = rdap_data.get("events", [])
    for event in events:
        action = event.get("eventAction", "")
        date_str = event.get("eventDate", "")

        if date_str:
            parsed_date = _parse_whois_date(date_str)
            if action == "registration":
                result["creation_date"] = parsed_date
            elif action == "last changed":
                result["updated_date"] = parsed_date
            elif action == "expiration":
                result["expiration_date"] = parsed_date

    # Extract registrar from entities
    entities = rdap_data.get("entities", [])
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        result["registrar"] = item[3]
                        break

    # Extract nameservers
    nameservers = rdap_data.get("nameservers", [])
    result["name_servers"] = [ns.get("ldhName", "").lower().rstrip('.') for ns in nameservers]

    # Check DNSSEC
    secure_dns = rdap_data.get("secureDNS", {})
    result["dnssec"] = "signed" if secure_dns.get("delegationSigned") else "unsigned"

    return result


# ============================================================================
# DOMAIN AGE & RISK ANALYSIS
# ============================================================================

def _calculate_domain_age(creation_date: datetime | None) -> dict[str, Any]:
    """Calculate domain age and assess risk based on age."""
    if not creation_date:
        return {
            "age_days": None,
            "age_years": None,
            "risk_level": "unknown",
            "reason": "Creation date not available"
        }

    now = datetime.now(UTC)
    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=UTC)

    age = now - creation_date
    age_days = age.days
    age_years = age_days / 365.25

    # Domain age is INFORMATIONAL context, not a vulnerability
    # Age provides business context but does not indicate exploitable security issues
    # Only note the age - don't inflate severity for something that isn't a vuln
    if age_days < 30:
        risk_level = "info"  # Informational - newly registered
        reason = "Domain registered less than 30 days ago (newly registered)"
    elif age_days < 90:
        risk_level = "info"  # Informational
        reason = "Domain registered less than 90 days ago"
    elif age_days < 180:
        risk_level = "info"
        reason = "Domain registered less than 6 months ago"
    elif age_days < 365:
        risk_level = "info"
        reason = "Domain registered less than 1 year ago"
    else:
        risk_level = "info"
        reason = f"Established domain ({age_years:.1f} years old)"

    return {
        "age_days": age_days,
        "age_years": round(age_years, 2),
        "risk_level": risk_level,
        "reason": reason,
        "creation_date": creation_date.isoformat() if creation_date else None
    }


def _check_expiration(expiration_date: datetime | None) -> dict[str, Any]:
    """Check domain expiration status and assess risk."""
    if not expiration_date:
        return {
            "days_until_expiry": None,
            "risk_level": "unknown",
            "reason": "Expiration date not available"
        }

    now = datetime.now(UTC)
    if expiration_date.tzinfo is None:
        expiration_date = expiration_date.replace(tzinfo=UTC)

    days_left = (expiration_date - now).days

    if days_left < 0:
        risk_level = "critical"
        reason = f"Domain EXPIRED {abs(days_left)} days ago - may be hijackable"
    elif days_left < 7:
        risk_level = "critical"
        reason = f"Domain expires in {days_left} days - immediate renewal needed"
    elif days_left < 30:
        risk_level = "high"
        reason = f"Domain expires in {days_left} days - renewal recommended"
    elif days_left < 90:
        risk_level = "medium"
        reason = f"Domain expires in {days_left} days"
    else:
        risk_level = "info"
        reason = f"Domain valid for {days_left} days ({days_left // 365} years, {(days_left % 365) // 30} months)"

    return {
        "days_until_expiry": days_left,
        "expiration_date": expiration_date.isoformat() if expiration_date else None,
        "risk_level": risk_level,
        "reason": reason
    }


def _assess_registrar_reputation(registrar: str | None, domain: str) -> dict[str, Any]:
    """Assess registrar and TLD reputation."""
    result = {
        "registrar": registrar,
        "registrar_risk": "unknown",
        "tld_risk": "unknown",
        "privacy_concerns": [],
        "overall_risk": "unknown",
        "recommendations": []
    }

    if not registrar:
        result["recommendations"].append("Registrar information not available - verify domain ownership")
        return result

    registrar_lower = registrar.lower()

    # Check registrar reputation
    if any(bad in registrar_lower for bad in HIGH_RISK_REGISTRARS):
        result["registrar_risk"] = "elevated"
        result["privacy_concerns"].append(f"Registrar '{registrar}' has elevated abuse rates")
    elif any(good in registrar_lower for good in LOW_RISK_REGISTRARS):
        result["registrar_risk"] = "low"
    else:
        result["registrar_risk"] = "normal"

    # Check TLD reputation
    domain_lower = domain.lower()
    if any(domain_lower.endswith(tld) for tld in HIGH_RISK_TLDS):
        result["tld_risk"] = "elevated"
        result["privacy_concerns"].append("TLD commonly associated with abuse")
    elif any(domain_lower.endswith(tld) for tld in LOW_RISK_TLDS):
        result["tld_risk"] = "low"
    else:
        result["tld_risk"] = "normal"

    # Calculate overall risk
    risks = [result["registrar_risk"], result["tld_risk"]]
    if "elevated" in risks:
        result["overall_risk"] = "elevated"
    elif all(r == "low" for r in risks):
        result["overall_risk"] = "low"
    else:
        result["overall_risk"] = "normal"

    return result


# ============================================================================
# MAIN DOMAIN INTELLIGENCE CHECK
# ============================================================================

async def check_domain_intelligence(
    domain: str,
    timeout: int = 30,
    use_rdap: bool = True,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Perform comprehensive domain intelligence check.

    Retrieves and analyzes:
    - WHOIS registration data
    - Domain age and creation date
    - Expiration status
    - Registrar reputation
    - TLD risk assessment
    - Privacy protection status

    Args:
        domain: Domain to check (e.g., "example.com")
        timeout: WHOIS lookup timeout
        use_rdap: Try RDAP (modern WHOIS) first
        safe_mode: Enable conservative timeouts

    Returns:
        {
            "domain": "example.com",
            "whois": {
                "registrar": "...",
                "creation_date": "...",
                "expiration_date": "...",
                ...
            },
            "age_analysis": {
                "age_days": int,
                "risk_level": "...",
                ...
            },
            "expiration_analysis": {
                "days_until_expiry": int,
                "risk_level": "...",
                ...
            },
            "registrar_analysis": {
                "registrar_risk": "...",
                "tld_risk": "...",
                ...
            },
            "overall_risk": "critical" | "high" | "medium" | "low" | "info",
            "findings": [...],
            "recommendations": [...]
        }
    """
    results = {
        "domain": domain,
        "whois": None,
        "rdap_used": False,
        "age_analysis": None,
        "expiration_analysis": None,
        "registrar_analysis": None,
        "overall_risk": "unknown",
        "findings": [],
        "recommendations": [],
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration"
    }

    whois_data = None

    # Try RDAP first (if enabled)
    if use_rdap:
        try:
            rdap_response = await _rdap_lookup(domain, timeout=timeout if safe_mode else timeout // 2)
            if rdap_response:
                whois_data = _parse_rdap_response(rdap_response)
                results["rdap_used"] = True
        except Exception:
            pass

    # Fall back to traditional WHOIS
    if not whois_data or not whois_data.get("creation_date"):
        whois_out, whois_err, whois_code = await _run_whois(domain, timeout=timeout)

        if whois_code == 0 and whois_out:
            whois_data = _parse_whois_output(whois_out)
            results["rdap_used"] = False
        elif not whois_data:
            results["error"] = whois_err or "WHOIS lookup failed"
            results["overall_risk"] = "unknown"
            results["recommendations"].append("Unable to retrieve WHOIS data - verify domain exists")
            return results

    # Store parsed WHOIS data
    results["whois"] = {
        "domain_name": whois_data.get("domain_name"),
        "registrar": whois_data.get("registrar"),
        "registrar_url": whois_data.get("registrar_url"),
        "creation_date": whois_data.get("creation_date").isoformat() if whois_data.get("creation_date") else None,
        "updated_date": whois_data.get("updated_date").isoformat() if whois_data.get("updated_date") else None,
        "expiration_date": whois_data.get("expiration_date").isoformat() if whois_data.get("expiration_date") else None,
        "name_servers": whois_data.get("name_servers", []),
        "status": whois_data.get("status", []),
        "dnssec": whois_data.get("dnssec"),
        "privacy_protected": whois_data.get("privacy_protected", False),
        "registrant_organization": whois_data.get("registrant_organization"),
        "registrant_country": whois_data.get("registrant_country"),
    }

    # Analyze domain age
    results["age_analysis"] = _calculate_domain_age(whois_data.get("creation_date"))

    # Analyze expiration
    results["expiration_analysis"] = _check_expiration(whois_data.get("expiration_date"))

    # Analyze registrar reputation
    results["registrar_analysis"] = _assess_registrar_reputation(
        whois_data.get("registrar"),
        domain
    )

    # Generate findings
    findings = []
    risk_levels = []

    # Age-based findings
    age_risk = results["age_analysis"].get("risk_level", "unknown")
    if age_risk in ["critical", "high"]:
        findings.append({
            "id": f"domain_intel:age_{age_risk}",
            "title": f"Newly Registered Domain ({results['age_analysis'].get('age_days', 'N/A')} days)",
            "severity": age_risk,
            "description": results["age_analysis"].get("reason"),
            "cvss_score": 7.5 if age_risk == "critical" else 5.5,
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-200"
        })
        risk_levels.append(age_risk)

    # Expiration-based findings
    exp_risk = results["expiration_analysis"].get("risk_level", "unknown")
    if exp_risk in ["critical", "high"]:
        findings.append({
            "id": f"domain_intel:expiry_{exp_risk}",
            "title": f"Domain Expiration Warning ({results['expiration_analysis'].get('days_until_expiry', 'N/A')} days)",
            "severity": exp_risk,
            "description": results["expiration_analysis"].get("reason"),
            "cvss_score": 8.0 if exp_risk == "critical" else 6.0,
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-200"
        })
        risk_levels.append(exp_risk)

    # Registrar/TLD-based findings (informational - not a vulnerability)
    reg_risk = results["registrar_analysis"].get("overall_risk", "unknown")
    if reg_risk == "elevated":
        concerns = results["registrar_analysis"].get("privacy_concerns", [])
        findings.append({
            "id": "domain_intel:registrar_risk",
            "title": "Registrar/TLD Note",
            "severity": "info",  # Informational context, not a vulnerability
            "description": "; ".join(concerns) if concerns else "Registrar or TLD associated with higher abuse rates (informational)",
            "cvss_score": 0,  # Not a vulnerability
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-200"
        })
        # Don't add to risk_levels - this is informational

    # Privacy protection finding (informational)
    if whois_data.get("privacy_protected"):
        findings.append({
            "id": "domain_intel:privacy_protected",
            "title": "WHOIS Privacy Protection Enabled",
            "severity": "info",
            "description": "Domain registration details are protected. This is common for legitimate sites but can also hide malicious actors.",
            "cvss_score": 0,
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-200"
        })

    results["findings"] = findings

    # Calculate overall risk
    if "critical" in risk_levels:
        results["overall_risk"] = "critical"
    elif "high" in risk_levels:
        results["overall_risk"] = "high"
    elif "medium" in risk_levels:
        results["overall_risk"] = "medium"
    elif risk_levels:
        results["overall_risk"] = "low"
    else:
        results["overall_risk"] = "info"

    # Generate recommendations
    recommendations = []

    # Domain age is informational - no security recommendation needed

    if results["expiration_analysis"].get("risk_level") in ["critical", "high"]:
        recommendations.append("Renew domain immediately to prevent hijacking")

    if not whois_data.get("dnssec") or whois_data.get("dnssec") == "unsigned":
        recommendations.append("Enable DNSSEC to prevent DNS spoofing attacks")

    if whois_data.get("privacy_protected"):
        recommendations.append("WHOIS privacy is enabled - verify domain legitimacy through other means")

    results["recommendations"] = recommendations

    return results


# ============================================================================
# BATCH DOMAIN CHECK (for multiple domains)
# ============================================================================

async def check_domains_batch(
    domains: list[str],
    timeout: int = 30,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Check multiple domains for intelligence data.

    Useful for checking related domains, subdomains, or vendor domains.

    Args:
        domains: List of domains to check
        timeout: Timeout per domain
        safe_mode: Rate limit concurrent checks

    Returns:
        {
            "total_checked": int,
            "results": {
                "example.com": {...},
                "other.com": {...}
            },
            "high_risk_domains": [...],
            "summary": {...}
        }
    """
    results = {
        "total_checked": 0,
        "results": {},
        "high_risk_domains": [],
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
        }
    }

    # Rate limit concurrent checks
    max_concurrent = 3 if safe_mode else 5
    semaphore = asyncio.Semaphore(max_concurrent)

    async def check_single(domain: str):
        async with semaphore:
            return domain, await check_domain_intelligence(domain, timeout=timeout, safe_mode=safe_mode)

    tasks = [check_single(d) for d in domains]
    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for item in check_results:
        if isinstance(item, Exception):
            continue

        domain, result = item
        results["total_checked"] += 1
        results["results"][domain] = result

        risk = result.get("overall_risk", "unknown")
        if risk == "critical":
            results["summary"]["critical_count"] += 1
            results["high_risk_domains"].append(domain)
        elif risk == "high":
            results["summary"]["high_count"] += 1
            results["high_risk_domains"].append(domain)
        elif risk == "medium":
            results["summary"]["medium_count"] += 1
        elif risk == "low":
            results["summary"]["low_count"] += 1

    return results
