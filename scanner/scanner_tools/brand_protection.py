#!/usr/bin/env python3
"""
Brand Protection & Typosquatting Detection Module

This module detects typosquatting and brand impersonation domains:
1. Character omission (exmple.com)
2. Character repetition (exxample.com)
3. Character swap (examlpe.com)
4. Adjacent key replacement (ezample.com)
5. Homoglyph attacks (exаmple.com - Cyrillic 'а')
6. TLD variations (.net, .org, .co, .io)
7. Hyphenation (exam-ple.com)
8. Bit-flipping

All checks are read-only (DNS resolution only).

OWASP Mapping:
- A07:2021 - Identification and Authentication Failures (brand impersonation)

CWE Mapping:
- CWE-359: Exposure of Private Information (phishing via lookalike domains)
"""

import asyncio
import re
import socket
import ssl
from typing import Any

# Disable SSL verification
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Set global socket timeout
socket.setdefaulttimeout(10)

# ============================================================================
# KEYBOARD ADJACENCY MAP (QWERTY layout)
# ============================================================================

KEYBOARD_ADJACENCY = {
    'q': 'wa12', 'w': 'qeas23', 'e': 'wrsdf34', 'r': 'etdfg45',
    't': 'ryfgh56', 'y': 'tughj67', 'u': 'yihjk78', 'i': 'uojkl89',
    'o': 'ipkl90', 'p': 'ol0',
    'a': 'qwszx', 's': 'awedxzc', 'd': 'serfcxv', 'f': 'drtgvcb',
    'g': 'ftyhbvn', 'h': 'gyujnbm', 'j': 'huikmn', 'k': 'jiolm',
    'l': 'kop',
    'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb',
    'b': 'vghn', 'n': 'bhjm', 'm': 'njk',
    '1': 'q2', '2': '1qw3', '3': '2we4', '4': '3er5', '5': '4rt6',
    '6': '5ty7', '7': '6yu8', '8': '7ui9', '9': '8io0', '0': '9op',
}

# ============================================================================
# HOMOGLYPH MAPPING (confusable characters)
# ============================================================================

HOMOGLYPHS = {
    # Latin to Cyrillic/Greek lookalikes
    'a': ['а', 'ɑ', 'α', '@', '4'],  # Cyrillic а, Latin alpha, Greek alpha
    'b': ['Ь', 'ʙ', '6', '8'],
    'c': ['с', 'ç', '(', '¢'],  # Cyrillic с
    'd': ['ԁ', 'ɗ'],
    'e': ['е', 'ë', 'ē', 'ě', '3', 'є'],  # Cyrillic е
    'f': ['ƒ'],
    'g': ['ɡ', '9', 'ǵ'],
    'h': ['һ', 'ʜ'],  # Cyrillic һ
    'i': ['і', 'ï', 'ι', 'l', '1', '!', '|'],  # Cyrillic і, Greek iota
    'j': ['ј', 'ʝ'],  # Cyrillic ј
    'k': ['κ', 'к'],  # Greek kappa, Cyrillic к
    'l': ['ӏ', '1', 'I', '|', 'ℓ'],  # Cyrillic palochka
    'm': ['м', 'ɱ', 'rn'],  # Cyrillic м
    'n': ['п', 'ո', 'ɳ'],  # Cyrillic п looks like n in some fonts
    'o': ['о', 'ο', '0', 'θ', 'σ'],  # Cyrillic о, Greek omicron
    'p': ['р', 'ρ'],  # Cyrillic р, Greek rho
    'q': ['ԛ'],
    'r': ['г', 'ɼ'],  # Cyrillic г can look like r
    's': ['ѕ', '$', '5'],  # Cyrillic ѕ
    't': ['τ', '+', '7'],  # Greek tau
    'u': ['υ', 'ս', 'μ'],  # Greek upsilon
    'v': ['ν', 'ѵ'],  # Greek nu
    'w': ['ω', 'ẃ', 'vv'],  # Greek omega, double-v
    'x': ['х', '×', '*'],  # Cyrillic х
    'y': ['у', 'γ', 'ý'],  # Cyrillic у, Greek gamma
    'z': ['ʐ', '2'],
}

# Common TLD variations
TLD_VARIATIONS = [
    'com', 'net', 'org', 'co', 'io', 'biz', 'info', 'app', 'dev',
    'xyz', 'online', 'site', 'tech', 'cloud', 'ai', 'cc', 'me',
    'us', 'uk', 'de', 'fr', 'eu', 'ca', 'au', 'in', 'jp', 'cn',
]


# ============================================================================
# DOMAIN PERMUTATION GENERATORS
# ============================================================================

def generate_character_omission(name: str) -> set[str]:
    """Remove one character at a time: example -> exmple, examle, etc."""
    permutations = set()
    for i in range(len(name)):
        permutation = name[:i] + name[i+1:]
        if len(permutation) > 1:  # Don't create single-char domains
            permutations.add(permutation)
    return permutations


def generate_character_repetition(name: str) -> set[str]:
    """Double one character: example -> eexample, exxample, etc."""
    permutations = set()
    for i in range(len(name)):
        permutation = name[:i] + name[i] + name[i:]
        permutations.add(permutation)
    return permutations


def generate_character_swap(name: str) -> set[str]:
    """Swap adjacent characters: example -> xeample, eaxmple, etc."""
    permutations = set()
    for i in range(len(name) - 1):
        chars = list(name)
        chars[i], chars[i+1] = chars[i+1], chars[i]
        permutations.add(''.join(chars))
    return permutations


def generate_adjacent_key(name: str) -> set[str]:
    """Replace with adjacent keyboard key: example -> ezample, rxample, etc."""
    permutations = set()
    for i, char in enumerate(name.lower()):
        if char in KEYBOARD_ADJACENCY:
            for adj in KEYBOARD_ADJACENCY[char]:
                permutation = name[:i] + adj + name[i+1:]
                permutations.add(permutation.lower())
    return permutations


def generate_homoglyphs(name: str) -> set[str]:
    """Replace with visually similar characters: example -> exаmple (Cyrillic а)"""
    permutations = set()
    for i, char in enumerate(name.lower()):
        if char in HOMOGLYPHS:
            for homo in HOMOGLYPHS[char]:
                permutation = name[:i] + homo + name[i+1:]
                permutations.add(permutation)
    return permutations


def generate_hyphenation(name: str) -> set[str]:
    """Insert hyphens: example -> ex-ample, exam-ple, etc."""
    permutations = set()
    for i in range(1, len(name)):
        permutation = name[:i] + '-' + name[i:]
        permutations.add(permutation)
    # Also try removing hyphens if they exist
    if '-' in name:
        permutations.add(name.replace('-', ''))
    return permutations


def generate_vowel_swap(name: str) -> set[str]:
    """Swap vowels: example -> ixample, oxample, etc."""
    vowels = 'aeiou'
    permutations = set()
    for i, char in enumerate(name.lower()):
        if char in vowels:
            for v in vowels:
                if v != char:
                    permutation = name[:i] + v + name[i+1:]
                    permutations.add(permutation.lower())
    return permutations


def generate_dot_variations(name: str, tld: str) -> set[str]:
    """Add extra dots: example.com -> example.co.m, www.example.com -> wwwexample.com"""
    permutations = set()
    # Add dot inside domain
    for i in range(1, len(name)):
        permutation = f"{name[:i]}.{name[i:]}.{tld}"
        permutations.add(permutation)
    # www prefix variations
    permutations.add(f"www{name}.{tld}")
    permutations.add(f"ww.{name}.{tld}")
    return permutations


def generate_tld_variations(name: str, original_tld: str) -> set[str]:
    """Try different TLDs: example.com -> example.net, example.org, etc."""
    permutations = set()
    for tld in TLD_VARIATIONS:
        if tld != original_tld:
            permutations.add(f"{name}.{tld}")
    return permutations


def generate_all_permutations(domain: str, max_total: int = 500) -> list[dict[str, str]]:
    """
    Generate all typosquatting permutations for a domain.

    Args:
        domain: Original domain (e.g., "example.com")
        max_total: Maximum permutations to generate

    Returns:
        List of {
            "domain": "exmple.com",
            "type": "character_omission"
        }
    """
    # Parse domain
    parts = domain.lower().rsplit('.', 1)
    if len(parts) != 2:
        return []

    name, tld = parts
    permutations = []

    # Character omission (high priority - common typo)
    for perm in generate_character_omission(name):
        permutations.append({"domain": f"{perm}.{tld}", "type": "character_omission"})

    # Character swap (high priority - common typo)
    for perm in generate_character_swap(name):
        permutations.append({"domain": f"{perm}.{tld}", "type": "character_swap"})

    # Adjacent key replacement (high priority)
    for perm in generate_adjacent_key(name):
        permutations.append({"domain": f"{perm}.{tld}", "type": "adjacent_key"})

    # Character repetition (medium priority)
    for perm in generate_character_repetition(name):
        permutations.append({"domain": f"{perm}.{tld}", "type": "character_repetition"})

    # Homoglyphs (high priority for phishing)
    for perm in generate_homoglyphs(name):
        permutations.append({"domain": f"{perm}.{tld}", "type": "homoglyph"})

    # TLD variations (medium priority)
    for full_domain in generate_tld_variations(name, tld):
        permutations.append({"domain": full_domain, "type": "tld_variation"})

    # Hyphenation (lower priority)
    for perm in generate_hyphenation(name):
        permutations.append({"domain": f"{perm}.{tld}", "type": "hyphenation"})

    # Vowel swap (lower priority)
    for perm in generate_vowel_swap(name):
        permutations.append({"domain": f"{perm}.{tld}", "type": "vowel_swap"})

    # Remove duplicates and limit
    seen = set()
    unique = []
    for p in permutations:
        if p["domain"] not in seen and p["domain"] != domain:
            seen.add(p["domain"])
            unique.append(p)
            if len(unique) >= max_total:
                break

    return unique


# ============================================================================
# DNS RESOLUTION AND DOMAIN CHECKING
# ============================================================================

async def _resolve_domain(domain: str, timeout: int = 5) -> dict[str, Any] | None:
    """
    Resolve domain to get A records, MX records, and check HTTPS.

    Returns:
        {
            "ip": "1.2.3.4",
            "has_mx": True,
            "has_https": True,
            "certificate_cn": "example.com"
        }
        or None if domain doesn't resolve
    """
    def _sync_resolve():
        try:
            socket.setdefaulttimeout(timeout)
            # Get A record
            ip = socket.gethostbyname(domain)

            result = {
                "ip": ip,
                "has_mx": False,
                "has_https": False,
                "certificate_cn": None
            }

            # Try to get MX records (indicates email capability - phishing risk)
            try:
                import subprocess
                mx_result = subprocess.run(
                    ["dig", "+short", "MX", domain],
                    capture_output=True, text=True, timeout=5
                )
                if mx_result.stdout.strip():
                    result["has_mx"] = True
            except Exception:
                pass

            # Try to check HTTPS (certificate)
            try:
                ctx = ssl.create_default_context()
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        result["has_https"] = True
                        # Extract CN from certificate
                        subject = dict(x[0] for x in cert.get('subject', []))
                        result["certificate_cn"] = subject.get('commonName')
            except Exception:
                pass

            return result
        except (TimeoutError, socket.gaierror):
            return None
        except Exception:
            return None

    return await asyncio.to_thread(_sync_resolve)


# ============================================================================
# MAIN TYPOSQUATTING DETECTION
# ============================================================================

async def check_typosquatting(
    domain: str,
    max_checks: int = 100,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Detect registered typosquatting domains.

    This function generates domain permutations and checks if they're registered.
    Registered lookalike domains may indicate:
    - Active phishing campaigns
    - Brand impersonation
    - Trademark infringement
    - Defensive registrations (by legitimate owner)

    Args:
        domain: Original domain to check (e.g., "example.com")
        max_checks: Maximum permutations to check (default: 100)
        safe_mode: If True, limit concurrent checks

    Returns:
        {
            "original_domain": "example.com",
            "total_permutations": int,
            "checked": int,
            "suspicious_domains": [
                {
                    "domain": "exmple.com",
                    "type": "character_omission",
                    "ip": "1.2.3.4",
                    "has_mx": True,
                    "has_https": True,
                    "risk_score": 85
                }
            ],
            "high_risk_count": int,
            "medium_risk_count": int,
            "cwe": "CWE-359",
            "owasp": "A07:2021 - Identification and Authentication Failures"
        }
    """
    results = {
        "original_domain": domain,
        "total_permutations": 0,
        "checked": 0,
        "suspicious_domains": [],
        "high_risk_count": 0,
        "medium_risk_count": 0,
        "low_risk_count": 0,
        "cwe": "CWE-359",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "severity": "medium",
        "recommendation": "Review suspicious domains and consider defensive registrations or legal action"
    }

    # Generate permutations
    permutations = generate_all_permutations(domain, max_total=max_checks * 2)
    results["total_permutations"] = len(permutations)

    # Limit to max_checks
    permutations = permutations[:max_checks]

    # Check domains concurrently with rate limiting
    max_concurrent = 10 if safe_mode else 20
    semaphore = asyncio.Semaphore(max_concurrent)

    async def check_domain(perm: dict[str, str]):
        async with semaphore:
            await asyncio.sleep(0.1)  # Rate limiting
            dns_result = await _resolve_domain(perm["domain"])
            if dns_result:
                # Calculate risk score
                risk_score = 50  # Base score for registered domain

                # Higher risk factors
                if dns_result["has_mx"]:
                    risk_score += 25  # Can receive email (phishing)
                if dns_result["has_https"]:
                    risk_score += 15  # Has SSL cert (more legitimate-looking)
                if perm["type"] == "homoglyph":
                    risk_score += 10  # Harder to detect visually

                return {
                    "domain": perm["domain"],
                    "type": perm["type"],
                    "ip": dns_result["ip"],
                    "has_mx": dns_result["has_mx"],
                    "has_https": dns_result["has_https"],
                    "certificate_cn": dns_result.get("certificate_cn"),
                    "risk_score": min(risk_score, 100)
                }
            return None

    tasks = [check_domain(perm) for perm in permutations]
    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in check_results:
        results["checked"] += 1
        if result and not isinstance(result, Exception):
            results["suspicious_domains"].append(result)

            # Categorize by risk level
            if result["risk_score"] >= 75:
                results["high_risk_count"] += 1
            elif result["risk_score"] >= 50:
                results["medium_risk_count"] += 1
            else:
                results["low_risk_count"] += 1

    # Sort by risk score (highest first)
    results["suspicious_domains"].sort(key=lambda x: -x["risk_score"])

    # Update severity based on findings
    if results["high_risk_count"] > 0:
        results["severity"] = "high"
    elif results["medium_risk_count"] > 2:
        results["severity"] = "medium"
    else:
        results["severity"] = "low"

    return results


# ============================================================================
# DOMAIN EXPIRATION CHECK (Bonus)
# ============================================================================

async def check_domain_expiration(domain: str) -> dict[str, Any]:
    """
    Check if domain is approaching expiration (via WHOIS).

    Note: WHOIS queries may be rate-limited by registrars.

    Returns:
        {
            "domain": "example.com",
            "expiration_date": "2025-01-01",
            "days_until_expiry": 30,
            "at_risk": True
        }
    """
    import subprocess

    results = {
        "domain": domain,
        "expiration_date": None,
        "days_until_expiry": None,
        "at_risk": False,
        "error": None
    }

    def _sync_whois():
        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=15
            )
            return result.stdout
        except Exception as e:
            return f"error: {e!s}"

    whois_output = await asyncio.to_thread(_sync_whois)

    if whois_output.startswith("error:"):
        results["error"] = whois_output
        return results

    # Parse expiration date from WHOIS (various formats)
    expiry_patterns = [
        r'Expir[ey](?: Date)?[:\s]+(\d{4}-\d{2}-\d{2})',
        r'Registry Expiry Date[:\s]+(\d{4}-\d{2}-\d{2})',
        r'Expiration Date[:\s]+(\d{2}-[A-Za-z]{3}-\d{4})',
        r'paid-till[:\s]+(\d{4}.\d{2}.\d{2})',
    ]

    from datetime import datetime

    for pattern in expiry_patterns:
        match = re.search(pattern, whois_output, re.IGNORECASE)
        if match:
            date_str = match.group(1)
            try:
                # Try common date formats
                for fmt in ['%Y-%m-%d', '%d-%b-%Y', '%Y.%m.%d']:
                    try:
                        expiry_date = datetime.strptime(date_str, fmt)
                        results["expiration_date"] = expiry_date.strftime('%Y-%m-%d')
                        days_remaining = (expiry_date - datetime.now()).days
                        results["days_until_expiry"] = days_remaining
                        results["at_risk"] = days_remaining < 90
                        break
                    except ValueError:
                        continue
            except Exception:
                pass
            break

    return results


# ============================================================================
# COMBINED BRAND PROTECTION CHECK
# ============================================================================

async def check_brand_protection(
    domain: str,
    max_typo_checks: int = 100,
    check_expiration: bool = True,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Comprehensive brand protection check.

    Combines:
    1. Typosquatting detection
    2. Domain expiration check (optional)

    Args:
        domain: Domain to protect (e.g., "example.com")
        max_typo_checks: Maximum typosquatting permutations to check
        check_expiration: Whether to check domain expiration
        safe_mode: Enable rate limiting

    Returns:
        {
            "domain": "example.com",
            "typosquatting": {...},
            "expiration": {...},
            "overall_risk": "high" | "medium" | "low",
            "recommendations": [...]
        }
    """
    results = {
        "domain": domain,
        "typosquatting": None,
        "expiration": None,
        "overall_risk": "low",
        "recommendations": []
    }

    # Check typosquatting
    results["typosquatting"] = await check_typosquatting(
        domain,
        max_checks=max_typo_checks,
        safe_mode=safe_mode
    )

    # Check expiration if requested
    if check_expiration:
        results["expiration"] = await check_domain_expiration(domain)

    # Determine overall risk
    typo_risk = results["typosquatting"].get("severity", "low")
    expiry_risk = results["expiration"].get("at_risk", False) if results["expiration"] else False

    if typo_risk == "high" or expiry_risk:
        results["overall_risk"] = "high"
    elif typo_risk == "medium":
        results["overall_risk"] = "medium"
    else:
        results["overall_risk"] = "low"

    # Generate recommendations
    high_risk_domains = results["typosquatting"].get("high_risk_count", 0)
    if high_risk_domains > 0:
        results["recommendations"].append(
            f"Found {high_risk_domains} high-risk typosquatting domains. Consider legal action or defensive registration."
        )

    if expiry_risk:
        days = results["expiration"].get("days_until_expiry", 0)
        results["recommendations"].append(
            f"Domain expires in {days} days. Renew immediately to prevent hijacking."
        )

    suspicious_count = len(results["typosquatting"].get("suspicious_domains", []))
    if suspicious_count > 5:
        results["recommendations"].append(
            f"Detected {suspicious_count} registered lookalike domains. Monitor for phishing campaigns."
        )

    return results
