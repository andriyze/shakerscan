#!/usr/bin/env python3
"""
Certificate Transparency (CT) Monitoring Module

Provides certificate transparency analysis for detecting:
1. Unauthorized certificate issuance
2. Wildcard certificate abuse
3. CA diversity (single CA = risk)
4. Historical certificate timeline
5. Subdomain discovery via CT logs

Uses free APIs:
- crt.sh (Sectigo's CT log search)

All checks are read-only and non-intrusive.

OWASP Mapping:
- A02:2021 - Cryptographic Failures
- A05:2021 - Security Misconfiguration

CWE Mapping:
- CWE-295: Improper Certificate Validation
- CWE-296: Improper Following of a Certificate's Chain of Trust
"""

import asyncio
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

# ============================================================================
# CRT.SH API CLIENT
# ============================================================================

CRT_SH_URL = "https://crt.sh"


async def _query_crtsh(domain: str, timeout: int = 30, include_expired: bool = False) -> list[dict[str, Any]]:
    """
    Query crt.sh for certificates issued for a domain.

    Args:
        domain: Domain to search (e.g., "example.com" or "%.example.com" for wildcards)
        timeout: Request timeout
        include_expired: Include expired certificates in results

    Returns:
        List of certificate records from crt.sh
    """
    def _sync_query():
        try:
            # Query crt.sh JSON API
            url = f"{CRT_SH_URL}/?q={quote(domain)}&output=json"
            if not include_expired:
                url += "&exclude=expired"

            req = Request(url, headers={
                "User-Agent": "Security Scanner/1.0",
                "Accept": "application/json"
            })

            with urlopen(req, timeout=timeout) as resp:
                data = resp.read().decode('utf-8')
                if data.strip():
                    return json.loads(data)
                return []
        except json.JSONDecodeError:
            return []
        except (URLError, HTTPError):
            return []
        except Exception:
            return []

    return await asyncio.to_thread(_sync_query)


def _parse_crtsh_date(date_str: str) -> datetime | None:
    """Parse crt.sh date format into datetime."""
    if not date_str:
        return None

    # Strip trailing 'Z' and any whitespace
    clean_str = date_str.strip().rstrip('Z')

    formats = [
        ("%Y-%m-%dT%H:%M:%S.%f", 26),
        ("%Y-%m-%dT%H:%M:%S", 19),
        ("%Y-%m-%d %H:%M:%S", 19),
        ("%Y-%m-%d", 10),
    ]

    for fmt, length in formats:
        try:
            dt = datetime.strptime(clean_str[:length], fmt)
            return dt.replace(tzinfo=UTC)
        except (ValueError, IndexError):
            continue

    # Try ISO format as fallback
    try:
        parsed = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        # Ensure timezone-aware
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    except Exception:
        pass

    return None


# ============================================================================
# CERTIFICATE ANALYSIS
# ============================================================================

def _analyze_certificate_diversity(certs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Analyze CA diversity in issued certificates.

    Single CA dependency is a risk - if that CA is compromised or has issues,
    all certificates could be affected.
    """
    issuers = {}
    for cert in certs:
        issuer = cert.get("issuer_name", "Unknown")
        # Extract CA organization from issuer DN
        ca_org = "Unknown"
        if "O=" in issuer:
            match = re.search(r"O=([^,]+)", issuer)
            if match:
                ca_org = match.group(1).strip()
        elif "CN=" in issuer:
            match = re.search(r"CN=([^,]+)", issuer)
            if match:
                ca_org = match.group(1).strip()

        issuers[ca_org] = issuers.get(ca_org, 0) + 1

    total_certs = len(certs)
    ca_count = len(issuers)

    # Risk assessment
    if ca_count == 0:
        risk_level = "unknown"
        recommendation = "No certificates found to analyze"
    elif ca_count == 1:
        risk_level = "medium"
        recommendation = f"All certificates issued by single CA ({list(issuers.keys())[0]}). Consider using multiple CAs for redundancy."
    elif ca_count == 2:
        risk_level = "low"
        recommendation = "Good CA diversity with 2 certificate authorities"
    else:
        risk_level = "info"
        recommendation = f"Excellent CA diversity with {ca_count} certificate authorities"

    return {
        "total_certificates": total_certs,
        "unique_cas": ca_count,
        "ca_distribution": issuers,
        "risk_level": risk_level,
        "recommendation": recommendation
    }


def _analyze_wildcard_usage(certs: list[dict[str, Any]], domain: str) -> dict[str, Any]:
    """
    Analyze wildcard certificate usage.

    Excessive wildcard usage increases risk:
    - Wildcard private key compromise affects all subdomains
    - Makes certificate revocation more impactful
    """
    wildcards = []
    non_wildcards = []

    for cert in certs:
        common_name = cert.get("common_name", "")
        name_value = cert.get("name_value", "")

        # Check if it's a wildcard
        is_wildcard = "*." in common_name or "*." in name_value

        if is_wildcard:
            wildcards.append({
                "common_name": common_name,
                "name_value": name_value,
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
                "issuer": cert.get("issuer_name", "Unknown")
            })
        else:
            non_wildcards.append(common_name)

    total = len(certs)
    wildcard_count = len(wildcards)
    wildcard_ratio = wildcard_count / total if total > 0 else 0

    # Risk assessment
    if wildcard_ratio > 0.8:
        risk_level = "medium"
        recommendation = "High wildcard certificate usage (>80%). Consider using specific certificates for critical services."
    elif wildcard_ratio > 0.5:
        risk_level = "low"
        recommendation = "Moderate wildcard certificate usage. Review if all wildcards are necessary."
    else:
        risk_level = "info"
        recommendation = "Good balance of wildcard and specific certificates"

    return {
        "total_certificates": total,
        "wildcard_count": wildcard_count,
        "wildcard_ratio": round(wildcard_ratio, 2),
        "wildcards": wildcards[:10],  # Limit to first 10
        "risk_level": risk_level,
        "recommendation": recommendation
    }


def _analyze_certificate_timeline(certs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Analyze certificate issuance timeline.

    Detects:
    - Unusual issuance patterns
    - Recent unexpected certificates
    - Certificate lifecycle patterns
    """
    now = datetime.now(UTC)

    timeline = {
        "last_24h": [],
        "last_7d": [],
        "last_30d": [],
        "last_90d": [],
        "older": []
    }

    for cert in certs:
        not_before_str = cert.get("not_before", "")
        not_before = _parse_crtsh_date(not_before_str)

        if not not_before:
            continue

        age = now - not_before

        cert_summary = {
            "common_name": cert.get("common_name", ""),
            "issuer": cert.get("issuer_name", "Unknown"),
            "not_before": not_before_str,
            "not_after": cert.get("not_after", ""),
            "id": cert.get("id")
        }

        if age.days < 1:
            timeline["last_24h"].append(cert_summary)
        elif age.days < 7:
            timeline["last_7d"].append(cert_summary)
        elif age.days < 30:
            timeline["last_30d"].append(cert_summary)
        elif age.days < 90:
            timeline["last_90d"].append(cert_summary)
        else:
            timeline["older"].append(cert_summary)

    # Risk assessment - account for automated certificate providers
    recent_count = len(timeline["last_24h"]) + len(timeline["last_7d"])

    # Automated CAs that legitimately issue many certificates (not suspicious)
    AUTOMATED_CAS = [
        "let's encrypt",
        "letsencrypt",
        "google trust",
        "cloudflare",
        "amazon",
        "digicert",
        "sectigo",
        "zerossl",
        "buypass",
        "ssl.com",
    ]

    # Check if recent certificates are from automated CAs (normal behavior)
    recent_certs = timeline["last_24h"] + timeline["last_7d"]
    automated_issuers = sum(
        1 for c in recent_certs
        if any(auto_ca in c.get("issuer", "").lower() for auto_ca in AUTOMATED_CAS)
    )
    is_mostly_automated = automated_issuers >= len(recent_certs) * 0.8 if recent_certs else True

    # Adjust thresholds for automated vs manual CAs
    if is_mostly_automated:
        # Automated CAs like LE/Cloudflare legitimately issue many certs
        # Only flag if truly excessive (>10 in 24h is unusual even for automation)
        if len(timeline["last_24h"]) > 10:
            risk_level = "info"  # Still just informational - not a vulnerability
            recommendation = f"High automated certificate activity: {len(timeline['last_24h'])} certs in 24 hours from automated CAs (normal for CDN/edge deployments)"
        else:
            risk_level = "info"
            recommendation = "Normal automated certificate issuance pattern"
    else:
        # Non-automated/unknown CAs - lower threshold for concern
        if len(timeline["last_24h"]) > 3:
            risk_level = "medium"  # Downgraded from high - still needs investigation but not critical
            recommendation = f"Review certificate activity: {len(timeline['last_24h'])} certificates from non-standard CAs in 24 hours"
        elif recent_count > 5:
            risk_level = "low"
            recommendation = f"Moderate certificate activity: {recent_count} certificates in 7 days"
        else:
            risk_level = "info"
            recommendation = "Normal certificate issuance pattern"

    return {
        "last_24h_count": len(timeline["last_24h"]),
        "last_7d_count": len(timeline["last_7d"]),
        "last_30d_count": len(timeline["last_30d"]),
        "last_90d_count": len(timeline["last_90d"]),
        "recent_certificates": timeline["last_24h"] + timeline["last_7d"][:5],  # Show recent ones
        "risk_level": risk_level,
        "recommendation": recommendation
    }


def _discover_subdomains_from_ct(certs: list[dict[str, Any]], domain: str) -> dict[str, Any]:
    """
    Extract unique subdomains from CT logs.

    CT logs are a great source for subdomain discovery since they
    contain all publicly issued certificates.
    """
    subdomains: set[str] = set()
    domain_lower = domain.lower()

    for cert in certs:
        # Check common_name
        cn = cert.get("common_name", "").lower()
        if cn and cn.endswith(domain_lower):
            # Remove wildcard prefix if present
            cn_clean = cn.replace("*.", "")
            if cn_clean != domain_lower:
                subdomains.add(cn_clean)

        # Check name_value (can contain multiple SANs)
        name_value = cert.get("name_value", "")
        if name_value:
            # Split by newline (crt.sh format) or comma
            names = re.split(r'[\n,]', name_value)
            for name in names:
                name = name.strip().lower().replace("*.", "")
                if name and name.endswith(domain_lower) and name != domain_lower:
                    subdomains.add(name)

    # Sort subdomains
    sorted_subdomains = sorted(list(subdomains))

    return {
        "total_subdomains": len(sorted_subdomains),
        "subdomains": sorted_subdomains[:100],  # Limit to 100
        "truncated": len(sorted_subdomains) > 100
    }


def _detect_suspicious_certificates(certs: list[dict[str, Any]], domain: str) -> list[dict[str, Any]]:
    """
    Detect potentially suspicious certificate issuance.

    Looks for:
    - Unknown/suspicious CAs
    - Very short validity periods
    - Certificates for unusual subdomains
    """
    suspicious = []

    # Known legitimate CAs (partial list)
    trusted_cas = {
        "let's encrypt", "digicert", "comodo", "sectigo", "globalsign",
        "godaddy", "entrust", "geotrust", "rapidssl", "thawte",
        "amazon", "google", "cloudflare", "microsoft", "apple"
    }

    for cert in certs:
        reasons = []

        issuer = cert.get("issuer_name", "").lower()
        common_name = cert.get("common_name", "")

        # Check for untrusted/unknown CA
        ca_trusted = any(ca in issuer for ca in trusted_cas)
        if not ca_trusted and issuer:
            reasons.append(f"Unknown CA: {cert.get('issuer_name', 'Unknown')}")

        # Check validity period
        not_before = _parse_crtsh_date(cert.get("not_before", ""))
        not_after = _parse_crtsh_date(cert.get("not_after", ""))

        if not_before and not_after:
            validity_days = (not_after - not_before).days
            if validity_days < 7:
                reasons.append(f"Very short validity: {validity_days} days")
            elif validity_days > 825:  # > ~27 months (CAB forum limit)
                reasons.append(f"Unusually long validity: {validity_days} days")

        # Check for suspicious subdomain patterns
        if common_name:
            cn_lower = common_name.lower()
            suspicious_patterns = [
                "admin", "login", "secure", "account", "banking",
                "paypal", "amazon", "google", "microsoft", "apple"
            ]
            # Only flag if it's not the main domain
            if cn_lower != domain.lower() and any(p in cn_lower for p in suspicious_patterns):
                # Could be legitimate, mark as info
                pass  # Don't add this as suspicious by itself

        if reasons:
            suspicious.append({
                "common_name": common_name,
                "issuer": cert.get("issuer_name", "Unknown"),
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
                "reasons": reasons,
                "id": cert.get("id"),
                "crt_sh_url": f"https://crt.sh/?id={cert.get('id')}" if cert.get('id') else None
            })

    return suspicious[:20]  # Limit to 20


# ============================================================================
# MAIN CT MONITORING CHECK
# ============================================================================

async def check_certificate_transparency(
    domain: str,
    timeout: int = 30,
    include_expired: bool = False,
    include_subdomains: bool = True,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Perform comprehensive Certificate Transparency analysis.

    Queries CT logs to detect:
    - All certificates issued for the domain
    - CA diversity analysis
    - Wildcard certificate usage
    - Recent/suspicious certificate issuance
    - Subdomain discovery from CT logs

    Args:
        domain: Domain to check (e.g., "example.com")
        timeout: API request timeout
        include_expired: Include expired certificates
        include_subdomains: Also query for wildcard/subdomain certificates
        safe_mode: Enable rate limiting

    Returns:
        {
            "domain": "example.com",
            "certificates_found": int,
            "ca_diversity": {...},
            "wildcard_analysis": {...},
            "timeline_analysis": {...},
            "subdomain_discovery": {...},
            "suspicious_certificates": [...],
            "overall_risk": "high" | "medium" | "low" | "info",
            "findings": [...],
            "recommendations": [...]
        }
    """
    results = {
        "domain": domain,
        "certificates_found": 0,
        "ca_diversity": None,
        "wildcard_analysis": None,
        "timeline_analysis": None,
        "subdomain_discovery": None,
        "suspicious_certificates": [],
        "overall_risk": "unknown",
        "findings": [],
        "recommendations": [],
        "cwe": "CWE-295",
        "owasp": "A02:2021 - Cryptographic Failures"
    }

    # Query for exact domain and wildcards
    queries = [domain]
    if include_subdomains:
        queries.append(f"%.{domain}")  # Wildcard query for subdomains

    all_certs = []

    for query in queries:
        if safe_mode:
            await asyncio.sleep(1)  # Rate limit

        certs = await _query_crtsh(query, timeout=timeout, include_expired=include_expired)
        all_certs.extend(certs)

    # Deduplicate by certificate ID
    seen_ids = set()
    unique_certs = []
    for cert in all_certs:
        cert_id = cert.get("id")
        if cert_id and cert_id not in seen_ids:
            seen_ids.add(cert_id)
            unique_certs.append(cert)

    results["certificates_found"] = len(unique_certs)

    if not unique_certs:
        results["error"] = "No certificates found in CT logs"
        results["recommendations"].append("No CT log entries found. This could indicate the domain doesn't use HTTPS or certificates are not logged.")
        return results

    # Perform analyses
    results["ca_diversity"] = _analyze_certificate_diversity(unique_certs)
    results["wildcard_analysis"] = _analyze_wildcard_usage(unique_certs, domain)
    results["timeline_analysis"] = _analyze_certificate_timeline(unique_certs)
    results["subdomain_discovery"] = _discover_subdomains_from_ct(unique_certs, domain)
    results["suspicious_certificates"] = _detect_suspicious_certificates(unique_certs, domain)

    # Generate findings
    findings = []
    risk_levels = []

    # CA diversity finding
    # NOTE: Downgraded to "info" - single CA is not a vulnerability, just a risk factor
    # Many legitimate sites use only Let's Encrypt or Cloudflare. This is informational.
    ca_risk = results["ca_diversity"].get("risk_level", "unknown")
    if ca_risk in ["high", "medium"]:
        findings.append({
            "id": "ct_monitor:ca_diversity",
            "title": "Single CA Dependency",
            "severity": "info",  # Downgraded - not a vulnerability, just observation
            "description": results["ca_diversity"].get("recommendation"),
            "cvss_score": 2.0,  # Low score - informational
            "owasp": "A02:2021 - Cryptographic Failures",
            "cwe": "CWE-296"
        })
        risk_levels.append("info")

    # Timeline finding - certificate issuance is informational, not a vulnerability
    timeline_risk = results["timeline_analysis"].get("risk_level", "unknown")
    if timeline_risk in ["medium", "low"]:  # Only flag non-info levels
        findings.append({
            "id": "ct_monitor:cert_activity",
            "title": "Certificate Issuance Activity Note",
            "severity": "info",  # Always informational - cert issuance itself is not a vuln
            "description": results["timeline_analysis"].get("recommendation"),
            "cvss_score": 0,  # Not a vulnerability
            "owasp": "A02:2021 - Cryptographic Failures",
            "cwe": "CWE-295"
        })
        # Don't add to risk_levels - informational only

    # Suspicious certificates finding
    if results["suspicious_certificates"]:
        severity = "high" if len(results["suspicious_certificates"]) > 3 else "medium"
        findings.append({
            "id": "ct_monitor:suspicious_certs",
            "title": f"Suspicious Certificates Detected ({len(results['suspicious_certificates'])})",
            "severity": severity,
            "description": f"Found {len(results['suspicious_certificates'])} certificates with suspicious characteristics. Review for unauthorized issuance.",
            "cvss_score": 8.0 if severity == "high" else 6.0,
            "owasp": "A02:2021 - Cryptographic Failures",
            "cwe": "CWE-295"
        })
        risk_levels.append(severity)

    # Wildcard finding (informational)
    wildcard_risk = results["wildcard_analysis"].get("risk_level", "unknown")
    if wildcard_risk == "medium":
        findings.append({
            "id": "ct_monitor:wildcard_usage",
            "title": "High Wildcard Certificate Usage",
            "severity": "low",
            "description": results["wildcard_analysis"].get("recommendation"),
            "cvss_score": 3.0,
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-295"
        })

    results["findings"] = findings

    # Calculate overall risk
    if "high" in risk_levels:
        results["overall_risk"] = "high"
    elif "medium" in risk_levels:
        results["overall_risk"] = "medium"
    elif risk_levels:
        results["overall_risk"] = "low"
    else:
        results["overall_risk"] = "info"

    # Generate recommendations
    recommendations = []

    if results["ca_diversity"].get("unique_cas", 0) == 1:
        recommendations.append("Consider using multiple Certificate Authorities for redundancy")

    if results["timeline_analysis"].get("last_24h_count", 0) > 0:
        recommendations.append(f"Review {results['timeline_analysis']['last_24h_count']} certificates issued in the last 24 hours")

    if results["suspicious_certificates"]:
        recommendations.append("Investigate suspicious certificates for potential unauthorized issuance")

    if results["subdomain_discovery"].get("total_subdomains", 0) > 50:
        recommendations.append("Large number of subdomains discovered. Review for unused/forgotten services.")

    if not recommendations:
        recommendations.append("Certificate transparency monitoring shows healthy certificate hygiene")

    results["recommendations"] = recommendations

    return results


# ============================================================================
# CT LOG MONITORING FOR SPECIFIC EVENTS
# ============================================================================

async def monitor_ct_for_domain(
    domain: str,
    since_hours: int = 24,
    timeout: int = 30
) -> dict[str, Any]:
    """
    Monitor CT logs for recent certificate issuance.

    Useful for alerting on new certificate issuance.

    Args:
        domain: Domain to monitor
        since_hours: Look back period in hours
        timeout: Request timeout

    Returns:
        {
            "domain": "example.com",
            "new_certificates": [...],
            "total_new": int,
            "alert_level": "high" | "medium" | "low" | "none"
        }
    """
    results = {
        "domain": domain,
        "new_certificates": [],
        "total_new": 0,
        "since_hours": since_hours,
        "alert_level": "none"
    }

    # Query CT logs
    certs = await _query_crtsh(f"%.{domain}", timeout=timeout, include_expired=False)
    certs.extend(await _query_crtsh(domain, timeout=timeout, include_expired=False))

    # Filter to recent certificates
    now = datetime.now(UTC)
    cutoff = now - timedelta(hours=since_hours)

    new_certs = []
    for cert in certs:
        not_before = _parse_crtsh_date(cert.get("not_before", ""))
        if not_before and not_before > cutoff:
            new_certs.append({
                "common_name": cert.get("common_name"),
                "issuer": cert.get("issuer_name"),
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
                "id": cert.get("id"),
                "crt_sh_url": f"https://crt.sh/?id={cert.get('id')}" if cert.get('id') else None
            })

    # Deduplicate
    seen = set()
    unique_new = []
    for cert in new_certs:
        key = (cert.get("common_name"), cert.get("not_before"))
        if key not in seen:
            seen.add(key)
            unique_new.append(cert)

    results["new_certificates"] = unique_new
    results["total_new"] = len(unique_new)

    # Determine alert level
    if len(unique_new) > 5:
        results["alert_level"] = "high"
    elif len(unique_new) > 2:
        results["alert_level"] = "medium"
    elif len(unique_new) > 0:
        results["alert_level"] = "low"
    else:
        results["alert_level"] = "none"

    return results
