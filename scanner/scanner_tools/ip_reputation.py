#!/usr/bin/env python3
"""
IP Reputation & Threat Intelligence Module

This module checks IP addresses against threat intelligence sources:
1. DNS-based Blackhole Lists (DNSBL) - Free, no API key required
2. AbuseIPDB API - Optional, requires API key (1000 free checks/day)
3. VirusTotal API - Optional, requires API key (4 lookups/min free tier)

All checks are read-only and non-intrusive.

OWASP Mapping:
- A09:2021 - Security Logging and Monitoring Failures (reputation indicates compromise)

CWE Mapping:
- CWE-693: Protection Mechanism Failure
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
"""

import asyncio
import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any

# Disable SSL verification for API calls (corporate proxies)
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Set global socket timeout
socket.setdefaulttimeout(10)

# ============================================================================
# DNS BLACKHOLE LIST (DNSBL) SERVERS - FREE, NO API KEY
# ============================================================================

DNSBL_SERVERS = [
    # Spamhaus - Most authoritative
    ("zen.spamhaus.org", "Spamhaus ZEN (spam, exploits, malware)"),
    ("sbl.spamhaus.org", "Spamhaus SBL (spam sources)"),
    ("xbl.spamhaus.org", "Spamhaus XBL (exploits, proxies)"),

    # Barracuda - Enterprise email security
    ("b.barracudacentral.org", "Barracuda Central"),

    # SpamCop - Crowd-sourced spam reporting
    ("bl.spamcop.net", "SpamCop"),

    # SORBS - Spam and Open Relay Blocking System
    ("dnsbl.sorbs.net", "SORBS (all lists)"),
    ("spam.dnsbl.sorbs.net", "SORBS Spam"),
    ("web.dnsbl.sorbs.net", "SORBS Web servers"),

    # CBL - Composite Blocking List (exploits/malware)
    ("cbl.abuseat.org", "CBL Abuseat"),

    # UCEPROTECT - Multi-tier blacklist
    ("dnsbl-1.uceprotect.net", "UCEPROTECT Level 1"),

    # SpamRATS - Rat traps (spam bots)
    ("dyna.spamrats.com", "SpamRATS Dynamic"),
    ("noptr.spamrats.com", "SpamRATS NoPtr"),

    # PSBL - Passive Spam Block List
    ("psbl.surriel.com", "PSBL"),
]

# Spamhaus return code meanings
SPAMHAUS_CODES = {
    "127.0.0.2": "SBL - Spamhaus Block List",
    "127.0.0.3": "SBL CSS - Spamhaus CSS",
    "127.0.0.4": "XBL - CBL (exploit bot)",
    "127.0.0.5": "XBL - NJABL proxy",
    "127.0.0.6": "XBL - Psyb's open relay",
    "127.0.0.7": "XBL - CBL hijacked",
    "127.0.0.9": "SBL DROP - Drop list",
    "127.0.0.10": "PBL - Policy Block List (ISP)",
    "127.0.0.11": "PBL - Policy Block List (maintainer)",
}


async def _dns_lookup(query: str, timeout: int = 5) -> list[str] | None:
    """
    Perform DNS A record lookup asynchronously.

    Returns list of IP addresses or None if not found.
    """
    def _sync_lookup():
        try:
            socket.setdefaulttimeout(timeout)
            results = socket.getaddrinfo(query, None, socket.AF_INET, socket.SOCK_STREAM)
            return [r[4][0] for r in results]
        except (TimeoutError, socket.gaierror):
            return None
        except Exception:
            return None

    return await asyncio.to_thread(_sync_lookup)


async def check_dnsbl(ip: str, timeout: int = 5) -> dict[str, Any]:
    """
    Check IP against DNS-based Blackhole Lists (free, no API key).

    How DNSBL works:
    1. Reverse the IP octets: 1.2.3.4 -> 4.3.2.1
    2. Append DNSBL server: 4.3.2.1.zen.spamhaus.org
    3. DNS lookup: if resolves to 127.0.0.x, IP is blacklisted

    Args:
        ip: IP address to check
        timeout: DNS lookup timeout per server

    Returns:
        {
            "ip": "1.2.3.4",
            "blacklisted": bool,
            "blacklists": [
                {
                    "list": "zen.spamhaus.org",
                    "description": "Spamhaus ZEN",
                    "response": "127.0.0.4",
                    "meaning": "XBL - CBL (exploit bot)"
                }
            ],
            "total_checked": int,
            "blacklist_count": int
        }
    """
    results = {
        "ip": ip,
        "blacklisted": False,
        "blacklists": [],
        "total_checked": len(DNSBL_SERVERS),
        "blacklist_count": 0
    }

    # Validate IPv4 address
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        results["error"] = "Invalid IPv4 address"
        return results

    # Reverse the IP octets
    reversed_ip = ".".join(reversed(ip.split(".")))

    # Check each DNSBL server in parallel
    async def check_single_dnsbl(dnsbl: str, description: str):
        query = f"{reversed_ip}.{dnsbl}"
        response = await _dns_lookup(query, timeout=timeout)

        if response:
            # IP is blacklisted
            response_ip = response[0]
            meaning = SPAMHAUS_CODES.get(response_ip, "Listed")
            return {
                "list": dnsbl,
                "description": description,
                "response": response_ip,
                "meaning": meaning
            }
        return None

    # Run all DNSBL checks in parallel
    tasks = [check_single_dnsbl(dnsbl, desc) for dnsbl, desc in DNSBL_SERVERS]
    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in check_results:
        if result and not isinstance(result, Exception):
            results["blacklists"].append(result)

    results["blacklist_count"] = len(results["blacklists"])
    results["blacklisted"] = results["blacklist_count"] > 0

    return results


# ============================================================================
# ABUSEIPDB API (OPTIONAL - FREE TIER: 1000 CHECKS/DAY)
# ============================================================================

async def check_abuseipdb(
    ip: str,
    api_key: str,
    max_age_days: int = 90,
    timeout: int = 10
) -> dict[str, Any]:
    """
    Check IP reputation via AbuseIPDB API.

    AbuseIPDB is a community-driven IP blacklist with detailed abuse reports.
    Free tier allows 1000 checks per day.

    API: https://docs.abuseipdb.com/#check-endpoint

    Args:
        ip: IP address to check
        api_key: AbuseIPDB API key
        max_age_days: Only consider reports from last N days (default: 90)
        timeout: API request timeout

    Returns:
        {
            "ip": "1.2.3.4",
            "abuse_confidence_score": 0-100,
            "total_reports": int,
            "country_code": "US",
            "isp": "Example ISP",
            "domain": "example.com",
            "is_tor": bool,
            "is_public": bool,
            "usage_type": "Data Center/Web Hosting/Transit",
            "last_reported_at": "2024-01-01T00:00:00+00:00",
            "categories": [list of abuse category IDs]
        }
    """
    results = {
        "ip": ip,
        "source": "abuseipdb",
        "checked": False,
        "error": None
    }

    if not api_key:
        results["error"] = "No API key provided"
        return results

    def _sync_request():
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            params = f"?ipAddress={ip}&maxAgeInDays={max_age_days}&verbose=1"

            req = urllib.request.Request(
                url + params,
                headers={
                    "Key": api_key,
                    "Accept": "application/json"
                }
            )

            with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as response:
                data = json.loads(response.read().decode('utf-8'))
                return data.get("data", {})
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return {"error": "Invalid API key"}
            elif e.code == 429:
                return {"error": "Rate limit exceeded (1000/day)"}
            return {"error": f"HTTP {e.code}"}
        except urllib.error.URLError as e:
            return {"error": f"Connection error: {e!s}"}
        except Exception as e:
            return {"error": str(e)}

    data = await asyncio.to_thread(_sync_request)

    if "error" in data:
        results["error"] = data["error"]
        return results

    results["checked"] = True
    results["abuse_confidence_score"] = data.get("abuseConfidenceScore", 0)
    results["total_reports"] = data.get("totalReports", 0)
    results["country_code"] = data.get("countryCode")
    results["isp"] = data.get("isp")
    results["domain"] = data.get("domain")
    results["is_tor"] = data.get("isTor", False)
    results["is_public"] = data.get("isPublic", True)
    results["usage_type"] = data.get("usageType")
    results["last_reported_at"] = data.get("lastReportedAt")

    # Map category IDs to names
    category_ids = []
    for report in data.get("reports", []):
        category_ids.extend(report.get("categories", []))
    results["categories"] = list(set(category_ids))

    return results


# AbuseIPDB Category Mapping
ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


# ============================================================================
# VIRUSTOTAL API (OPTIONAL - FREE TIER: 4 LOOKUPS/MIN)
# ============================================================================

async def check_virustotal(
    ip: str,
    api_key: str,
    timeout: int = 15
) -> dict[str, Any]:
    """
    Check IP reputation via VirusTotal API.

    VirusTotal aggregates data from 70+ security vendors.
    Free tier allows 4 lookups per minute.

    API: https://developers.virustotal.com/reference/ip-info

    Args:
        ip: IP address to check
        api_key: VirusTotal API key
        timeout: API request timeout

    Returns:
        {
            "ip": "1.2.3.4",
            "malicious_count": int,
            "suspicious_count": int,
            "harmless_count": int,
            "undetected_count": int,
            "reputation": int (-100 to 100),
            "asn": int,
            "as_owner": str,
            "country": str,
            "network": str,
            "last_analysis_date": str
        }
    """
    results = {
        "ip": ip,
        "source": "virustotal",
        "checked": False,
        "error": None
    }

    if not api_key:
        results["error"] = "No API key provided"
        return results

    def _sync_request():
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

            req = urllib.request.Request(
                url,
                headers={
                    "x-apikey": api_key,
                    "Accept": "application/json"
                }
            )

            with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as response:
                data = json.loads(response.read().decode('utf-8'))
                return data.get("data", {}).get("attributes", {})
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return {"error": "Invalid API key"}
            elif e.code == 429:
                return {"error": "Rate limit exceeded (4/min)"}
            elif e.code == 404:
                return {"error": "IP not found in database"}
            return {"error": f"HTTP {e.code}"}
        except Exception as e:
            return {"error": str(e)}

    data = await asyncio.to_thread(_sync_request)

    if "error" in data:
        results["error"] = data["error"]
        return results

    results["checked"] = True

    # Last analysis stats
    stats = data.get("last_analysis_stats", {})
    results["malicious_count"] = stats.get("malicious", 0)
    results["suspicious_count"] = stats.get("suspicious", 0)
    results["harmless_count"] = stats.get("harmless", 0)
    results["undetected_count"] = stats.get("undetected", 0)

    # Reputation and network info
    results["reputation"] = data.get("reputation", 0)
    results["asn"] = data.get("asn")
    results["as_owner"] = data.get("as_owner")
    results["country"] = data.get("country")
    results["network"] = data.get("network")
    results["last_analysis_date"] = data.get("last_analysis_date")

    return results


# ============================================================================
# COMBINED IP REPUTATION CHECK
# ============================================================================

async def check_ip_reputation(
    ip: str,
    abuseipdb_key: str | None = None,
    virustotal_key: str | None = None,
    check_dnsbl_servers: bool = True,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Comprehensive IP reputation check using multiple sources.

    This is the main entry point for IP reputation checking.

    Sources checked:
    1. DNSBL servers (always, free)
    2. AbuseIPDB (if API key provided)
    3. VirusTotal (if API key provided)

    Args:
        ip: IP address to check
        abuseipdb_key: Optional AbuseIPDB API key
        virustotal_key: Optional VirusTotal API key
        check_dnsbl_servers: Whether to check DNS blacklists
        safe_mode: Not used (all checks are read-only)

    Returns:
        {
            "ip": "1.2.3.4",
            "reputation_score": 0-100 (100 = clean),
            "risk_level": "low" | "medium" | "high" | "critical",
            "blacklisted": bool,
            "is_tor_exit": bool,
            "is_proxy": bool,
            "threat_indicators": [list of threat types],
            "dnsbl": {...},
            "abuseipdb": {...},
            "virustotal": {...},
            "recommendations": [list of recommendations],
            "cwe": "CWE-693",
            "owasp": "A09:2021 - Security Logging and Monitoring Failures"
        }
    """
    results = {
        "ip": ip,
        "reputation_score": 100,
        "risk_level": "low",
        "blacklisted": False,
        "is_tor_exit": False,
        "is_proxy": False,
        "threat_indicators": [],
        "sources_checked": [],
        "recommendations": [],
        "cwe": "CWE-693",
        "owasp": "A09:2021 - Security Logging and Monitoring Failures"
    }

    # 1. Check DNSBL servers (free)
    if check_dnsbl_servers:
        dnsbl_results = await check_dnsbl(ip)
        results["dnsbl"] = dnsbl_results
        results["sources_checked"].append("dnsbl")

        if dnsbl_results["blacklisted"]:
            results["blacklisted"] = True
            results["reputation_score"] -= 20 * min(dnsbl_results["blacklist_count"], 3)

            # Identify threat types from DNSBL responses
            for bl in dnsbl_results["blacklists"]:
                meaning = bl.get("meaning", "").lower()
                if "spam" in meaning:
                    results["threat_indicators"].append("spam_source")
                if "exploit" in meaning or "bot" in meaning:
                    results["threat_indicators"].append("malware_infected")
                if "proxy" in meaning:
                    results["threat_indicators"].append("open_proxy")
                    results["is_proxy"] = True

    # 2. Check AbuseIPDB (if API key provided)
    if abuseipdb_key:
        abuse_results = await check_abuseipdb(ip, abuseipdb_key)
        results["abuseipdb"] = abuse_results
        results["sources_checked"].append("abuseipdb")

        if abuse_results.get("checked"):
            confidence = abuse_results.get("abuse_confidence_score", 0)
            if confidence > 0:
                # Deduct based on confidence score
                results["reputation_score"] -= int(confidence * 0.5)

                if confidence >= 80:
                    results["threat_indicators"].append("high_abuse_confidence")
                elif confidence >= 50:
                    results["threat_indicators"].append("moderate_abuse_confidence")

            if abuse_results.get("is_tor"):
                results["is_tor_exit"] = True
                results["threat_indicators"].append("tor_exit_node")
                results["reputation_score"] -= 10

            # Check abuse categories
            categories = abuse_results.get("categories", [])
            if 4 in categories:  # DDoS
                results["threat_indicators"].append("ddos_source")
            if 14 in categories:  # Port scan
                results["threat_indicators"].append("port_scanner")
            if 15 in categories or 21 in categories:  # Hacking / Web App Attack
                results["threat_indicators"].append("attack_source")
            if 18 in categories:  # Brute-Force
                results["threat_indicators"].append("brute_force_source")

    # 3. Check VirusTotal (if API key provided)
    if virustotal_key:
        vt_results = await check_virustotal(ip, virustotal_key)
        results["virustotal"] = vt_results
        results["sources_checked"].append("virustotal")

        if vt_results.get("checked"):
            malicious = vt_results.get("malicious_count", 0)
            suspicious = vt_results.get("suspicious_count", 0)

            if malicious > 0:
                # Heavy penalty for malicious detections
                results["reputation_score"] -= min(malicious * 5, 30)
                results["threat_indicators"].append(f"vt_malicious_{malicious}")

            if suspicious > 0:
                results["reputation_score"] -= min(suspicious * 2, 10)
                results["threat_indicators"].append(f"vt_suspicious_{suspicious}")

            # VirusTotal community reputation
            vt_rep = vt_results.get("reputation", 0)
            if vt_rep < -10:
                results["reputation_score"] -= 10
                results["threat_indicators"].append("negative_community_reputation")

    # Calculate final risk level
    results["reputation_score"] = max(0, results["reputation_score"])

    if results["reputation_score"] >= 80:
        results["risk_level"] = "low"
    elif results["reputation_score"] >= 60:
        results["risk_level"] = "medium"
    elif results["reputation_score"] >= 40:
        results["risk_level"] = "high"
    else:
        results["risk_level"] = "critical"

    # Remove duplicate threat indicators
    results["threat_indicators"] = list(set(results["threat_indicators"]))

    # Generate recommendations
    if results["blacklisted"]:
        results["recommendations"].append(
            "IP is blacklisted. Consider investigating for compromise or requesting delisting."
        )
    if results["is_tor_exit"]:
        results["recommendations"].append(
            "IP is a known Tor exit node. May receive traffic from anonymous users."
        )
    if results["is_proxy"]:
        results["recommendations"].append(
            "IP is a known open proxy. May be used for anonymous attacks."
        )
    if "attack_source" in results["threat_indicators"]:
        results["recommendations"].append(
            "IP has been reported as an attack source. Review security logs for suspicious activity."
        )
    if results["risk_level"] in ["high", "critical"]:
        results["recommendations"].append(
            "Consider blocking this IP or implementing additional monitoring."
        )

    return results


# ============================================================================
# BATCH IP REPUTATION CHECK
# ============================================================================

async def check_multiple_ips(
    ips: list[str],
    abuseipdb_key: str | None = None,
    virustotal_key: str | None = None,
    max_concurrent: int = 5
) -> dict[str, Any]:
    """
    Check reputation of multiple IPs with rate limiting.

    Args:
        ips: List of IP addresses to check
        abuseipdb_key: Optional AbuseIPDB API key
        virustotal_key: Optional VirusTotal API key
        max_concurrent: Max concurrent checks (default: 5)

    Returns:
        {
            "total_checked": int,
            "high_risk_count": int,
            "blacklisted_count": int,
            "results": {
                "1.2.3.4": {...},
                "5.6.7.8": {...}
            }
        }
    """
    results = {
        "total_checked": len(ips),
        "high_risk_count": 0,
        "blacklisted_count": 0,
        "results": {}
    }

    semaphore = asyncio.Semaphore(max_concurrent)

    async def check_with_limit(ip: str):
        async with semaphore:
            # Add small delay to respect rate limits
            await asyncio.sleep(0.5)
            return await check_ip_reputation(
                ip,
                abuseipdb_key=abuseipdb_key,
                virustotal_key=virustotal_key
            )

    tasks = [check_with_limit(ip) for ip in ips]
    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for ip, result in zip(ips, check_results, strict=False):
        if isinstance(result, Exception):
            results["results"][ip] = {"error": str(result)}
        else:
            results["results"][ip] = result
            if result.get("blacklisted"):
                results["blacklisted_count"] += 1
            if result.get("risk_level") in ["high", "critical"]:
                results["high_risk_count"] += 1

    return results
