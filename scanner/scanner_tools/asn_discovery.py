"""
ASN/IP Discovery Module

Comprehensive network intelligence including:
- ASN lookup and BGP information
- IP range enumeration for organizations
- Hosting provider identification (AWS, GCP, Azure, Cloudflare)
- Geographic distribution mapping
- Multi-homed network detection

Uses free APIs/tools only: Team Cymru DNS, RIPE, whois
"""

import asyncio
import hashlib
import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

# ============================================================================
# CONSTANTS
# ============================================================================

# Major cloud/hosting provider ASN ranges
CLOUD_PROVIDERS = {
    # AWS
    "16509": {"name": "Amazon AWS", "type": "cloud"},
    "14618": {"name": "Amazon AWS", "type": "cloud"},
    "8987": {"name": "Amazon AWS (EU)", "type": "cloud"},
    # Google
    "15169": {"name": "Google Cloud", "type": "cloud"},
    "396982": {"name": "Google Cloud", "type": "cloud"},
    "36040": {"name": "Google Cloud", "type": "cloud"},
    # Microsoft Azure
    "8075": {"name": "Microsoft Azure", "type": "cloud"},
    "8068": {"name": "Microsoft Azure", "type": "cloud"},
    "8069": {"name": "Microsoft Azure", "type": "cloud"},
    # Cloudflare
    "13335": {"name": "Cloudflare", "type": "cdn"},
    "209242": {"name": "Cloudflare", "type": "cdn"},
    # Akamai
    "20940": {"name": "Akamai", "type": "cdn"},
    "16625": {"name": "Akamai", "type": "cdn"},
    # Fastly
    "54113": {"name": "Fastly", "type": "cdn"},
    # DigitalOcean
    "14061": {"name": "DigitalOcean", "type": "cloud"},
    # Linode
    "63949": {"name": "Linode (Akamai)", "type": "cloud"},
    # Vultr
    "20473": {"name": "Vultr", "type": "cloud"},
    # OVH
    "16276": {"name": "OVH", "type": "hosting"},
    # Hetzner
    "24940": {"name": "Hetzner", "type": "hosting"},
    # Oracle Cloud
    "31898": {"name": "Oracle Cloud", "type": "cloud"},
    # Alibaba Cloud
    "45102": {"name": "Alibaba Cloud", "type": "cloud"},
    # Tencent Cloud
    "132203": {"name": "Tencent Cloud", "type": "cloud"},
}

# Country codes for geographic mapping
COUNTRY_NAMES = {
    "US": "United States", "GB": "United Kingdom", "DE": "Germany",
    "FR": "France", "NL": "Netherlands", "JP": "Japan", "AU": "Australia",
    "CA": "Canada", "SG": "Singapore", "IN": "India", "BR": "Brazil",
    "IE": "Ireland", "SE": "Sweden", "FI": "Finland", "NO": "Norway",
    "DK": "Denmark", "CH": "Switzerland", "BE": "Belgium", "IT": "Italy",
    "ES": "Spain", "PL": "Poland", "CZ": "Czech Republic", "AT": "Austria",
    "RU": "Russia", "CN": "China", "KR": "South Korea", "HK": "Hong Kong",
    "TW": "Taiwan", "ID": "Indonesia", "MY": "Malaysia", "TH": "Thailand",
    "VN": "Vietnam", "PH": "Philippines", "NZ": "New Zealand",
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

async def _run_command(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a command asynchronously with timeout."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout
        )
        return (
            stdout.decode('utf-8', errors='replace'),
            stderr.decode('utf-8', errors='replace'),
            proc.returncode or 0
        )
    except TimeoutError:
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        return "", "Command timed out", -1
    except asyncio.CancelledError:
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        raise
    except Exception as e:
        return "", str(e), -1


def _reverse_ip(ip: str) -> str:
    """Reverse an IP address for DNS queries."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            octets = ip.split('.')
            return '.'.join(reversed(octets))
        else:
            # IPv6 - expand and reverse
            expanded = ip_obj.exploded.replace(':', '')
            return '.'.join(reversed(expanded))
    except Exception:
        return ""


async def _dns_query(name: str, record_type: str = "TXT", timeout: int = 10) -> str | None:
    """Perform a DNS query."""
    cmd = ["dig", "+short", record_type, name]
    stdout, stderr, returncode = await _run_command(cmd, timeout)
    if returncode == 0 and stdout.strip():
        return stdout.strip()
    return None


# ============================================================================
# ASN LOOKUP
# ============================================================================

async def _lookup_asn_cymru(ip: str, timeout: int = 15) -> dict[str, Any]:
    """
    Look up ASN information using Team Cymru DNS service.

    Query format: <reversed-ip>.origin.asn.cymru.com
    Response format: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    """
    result = {
        "ip": ip,
        "asn": None,
        "as_name": None,
        "prefix": None,
        "country": None,
        "registry": None,
        "allocated": None,
        "source": "team_cymru"
    }

    try:
        ip_obj = ipaddress.ip_address(ip)

        if isinstance(ip_obj, ipaddress.IPv4Address):
            reversed_ip = _reverse_ip(ip)
            query = f"{reversed_ip}.origin.asn.cymru.com"
        else:
            # IPv6
            expanded = ip_obj.exploded.replace(':', '')
            reversed_ip = '.'.join(reversed(expanded))
            query = f"{reversed_ip}.origin6.asn.cymru.com"

        response = await _dns_query(query, "TXT", timeout)

        if response:
            # Parse response: "AS | IP | Prefix | CC | Registry | Allocated"
            # Clean up quotes and whitespace
            clean_response = response.strip('"').strip()
            parts = [p.strip() for p in clean_response.split('|')]

            if len(parts) >= 3:
                result["asn"] = parts[0].replace("AS", "").strip()
                result["prefix"] = parts[2] if len(parts) > 2 else None
                result["country"] = parts[3] if len(parts) > 3 else None
                result["registry"] = parts[4] if len(parts) > 4 else None
                result["allocated"] = parts[5] if len(parts) > 5 else None

                # Get AS name
                if result["asn"]:
                    as_query = f"AS{result['asn']}.asn.cymru.com"
                    as_response = await _dns_query(as_query, "TXT", timeout)
                    if as_response:
                        as_parts = [p.strip() for p in as_response.strip('"').split('|')]
                        if len(as_parts) >= 5:
                            result["as_name"] = as_parts[4].strip()

    except Exception as e:
        result["error"] = str(e)

    return result


async def _lookup_asn_whois(ip: str, timeout: int = 15) -> dict[str, Any]:
    """Fallback ASN lookup using whois command."""
    result = {
        "ip": ip,
        "asn": None,
        "as_name": None,
        "prefix": None,
        "country": None,
        "org": None,
        "source": "whois"
    }

    cmd = ["whois", ip]
    stdout, stderr, returncode = await _run_command(cmd, timeout)

    if returncode == 0 and stdout:
        # Parse whois output
        for line in stdout.split('\n'):
            line_lower = line.lower()

            if 'origin' in line_lower and ':' in line:
                # OriginAS or origin
                value = line.split(':', 1)[1].strip()
                asn_match = re.search(r'AS?(\d+)', value, re.I)
                if asn_match:
                    result["asn"] = asn_match.group(1)

            elif 'netname' in line_lower and ':' in line:
                result["as_name"] = line.split(':', 1)[1].strip()

            elif 'country' in line_lower and ':' in line:
                result["country"] = line.split(':', 1)[1].strip()[:2].upper()

            elif 'organization' in line_lower and ':' in line:
                result["org"] = line.split(':', 1)[1].strip()

            elif 'cidr' in line_lower and ':' in line:
                result["prefix"] = line.split(':', 1)[1].strip().split(',')[0].strip()

            elif 'route' in line_lower and ':' in line and not result["prefix"]:
                result["prefix"] = line.split(':', 1)[1].strip()

    return result


async def lookup_asn(ip: str, timeout: int = 15) -> dict[str, Any]:
    """Look up ASN information for an IP address."""
    # Try Team Cymru first
    result = await _lookup_asn_cymru(ip, timeout)

    # If ASN not found, try whois fallback
    if not result.get("asn"):
        whois_result = await _lookup_asn_whois(ip, timeout)
        if whois_result.get("asn"):
            result = whois_result

    return result


# ============================================================================
# HOSTING PROVIDER IDENTIFICATION
# ============================================================================

def identify_hosting_provider(asn: str, as_name: str = "") -> dict[str, Any]:
    """Identify the hosting/cloud provider based on ASN."""
    result = {
        "provider": None,
        "type": None,
        "is_cloud": False,
        "is_cdn": False,
        "is_hosting": False
    }

    # Check known ASNs
    if asn in CLOUD_PROVIDERS:
        provider_info = CLOUD_PROVIDERS[asn]
        result["provider"] = provider_info["name"]
        result["type"] = provider_info["type"]
        result["is_cloud"] = provider_info["type"] == "cloud"
        result["is_cdn"] = provider_info["type"] == "cdn"
        result["is_hosting"] = provider_info["type"] == "hosting"
        return result

    # Check AS name for common patterns
    as_name_lower = (as_name or "").lower()

    provider_patterns = [
        (["amazon", "aws", "ec2"], "Amazon AWS", "cloud"),
        (["google", "gcp"], "Google Cloud", "cloud"),
        (["microsoft", "azure"], "Microsoft Azure", "cloud"),
        (["cloudflare"], "Cloudflare", "cdn"),
        (["akamai"], "Akamai", "cdn"),
        (["fastly"], "Fastly", "cdn"),
        (["digitalocean"], "DigitalOcean", "cloud"),
        (["linode"], "Linode", "cloud"),
        (["vultr"], "Vultr", "cloud"),
        (["ovh"], "OVH", "hosting"),
        (["hetzner"], "Hetzner", "hosting"),
        (["oracle"], "Oracle Cloud", "cloud"),
        (["alibaba", "aliyun"], "Alibaba Cloud", "cloud"),
        (["tencent"], "Tencent Cloud", "cloud"),
        (["rackspace"], "Rackspace", "hosting"),
        (["godaddy"], "GoDaddy", "hosting"),
        (["hostgator"], "HostGator", "hosting"),
        (["bluehost"], "Bluehost", "hosting"),
    ]

    for patterns, provider_name, provider_type in provider_patterns:
        if any(p in as_name_lower for p in patterns):
            result["provider"] = provider_name
            result["type"] = provider_type
            result["is_cloud"] = provider_type == "cloud"
            result["is_cdn"] = provider_type == "cdn"
            result["is_hosting"] = provider_type == "hosting"
            break

    return result


# ============================================================================
# IP RANGE AND NETWORK ANALYSIS
# ============================================================================

async def _get_prefixes_for_asn(asn: str, timeout: int = 20) -> list[str]:
    """Get announced prefixes for an ASN using RIPE RIS."""
    prefixes = []

    # Use whois to query for prefixes
    cmd = ["whois", "-h", "whois.radb.net", f"-i origin AS{asn}"]
    stdout, stderr, returncode = await _run_command(cmd, timeout)

    if returncode == 0 and stdout:
        for line in stdout.split('\n'):
            if line.startswith('route:') or line.startswith('route6:'):
                prefix = line.split(':', 1)[1].strip()
                if prefix and prefix not in prefixes:
                    prefixes.append(prefix)

    return prefixes[:20]  # Limit to 20 prefixes


def _analyze_network_size(prefixes: list[str]) -> dict[str, Any]:
    """Analyze the total network size from prefixes."""
    result = {
        "ipv4_prefixes": [],
        "ipv6_prefixes": [],
        "total_ipv4_addresses": 0,
        "total_ipv6_prefixes": 0,
        "largest_ipv4_block": None,
        "network_size_class": "unknown"
    }

    for prefix in prefixes:
        try:
            network = ipaddress.ip_network(prefix, strict=False)
            if isinstance(network, ipaddress.IPv4Network):
                result["ipv4_prefixes"].append(prefix)
                result["total_ipv4_addresses"] += network.num_addresses
                if result["largest_ipv4_block"] is None or network.prefixlen < int(result["largest_ipv4_block"].split('/')[1]):
                    result["largest_ipv4_block"] = prefix
            else:
                result["ipv6_prefixes"].append(prefix)
                result["total_ipv6_prefixes"] += 1
        except Exception:
            continue

    # Classify network size
    total = result["total_ipv4_addresses"]
    if total >= 16777216:  # /8 or larger
        result["network_size_class"] = "tier1"
    elif total >= 65536:  # /16 or larger
        result["network_size_class"] = "large"
    elif total >= 256:  # /24 or larger
        result["network_size_class"] = "medium"
    elif total > 0:
        result["network_size_class"] = "small"

    return result


# ============================================================================
# GEOGRAPHIC DISTRIBUTION
# ============================================================================

async def _analyze_geographic_distribution(ips: list[str], timeout: int = 30) -> dict[str, Any]:
    """Analyze geographic distribution of IP addresses."""
    result = {
        "countries": {},
        "primary_country": None,
        "is_distributed": False,
        "distribution_score": 0
    }

    countries = {}

    for ip in ips[:10]:  # Limit to first 10 IPs
        asn_info = await lookup_asn(ip, timeout // len(ips))
        country = asn_info.get("country")
        if country:
            countries[country] = countries.get(country, 0) + 1

    if countries:
        result["countries"] = countries
        result["primary_country"] = max(countries, key=countries.get)
        result["is_distributed"] = len(countries) > 1
        # Distribution score: 0 = single location, 100 = evenly distributed
        if len(ips) > 0:
            max_concentration = max(countries.values()) / len(ips)
            result["distribution_score"] = int((1 - max_concentration) * 100)

    return result


# ============================================================================
# MULTI-HOMING DETECTION
# ============================================================================

async def _detect_multi_homing(domain: str, timeout: int = 30) -> dict[str, Any]:
    """Detect if a domain uses multiple ASNs (multi-homed)."""
    result = {
        "is_multi_homed": False,
        "unique_asns": [],
        "asn_details": [],
        "redundancy_level": "none"
    }

    # Resolve all IPs for the domain
    cmd = ["dig", "+short", "A", domain]
    stdout, _, _ = await _run_command(cmd, timeout)

    ips = [ip.strip() for ip in stdout.strip().split('\n') if ip.strip()]

    # Also get AAAA records
    cmd = ["dig", "+short", "AAAA", domain]
    stdout, _, _ = await _run_command(cmd, timeout)
    ips.extend([ip.strip() for ip in stdout.strip().split('\n') if ip.strip()])

    # Look up ASN for each IP
    unique_asns = set()
    asn_details = []

    for ip in ips[:10]:  # Limit to 10 IPs
        asn_info = await lookup_asn(ip, timeout // max(len(ips), 1))
        if asn_info.get("asn"):
            unique_asns.add(asn_info["asn"])
            asn_details.append({
                "ip": ip,
                "asn": asn_info["asn"],
                "as_name": asn_info.get("as_name"),
                "country": asn_info.get("country")
            })

    result["unique_asns"] = list(unique_asns)
    result["asn_details"] = asn_details
    result["is_multi_homed"] = len(unique_asns) > 1

    # Assess redundancy level
    if len(unique_asns) >= 3:
        result["redundancy_level"] = "high"
    elif len(unique_asns) == 2:
        result["redundancy_level"] = "medium"
    elif len(unique_asns) == 1 and len(ips) > 1:
        result["redundancy_level"] = "low"
    else:
        result["redundancy_level"] = "none"

    return result


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

async def check_asn_discovery(
    domain: str,
    timeout: int = 60,
    include_prefixes: bool = False,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Comprehensive ASN and network discovery.

    Args:
        domain: Domain to analyze
        timeout: Timeout for all operations
        include_prefixes: Whether to enumerate all prefixes for discovered ASNs
        safe_mode: If True, limit queries to avoid rate limiting

    Returns:
        Dict with ASN discovery results
    """
    results = {
        "domain": domain,
        "scan_timestamp": datetime.now(UTC).isoformat(),
        "resolved_ips": [],
        "asn_info": [],
        "hosting_providers": [],
        "geographic_distribution": None,
        "multi_homing": None,
        "network_analysis": None,
        "overall_assessment": {
            "primary_provider": None,
            "infrastructure_type": None,
            "redundancy_level": "unknown",
            "risk_level": "info",
            "issues": [],
            "recommendations": []
        },
        "findings": []
    }

    # Step 1: Resolve domain to IPs
    cmd = ["dig", "+short", "A", domain]
    stdout, _, _ = await _run_command(cmd, timeout // 4)
    ipv4_ips = [ip.strip() for ip in stdout.strip().split('\n') if ip.strip()]

    cmd = ["dig", "+short", "AAAA", domain]
    stdout, _, _ = await _run_command(cmd, timeout // 4)
    ipv6_ips = [ip.strip() for ip in stdout.strip().split('\n') if ip.strip()]

    results["resolved_ips"] = {
        "ipv4": ipv4_ips,
        "ipv6": ipv6_ips,
        "total": len(ipv4_ips) + len(ipv6_ips)
    }

    # Step 2: Look up ASN for each IP
    all_ips = ipv4_ips + ipv6_ips
    seen_asns = set()
    providers = []

    for ip in all_ips[:5]:  # Limit to 5 IPs
        asn_info = await lookup_asn(ip, timeout // 5)
        if asn_info.get("asn"):
            # Add provider identification
            provider_info = identify_hosting_provider(
                asn_info["asn"],
                asn_info.get("as_name", "")
            )
            asn_info["provider"] = provider_info

            results["asn_info"].append(asn_info)

            if asn_info["asn"] not in seen_asns:
                seen_asns.add(asn_info["asn"])
                if provider_info.get("provider"):
                    providers.append(provider_info)

    results["hosting_providers"] = providers

    # Step 3: Multi-homing detection
    results["multi_homing"] = await _detect_multi_homing(domain, timeout // 3)

    # Step 4: Geographic distribution
    if len(all_ips) > 0:
        results["geographic_distribution"] = await _analyze_geographic_distribution(
            all_ips[:5], timeout // 3
        )

    # Step 5: Network analysis (if prefixes requested)
    if include_prefixes and results["asn_info"]:
        first_asn = results["asn_info"][0].get("asn")
        if first_asn:
            prefixes = await _get_prefixes_for_asn(first_asn, timeout // 3)
            results["network_analysis"] = _analyze_network_size(prefixes)

    # Step 6: Calculate overall assessment
    _calculate_assessment(results)

    # Step 7: Generate findings
    _generate_findings(results)

    return results


def _calculate_assessment(results: dict[str, Any]) -> None:
    """Calculate overall assessment based on results."""
    assessment = results["overall_assessment"]
    issues = []
    recommendations = []

    # Determine primary provider
    if results["hosting_providers"]:
        assessment["primary_provider"] = results["hosting_providers"][0].get("provider")

        # Determine infrastructure type
        types = [p.get("type") for p in results["hosting_providers"] if p.get("type")]
        if "cloud" in types:
            assessment["infrastructure_type"] = "cloud"
        elif "cdn" in types:
            assessment["infrastructure_type"] = "cdn"
        elif "hosting" in types:
            assessment["infrastructure_type"] = "shared_hosting"
        else:
            assessment["infrastructure_type"] = "unknown"

    # Set redundancy level from multi-homing results
    if results.get("multi_homing"):
        assessment["redundancy_level"] = results["multi_homing"].get("redundancy_level", "unknown")

    # Identify issues
    if not results["asn_info"]:
        issues.append("Could not determine ASN information")
        assessment["risk_level"] = "low"

    if results.get("multi_homing", {}).get("redundancy_level") == "none":
        issues.append("Single point of failure: no network redundancy detected")
        recommendations.append("Consider multi-homing with multiple providers for redundancy")

    geo_dist = results.get("geographic_distribution", {})
    if geo_dist.get("countries") and len(geo_dist["countries"]) == 1:
        recommendations.append("All infrastructure in single country - consider geographic distribution")

    # Check for CDN usage
    cdn_providers = [p for p in results.get("hosting_providers", []) if p.get("is_cdn")]
    if not cdn_providers and assessment["infrastructure_type"] != "cdn":
        recommendations.append("Consider using a CDN for improved performance and DDoS protection")

    assessment["issues"] = issues
    assessment["recommendations"] = recommendations


def _generate_findings(results: dict[str, Any]) -> None:
    """Generate security findings from ASN discovery."""
    findings = []
    domain = results["domain"]

    # Finding: No redundancy
    multi_homing = results.get("multi_homing", {})
    if multi_homing.get("redundancy_level") == "none":
        findings.append({
            "id": f"asn_discovery:{hashlib.md5(f'no_redundancy_{domain}'.encode()).hexdigest()[:8]}",
            "tool": "asn_discovery",
            "title": "No Network Redundancy Detected",
            "severity": "low",
            "cvss_score": 2.5,
            "cwe": "CWE-693",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": (
                f"Domain {domain} resolves to IPs in a single ASN with no multi-homing. "
                "This creates a single point of failure if the provider experiences issues."
            ),
            "evidence": {
                "domain": domain,
                "unique_asns": multi_homing.get("unique_asns", []),
                "ip_count": len(multi_homing.get("asn_details", []))
            },
            "remediation": "Consider using multiple providers or a multi-homed architecture for redundancy."
        })

    # Finding: Shared hosting detected
    providers = results.get("hosting_providers", [])
    for provider in providers:
        if provider.get("type") == "hosting":
            findings.append({
                "id": f"asn_discovery:{hashlib.md5(f'shared_hosting_{domain}'.encode()).hexdigest()[:8]}",
                "tool": "asn_discovery",
                "title": f"Shared Hosting Detected: {provider.get('provider', 'Unknown')}",
                "severity": "info",
                "cvss_score": 0,
                "cwe": "CWE-1188",
                "owasp": "A05:2021 - Security Misconfiguration",
                "description": (
                    f"Domain is hosted on shared hosting provider {provider.get('provider')}. "
                    "Shared hosting may have security implications from co-tenants."
                ),
                "evidence": {
                    "domain": domain,
                    "provider": provider.get("provider"),
                    "provider_type": provider.get("type")
                },
                "remediation": "Ensure hosting provider has proper tenant isolation. Consider dedicated hosting for sensitive applications."
            })
            break  # Only report once

    # Finding: Single geographic location
    geo_dist = results.get("geographic_distribution", {})
    countries = geo_dist.get("countries", {})
    if len(countries) == 1:
        country_code = list(countries.keys())[0]
        country_name = COUNTRY_NAMES.get(country_code, country_code)
        findings.append({
            "id": f"asn_discovery:{hashlib.md5(f'single_geo_{domain}'.encode()).hexdigest()[:8]}",
            "tool": "asn_discovery",
            "title": f"Infrastructure Concentrated in {country_name}",
            "severity": "info",
            "cvss_score": 0,
            "cwe": "CWE-693",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": (
                f"All resolved IP addresses are located in {country_name}. "
                "Geographic concentration may impact availability for global users."
            ),
            "evidence": {
                "domain": domain,
                "country": country_code,
                "country_name": country_name
            },
            "remediation": "Consider geographic distribution using CDN or multi-region deployment for global availability."
        })

    # Finding: Cloud provider identified (informational)
    cloud_providers = [p for p in providers if p.get("is_cloud")]
    if cloud_providers:
        provider_name = cloud_providers[0].get("provider", "Unknown")
        findings.append({
            "id": f"asn_discovery:{hashlib.md5(f'cloud_provider_{domain}'.encode()).hexdigest()[:8]}",
            "tool": "asn_discovery",
            "title": f"Cloud Infrastructure: {provider_name}",
            "severity": "info",
            "cvss_score": 0,
            "cwe": "CWE-1188",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": f"Domain is hosted on {provider_name} cloud infrastructure.",
            "evidence": {
                "domain": domain,
                "provider": provider_name,
                "asn_count": len(results.get("asn_info", []))
            },
            "remediation": "Ensure cloud security best practices are followed for the platform."
        })

    results["findings"] = findings
