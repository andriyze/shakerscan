#!/usr/bin/env python3
"""
Enhanced Subdomain Discovery Module

Combines multiple sources for comprehensive subdomain enumeration:

1. **Gungnir** (CT logs - ALL logs)
   - Pulls from RFC logs and static CT API logs
   - More comprehensive than crt.sh (includes self-signed, outdated, non-standard certs)
   - Recommended by @Jhaddix as "2025 hacker tool Grammy for best horizontal recon tool"

2. **Subfinder** (Multiple passive sources)
   - crt.sh, hackertarget, anubis, urlscan, waybackarchive
   - Good coverage from multiple data sources

3. **CT Monitor** (crt.sh direct query)
   - Fast fallback for certificate transparency data
   - Provides additional certificate metadata

The module runs sources in parallel and deduplicates results for maximum coverage.

OWASP Mapping:
- A05:2021 - Security Misconfiguration (forgotten subdomains, shadow IT)
- A06:2021 - Vulnerable and Outdated Components (legacy subdomains)

CWE Mapping:
- CWE-200: Exposure of Sensitive Information
- CWE-284: Improper Access Control (exposed internal services)
"""

import asyncio
from typing import Any, Callable

# Import source modules
from .gungnir import gungnir_scan, check_gungnir_available
from .subfinder import subfinder_scan
from .ct_monitor import check_certificate_transparency


async def discover_subdomains(
    domain: str,
    use_gungnir: bool = True,
    use_subfinder: bool = True,
    use_crtsh: bool = True,
    gungnir_timeout: int = 30,
    subfinder_timeout: int = 120,
    crtsh_timeout: int = 30,
    callback: Callable[[str, str], None] | None = None,
) -> dict[str, Any]:
    """
    Comprehensive subdomain discovery using multiple CT and passive sources.

    This function combines:
    - Gungnir: Real-time CT log scanner (ALL logs)
    - Subfinder: Multi-source passive enumeration
    - crt.sh: Certificate Transparency database query

    Args:
        domain: Target domain (e.g., "example.com")
        use_gungnir: Enable Gungnir CT log scanning (recommended)
        use_subfinder: Enable Subfinder passive enumeration
        use_crtsh: Enable crt.sh query via CT monitor
        gungnir_timeout: Timeout for Gungnir (streaming tool)
        subfinder_timeout: Timeout for Subfinder
        crtsh_timeout: Timeout for crt.sh query
        callback: Optional callback(subdomain, source) for each discovery

    Returns:
        {
            "domain": "example.com",
            "subdomains": ["api.example.com", "www.example.com", ...],
            "count": int,
            "by_source": {
                "gungnir": {"subdomains": [...], "count": int, "unique": int},
                "subfinder": {"subdomains": [...], "count": int, "unique": int},
                "crtsh": {"subdomains": [...], "count": int, "unique": int}
            },
            "source_stats": {
                "gungnir_exclusive": int,  # Found only by Gungnir
                "subfinder_exclusive": int,
                "crtsh_exclusive": int,
                "overlap": int  # Found by multiple sources
            },
            "recommendations": [...],
            "error": str or None
        }
    """
    result: dict[str, Any] = {
        "domain": domain,
        "subdomains": [],
        "count": 0,
        "by_source": {},
        "source_stats": {},
        "recommendations": [],
        "error": None,
    }

    # Track subdomains by source
    all_subdomains: set[str] = set()
    source_subdomains: dict[str, set[str]] = {
        "gungnir": set(),
        "subfinder": set(),
        "crtsh": set(),
    }

    # Create tasks for each enabled source
    tasks = []

    if use_gungnir:
        # Check if Gungnir is available
        gungnir_available = await check_gungnir_available()
        if gungnir_available:
            tasks.append(("gungnir", gungnir_scan(domain, timeout=gungnir_timeout)))
        else:
            result["by_source"]["gungnir"] = {
                "subdomains": [],
                "count": 0,
                "unique": 0,
                "error": "Gungnir binary not available"
            }

    if use_subfinder:
        tasks.append(("subfinder", subfinder_scan(domain)))

    if use_crtsh:
        tasks.append(("crtsh", check_certificate_transparency(
            domain,
            timeout=crtsh_timeout,
            include_subdomains=True,
            safe_mode=True
        )))

    if not tasks:
        result["error"] = "No subdomain discovery sources enabled"
        return result

    # Run all sources in parallel
    task_results = await asyncio.gather(
        *[t[1] for t in tasks],
        return_exceptions=True
    )

    # Process results from each source
    for i, (source_name, _) in enumerate(tasks):
        source_result = task_results[i]

        if isinstance(source_result, Exception):
            result["by_source"][source_name] = {
                "subdomains": [],
                "count": 0,
                "unique": 0,
                "error": str(source_result)
            }
            continue

        # Extract subdomains based on source format
        subdomains = []
        error = None

        if source_name == "gungnir":
            subdomains = source_result.get("subdomains", [])
            error = source_result.get("error")

        elif source_name == "subfinder":
            subdomains = source_result.get("subdomains", [])
            error = source_result.get("error")

        elif source_name == "crtsh":
            # CT monitor has subdomain_discovery nested
            sd = source_result.get("subdomain_discovery", {})
            subdomains = sd.get("subdomains", [])
            if source_result.get("error"):
                error = source_result.get("error")

        # Normalize and store
        normalized = set()
        for sub in subdomains:
            if sub:
                s = sub.lower().strip().replace("*.", "")
                if s and s.endswith(domain.lower()) and s != domain.lower():
                    normalized.add(s)
                    all_subdomains.add(s)
                    if callback:
                        try:
                            callback(s, source_name)
                        except Exception:
                            pass

        source_subdomains[source_name] = normalized

        result["by_source"][source_name] = {
            "subdomains": sorted(list(normalized))[:100],  # Limit per source
            "count": len(normalized),
            "unique": 0,  # Will be calculated below
            "error": error
        }

    # Calculate unique counts (subdomains found only by that source)
    for source in source_subdomains:
        if source not in result["by_source"]:
            continue
        other_sources = [s for s in source_subdomains if s != source]
        other_subdomains = set()
        for other in other_sources:
            other_subdomains.update(source_subdomains[other])

        unique_to_source = source_subdomains[source] - other_subdomains
        result["by_source"][source]["unique"] = len(unique_to_source)

    # Calculate source stats
    gungnir_only = source_subdomains["gungnir"] - source_subdomains["subfinder"] - source_subdomains["crtsh"]
    subfinder_only = source_subdomains["subfinder"] - source_subdomains["gungnir"] - source_subdomains["crtsh"]
    crtsh_only = source_subdomains["crtsh"] - source_subdomains["gungnir"] - source_subdomains["subfinder"]

    # Overlap: found by at least 2 sources
    overlap = (
        (source_subdomains["gungnir"] & source_subdomains["subfinder"]) |
        (source_subdomains["gungnir"] & source_subdomains["crtsh"]) |
        (source_subdomains["subfinder"] & source_subdomains["crtsh"])
    )

    result["source_stats"] = {
        "gungnir_exclusive": len(gungnir_only),
        "subfinder_exclusive": len(subfinder_only),
        "crtsh_exclusive": len(crtsh_only),
        "overlap": len(overlap),
        "total_unique": len(all_subdomains),
    }

    # Set final results
    result["subdomains"] = sorted(list(all_subdomains))
    result["count"] = len(all_subdomains)

    # Generate recommendations
    recommendations = []

    if len(gungnir_only) > 0:
        recommendations.append(
            f"Gungnir found {len(gungnir_only)} subdomains not in other sources. "
            "These may include certificates from less-monitored CT logs."
        )

    if result["count"] > 50:
        recommendations.append(
            f"Large attack surface detected ({result['count']} subdomains). "
            "Review for forgotten/legacy services."
        )

    if result["count"] == 0:
        recommendations.append(
            "No subdomains discovered. Domain may not use HTTPS or "
            "certificates may not be logged to CT."
        )

    if not recommendations:
        recommendations.append(
            f"Discovered {result['count']} subdomains across {len([s for s in result['by_source'] if result['by_source'][s].get('count', 0) > 0])} sources."
        )

    result["recommendations"] = recommendations

    return result


async def quick_subdomain_scan(domain: str, timeout: int = 60) -> list[str]:
    """
    Quick subdomain scan using Gungnir only.

    For fast enumeration when time is limited. Falls back to subfinder
    if Gungnir is unavailable.

    Args:
        domain: Target domain
        timeout: Total timeout

    Returns:
        List of discovered subdomains
    """
    # Try Gungnir first
    if await check_gungnir_available():
        result = await gungnir_scan(domain, timeout=timeout)
        if result.get("subdomains"):
            return result["subdomains"]

    # Fallback to subfinder
    result = await subfinder_scan(domain)
    return result.get("subdomains", [])


async def comprehensive_subdomain_scan(
    domain: str,
    include_expired_certs: bool = False,
) -> dict[str, Any]:
    """
    Comprehensive subdomain scan with all sources and extended timeouts.

    For thorough enumeration when completeness is more important than speed.

    Args:
        domain: Target domain
        include_expired_certs: Include expired certificates (more results, less relevant)

    Returns:
        Full discovery results with all sources
    """
    return await discover_subdomains(
        domain,
        use_gungnir=True,
        use_subfinder=True,
        use_crtsh=True,
        gungnir_timeout=90,
        subfinder_timeout=180,
        crtsh_timeout=60,
    )
