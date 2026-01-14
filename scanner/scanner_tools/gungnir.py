#!/usr/bin/env python3
"""
Gungnir CT Log Scanner Integration

Gungnir is a Certificate Transparency log scanner that pulls from ALL logs:
- RFC logs (original CT log format)
- Static CT API logs

This is superior to crt.sh which omits:
- Self-signed certificates
- Outdated certificates
- Non-standard certificates

As noted by @Jhaddix: "crt.sh is the least good source" for CT data because
it does not pull from all available logs. Gungnir provides more comprehensive
coverage for subdomain discovery via certificate transparency.

Tool: https://github.com/g0ldencybersec/gungnir
Author: @G0LDEN_infosec

OWASP Mapping:
- A05:2021 - Security Misconfiguration (asset discovery)

CWE Mapping:
- CWE-200: Exposure of Sensitive Information (certificate disclosure)
"""

import asyncio
import os
import tempfile
from typing import Any

from .common import run


GUNGNIR_BIN = "/opt/tools/gungnir"


async def gungnir_scan(
    domain: str,
    timeout: int = 60,
    json_output: bool = False,
) -> dict[str, Any]:
    """
    Run Gungnir to discover subdomains via Certificate Transparency logs.

    Gungnir monitors ALL CT logs (RFC + static CT API) providing more
    comprehensive coverage than crt.sh which omits self-signed, outdated,
    and non-standard certificates.

    Args:
        domain: Root domain to scan (e.g., "example.com")
        timeout: Timeout in seconds (Gungnir is a streaming tool)
        json_output: If True, request JSONL output with certificate details

    Returns:
        {
            "subdomains": ["api.example.com", "www.example.com", ...],
            "count": int,
            "source": "gungnir",
            "certificates": [...] if json_output else None,
            "error": str or None
        }
    """
    result: dict[str, Any] = {
        "subdomains": [],
        "count": 0,
        "source": "gungnir",
        "certificates": None,
        "error": None,
    }

    # Check if gungnir binary exists
    if not os.path.isfile(GUNGNIR_BIN):
        result["error"] = f"Gungnir binary not found at {GUNGNIR_BIN}"
        return result

    try:
        # Create temp file with root domain for filtering
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(domain + "\n")
            roots_file = f.name

        try:
            # Build command
            # -r: filter by root domains file
            # -j: JSON output (optional)
            cmd = [GUNGNIR_BIN, "-r", roots_file]
            if json_output:
                cmd.append("-j")

            # Run gungnir with timeout
            # Note: Gungnir is a streaming tool that monitors CT logs in real-time
            # We run it for a limited time to collect discovered subdomains
            stdout, stderr, rc = await run(cmd, timeout=timeout)

            if rc == 124:
                # Timeout is expected for streaming tools - we still have partial results
                pass
            elif rc != 0 and not stdout.strip():
                # Only treat as error if we got no output
                if stderr:
                    result["error"] = stderr.strip()
                return result

            # Parse output
            subdomains: set[str] = set()

            if stdout.strip():
                for line in stdout.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    if json_output:
                        # JSONL format - each line is a JSON object
                        try:
                            import json
                            cert_data = json.loads(line)
                            # Extract domains from certificate
                            if result["certificates"] is None:
                                result["certificates"] = []
                            result["certificates"].append(cert_data)

                            # Get domains from CN and SANs
                            if "common_name" in cert_data:
                                cn = cert_data["common_name"].lower()
                                if cn.endswith(domain.lower()) and cn != domain.lower():
                                    subdomains.add(cn.replace("*.", ""))

                            for san in cert_data.get("sans", []):
                                san = san.lower()
                                if san.endswith(domain.lower()) and san != domain.lower():
                                    subdomains.add(san.replace("*.", ""))
                        except:
                            # Not valid JSON, treat as plain domain
                            if line.endswith(domain.lower()) and line != domain.lower():
                                subdomains.add(line.replace("*.", ""))
                    else:
                        # Plain text output - each line is a domain
                        subdomain = line.lower().replace("*.", "")
                        if subdomain.endswith(domain.lower()) and subdomain != domain.lower():
                            subdomains.add(subdomain)

            result["subdomains"] = sorted(list(subdomains))
            result["count"] = len(result["subdomains"])

        finally:
            # Clean up temp file
            try:
                os.unlink(roots_file)
            except:
                pass

    except Exception as e:
        result["error"] = str(e)

    return result


async def gungnir_monitor(
    domains: list[str],
    duration: int = 300,
    callback: callable = None,
) -> dict[str, Any]:
    """
    Monitor CT logs for new certificates for multiple domains.

    This is useful for continuous monitoring of certificate issuance.
    The callback function is called for each new domain discovered.

    Args:
        domains: List of root domains to monitor
        duration: How long to monitor in seconds (default 5 minutes)
        callback: Optional async callback(domain: str) for each discovery

    Returns:
        {
            "domains_monitored": ["example.com", ...],
            "discoveries": {"example.com": ["api.example.com", ...], ...},
            "total_discovered": int,
            "duration": int,
            "error": str or None
        }
    """
    result: dict[str, Any] = {
        "domains_monitored": domains,
        "discoveries": {d: [] for d in domains},
        "total_discovered": 0,
        "duration": duration,
        "error": None,
    }

    if not os.path.isfile(GUNGNIR_BIN):
        result["error"] = f"Gungnir binary not found at {GUNGNIR_BIN}"
        return result

    try:
        # Create temp file with all root domains
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for domain in domains:
                f.write(domain + "\n")
            roots_file = f.name

        try:
            cmd = [GUNGNIR_BIN, "-r", roots_file]

            # Run with streaming output collection
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            seen: set[str] = set()

            async def read_output():
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    subdomain = line.decode().strip().lower().replace("*.", "")
                    if subdomain and subdomain not in seen:
                        seen.add(subdomain)
                        # Find which root domain this belongs to
                        for domain in domains:
                            if subdomain.endswith(domain.lower()):
                                if subdomain != domain.lower():
                                    result["discoveries"][domain].append(subdomain)
                                    result["total_discovered"] += 1
                                    if callback:
                                        await callback(subdomain)
                                break

            # Run for specified duration
            try:
                await asyncio.wait_for(read_output(), timeout=duration)
            except asyncio.TimeoutError:
                pass  # Expected - we're limiting duration

            proc.kill()
            await proc.wait()

        finally:
            try:
                os.unlink(roots_file)
            except:
                pass

    except Exception as e:
        result["error"] = str(e)

    return result


async def check_gungnir_available() -> bool:
    """Check if Gungnir binary is available and working."""
    if not os.path.isfile(GUNGNIR_BIN):
        return False

    try:
        stdout, stderr, rc = await run([GUNGNIR_BIN, "-h"], timeout=5)
        return rc == 0 or "gungnir" in stdout.lower() or "gungnir" in stderr.lower()
    except:
        return False
