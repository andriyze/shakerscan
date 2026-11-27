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

import os
import tempfile
from typing import Any

from .common import run
from .discovered_names import subdomain_of


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
                            for name in (cert_data.get("common_name"), *(cert_data.get("sans") or ())):
                                accepted = subdomain_of(name, domain)
                                if accepted:
                                    subdomains.add(accepted)
                        except Exception:
                            # Not valid JSON, treat as plain domain
                            accepted = subdomain_of(line, domain)
                            if accepted:
                                subdomains.add(accepted)
                    else:
                        # Plain text output - each line is a domain
                        accepted = subdomain_of(line, domain)
                        if accepted:
                            subdomains.add(accepted)

            result["subdomains"] = sorted(list(subdomains))
            result["count"] = len(result["subdomains"])

        finally:
            # Clean up temp file
            try:
                os.unlink(roots_file)
            except Exception:
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
    except Exception:
        return False
