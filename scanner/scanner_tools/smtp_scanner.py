"""
SMTP Security Scanner Module

Comprehensive email server security testing including:
- STARTTLS verification and cipher analysis
- Open relay testing (safe mode)
- SMTP banner analysis for version disclosure
- MX record redundancy and priority analysis
- TLS configuration on ports 25/587/465

Uses free tools only: openssl, nmap, dig
"""

import asyncio
import hashlib
import re
from datetime import UTC, datetime
from typing import Any

# ============================================================================
# CONSTANTS
# ============================================================================

# Standard SMTP ports
SMTP_PORTS = {
    25: "SMTP (standard)",
    465: "SMTPS (implicit TLS)",
    587: "SMTP Submission (STARTTLS)"
}

# Known vulnerable SMTP versions
VULNERABLE_VERSIONS = {
    "Postfix": {
        "2.": "Postfix 2.x may have known vulnerabilities - recommend upgrade to 3.x",
        "3.0": "Postfix 3.0 - consider upgrading to latest 3.x",
        "3.1": "Postfix 3.1 - consider upgrading to latest 3.x",
    },
    "Exim": {
        "4.8": "Exim 4.8x has critical CVEs (CVE-2019-15846, CVE-2019-16928)",
        "4.9.0": "Exim 4.9.0 vulnerable to CVE-2019-15846",
        "4.9.1": "Exim 4.9.1 has known vulnerabilities",
    },
    "Sendmail": {
        "8.14": "Sendmail 8.14 - end of life, multiple CVEs",
        "8.15.1": "Sendmail 8.15.1 vulnerable to CVE-2014-3956",
    },
    "Microsoft": {
        "Exchange Server 2010": "Exchange 2010 end of life - critical vulnerabilities",
        "Exchange Server 2013": "Exchange 2013 extended support ending",
    },
    "qmail": {
        "1.0": "qmail 1.03 - legacy version with known issues",
    }
}

# Weak ciphers to flag
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "anon",
    "RC2", "IDEA", "SEED", "CAMELLIA128"
]

# Strong ciphers (for positive reporting)
STRONG_CIPHERS = [
    "AES256-GCM", "AES128-GCM", "CHACHA20", "ECDHE", "DHE"
]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

async def _run_command(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a command asynchronously with timeout."""
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
        try:
            proc.kill()
        except:
            pass
        return "", "Command timed out", -1
    except Exception as e:
        return "", str(e), -1


def _parse_mx_records(dig_output: str) -> list[dict[str, Any]]:
    """Parse MX records from dig output."""
    mx_records = []
    for line in dig_output.split('\n'):
        line = line.strip()
        if not line or line.startswith(';'):
            continue
        # Match MX record format: domain. TTL IN MX priority host.
        match = re.search(r'MX\s+(\d+)\s+(\S+)', line)
        if match:
            priority = int(match.group(1))
            host = match.group(2).rstrip('.')
            mx_records.append({
                "priority": priority,
                "host": host
            })
    return sorted(mx_records, key=lambda x: x["priority"])


def _analyze_banner(banner: str) -> dict[str, Any]:
    """Analyze SMTP banner for security issues."""
    analysis = {
        "raw_banner": banner,
        "software": None,
        "version": None,
        "hostname_disclosed": False,
        "version_disclosed": False,
        "vulnerabilities": [],
        "recommendations": []
    }

    if not banner:
        return analysis

    # Extract software and version
    patterns = [
        # Postfix
        (r'Postfix', r'Postfix(?:\s+\(([^)]+)\))?', 'Postfix'),
        # Exim
        (r'Exim', r'Exim\s+([\d.]+)', 'Exim'),
        # Sendmail
        (r'Sendmail', r'Sendmail[/\s]+([\d.]+)', 'Sendmail'),
        # Microsoft Exchange
        (r'Microsoft', r'Microsoft\s+(ESMTP\s+MAIL|Exchange[^;]*)', 'Microsoft'),
        # qmail
        (r'qmail', r'qmail', 'qmail'),
        # Haraka
        (r'Haraka', r'Haraka\s*([\d.]*)', 'Haraka'),
        # OpenSMTPD
        (r'OpenSMTPD', r'OpenSMTPD', 'OpenSMTPD'),
        # Zimbra
        (r'Zimbra', r'Zimbra\s*([\d.]*)', 'Zimbra'),
    ]

    for detect_pattern, version_pattern, name in patterns:
        if re.search(detect_pattern, banner, re.I):
            analysis["software"] = name
            version_match = re.search(version_pattern, banner, re.I)
            if version_match and version_match.groups():
                analysis["version"] = version_match.group(1)
                analysis["version_disclosed"] = True
            break

    # Check for hostname disclosure
    hostname_patterns = [
        r'220\s+(\S+\.\S+)',  # FQDN after 220
        r'ESMTP\s+(\S+\.\S+)',  # FQDN after ESMTP
    ]
    for pattern in hostname_patterns:
        match = re.search(pattern, banner)
        if match:
            hostname = match.group(1)
            if '.' in hostname and not hostname.startswith('220'):
                analysis["hostname_disclosed"] = True
                break

    # Check for known vulnerabilities
    if analysis["software"] and analysis["software"] in VULNERABLE_VERSIONS:
        version_vulns = VULNERABLE_VERSIONS[analysis["software"]]
        for vuln_version, description in version_vulns.items():
            if analysis["version"] and analysis["version"].startswith(vuln_version):
                analysis["vulnerabilities"].append(description)

    # Generate recommendations
    if analysis["version_disclosed"]:
        analysis["recommendations"].append(
            "Consider hiding software version in SMTP banner to reduce attack surface"
        )
    if analysis["hostname_disclosed"]:
        analysis["recommendations"].append(
            "Internal hostname disclosed in banner - consider using generic greeting"
        )

    return analysis


def _assess_cipher_strength(ciphers: list[str]) -> dict[str, Any]:
    """Assess the strength of offered ciphers."""
    assessment = {
        "total_ciphers": len(ciphers),
        "weak_ciphers": [],
        "strong_ciphers": [],
        "grade": "A",
        "issues": []
    }

    for cipher in ciphers:
        cipher_upper = cipher.upper()

        # Check for weak ciphers
        is_weak = False
        for weak in WEAK_CIPHERS:
            if weak.upper() in cipher_upper:
                assessment["weak_ciphers"].append(cipher)
                is_weak = True
                break

        # Check for strong ciphers
        if not is_weak:
            for strong in STRONG_CIPHERS:
                if strong.upper() in cipher_upper:
                    assessment["strong_ciphers"].append(cipher)
                    break

    # Grade calculation
    weak_count = len(assessment["weak_ciphers"])
    strong_count = len(assessment["strong_ciphers"])

    if weak_count > 0:
        if "NULL" in str(assessment["weak_ciphers"]).upper():
            assessment["grade"] = "F"
            assessment["issues"].append("NULL cipher supported - critical vulnerability")
        elif "EXPORT" in str(assessment["weak_ciphers"]).upper():
            assessment["grade"] = "F"
            assessment["issues"].append("EXPORT cipher supported - FREAK vulnerability")
        elif "RC4" in str(assessment["weak_ciphers"]).upper():
            assessment["grade"] = "C"
            assessment["issues"].append("RC4 cipher supported - known weaknesses")
        elif "3DES" in str(assessment["weak_ciphers"]).upper():
            assessment["grade"] = "B"
            assessment["issues"].append("3DES cipher supported - SWEET32 vulnerability")
        else:
            assessment["grade"] = "B"
            assessment["issues"].append(f"{weak_count} weak cipher(s) supported")

    if strong_count == 0 and assessment["total_ciphers"] > 0:
        if assessment["grade"] == "A":
            assessment["grade"] = "B"
        assessment["issues"].append("No modern AEAD ciphers (GCM/CHACHA20) supported")

    return assessment


# ============================================================================
# STARTTLS TESTING
# ============================================================================

async def _test_starttls(host: str, port: int, timeout: int = 15) -> dict[str, Any]:
    """Test STARTTLS support and configuration on a specific port."""
    result = {
        "port": port,
        "port_description": SMTP_PORTS.get(port, "Unknown"),
        "reachable": False,
        "starttls_supported": False,
        "tls_version": None,
        "cipher": None,
        "certificate": None,
        "ciphers_offered": [],
        "issues": [],
        "error": None
    }

    # For port 465 (SMTPS), TLS is implicit
    if port == 465:
        cmd = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-servername", host,
            "-brief"
        ]
    else:
        # For ports 25 and 587, use STARTTLS
        cmd = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-servername", host,
            "-starttls", "smtp",
            "-brief"
        ]

    stdout, stderr, returncode = await _run_command(cmd, timeout)
    combined = stdout + stderr

    if returncode == 0 or "CONNECTION ESTABLISHED" in combined.upper():
        result["reachable"] = True
        result["starttls_supported"] = True

        # Extract TLS version
        tls_match = re.search(r'Protocol\s*:\s*(TLS[v\d.]+|SSLv[\d.]+)', combined, re.I)
        if tls_match:
            result["tls_version"] = tls_match.group(1)

        # Extract cipher
        cipher_match = re.search(r'Cipher\s*:\s*(\S+)', combined, re.I)
        if cipher_match:
            result["cipher"] = cipher_match.group(1)

        # Check for issues
        if result["tls_version"]:
            if "SSLv" in result["tls_version"] or result["tls_version"] in ["TLSv1", "TLSv1.0", "TLSv1.1"]:
                result["issues"].append(f"Outdated protocol: {result['tls_version']}")

    elif "Connection refused" in combined or returncode == -1:
        result["error"] = "Connection refused or timed out"
    else:
        result["reachable"] = True
        result["starttls_supported"] = False
        result["issues"].append("STARTTLS not supported - emails transmitted in plaintext")

    # Get cipher list if TLS is supported
    if result["starttls_supported"]:
        cipher_cmd = [
            "nmap", "-Pn", "--host-timeout", "120s", "--script", "ssl-enum-ciphers",
            "-p", str(port), host
        ]
        cipher_stdout, _, _ = await _run_command(cipher_cmd, timeout + 10)

        # Parse cipher output
        cipher_lines = re.findall(r'(TLS_\S+|SSL_\S+)', cipher_stdout)
        result["ciphers_offered"] = list(set(cipher_lines))[:20]  # Limit to 20

    return result


# ============================================================================
# OPEN RELAY TESTING (SAFE MODE)
# ============================================================================

async def _test_open_relay_safe(host: str, port: int = 25, timeout: int = 15) -> dict[str, Any]:
    """
    Test for open relay vulnerability using SAFE methods only.

    This does NOT actually send email - it only tests SMTP responses
    to RCPT TO commands with external addresses.
    """
    result = {
        "tested": False,
        "potentially_vulnerable": False,
        "responses": [],
        "risk_level": "info",
        "recommendation": None
    }

    try:
        # Create socket connection
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )

        # Read banner
        banner = await asyncio.wait_for(reader.readline(), timeout=5)
        banner_text = banner.decode('utf-8', errors='replace').strip()
        result["responses"].append(f"Banner: {banner_text}")

        # Send EHLO
        writer.write(b"EHLO relay-test.local\r\n")
        await writer.drain()

        # Read EHLO response (may be multiple lines)
        ehlo_response = ""
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            line_text = line.decode('utf-8', errors='replace').strip()
            ehlo_response += line_text + "\n"
            if line_text[:3].isdigit() and line_text[3:4] == ' ':
                break

        result["responses"].append(f"EHLO response: {ehlo_response.strip()[:200]}")

        # Send MAIL FROM with external address
        writer.write(b"MAIL FROM:<test@external-domain.test>\r\n")
        await writer.drain()
        mail_response = await asyncio.wait_for(reader.readline(), timeout=5)
        mail_text = mail_response.decode('utf-8', errors='replace').strip()
        result["responses"].append(f"MAIL FROM: {mail_text}")

        # If MAIL FROM accepted, try RCPT TO with external address
        if mail_text.startswith("250"):
            writer.write(b"RCPT TO:<test@another-external.test>\r\n")
            await writer.drain()
            rcpt_response = await asyncio.wait_for(reader.readline(), timeout=5)
            rcpt_text = rcpt_response.decode('utf-8', errors='replace').strip()
            result["responses"].append(f"RCPT TO: {rcpt_text}")

            # Check if relay was accepted
            if rcpt_text.startswith("250") or rcpt_text.startswith("251"):
                result["potentially_vulnerable"] = True
                result["risk_level"] = "critical"
                result["recommendation"] = (
                    "SMTP server may be an open relay - accepts mail from external "
                    "sender to external recipient. Configure authentication requirements."
                )
            elif rcpt_text.startswith("550") or rcpt_text.startswith("553") or rcpt_text.startswith("554"):
                result["risk_level"] = "info"
                result["recommendation"] = "Relay correctly rejected - server properly configured"
            elif rcpt_text.startswith("450") or rcpt_text.startswith("451"):
                result["risk_level"] = "low"
                result["recommendation"] = "Relay deferred - may require authentication"

        # Send QUIT
        writer.write(b"QUIT\r\n")
        await writer.drain()

        writer.close()
        await writer.wait_closed()

        result["tested"] = True

    except TimeoutError:
        result["responses"].append("Connection timed out")
    except ConnectionRefusedError:
        result["responses"].append("Connection refused")
    except Exception as e:
        result["responses"].append(f"Error: {e!s}")

    return result


# ============================================================================
# MX ANALYSIS
# ============================================================================

async def _analyze_mx_records(domain: str, timeout: int = 15) -> dict[str, Any]:
    """Analyze MX record configuration for security and redundancy."""
    result = {
        "domain": domain,
        "mx_records": [],
        "mx_count": 0,
        "has_redundancy": False,
        "priority_spread": 0,
        "issues": [],
        "recommendations": [],
        "risk_level": "info"
    }

    # Query MX records
    cmd = ["dig", "+short", "MX", domain]
    stdout, stderr, returncode = await _run_command(cmd, timeout)

    if returncode != 0 or not stdout.strip():
        result["issues"].append("No MX records found")
        result["risk_level"] = "medium"
        result["recommendations"].append(
            "No MX records configured - email may fall back to A record or fail"
        )
        return result

    # Parse MX records
    for line in stdout.strip().split('\n'):
        parts = line.split()
        if len(parts) >= 2:
            try:
                priority = int(parts[0])
                host = parts[1].rstrip('.')
                result["mx_records"].append({
                    "priority": priority,
                    "host": host
                })
            except ValueError:
                continue

    result["mx_records"].sort(key=lambda x: x["priority"])
    result["mx_count"] = len(result["mx_records"])

    # Analyze redundancy
    if result["mx_count"] >= 2:
        result["has_redundancy"] = True
        priorities = [mx["priority"] for mx in result["mx_records"]]
        result["priority_spread"] = max(priorities) - min(priorities)
    else:
        result["issues"].append("Single MX record - no redundancy")
        result["risk_level"] = "low"
        result["recommendations"].append(
            "Consider adding backup MX server for redundancy"
        )

    # Check for same priority (load balancing)
    priorities = [mx["priority"] for mx in result["mx_records"]]
    if len(priorities) > 1 and len(set(priorities)) == 1:
        result["recommendations"].append(
            "All MX records have same priority - using round-robin load balancing"
        )

    # Check for common mail providers
    hosts_lower = [mx["host"].lower() for mx in result["mx_records"]]
    providers = {
        "google": ["google.com", "googlemail.com", "gmail-smtp"],
        "microsoft": ["outlook.com", "protection.outlook.com", "mail.protection"],
        "proofpoint": ["pphosted.com", "proofpoint"],
        "mimecast": ["mimecast.com"],
        "barracuda": ["barracudanetworks.com"],
    }

    detected_providers = []
    for provider, patterns in providers.items():
        for host in hosts_lower:
            if any(p in host for p in patterns):
                detected_providers.append(provider)
                break

    if detected_providers:
        result["mail_providers"] = detected_providers

    return result


# ============================================================================
# COMPREHENSIVE SMTP PORT SCAN
# ============================================================================

async def _scan_smtp_ports(host: str, timeout: int = 30) -> dict[str, Any]:
    """Scan all SMTP ports and assess overall configuration."""
    result = {
        "host": host,
        "ports_tested": list(SMTP_PORTS.keys()),
        "open_ports": [],
        "tls_results": {},
        "overall_grade": "A",
        "issues": [],
        "recommendations": []
    }

    # Test each port concurrently
    tasks = []
    for port in SMTP_PORTS:
        tasks.append(_test_starttls(host, port, timeout))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for port, port_result in zip(SMTP_PORTS.keys(), results, strict=False):
        if isinstance(port_result, Exception):
            result["tls_results"][port] = {"error": str(port_result)}
            continue

        result["tls_results"][port] = port_result

        if port_result.get("reachable"):
            result["open_ports"].append(port)

            # Collect issues
            if port_result.get("issues"):
                for issue in port_result["issues"]:
                    result["issues"].append(f"Port {port}: {issue}")

    # Grade calculation
    if not result["open_ports"]:
        result["overall_grade"] = "N/A"
        result["recommendations"].append("No SMTP ports reachable")
    else:
        # Check for critical issues
        has_starttls = any(
            result["tls_results"].get(p, {}).get("starttls_supported")
            for p in [25, 587]
        )
        has_implicit_tls = result["tls_results"].get(465, {}).get("starttls_supported")

        if not has_starttls and not has_implicit_tls:
            result["overall_grade"] = "F"
            result["issues"].append("No TLS support on any SMTP port")
        elif 25 in result["open_ports"]:
            port_25_result = result["tls_results"].get(25, {})
            if not port_25_result.get("starttls_supported"):
                result["overall_grade"] = "D"
                result["issues"].append("Port 25 open without STARTTLS - MitM possible")

        # Check for outdated protocols
        for port, port_result in result["tls_results"].items():
            tls_version = port_result.get("tls_version", "")
            if tls_version and ("SSLv" in tls_version or tls_version in ["TLSv1", "TLSv1.0"]):
                if result["overall_grade"] in ["A", "B"]:
                    result["overall_grade"] = "C"

    return result


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

async def check_smtp_security(
    domain: str,
    timeout: int = 30,
    test_relay: bool = True,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Comprehensive SMTP security assessment.

    Args:
        domain: Domain to test (will resolve MX records)
        timeout: Timeout for each test in seconds
        test_relay: Whether to test for open relay
        safe_mode: If True, only use non-intrusive tests

    Returns:
        Dict with SMTP security analysis
    """
    results = {
        "domain": domain,
        "scan_timestamp": datetime.now(UTC).isoformat(),
        "mx_analysis": None,
        "smtp_hosts": {},
        "banner_analysis": {},
        "relay_tests": {},
        "overall_assessment": {
            "grade": "A",
            "risk_level": "info",
            "issues": [],
            "recommendations": []
        },
        "findings": []
    }

    # Step 1: Analyze MX records
    results["mx_analysis"] = await _analyze_mx_records(domain, timeout)

    # Get MX hosts to test
    mx_hosts = [mx["host"] for mx in results["mx_analysis"].get("mx_records", [])]

    # If no MX records, try the domain directly
    if not mx_hosts:
        mx_hosts = [domain]

    # Limit to first 3 MX hosts
    mx_hosts = mx_hosts[:3]

    # Step 2: Test each MX host
    for mx_host in mx_hosts:
        # Port scan and TLS test
        port_results = await _scan_smtp_ports(mx_host, timeout)
        results["smtp_hosts"][mx_host] = port_results

        # Get banner from port 25 or 587
        for port in [25, 587]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(mx_host, port),
                    timeout=10
                )
                banner = await asyncio.wait_for(reader.readline(), timeout=5)
                banner_text = banner.decode('utf-8', errors='replace').strip()
                writer.close()
                await writer.wait_closed()

                results["banner_analysis"][mx_host] = _analyze_banner(banner_text)
                break
            except:
                continue

        # Open relay test (safe mode only)
        if test_relay and safe_mode:
            relay_result = await _test_open_relay_safe(mx_host, 25, timeout)
            results["relay_tests"][mx_host] = relay_result

    # Step 3: Calculate overall assessment
    all_issues = []
    all_recommendations = []
    worst_grade = "A"
    grade_order = ["A", "B", "C", "D", "F", "N/A"]

    # Collect from MX analysis
    if results["mx_analysis"].get("issues"):
        all_issues.extend(results["mx_analysis"]["issues"])
    if results["mx_analysis"].get("recommendations"):
        all_recommendations.extend(results["mx_analysis"]["recommendations"])

    # Collect from SMTP hosts
    for host, host_results in results["smtp_hosts"].items():
        if host_results.get("issues"):
            all_issues.extend(host_results["issues"])
        if host_results.get("recommendations"):
            all_recommendations.extend(host_results["recommendations"])

        host_grade = host_results.get("overall_grade", "A")
        if grade_order.index(host_grade) > grade_order.index(worst_grade):
            worst_grade = host_grade

    # Collect from banner analysis
    for host, banner_results in results["banner_analysis"].items():
        if banner_results.get("vulnerabilities"):
            all_issues.extend([f"{host}: {v}" for v in banner_results["vulnerabilities"]])
        if banner_results.get("recommendations"):
            all_recommendations.extend(banner_results["recommendations"])

    # Collect from relay tests
    for host, relay_results in results["relay_tests"].items():
        if relay_results.get("potentially_vulnerable"):
            all_issues.append(f"{host}: Potential open relay detected")
            worst_grade = "F"

    results["overall_assessment"]["grade"] = worst_grade
    results["overall_assessment"]["issues"] = list(set(all_issues))[:20]
    results["overall_assessment"]["recommendations"] = list(set(all_recommendations))[:10]

    # Determine risk level
    if worst_grade == "F":
        results["overall_assessment"]["risk_level"] = "critical"
    elif worst_grade == "D":
        results["overall_assessment"]["risk_level"] = "high"
    elif worst_grade == "C":
        results["overall_assessment"]["risk_level"] = "medium"
    elif worst_grade == "B":
        results["overall_assessment"]["risk_level"] = "low"
    else:
        results["overall_assessment"]["risk_level"] = "info"

    # Generate findings
    _generate_smtp_findings(results)

    return results


def _generate_smtp_findings(results: dict[str, Any]) -> None:
    """Generate security findings from SMTP analysis."""
    findings = []
    domain = results["domain"]

    # Finding: Open relay
    for host, relay_result in results.get("relay_tests", {}).items():
        if relay_result.get("potentially_vulnerable"):
            findings.append({
                "id": f"smtp_scanner:{hashlib.md5(f'open_relay_{host}'.encode()).hexdigest()[:8]}",
                "tool": "smtp_scanner",
                "title": f"Potential Open Relay Detected on {host}",
                "severity": "critical",
                "cvss_score": 9.1,
                "cwe": "CWE-284",
                "owasp": "A05:2021 - Security Misconfiguration",
                "description": (
                    f"SMTP server {host} may be configured as an open relay, accepting "
                    "mail from external senders to external recipients without authentication."
                ),
                "evidence": {
                    "host": host,
                    "responses": relay_result.get("responses", [])[:5]
                },
                "remediation": (
                    "Configure SMTP server to require authentication for relaying. "
                    "Restrict relay to authenticated users or specific IP ranges."
                )
            })

    # Finding: No STARTTLS
    for host, host_results in results.get("smtp_hosts", {}).items():
        port_25 = host_results.get("tls_results", {}).get(25, {})
        if port_25.get("reachable") and not port_25.get("starttls_supported"):
            findings.append({
                "id": f"smtp_scanner:{hashlib.md5(f'no_starttls_{host}'.encode()).hexdigest()[:8]}",
                "tool": "smtp_scanner",
                "title": f"STARTTLS Not Supported on {host}:25",
                "severity": "high",
                "cvss_score": 7.5,
                "cwe": "CWE-319",
                "owasp": "A02:2021 - Cryptographic Failures",
                "description": (
                    f"SMTP server {host} on port 25 does not support STARTTLS. "
                    "Email communications are transmitted in plaintext, allowing interception."
                ),
                "evidence": {
                    "host": host,
                    "port": 25
                },
                "remediation": "Enable STARTTLS on the SMTP server to encrypt email transmissions."
            })

    # Finding: Outdated TLS
    for host, host_results in results.get("smtp_hosts", {}).items():
        for port, port_result in host_results.get("tls_results", {}).items():
            tls_version = port_result.get("tls_version", "")
            if tls_version and ("SSLv" in tls_version or tls_version in ["TLSv1", "TLSv1.0", "TLSv1.1"]):
                findings.append({
                    "id": f"smtp_scanner:{hashlib.md5(f'old_tls_{host}_{port}'.encode()).hexdigest()[:8]}",
                    "tool": "smtp_scanner",
                    "title": f"Outdated TLS Version on {host}:{port}",
                    "severity": "medium",
                    "cvss_score": 5.3,
                    "cwe": "CWE-326",
                    "owasp": "A02:2021 - Cryptographic Failures",
                    "description": f"SMTP server supports outdated TLS version: {tls_version}",
                    "evidence": {
                        "host": host,
                        "port": port,
                        "tls_version": tls_version
                    },
                    "remediation": "Disable TLSv1.0 and TLSv1.1. Enable TLSv1.2 and TLSv1.3 only."
                })

    # Finding: Version disclosure
    for host, banner_result in results.get("banner_analysis", {}).items():
        if banner_result.get("version_disclosed"):
            findings.append({
                "id": f"smtp_scanner:{hashlib.md5(f'version_disclosure_{host}'.encode()).hexdigest()[:8]}",
                "tool": "smtp_scanner",
                "title": f"SMTP Version Disclosure on {host}",
                "severity": "low",
                "cvss_score": 3.1,
                "cwe": "CWE-200",
                "owasp": "A05:2021 - Security Misconfiguration",
                "description": (
                    f"SMTP banner reveals software version: {banner_result.get('software')} "
                    f"{banner_result.get('version', '')}"
                ),
                "evidence": {
                    "host": host,
                    "banner": banner_result.get("raw_banner", "")[:200]
                },
                "remediation": "Configure SMTP server to use a generic banner without version information."
            })

    # Finding: No MX redundancy
    mx_analysis = results.get("mx_analysis", {})
    if mx_analysis.get("mx_count", 0) == 1:
        findings.append({
            "id": f"smtp_scanner:{hashlib.md5(f'no_mx_redundancy_{domain}'.encode()).hexdigest()[:8]}",
            "tool": "smtp_scanner",
            "title": "No MX Record Redundancy",
            "severity": "low",
            "cvss_score": 2.5,
            "cwe": "CWE-693",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": "Domain has only one MX record with no backup mail server.",
            "evidence": {
                "domain": domain,
                "mx_records": mx_analysis.get("mx_records", [])
            },
            "remediation": "Add backup MX records for email delivery redundancy."
        })

    # Finding: Known vulnerabilities
    for host, banner_result in results.get("banner_analysis", {}).items():
        for vuln in banner_result.get("vulnerabilities", []):
            findings.append({
                "id": f"smtp_scanner:{hashlib.md5(f'vuln_{host}_{vuln[:20]}'.encode()).hexdigest()[:8]}",
                "tool": "smtp_scanner",
                "title": f"Known Vulnerability in SMTP Software on {host}",
                "severity": "high",
                "cvss_score": 7.5,
                "cwe": "CWE-1104",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "description": vuln,
                "evidence": {
                    "host": host,
                    "software": banner_result.get("software"),
                    "version": banner_result.get("version")
                },
                "remediation": "Update SMTP server software to the latest secure version."
            })

    results["findings"] = findings
