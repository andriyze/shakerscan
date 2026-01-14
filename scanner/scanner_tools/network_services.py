"""
Network Services Detection Module

Comprehensive network service discovery including:
- VPN endpoints (OpenVPN, WireGuard, IPSec, SSTP)
- Remote desktop (RDP, VNC, TeamViewer)
- IoT protocols (MQTT, CoAP, AMQP)
- Industrial protocols (Modbus, DNP3, BACnet) - detection only
- Database exposure (MongoDB, Redis, Elasticsearch, Memcached)
- Service version fingerprinting

Uses nmap and custom probes for detection.
"""

import asyncio
import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from .nmap import correct_service_name

# ============================================================================
# CONSTANTS
# ============================================================================

# Service port definitions
SERVICE_PORTS = {
    # VPN Services
    "openvpn": [1194, 443],
    "wireguard": [51820],
    "ipsec": [500, 4500],
    "sstp": [443],
    "l2tp": [1701],
    "pptp": [1723],

    # Remote Desktop
    "rdp": [3389],
    "vnc": [5900, 5901, 5902, 5903, 5904, 5905],
    "teamviewer": [5938],
    "anydesk": [7070],
    "ssh": [22],
    "telnet": [23],

    # IoT Protocols
    "mqtt": [1883, 8883],
    "coap": [5683, 5684],
    "amqp": [5672, 5671],
    "xmpp": [5222, 5223],

    # Industrial/SCADA
    "modbus": [502],
    "dnp3": [20000],
    "bacnet": [47808],
    "ethernetip": [44818],
    "s7comm": [102],

    # Databases
    "mongodb": [27017, 27018, 27019],
    "redis": [6379],
    "elasticsearch": [9200, 9300],
    "memcached": [11211],
    "mysql": [3306],
    "postgres": [5432],
    "mssql": [1433],
    "oracle": [1521],
    "cassandra": [9042],
    "couchdb": [5984],

    # Message Queues
    "rabbitmq": [5672, 15672],
    "kafka": [9092],
    "zookeeper": [2181],

    # Other Services
    "docker": [2375, 2376],
    "kubernetes_api": [6443, 8443],
    "etcd": [2379, 2380],
    "consul": [8500, 8501],
    "vault": [8200],
    "prometheus": [9090],
    "grafana": [3000],
}

# Service risk levels
SERVICE_RISKS = {
    # Critical - should never be exposed
    "modbus": "critical",
    "dnp3": "critical",
    "bacnet": "critical",
    "s7comm": "critical",
    "ethernetip": "critical",
    "telnet": "critical",
    "redis": "critical",
    "memcached": "critical",
    "mongodb": "high",
    "elasticsearch": "high",
    "docker": "critical",
    "etcd": "critical",

    # High - requires authentication
    "rdp": "high",
    "vnc": "high",
    "mysql": "high",
    "postgres": "high",
    "mssql": "high",
    "oracle": "high",
    "cassandra": "high",
    "rabbitmq": "high",
    "kafka": "high",

    # Medium - should be protected
    "ssh": "medium",
    "mqtt": "medium",
    "amqp": "medium",
    "kubernetes_api": "medium",
    "consul": "medium",
    "vault": "medium",

    # Low/Info - typically safe if configured
    "openvpn": "info",
    "wireguard": "info",
    "ipsec": "info",
}

# Banner patterns for service identification
SERVICE_BANNERS = {
    "ssh": [
        (r"SSH-(\d+\.\d+)-(.+)", "SSH"),
        (r"OpenSSH[_\s](\d+\.\d+)", "OpenSSH"),
        (r"dropbear[_\s]?(\d+\.\d+)?", "Dropbear SSH"),
    ],
    "rdp": [
        (r"\x03\x00", "RDP"),
    ],
    "vnc": [
        (r"RFB (\d+\.\d+)", "VNC"),
    ],
    "mysql": [
        (r"(\d+\.\d+\.\d+)-MariaDB", "MariaDB"),
        (r"(\d+\.\d+\.\d+).*mysql", "MySQL"),
    ],
    "postgres": [
        (r"PostgreSQL (\d+\.\d+)", "PostgreSQL"),
    ],
    "redis": [
        (r"-ERR.*redis", "Redis"),
        (r"\$\d+\r\nredis_version:(\d+\.\d+)", "Redis"),
    ],
    "mongodb": [
        (r"MongoDB", "MongoDB"),
        (r"ismaster", "MongoDB"),
    ],
    "elasticsearch": [
        (r'"cluster_name"', "Elasticsearch"),
        (r'"version".*"number".*"(\d+\.\d+\.\d+)"', "Elasticsearch"),
    ],
    "mqtt": [
        (r"\x20\x02\x00\x00", "MQTT"),
    ],
    "modbus": [
        (r"\x00\x00\x00\x00\x00", "Modbus"),
    ],
}


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


async def _tcp_probe(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    """Probe a TCP port and capture any banner."""
    result = {
        "port": port,
        "open": False,
        "banner": None,
        "service": None,
        "version": None
    }

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )

        result["open"] = True

        # Try to read banner
        try:
            # Send minimal probe data for some services
            if port in [6379]:  # Redis
                writer.write(b"INFO\r\n")
            elif port in [27017]:  # MongoDB
                writer.write(b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00")
            elif port in [9200]:  # Elasticsearch
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
            elif port in [11211]:  # Memcached
                writer.write(b"stats\r\n")

            await writer.drain()

            banner_data = await asyncio.wait_for(
                reader.read(1024),
                timeout=2.0
            )
            if banner_data:
                # Try to decode as text, fallback to hex representation
                try:
                    result["banner"] = banner_data.decode('utf-8', errors='replace')[:200]
                except:
                    result["banner"] = banner_data[:100].hex()

        except TimeoutError:
            pass
        except Exception:
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass

    except TimeoutError:
        pass
    except ConnectionRefusedError:
        pass
    except Exception:
        pass

    return result


async def _udp_probe(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    """Probe a UDP port."""
    result = {
        "port": port,
        "open": False,
        "service": None
    }

    # UDP probing is unreliable without specific payloads
    # We'll rely on nmap for UDP scanning

    return result


# ============================================================================
# SERVICE DETECTION FUNCTIONS
# ============================================================================

async def _detect_vpn_services(host: str, timeout: int = 30) -> dict[str, Any]:
    """Detect VPN service endpoints."""
    result = {
        "detected": [],
        "ports_scanned": []
    }

    vpn_ports = []
    for vpn_type in ["openvpn", "wireguard", "ipsec", "l2tp", "pptp"]:
        vpn_ports.extend(SERVICE_PORTS.get(vpn_type, []))

    vpn_ports = list(set(vpn_ports))
    result["ports_scanned"] = vpn_ports

    # Scan ports
    tasks = [_tcp_probe(host, port, timeout/len(vpn_ports)) for port in vpn_ports]
    probe_results = await asyncio.gather(*tasks, return_exceptions=True)

    for port, probe_result in zip(vpn_ports, probe_results, strict=False):
        if isinstance(probe_result, Exception):
            continue
        if probe_result.get("open"):
            vpn_info = {
                "port": port,
                "type": "unknown",
                "banner": probe_result.get("banner")
            }

            # Identify VPN type by port
            if port == 1194:
                vpn_info["type"] = "OpenVPN"
            elif port == 51820:
                vpn_info["type"] = "WireGuard"
            elif port in [500, 4500]:
                vpn_info["type"] = "IPSec/IKE"
            elif port == 1701:
                vpn_info["type"] = "L2TP"
            elif port == 1723:
                vpn_info["type"] = "PPTP"
            elif port == 443:
                # Port 443 is commonly HTTPS - only flag as VPN if banner indicates VPN
                banner = (probe_result.get("banner") or "").lower()
                if any(sig in banner for sig in ["openvpn", "sstp", "vpn"]):
                    vpn_info["type"] = "OpenVPN/SSTP (port 443)"
                else:
                    # Skip - likely just HTTPS, not VPN
                    continue

            # Only add if we identified a specific VPN type (skip unknown)
            if vpn_info["type"] != "unknown":
                result["detected"].append(vpn_info)

    return result


async def _detect_remote_desktop(host: str, timeout: int = 30) -> dict[str, Any]:
    """Detect remote desktop services."""
    result = {
        "rdp": None,
        "vnc": [],
        "ssh": None,
        "other": []
    }

    # RDP Detection (port 3389)
    rdp_probe = await _tcp_probe(host, 3389, 5)
    if rdp_probe.get("open"):
        result["rdp"] = {
            "port": 3389,
            "open": True,
            "nla_enabled": None,  # Would need deeper probe
            "risk": "high",
            "recommendation": "Ensure NLA is enabled and access is restricted to VPN"
        }

    # VNC Detection (ports 5900-5905)
    vnc_tasks = [_tcp_probe(host, port, 3) for port in range(5900, 5906)]
    vnc_results = await asyncio.gather(*vnc_tasks, return_exceptions=True)

    for port, probe_result in zip(range(5900, 5906), vnc_results, strict=False):
        if isinstance(probe_result, Exception):
            continue
        if probe_result.get("open"):
            vnc_info = {
                "port": port,
                "display": port - 5900,
                "banner": probe_result.get("banner"),
                "risk": "high"
            }

            # Parse VNC version from banner
            banner = probe_result.get("banner", "")
            rfb_match = re.search(r"RFB (\d+\.\d+)", banner)
            if rfb_match:
                vnc_info["version"] = rfb_match.group(1)

            result["vnc"].append(vnc_info)

    # SSH Detection (port 22)
    ssh_probe = await _tcp_probe(host, 22, 5)
    if ssh_probe.get("open"):
        ssh_info = {
            "port": 22,
            "open": True,
            "banner": ssh_probe.get("banner"),
            "version": None,
            "risk": "medium"
        }

        # Parse SSH version
        banner = ssh_probe.get("banner", "")
        ssh_match = re.search(r"SSH-(\d+\.\d+)-(.+)", banner)
        if ssh_match:
            ssh_info["protocol"] = ssh_match.group(1)
            ssh_info["software"] = ssh_match.group(2)

            openssh_match = re.search(r"OpenSSH[_\s](\d+\.\d+)", banner)
            if openssh_match:
                ssh_info["version"] = openssh_match.group(1)

        result["ssh"] = ssh_info

    # Telnet Detection (critical risk)
    telnet_probe = await _tcp_probe(host, 23, 3)
    if telnet_probe.get("open"):
        result["other"].append({
            "service": "telnet",
            "port": 23,
            "risk": "critical",
            "recommendation": "Disable Telnet immediately and use SSH instead"
        })

    return result


async def _detect_iot_protocols(host: str, timeout: int = 30) -> dict[str, Any]:
    """Detect IoT protocol endpoints."""
    result = {
        "mqtt": None,
        "coap": None,
        "amqp": None,
        "detected": []
    }

    # MQTT Detection (1883 unencrypted, 8883 TLS)
    for port in [1883, 8883]:
        mqtt_probe = await _tcp_probe(host, port, 5)
        if mqtt_probe.get("open"):
            result["mqtt"] = {
                "port": port,
                "encrypted": port == 8883,
                "risk": "medium" if port == 8883 else "high",
                "recommendation": "Use TLS (port 8883) and require authentication"
            }
            result["detected"].append({
                "protocol": "MQTT",
                "port": port,
                "encrypted": port == 8883
            })
            break

    # AMQP Detection (5672 unencrypted, 5671 TLS)
    for port in [5672, 5671]:
        amqp_probe = await _tcp_probe(host, port, 5)
        if amqp_probe.get("open"):
            result["amqp"] = {
                "port": port,
                "encrypted": port == 5671,
                "risk": "medium" if port == 5671 else "high"
            }
            result["detected"].append({
                "protocol": "AMQP",
                "port": port,
                "encrypted": port == 5671
            })
            break

    return result


async def _detect_industrial_protocols(host: str, timeout: int = 30) -> dict[str, Any]:
    """Detect industrial/SCADA protocol endpoints."""
    result = {
        "detected": [],
        "critical_exposure": False,
        "protocols_found": []
    }

    industrial_ports = {
        502: "Modbus",
        20000: "DNP3",
        47808: "BACnet",
        44818: "EtherNet/IP",
        102: "S7comm (Siemens)"
    }

    for port, protocol in industrial_ports.items():
        probe_result = await _tcp_probe(host, port, 5)
        if probe_result.get("open"):
            result["critical_exposure"] = True
            result["protocols_found"].append(protocol)
            result["detected"].append({
                "protocol": protocol,
                "port": port,
                "risk": "critical",
                "owasp": "A05:2021 - Security Misconfiguration",
                "recommendation": f"CRITICAL: {protocol} should NEVER be exposed to the internet. Isolate on dedicated network."
            })

    return result


async def _detect_database_exposure(host: str, timeout: int = 30) -> dict[str, Any]:
    """Detect exposed database services."""
    result = {
        "detected": [],
        "unauthenticated": [],
        "total_exposed": 0
    }

    db_ports = {
        27017: ("MongoDB", "critical"),
        6379: ("Redis", "critical"),
        9200: ("Elasticsearch", "high"),
        11211: ("Memcached", "critical"),
        3306: ("MySQL", "high"),
        5432: ("PostgreSQL", "high"),
        1433: ("MSSQL", "high"),
        1521: ("Oracle", "high"),
        9042: ("Cassandra", "high"),
        5984: ("CouchDB", "high"),
    }

    tasks = []
    ports = []
    for port in db_ports:
        tasks.append(_tcp_probe(host, port, 5))
        ports.append(port)

    probe_results = await asyncio.gather(*tasks, return_exceptions=True)

    for port, probe_result in zip(ports, probe_results, strict=False):
        if isinstance(probe_result, Exception):
            continue
        if probe_result.get("open"):
            db_name, risk = db_ports[port]
            db_info = {
                "database": db_name,
                "port": port,
                "risk": risk,
                "banner": probe_result.get("banner", "")[:100],
                "authentication_required": True,  # Assume true by default
                "version": None
            }

            # Check for unauthenticated access indicators
            banner = probe_result.get("banner", "")

            if db_name == "Redis":
                if "ERR" not in banner and "NOAUTH" not in banner:
                    db_info["authentication_required"] = False
                    result["unauthenticated"].append(db_name)
            elif db_name == "MongoDB":
                if "ismaster" in banner.lower():
                    db_info["authentication_required"] = False
                    result["unauthenticated"].append(db_name)
            elif db_name == "Elasticsearch":
                if "cluster_name" in banner:
                    db_info["authentication_required"] = False
                    result["unauthenticated"].append(db_name)
            elif db_name == "Memcached":
                if "STAT" in banner:
                    db_info["authentication_required"] = False
                    result["unauthenticated"].append(db_name)

            result["detected"].append(db_info)
            result["total_exposed"] += 1

    return result


# ============================================================================
# NMAP SERVICE SCAN
# ============================================================================

async def _nmap_service_scan(host: str, ports: list[int], timeout: int = 60) -> dict[str, Any]:
    """Run nmap service version detection on specified ports."""
    result = {
        "services": [],
        "raw": None,
        "error": None
    }

    if not ports:
        return result

    port_str = ",".join(str(p) for p in ports[:50])  # Limit to 50 ports

    cmd = [
        "nmap", "-Pn", "-sV", "-sT",
        "--version-intensity", "5",
        "-p", port_str,
        "-oG", "-",
        "--host-timeout", str(timeout) + "s",
        host
    ]

    stdout, stderr, returncode = await _run_command(cmd, timeout + 10)
    result["raw"] = stdout

    if returncode != 0:
        result["error"] = stderr
        return result

    # Parse nmap grepable output
    for line in stdout.split('\n'):
        if '/open/' in line:
            # Parse: Ports: 22/open/tcp//ssh//OpenSSH 8.0/
            ports_section = re.search(r'Ports:\s*(.+)', line)
            if ports_section:
                port_entries = ports_section.group(1).split(', ')
                for entry in port_entries:
                    parts = entry.split('/')
                    if len(parts) >= 5 and parts[1] == 'open':
                        port_num = int(parts[0])
                        raw_service = parts[4] if len(parts) > 4 else "unknown"
                        version = parts[6] if len(parts) > 6 else ""
                        # Apply service name correction for common misidentifications
                        corrected_service = correct_service_name(port_num, raw_service, version or "")
                        service_info = {
                            "port": port_num,
                            "protocol": parts[2],
                            "service": corrected_service,
                            "version": version if version else None
                        }
                        if raw_service != corrected_service:
                            service_info["original_detection"] = raw_service
                        result["services"].append(service_info)

    return result


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

async def check_network_services(
    host: str,
    timeout: int = 120,
    scan_vpn: bool = True,
    scan_remote_desktop: bool = True,
    scan_iot: bool = True,
    scan_industrial: bool = True,
    scan_databases: bool = True,
    safe_mode: bool = True
) -> dict[str, Any]:
    """
    Comprehensive network service discovery.

    Args:
        host: Target host to scan
        timeout: Total timeout for all scans
        scan_vpn: Scan for VPN endpoints
        scan_remote_desktop: Scan for RDP/VNC/SSH
        scan_iot: Scan for IoT protocols
        scan_industrial: Scan for industrial/SCADA protocols
        scan_databases: Scan for exposed databases
        safe_mode: If True, use non-intrusive probes only

    Returns:
        Dict with network service discovery results
    """
    results = {
        "host": host,
        "scan_timestamp": datetime.now(UTC).isoformat(),
        "vpn_services": None,
        "remote_desktop": None,
        "iot_protocols": None,
        "industrial_protocols": None,
        "database_exposure": None,
        "summary": {
            "total_services": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "services_by_risk": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            }
        },
        "findings": []
    }

    # Run scans concurrently
    tasks = []
    task_names = []

    if scan_vpn:
        tasks.append(_detect_vpn_services(host, timeout // 5))
        task_names.append("vpn_services")

    if scan_remote_desktop:
        tasks.append(_detect_remote_desktop(host, timeout // 5))
        task_names.append("remote_desktop")

    if scan_iot:
        tasks.append(_detect_iot_protocols(host, timeout // 5))
        task_names.append("iot_protocols")

    if scan_industrial:
        tasks.append(_detect_industrial_protocols(host, timeout // 5))
        task_names.append("industrial_protocols")

    if scan_databases:
        tasks.append(_detect_database_exposure(host, timeout // 5))
        task_names.append("database_exposure")

    scan_results = await asyncio.gather(*tasks, return_exceptions=True)

    for name, scan_result in zip(task_names, scan_results, strict=False):
        if isinstance(scan_result, Exception):
            results[name] = {"error": str(scan_result)}
        else:
            results[name] = scan_result

    # Calculate summary and generate findings
    _calculate_summary(results)
    _generate_findings(results)

    return results


def _calculate_summary(results: dict[str, Any]) -> None:
    """Calculate summary statistics from scan results."""
    summary = results["summary"]

    # VPN services
    vpn_svc = results.get("vpn_services") or {}
    if vpn_svc.get("detected"):
        for vpn in vpn_svc["detected"]:
            summary["total_services"] += 1
            summary["services_by_risk"]["info"].append(f"VPN: {vpn.get('type', 'Unknown')} (port {vpn.get('port')})")

    # Remote desktop
    rd = results.get("remote_desktop") or {}
    rdp_info = rd.get("rdp") or {}
    if rdp_info.get("open"):
        summary["total_services"] += 1
        summary["high_findings"] += 1
        summary["services_by_risk"]["high"].append("RDP (port 3389)")

    if rd.get("vnc"):
        for vnc in rd["vnc"]:
            summary["total_services"] += 1
            summary["high_findings"] += 1
            summary["services_by_risk"]["high"].append(f"VNC (port {vnc.get('port')})")

    ssh_info = rd.get("ssh") or {}
    if ssh_info.get("open"):
        summary["total_services"] += 1
        summary["services_by_risk"]["medium"].append("SSH (port 22)")

    for other in rd.get("other", []):
        summary["total_services"] += 1
        risk = other.get("risk", "medium")
        if risk == "critical":
            summary["critical_findings"] += 1
        summary["services_by_risk"][risk].append(f"{other.get('service')} (port {other.get('port')})")

    # IoT protocols
    iot_results = results.get("iot_protocols") or {}
    if iot_results.get("detected"):
        for iot in iot_results["detected"]:
            summary["total_services"] += 1
            risk = "high" if not iot.get("encrypted") else "medium"
            summary["services_by_risk"][risk].append(f"{iot.get('protocol')} (port {iot.get('port')})")

    # Industrial protocols
    ind_results = results.get("industrial_protocols") or {}
    if ind_results.get("detected"):
        for ind in ind_results["detected"]:
            summary["total_services"] += 1
            summary["critical_findings"] += 1
            summary["services_by_risk"]["critical"].append(f"{ind.get('protocol')} (port {ind.get('port')})")

    # Database exposure
    db_results = results.get("database_exposure") or {}
    if db_results.get("detected"):
        for db in db_results["detected"]:
            summary["total_services"] += 1
            risk = db.get("risk", "high")
            if risk == "critical":
                summary["critical_findings"] += 1
            elif risk == "high":
                summary["high_findings"] += 1
            summary["services_by_risk"][risk].append(f"{db.get('database')} (port {db.get('port')})")


def _generate_findings(results: dict[str, Any]) -> None:
    """Generate security findings from network service scan."""
    findings = []
    host = results["host"]

    # Industrial protocols - CRITICAL
    ind_results = results.get("industrial_protocols", {})
    if ind_results.get("critical_exposure"):
        for protocol in ind_results.get("detected", []):
            prot_port = protocol.get("port")
            findings.append({
                "id": f"network_services:{hashlib.md5(f'industrial_{host}_{prot_port}'.encode()).hexdigest()[:8]}",
                "tool": "network_services",
                "title": f"Critical: {protocol.get('protocol')} Exposed to Internet",
                "severity": "critical",
                "cvss_score": 10.0,
                "cwe": "CWE-284",
                "owasp": "A05:2021 - Security Misconfiguration",
                "description": (
                    f"Industrial/SCADA protocol {protocol.get('protocol')} is exposed on port {protocol.get('port')}. "
                    "These protocols have no built-in security and should NEVER be accessible from the internet."
                ),
                "evidence": {
                    "host": host,
                    "protocol": protocol.get("protocol"),
                    "port": protocol.get("port")
                },
                "remediation": (
                    "Immediately isolate this system from the internet. "
                    "Industrial protocols should only be accessible via dedicated, air-gapped networks or VPN."
                )
            })

    # Database exposure
    db_results = results.get("database_exposure", {})
    for db in db_results.get("detected", []):
        db_port = db.get("port")
        if not db.get("authentication_required"):
            findings.append({
                "id": f"network_services:{hashlib.md5(f'unauth_db_{host}_{db_port}'.encode()).hexdigest()[:8]}",
                "tool": "network_services",
                "title": f"Unauthenticated {db.get('database')} Access",
                "severity": "critical",
                "cvss_score": 9.8,
                "cwe": "CWE-306",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "description": (
                    f"{db.get('database')} on port {db.get('port')} appears to allow unauthenticated access. "
                    "This could allow attackers to read, modify, or delete data."
                ),
                "evidence": {
                    "host": host,
                    "database": db.get("database"),
                    "port": db.get("port")
                },
                "remediation": (
                    f"Enable authentication for {db.get('database')}. "
                    "Restrict access to trusted networks only. Consider using a firewall."
                )
            })
        else:
            risk = db.get("risk", "high")
            if risk in ["critical", "high"]:
                findings.append({
                    "id": f"network_services:{hashlib.md5(f'exposed_db_{host}_{db_port}'.encode()).hexdigest()[:8]}",
                    "tool": "network_services",
                    "title": f"Exposed {db.get('database')} Service",
                    "severity": risk,
                    "cvss_score": 7.5 if risk == "high" else 9.0,
                    "cwe": "CWE-284",
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "description": (
                        f"{db.get('database')} is accessible on port {db.get('port')}. "
                        "Database services should not be directly exposed to the internet."
                    ),
                    "evidence": {
                        "host": host,
                        "database": db.get("database"),
                        "port": db.get("port")
                    },
                    "remediation": (
                        "Restrict database access to application servers only. "
                        "Use firewall rules or VPN for remote access."
                    )
                })

    # Remote desktop - RDP
    rd_results = results.get("remote_desktop") or {}
    rdp_info = rd_results.get("rdp") or {}
    if rdp_info.get("open"):
        findings.append({
            "id": f"network_services:{hashlib.md5(f'rdp_{host}'.encode()).hexdigest()[:8]}",
            "tool": "network_services",
            "title": "RDP Service Exposed to Internet",
            "severity": "high",
            "cvss_score": 7.5,
            "cwe": "CWE-284",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": (
                "Remote Desktop Protocol (RDP) is accessible on port 3389. "
                "RDP is a common target for brute force attacks and has had critical vulnerabilities (BlueKeep)."
            ),
            "evidence": {
                "host": host,
                "port": 3389
            },
            "remediation": (
                "Disable direct RDP access from the internet. "
                "Use VPN, RD Gateway, or Azure AD Proxy for remote access. Enable NLA."
            )
        })

    # VNC
    for vnc in rd_results.get("vnc", []):
        vnc_port = vnc.get("port")
        findings.append({
            "id": f"network_services:{hashlib.md5(f'vnc_{host}_{vnc_port}'.encode()).hexdigest()[:8]}",
            "tool": "network_services",
            "title": f"VNC Service Exposed on Port {vnc.get('port')}",
            "severity": "high",
            "cvss_score": 7.5,
            "cwe": "CWE-284",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": (
                f"VNC remote access is available on port {vnc.get('port')}. "
                "VNC has weak encryption and is vulnerable to brute force attacks."
            ),
            "evidence": {
                "host": host,
                "port": vnc.get("port"),
                "version": vnc.get("version")
            },
            "remediation": "Disable direct VNC access. Use SSH tunneling or VPN for remote access."
        })

    # Telnet
    for other in rd_results.get("other", []):
        if other.get("service") == "telnet":
            findings.append({
                "id": f"network_services:{hashlib.md5(f'telnet_{host}'.encode()).hexdigest()[:8]}",
                "tool": "network_services",
                "title": "Telnet Service Exposed (Critical)",
                "severity": "critical",
                "cvss_score": 9.8,
                "cwe": "CWE-319",
                "owasp": "A02:2021 - Cryptographic Failures",
                "description": (
                    "Telnet transmits all data including credentials in plaintext. "
                    "This is a critical security vulnerability."
                ),
                "evidence": {
                    "host": host,
                    "port": 23
                },
                "remediation": "Disable Telnet immediately. Use SSH for remote access."
            })

    # Unencrypted IoT protocols
    iot_results = results.get("iot_protocols") or {}
    for iot in iot_results.get("detected") or []:
        iot_port = iot.get("port")
        if not iot.get("encrypted"):
            findings.append({
                "id": f"network_services:{hashlib.md5(f'unenc_iot_{host}_{iot_port}'.encode()).hexdigest()[:8]}",
                "tool": "network_services",
                "title": f"Unencrypted {iot.get('protocol')} Service",
                "severity": "high",
                "cvss_score": 7.5,
                "cwe": "CWE-319",
                "owasp": "A02:2021 - Cryptographic Failures",
                "description": (
                    f"{iot.get('protocol')} is running without encryption on port {iot.get('port')}. "
                    "Data transmitted over this protocol can be intercepted."
                ),
                "evidence": {
                    "host": host,
                    "protocol": iot.get("protocol"),
                    "port": iot.get("port")
                },
                "remediation": f"Enable TLS encryption for {iot.get('protocol')}. Require authentication."
            })

    results["findings"] = findings
