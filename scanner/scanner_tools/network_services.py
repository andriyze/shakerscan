"""
Network Services Detection Module

Bounded discovery of non-web network services on the scanned host: VPN endpoints, remote
access (RDP, VNC, SSH, Telnet), IoT brokers (MQTT, AMQP), industrial protocols and databases.

A listener is named only by a parsed protocol reply (``service_protocols``); the port number
only decides which adapter is tried first. An open port nothing identified is reported with its
conventional service as an explicit ``port_hint``, never as that service. A database handshake
is protocol identity, not access: "unauthenticated access" needs a bounded read-only command the
server executed without credentials, and otherwise authentication is "not tested".
"""

import asyncio
import hashlib
import ipaddress
import socket
from datetime import UTC, datetime
from typing import Any

try:
    from . import service_identity as si
    from . import service_protocols as sp
    from .cdn_edges import network_role as cdn_network_role
except ImportError:  # pragma: no cover - flat scanner runtime
    import service_identity as si  # type: ignore[no-redef]
    import service_protocols as sp  # type: ignore[no-redef]
    from cdn_edges import network_role as cdn_network_role  # type: ignore[no-redef]

# ============================================================================
# CONSTANTS
# ============================================================================

# Candidate TCP ports per category. They choose where to look and which adapter to try first;
# they never name what is found there.
VPN_TCP_PORTS = (1194, 1723)
VPN_UDP_PORTS = (500, 4500, 1194)
SILENT_VPN_UDP_PORTS = (51820,)  # WireGuard: silent by design, never confirmed
REMOTE_ACCESS_TCP_PORTS = (22, 23, 3389, 5900, 5901, 5902, 5903, 5904, 5905, 5938, 7070)
IOT_TCP_PORTS = (1883, 8883, 5672, 5671)
INDUSTRIAL_TCP_PORTS = (502, 102, 20000, 44818)
DATABASE_TCP_PORTS = (27017, 27018, 6379, 9200, 11211, 3306, 5432, 1433, 1521, 9042, 5984)

MAX_ADDRESSES = 4
CONNECT_CONCURRENCY = 32
IDENTIFY_CONCURRENCY = 4
# The banner read, the port's conventional adapter, then HTTP and TLS: these candidate ports
# are conventional ones, so a full silent-protocol sweep is left to the device engine.
MAX_ADAPTERS_PER_PORT = 4

VPN_PROTOCOLS = {"openvpn": "OpenVPN", "ike": "IPsec/IKE", "pptp": "PPTP"}
REMOTE_PROTOCOLS = {"rdp", "vnc", "ssh", "telnet"}
IOT_PROTOCOLS = {"mqtt": "MQTT", "amqp": "AMQP"}
INDUSTRIAL_PROTOCOLS = {"modbus": "Modbus", "ethernet-ip": "EtherNet/IP"}
# Conventional industrial ports whose protocol has no adapter here: an open port is reported as
# a hint ("conventionally DNP3"), never as the protocol.
INDUSTRIAL_PORT_HINTS = {102: "S7comm (ISO-TSAP)", 20000: "DNP3"}
DATABASE_PRODUCTS = {
    "mongodb": ("MongoDB", "critical"), "redis": ("Redis", "critical"),
    "memcached": ("Memcached", "critical"), "mysql": ("MySQL", "high"),
    "postgresql": ("PostgreSQL", "high"),
}
SEARCH_PRODUCTS = {"Elasticsearch": "high", "OpenSearch": "high"}


# ============================================================================
# HELPERS
# ============================================================================

async def _resolve(host: str) -> list[str]:
    """The host's addresses as the process resolver answers them (frozen in a canonical Scan)."""
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), 10)
    except (OSError, TimeoutError, asyncio.TimeoutError):
        return []
    addresses: list[str] = []
    for info in infos:
        try:
            address = str(ipaddress.ip_address(str(info[4][0]).split("%", 1)[0]))
        except (ValueError, IndexError):
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


async def _tcp_open(address: str, port: int, gate: asyncio.Semaphore, timeout: float = 3.0) -> bool:
    async with gate:
        try:
            _reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
        except (OSError, TimeoutError, asyncio.TimeoutError):
            return False
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1.0)
        except Exception:  # noqa: BLE001
            pass
        return True


def _category_ports(
    *, scan_vpn: bool, scan_remote_desktop: bool, scan_iot: bool, scan_industrial: bool,
    scan_databases: bool,
) -> tuple[list[int], list[int]]:
    tcp: list[int] = []
    udp: list[int] = []
    for enabled, ports in (
        (scan_vpn, VPN_TCP_PORTS), (scan_remote_desktop, REMOTE_ACCESS_TCP_PORTS),
        (scan_iot, IOT_TCP_PORTS), (scan_industrial, INDUSTRIAL_TCP_PORTS),
        (scan_databases, DATABASE_TCP_PORTS),
    ):
        if enabled:
            tcp.extend(port for port in ports if port not in tcp)
    if scan_vpn:
        udp.extend(VPN_UDP_PORTS)
    return tcp, udp


async def _scan_address(
    address: str, *, tcp_ports: list[int], udp_ports: list[int], server_name: str | None,
    deadline: float,
) -> list[dict[str, Any]]:
    loop = asyncio.get_running_loop()
    gate = asyncio.Semaphore(CONNECT_CONCURRENCY)
    open_flags = await asyncio.gather(*(_tcp_open(address, port, gate) for port in tcp_ports))
    open_ports = [port for port, is_open in zip(tcp_ports, open_flags) if is_open]
    identify_gate = asyncio.Semaphore(IDENTIFY_CONCURRENCY)

    async def identify_tcp(port: int) -> dict[str, Any]:
        async with identify_gate:
            if loop.time() >= deadline:
                row = sp.public_row({"transport": "tcp", "port": port, "status": si.STATUS_SILENT,
                                     "port_hint": si.port_hint(port)})
                row["details"] = {"reason": "time_budget_exhausted"}
                return row
            return sp.public_row(await sp.identify_tcp_service(
                address, port, hints=(si.port_hint(port),), server_name=server_name,
                max_adapters=MAX_ADAPTERS_PER_PORT,
            ))

    async def identify_udp(port: int) -> dict[str, Any]:
        async with identify_gate:
            return sp.public_row(await sp.identify_udp_service(address, port))

    rows = list(await asyncio.gather(
        *(identify_tcp(port) for port in open_ports),
        *(identify_udp(port) for port in udp_ports),
    ))
    for port in SILENT_VPN_UDP_PORTS if udp_ports else ():
        rows.append(sp.public_row({
            "transport": "udp", "port": port, "status": si.STATUS_NOT_IDENTIFIABLE,
            "adapter": "wireguard", "port_hint": si.port_hint(port),
            "details": {"reason": "silent_by_design"},
        }))
    for row in rows:
        row["address"] = address
    # A UDP port that never answered is not an observed service.
    return [row for row in rows if not (row["transport"] == "udp" and row["status"] == si.STATUS_SILENT)]


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
    safe_mode: bool = True,
    server_name: str | None = None,
) -> dict[str, Any]:
    """Bounded discovery of non-web services on every address of ``host``.

    Args:
        host: Target host (its addresses are resolved once and each is examined)
        timeout: Overall time budget in seconds
        scan_*: Which candidate port sets to examine
        safe_mode: Kept for compatibility; every probe is read-only
        server_name: Host/SNI name for TLS and HTTP adapters (defaults to ``host``)
    """
    del safe_mode
    results: dict[str, Any] = {
        "host": host,
        "scan_timestamp": datetime.now(UTC).isoformat(),
        "schema_version": si.SCHEMA_VERSION,
        "addresses": [],
        # Addresses on a shared CDN edge: the provider's network, not the origin's. Their
        # non-web ports are not examined and nothing found there is attributed to the target.
        "cdn_edges": [],
        "services": [],
        "vpn_services": {"detected": [], "not_identifiable": []},
        "remote_desktop": {"rdp": None, "vnc": [], "ssh": None, "other": []},
        "iot_protocols": {"detected": []},
        "industrial_protocols": {"detected": [], "unconfirmed": [], "critical_exposure": False, "protocols_found": []},
        "database_exposure": {"detected": [], "unauthenticated": [], "total_exposed": 0},
        "summary": {
            "total_services": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "services_by_risk": {"critical": [], "high": [], "medium": [], "low": [], "info": []},
        },
        "findings": [],
    }
    tcp_ports, udp_ports = _category_ports(
        scan_vpn=scan_vpn, scan_remote_desktop=scan_remote_desktop, scan_iot=scan_iot,
        scan_industrial=scan_industrial, scan_databases=scan_databases,
    )
    addresses = (await _resolve(host))[:MAX_ADDRESSES]
    results["addresses"] = addresses
    if not addresses:
        results["error"] = "host_not_resolved"
        return results
    try:
        is_literal = bool(ipaddress.ip_address(host))
    except ValueError:
        is_literal = False
    name = server_name or (None if is_literal else host)
    deadline = asyncio.get_running_loop().time() + max(10, int(timeout) - 10)
    for address in list(addresses):
        role = cdn_network_role(address)
        if role is not None:
            results["cdn_edges"].append({"address": address, **role})
            addresses.remove(address)
    if not addresses:
        results["note"] = results["cdn_edges"][0]["note"]
        return results
    scanned = await asyncio.gather(*(
        _scan_address(address, tcp_ports=tcp_ports, udp_ports=udp_ports, server_name=name,
                      deadline=deadline)
        for address in addresses
    ), return_exceptions=True)
    for address, outcome in zip(addresses, scanned):
        if isinstance(outcome, BaseException):
            results.setdefault("errors", []).append({"address": address, "error": type(outcome).__name__})
            continue
        results["services"].extend(outcome)
    _classify(results)
    _calculate_summary(results)
    _generate_findings(results)
    return results


def _classify(results: dict[str, Any]) -> None:
    """Group identified services by category; unidentified ones stay in ``services`` only."""
    for row in results["services"]:
        protocol = row.get("protocol")
        identified = row.get("status") == si.STATUS_IDENTIFIED
        port, address = row.get("port"), row.get("address")
        if row.get("adapter") == "wireguard":
            results["vpn_services"]["not_identifiable"].append({"port": port, "address": address, "type": "WireGuard (not identifiable)"})
            continue
        if not identified:
            if row.get("transport") == "tcp" and port in INDUSTRIAL_PORT_HINTS:
                results["industrial_protocols"]["unconfirmed"].append({
                    "port": port, "address": address, "port_hint": INDUSTRIAL_PORT_HINTS[port],
                    "status": row.get("status"),
                })
            continue
        if protocol in VPN_PROTOCOLS:
            results["vpn_services"]["detected"].append({
                "port": port, "transport": row.get("transport"), "address": address,
                "type": VPN_PROTOCOLS[protocol], "product": row.get("product"),
            })
        elif protocol in REMOTE_PROTOCOLS:
            remote = results["remote_desktop"]
            info = {
                "port": port, "address": address, "open": True, "product": row.get("product"),
                "version": row.get("version"), "version_reported": row.get("version_reported"),
                "authentication": row.get("authentication"),
                "authentication_proof": row.get("authentication_proof"),
                "details": row.get("details") or {},
            }
            if protocol == "rdp":
                info["nla_required"] = row.get("authentication_proof") == "rdp_nla_required"
                remote["rdp"] = remote["rdp"] or info
            elif protocol == "vnc":
                remote["vnc"].append({**info, "risk": "critical" if row.get("authentication") == si.AUTH_NOT_REQUIRED else "high"})
            elif protocol == "ssh":
                remote["ssh"] = remote["ssh"] or {**info, "risk": "medium"}
            else:
                remote["other"].append({**info, "service": "telnet", "risk": "critical"})
        elif protocol in IOT_PROTOCOLS:
            encrypted = bool((row.get("details") or {}).get("tls"))
            results["iot_protocols"]["detected"].append({
                "protocol": IOT_PROTOCOLS[protocol], "port": port, "address": address,
                "encrypted": encrypted, "product": row.get("product"), "version": row.get("version"),
                "authentication": row.get("authentication"),
                "authentication_proof": row.get("authentication_proof"),
            })
        elif protocol in INDUSTRIAL_PROTOCOLS:
            industrial = results["industrial_protocols"]
            industrial["critical_exposure"] = True
            industrial["protocols_found"].append(INDUSTRIAL_PROTOCOLS[protocol])
            industrial["detected"].append({
                "protocol": INDUSTRIAL_PROTOCOLS[protocol], "port": port, "address": address,
                "product": row.get("product"), "risk": "critical",
            })
        else:
            database = DATABASE_PRODUCTS.get(protocol or "")
            product = row.get("product")
            if database is None and product in SEARCH_PRODUCTS:
                database = (product, SEARCH_PRODUCTS[product])
            if database is None:
                continue
            label, risk = database
            entry = {
                "database": product or label, "port": port, "address": address, "risk": risk,
                "version": row.get("version"), "version_reported": row.get("version_reported"),
                "authentication": row.get("authentication"),
                "authentication_proof": row.get("authentication_proof"),
                # Kept for older readers: True only when the server refused unauthenticated use.
                "authentication_required": row.get("authentication") == si.AUTH_REQUIRED,
            }
            results["database_exposure"]["detected"].append(entry)
            results["database_exposure"]["total_exposed"] += 1
            if row.get("authentication") == si.AUTH_NOT_REQUIRED:
                results["database_exposure"]["unauthenticated"].append(entry["database"])


def _calculate_summary(results: dict[str, Any]) -> None:
    """Calculate summary statistics from scan results."""
    summary = results["summary"]
    by_risk = summary["services_by_risk"]

    def add(risk: str, text: str) -> None:
        summary["total_services"] += 1
        if risk == "critical":
            summary["critical_findings"] += 1
        elif risk == "high":
            summary["high_findings"] += 1
        by_risk[risk].append(text)

    for vpn in results["vpn_services"]["detected"]:
        add("info", f"VPN: {vpn['type']} (port {vpn['port']}/{vpn['transport']})")
    remote = results["remote_desktop"]
    if remote["rdp"]:
        add("high", f"RDP (port {remote['rdp']['port']})")
    for vnc in remote["vnc"]:
        add(vnc["risk"], f"VNC (port {vnc['port']})")
    if remote["ssh"]:
        add("medium", f"SSH (port {remote['ssh']['port']})")
    for other in remote["other"]:
        add(other["risk"], f"{other['service']} (port {other['port']})")
    for iot in results["iot_protocols"]["detected"]:
        add("medium" if iot["encrypted"] else "high", f"{iot['protocol']} (port {iot['port']})")
    for industrial in results["industrial_protocols"]["detected"]:
        add("critical", f"{industrial['protocol']} (port {industrial['port']})")
    for database in results["database_exposure"]["detected"]:
        add(database["risk"], f"{database['database']} (port {database['port']})")


def _auth_sentence(entry: dict[str, Any]) -> str:
    proof = entry.get("authentication_proof")
    if entry.get("authentication") == si.AUTH_REQUIRED and proof:
        return f"The server refused unauthenticated use ({si.AUTHENTICATION_PROOFS[proof]})."
    return f"Unauthenticated access was not shown; {si.AUTH_NOT_TESTED_LABEL} beyond the handshake."


def _finding_id(host: str, kind: str, address: Any, port: Any) -> str:
    """A stable finding id from the host, address and port (never response data)."""
    return "network_services:" + hashlib.md5(f"{kind}_{host}_{address}_{port}".encode()).hexdigest()[:8]


def _generate_findings(results: dict[str, Any]) -> None:
    """Generate security findings from identified services only."""
    findings = []
    host = results["host"]

    def finding_id(kind: str, address: Any, port: Any) -> str:
        return _finding_id(host, kind, address, port)

    for protocol in results["industrial_protocols"]["detected"]:
        findings.append({
            "id": finding_id("industrial", protocol["address"], protocol["port"]),
            "tool": "network_services",
            "title": f"Critical: {protocol['protocol']} Exposed to Internet",
            "severity": "critical",
            "cvss_score": 10.0,
            "cwe": "CWE-284",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": (
                f"{protocol['protocol']} answered a read-only identification request on port "
                f"{protocol['port']}. Industrial protocols have no built-in security and should never be "
                "reachable from the internet."
            ),
            "evidence": {"host": host, "address": protocol["address"], "protocol": protocol["protocol"],
                         "port": protocol["port"], "product": protocol.get("product"),
                         "identity_basis": "protocol_response"},
            "remediation": (
                "Immediately isolate this system from the internet. "
                "Industrial protocols should only be accessible via dedicated, air-gapped networks or VPN."
            ),
        })
    for hint in results["industrial_protocols"]["unconfirmed"]:
        findings.append({
            "id": finding_id("industrial_port", hint["address"], hint["port"]),
            "tool": "network_services",
            "title": f"Open port {hint['port']} conventionally used by {hint['port_hint']} (protocol not confirmed)",
            "severity": "medium",
            "cwe": "CWE-284",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": (
                f"TCP port {hint['port']} accepts connections. It is conventionally used by "
                f"{hint['port_hint']}, but no protocol reply confirmed that; the port number alone is "
                "not an identification."
            ),
            "evidence": {"host": host, "address": hint["address"], "port": hint["port"],
                         "port_hint": hint["port_hint"], "identity_basis": "port_hint"},
            "remediation": "Confirm what listens on this port and restrict it to the networks that need it.",
        })

    for db in results["database_exposure"]["detected"]:
        evidence = {
            "host": host, "address": db["address"], "database": db["database"], "port": db["port"],
            "version": db.get("version"), "version_reported": db.get("version_reported"),
            "authentication": db.get("authentication"),
            "authentication_proof": db.get("authentication_proof"),
            "identity_basis": "protocol_response",
        }
        if db.get("authentication") == si.AUTH_NOT_REQUIRED:
            proof = si.AUTHENTICATION_PROOFS[db["authentication_proof"]]
            findings.append({
                "id": finding_id("unauth_db", db["address"], db["port"]),
                "tool": "network_services",
                "title": f"Unauthenticated {db['database']} Access",
                "severity": "critical",
                "cvss_score": 9.8,
                "cwe": "CWE-306",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "description": (
                    f"{db['database']} on port {db['port']} executed a read-only command without "
                    f"credentials: {proof}. Anyone who can reach it can likely read or change its data."
                ),
                "evidence": evidence,
                "remediation": (
                    f"Enable authentication for {db['database']}. "
                    "Restrict access to trusted networks only. Consider using a firewall."
                ),
            })
            continue
        findings.append({
            "id": finding_id("exposed_db", db["address"], db["port"]),
            "tool": "network_services",
            "title": f"Exposed {db['database']} Service",
            "severity": "high",
            "cvss_score": 7.5,
            "cwe": "CWE-284",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": (
                f"{db['database']} answered its protocol handshake on port {db['port']}. Database "
                f"services should not be reachable from the internet. {_auth_sentence(db)}"
            ),
            "evidence": evidence,
            "remediation": (
                "Restrict database access to application servers only. "
                "Use firewall rules or VPN for remote access."
            ),
        })

    remote = results["remote_desktop"]
    rdp_info = remote.get("rdp")
    if rdp_info:
        nla = "Network Level Authentication is required." if rdp_info.get("nla_required") else (
            "The server accepted TLS-only security, so its login screen is reachable before authentication."
        )
        findings.append({
            "id": finding_id("rdp", rdp_info["address"], rdp_info["port"]),
            "tool": "network_services",
            "title": "RDP Service Exposed to Internet",
            "severity": "high",
            "cvss_score": 7.5,
            "cwe": "CWE-284",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": (
                f"Remote Desktop Protocol answered its connection request on port {rdp_info['port']}. "
                f"{nla} RDP is a common target for brute force attacks and has had critical "
                "vulnerabilities (BlueKeep)."
            ),
            "evidence": {"host": host, "address": rdp_info["address"], "port": rdp_info["port"],
                         "nla_required": rdp_info.get("nla_required"),
                         "authentication": rdp_info.get("authentication")},
            "remediation": (
                "Disable direct RDP access from the internet. "
                "Use VPN, RD Gateway, or Azure AD Proxy for remote access. Enable NLA."
            ),
        })

    for vnc in remote.get("vnc", []):
        open_vnc = vnc.get("authentication") == si.AUTH_NOT_REQUIRED
        findings.append({
            "id": finding_id("vnc", vnc["address"], vnc["port"]),
            "tool": "network_services",
            "title": (f"VNC Without Authentication on Port {vnc['port']}" if open_vnc
                      else f"VNC Service Exposed on Port {vnc['port']}"),
            "severity": "critical" if open_vnc else "high",
            "cvss_score": 9.8 if open_vnc else 7.5,
            "cwe": "CWE-306" if open_vnc else "CWE-284",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": (
                f"VNC answered its handshake on port {vnc['port']}. "
                + ("It accepted the None security type, so a session needs no password."
                   if open_vnc else "VNC has weak encryption and is vulnerable to brute force attacks.")
            ),
            "evidence": {"host": host, "address": vnc["address"], "port": vnc["port"],
                         "protocol_version": (vnc.get("details") or {}).get("protocol_version"),
                         "authentication": vnc.get("authentication"),
                         "authentication_proof": vnc.get("authentication_proof")},
            "remediation": "Disable direct VNC access. Use SSH tunneling or VPN for remote access.",
        })

    for other in remote.get("other", []):
        if other.get("service") == "telnet":
            findings.append({
                "id": finding_id("telnet", other["address"], other["port"]),
                "tool": "network_services",
                "title": "Telnet Service Exposed (Critical)",
                "severity": "critical",
                "cvss_score": 9.8,
                "cwe": "CWE-319",
                "owasp": "A02:2021 - Cryptographic Failures",
                "description": (
                    "A Telnet server negotiated options on this port. Telnet transmits all data "
                    "including credentials in plaintext."
                ),
                "evidence": {"host": host, "address": other["address"], "port": other["port"]},
                "remediation": "Disable Telnet immediately. Use SSH for remote access.",
            })

    for iot in results["iot_protocols"]["detected"]:
        if iot.get("encrypted"):
            continue
        anonymous = iot.get("authentication") == si.AUTH_NOT_REQUIRED
        findings.append({
            "id": finding_id("unenc_iot", iot["address"], iot["port"]),
            "tool": "network_services",
            "title": (f"Unencrypted {iot['protocol']} Broker Accepts Anonymous Clients" if anonymous
                      else f"Unencrypted {iot['protocol']} Service"),
            "severity": "critical" if anonymous else "high",
            "cvss_score": 9.1 if anonymous else 7.5,
            "cwe": "CWE-306" if anonymous else "CWE-319",
            "owasp": "A02:2021 - Cryptographic Failures",
            "description": (
                f"{iot['protocol']} answered without encryption on port {iot['port']}. "
                + ("It accepted a connection without credentials. " if anonymous else "")
                + "Data transmitted over this protocol can be intercepted."
            ),
            "evidence": {"host": host, "address": iot["address"], "protocol": iot["protocol"],
                         "port": iot["port"], "product": iot.get("product"),
                         "authentication": iot.get("authentication"),
                         "authentication_proof": iot.get("authentication_proof")},
            "remediation": f"Enable TLS encryption for {iot['protocol']}. Require authentication.",
        })

    results["findings"] = findings
