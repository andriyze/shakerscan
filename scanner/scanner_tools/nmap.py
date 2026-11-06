import re
from typing import Any

from .common import run

try:
    from .service_identity import port_hint as _conventional_service
except ImportError:  # flat scanner runtime
    from service_identity import port_hint as _conventional_service


def nmap_service_identity(port: int, service_elem_attrs: Any) -> dict[str, Any]:
    """Nmap's service name, kept apart from a port-number guess.

    Nmap names a port from its port table when no probe matched (``method="table"``); that and
    an ``unknown`` result say nothing about what listens there. Such a port is named
    ``unknown`` and the conventional service is kept only as ``port_hint``, which never
    replaces a probed name. A probed name is kept exactly as Nmap reported it.
    """
    attrs = dict(service_elem_attrs or {})
    raw_name = str(attrs.get("name") or "unknown")
    method = str(attrs.get("method") or "")
    identity: dict[str, Any] = {"name": raw_name, "method": method or None}
    if method == "table" or raw_name.lower() in {"unknown", ""}:
        identity["name"] = "unknown"
        hint = (raw_name if method == "table" and raw_name.lower() not in {"unknown", ""} else None) \
            or _conventional_service(port)
        if hint:
            identity["port_hint"] = hint
    return identity


async def nmap_ciphers(host: str, port: int) -> dict[str, Any]:
    out, err, rc = await run(["nmap", "-Pn", "-p", str(port), "--script", "ssl-enum-ciphers", host], timeout=120)
    weak = []
    ciphers_by_protocol: dict[str, list] = {}
    if rc == 0 and out:
        current_protocol = None
        for line in out.splitlines():
            l = line.lstrip('| ').strip()
            proto_match = re.match(r"(TLSv\d+\.\d+|SSLv\d+):?", l)
            if proto_match:
                current_protocol = proto_match.group(1)
                ciphers_by_protocol[current_protocol] = []
                continue
            cipher_match = re.match(r"(TLS_[A-Z0-9_]+|[A-Z0-9_]+_WITH_[A-Z0-9_]+)\s*\([^)]+\)\s*-\s*([A-F])", l)
            if cipher_match and current_protocol:
                cipher_name = cipher_match.group(1)
                grade = cipher_match.group(2)
                is_weak = False
                is_insecure = False
                reason = []
                if re.search(r"\b(NULL|anon|EXPORT|EXP)\b", cipher_name, re.I):
                    is_insecure = True; reason.append("Uses NULL/anonymous/export-grade encryption")
                elif re.search(r"\b(RC4|RC2)\b", cipher_name, re.I):
                    is_insecure = True; reason.append("RC4/RC2 is broken")
                elif re.search(r"\b(DES)\b", cipher_name, re.I) and not re.search(r"\b(3DES)\b", cipher_name, re.I):
                    is_insecure = True; reason.append("DES is broken")
                elif re.search(r"\b(3DES)\b", cipher_name, re.I):
                    is_weak = True; reason.append("3DES is weak")
                elif re.search(r"\bMD5\b", cipher_name, re.I):
                    is_weak = True; reason.append("MD5 is weak")
                elif re.search(r"\bCBC\b", cipher_name, re.I):
                    if "1.0" in current_protocol:
                        is_weak = True; reason.append("CBC mode vulnerable in TLS 1.0 (BEAST)")
                    elif "1.1" in current_protocol:
                        is_weak = True; reason.append("CBC mode has known weaknesses")
                has_forward_secrecy = "ECDHE" in cipher_name or "DHE" in cipher_name or "EDH" in cipher_name
                if not has_forward_secrecy and not ("TLS13" in cipher_name or "AKE" in cipher_name):
                    is_weak = True; reason.append("No forward secrecy")
                if not (is_weak or is_insecure):
                    if "GCM" in cipher_name or "CHACHA20" in cipher_name or "CCM" in cipher_name:
                        reason = ["Modern authenticated encryption with forward secrecy" if has_forward_secrecy else "Modern authenticated encryption"]
                cipher_info = {
                    "name": cipher_name,
                    "grade": grade,
                    "secure": not (is_weak or is_insecure),
                    "weak": is_weak,
                    "insecure": is_insecure,
                    "reason": "; ".join(reason) if reason else None
                }
                ciphers_by_protocol[current_protocol].append(cipher_info)
                if is_weak or is_insecure:
                    weak.append(f"{cipher_name} ({current_protocol})")
    return {"raw": out[:4000] if out else (err or "")[:4000], "weak_indicators": weak, "ciphers_by_protocol": ciphers_by_protocol}


async def nmap_full_scan(
    host: str,
    quick_mode: bool = False,
    top_ports: int | None = None,
    scripts: bool = False,
) -> dict[str, Any]:
    """Comprehensive port and service scanning with Nmap.

    Args:
        host: Target host
        quick_mode: Legacy quick scan profile (top 33 ports)
        top_ports: If set, scan top N ports instead of full port range
        scripts: If True, enable nmap scripts for top-port scans
    """
    results: dict[str, Any] = {
        "open_ports": [],
        "services": [],
        "os_detection": {},
        "vulnerabilities": [],
        "scan_completed": False
    }

    if top_ports is not None:
        # Scale timeout based on port count
        if top_ports <= 50:
            host_timeout = "120s"
            timeout = 180
        elif top_ports <= 200:
            host_timeout = "180s"
            timeout = 300
        elif top_ports <= 1000:
            host_timeout = "300s"
            timeout = 600
        elif top_ports <= 5000:
            host_timeout = "600s"
            timeout = 1200
        else:
            host_timeout = "1200s"
            timeout = 1800

        cmd = [
            "nmap", "-Pn", "--host-timeout", host_timeout, "-sT", "-sV", "-T3",
            "--top-ports", str(top_ports),
            "-oX", "-",
            host,
        ]
        if scripts:
            cmd.extend(["--script", "vuln,discovery,auth"])
        else:
            cmd.extend(["--version-intensity", "5"])
    elif quick_mode:
        cmd = [
            "nmap", "-Pn", "--host-timeout", "120s", "-sT", "-sV", "-T4",
            "--top-ports", "33",  # Fast: top 33 ports only for smart/quick scans
            "--version-intensity", "5",
            "-oX", "-",
            host,
        ]
        timeout = 120
    else:
        cmd = [
            "nmap", "-Pn", "--host-timeout", "300s", "-sT", "-sV", "-sC", "-T3",
            "-p-",
            "--version-all",
            "--script", "vuln,discovery,auth",
            "-oX", "-",
            host,
        ]
        timeout = 600

    out, err, rc = await run(cmd, timeout=timeout)

    if rc == 0 and out:
        from defusedxml import ElementTree as ET
        try:
            root = ET.fromstring(out)
            for host_elem in root.findall(".//host"):
                for port_elem in host_elem.findall(".//port"):
                    port_id = port_elem.get("portid")
                    protocol = port_elem.get("protocol")
                    state_elem = port_elem.find("state")
                    if state_elem is not None and state_elem.get("state") == "open":
                        port_info: dict[str, Any] = {
                            "port": int(port_id),
                            "protocol": protocol,
                            "state": "open",
                        }
                        service_elem = port_elem.find("service")
                        if service_elem is not None:
                            identity = nmap_service_identity(int(port_id), service_elem.attrib)
                            service_info = {
                                "name": identity["name"],
                                "product": service_elem.get("product", ""),
                                "version": service_elem.get("version", ""),
                                "extrainfo": service_elem.get("extrainfo", ""),
                                "port": int(port_id),
                                "method": identity["method"],
                            }
                            if identity.get("port_hint"):
                                service_info["port_hint"] = identity["port_hint"]
                            results["services"].append(service_info)
                            port_info["service"] = service_info["name"]
                        results["open_ports"].append(port_info)
            results["scan_completed"] = True
        except ET.ParseError:
            # Fallback regex parsing of normal output: it does not say how a name was found, so
            # only an explicit "unknown" is turned into a port hint.
            port_pattern = re.compile(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?')
            for match in port_pattern.finditer(out):
                port_num = int(match.group(1))
                identity = nmap_service_identity(port_num, {"name": match.group(3)})
                version_info = match.group(4) or ""
                port_info = {
                    "port": port_num,
                    "protocol": match.group(2),
                    "service": identity["name"],
                }
                results["open_ports"].append(port_info)
                # Also populate services array for consistency
                service_info = {
                    "name": identity["name"],
                    "port": port_num,
                    "version": version_info.strip() if version_info else "",
                }
                if identity.get("port_hint"):
                    service_info["port_hint"] = identity["port_hint"]
                results["services"].append(service_info)
            if results["open_ports"]:
                results["scan_completed"] = True
    return results


async def comprehensive_port_scan(host: str, max_ports: int = 1000) -> dict[str, Any]:
    """Complete mode: Comprehensive port scanning with all 65535 ports or limited by max_ports."""
    results: dict[str, Any] = {
        "scan_type": "comprehensive",
        "open_ports": [],
        "services": [],
        "vulnerabilities": [],
        "scan_completed": False,
        "errors": [],
    }

    # Build port argument correctly as separate list items
    if max_ports >= 65535:
        port_args = ["-p-"]
    else:
        port_args = ["--top-ports", str(max_ports)]

    # Scale timeout based on port count
    # ~3s per 1000 ports minimum for TCP connect + service detection
    if max_ports >= 65535:
        host_timeout = "1800s"  # 30 min for full port scan
    elif max_ports >= 10000:
        host_timeout = "600s"   # 10 min
    else:
        host_timeout = "120s"   # 2 min for top-1000 (default)

    cmd = [
        "nmap", "-Pn", "--host-timeout", host_timeout, "-sT", "-sV", "-T3",
        *port_args,
        "--version-light",  # Faster than --version-all
        "-oX", "-",
        host,
    ]

    out, err, rc = await run(cmd, timeout=1800)
    if rc != 0:
        results["errors"].append(f"nmap returned code {rc}")
        if err:
            results["errors"].append(f"stderr: {err[:300]}")
    if rc == 0 and out:
        from defusedxml import ElementTree as ET
        try:
            root = ET.fromstring(out)
            for host_elem in root.findall(".//host"):
                for port_elem in host_elem.findall(".//port"):
                    port_id = port_elem.get("portid")
                    state_elem = port_elem.find("state")
                    if state_elem is not None and state_elem.get("state") == "open":
                        results["open_ports"].append({
                            "port": int(port_id),
                            "protocol": port_elem.get("protocol"),
                            "state": "open",
                        })
            results["scan_completed"] = True
        except Exception:
            pass
    return results
