import re
from typing import Any

from .common import run

# Well-known port/service mappings for correcting nmap misidentifications
# Maps port numbers to their expected service names
KNOWN_PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb",
}


def correct_service_name(port: int, detected_service: str, version: str = "") -> str:
    """
    Correct common nmap service misidentifications based on well-known ports.
    Only corrects if the detected service is clearly wrong for the port.
    """
    if port not in KNOWN_PORT_SERVICES:
        return detected_service

    expected_service = KNOWN_PORT_SERVICES[port]
    detected_lower = detected_service.lower()

    # Don't correct if nmap already detected it correctly or a valid variant
    if expected_service in detected_lower or detected_lower.startswith(expected_service):
        return detected_service

    # Special case: PostgreSQL on 5432 is often misidentified
    if port == 5432:
        # PostgreSQL versions look like "15.3", "14.0", etc.
        if re.match(r'^\d+\.\d+', version):
            return "postgresql"
        # Common misidentifications for 5432
        if detected_lower in ("nagios-nsca", "unknown", ""):
            return "postgresql"

    # Special case: MySQL on 3306
    if port == 3306:
        if re.match(r'^\d+\.\d+', version):
            return "mysql"
        if detected_lower in ("unknown", ""):
            return "mysql"

    # Special case: MongoDB on 27017
    if port == 27017:
        if detected_lower in ("unknown", ""):
            return "mongodb"

    # Special case: Redis on 6379
    if port == 6379:
        if detected_lower in ("unknown", ""):
            return "redis"

    # General fallback: if detected service is "unknown", use expected
    if detected_lower in ("unknown", ""):
        return expected_service

    return detected_service


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


async def nmap_full_scan(host: str, quick_mode: bool = False) -> dict[str, Any]:
    """Comprehensive port and service scanning with Nmap."""
    results: dict[str, Any] = {
        "open_ports": [],
        "services": [],
        "os_detection": {},
        "vulnerabilities": [],
        "scan_completed": False
    }

    if quick_mode:
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
        import xml.etree.ElementTree as ET
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
                            raw_name = service_elem.get("name", "unknown")
                            version = service_elem.get("version", "")
                            # Correct common misidentifications
                            corrected_name = correct_service_name(int(port_id), raw_name, version)
                            service_info = {
                                "name": corrected_name,
                                "product": service_elem.get("product", ""),
                                "version": version,
                                "extrainfo": service_elem.get("extrainfo", ""),
                                "port": int(port_id),
                            }
                            if raw_name != corrected_name:
                                service_info["original_detection"] = raw_name
                            results["services"].append(service_info)
                            port_info["service"] = service_info["name"]
                        results["open_ports"].append(port_info)
            results["scan_completed"] = True
        except ET.ParseError:
            # Fallback regex parsing - also apply service name correction
            port_pattern = re.compile(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?')
            for match in port_pattern.finditer(out):
                port_num = int(match.group(1))
                raw_service = match.group(3)
                version_info = match.group(4) or ""
                corrected_service = correct_service_name(port_num, raw_service, version_info)
                port_info = {
                    "port": port_num,
                    "protocol": match.group(2),
                    "service": corrected_service,
                }
                results["open_ports"].append(port_info)
                # Also populate services array for consistency
                service_info = {
                    "name": corrected_service,
                    "port": port_num,
                    "version": version_info.strip() if version_info else "",
                }
                if raw_service != corrected_service:
                    service_info["original_detection"] = raw_service
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

    cmd = [
        "nmap", "-Pn", "--host-timeout", "120s", "-sT", "-sV", "-T3",
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
        import xml.etree.ElementTree as ET
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
