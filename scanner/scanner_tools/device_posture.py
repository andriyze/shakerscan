"""Connected-device network posture scanner.

This module is intentionally independent from the Web DAST CLI.  It inventories
one authorized network locator, evaluates observed services against a device
policy, and identifies concrete HTTP(S) origins for an isolated Web DAST handoff.
It never creates Web DAST targets and never performs credential guessing.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import ssl
import urllib.parse
from dataclasses import dataclass
from typing import Any

try:
    from defusedxml import ElementTree as ET
except ImportError:  # pragma: no cover - minimal host test environment
    from xml.etree import ElementTree as ET

try:
    from .common import run
    from .ssh_scanner import full_ssh_scan
except ImportError:  # pragma: no cover - flat scanner runtime
    from common import run
    from ssh_scanner import full_ssh_scan


DEVICE_PROFILES = {"inventory", "posture", "thorough"}
COMMON_UDP_PORTS = (53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 1900, 4500, 5353, 5683, 47808)
WEB_SERVICE_NAMES = {"http", "https", "http-proxy", "http-alt", "ssl/http", "https-alt"}
SSH_SERVICE_NAMES = {"ssh", "ssh-alt"}
_HTTP_STATUS = re.compile(rb"^HTTP/(?:1\.[01]|2(?:\.0)?)\s+\d{3}\b", re.I)
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$")


@dataclass(frozen=True)
class DeviceScanProfile:
    name: str
    tcp_args: tuple[str, ...]
    udp_ports: tuple[int, ...]
    host_timeout: str
    process_timeout: int
    web_probe_cap: int


PROFILES = {
    "inventory": DeviceScanProfile("inventory", ("--top-ports", "100"), COMMON_UDP_PORTS[:8], "180s", 240, 20),
    "posture": DeviceScanProfile("posture", ("-p-",), COMMON_UDP_PORTS, "900s", 960, 64),
    "thorough": DeviceScanProfile("thorough", ("-p-",), COMMON_UDP_PORTS, "1200s", 1260, 128),
}


def normalize_device_locator(value: Any) -> str:
    """Return one safe hostname or IP literal; ranges and URLs are rejected."""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("device locator is required")
    if "://" in raw or any(ch in raw for ch in "/?#@"):
        raise ValueError("device locator must be one hostname or IP address, not a URL or range")
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        candidate = raw.rstrip(".").lower()
        if not _HOST_RE.fullmatch(candidate):
            raise ValueError("device locator must be one valid hostname or IP address")
        return candidate


def _service_from_element(port_elem: Any) -> dict[str, Any]:
    port = int(port_elem.get("portid"))
    transport = str(port_elem.get("protocol") or "tcp").lower()
    state_elem = port_elem.find("state")
    state = str(state_elem.get("state") if state_elem is not None else "unknown")
    service_elem = port_elem.find("service")
    service_name = str(service_elem.get("name") if service_elem is not None else "unknown").lower()
    tunnel = str(service_elem.get("tunnel") if service_elem is not None else "").lower()
    if tunnel == "ssl" and service_name == "http":
        service_name = "https"
    cp = service_elem.find("cpe") if service_elem is not None else None
    return {
        "transport": transport,
        "port": port,
        "state": state,
        "service_name": service_name or "unknown",
        "product": str(service_elem.get("product") or "") if service_elem is not None else "",
        "version": str(service_elem.get("version") or "") if service_elem is not None else "",
        "extra_info": str(service_elem.get("extrainfo") or "") if service_elem is not None else "",
        "tunnel": tunnel or None,
        "cpe": str(cp.text or "") if cp is not None else None,
    }


def parse_nmap_services(xml_text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    services: list[dict[str, Any]] = []
    identity: dict[str, Any] = {"hostnames": [], "addresses": [], "os_matches": []}
    if not xml_text.strip():
        return services, identity
    root = ET.fromstring(xml_text)
    for host_elem in root.findall(".//host"):
        for address in host_elem.findall("address"):
            identity["addresses"].append({
                "address": address.get("addr"),
                "type": address.get("addrtype"),
                "vendor": address.get("vendor"),
            })
        for hostname in host_elem.findall("./hostnames/hostname"):
            if hostname.get("name"):
                identity["hostnames"].append(hostname.get("name"))
        for osmatch in host_elem.findall("./os/osmatch")[:5]:
            identity["os_matches"].append({"name": osmatch.get("name"), "accuracy": osmatch.get("accuracy")})
        for port_elem in host_elem.findall("./ports/port"):
            service = _service_from_element(port_elem)
            if service["state"] in {"open", "open|filtered"}:
                services.append(service)
    services.sort(key=lambda row: (row["transport"], row["port"]))
    return services, identity


async def _nmap_scan(locator: str, profile: DeviceScanProfile) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    receipts: list[dict[str, Any]] = []
    tcp_cmd = [
        "nmap", "-Pn", "-n", "-sT", "-sV", "--version-intensity", "5",
        "--host-timeout", profile.host_timeout, *profile.tcp_args, "-oX", "-", locator,
    ]
    tcp_out, tcp_err, tcp_rc = await run(tcp_cmd, timeout=profile.process_timeout)
    receipts.append({"transport": "tcp", "exit_code": tcp_rc, "stderr": tcp_err[:500]})
    if tcp_rc != 0 and not tcp_out:
        raise RuntimeError(f"TCP inventory failed: {tcp_err.strip() or f'nmap exited {tcp_rc}'}")
    services, identity = parse_nmap_services(tcp_out)

    if profile.udp_ports:
        udp_cmd = [
            "nmap", "-Pn", "-n", "-sU", "-sV", "--version-intensity", "3",
            "--max-retries", "1", "--host-timeout", "240s",
            "-p", ",".join(str(port) for port in profile.udp_ports), "-oX", "-", locator,
        ]
        udp_out, udp_err, udp_rc = await run(udp_cmd, timeout=300)
        receipts.append({"transport": "udp", "exit_code": udp_rc, "stderr": udp_err[:500]})
        if udp_out:
            udp_services, udp_identity = parse_nmap_services(udp_out)
            services.extend(udp_services)
            for key in ("hostnames", "addresses", "os_matches"):
                identity[key] = identity.get(key, []) or udp_identity.get(key, [])

    deduped = {(row["transport"], row["port"]): row for row in services}
    return sorted(deduped.values(), key=lambda row: (row["transport"], row["port"])), identity, receipts


def _format_origin_host(locator: str) -> str:
    try:
        return f"[{locator}]" if ipaddress.ip_address(locator).version == 6 else locator
    except ValueError:
        return locator


async def _probe_http(locator: str, port: int, *, tls: bool, server_name: str | None = None, timeout: float = 3.0) -> dict[str, Any] | None:
    ssl_context = None
    if tls:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                locator,
                port,
                ssl=ssl_context,
                server_hostname=(server_name or locator) if tls else None,
            ),
            timeout=timeout,
        )
        host_header = server_name or _format_origin_host(locator)
        request = f"HEAD / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: ShakerScan-Device/1\r\nConnection: close\r\n\r\n"
        writer.write(request.encode("ascii", "ignore"))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        ssl_object = writer.get_extra_info("ssl_object")
        peer_cert = ssl_object.getpeercert() if ssl_object else None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        if not _HTTP_STATUS.match(data):
            return None
        status_line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        origin = f"{'https' if tls else 'http'}://{_format_origin_host(locator)}:{port}"
        return {
            "origin": origin,
            "scheme": "https" if tls else "http",
            "connect_address": locator,
            "host_header": host_header,
            "sni": (server_name or locator) if tls else None,
            "port": port,
            "status_line": status_line,
            "tls": tls,
            "peer_certificate_present": bool(peer_cert),
        }
    except (TimeoutError, OSError, ssl.SSLError, asyncio.IncompleteReadError):
        return None


async def detect_web_origins(locator: str, services: list[dict[str, Any]], *, cap: int = 64, advertised_name: str | None = None) -> list[dict[str, Any]]:
    """Detect HTTP on any open TCP port, independently of the port number."""
    tcp_services = [row for row in services if row.get("transport") == "tcp" and row.get("state") == "open"][:cap]
    semaphore = asyncio.Semaphore(8)

    async def probe(service: dict[str, Any]) -> dict[str, Any] | None:
        async with semaphore:
            port = int(service["port"])
            hint = str(service.get("service_name") or "").lower()
            tls_first = bool(service.get("tunnel") == "ssl" or hint in {"https", "ssl/http"})
            order = (True, False) if tls_first else (False, True)
            for use_tls in order:
                found = await _probe_http(locator, port, tls=use_tls, server_name=advertised_name)
                if found:
                    found["detected_service"] = hint or "unknown"
                    return found
            return None

    results = await asyncio.gather(*(probe(service) for service in tcp_services))
    origins = [result for result in results if result]
    origins.sort(key=lambda item: (item["port"], item["scheme"]))
    return origins


def _rule_matches(rule: dict[str, Any], service: dict[str, Any]) -> bool:
    transport = str(rule.get("transport") or "any").lower()
    if transport not in {"any", str(service.get("transport") or "").lower()}:
        return False
    ports = rule.get("ports")
    if isinstance(ports, list) and int(service.get("port") or 0) not in {int(port) for port in ports}:
        return False
    expected = str(rule.get("service") or "any").lower()
    actual = str(service.get("service_name") or "unknown").lower()
    if expected not in {"any", actual}:
        return False
    encrypted = rule.get("encrypted")
    if encrypted is not None and bool(service.get("encrypted")) != bool(encrypted):
        return False
    return True


def evaluate_service_policy(services: list[dict[str, Any]], rules: list[dict[str, Any]], *, policy_name: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evaluated: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for original in services:
        service = dict(original)
        matching = next((rule for rule in rules if _rule_matches(rule, service)), None)
        action = str((matching or {}).get("action") or "review").lower()
        reason = str((matching or {}).get("reason") or "No allowlist rule matched this listening service.")
        service["policy_disposition"] = action
        service["policy_reason"] = reason
        evaluated.append(service)
        if action not in {"deny", "review"}:
            continue
        severity = str((matching or {}).get("severity") or ("high" if action == "deny" else "medium"))
        transport = service.get("transport")
        port = service.get("port")
        name = service.get("service_name") or "unknown"
        fingerprint = hashlib.sha256(f"device-policy|{transport}|{port}|{name}|{action}".encode()).hexdigest()
        findings.append({
            "fingerprint": fingerprint,
            "title": f"{action.title()} device service: {name} on {port}/{transport}",
            "description": reason,
            "severity": severity,
            "tool": "device_policy",
            "source": "device",
            "cwe": "CWE-284",
            "evidence": {"service": service, "policy_name": policy_name, "disposition": action},
            "remediation": "Disable the service or update the approved device policy with a narrowly scoped exception.",
        })
    return evaluated, findings


def _score(findings: list[dict[str, Any]], *, complete: bool) -> tuple[int, str]:
    weights = {"critical": 30, "high": 18, "medium": 8, "low": 3, "info": 0}
    score = max(0, 100 - sum(weights.get(str(item.get("severity") or "info").lower(), 0) for item in findings))
    if not complete:
        score = min(score, 69)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return score, grade


async def run_device_posture_scan(locator: str, options: dict[str, Any]) -> dict[str, Any]:
    locator = normalize_device_locator(locator)
    profile_name = str(options.get("device_profile") or "posture").lower()
    if profile_name not in DEVICE_PROFILES:
        raise ValueError(f"device_profile must be one of: {', '.join(sorted(DEVICE_PROFILES))}")
    if not options.get("confirm_authorized"):
        raise ValueError("connected-device scans require confirm_authorized=true")
    profile = PROFILES[profile_name]
    services, identity, tool_receipts = await _nmap_scan(locator, profile)
    advertised_name = next(iter(identity.get("hostnames") or []), None)
    web_origins = await detect_web_origins(locator, services, cap=profile.web_probe_cap, advertised_name=advertised_name)
    origin_by_port = {int(origin["port"]): origin for origin in web_origins}
    for service in services:
        origin = origin_by_port.get(int(service["port"])) if service.get("transport") == "tcp" else None
        if origin:
            service["service_name"] = "https" if origin["tls"] else "http"
            service["encrypted"] = bool(origin["tls"])
            service["web_origin"] = origin["origin"]
        elif service.get("tunnel") == "ssl":
            service["encrypted"] = True

    ssh_findings: list[dict[str, Any]] = []
    for service in services:
        if service.get("transport") != "tcp" or str(service.get("service_name") or "").lower() not in SSH_SERVICE_NAMES:
            continue
        ssh_result = await full_ssh_scan(locator, port=int(service["port"]), timeout=8)
        service["ssh"] = {key: value for key, value in ssh_result.items() if key != "findings"}
        for finding in ssh_result.get("findings") or []:
            finding = dict(finding)
            finding.setdefault("tool", "device_ssh")
            finding["source"] = "device"
            ssh_findings.append(finding)

    policy = options.get("device_policy") if isinstance(options.get("device_policy"), dict) else {}
    policy_name = str(policy.get("name") or "connected-device-default-v1")
    rules = policy.get("rules") if isinstance(policy.get("rules"), list) else []
    services, policy_findings = evaluate_service_policy(services, rules, policy_name=policy_name)
    findings = policy_findings + ssh_findings
    tcp_receipt = next((item for item in tool_receipts if item["transport"] == "tcp"), {})
    udp_receipt = next((item for item in tool_receipts if item["transport"] == "udp"), {})
    complete = tcp_receipt.get("exit_code") == 0 and (not profile.udp_ports or udp_receipt.get("exit_code") == 0)
    score, grade = _score(findings, complete=complete)
    blocking = [item for item in findings if item.get("severity") in {"critical", "high"}]
    decision = "block" if blocking else "allow" if complete else "needs_review"
    rationale = (
        f"{len(blocking)} high/critical device posture finding(s) require remediation."
        if blocking else "Observed services conform to policy." if complete else "Inventory was incomplete and requires review."
    )
    return {
        "target": locator,
        "result": {"score": score, "grade": grade},
        "findings": findings,
        "device_posture": {
            "schema_version": "device-posture/v1",
            "profile": profile_name,
            "identity": identity,
            "services": services,
            "web_origins": web_origins,
            "policy": {"name": policy_name, "rules_count": len(rules)},
            "decision": {"decision": decision, "rationale": rationale, "policy_name": policy_name},
            "completeness": {
                "complete": complete,
                "tcp_scope": "all_65535" if "-p-" in profile.tcp_args else "top_100",
                "udp_ports_requested": list(profile.udp_ports),
                "tool_receipts": tool_receipts,
                "web_probe_cap": profile.web_probe_cap,
                "web_probe_truncated": len([s for s in services if s.get("transport") == "tcp" and s.get("state") == "open"]) > profile.web_probe_cap,
            },
        },
        "scan_metadata": {"run_kind": "device_posture", "active_testing": False, "credentials_attempted": False},
    }
