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
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

try:
    from defusedxml import ElementTree as ET
except ImportError:  # pragma: no cover - minimal host test environment
    from xml.etree import ElementTree as ET

try:
    from .common import run
    from .device_evidence import build_device_evidence_graph
    from .device_protocols import discover_core_device_protocols
    from .device_safety import DeviceSafetyGovernor, check_device_health, validate_safety_request
    from .ssh_scanner import full_ssh_scan
except ImportError:  # pragma: no cover - flat scanner runtime
    from common import run
    from device_evidence import build_device_evidence_graph
    from device_protocols import discover_core_device_protocols
    from device_safety import DeviceSafetyGovernor, check_device_health, validate_safety_request
    from ssh_scanner import full_ssh_scan


DEVICE_PROFILES = {"inventory", "posture", "thorough"}
MAX_FINGERPRINT_PORTS = 512
DEFAULT_PROFILE_BUDGET_SECONDS = {"inventory": 120 * 60, "posture": 360 * 60, "thorough": 720 * 60}
COMMON_UDP_PORTS = (53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 1900, 4500, 5353, 5683, 47808)
INVENTORY_UDP_PORTS = (53, 123, 161, 1900, 5353, 5683, 47808, 67)
PRIORITY_TCP_PORTS = (
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 554,
    631, 1883, 2323, 3000, 5000, 5357, 5683, 7000, 8000, 8008, 8009,
    8060, 8080, 8081, 8088, 8443, 8883, 8888, 9000, 9080, 9100, 9197,
    49152,
)
SSH_SERVICE_NAMES = {"ssh", "ssh-alt"}
_HTTP_STATUS = re.compile(rb"^HTTP/(?:1\.[01]|2(?:\.0)?)\s+\d{3}\b", re.I)
_TIMEOUT_TEXT = re.compile(r"(?:host\s+)?timed?\s*out|host-timeout", re.I)
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$")
KNOWN_POLICY_REQUIREMENTS = {"encrypted", "password_auth", "weak_algorithms", "publickey_auth"}


@dataclass(frozen=True)
class DeviceScanProfile:
    name: str
    tcp_args: tuple[str, ...]
    udp_ports: tuple[int, ...]
    host_timeout: str
    process_timeout: int
    web_probe_cap: int
    fingerprint_intensity: int
    fingerprint_timeout: int


PROFILES = {
    "inventory": DeviceScanProfile("inventory", ("--top-ports", "100"), INVENTORY_UDP_PORTS, "180s", 240, 20, 3, 180),
    "posture": DeviceScanProfile("posture", ("-p-",), COMMON_UDP_PORTS, "900s", 960, 64, 5, 300),
    "thorough": DeviceScanProfile("thorough", ("-p-",), COMMON_UDP_PORTS, "1200s", 1260, 128, 7, 600),
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
        labels = candidate.split(".")
        legacy_ip_shaped = all(
            re.fullmatch(r"(?:0x[0-9a-f]+|0[0-7]+|[0-9]+)", label) is not None
            for label in labels
        )
        try:
            socket.inet_aton(candidate)
            legacy_ip_shaped = True
        except OSError:
            pass
        if legacy_ip_shaped:
            raise ValueError("device locator must use canonical IPv4 or IPv6 notation")
        return candidate


async def resolve_device_address(locator: str, *, timeout: float = 5.0) -> str:
    """Resolve once so every stage stays pinned to one authorized address."""
    try:
        return str(ipaddress.ip_address(locator))
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(locator, None, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
    except (TimeoutError, OSError, socket.gaierror) as exc:
        raise ValueError(f"device locator could not be resolved: {type(exc).__name__}") from exc
    addresses = []
    for info in infos:
        try:
            address = str(ipaddress.ip_address(str(info[4][0]).split("%", 1)[0]))
        except (ValueError, IndexError, TypeError):
            continue
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError("device locator resolved to no usable IP address")
    addresses.sort(key=lambda value: (ipaddress.ip_address(value).version, value))
    return addresses[0]


def _service_from_element(port_elem: Any) -> dict[str, Any]:
    port = int(port_elem.get("portid"))
    transport = str(port_elem.get("protocol") or "tcp").lower()
    state_elem = port_elem.find("state")
    state = str(state_elem.get("state") if state_elem is not None else "unknown")
    state_reason = str(state_elem.get("reason") if state_elem is not None else "")
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
        "state_reason": state_reason or None,
        "service_name": service_name or "unknown",
        "product": str(service_elem.get("product") or "") if service_elem is not None else "",
        "version": str(service_elem.get("version") or "") if service_elem is not None else "",
        "extra_info": str(service_elem.get("extrainfo") or "") if service_elem is not None else "",
        "tunnel": tunnel or None,
        "cpe": str(cp.text or "") if cp is not None else None,
    }


def parse_nmap_evidence(
    xml_text: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Parse confirmed services, inconclusive observations, identity, and run status.

    Nmap's UDP ``open|filtered`` state means that no response was received.  It
    is useful inventory evidence, but it is not proof of a listening service.
    Only an explicit ``open`` state is eligible for service policy evaluation.
    """
    services: list[dict[str, Any]] = []
    inconclusive: list[dict[str, Any]] = []
    identity: dict[str, Any] = {"hostnames": [], "addresses": [], "os_matches": []}
    scan_status: dict[str, Any] = {
        "xml_parsed": False,
        "complete": False,
        "finished_exit": None,
        "summary": None,
        "elapsed_seconds": None,
        "host_count": 0,
        "host_timed_out": False,
        "port_state_counts": {},
        "tcp_filtered_count": 0,
        "udp_extraports_inconclusive_count": 0,
        "malformed_port_count": 0,
        "incomplete_reasons": [],
    }
    if not xml_text.strip():
        scan_status["incomplete_reasons"].append("empty_nmap_output")
        return services, inconclusive, identity, scan_status
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, ValueError) as exc:
        scan_status["incomplete_reasons"].append(f"invalid_nmap_xml:{type(exc).__name__}")
        return services, inconclusive, identity, scan_status
    scan_status["xml_parsed"] = True
    finished = root.find("./runstats/finished")
    if finished is not None:
        scan_status["finished_exit"] = finished.get("exit")
        scan_status["summary"] = finished.get("summary")
        try:
            scan_status["elapsed_seconds"] = float(finished.get("elapsed")) if finished.get("elapsed") else None
        except (TypeError, ValueError):
            pass
    else:
        scan_status["incomplete_reasons"].append("missing_nmap_runstats")
    for host_elem in root.findall(".//host"):
        scan_status["host_count"] += 1
        timed_out = str(host_elem.get("timedout") or "").strip().lower()
        if timed_out not in {"", "0", "false", "no"}:
            scan_status["host_timed_out"] = True
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
            try:
                service = _service_from_element(port_elem)
            except (TypeError, ValueError, AttributeError):
                scan_status["malformed_port_count"] += 1
                if "malformed_nmap_port" not in scan_status["incomplete_reasons"]:
                    scan_status["incomplete_reasons"].append("malformed_nmap_port")
                continue
            state = str(service["state"])
            scan_status["port_state_counts"][state] = int(scan_status["port_state_counts"].get(state, 0)) + 1
            if service["transport"] == "tcp" and state in {"filtered", "open|filtered"}:
                scan_status["tcp_filtered_count"] += 1
            if service["state"] == "open":
                service["confidence"] = "confirmed"
                service["policy_eligible"] = True
                services.append(service)
            elif service["state"] == "open|filtered":
                service["confidence"] = "inconclusive"
                service["policy_eligible"] = False
                service["observation_reason"] = (
                    "No protocol response or ICMP unreachable message was received; "
                    "the port may be open or filtered."
                )
                inconclusive.append(service)
        scan_protocols = {
            str(item.get("protocol") or "").lower()
            for item in root.findall("./scaninfo")
            if item.get("protocol")
        }
        scan_protocol = next(iter(scan_protocols)) if len(scan_protocols) == 1 else ""
        for extra in host_elem.findall("./ports/extraports"):
            state = str(extra.get("state") or "unknown")
            try:
                count = max(0, int(extra.get("count") or 0))
            except (TypeError, ValueError):
                count = 0
            scan_status["port_state_counts"][state] = int(scan_status["port_state_counts"].get(state, 0)) + count
            if scan_protocol == "tcp" and state in {"filtered", "open|filtered"}:
                scan_status["tcp_filtered_count"] += count
            if scan_protocol == "udp" and state == "open|filtered":
                # Nmap normally collapses silent UDP ports into <extraports>.
                # They have the same uncertainty as individually listed
                # open|filtered ports, but do not have port ids that can be
                # promoted by a protocol-specific response.
                scan_status["udp_extraports_inconclusive_count"] += count
    if scan_status["host_timed_out"]:
        scan_status["incomplete_reasons"].append("nmap_host_timeout")
    if scan_status["finished_exit"] not in {"success", None}:
        scan_status["incomplete_reasons"].append(f"nmap_exit:{scan_status['finished_exit']}")
    scan_status["complete"] = bool(
        scan_status["xml_parsed"]
        and finished is not None
        and scan_status["finished_exit"] == "success"
        and not scan_status["host_timed_out"]
    )
    services.sort(key=lambda row: (row["transport"], row["port"]))
    inconclusive.sort(key=lambda row: (row["transport"], row["port"]))
    return services, inconclusive, identity, scan_status


def parse_nmap_services(xml_text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Compatibility parser returning confirmed-open services only."""
    services, _inconclusive, identity, _scan_status = parse_nmap_evidence(xml_text)
    return services, identity


def _merge_identity(current: dict[str, Any], incoming: dict[str, Any]) -> None:
    for key in ("hostnames", "addresses", "os_matches"):
        existing = current.setdefault(key, [])
        for item in incoming.get(key) or []:
            if item not in existing:
                existing.append(item)


def _merge_services(current: dict[tuple[str, int], dict[str, Any]], services: list[dict[str, Any]]) -> None:
    for service in services:
        key = (str(service.get("transport") or "tcp"), int(service["port"]))
        previous = current.get(key, {})
        merged = dict(previous)
        for field, value in service.items():
            if value is not None and value != "" or field not in merged:
                merged[field] = value
        merged["state"] = "open"
        merged["confidence"] = "confirmed"
        merged["policy_eligible"] = True
        current[key] = merged


def merge_protocol_confirmations(
    services: list[dict[str, Any]],
    inconclusive: list[dict[str, Any]],
    protocol_results: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Promote UDP service state only when a protocol adapter received a valid response."""
    by_key = {(str(item.get("transport") or "tcp"), int(item["port"])): dict(item) for item in services}
    uncertain = {(str(item.get("transport") or "udp"), int(item["port"])): dict(item) for item in inconclusive}
    for protocol in protocol_results:
        if not isinstance(protocol, dict) or not protocol.get("confirmed"):
            continue
        transport = str(protocol.get("transport") or "udp")
        port = int(protocol.get("port") or 0)
        if not 1 <= port <= 65535:
            continue
        name = str(protocol.get("protocol") or "unknown")
        responses = list(protocol.get("responses") or [])
        product = ""
        if name == "ssdp" and responses:
            product = str((responses[0] or {}).get("server") or "")[:500]
        current = by_key.get((transport, port), {})
        current.update({
            "transport": transport,
            "port": port,
            "state": "open",
            "state_reason": "application-response",
            "service_name": "upnp" if name == "ssdp" else name,
            "product": current.get("product") or product,
            "confidence": "validated",
            "policy_eligible": True,
            "protocol_evidence": {
                "protocol": name,
                "response_count": len(responses),
                "responses": responses,
            },
        })
        by_key[(transport, port)] = current
        uncertain.pop((transport, port), None)
    return (
        sorted(by_key.values(), key=lambda row: (str(row.get("transport")), int(row.get("port") or 0))),
        sorted(uncertain.values(), key=lambda row: (str(row.get("transport")), int(row.get("port") or 0))),
    )


async def _run_nmap_stage(
    cmd: list[str],
    *,
    stage: str,
    transport: str,
    timeout: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    stdout, stderr, exit_code = await run(cmd, timeout=timeout)
    services, inconclusive, identity, scan_status = parse_nmap_evidence(stdout)
    incomplete_reasons = list(scan_status.get("incomplete_reasons") or [])
    if exit_code != 0:
        incomplete_reasons.append(f"process_exit:{exit_code}")
    if _TIMEOUT_TEXT.search(stderr or "") and "nmap_host_timeout" not in incomplete_reasons:
        incomplete_reasons.append("nmap_timeout_reported")
    complete = bool(exit_code == 0 and scan_status.get("complete") and not incomplete_reasons)
    receipt = {
        "stage": stage,
        "transport": transport,
        "exit_code": exit_code,
        "complete": complete,
        "xml_parsed": bool(scan_status.get("xml_parsed")),
        "finished_exit": scan_status.get("finished_exit"),
        "host_timed_out": bool(scan_status.get("host_timed_out")),
        "elapsed_seconds": scan_status.get("elapsed_seconds"),
        "confirmed_open_count": len(services),
        "inconclusive_count": len(inconclusive),
        "port_state_counts": dict(scan_status.get("port_state_counts") or {}),
        "tcp_filtered_count": int(scan_status.get("tcp_filtered_count") or 0),
        "udp_extraports_inconclusive_count": int(
            scan_status.get("udp_extraports_inconclusive_count") or 0
        ),
        "malformed_port_count": int(scan_status.get("malformed_port_count") or 0),
        "incomplete_reasons": list(dict.fromkeys(incomplete_reasons)),
        "stderr": (stderr or "")[:500],
    }
    return services, inconclusive, identity, receipt


async def _nmap_scan(
    locator: str,
    profile: DeviceScanProfile,
    *,
    deadline: float | None = None,
    cancel_check: Any = None,
    max_requests_per_second: float = 10.0,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    services_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    observations_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    identity: dict[str, Any] = {"hostnames": [], "addresses": [], "os_matches": []}

    async def ensure_active(stage: str) -> bool:
        if callable(cancel_check) and bool(await cancel_check()):
            raise ValueError(f"connected-device scan cancelled before {stage}")
        return deadline is None or time.monotonic() < deadline

    request_rate = max(1.0, float(max_requests_per_second or 1.0))
    rate_args = ["--max-rate", f"{request_rate:g}"]

    await ensure_active("TCP priority discovery")
    priority_cmd = [
        "nmap", "-Pn", "-n", "-sT", "-T4", "--max-retries", "1", *rate_args,
        "--host-timeout", "180s", "-p", ",".join(str(port) for port in PRIORITY_TCP_PORTS),
        "-oX", "-", locator,
    ]
    priority_services, _priority_uncertain, priority_identity, priority_receipt = await _run_nmap_stage(
        priority_cmd, stage="tcp_priority_discovery", transport="tcp", timeout=210,
    )
    priority_receipt["required"] = False
    receipts.append(priority_receipt)
    _merge_services(services_by_key, priority_services)
    _merge_identity(identity, priority_identity)

    await ensure_active("TCP scope discovery")
    scope_port_count = 65_535 if "-p-" in profile.tcp_args else 100
    rate_bound_timeout = int(scope_port_count / request_rate * 1.5) + 60
    tcp_stage_timeout = max(profile.process_timeout, rate_bound_timeout)
    if deadline is not None:
        tcp_stage_timeout = max(60, min(tcp_stage_timeout, int(max(60, deadline - time.monotonic()))))
    tcp_cmd = [
        "nmap", "-Pn", "-n", "-sT", "-T4", "--max-retries", "1", *rate_args,
        "--host-timeout", f"{max(30, tcp_stage_timeout - 15)}s", *profile.tcp_args, "-oX", "-", locator,
    ]
    tcp_services, _tcp_uncertain, tcp_identity, tcp_receipt = await _run_nmap_stage(
        tcp_cmd, stage="tcp_scope_discovery", transport="tcp", timeout=tcp_stage_timeout,
    )
    receipts.append(tcp_receipt)
    tcp_receipt["required"] = True
    _merge_services(services_by_key, tcp_services)
    _merge_identity(identity, tcp_identity)

    discovered_tcp_ports = sorted(port for (transport, port) in services_by_key if transport == "tcp")
    priority_set = set(PRIORITY_TCP_PORTS)
    tcp_ports = sorted(discovered_tcp_ports, key=lambda port: (port not in priority_set, port))[:MAX_FINGERPRINT_PORTS]
    fingerprint_truncated_count = max(0, len(discovered_tcp_ports) - len(tcp_ports))
    fingerprint_budget_exhausted = False
    fingerprint_receipts: list[dict[str, Any]] = []
    for batch_number, offset in enumerate(range(0, len(tcp_ports), 128), start=1):
        if not await ensure_active(f"TCP fingerprint batch {batch_number}"):
            fingerprint_budget_exhausted = True
            break
        batch = tcp_ports[offset:offset + 128]
        fingerprint_cmd = [
            "nmap", "-Pn", "-n", "-sT", "-sV", "--version-intensity", str(profile.fingerprint_intensity), *rate_args,
            "--host-timeout", f"{profile.fingerprint_timeout}s", "-p", ",".join(str(port) for port in batch),
            "-oX", "-", locator,
        ]
        fingerprinted, _uncertain, fingerprint_identity, receipt = await _run_nmap_stage(
            fingerprint_cmd,
            stage=f"tcp_service_fingerprint_{batch_number}",
            transport="tcp",
            timeout=profile.fingerprint_timeout + 30,
        )
        receipts.append(receipt)
        receipt["required"] = True
        fingerprint_receipts.append(receipt)
        _merge_services(services_by_key, fingerprinted)
        _merge_identity(identity, fingerprint_identity)

    udp_budget_exhausted = False
    if profile.udp_ports and await ensure_active("UDP discovery"):
        udp_cmd = [
            "nmap", "-Pn", "-n", "-sU", "-sV", "--version-intensity", "3", *rate_args,
            "--max-retries", "1", "--host-timeout", "240s",
            "-p", ",".join(str(port) for port in profile.udp_ports), "-oX", "-", locator,
        ]
        udp_services, udp_observations, udp_identity, udp_receipt = await _run_nmap_stage(
            udp_cmd, stage="udp_service_discovery", transport="udp", timeout=300,
        )
        receipts.append(udp_receipt)
        udp_receipt["required"] = True
        _merge_services(services_by_key, udp_services)
        _merge_identity(identity, udp_identity)
        for observation in udp_observations:
            observations_by_key[("udp", int(observation["port"]))] = observation
    elif profile.udp_ports:
        udp_budget_exhausted = True
        receipts.append({
            "stage": "udp_service_discovery",
            "transport": "udp",
            "exit_code": None,
            "complete": False,
            "required": True,
            "incomplete_reasons": ["overall_device_budget_exhausted"],
            "confirmed_open_count": 0,
            "inconclusive_count": 0,
        })

    if not any(receipt.get("xml_parsed") for receipt in receipts if receipt.get("transport") == "tcp"):
        errors = "; ".join(
            str(receipt.get("stderr") or ",".join(receipt.get("incomplete_reasons") or []))
            for receipt in receipts if receipt.get("transport") == "tcp"
        )
        raise RuntimeError(f"TCP inventory failed: {errors or 'Nmap returned no parseable result'}")

    udp_receipts = [receipt for receipt in receipts if receipt.get("transport") == "udp"]
    execution_complete = bool(
            tcp_receipt.get("complete")
            and all(receipt.get("complete") for receipt in fingerprint_receipts)
            and all(receipt.get("complete") for receipt in udp_receipts)
            and not fingerprint_truncated_count
            and not fingerprint_budget_exhausted
            and not udp_budget_exhausted
    )
    tcp_filtered_count = int(tcp_receipt.get("tcp_filtered_count") or 0)
    udp_extraports_inconclusive_count = sum(
        int(receipt.get("udp_extraports_inconclusive_count") or 0)
        for receipt in udp_receipts
    )
    tcp_visibility_complete = bool(tcp_receipt.get("complete") and tcp_filtered_count == 0)
    uncertainty_present = bool(
        observations_by_key or tcp_filtered_count or udp_extraports_inconclusive_count
    )
    incomplete_stages = [
        receipt["stage"] for receipt in receipts
        if receipt.get("required", True) and not receipt.get("complete")
    ]
    if tcp_filtered_count:
        incomplete_stages.append("tcp_scope_visibility")
    if observations_by_key or udp_extraports_inconclusive_count:
        incomplete_stages.append("udp_service_uncertainty")
    if fingerprint_truncated_count:
        incomplete_stages.append("tcp_fingerprint_truncated")
    if fingerprint_budget_exhausted or udp_budget_exhausted:
        incomplete_stages.append("overall_device_budget_exhausted")
    completeness = {
        "complete": bool(execution_complete and not uncertainty_present),
        "execution_complete": execution_complete,
        "tcp_discovery_complete": bool(tcp_receipt.get("complete")),
        "tcp_visibility_complete": tcp_visibility_complete,
        "tcp_filtered_ports_count": tcp_filtered_count,
        "tcp_fingerprinting_complete": bool(
            not fingerprint_truncated_count
            and not fingerprint_budget_exhausted
            and all(receipt.get("complete") for receipt in fingerprint_receipts)
        ),
        "tcp_fingerprint_port_cap": MAX_FINGERPRINT_PORTS,
        "tcp_fingerprint_truncated_count": fingerprint_truncated_count,
        "overall_budget_exhausted": bool(fingerprint_budget_exhausted or udp_budget_exhausted),
        "max_requests_per_second_enforced": request_rate,
        "udp_discovery_complete": all(receipt.get("complete") for receipt in udp_receipts),
        "udp_extraports_inconclusive_count": udp_extraports_inconclusive_count,
        "uncertainty_present": uncertainty_present,
        "incomplete_stages": incomplete_stages,
    }
    return (
        sorted(services_by_key.values(), key=lambda row: (row["transport"], row["port"])),
        sorted(observations_by_key.values(), key=lambda row: (row["transport"], row["port"])),
        identity,
        receipts,
        completeness,
    )


def _format_origin_host(locator: str) -> str:
    try:
        return f"[{locator}]" if ipaddress.ip_address(locator).version == 6 else locator
    except ValueError:
        return locator


async def _probe_http(
    connect_address: str,
    port: int,
    *,
    tls: bool,
    origin_locator: str | None = None,
    timeout: float = 3.0,
) -> dict[str, Any] | None:
    ssl_context = None
    if tls:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                connect_address,
                port,
                ssl=ssl_context,
                server_hostname=(origin_locator or connect_address) if tls else None,
            ),
            timeout=timeout,
        )
        host_header = _format_origin_host(
            normalize_device_locator(origin_locator or connect_address)
        )
        request = f"HEAD / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: ShakerScan-Device/1\r\nConnection: close\r\n\r\n"
        writer.write(request.encode("ascii", "ignore"))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        ssl_object = writer.get_extra_info("ssl_object")
        peer_cert = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        if not _HTTP_STATUS.match(data):
            return None
        status_line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        origin = f"{'https' if tls else 'http'}://{_format_origin_host(origin_locator or connect_address)}:{port}"
        return {
            "origin": origin,
            "scheme": "https" if tls else "http",
            "connect_address": connect_address,
            "host_header": host_header,
            "sni": (origin_locator or connect_address) if tls else None,
            "port": port,
            "status_line": status_line,
            "tls": tls,
            "peer_certificate_present": bool(peer_cert),
        }
    except (TimeoutError, OSError, ssl.SSLError, asyncio.IncompleteReadError):
        return None


async def detect_web_origins(
    connect_address: str,
    services: list[dict[str, Any]],
    *,
    cap: int = 64,
    origin_locator: str | None = None,
    max_concurrency: int = 8,
    max_requests_per_second: float = 10.0,
) -> list[dict[str, Any]]:
    """Detect HTTP on any open TCP port, independently of the port number."""
    tcp_services = [row for row in services if row.get("transport") == "tcp" and row.get("state") == "open"][:cap]
    semaphore = asyncio.Semaphore(max(1, int(max_concurrency)))
    rate_lock = asyncio.Lock()
    request_interval = 1.0 / max(0.1, float(max_requests_per_second))
    next_request_at = 0.0

    async def wait_for_rate_slot() -> None:
        nonlocal next_request_at
        async with rate_lock:
            now = time.monotonic()
            delay = max(0.0, next_request_at - now)
            if delay:
                await asyncio.sleep(delay)
            next_request_at = max(now, next_request_at) + request_interval

    async def probe(service: dict[str, Any]) -> dict[str, Any] | None:
        async with semaphore:
            port = int(service["port"])
            hint = str(service.get("service_name") or "").lower()
            tls_first = bool(service.get("tunnel") == "ssl" or hint in {"https", "ssl/http"})
            order = (True, False) if tls_first else (False, True)
            for use_tls in order:
                await wait_for_rate_slot()
                found = await _probe_http(
                    connect_address,
                    port,
                    tls=use_tls,
                    origin_locator=origin_locator,
                )
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
    # ``require`` rules select the service first and evaluate controls below.
    # For allow/deny/review, encryption remains part of the selector.
    if str(rule.get("action") or "").lower() != "require" and encrypted is not None and bool(service.get("encrypted")) != bool(encrypted):
        return False
    return True


def _requirement_failures(rule: dict[str, Any], service: dict[str, Any]) -> list[str]:
    requirements = rule.get("requirements") if isinstance(rule.get("requirements"), dict) else {}
    failures: list[str] = []
    unknown = sorted(set(requirements) - KNOWN_POLICY_REQUIREMENTS)
    if unknown:
        failures.append("unknown policy requirements: " + ", ".join(unknown))
    expected_encrypted = rule.get("encrypted", requirements.get("encrypted"))
    if expected_encrypted is not None and bool(service.get("encrypted")) != bool(expected_encrypted):
        failures.append("service encryption does not match policy")

    ssh = service.get("ssh") if isinstance(service.get("ssh"), dict) else {}
    ssh_requirements = {"password_auth", "weak_algorithms", "publickey_auth"} & set(requirements)
    if ssh_requirements and not ssh.get("scan_completed"):
        failures.append("SSH controls could not be verified")
        return failures
    if requirements.get("password_auth") is False and ssh.get("password_auth_enabled"):
        failures.append("SSH password authentication is enabled")
    if requirements.get("weak_algorithms") is False and ssh.get("weak_algorithms"):
        failures.append("SSH negotiated a weak cryptographic algorithm")
    if requirements.get("publickey_auth") is True and not ssh.get("publickey_enabled"):
        failures.append("SSH public-key authentication was not offered")
    return failures


def evaluate_service_policy(services: list[dict[str, Any]], rules: list[dict[str, Any]], *, policy_name: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evaluated: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for original in services:
        service = dict(original)
        if service.get("state") not in {None, "open"} or service.get("policy_eligible") is False:
            service["policy_disposition"] = "not_evaluated"
            service["policy_reason"] = "The service was not confirmed open and was excluded from policy evaluation."
            evaluated.append(service)
            continue
        matching = next((rule for rule in rules if _rule_matches(rule, service)), None)
        action = str((matching or {}).get("action") or "review").lower()
        reason = str((matching or {}).get("reason") or "No allowlist rule matched this listening service.")
        requirement_failures = _requirement_failures(matching, service) if matching and action == "require" else []
        if requirement_failures:
            reason = "; ".join(requirement_failures) + "."
        service["policy_disposition"] = action
        service["policy_reason"] = reason
        evaluated.append(service)
        if action not in {"deny", "review"} and not requirement_failures:
            continue
        severity = str((matching or {}).get("severity") or ("high" if action == "deny" else "medium"))
        transport = service.get("transport")
        port = service.get("port")
        name = service.get("service_name") or "unknown"
        finding_action = "require" if requirement_failures else action
        fingerprint = hashlib.sha256(f"device-policy|{transport}|{port}|{name}|{finding_action}".encode()).hexdigest()
        findings.append({
            "fingerprint": fingerprint,
            "title": (
                f"Device service requirement not met: {name} on {port}/{transport}"
                if requirement_failures else f"{action.title()} device service: {name} on {port}/{transport}"
            ),
            "description": reason,
            "severity": severity,
            "tool": "device_policy",
            "source": "device",
            "cwe": "CWE-284",
            "evidence": {
                "service": service,
                "policy_name": policy_name,
                "disposition": finding_action,
                "requirement_failures": requirement_failures,
            },
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


def _device_decision(findings: list[dict[str, Any]], *, complete: bool) -> tuple[str, str]:
    blocking: list[dict[str, Any]] = []
    review: list[dict[str, Any]] = []
    for finding in findings:
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        disposition = str(evidence.get("disposition") or "").lower()
        severity = str(finding.get("severity") or "info").lower()
        tool = str(finding.get("tool") or "")
        if disposition in {"deny", "require"} or (tool != "device_policy" and severity in {"critical", "high"}):
            blocking.append(finding)
        elif severity != "info" or disposition == "review":
            review.append(finding)
    if blocking:
        return "block", f"{len(blocking)} blocking device posture finding(s) require remediation."
    if not complete:
        return "needs_review", "One or more required device inventory stages were incomplete."
    if review:
        return "needs_review", f"{len(review)} confirmed device service finding(s) require review."
    return "allow", "Confirmed listening services conform to policy."


async def run_device_posture_scan(locator: str, options: dict[str, Any]) -> dict[str, Any]:
    locator = normalize_device_locator(locator)
    resolved_address = await resolve_device_address(locator)
    profile_name = str(options.get("device_profile") or "posture").lower()
    if profile_name not in DEVICE_PROFILES:
        raise ValueError(f"device_profile must be one of: {', '.join(sorted(DEVICE_PROFILES))}")
    if not options.get("confirm_authorized"):
        raise ValueError("connected-device scans require confirm_authorized=true")
    safety_profile = validate_safety_request(options)
    safety = DeviceSafetyGovernor(safety_profile)
    resolved_budget = options.get("resolved_budget") if isinstance(options.get("resolved_budget"), dict) else {}
    try:
        configured_minutes = int(resolved_budget.get("max_duration_minutes") or 0)
    except (TypeError, ValueError):
        configured_minutes = 0
    budget_seconds = configured_minutes * 60 if configured_minutes > 0 else DEFAULT_PROFILE_BUDGET_SECONDS[profile_name]
    deadline = time.monotonic() + max(60, budget_seconds)
    cancel_check = options.get("_cancel_check")

    async def ensure_active(stage: str) -> bool:
        if callable(cancel_check) and bool(await cancel_check()):
            raise ValueError(f"connected-device scan cancelled before {stage}")
        return time.monotonic() < deadline

    await ensure_active("health baseline")
    safety.authorize("target_health_baseline", "readonly")
    safety.record_health(await check_device_health(resolved_address, stage="baseline"))
    safety.authorize("network_inventory", "readonly")
    safety.record_limit_enforcement(
        "nmap",
        max_concurrency=1,
        max_requests_per_second=safety_profile.max_requests_per_second,
    )
    profile = PROFILES[profile_name]
    services, inconclusive_observations, identity, tool_receipts, scan_completeness = await _nmap_scan(
        resolved_address,
        profile,
        deadline=deadline,
        cancel_check=cancel_check,
        max_requests_per_second=safety_profile.max_requests_per_second,
    )
    safety.authorize("core_protocol_discovery", "readonly")
    if await ensure_active("core protocol discovery"):
        protocol_results = await discover_core_device_protocols(resolved_address, udp_ports=profile.udp_ports)
    else:
        protocol_results = []
        scan_completeness["complete"] = False
        scan_completeness["execution_complete"] = False
        scan_completeness["overall_budget_exhausted"] = True
        scan_completeness.setdefault("incomplete_stages", []).append("overall_device_budget_exhausted")
    for protocol in protocol_results:
        receipt = protocol.get("receipt") if isinstance(protocol.get("receipt"), dict) else None
        if receipt:
            receipt["required"] = False
            tool_receipts.append(receipt)
    services, inconclusive_observations = merge_protocol_confirmations(
        services,
        inconclusive_observations,
        protocol_results,
    )
    tcp_filtered_count = int(scan_completeness.get("tcp_filtered_ports_count") or 0)
    udp_extraports_inconclusive_count = int(
        scan_completeness.get("udp_extraports_inconclusive_count") or 0
    )
    scan_completeness["uncertainty_present"] = bool(
        tcp_filtered_count or udp_extraports_inconclusive_count or inconclusive_observations
    )
    if not inconclusive_observations and not udp_extraports_inconclusive_count:
        scan_completeness["incomplete_stages"] = [
            stage for stage in list(scan_completeness.get("incomplete_stages") or [])
            if stage != "udp_service_uncertainty"
        ]
    scan_completeness["complete"] = bool(
        scan_completeness.get("execution_complete") and not scan_completeness["uncertainty_present"]
    )
    scan_completeness["protocol_discovery_complete"] = all(
        bool((protocol.get("receipt") or {}).get("complete")) for protocol in protocol_results
    )
    known_tcp_ports = [
        int(service["port"])
        for service in services
        if service.get("transport") == "tcp" and service.get("state") == "open"
    ]
    if await ensure_active("post-inventory health check"):
        safety.record_health(await check_device_health(resolved_address, stage="post_inventory", tcp_ports=known_tcp_ports))
    safety.authorize("web_origin_discovery", "readonly")
    safety.record_limit_enforcement(
        "web_origin_probes",
        max_concurrency=safety_profile.max_concurrency,
        max_requests_per_second=safety_profile.max_requests_per_second,
    )
    if await ensure_active("web origin discovery"):
        web_origins = await detect_web_origins(
            resolved_address,
            services,
            cap=profile.web_probe_cap,
            origin_locator=locator,
            max_concurrency=safety_profile.max_concurrency,
            max_requests_per_second=safety_profile.max_requests_per_second,
        )
    else:
        web_origins = []
        scan_completeness["complete"] = False
        scan_completeness["execution_complete"] = False
        scan_completeness["overall_budget_exhausted"] = True
        scan_completeness.setdefault("incomplete_stages", []).append("overall_device_budget_exhausted")
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
    if await ensure_active("post-web health check"):
        safety.record_health(
            await check_device_health(resolved_address, stage="post_web_discovery", tcp_ports=known_tcp_ports)
        )
    if safety.halted:
        scan_completeness["complete"] = False
        scan_completeness["execution_complete"] = False
        scan_completeness["safety_halted"] = True
        scan_completeness.setdefault("incomplete_stages", []).append("device_health_degraded")
    else:
        safety.authorize("ssh_posture_handshake", "readonly")
        for service in services:
            if service.get("transport") != "tcp" or str(service.get("service_name") or "").lower() not in SSH_SERVICE_NAMES:
                continue
            if not await ensure_active("SSH posture"):
                scan_completeness["complete"] = False
                scan_completeness["execution_complete"] = False
                scan_completeness["overall_budget_exhausted"] = True
                scan_completeness.setdefault("incomplete_stages", []).append("overall_device_budget_exhausted")
                break
            ssh_result = await full_ssh_scan(resolved_address, port=int(service["port"]), timeout=8)
            service["ssh"] = {key: value for key, value in ssh_result.items() if key != "findings"}
            for finding in ssh_result.get("findings") or []:
                finding = dict(finding)
                finding.setdefault("tool", "device_ssh")
                finding["source"] = "device"
                ssh_findings.append(finding)

    safety.record_health(await check_device_health(resolved_address, stage="final", tcp_ports=known_tcp_ports))
    safety_receipt = safety.receipt()
    if safety.halted:
        scan_completeness["complete"] = False
        scan_completeness["safety_halted"] = True
        scan_completeness.setdefault("incomplete_stages", []).append("device_health_degraded")

    policy = options.get("device_policy") if isinstance(options.get("device_policy"), dict) else {}
    policy_name = str(policy.get("name") or "connected-device-default-v1")
    rules = policy.get("rules") if isinstance(policy.get("rules"), list) else []
    services, policy_findings = evaluate_service_policy(services, rules, policy_name=policy_name)
    findings = policy_findings + ssh_findings
    complete = bool(scan_completeness.get("complete"))
    execution_complete = bool(scan_completeness.get("execution_complete", complete))
    score, grade = _score(findings, complete=execution_complete)
    decision, rationale = _device_decision(findings, complete=complete)
    evidence_graph = build_device_evidence_graph(
        locator=locator,
        identity=identity,
        services=services,
        inconclusive_observations=inconclusive_observations,
        web_origins=web_origins,
        protocol_observations=protocol_results,
        tool_receipts=tool_receipts,
        safety_receipt=safety_receipt,
    )
    return {
        "target": locator,
        "resolved_target": resolved_address,
        "result": {"score": score, "grade": grade},
        "findings": findings,
        "device_posture": {
            "schema_version": "device-posture/v1",
            "profile": profile_name,
            "identity": identity,
            "resolved_target": resolved_address,
            "services": services,
            "inconclusive_observations": inconclusive_observations,
            "web_origins": web_origins,
            "protocols": protocol_results,
            "policy": {"name": policy_name, "rules_count": len(rules)},
            "decision": {"decision": decision, "rationale": rationale, "policy_name": policy_name},
            "safety": safety_receipt,
            "evidence_graph": evidence_graph,
            "completeness": {
                "complete": complete,
                "tcp_scope": "all_65535" if "-p-" in profile.tcp_args else "top_100",
                "tcp_priority_ports": list(PRIORITY_TCP_PORTS),
                "udp_ports_requested": list(profile.udp_ports),
                "confirmed_services_count": len(services),
                "inconclusive_observations_count": len(inconclusive_observations),
                "tool_receipts": tool_receipts,
                "web_probe_cap": profile.web_probe_cap,
                "web_probe_truncated": len([s for s in services if s.get("transport") == "tcp" and s.get("state") == "open"]) > profile.web_probe_cap,
                **scan_completeness,
            },
        },
        "scan_metadata": {
            "run_kind": "device_posture",
            "active_testing": False,
            "credentials_attempted": False,
            "device_coverage_profile": profile_name,
            "device_safety_profile": safety_profile.name,
        },
    }
