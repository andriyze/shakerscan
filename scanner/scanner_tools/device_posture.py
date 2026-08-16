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
import inspect
import json
import math
import os
import re
import shutil
import socket
import ssl
import tempfile
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
    from .device_reachability import (
        REACHABILITY_TCP_PORTS,
        corroborate_device_reachability,
        probe_device_reachability,
        unresolved_reachability,
    )
    from .device_shell import validate_shell_plan
    from .device_protocols import discover_core_device_protocols
    from .device_safety import DeviceSafetyGovernor, check_device_health, validate_safety_request
    from .ssh_scanner import DEFAULT_SSH_HOST_REVIEW_BUNDLES, full_ssh_scan
except ImportError:  # pragma: no cover - flat scanner runtime
    from common import run
    from device_evidence import build_device_evidence_graph
    from device_reachability import (
        REACHABILITY_TCP_PORTS,
        corroborate_device_reachability,
        probe_device_reachability,
        unresolved_reachability,
    )
    from device_shell import validate_shell_plan
    from device_protocols import discover_core_device_protocols
    from device_safety import DeviceSafetyGovernor, check_device_health, validate_safety_request
    from ssh_scanner import DEFAULT_SSH_HOST_REVIEW_BUNDLES, full_ssh_scan


DEVICE_PROFILES = {"inventory", "posture", "thorough"}
MAX_FINGERPRINT_PORTS = 512
NAABU_FULL_TCP_CHUNK_SIZE = 8192
NAABU_MIN_CONNECT_WORKERS = 32
NAABU_MAX_CONNECT_WORKERS = 1024
NAABU_TIMEOUT_MS = 1000
NAABU_RETRY_TIMEOUT_MS = 1500
NAABU_INPUT_READ_TIMEOUT = "1s"
DEFAULT_PROFILE_BUDGET_SECONDS = {"inventory": 120 * 60, "posture": 360 * 60, "thorough": 720 * 60}
COMMON_UDP_PORTS = (53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 1900, 4500, 5353, 5683, 47808)
INVENTORY_UDP_PORTS = (53, 123, 161, 1900, 5353, 5683, 47808, 67)
PRIORITY_TCP_PORTS = (
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 554,
    631, 1883, 2323, 3000, 5000, 5357, 5683, 7000, 8000, 8008, 8009,
    8060, 8080, 8081, 8088, 8443, 8883, 8888, 9000, 9080, 9100, 9197,
    49152,
)
DEVICE_CLASS_TCP_PORTS = {
    "generic": (),
    "media": (
        3001, 5555, 6466, 6467, 7000, 7001, 7100, 7345, 8001, 8002,
        8008, 8009, 8060, 8200, 9080, 9197, 32400, 55000, 56789,
    ),
    "camera": (554, 1935, 5000, 8000, 8554, 8899, 9000, 34567, 37777),
    "printer": (80, 280, 443, 515, 631, 1230, 1782, 1783, 1784, 9100, 9101, 9102, 9220, 9221, 9222, 9280, 9290),
    "router": (21, 22, 23, 53, 80, 443, 445, 548, 873, 2049, 5000, 5001, 6690, 8200),
    "nas": (21, 22, 80, 111, 139, 443, 445, 548, 873, 2049, 3260, 5000, 5001, 6690, 8200, 32400),
    "conference": (80, 443, 554, 1720, 1935, 5060, 5061, 8000, 8443, 8554),
    "building": (80, 102, 443, 502, 1883, 4840, 5683, 8000, 20000, 44818, 47808),
    "industrial": (80, 102, 443, 502, 1883, 4840, 5683, 20000, 44818, 47808),
}
TV_MANUFACTURER_TCP_PORTS = {
    # Vizio SmartCast uses HTTPS/7345 on current firmware and HTTPS/9000 on
    # older firmware generations.
    "vizio": (7345, 9000),
    # LG webOS uses WS/3000 and WSS/3001; 8080 covers older REST generations.
    "lg": (3000, 3001, 8080),
    # Samsung Smart View/Tizen control and service endpoints.
    "samsung": (8000, 8001, 8002, 9197),
    # TCL ships multiple TV platforms, principally Roku and Google/Android TV.
    "tcl": (5555, 6466, 6467, 8008, 8009, 8060),
    # Hisense ships VIDAA plus Google/Android and Roku variants.
    "hisense": (5555, 6466, 6467, 8008, 8009, 8060, 36669),
}
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


def parse_naabu_evidence(output: str, locator: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse Naabu JSONL without treating malformed or silent output as an open port."""
    services: dict[int, dict[str, Any]] = {}
    malformed_lines = 0
    for raw_line in str(output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            port = int(row.get("port"))
        except (json.JSONDecodeError, TypeError, ValueError, AttributeError):
            malformed_lines += 1
            continue
        if not 1 <= port <= 65535:
            malformed_lines += 1
            continue
        services[port] = {
            "transport": "tcp",
            "port": port,
            "state": "open",
            "state_reason": "tcp-connect",
            "service_name": "unknown",
            "product": "",
            "version": "",
            "extra_info": "",
            "tunnel": None,
            "cpe": None,
            "confidence": "confirmed",
            "policy_eligible": True,
            "discovery_tool": "naabu",
        }
    return sorted(services.values(), key=lambda item: int(item["port"])), {
        "parsed": malformed_lines == 0,
        "malformed_line_count": malformed_lines,
        "confirmed_open_count": len(services),
        "identity": {
            "hostnames": [],
            "addresses": [{"address": locator, "type": "ipv6" if ":" in locator else "ipv4", "vendor": None}],
            "os_matches": [],
        },
    }


def _naabu_available() -> bool:
    return bool(shutil.which("naabu") or shutil.which("/opt/tools/naabu"))


def _naabu_connect_workers(rate: float, timeout_ms: int) -> int:
    """Derive enough in-flight connects for the configured rate on silent hosts."""
    required = math.ceil(max(1.0, float(rate)) * max(1, int(timeout_ms)) / 1000.0 * 1.25)
    return max(NAABU_MIN_CONNECT_WORKERS, min(NAABU_MAX_CONNECT_WORKERS, required))


async def _call_stage_callback(callback: Any, payload: dict[str, Any]) -> Any:
    if not callable(callback):
        return None
    result = callback(dict(payload))
    if inspect.isawaitable(result):
        return await result
    return result


def _full_tcp_ranges() -> list[tuple[int, int]]:
    return [
        (start, min(65535, start + NAABU_FULL_TCP_CHUNK_SIZE - 1))
        for start in range(1, 65536, NAABU_FULL_TCP_CHUNK_SIZE)
    ]


async def _run_naabu_chunk(
    locator: str,
    *,
    stage: str,
    port_args: list[str],
    port_count: int,
    rate: int,
    timeout_ms: int,
    process_timeout: int,
    attempt: int,
    required_scope: bool,
    cancel_check: Any = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    workers = _naabu_connect_workers(rate, timeout_ms)
    output_handle = tempfile.NamedTemporaryFile(
        mode="w", prefix="shakerscan-naabu-", suffix=".jsonl", delete=False,
    )
    output_path = output_handle.name
    output_handle.close()
    cmd = [
        "naabu", "-host", locator, "-Pn", "-scan-type", "c", *port_args,
        "-rate", str(rate), "-c", str(workers), "-retries", "1",
        "-timeout", f"{timeout_ms}ms", "-input-read-timeout", NAABU_INPUT_READ_TIMEOUT,
        "-verify", "-json", "-silent", "-no-color",
        "-disable-update-check", "-no-stdin", "-o", output_path,
    ]
    run_options: dict[str, Any] = {"timeout": process_timeout}
    if callable(cancel_check):
        run_options["cancel_check"] = cancel_check
    started = time.monotonic()
    try:
        stdout, stderr, exit_code = await run(cmd, **run_options)
        try:
            with open(output_path, encoding="utf-8", errors="replace") as output_file:
                durable_output = output_file.read()
        except OSError:
            durable_output = ""
    finally:
        try:
            os.unlink(output_path)
        except OSError:
            pass
    evidence_output = durable_output if durable_output.strip() else stdout
    services, parsed = parse_naabu_evidence(evidence_output, locator)
    incomplete_reasons: list[str] = []
    if exit_code != 0:
        incomplete_reasons.append(f"process_exit:{exit_code}")
    if not parsed["parsed"]:
        incomplete_reasons.append("malformed_naabu_jsonl")
    receipt = {
        "stage": stage,
        "tool": "naabu",
        "transport": "tcp",
        "attempt": attempt,
        "required_scope": required_scope,
        "exit_code": exit_code,
        "complete": not incomplete_reasons,
        "parsed": bool(parsed["parsed"]),
        "xml_parsed": False,
        "confirmed_open_count": len(services),
        "partial_output_recovered": bool(exit_code != 0 and durable_output.strip()),
        "inconclusive_count": 0,
        "port_state_counts": {"open": len(services)},
        "silent_port_classification": "closed_or_filtered_not_distinguished",
        "closed_filtered_classification_complete": False,
        "malformed_port_count": int(parsed["malformed_line_count"]),
        "incomplete_reasons": incomplete_reasons,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "rate_limit_per_second": rate,
        "connect_workers": workers,
        "connect_timeout_ms": timeout_ms,
        "input_read_timeout": NAABU_INPUT_READ_TIMEOUT,
        "process_timeout_seconds": process_timeout,
        "port_count": port_count,
        "port_spec": port_args[-1] if port_args else None,
        "scan_type": "connect",
        "stderr": (stderr or "")[:500],
    }
    return services, parsed["identity"], receipt


async def _run_naabu_tcp_scope_discovery(
    locator: str,
    *,
    full_tcp: bool,
    priority_ports: tuple[int, ...],
    deadline: float | None = None,
    cancel_check: Any = None,
    max_port_probes_per_second: float = 250.0,
    stage_callback: Any = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    rate = max(1, int(max_port_probes_per_second or 1))
    priority_spec = ",".join(str(port) for port in sorted(set(priority_ports)))
    chunks: list[dict[str, Any]] = []
    if priority_spec:
        chunks.append({
            "stage": "tcp_priority_discovery", "args": ["-p", priority_spec],
            "count": len(set(priority_ports)), "required": not full_tcp,
        })
    if full_tcp:
        ranges = _full_tcp_ranges()
        for index, (start, end) in enumerate(ranges, start=1):
            chunks.append({
                "stage": f"tcp_scope_range_{index}_of_{len(ranges)}",
                "args": ["-p", f"{start}-{end}"],
                "count": end - start + 1, "required": True,
            })
    else:
        chunks.append({
            "stage": "tcp_scope_top_100", "args": ["-top-ports", "100"],
            "count": 100, "required": True,
        })

    services_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    identity: dict[str, Any] = {"hostnames": [], "addresses": [], "os_matches": []}
    child_receipts: list[dict[str, Any]] = []
    failed_required_stages: list[str] = []
    completed_required_ports = 0
    total_required_ports = sum(int(chunk["count"]) for chunk in chunks if chunk["required"])
    started = time.monotonic()
    halted_by_callback = False

    for index, chunk in enumerate(chunks, start=1):
        if callable(cancel_check) and bool(await cancel_check()):
            raise ValueError(f"connected-device scan cancelled before {chunk['stage']}")
        remaining = int(deadline - time.monotonic()) if deadline is not None else None
        if halted_by_callback or (remaining is not None and remaining < 30):
            reason = "device_health_degraded" if halted_by_callback else "overall_device_budget_exhausted"
            receipt = {
                "stage": chunk["stage"], "tool": "naabu", "transport": "tcp",
                "attempt": 1, "required_scope": bool(chunk["required"]),
                "exit_code": None, "complete": False, "parsed": False,
                "confirmed_open_count": 0, "inconclusive_count": 0,
                "port_count": int(chunk["count"]), "port_spec": chunk["args"][-1],
                "incomplete_reasons": [reason],
            }
            child_receipts.append(receipt)
            if chunk["required"]:
                failed_required_stages.append(str(chunk["stage"]))
            await _call_stage_callback(stage_callback, {
                "kind": "tcp_chunk", "stage": chunk["stage"], "chunk_index": index,
                "chunk_count": len(chunks), "receipt": receipt, "known_tcp_ports": [],
                "skip_health": True,
            })
            continue

        process_timeout = max(45, math.ceil(int(chunk["count"]) / rate * 1.8) + 30)
        if remaining is not None:
            process_timeout = max(20, min(process_timeout, remaining))
        attempt_services, attempt_identity, receipt = await _run_naabu_chunk(
            locator, stage=str(chunk["stage"]), port_args=list(chunk["args"]),
            port_count=int(chunk["count"]), rate=rate, timeout_ms=NAABU_TIMEOUT_MS,
            process_timeout=process_timeout, attempt=1,
            required_scope=bool(chunk["required"]), cancel_check=cancel_check,
        )
        _merge_services(services_by_key, attempt_services)
        _merge_identity(identity, attempt_identity)
        child_receipts.append(receipt)
        final_receipt = receipt

        if not receipt["complete"]:
            remaining = int(deadline - time.monotonic()) if deadline is not None else None
            retry_timeout = max(60, math.ceil(int(chunk["count"]) / rate * 2.25) + 45)
            if remaining is None or remaining >= 30:
                if remaining is not None:
                    retry_timeout = max(20, min(retry_timeout, remaining))
                retry_services, retry_identity, retry_receipt = await _run_naabu_chunk(
                    locator, stage=str(chunk["stage"]), port_args=list(chunk["args"]),
                    port_count=int(chunk["count"]), rate=rate,
                    timeout_ms=NAABU_RETRY_TIMEOUT_MS, process_timeout=retry_timeout,
                    attempt=2, required_scope=bool(chunk["required"]),
                    cancel_check=cancel_check,
                )
                retry_receipt["retry_of_attempt"] = 1
                _merge_services(services_by_key, retry_services)
                _merge_identity(identity, retry_identity)
                child_receipts.append(retry_receipt)
                final_receipt = retry_receipt
        if chunk["required"]:
            if final_receipt["complete"]:
                completed_required_ports += int(chunk["count"])
            else:
                failed_required_stages.append(str(chunk["stage"]))
        callback_result = await _call_stage_callback(stage_callback, {
            "kind": "tcp_chunk", "stage": chunk["stage"], "chunk_index": index,
            "chunk_count": len(chunks), "receipt": final_receipt,
            "known_tcp_ports": sorted(port for (_transport, port) in services_by_key),
        })
        halted_by_callback = callback_result is False

    complete = not failed_required_stages
    services = sorted(services_by_key.values(), key=lambda item: int(item["port"]))
    receipt = {
        "stage": "tcp_scope_discovery",
        "tool": "naabu",
        "transport": "tcp",
        "exit_code": 0 if complete else None,
        "complete": complete,
        "parsed": any(bool(item.get("parsed")) for item in child_receipts),
        "xml_parsed": False,
        "confirmed_open_count": len(services),
        "inconclusive_count": 0,
        "port_state_counts": {"open": len(services)},
        "silent_port_classification": "closed_or_filtered_not_distinguished",
        "closed_filtered_classification_complete": False,
        "reachable_open_port_inventory_complete": complete,
        "malformed_port_count": sum(int(item.get("malformed_port_count") or 0) for item in child_receipts),
        "incomplete_reasons": [f"incomplete_range:{stage}" for stage in failed_required_stages],
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "rate_limit_per_second": rate,
        "scan_type": "connect",
        "scope": "all_tcp" if full_tcp else "top_100_plus_priority",
        "required_port_count": total_required_ports,
        "completed_required_port_count": completed_required_ports,
        "failed_required_stages": failed_required_stages,
        "chunk_receipts": child_receipts,
    }
    return services, [], identity, receipt


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
    cancel_check: Any = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    run_options: dict[str, Any] = {"timeout": timeout}
    if callable(cancel_check):
        run_options["cancel_check"] = cancel_check
    stdout, stderr, exit_code = await run(cmd, **run_options)
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
        "parsed": bool(scan_status.get("xml_parsed")),
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


async def _run_tcp_scope_discovery(
    locator: str,
    profile: DeviceScanProfile,
    *,
    deadline: float | None = None,
    cancel_check: Any = None,
    max_requests_per_second: float = 10.0,
    max_port_probes_per_second: float = 250.0,
    extra_priority_ports: tuple[int, ...] = (),
    stage_callback: Any = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Run Naabu as the authoritative TCP discovery engine.

    Nmap is deliberately not an all-port fallback. On filtered devices that
    path can take hours; missing Naabu is instead an explicit readiness error.
    """
    del max_requests_per_second
    priority_ports = tuple(sorted(
        set(PRIORITY_TCP_PORTS)
        | set(REACHABILITY_TCP_PORTS)
        | {int(port) for port in extra_priority_ports if 1 <= int(port) <= 65535}
    ))
    if not _naabu_available():
        return [], [], {"hostnames": [], "addresses": [], "os_matches": []}, {
            "stage": "tcp_scope_discovery", "tool": "naabu", "transport": "tcp",
            "exit_code": None, "complete": False, "parsed": False,
            "confirmed_open_count": 0, "inconclusive_count": 0,
            "silent_port_classification": "not_scanned",
            "closed_filtered_classification_complete": False,
            "reachable_open_port_inventory_complete": False,
            "incomplete_reasons": ["naabu_unavailable"], "chunk_receipts": [],
        }
    return await _run_naabu_tcp_scope_discovery(
        locator,
        full_tcp="-p-" in profile.tcp_args,
        priority_ports=priority_ports,
        deadline=deadline,
        cancel_check=cancel_check,
        max_port_probes_per_second=max_port_probes_per_second,
        stage_callback=stage_callback,
    )


async def _nmap_scan(
    locator: str,
    profile: DeviceScanProfile,
    *,
    deadline: float | None = None,
    cancel_check: Any = None,
    max_requests_per_second: float = 10.0,
    max_port_probes_per_second: float = 250.0,
    extra_priority_ports: tuple[int, ...] = (),
    stage_callback: Any = None,
    prefetched_tcp_scope: tuple[
        list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]
    ] | None = None,
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

    priority_ports = tuple(sorted(
        set(PRIORITY_TCP_PORTS)
        | set(REACHABILITY_TCP_PORTS)
        | {int(port) for port in extra_priority_ports if 1 <= int(port) <= 65535}
    ))
    if prefetched_tcp_scope is None:
        await ensure_active("TCP scope discovery")
        tcp_services, _tcp_uncertain, tcp_identity, tcp_receipt = await _run_tcp_scope_discovery(
            locator,
            profile,
            deadline=deadline,
            cancel_check=cancel_check,
            max_requests_per_second=request_rate,
            max_port_probes_per_second=max_port_probes_per_second,
            extra_priority_ports=extra_priority_ports,
            stage_callback=stage_callback,
        )
    else:
        tcp_services, _tcp_uncertain, tcp_identity, original_receipt = prefetched_tcp_scope
        tcp_receipt = dict(original_receipt)
        tcp_receipt["reused_from_reachability_fallback"] = True
    for child_receipt in tcp_receipt.get("chunk_receipts") or []:
        child_evidence = dict(child_receipt)
        child_evidence["required"] = False
        receipts.append(child_evidence)
    receipts.append(tcp_receipt)
    tcp_receipt["required"] = True
    _merge_services(services_by_key, tcp_services)
    _merge_identity(identity, tcp_identity)

    discovered_tcp_ports = sorted(port for (transport, port) in services_by_key if transport == "tcp")
    priority_set = set(priority_ports)
    tcp_ports = sorted(discovered_tcp_ports, key=lambda port: (port not in priority_set, port))[:MAX_FINGERPRINT_PORTS]
    fingerprint_truncated_count = max(0, len(discovered_tcp_ports) - len(tcp_ports))
    fingerprint_budget_exhausted = False
    fingerprint_receipts: list[dict[str, Any]] = []
    fingerprint_stage_allowed = (await _call_stage_callback(stage_callback, {
        "kind": "phase", "stage": "device_service_fingerprinting",
        "known_tcp_ports": discovered_tcp_ports,
    })) is not False
    fingerprint_stage_halted = not fingerprint_stage_allowed
    for batch_number, offset in enumerate(range(0, len(tcp_ports), 128), start=1):
        if not fingerprint_stage_allowed:
            break
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
            cancel_check=cancel_check,
        )
        receipts.append(receipt)
        receipt["required"] = True
        fingerprint_receipts.append(receipt)
        _merge_services(services_by_key, fingerprinted)
        _merge_identity(identity, fingerprint_identity)

    udp_budget_exhausted = False
    udp_stage_allowed = (await _call_stage_callback(stage_callback, {
        "kind": "phase", "stage": "device_udp_discovery",
        "known_tcp_ports": discovered_tcp_ports,
    })) is not False
    udp_stage_halted = not udp_stage_allowed
    if profile.udp_ports and udp_stage_allowed and await ensure_active("UDP discovery"):
        udp_cmd = [
            "nmap", "-Pn", "-n", "-sU", "-sV", "--version-intensity", "3", *rate_args,
            "--max-retries", "1", "--host-timeout", "240s",
            "-p", ",".join(str(port) for port in profile.udp_ports), "-oX", "-", locator,
        ]
        udp_services, udp_observations, udp_identity, udp_receipt = await _run_nmap_stage(
            udp_cmd, stage="udp_service_discovery", transport="udp", timeout=300,
            cancel_check=cancel_check,
        )
        receipts.append(udp_receipt)
        udp_receipt["required"] = True
        _merge_services(services_by_key, udp_services)
        _merge_identity(identity, udp_identity)
        for observation in udp_observations:
            observations_by_key[("udp", int(observation["port"]))] = observation
    elif profile.udp_ports:
        udp_budget_exhausted = not udp_stage_halted
        receipts.append({
            "stage": "udp_service_discovery",
            "transport": "udp",
            "exit_code": None,
            "complete": False,
            "required": True,
            "incomplete_reasons": [
                "device_health_degraded" if udp_stage_halted else "overall_device_budget_exhausted"
            ],
            "confirmed_open_count": 0,
            "inconclusive_count": 0,
        })

    if not any(receipt.get("parsed") or receipt.get("xml_parsed") for receipt in receipts if receipt.get("transport") == "tcp"):
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
            and not fingerprint_stage_halted
            and not udp_stage_halted
    )
    tcp_filtered_count = int(tcp_receipt.get("tcp_filtered_count") or 0)
    udp_extraports_inconclusive_count = sum(
        int(receipt.get("udp_extraports_inconclusive_count") or 0)
        for receipt in udp_receipts
    )
    tcp_visibility_complete = bool(
        tcp_receipt.get("complete")
        and tcp_receipt.get("reachable_open_port_inventory_complete")
    )
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
    if fingerprint_stage_halted or udp_stage_halted:
        incomplete_stages.append("device_health_degraded")
    completeness = {
        "complete": bool(execution_complete and not uncertainty_present),
        "execution_complete": execution_complete,
        "tcp_discovery_complete": bool(tcp_receipt.get("complete")),
        "tcp_visibility_complete": tcp_visibility_complete,
        "tcp_filtered_ports_count": tcp_filtered_count,
        "tcp_closed_filtered_classification_complete": bool(
            tcp_receipt.get("closed_filtered_classification_complete")
        ),
        "tcp_silent_port_classification": tcp_receipt.get("silent_port_classification"),
        "tcp_scope": tcp_receipt.get("scope"),
        "tcp_required_port_count": tcp_receipt.get("required_port_count"),
        "tcp_completed_required_port_count": tcp_receipt.get("completed_required_port_count"),
        "tcp_fingerprinting_complete": bool(
            not fingerprint_truncated_count
            and not fingerprint_budget_exhausted
            and not fingerprint_stage_halted
            and all(receipt.get("complete") for receipt in fingerprint_receipts)
        ),
        "tcp_fingerprint_port_cap": MAX_FINGERPRINT_PORTS,
        "tcp_fingerprint_truncated_count": fingerprint_truncated_count,
        "overall_budget_exhausted": bool(fingerprint_budget_exhausted or udp_budget_exhausted),
        "safety_halted": bool(fingerprint_stage_halted or udp_stage_halted),
        "max_requests_per_second_enforced": request_rate,
        "max_port_probes_per_second_enforced": max_port_probes_per_second,
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
    if ssh_requirements and (
        not ssh.get("scan_completed") or not ssh.get("auth_methods_complete")
    ):
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


def _reachability_checkpoint(reachability: dict[str, Any], *, stage: str) -> dict[str, Any]:
    status = str(reachability.get("status") or "inconclusive")
    signals = reachability.get("positive_signals") if isinstance(reachability.get("positive_signals"), dict) else {}
    return {
        "stage": stage,
        "status": "healthy" if status == "online" else "degraded" if status == "unreachable" else "indeterminate",
        "reachability_status": status,
        "resolution_succeeded": bool(reachability.get("resolution_succeeded")),
        "addresses": [reachability.get("resolved_address")] if reachability.get("resolved_address") else [],
        "attempted_tcp_ports": sorted({
            int(probe.get("port"))
            for attempt in reachability.get("attempts") or [] if isinstance(attempt, dict)
            for probe in attempt.get("tcp_probes") or [] if isinstance(probe, dict) and probe.get("port") is not None
        }),
        "responsive_tcp_ports": sorted(set(
            [int(port) for port in signals.get("tcp_open_ports") or []]
            + [int(port) for port in signals.get("tcp_refused_ports") or []]
        )),
        "reason": reachability.get("reason"),
    }


def _reachability_only_result(
    *,
    locator: str,
    resolved_address: str | None,
    profile_name: str,
    profile: DeviceScanProfile,
    safety: DeviceSafetyGovernor,
    reachability: dict[str, Any],
    resolved_credentials: list[dict[str, Any]],
    requested_capabilities: list[str],
    policy_name: str,
    policy_rules_count: int,
) -> dict[str, Any]:
    """Return an explicit no-score result when the device never proves it is online."""
    incomplete_stage = (
        "device_unreachable"
        if reachability.get("status") == "unreachable"
        else "device_reachability_inconclusive"
    )
    completeness = {
        "complete": False,
        "execution_complete": False,
        "reachability_confirmed": False,
        "reachability_status": reachability.get("status"),
        "tcp_scope": "all_65535" if "-p-" in profile.tcp_args else "top_100",
        "tcp_priority_ports": list(PRIORITY_TCP_PORTS),
        "udp_ports_requested": list(profile.udp_ports),
        "confirmed_services_count": 0,
        "inconclusive_observations_count": 0,
        "tool_receipts": [],
        "incomplete_stages": [incomplete_stage],
        "web_probe_cap": profile.web_probe_cap,
        "web_probe_truncated": False,
    }
    safety_receipt = safety.receipt()
    evidence_graph = build_device_evidence_graph(
        locator=locator,
        identity={"hostnames": [], "addresses": [], "os_matches": []},
        services=[],
        inconclusive_observations=[],
        web_origins=[],
        protocol_observations=[],
        tool_receipts=[],
        safety_receipt=safety_receipt,
        reachability=reachability,
    )
    return {
        "target": locator,
        "resolved_target": resolved_address,
        "result": {"score": None, "grade": None},
        "findings": [],
        "device_posture": {
            "schema_version": "device-posture/v1",
            "profile": profile_name,
            "identity": {"hostnames": [], "addresses": [], "os_matches": []},
            "resolved_target": resolved_address,
            "reachability": reachability,
            "services": [],
            "inconclusive_observations": [],
            "web_origins": [],
            "protocols": [],
            "policy": {"name": policy_name, "rules_count": policy_rules_count},
            "decision": {
                "decision": "needs_review",
                "rationale": reachability.get("reason"),
                "policy_name": policy_name,
            },
            "safety": safety_receipt,
            "evidence_graph": evidence_graph,
            "capability_coverage": [
                {"capability_id": "scope-safety-health", "status": "failed"},
                {"capability_id": "device-identity-attack-surface", "status": "blocked", "reason": incomplete_stage},
                {"capability_id": "tcp-udp-network-discovery", "status": "blocked", "reason": incomplete_stage},
                {"capability_id": "service-fingerprinting-crypto", "status": "blocked", "reason": incomplete_stage},
                {"capability_id": "evidence-correlation-reporting", "status": "completed"},
            ],
            "requested_capabilities": requested_capabilities,
            "completeness": completeness,
        },
        "scan_metadata": {
            "run_kind": "device_posture",
            "active_testing": False,
            "credentials_attempted": False,
            "device_coverage_profile": profile_name,
            "device_safety_profile": safety.profile.name,
            "device_reachability_status": reachability.get("status"),
            "credential_profile_refs": [
                {"role": item.get("role"), "profile_id": item.get("profile_id"), "auth_kind": item.get("auth_kind")}
                for item in resolved_credentials
            ],
        },
    }


async def run_device_posture_scan(locator: str, options: dict[str, Any]) -> dict[str, Any]:
    locator = normalize_device_locator(locator)
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
    progress_callback = options.get("_progress_callback")
    resolved_credentials = [
        dict(item) for item in options.get("_resolved_device_credentials", [])
        if isinstance(item, dict)
    ]
    if resolved_credentials and not safety_profile.credentials_allowed:
        raise ValueError(f"device credentials are forbidden by safety profile {safety_profile.name}")
    ssh_credentials = [item for item in resolved_credentials if item.get("role") == "ssh"]
    requested_capabilities = list(dict.fromkeys(
        str(item or "").strip().lower()
        for item in options.get("device_capability_ids", [])
        if str(item or "").strip()
    ))
    unsupported_capabilities = [
        item for item in requested_capabilities
        if item not in {"ssh-authenticated-host-review", "agent-confirmed-ssh-shell"}
    ]
    if unsupported_capabilities:
        raise ValueError("unsupported executable device capability: " + ", ".join(unsupported_capabilities))
    if {"ssh-authenticated-host-review", "agent-confirmed-ssh-shell"}.intersection(requested_capabilities) and not ssh_credentials:
        raise ValueError("requested SSH capability requires an SSH credential profile")
    shell_plan = None
    if "agent-confirmed-ssh-shell" in requested_capabilities:
        shell_plan = validate_shell_plan(options.get("device_shell_plan"))
        if (
            shell_plan.get("confirmation_basis") != "explicit_user_exact_command_confirmation"
            or shell_plan.get("confirmed_plan_digest") != shell_plan.get("plan_digest")
            or not shell_plan.get("confirmed_at")
        ):
            raise ValueError("agent-confirmed-ssh-shell requires exact user confirmation")
    credential_priority_ports = {
        int(item.get("port"))
        for item in ssh_credentials
        if item.get("port") is not None and 1 <= int(item.get("port")) <= 65535
    } | ({int(shell_plan["ssh_port"])} if shell_plan else set())
    expected_ssh_host_keys = {
        int(port): str(fingerprint)
        for port, fingerprint in (options.get("expected_ssh_host_keys") or {}).items()
        if str(port).isdigit() and 1 <= int(port) <= 65535 and str(fingerprint).startswith("SHA256:")
    }
    profile = PROFILES[profile_name]
    policy = options.get("device_policy") if isinstance(options.get("device_policy"), dict) else {}
    policy_name = str(policy.get("name") or "connected-device-default-v1")
    rules = policy.get("rules") if isinstance(policy.get("rules"), list) else []
    hint_payload = (
        options.get("device_reachability_port_hints")
        if isinstance(options.get("device_reachability_port_hints"), dict)
        else {}
    )

    def valid_ports(values: Any) -> list[int]:
        result: list[int] = []
        for raw_port in values if isinstance(values, (list, tuple, set)) else []:
            try:
                port = int(raw_port)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535 and port not in result:
                result.append(port)
        return result

    policy_ports = [
        port
        for rule in rules if isinstance(rule, dict) and str(rule.get("transport") or "any") in {"any", "tcp"}
        for port in valid_ports(rule.get("ports"))
    ]
    device_class = str(options.get("device_class") or "generic").strip().lower()
    class_ports = DEVICE_CLASS_TCP_PORTS.get(device_class, DEVICE_CLASS_TCP_PORTS["generic"])
    manufacturer = re.sub(
        r"[^a-z0-9]+", "",
        " ".join([
            str(options.get("device_manufacturer") or ""),
            str(options.get("device_model") or ""),
            str(options.get("device_name") or ""),
        ]).lower(),
    )
    manufacturer_ports = tuple(dict.fromkeys(
        port
        for vendor, ports in TV_MANUFACTURER_TCP_PORTS.items()
        if vendor in manufacturer
        for port in ports
    ))
    reachability_port_hints = list(dict.fromkeys([
        *valid_ports(hint_payload.get("user")),
        *valid_ports(hint_payload.get("observed")),
        *valid_ports(hint_payload.get("credential")),
        *valid_ports(hint_payload.get("request_collection")),
        *credential_priority_ports,
        *valid_ports(hint_payload.get("policy")),
        *policy_ports,
        *class_ports,
        *manufacturer_ports,
    ]))
    extra_priority_ports = tuple(sorted(set(reachability_port_hints)))

    async def ensure_active(stage: str) -> bool:
        if callable(cancel_check) and bool(await cancel_check()):
            raise ValueError(f"connected-device scan cancelled before {stage}")
        return time.monotonic() < deadline

    await ensure_active("health baseline")
    safety.authorize("target_health_baseline", "readonly")
    try:
        resolved_address = await resolve_device_address(locator)
    except ValueError as exc:
        reachability = unresolved_reachability(locator, exc)
        safety.record_health(_reachability_checkpoint(reachability, stage="reachability_preflight"))
        return _reachability_only_result(
            locator=locator,
            resolved_address=None,
            profile_name=profile_name,
            profile=profile,
            safety=safety,
            reachability=reachability,
            resolved_credentials=resolved_credentials,
            requested_capabilities=requested_capabilities,
            policy_name=policy_name,
            policy_rules_count=len(rules),
        )

    async def scan_stage_callback(event: dict[str, Any]) -> bool | None:
        kind = str(event.get("kind") or "")
        if kind == "tcp_chunk":
            chunk_index = max(0, int(event.get("chunk_index") or 0))
            chunk_count = max(1, int(event.get("chunk_count") or 1))
            progress = min(68, 15 + round(50 * chunk_index / chunk_count))
            await _call_stage_callback(progress_callback, {
                "phase": str(event.get("stage") or "device_tcp_discovery"),
                "progress": progress,
            })
            if event.get("skip_health"):
                return not safety.halted
            known_ports = valid_ports(event.get("known_tcp_ports"))[:3]
            checkpoint = await check_device_health(
                resolved_address,
                stage=f"after_{event.get('stage') or 'tcp_chunk'}",
                tcp_ports=known_ports,
            )
            if checkpoint.get("status") == "degraded":
                confirmation = await check_device_health(
                    resolved_address,
                    stage=f"confirm_{event.get('stage') or 'tcp_chunk'}",
                    tcp_ports=known_ports,
                    timeout=2.0,
                )
                confirmation["initial_checkpoint"] = checkpoint
                checkpoint = confirmation
            safety.record_health(checkpoint)
            return not safety.halted
        phase_progress = {
            "device_service_fingerprinting": 70,
            "device_udp_discovery": 78,
        }
        phase = str(event.get("stage") or "device_inventory")
        await _call_stage_callback(progress_callback, {
            "phase": phase,
            "progress": phase_progress.get(phase, 15),
        })
        return not safety.halted

    reachability = await probe_device_reachability(
        locator,
        resolved_address,
        attempts=2,
        timeout=1.0,
        port_hints=reachability_port_hints,
        cancel_check=cancel_check,
    )
    safety.record_health(_reachability_checkpoint(reachability, stage="reachability_preflight"))
    prefetched_tcp_scope = None
    inventory_authorized = False
    if reachability.get("status") == "inconclusive" and "-p-" in profile.tcp_args:
        await ensure_active("inconclusive reachability fallback")
        safety.authorize("network_inventory", "readonly")
        inventory_authorized = True
        safety.record_limit_enforcement(
            "naabu_tcp_connect",
            max_concurrency=_naabu_connect_workers(
                safety_profile.max_port_probes_per_second, NAABU_TIMEOUT_MS
            ),
            max_requests_per_second=safety_profile.max_port_probes_per_second,
        )
        prefetched_tcp_scope = await _run_tcp_scope_discovery(
            resolved_address,
            profile,
            deadline=deadline,
            cancel_check=cancel_check,
            max_requests_per_second=safety_profile.max_requests_per_second,
            max_port_probes_per_second=safety_profile.max_port_probes_per_second,
            extra_priority_ports=extra_priority_ports,
            stage_callback=scan_stage_callback,
        )
        fallback_services, _fallback_uncertain, _fallback_identity, fallback_receipt = prefetched_tcp_scope
        reachability = corroborate_device_reachability(
            reachability,
            services=fallback_services,
            tool_receipts=[fallback_receipt],
            protocol_results=[],
            health_checkpoints=[],
            full_tcp_visibility=bool(
                fallback_receipt.get("complete")
                and not int(fallback_receipt.get("tcp_filtered_count") or 0)
            ),
        )
        reachability["fallback"] = {
            "attempted": True,
            "kind": "all_tcp_scope",
            "inventory_reused": True,
            "complete": bool(fallback_receipt.get("complete")),
            "confirmed_open_count": int(fallback_receipt.get("confirmed_open_count") or 0),
            "closed_response_count": int(
                (fallback_receipt.get("port_state_counts") or {}).get("closed") or 0
            ),
            "filtered_count": int(fallback_receipt.get("tcp_filtered_count") or 0),
        }
        safety.record_health(_reachability_checkpoint(reachability, stage="reachability_all_tcp_fallback"))
    if reachability.get("status") != "online":
        return _reachability_only_result(
            locator=locator,
            resolved_address=resolved_address,
            profile_name=profile_name,
            profile=profile,
            safety=safety,
            reachability=reachability,
            resolved_credentials=resolved_credentials,
            requested_capabilities=requested_capabilities,
            policy_name=policy_name,
            policy_rules_count=len(rules),
        )
    if not inventory_authorized:
        safety.authorize("network_inventory", "readonly")
        safety.record_limit_enforcement(
            "naabu_tcp_connect",
            max_concurrency=_naabu_connect_workers(
                safety_profile.max_port_probes_per_second, NAABU_TIMEOUT_MS
            ),
            max_requests_per_second=safety_profile.max_port_probes_per_second,
        )
    services, inconclusive_observations, identity, tool_receipts, scan_completeness = await _nmap_scan(
        resolved_address,
        profile,
        deadline=deadline,
        cancel_check=cancel_check,
        max_requests_per_second=safety_profile.max_requests_per_second,
        max_port_probes_per_second=safety_profile.max_port_probes_per_second,
        extra_priority_ports=extra_priority_ports,
        stage_callback=scan_stage_callback,
        prefetched_tcp_scope=prefetched_tcp_scope,
    )
    await _call_stage_callback(progress_callback, {"phase": "device_protocol_discovery", "progress": 82})
    if not safety.halted:
        safety.authorize("core_protocol_discovery", "readonly")
    if not safety.halted and await ensure_active("core protocol discovery"):
        protocol_results = await discover_core_device_protocols(resolved_address, udp_ports=profile.udp_ports)
    else:
        protocol_results = []
        scan_completeness["complete"] = False
        scan_completeness["execution_complete"] = False
        if safety.halted:
            scan_completeness["safety_halted"] = True
            scan_completeness.setdefault("incomplete_stages", []).append("device_health_degraded")
        else:
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
    if not safety.halted:
        safety.authorize("web_origin_discovery", "readonly")
        await _call_stage_callback(progress_callback, {"phase": "device_web_discovery", "progress": 85})
        safety.record_limit_enforcement(
            "web_origin_probes",
            max_concurrency=safety_profile.max_concurrency,
            max_requests_per_second=safety_profile.max_requests_per_second,
        )
    if not safety.halted and await ensure_active("web origin discovery"):
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
        if safety.halted:
            scan_completeness["safety_halted"] = True
            scan_completeness.setdefault("incomplete_stages", []).append("device_health_degraded")
        else:
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
        await _call_stage_callback(progress_callback, {"phase": "device_ssh_posture", "progress": 88})
        safety.authorize(
            "ssh_posture_handshake",
            "ephemeral_state" if ssh_credentials else "readonly",
            side_effects="one operator-supplied authentication attempt" if ssh_credentials else "none",
        )
        if "ssh-authenticated-host-review" in requested_capabilities:
            safety.authorize(
                "ssh_authenticated_host_review",
                "readonly",
                side_effects="server-owned read-only command bundles after supplied authentication",
            )
            safety.record_limit_enforcement("ssh_host_review", max_concurrency=1)
        if "agent-confirmed-ssh-shell" in requested_capabilities:
            safety.authorize(
                "agent_confirmed_ssh_shell",
                "explicit_user_confirmed_shell",
                side_effects="arbitrary remote-device effects from the exact user-confirmed command plan",
            )
            safety.record_limit_enforcement("agent_confirmed_ssh_shell", max_concurrency=1)
        attempted_ssh_profiles: set[str] = set()
        for service in services:
            if service.get("transport") != "tcp" or str(service.get("service_name") or "").lower() not in SSH_SERVICE_NAMES:
                continue
            if not await ensure_active("SSH posture"):
                scan_completeness["complete"] = False
                scan_completeness["execution_complete"] = False
                scan_completeness["overall_budget_exhausted"] = True
                scan_completeness.setdefault("incomplete_stages", []).append("overall_device_budget_exhausted")
                break
            service_port = int(service["port"])
            ssh_credential = next((
                item for item in ssh_credentials
                if item.get("port") is None or int(item.get("port")) == service_port
            ), None)
            shell_for_port = (
                shell_plan
                if shell_plan
                and service_port == int(shell_plan["ssh_port"])
                and ssh_credential
                and str(ssh_credential.get("profile_id")) == str(shell_plan["credential_profile_id"])
                else None
            )
            if (
                ssh_credential
                and {"ssh-authenticated-host-review", "agent-confirmed-ssh-shell"}.intersection(requested_capabilities)
                and service_port not in expected_ssh_host_keys
            ):
                ssh_credential = None
                shell_for_port = None
            if "agent-confirmed-ssh-shell" in requested_capabilities and not shell_for_port and "ssh-authenticated-host-review" not in requested_capabilities:
                ssh_credential = None
            credential_profile_id = str((ssh_credential or {}).get("profile_id") or "")
            if credential_profile_id in attempted_ssh_profiles:
                ssh_credential = None
            ssh_result = await full_ssh_scan(
                resolved_address,
                port=service_port,
                timeout=8,
                credential=ssh_credential,
                host_review_bundles=(
                    DEFAULT_SSH_HOST_REVIEW_BUNDLES
                    if ssh_credential and "ssh-authenticated-host-review" in requested_capabilities
                    else None
                ),
                expected_host_key_fingerprint=expected_ssh_host_keys.get(service_port),
                shell_plan=shell_for_port,
            )
            if ssh_credential:
                attempted_ssh_profiles.add(credential_profile_id)
                ssh_result["credential_profile_id"] = credential_profile_id
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

    reachability = corroborate_device_reachability(
        reachability,
        services=services,
        tool_receipts=tool_receipts,
        protocol_results=protocol_results,
        health_checkpoints=safety_receipt.get("health_checkpoints") or [],
        full_tcp_visibility=bool(
            "-p-" in profile.tcp_args
            and scan_completeness.get("tcp_discovery_complete")
            and scan_completeness.get("tcp_visibility_complete")
        ),
    )
    scan_completeness["reachability_confirmed"] = reachability.get("status") == "online"
    scan_completeness["reachability_status"] = reachability.get("status")
    if reachability.get("status") != "online":
        scan_completeness["complete"] = False
        scan_completeness["execution_complete"] = False
        scan_completeness.setdefault("incomplete_stages", []).append("device_reachability_unconfirmed")
    scan_completeness["incomplete_stages"] = list(dict.fromkeys(
        str(stage) for stage in scan_completeness.get("incomplete_stages") or []
    ))
    services, policy_findings = evaluate_service_policy(services, rules, policy_name=policy_name)
    findings = policy_findings + ssh_findings
    complete = bool(scan_completeness.get("complete"))
    execution_complete = bool(scan_completeness.get("execution_complete", complete))
    score, grade = (
        _score(findings, complete=execution_complete)
        if reachability.get("status") == "online"
        else (None, None)
    )
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
        reachability=reachability,
    )
    capability_coverage = [
        {"capability_id": "scope-safety-health", "status": "completed" if not safety.halted and reachability.get("status") == "online" else "failed"},
        {"capability_id": "device-identity-attack-surface", "status": "completed" if identity else "partial"},
        {"capability_id": "tcp-udp-network-discovery", "status": "completed" if scan_completeness.get("execution_complete") else "partial"},
        {"capability_id": "service-fingerprinting-crypto", "status": "completed" if services else "partial"},
        {"capability_id": "smart-tv-lan-protocols", "status": "partial" if protocol_results else "not_observed"},
        {"capability_id": "web-ui-dast", "status": "completed" if web_origins else "not_observed"},
        {"capability_id": "evidence-correlation-reporting", "status": "completed"},
    ]
    if "ssh-authenticated-host-review" in requested_capabilities:
        reviews = [
            (service.get("ssh") or {}).get("host_review")
            for service in services
            if isinstance(service, dict) and isinstance(service.get("ssh"), dict)
        ]
        reviews = [item for item in reviews if isinstance(item, dict)]
        review_status = "blocked"
        if any(item.get("status") == "completed" for item in reviews):
            review_status = "completed"
        elif reviews:
            review_status = "partial"
        capability_coverage.append({
            "capability_id": "ssh-authenticated-host-review",
            "status": review_status,
            "reason": None if reviews else "authenticated_ssh_collection_unavailable",
        })
    if "agent-confirmed-ssh-shell" in requested_capabilities:
        shell_results = [
            (service.get("ssh") or {}).get("shell_execution")
            for service in services
            if isinstance(service, dict) and isinstance(service.get("ssh"), dict)
        ]
        shell_results = [item for item in shell_results if isinstance(item, dict)]
        shell_status = "blocked"
        if any(item.get("status") == "completed" for item in shell_results):
            shell_status = "completed"
        elif shell_results:
            shell_status = "partial"
        capability_coverage.append({
            "capability_id": "agent-confirmed-ssh-shell",
            "status": shell_status,
            "plan_id": shell_plan.get("plan_id") if shell_plan else None,
            "plan_digest": shell_plan.get("plan_digest") if shell_plan else None,
            "reason": None if shell_results else "confirmed_ssh_shell_execution_unavailable",
        })

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
            "reachability": reachability,
            "services": services,
            "inconclusive_observations": inconclusive_observations,
            "web_origins": web_origins,
            "protocols": protocol_results,
            "policy": {"name": policy_name, "rules_count": len(rules)},
            "decision": {"decision": decision, "rationale": rationale, "policy_name": policy_name},
            "safety": safety_receipt,
            "evidence_graph": evidence_graph,
            "capability_coverage": capability_coverage,
            "requested_capabilities": requested_capabilities,
            "completeness": {
                "complete": complete,
                "tcp_scope": "all_65535" if "-p-" in profile.tcp_args else "top_100",
                "tcp_priority_ports": sorted(set(PRIORITY_TCP_PORTS) | set(extra_priority_ports)),
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
            "credentials_attempted": any(
                bool((service.get("ssh") or {}).get("authentication_attempted"))
                for service in services
                if isinstance(service, dict) and isinstance(service.get("ssh"), dict)
            ),
            "device_coverage_profile": profile_name,
            "device_safety_profile": safety_profile.name,
            "device_reachability_status": reachability.get("status"),
            "credential_profile_refs": [
                {"role": item.get("role"), "profile_id": item.get("profile_id"), "auth_kind": item.get("auth_kind")}
                for item in resolved_credentials
            ],
        },
    }
