"""Typed, single-service verification for one authorized connected device.

This executor deliberately has no raw-command, URL, path, or payload input.  It
resolves the registered locator once, pins that address, and asks Nmap about one
explicit TCP or UDP port.  A closed assertion is accepted only when the scanner
receives an explicit closed state; silence and filtering stay inconclusive.
"""

from __future__ import annotations

import time
from typing import Any

try:
    from defusedxml import ElementTree as ET
except ImportError:  # pragma: no cover - minimal host test environment
    from xml.etree import ElementTree as ET

try:
    from .common import run
    from .device_posture import normalize_device_locator, resolve_device_address
    from .device_safety import DeviceSafetyGovernor, check_device_health, validate_safety_request
except ImportError:  # pragma: no cover - flat scanner runtime
    from common import run
    from device_posture import normalize_device_locator, resolve_device_address
    from device_safety import DeviceSafetyGovernor, check_device_health, validate_safety_request


PROBE_TRANSPORTS = {"tcp", "udp"}
EXPECTED_STATES = {"open", "closed"}
MAX_PROBE_DURATION_SECONDS = 120


def _parse_single_port(xml_text: str, *, transport: str, port: int) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "xml_parsed": False,
        "complete": False,
        "transport": transport,
        "port": port,
        "state": "unknown",
        "state_reason": None,
        "service_name": "unknown",
        "product": "",
        "version": "",
        "cpe": None,
        "incomplete_reasons": [],
    }
    if not str(xml_text or "").strip():
        receipt["incomplete_reasons"].append("empty_nmap_output")
        return receipt
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, ValueError) as exc:
        receipt["incomplete_reasons"].append(f"invalid_nmap_xml:{type(exc).__name__}")
        return receipt
    receipt["xml_parsed"] = True
    finished = root.find("./runstats/finished")
    finished_exit = str(finished.get("exit") or "") if finished is not None else ""
    if finished_exit != "success":
        receipt["incomplete_reasons"].append(f"nmap_exit:{finished_exit or 'missing'}")
    match = None
    for element in root.findall(".//ports/port"):
        try:
            if str(element.get("protocol") or "").lower() == transport and int(element.get("portid") or 0) == port:
                match = element
                break
        except (TypeError, ValueError):
            continue
    if match is None:
        receipt["incomplete_reasons"].append("requested_port_missing")
        return receipt
    state_element = match.find("state")
    service_element = match.find("service")
    state = str(state_element.get("state") or "unknown") if state_element is not None else "unknown"
    receipt["state"] = state
    receipt["state_reason"] = str(state_element.get("reason") or "") or None if state_element is not None else None
    if service_element is not None:
        receipt["service_name"] = str(service_element.get("name") or "unknown")[:100]
        receipt["product"] = str(service_element.get("product") or "")[:500]
        receipt["version"] = str(service_element.get("version") or "")[:300]
        cpe = service_element.find("cpe")
        receipt["cpe"] = str(cpe.text or "")[:500] if cpe is not None else None
    if state not in {"open", "closed"}:
        receipt["incomplete_reasons"].append(f"non_definitive_state:{state}")
    receipt["complete"] = bool(finished_exit == "success" and state in {"open", "closed"})
    return receipt


def evaluate_service_state(observed_state: str, expected_state: str, *, complete: bool) -> dict[str, Any]:
    if not complete or observed_state not in {"open", "closed"}:
        return {
            "verdict": "inconclusive",
            "rationale": "The probe did not receive a definitive open or closed result.",
        }
    if observed_state == expected_state:
        return {
            "verdict": "satisfied",
            "rationale": f"The service state was explicitly observed as {observed_state}.",
        }
    return {
        "verdict": "refuted",
        "rationale": f"Expected {expected_state}, but the service state was explicitly observed as {observed_state}.",
    }


async def run_device_service_probe(locator: str, options: dict[str, Any]) -> dict[str, Any]:
    locator = normalize_device_locator(locator)
    transport = str(options.get("probe_transport") or "").lower()
    expected_state = str(options.get("expected_state") or "").lower()
    try:
        port = int(options.get("probe_port"))
    except (TypeError, ValueError) as exc:
        raise ValueError("device service probe requires one valid port") from exc
    if transport not in PROBE_TRANSPORTS:
        raise ValueError("device service probe transport must be tcp or udp")
    if expected_state not in EXPECTED_STATES:
        raise ValueError("device service probe expected_state must be open or closed")
    if not 1 <= port <= 65535:
        raise ValueError("device service probe port must be between 1 and 65535")
    if not options.get("confirm_authorized"):
        raise ValueError("connected-device authorization confirmation is required")

    safety_profile = validate_safety_request(options)
    if safety_profile.name == "observe_only":
        raise ValueError("observe_only does not permit a network service probe")
    safety = DeviceSafetyGovernor(safety_profile)
    safety.authorize("device_service_state_probe", "readonly", side_effects="one fixed-port service query")
    safety.record_limit_enforcement(
        "device_service_state_probe",
        max_concurrency=1,
        max_requests_per_second=min(5.0, safety_profile.max_requests_per_second),
    )
    started = time.monotonic()
    resolved_address = await resolve_device_address(locator)
    known_ports = [port] if transport == "tcp" else []
    safety.record_health(await check_device_health(resolved_address, stage="before_targeted_probe", tcp_ports=known_ports))
    if safety.halted:
        raise ValueError("device health circuit breaker halted the targeted probe")
    cancel_check = options.get("_cancel_check")
    if callable(cancel_check) and bool(await cancel_check()):
        raise ValueError("connected-device probe cancelled before execution")

    scan_mode = "-sT" if transport == "tcp" else "-sU"
    command = [
        "nmap", "-Pn", "-n", scan_mode, "-sV", "--version-light", "--max-retries", "1",
        "--max-rate", "5", "--host-timeout", "90s", "-p", str(port), "-oX", "-", resolved_address,
    ]
    stdout, stderr, exit_code = await run(command, timeout=MAX_PROBE_DURATION_SECONDS)
    observation = _parse_single_port(stdout, transport=transport, port=port)
    if exit_code != 0:
        observation["complete"] = False
        observation["incomplete_reasons"].append(f"process_exit:{exit_code}")
    verification = evaluate_service_state(
        str(observation.get("state") or "unknown"),
        expected_state,
        complete=bool(observation.get("complete")),
    )
    safety.record_health(await check_device_health(resolved_address, stage="after_targeted_probe", tcp_ports=known_ports))
    if safety.halted:
        verification = {
            "verdict": "inconclusive",
            "rationale": "Device health degraded after the probe; the result is retained but not accepted as proof.",
        }
    safety_receipt = safety.receipt()
    return {
        "target": locator,
        "resolved_target": resolved_address,
        "result": {"score": None, "grade": None},
        "findings": [],
        "device_probe": {
            "schema_version": "device-probe/v1",
            "probe_kind": "service_state",
            "transport": transport,
            "port": port,
            "expected_state": expected_state,
            "observation": observation,
            "verification": verification,
            "safety": safety_receipt,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "tool_receipt": {
                "tool": "nmap",
                "fixed_scope": True,
                "target_count": 1,
                "port_count": 1,
                "exit_code": exit_code,
                "stderr": str(stderr or "")[:500],
            },
        },
        "scan_metadata": {
            "run_kind": "device_probe",
            "active_testing": False,
            "credentials_attempted": False,
            "device_safety_profile": safety_profile.name,
        },
    }
