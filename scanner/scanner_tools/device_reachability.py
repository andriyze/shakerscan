"""Fail-closed, multi-signal reachability checks for connected devices."""

from __future__ import annotations

import asyncio
import errno
import time
from datetime import datetime, timezone
from typing import Any, Iterable

try:
    from defusedxml import ElementTree as ET
except ImportError:  # pragma: no cover - minimal host test environment
    from xml.etree import ElementTree as ET

try:
    from .common import run
except ImportError:  # pragma: no cover - flat scanner runtime
    from common import run


REACHABILITY_TCP_PORTS = (
    21, 22, 23, 53, 80, 81, 111, 139, 443, 445, 502, 515, 548, 554,
    631, 873, 1883, 2049, 2323, 3000, 5000, 5001, 5555, 5683, 7000,
    7001, 7345, 8000, 8001, 8002, 8008, 8009, 8060, 8080, 8081,
    8443, 8554, 8883, 9000, 9080, 9090, 9100, 9197, 9220, 49152,
    55000,
)
REACHABILITY_UDP_PORTS = (53, 123, 1900, 5353)
MAX_REACHABILITY_TCP_PORTS = 256
_REFUSED_ERRNOS = {errno.ECONNREFUSED}
_UNREACHABLE_ERRNOS = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL}
_POSITIVE_NMAP_REASONS = {
    "arp-response", "conn-refused", "echo-reply", "localhost-response",
    "nd-response", "port-unreach", "proto-response", "reset", "syn-ack",
    "syn-response", "udp-response",
}


def parse_host_discovery(xml_text: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "xml_parsed": False,
        "host_state": "unknown",
        "reason": None,
        "addresses": [],
        "positive": False,
        "error": None,
    }
    if not str(xml_text or "").strip():
        result["error"] = "empty_nmap_output"
        return result
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, ValueError) as exc:
        result["error"] = f"invalid_nmap_xml:{type(exc).__name__}"
        return result
    result["xml_parsed"] = True
    host = root.find("./host")
    if host is None:
        result["host_state"] = "down"
        return result
    status = host.find("./status")
    state = str(status.get("state") if status is not None else "unknown").lower()
    reason = str(status.get("reason") if status is not None else "").lower() or None
    result["host_state"] = state
    result["reason"] = reason
    result["addresses"] = [
        str(item.get("addr")) for item in host.findall("./address") if item.get("addr")
    ][:8]
    result["positive"] = bool(state == "up" and reason in _POSITIVE_NMAP_REASONS)
    return result


def _tcp_outcome_from_error(exc: BaseException) -> str:
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return "no_response"
    code = getattr(exc, "errno", None)
    if code in _REFUSED_ERRNOS:
        return "refused"
    if code in _UNREACHABLE_ERRNOS:
        return "network_unreachable"
    return "error"


async def _probe_tcp_port(locator: str, port: int, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(locator, port),
            timeout=timeout,
        )
        outcome = "open"
        error_name = None
    except (TimeoutError, asyncio.TimeoutError, OSError) as exc:
        outcome = _tcp_outcome_from_error(exc)
        error_name = type(exc).__name__
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    return {
        "port": int(port),
        "outcome": outcome,
        "error": error_name,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
    }


async def _tcp_probe_round(
    locator: str,
    ports: tuple[int, ...],
    *,
    timeout: float,
    max_concurrency: int,
) -> list[dict[str, Any]]:
    semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def bounded(port: int) -> dict[str, Any]:
        async with semaphore:
            return await _probe_tcp_port(locator, port, timeout)

    return await asyncio.gather(*(bounded(port) for port in ports))


async def _nmap_host_discovery(
    locator: str,
    *,
    tcp_ports: tuple[int, ...] = REACHABILITY_TCP_PORTS,
    cancel_check: Any = None,
) -> dict[str, Any]:
    tcp = ",".join(str(port) for port in tcp_ports)
    udp = ",".join(str(port) for port in REACHABILITY_UDP_PORTS)
    cmd = [
        "nmap", "-sn", "-n", "--reason", "--max-retries", "1", "--host-timeout", "20s",
        "-PE", "-PP", f"-PS{tcp}", f"-PA{tcp}", f"-PU{udp}", "-oX", "-", locator,
    ]
    options: dict[str, Any] = {"timeout": 30}
    if callable(cancel_check):
        options["cancel_check"] = cancel_check
    stdout, stderr, exit_code = await run(cmd, **options)
    result = parse_host_discovery(stdout)
    result.update({
        "exit_code": exit_code,
        "complete": bool(exit_code == 0 and result.get("xml_parsed")),
        "stderr": str(stderr or "")[:500],
    })
    return result


def normalize_reachability_tcp_ports(port_hints: Iterable[Any] = ()) -> tuple[int, ...]:
    """Keep operator/device-specific ports first, then the bounded common set."""
    hinted: list[int] = []
    seen: set[int] = set()
    for raw_port in port_hints:
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535 or port in seen:
            continue
        hinted.append(port)
        seen.add(port)
        if len(hinted) >= MAX_REACHABILITY_TCP_PORTS:
            return tuple(hinted)
    for port in REACHABILITY_TCP_PORTS:
        if port not in seen:
            hinted.append(port)
            seen.add(port)
        if len(hinted) >= MAX_REACHABILITY_TCP_PORTS:
            break
    return tuple(hinted)


def _build_verdict(
    *,
    locator: str,
    resolved_address: str | None,
    attempts: list[dict[str, Any]],
    nmap: dict[str, Any] | None,
    resolution_error: str | None = None,
) -> dict[str, Any]:
    probes = [probe for attempt in attempts for probe in attempt.get("tcp_probes", [])]
    open_ports = sorted({int(item["port"]) for item in probes if item.get("outcome") == "open"})
    refused_ports = sorted({int(item["port"]) for item in probes if item.get("outcome") == "refused"})
    unreachable_count = sum(1 for item in probes if item.get("outcome") == "network_unreachable")
    positive_nmap = bool((nmap or {}).get("positive"))
    if resolution_error or not resolved_address:
        status = "unreachable"
        confidence = "high"
        reason = "The registered device address could not be resolved to a usable IP address."
    elif open_ports:
        status = "online"
        confidence = "high"
        reason = "The device accepted at least one bounded TCP connection."
    elif refused_ports:
        status = "online"
        confidence = "high"
        reason = "The device actively refused TCP connections, proving that its network stack responded."
    elif positive_nmap:
        status = "online"
        confidence = "high"
        reason = f"Nmap host discovery received a direct {nmap.get('reason')} response."
    elif probes and unreachable_count == len(probes):
        status = "unreachable"
        confidence = "medium"
        reason = "Every bounded TCP probe reported the network or host unreachable."
    else:
        status = "inconclusive"
        confidence = "none"
        reason = (
            "No direct response proved that the device is online. It may be powered off, asleep, "
            "isolated from this scanner, or filtering discovery traffic."
        )
    return {
        "schema_version": "device-reachability/v1",
        "status": status,
        "online": True if status == "online" else False if status == "unreachable" else None,
        "network_accessible": True if status == "online" else False if status == "unreachable" else None,
        "service_accessible": True if open_ports else False if status == "unreachable" else None,
        "confidence": confidence,
        "reason": reason,
        "locator": locator,
        "resolved_address": resolved_address,
        "resolution_succeeded": bool(resolved_address),
        "resolution_error": resolution_error,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "positive_signals": {
            "tcp_open_ports": open_ports,
            "tcp_refused_ports": refused_ports,
            "nmap_host_discovery": positive_nmap,
            "nmap_reason": (nmap or {}).get("reason"),
        },
        "attempts": attempts,
        "nmap_host_discovery": nmap or {},
    }


async def probe_device_reachability(
    locator: str,
    resolved_address: str,
    *,
    attempts: int = 2,
    timeout: float = 1.0,
    port_hints: Iterable[Any] = (),
    cancel_check: Any = None,
) -> dict[str, Any]:
    """Require a positive device response; silence is never treated as online."""
    rounds: list[dict[str, Any]] = []
    attempt_limit = max(1, min(int(attempts), 3))
    tcp_ports = normalize_reachability_tcp_ports(port_hints)
    nmap_task = asyncio.create_task(_nmap_host_discovery(
        resolved_address,
        tcp_ports=tcp_ports,
        cancel_check=cancel_check,
    ))
    try:
        for attempt in range(1, attempt_limit + 1):
            if callable(cancel_check) and bool(await cancel_check()):
                raise ValueError("connected-device scan cancelled during reachability preflight")
            probes = await _tcp_probe_round(
                resolved_address,
                tcp_ports,
                timeout=max(0.2, min(float(timeout), 3.0)),
                max_concurrency=10,
            )
            rounds.append({"attempt": attempt, "tcp_probes": probes})
            if any(item.get("outcome") in {"open", "refused"} for item in probes):
                break
            if attempt < attempt_limit:
                await asyncio.sleep(0.25)
    except BaseException:
        if not nmap_task.done():
            nmap_task.cancel()
        await asyncio.gather(nmap_task, return_exceptions=True)
        raise
    try:
        nmap = await nmap_task
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # pragma: no cover - command runner normally returns diagnostics
        nmap = {"complete": False, "positive": False, "error": type(exc).__name__}
    return _build_verdict(
        locator=locator,
        resolved_address=resolved_address,
        attempts=rounds,
        nmap=nmap,
    )


def unresolved_reachability(locator: str, error: BaseException) -> dict[str, Any]:
    return _build_verdict(
        locator=locator,
        resolved_address=None,
        attempts=[],
        nmap=None,
        resolution_error=type(error).__name__,
    )


def corroborate_device_reachability(
    preflight: dict[str, Any],
    *,
    services: list[dict[str, Any]],
    tool_receipts: list[dict[str, Any]],
    protocol_results: list[dict[str, Any]],
    health_checkpoints: list[dict[str, Any]],
    full_tcp_visibility: bool,
) -> dict[str, Any]:
    """Strengthen the preflight with evidence produced by the actual scan."""
    result = dict(preflight)
    signals = dict(result.get("positive_signals") or {})
    confirmed_services = [
        item for item in services
        if isinstance(item, dict) and item.get("state") == "open"
    ]
    closed_responses = sum(
        int((receipt.get("port_state_counts") or {}).get("closed") or 0)
        for receipt in tool_receipts if isinstance(receipt, dict)
    )
    responsive_health_ports = sorted({
        int(port)
        for checkpoint in health_checkpoints if isinstance(checkpoint, dict)
        for port in checkpoint.get("responsive_tcp_ports") or []
    })
    confirmed_protocols = [
        str(item.get("protocol") or "unknown")
        for item in protocol_results if isinstance(item, dict) and item.get("confirmed")
    ]
    signals.update({
        "confirmed_open_services": len(confirmed_services),
        "closed_port_responses": closed_responses,
        "responsive_health_ports": responsive_health_ports,
        "confirmed_protocols": confirmed_protocols,
    })
    if confirmed_services or responsive_health_ports or confirmed_protocols:
        result.update({
            "status": "online", "online": True, "network_accessible": True,
            "service_accessible": True, "confidence": "high",
            "reason": "The assessment received a direct service or protocol response from the device.",
        })
    elif closed_responses > 0:
        result.update({
            "status": "online", "online": True, "network_accessible": True,
            "confidence": "high",
            "reason": "The assessment received explicit closed-port responses from the device.",
        })
        if full_tcp_visibility:
            result["service_accessible"] = False
    elif result.get("status") == "online" and full_tcp_visibility:
        result["service_accessible"] = False
    result["positive_signals"] = signals
    result["checked_at"] = datetime.now(timezone.utc).isoformat()
    result["post_scan_corroborated"] = bool(
        confirmed_services or closed_responses or responsive_health_ports or confirmed_protocols
    )
    return result
