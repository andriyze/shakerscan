"""Protocol identification of a device's confirmed-open ports, and its per-address coverage.

Nmap names what its probes matched; a port it could only name from its port table, or not at
all, is offered to the native protocol adapters (``service_protocols``), which identify by a
parsed reply and never by the port number. A port Nmap did identify gets only its own adapter,
for the structured protocol, version build and authentication fields.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

try:
    from . import service_identity as si
    from . import service_protocols as sp
except ImportError:  # flat scanner runtime
    import service_identity as si  # type: ignore[no-redef]
    import service_protocols as sp  # type: ignore[no-redef]

# Ports offered the whole adapter sequence (Nmap unknown, tcpwrapped or table-only) and ports
# offered only their own adapter, per address.
FULL_IDENTIFICATION_CAP = 32
HINTED_IDENTIFICATION_CAP = 64
IDENTIFICATION_CONCURRENCY = 4
UNNAMED = {"unknown", "tcpwrapped", ""}
UDP_ADAPTER_PORTS = (53, 123, 500, 4500, 1194)
STAGE = "device_protocol_identification"


def _unnamed(service: dict[str, Any]) -> bool:
    return str(service.get("service_name") or "").lower() in UNNAMED


async def identify_device_services(
    address: str,
    services: list[dict[str, Any]],
    *,
    server_name: str | None = None,
    deadline: float | None = None,
    max_concurrency: int = IDENTIFICATION_CONCURRENCY,
) -> dict[str, Any]:
    """Attach ``identity`` (``service_protocols.public_row``) to open TCP services in place.

    An unnamed service takes the adapter's protocol as its ``service_name`` (so SSH posture,
    web discovery and policy see a confirmed name); a name Nmap probed is never overwritten.
    Returns the stage receipt.
    """
    started = time.monotonic()
    open_tcp = [
        item for item in services
        if item.get("transport") == "tcp" and item.get("state") == "open"
    ]
    unnamed = [item for item in open_tcp if _unnamed(item)][:FULL_IDENTIFICATION_CAP]
    hinted = [
        item for item in open_tcp
        if not _unnamed(item)
        and sp.ADAPTER_FOR_SERVICE.get(str(item.get("service_name") or "").lower()) in sp.TCP_ADAPTERS
    ][:HINTED_IDENTIFICATION_CAP]
    gate = asyncio.Semaphore(max(1, min(int(max_concurrency or 1), IDENTIFICATION_CONCURRENCY)))
    skipped: list[int] = []
    excluded: list[int] = []

    async def one(service: dict[str, Any], full: bool) -> None:
        async with gate:
            if deadline is not None and time.monotonic() >= deadline - 15:
                skipped.append(int(service["port"]))
                return
            hints = (service.get("port_hint"), None if full else service.get("service_name"))
            row = await sp.identify_tcp_service(
                address, int(service["port"]), hints=hints, server_name=server_name,
                max_adapters=len(sp.SILENT_TCP_ADAPTERS) + 1 if full else 2,
            )
        public = sp.public_row(row)
        if public["status"] == si.STATUS_EXCLUDED:
            excluded.append(int(service["port"]))
        service["identity"] = public
        if public["status"] != si.STATUS_IDENTIFIED:
            return
        if _unnamed(service) and public["protocol"]:
            service["service_name"] = public["protocol"]
            service["identity_basis"] = "protocol_adapter"
        if not service.get("product") and public.get("product"):
            service["product"] = public["product"]
        if not service.get("version") and public.get("version"):
            service["version"] = public["version"]

    await asyncio.gather(
        *(one(item, True) for item in unnamed),
        *(one(item, False) for item in hinted),
    )
    identified = sum(
        1 for item in open_tcp
        if isinstance(item.get("identity"), dict) and item["identity"].get("status") == si.STATUS_IDENTIFIED
    )
    return {
        "stage": STAGE,
        "tool": "native_protocol_adapters",
        "transport": "tcp",
        "required": False,
        "complete": not skipped,
        "attempted": len(unnamed) + len(hinted) - len(skipped),
        "identified": identified,
        "unnamed_offered_all_adapters": len(unnamed),
        "unnamed_beyond_cap": max(0, sum(1 for item in open_tcp if _unnamed(item)) - FULL_IDENTIFICATION_CAP),
        "skipped_for_budget": sorted(skipped),
        "payload_excluded_ports": sorted(excluded),
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


async def identify_device_udp(address: str, udp_ports: tuple[int, ...]) -> list[dict[str, Any]]:
    """Protocol results for the declared UDP ports that have an adapter, in the shape
    ``merge_protocol_confirmations`` promotes: only a parsed reply confirms a UDP service."""
    results: list[dict[str, Any]] = []
    for port in [port for port in UDP_ADAPTER_PORTS if port in set(udp_ports)]:
        started = time.monotonic()
        row = sp.public_row(await sp.identify_udp_service(address, port))
        confirmed = row["status"] == si.STATUS_IDENTIFIED
        results.append({
            "protocol": row["protocol"] or "unknown",
            "transport": "udp",
            "port": port,
            "confirmed": confirmed,
            "responses": [],
            "identity": row,
            "receipt": {
                "stage": f"udp_protocol_{port}", "complete": True, "required": False,
                "adapters_attempted": row["adapters_attempted"], "confirmed": confirmed,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            },
        })
    return results


def address_coverage(
    address: str,
    *,
    tool_receipts: list[dict[str, Any]],
    udp_ports: tuple[int, ...],
    tcp_scope: str,
    network_role: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """What was attempted on one address: TCP ranges with their outcome and retries, UDP ports,
    and what was deliberately excluded."""
    ranges: list[dict[str, Any]] = []
    retries = 0
    for receipt in tool_receipts:
        chunks = receipt.get("chunk_receipts") if isinstance(receipt.get("chunk_receipts"), list) else []
        for chunk in chunks:
            if not isinstance(chunk, dict):
                continue
            if int(chunk.get("attempt") or 1) > 1:
                retries += 1
            ranges.append({
                "stage": chunk.get("stage"),
                "ports": chunk.get("port_spec"),
                "port_count": chunk.get("port_count"),
                "attempt": int(chunk.get("attempt") or 1),
                "complete": bool(chunk.get("complete")),
                "incomplete_reasons": list(chunk.get("incomplete_reasons") or [])[:4],
            })
    # The latest attempt of each stage decides whether that range was covered.
    final: dict[str, dict[str, Any]] = {}
    for item in ranges:
        final[str(item["stage"])] = item
    incomplete = [stage for stage, item in final.items() if not item["complete"]]
    return {
        "address": address,
        "tcp_scope": tcp_scope,
        "tcp_ranges": ranges,
        "tcp_ranges_incomplete": incomplete,
        "retries": retries,
        "udp_ports_requested": list(udp_ports),
        "exclusions": [{
            "transport": "tcp",
            "ports": "9100-9107",
            "scope": "service payload probes",
            "reason": "printer raw ports print every byte they receive; they are connected to, never sent a probe",
        }],
        **({"network_role": network_role} if network_role else {}),
    }


__all__ = ["address_coverage", "identify_device_services", "identify_device_udp"]
