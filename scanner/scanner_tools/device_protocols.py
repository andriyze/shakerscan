"""Bounded, target-scoped connected-device protocol discovery adapters."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
import urllib.parse
from typing import Any


class _Collector(asyncio.DatagramProtocol):
    def __init__(self, *, max_responses: int, max_bytes: int, allowed_addresses: set[str]):
        self.max_responses = max_responses
        self.max_bytes = max_bytes
        self.allowed_addresses = allowed_addresses
        self.responses: list[dict[str, Any]] = []
        self.total_bytes = 0

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            responder = str(ipaddress.ip_address(str(addr[0]).split("%", 1)[0]))
        except ValueError:
            return
        if responder not in self.allowed_addresses:
            return
        if len(self.responses) >= self.max_responses or self.total_bytes >= self.max_bytes:
            return
        remaining = max(0, self.max_bytes - self.total_bytes)
        bounded = bytes(data[:remaining])
        self.total_bytes += len(bounded)
        self.responses.append({"data": bounded, "address": responder, "port": int(addr[1])})


async def _udp_exchange(
    locator: str,
    port: int,
    payload: bytes,
    *,
    timeout: float = 2.0,
    max_responses: int = 16,
    max_bytes: int = 65_536,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Send one unicast datagram to the authorized locator and collect bounded replies."""
    loop = asyncio.get_running_loop()
    collector: _Collector | None = None
    transport = None
    error: str | None = None
    target_address: str | None = None
    try:
        addresses = await asyncio.wait_for(
            loop.getaddrinfo(locator, port, type=socket.SOCK_DGRAM),
            timeout=timeout,
        )
        resolved = next(
            (item for item in addresses if item[0] in {socket.AF_INET, socket.AF_INET6}),
            None,
        )
        if resolved is None:
            raise OSError("no UDP address resolved for target")
        family, _socktype, _protocol, _canonical, target_sockaddr = resolved
        target_address = str(ipaddress.ip_address(str(target_sockaddr[0]).split("%", 1)[0]))
        collector = _Collector(
            max_responses=max_responses,
            max_bytes=max_bytes,
            allowed_addresses={target_address},
        )
        local_addr = ("::", 0) if family == socket.AF_INET6 else ("0.0.0.0", 0)
        transport, _ = await asyncio.wait_for(
            # Keep the socket unconnected: embedded SSDP/mDNS stacks sometimes
            # answer a unicast request from a different source port. A connected
            # UDP socket would let the kernel silently discard that valid reply.
            loop.create_datagram_endpoint(lambda: collector, family=family, local_addr=local_addr),
            timeout=timeout,
        )
        transport.sendto(payload, target_sockaddr)
        await asyncio.sleep(max(0.05, min(timeout, 3.0)))
    except (TimeoutError, OSError, socket.gaierror) as exc:
        error = f"{type(exc).__name__}: {exc}"[:300]
    finally:
        if transport is not None:
            transport.close()
    responses = collector.responses if collector is not None else []
    response_bytes = collector.total_bytes if collector is not None else 0
    return responses, {
        "complete": error is None,
        "target": locator,
        "port": port,
        "request_bytes": len(payload),
        "resolved_target_address": target_address,
        "response_count": len(responses),
        "response_bytes": response_bytes,
        "timeout_seconds": timeout,
        "error": error,
        "scope": "exact_target_unicast",
    }


def parse_ssdp_response(data: bytes, *, locator: str) -> dict[str, Any] | None:
    text = data[:16_384].decode("latin-1", "replace")
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip().upper().startswith("HTTP/"):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        normalized = name.strip().lower()
        if normalized and normalized not in headers:
            headers[normalized] = value.strip()[:2000]
    location = headers.get("location")
    location_in_scope = None
    if location:
        try:
            host = urllib.parse.urlsplit(location).hostname
            if host:
                try:
                    location_in_scope = ipaddress.ip_address(host) == ipaddress.ip_address(locator)
                except ValueError:
                    location_in_scope = host.rstrip(".").lower() == locator.rstrip(".").lower()
        except ValueError:
            location_in_scope = False
    return {
        "status_line": lines[0].strip()[:300],
        "server": headers.get("server"),
        "search_target": headers.get("st"),
        "unique_service_name": headers.get("usn"),
        "location": location,
        "location_in_scope": location_in_scope,
        "cache_control": headers.get("cache-control"),
        "boot_id": headers.get("bootid.upnp.org"),
        "config_id": headers.get("configid.upnp.org"),
        "headers": headers,
    }


async def discover_ssdp(locator: str, *, timeout: float = 2.0) -> dict[str, Any]:
    payload = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "USER-AGENT: ShakerScan-Device/1\r\n\r\n"
    ).encode("ascii")
    raw, receipt = await _udp_exchange(locator, 1900, payload, timeout=timeout)
    responses: list[dict[str, Any]] = []
    for item in raw:
        parsed = parse_ssdp_response(item["data"], locator=locator)
        if parsed:
            parsed["responder_address"] = item["address"]
            parsed["responder_port"] = item["port"]
            responses.append(parsed)
    receipt.update({"stage": "protocol_ssdp", "protocol": "ssdp", "parsed_response_count": len(responses)})
    return {
        "protocol": "ssdp",
        "transport": "udp",
        "port": 1900,
        "confirmed": bool(responses),
        "responses": responses,
        "receipt": receipt,
    }


def _encode_dns_name(name: str) -> bytes:
    output = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("utf-8")
        if not encoded or len(encoded) > 63:
            raise ValueError("invalid DNS label")
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    return bytes(output)


def build_mdns_service_query() -> bytes:
    question = _encode_dns_name("_services._dns-sd._udp.local") + struct.pack("!HH", 12, 1)
    return struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + question


def _decode_dns_name(data: bytes, offset: int, *, depth: int = 0) -> tuple[str, int]:
    if depth > 12 or offset < 0 or offset >= len(data):
        raise ValueError("invalid DNS name")
    labels: list[str] = []
    cursor = offset
    consumed: int | None = None
    visited: set[int] = set()
    while cursor < len(data):
        if cursor in visited:
            raise ValueError("DNS compression loop")
        visited.add(cursor)
        length = data[cursor]
        if length == 0:
            cursor += 1
            if consumed is None:
                consumed = cursor
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            pointed, _ = _decode_dns_name(data, pointer, depth=depth + 1)
            if pointed:
                labels.append(pointed)
            cursor += 2
            if consumed is None:
                consumed = cursor
            break
        if length & 0xC0 or cursor + 1 + length > len(data):
            raise ValueError("invalid DNS label")
        cursor += 1
        labels.append(data[cursor:cursor + length].decode("utf-8", "replace"))
        cursor += length
    if consumed is None:
        raise ValueError("unterminated DNS name")
    return ".".join(label for label in labels if label), consumed


def parse_mdns_response(data: bytes) -> dict[str, Any] | None:
    if len(data) < 12:
        return None
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    cursor = 12
    try:
        for _ in range(min(qdcount, 64)):
            _name, cursor = _decode_dns_name(data, cursor)
            if cursor + 4 > len(data):
                return None
            cursor += 4
        records: list[dict[str, Any]] = []
        type_names = {1: "A", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV"}
        for _ in range(min(ancount + nscount + arcount, 256)):
            name, cursor = _decode_dns_name(data, cursor)
            if cursor + 10 > len(data):
                break
            record_type, record_class, ttl, rdlength = struct.unpack("!HHIH", data[cursor:cursor + 10])
            cursor += 10
            rdata_offset = cursor
            rdata = data[cursor:cursor + rdlength]
            if len(rdata) != rdlength:
                break
            cursor += rdlength
            value: Any
            if record_type == 12:
                value, _ = _decode_dns_name(data, rdata_offset)
            elif record_type == 33 and len(rdata) >= 6:
                priority, weight, port = struct.unpack("!HHH", rdata[:6])
                target, _ = _decode_dns_name(data, rdata_offset + 6)
                value = {"priority": priority, "weight": weight, "port": port, "target": target}
            elif record_type == 16:
                strings: list[str] = []
                index = 0
                while index < len(rdata):
                    length = rdata[index]
                    index += 1
                    strings.append(rdata[index:index + length].decode("utf-8", "replace"))
                    index += length
                value = strings
            elif record_type == 1 and len(rdata) == 4:
                value = socket.inet_ntop(socket.AF_INET, rdata)
            elif record_type == 28 and len(rdata) == 16:
                value = socket.inet_ntop(socket.AF_INET6, rdata)
            else:
                value = rdata.hex()[:2048]
            records.append({
                "name": name,
                "type": type_names.get(record_type, str(record_type)),
                "class": record_class & 0x7FFF,
                "cache_flush": bool(record_class & 0x8000),
                "ttl": ttl,
                "value": value,
            })
        return {
            "transaction_id": transaction_id,
            "flags": flags,
            "questions": qdcount,
            "answers": ancount,
            "authorities": nscount,
            "additionals": arcount,
            "records": records,
        }
    except (ValueError, struct.error, UnicodeError):
        return None


async def discover_mdns(locator: str, *, timeout: float = 2.0) -> dict[str, Any]:
    payload = build_mdns_service_query()
    raw, receipt = await _udp_exchange(locator, 5353, payload, timeout=timeout)
    responses: list[dict[str, Any]] = []
    for item in raw:
        parsed = parse_mdns_response(item["data"])
        if parsed:
            parsed["responder_address"] = item["address"]
            parsed["responder_port"] = item["port"]
            responses.append(parsed)
    receipt.update({"stage": "protocol_mdns", "protocol": "mdns", "parsed_response_count": len(responses)})
    return {
        "protocol": "mdns",
        "transport": "udp",
        "port": 5353,
        "confirmed": bool(responses),
        "responses": responses,
        "receipt": receipt,
    }


async def discover_core_device_protocols(locator: str, *, udp_ports: tuple[int, ...]) -> list[dict[str, Any]]:
    """Run only adapters whose ports are declared in the selected coverage profile."""
    tasks = []
    if 1900 in udp_ports:
        tasks.append(discover_ssdp(locator))
    if 5353 in udp_ports:
        tasks.append(discover_mdns(locator))
    return list(await asyncio.gather(*tasks)) if tasks else []
