"""Legacy TLS protocol and weak cipher-suite support, probed with raw ClientHello messages.

Why raw messages: the worker's OpenSSL is built without (or refuses at its security level) SSL 3.0,
TLS 1.0/1.1, RC4, single DES, EXPORT, NULL and anonymous suites. A client that cannot offer a
protocol or suite cannot learn whether the server would accept it, so a server that still enables
them looked clean, and a server that offered ONLY such suites failed every handshake and the Scan
reported the target unreachable.

Support is decided by the server's first flight, before any key exchange: one ClientHello offering
exactly the protocol version (or exactly the suite group) under test, then the ServerHello the
server answers with. A ServerHello that selects the offered version and one of the offered suites
is acceptance; a handshake alert, a reset or silence is refusal. TLS up to 1.2 sends the
certificate in the clear in the same flight, so a server that speaks only legacy protocols or
suites still yields its certificate for the certificate checks. Nothing here completes a handshake,
sends application data or holds a session: each probe is one TCP connection to the frozen address,
one message out and at most ``_MAX_RESPONSE_BYTES`` back.

This module is pure protocol encoding plus one bounded connection per probe; scope (which address
and port may be contacted) is decided by the caller, exactly as for the stdlib handshakes.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import struct
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping, Sequence

# Wire versions.
SSL3 = 0x0300
TLS10 = 0x0301
TLS11 = 0x0302
TLS12 = 0x0303
VERSION_NAMES: Mapping[int, str] = {SSL3: "SSLv3", TLS10: "TLSv1", TLS11: "TLSv1.1", TLS12: "TLSv1.2"}

# IANA code -> (OpenSSL name, bits, weakness class or "" when not weak). OpenSSL names match what
# ``ssl.SSLSocket.cipher()`` reports for the stdlib handshakes, so one finding reads the same
# whichever path observed it.
SUITES: Mapping[int, tuple[str, int, str]] = {
    0xC02F: ("ECDHE-RSA-AES128-GCM-SHA256", 128, ""),
    0xC030: ("ECDHE-RSA-AES256-GCM-SHA384", 256, ""),
    0xC02B: ("ECDHE-ECDSA-AES128-GCM-SHA256", 128, ""),
    0xC02C: ("ECDHE-ECDSA-AES256-GCM-SHA384", 256, ""),
    0xCCA8: ("ECDHE-RSA-CHACHA20-POLY1305", 256, ""),
    0xCCA9: ("ECDHE-ECDSA-CHACHA20-POLY1305", 256, ""),
    0xC013: ("ECDHE-RSA-AES128-SHA", 128, ""),
    0xC014: ("ECDHE-RSA-AES256-SHA", 256, ""),
    0xC009: ("ECDHE-ECDSA-AES128-SHA", 128, ""),
    0xC00A: ("ECDHE-ECDSA-AES256-SHA", 256, ""),
    0x009E: ("DHE-RSA-AES128-GCM-SHA256", 128, ""),
    0x009F: ("DHE-RSA-AES256-GCM-SHA384", 256, ""),
    0x0033: ("DHE-RSA-AES128-SHA", 128, ""),
    0x0039: ("DHE-RSA-AES256-SHA", 256, ""),
    0x009C: ("AES128-GCM-SHA256", 128, ""),
    0x009D: ("AES256-GCM-SHA384", 256, ""),
    0x003C: ("AES128-SHA256", 128, ""),
    0x003D: ("AES256-SHA256", 256, ""),
    0x002F: ("AES128-SHA", 128, ""),
    0x0035: ("AES256-SHA", 256, ""),
    0x000A: ("DES-CBC3-SHA", 112, "3des"),
    0xC012: ("ECDHE-RSA-DES-CBC3-SHA", 112, "3des"),
    0xC008: ("ECDHE-ECDSA-DES-CBC3-SHA", 112, "3des"),
    0x0016: ("EDH-RSA-DES-CBC3-SHA", 112, "3des"),
    0x0009: ("DES-CBC-SHA", 56, "des"),
    0x0015: ("EDH-RSA-DES-CBC-SHA", 56, "des"),
    0x0005: ("RC4-SHA", 128, "rc4"),
    0x0004: ("RC4-MD5", 128, "rc4"),
    0xC011: ("ECDHE-RSA-RC4-SHA", 128, "rc4"),
    0xC007: ("ECDHE-ECDSA-RC4-SHA", 128, "rc4"),
    0x0001: ("NULL-MD5", 0, "null"),
    0x0002: ("NULL-SHA", 0, "null"),
    0x003B: ("NULL-SHA256", 0, "null"),
    0xC010: ("ECDHE-RSA-NULL-SHA", 0, "null"),
    0xC006: ("ECDHE-ECDSA-NULL-SHA", 0, "null"),
    0x0003: ("EXP-RC4-MD5", 40, "export"),
    0x0006: ("EXP-RC2-CBC-MD5", 40, "export"),
    0x0008: ("EXP-DES-CBC-SHA", 40, "export"),
    0x0014: ("EXP-EDH-RSA-DES-CBC-SHA", 40, "export"),
    0x0018: ("ADH-RC4-MD5", 128, "anonymous"),
    0x0034: ("ADH-AES128-SHA", 128, "anonymous"),
    0x003A: ("ADH-AES256-SHA", 256, "anonymous"),
    0x001B: ("ADH-DES-CBC3-SHA", 112, "anonymous"),
    0xC018: ("AECDH-AES128-SHA", 128, "anonymous"),
    0xC019: ("AECDH-AES256-SHA", 256, "anonymous"),
}
# Worst first: the order a finding names the weakest suite the server accepts.
WEAKNESS_ORDER = ("null", "anonymous", "export", "des", "rc4", "3des")

_STRONG = tuple(code for code, (_n, _b, weak) in SUITES.items() if not weak)
_ALL = tuple(SUITES)

# One probe per protocol version (every suite offered, so a server that enables the version with
# any suite answers) and one per weak suite group at the highest legacy version (the server picks
# the version; any weak suite it selects is accepted at that version).
PROTOCOL_PROBES: tuple[tuple[str, int], ...] = (("SSLv3", SSL3), ("TLSv1", TLS10), ("TLSv1.1", TLS11))
CIPHER_GROUP_PROBES: tuple[tuple[str, tuple[int, ...]], ...] = (
    ("rc4", tuple(code for code, row in SUITES.items() if row[2] == "rc4")),
    ("des_3des", tuple(code for code, row in SUITES.items() if row[2] in {"3des", "des"})),
    ("null_export_anonymous", tuple(code for code, row in SUITES.items() if row[2] in {"null", "export", "anonymous"})),
)
PROBE_COUNT = len(PROTOCOL_PROBES) + len(CIPHER_GROUP_PROBES)

_MAX_RESPONSE_BYTES = 96 * 1024
_MAX_CERTIFICATES = 8
_HANDSHAKE, _ALERT = 0x16, 0x15
_SERVER_HELLO, _CERTIFICATE, _SERVER_HELLO_DONE = 2, 11, 14


def _extension(kind: int, body: bytes) -> bytes:
    return struct.pack("!HH", kind, len(body)) + body


def _sni_host(server_name: str | None) -> bytes | None:
    name = str(server_name or "").strip().rstrip(".")
    if not name:
        return None
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return None  # RFC 6066: literal addresses are never sent as SNI
    try:
        encoded = name.encode("idna")
    except UnicodeError:
        return None
    return encoded if 0 < len(encoded) <= 253 else None


def client_hello(version: int, suites: Sequence[int], server_name: str | None, *, random: bytes | None = None) -> bytes:
    """One TLS record holding a ClientHello that offers exactly ``version`` and ``suites``."""
    random = random if random is not None and len(random) == 32 else os.urandom(32)
    cipher_bytes = b"".join(struct.pack("!H", code) for code in suites)
    body = struct.pack("!H", version) + random + b"\x00"
    body += struct.pack("!H", len(cipher_bytes)) + cipher_bytes + b"\x01\x00"
    if version >= TLS10:
        extensions = b""
        host = _sni_host(server_name)
        if host is not None:
            entry = b"\x00" + struct.pack("!H", len(host)) + host
            extensions += _extension(0x0000, struct.pack("!H", len(entry)) + entry)
        groups = b"".join(struct.pack("!H", group) for group in (0x001D, 0x0017, 0x0018, 0x0019))
        extensions += _extension(0x000A, struct.pack("!H", len(groups)) + groups)
        extensions += _extension(0x000B, b"\x01\x00")
        if version >= TLS12:
            algorithms = b"".join(struct.pack("!H", item) for item in (
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
            ))
            extensions += _extension(0x000D, struct.pack("!H", len(algorithms)) + algorithms)
        extensions += _extension(0xFF01, b"\x00")
        body += struct.pack("!H", len(extensions)) + extensions
    handshake = bytes([1]) + len(body).to_bytes(3, "big") + body
    return bytes([_HANDSHAKE]) + struct.pack("!HH", min(version, TLS10), len(handshake)) + handshake


@dataclass
class ServerFlight:
    """What the server's first flight said about one ClientHello."""

    outcome: str = "no_answer"  # accepted | refused | no_answer | invalid
    version: int | None = None
    suite: int | None = None
    alert: int | None = None
    certificates: list[bytes] = field(default_factory=list)
    complete: bool = False


def parse_server_flight(data: bytes, *, offered_version: int, offered_suites: Sequence[int]) -> ServerFlight:
    """Read records until ServerHelloDone, an alert, or the end of ``data``."""
    flight = ServerFlight()
    handshake = bytearray()
    offset = 0
    saw_record = False
    while offset + 5 <= len(data):
        record_type = data[offset]
        record_version = struct.unpack("!H", data[offset + 1:offset + 3])[0]
        length = struct.unpack("!H", data[offset + 3:offset + 5])[0]
        if record_type not in {_HANDSHAKE, _ALERT, 0x14, 0x17} or record_version >> 8 != 3 or length > 18_432:
            flight.outcome = "invalid" if not saw_record else flight.outcome
            break
        saw_record = True
        payload = data[offset + 5:offset + 5 + length]
        offset += 5 + length
        if len(payload) < length:
            break  # truncated record: use what was complete
        if record_type == _ALERT:
            if flight.outcome != "accepted" and len(payload) >= 2:
                flight.outcome, flight.alert = "refused", payload[1]
            break
        if record_type != _HANDSHAKE:
            continue
        handshake.extend(payload)
        if _consume_handshake(handshake, flight, offered_version, offered_suites):
            break
    if flight.outcome == "no_answer" and saw_record and flight.version is None:
        flight.outcome = "invalid"
    return flight


def _consume_handshake(buffer: bytearray, flight: ServerFlight, offered_version: int, offered_suites: Sequence[int]) -> bool:
    """Parse whole handshake messages from ``buffer``; True when the flight is finished."""
    while len(buffer) >= 4:
        kind = buffer[0]
        length = int.from_bytes(buffer[1:4], "big")
        if len(buffer) < 4 + length:
            return False
        body = bytes(buffer[4:4 + length])
        del buffer[:4 + length]
        if kind == _SERVER_HELLO:
            if len(body) < 38:
                flight.outcome = "invalid"
                return True
            version = struct.unpack("!H", body[0:2])[0]
            session_length = body[34]
            if len(body) < 35 + session_length + 3:
                flight.outcome = "invalid"
                return True
            suite = struct.unpack("!H", body[35 + session_length:37 + session_length])[0]
            flight.version, flight.suite = version, suite
            # A server may only select what was offered; anything else is not acceptance.
            if offered_version < TLS12 and SSL3 <= version < offered_version:
                # The server answered with an older version than the one under test: it does
                # not support the tested version (the older one has its own probe).
                flight.outcome = "refused"
                return True
            accepted = version == offered_version if offered_version < TLS12 else SSL3 <= version <= offered_version
            flight.outcome = "accepted" if accepted and suite in offered_suites else "invalid"
        elif kind == _CERTIFICATE and flight.outcome == "accepted":
            flight.certificates = _certificates(body)
        elif kind == _SERVER_HELLO_DONE:
            flight.complete = True
            return True
    return False


def _certificates(body: bytes) -> list[bytes]:
    if len(body) < 3:
        return []
    total = int.from_bytes(body[0:3], "big")
    cursor, end = 3, min(len(body), 3 + total)
    out: list[bytes] = []
    while cursor + 3 <= end and len(out) < _MAX_CERTIFICATES:
        size = int.from_bytes(body[cursor:cursor + 3], "big")
        cursor += 3
        if size <= 0 or cursor + size > end:
            break
        out.append(body[cursor:cursor + size])
        cursor += size
    return out


# The caller supplies the connection: scope (which frozen address and port) is its decision, and
# the reviewed connect site stays in capabilities/tls.py.
Connector = Callable[[str, int], Awaitable[tuple[Any, Any]]]


async def send_probe(
    address: str, port: int, hello: bytes, *, offered_version: int, offered_suites: Sequence[int],
    timeout: float, connect: Connector,
) -> ServerFlight:
    """One connection, one ClientHello, the server's first flight; never raises for network errors."""
    writer = None
    data = bytearray()
    try:
        async def exchange() -> None:
            nonlocal writer
            reader, writer = await connect(address, port)
            writer.write(hello)
            await writer.drain()
            while len(data) < _MAX_RESPONSE_BYTES:
                chunk = await reader.read(min(16_384, _MAX_RESPONSE_BYTES - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                flight = parse_server_flight(bytes(data), offered_version=offered_version, offered_suites=offered_suites)
                if flight.complete or flight.outcome in {"refused", "invalid"}:
                    break
        await asyncio.wait_for(exchange(), timeout=timeout)
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 - a probe that cannot complete is a refusal, never an error
        pass
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except Exception:  # noqa: BLE001 - closing a refused probe must not raise
                pass
    if not data:
        return ServerFlight(outcome="no_answer")
    return parse_server_flight(bytes(data), offered_version=offered_version, offered_suites=offered_suites)


def _row(flight: ServerFlight) -> dict[str, Any]:
    name, bits, weakness = SUITES.get(flight.suite or -1, (None, None, ""))
    row: dict[str, Any] = {"supported": flight.outcome == "accepted", "result": flight.outcome}
    if flight.outcome == "accepted":
        row.update({
            "negotiated_protocol": VERSION_NAMES.get(flight.version or 0),
            "cipher": name, "cipher_bits": bits,
            **({"weakness": weakness} if weakness else {}),
        })
    if flight.alert is not None:
        row["alert"] = flight.alert
    return row


async def probe_legacy_tls(
    address: str, port: int, server_name: str | None, *, timeout: float, connect: Connector,
) -> dict[str, Any]:
    """Probe every legacy protocol and weak suite group concurrently (``PROBE_COUNT`` connections).

    Returns value-free evidence: per-probe outcome, the accepted protocol versions and weak
    suites, and the certificates the first accepting server flight carried (DER), for a server
    the stdlib client cannot handshake with at all.
    """
    jobs: list[tuple[str, str, int, tuple[int, ...]]] = [
        ("protocol", label, version, _ALL) for label, version in PROTOCOL_PROBES
    ] + [("cipher", label, TLS12, suites) for label, suites in CIPHER_GROUP_PROBES]
    flights = await asyncio.gather(*(
        send_probe(address, port, client_hello(version, suites, server_name),
                   offered_version=version, offered_suites=suites, timeout=timeout, connect=connect)
        for _kind, _label, version, suites in jobs
    ))
    protocol_rows: list[dict[str, Any]] = []
    cipher_rows: list[dict[str, Any]] = []
    certificates: list[bytes] = []
    best: tuple[int, int] | None = None
    for (kind, label, _version, _suites), flight in zip(jobs, flights):
        row = {("protocol" if kind == "protocol" else "group"): label, **_row(flight)}
        (protocol_rows if kind == "protocol" else cipher_rows).append(row)
        if flight.outcome == "accepted":
            if flight.certificates and not certificates:
                certificates = list(flight.certificates)
            if flight.version is not None and flight.suite is not None and (best is None or flight.version > best[0]):
                best = (flight.version, flight.suite)
    weak = sorted(
        {row["cipher"]: row.get("weakness") for row in cipher_rows if row.get("supported") and row.get("weakness")}.items(),
        key=lambda item: WEAKNESS_ORDER.index(item[1]) if item[1] in WEAKNESS_ORDER else 99,
    )
    return {
        "legacy_protocol_probes": protocol_rows,
        "weak_cipher_probes": cipher_rows,
        "legacy_protocols_supported": [row["protocol"] for row in protocol_rows if row["supported"]],
        "weak_ciphers_supported": [name for name, _weakness in weak],
        "probe_connections": len(jobs),
        "best": (
            {"protocol": VERSION_NAMES.get(best[0]), "cipher": SUITES.get(best[1], (None,))[0],
             "cipher_bits": SUITES.get(best[1], (None, None))[1]}
            if best else None
        ),
        "certificates": certificates,
    }


__all__ = [
    "CIPHER_GROUP_PROBES", "PROBE_COUNT", "PROTOCOL_PROBES", "SUITES", "ServerFlight", "VERSION_NAMES",
    "WEAKNESS_ORDER", "client_hello", "parse_server_flight", "probe_legacy_tls", "send_probe",
]
