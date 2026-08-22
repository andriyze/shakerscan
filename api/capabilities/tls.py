"""Shared target-bound TLS inspection used by Scan and Hunt."""

from __future__ import annotations

import asyncio
import hashlib
import math
import ssl
import time
from typing import Any
import urllib.parse

try:
    from runtime.models import TargetBinding
except ModuleNotFoundError:  # package imports in host-side tests
    from ..runtime.models import TargetBinding


def _origin(value: str) -> str | None:
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        return None
    return urllib.parse.urlunsplit((
        parsed.scheme.lower(), parsed.netloc.lower(), "", "", "",
    ))


async def inspect_tls_origin(
    origin: str,
    *,
    target: TargetBinding,
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    """Perform one SNI-preserving handshake against one frozen target address."""
    normalized_origin = _origin(origin)
    parsed = urllib.parse.urlsplit(normalized_origin or "")
    if normalized_origin is None or parsed.scheme != "https" or not parsed.hostname:
        return {
            "ok": False,
            "status": "not_applicable",
            "error": "tls inspection requires an HTTPS target origin",
            "budget_consumed": {
                "tcp_ports_attempted": 0,
                "tool_wall_seconds": 0,
            },
        }
    if (
        target.target_kind not in {"web", "api"}
        or parsed.hostname.lower().rstrip(".") != target.canonical_host
        or normalized_origin not in target.allowed_origins
    ):
        return {
            "ok": False,
            "status": "blocked",
            "error": "scope:TLS origin is outside the frozen target binding",
            "budget_consumed": {
                "tcp_ports_attempted": 0,
                "tool_wall_seconds": 0,
            },
        }
    if not target.allowed_addresses:
        return {
            "ok": False,
            "status": "blocked",
            "error": "scope:TLS target has no frozen address",
            "budget_consumed": {
                "tcp_ports_attempted": 0,
                "tool_wall_seconds": 0,
            },
        }

    pinned_address = target.allowed_addresses[0]
    port = parsed.port or 443
    timeout = max(1, min(15, int(timeout_seconds)))
    tls_context = ssl.create_default_context()
    tls_context.check_hostname = False
    tls_context.verify_mode = ssl.CERT_NONE
    tls_context.set_alpn_protocols(["h2", "http/1.1"])
    started = time.perf_counter()
    writer: asyncio.StreamWriter | None = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=pinned_address,
                port=port,
                ssl=tls_context,
                server_hostname=parsed.hostname,
            ),
            timeout=timeout,
        )
        tls_object = writer.get_extra_info("ssl_object")
        if tls_object is None:
            raise ssl.SSLError("TLS handshake produced no SSL object")
        certificate = tls_object.getpeercert(binary_form=True) or b""
        cipher = tls_object.cipher()
        elapsed = min(
            timeout,
            max(1, math.ceil(time.perf_counter() - started)),
        )
        return {
            "ok": True,
            "status": "success",
            "observation": {
                "kind": "tls_protocol",
                "origin": normalized_origin,
                "server_hostname": parsed.hostname,
                "pinned_address": pinned_address,
                "port": port,
                "protocol": tls_object.version(),
                "cipher": cipher[0] if cipher else None,
                "cipher_protocol": cipher[1] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "alpn_protocol": tls_object.selected_alpn_protocol(),
                "certificate_sha256": (
                    hashlib.sha256(certificate).hexdigest()
                    if certificate else None
                ),
                "certificate_bytes": len(certificate),
                "certificate_trust": "not_evaluated",
            },
            "budget_consumed": {
                "tcp_ports_attempted": 1,
                "tool_wall_seconds": elapsed,
            },
        }
    except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
        elapsed = min(
            timeout,
            max(1, math.ceil(time.perf_counter() - started)),
        )
        return {
            "ok": False,
            "status": "failed",
            "error": f"tls_handshake:{type(exc).__name__}",
            "budget_consumed": {
                "tcp_ports_attempted": 1,
                "tool_wall_seconds": elapsed,
            },
        }
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass
