"""Shared target-bound TLS inspection used by Scan and Hunt."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import math
import ssl
import time
from typing import Any, Mapping
import urllib.parse

try:
    from cryptography import x509
except ModuleNotFoundError:  # minimal host-side test environments
    x509 = None

try:
    from runtime.models import TargetBinding
    from runtime.target_bound_socket import FrozenTargetSocketFactory
except ModuleNotFoundError:  # package imports in host-side tests
    from ..runtime.models import TargetBinding
    from ..runtime.target_bound_socket import FrozenTargetSocketFactory


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
    pinned_address: str | None = None,
) -> dict[str, Any]:
    """Inspect modern protocols, leaf certificate, and trust on one frozen address."""
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

    port = parsed.port or 443
    try:
        socket_factory = FrozenTargetSocketFactory(
            hostname=parsed.hostname,
            port=port,
            frozen_addresses=target.allowed_addresses,
        )
    except ValueError as exc:
        return {
            "ok": False,
            "status": "blocked",
            "error": f"scope:TLS target address policy is invalid: {exc}",
            "budget_consumed": {
                "tcp_ports_attempted": 0,
                "tool_wall_seconds": 0,
            },
        }
    selected_address = str(
        pinned_address or socket_factory.primary_address
    ).strip()
    if selected_address not in target.allowed_addresses:
        return {
            "ok": False,
            "status": "blocked",
            "error": "scope:TLS address is outside the frozen target binding",
            "budget_consumed": {
                "tcp_ports_attempted": 0,
                "tool_wall_seconds": 0,
            },
        }
    timeout = max(4, min(15, int(timeout_seconds)))
    attempt_timeout = max(1, timeout // 4)
    started = time.perf_counter()
    attempts = 0

    async def handshake(context: ssl.SSLContext) -> tuple[dict[str, Any], bytes]:
        nonlocal attempts
        attempts += 1
        writer: asyncio.StreamWriter | None = None
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=selected_address,
                    port=port,
                    ssl=context,
                    server_hostname=parsed.hostname,
                ),
                timeout=attempt_timeout,
            )
            tls_object = writer.get_extra_info("ssl_object")
            if tls_object is None:
                raise ssl.SSLError("TLS handshake produced no SSL object")
            certificate = tls_object.getpeercert(binary_form=True) or b""
            # SSLObject access after StreamWriter.wait_closed() is backend- and
            # timing-dependent. Snapshot every proof-bearing value while the
            # connection is live; a closed object has returned None in production
            # and was then misclassified as a verified legacy protocol.
            return {
                "protocol": tls_object.version(),
                "cipher": tls_object.cipher(),
                "alpn_protocol": tls_object.selected_alpn_protocol(),
                "certificate_chain": _certificate_chain(tls_object, certificate),
            }, certificate
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
                except (OSError, ssl.SSLError, asyncio.TimeoutError):
                    pass

    protocol_results: list[dict[str, Any]] = []
    successful: list[tuple[dict[str, Any], bytes]] = []
    for label, version in (
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        context.set_alpn_protocols(["h2", "http/1.1"])
        try:
            snapshot, certificate = await handshake(context)
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            protocol_results.append({
                "protocol": label,
                "supported": False,
                "error_type": type(exc).__name__,
            })
        else:
            cipher = snapshot.get("cipher")
            protocol_results.append({
                "protocol": label,
                "supported": True,
                "negotiated_protocol": snapshot.get("protocol"),
                "cipher": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "alpn_protocol": snapshot.get("alpn_protocol"),
            })
            successful.append((snapshot, certificate))

    # If the two supported modern profiles both fail, one default negotiation
    # distinguishes a reachable legacy-only endpoint from a non-TLS service.
    if not successful:
        fallback = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        fallback.check_hostname = False
        fallback.verify_mode = ssl.CERT_NONE
        fallback.set_alpn_protocols(["h2", "http/1.1"])
        try:
            snapshot, certificate = await handshake(fallback)
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            protocol_results.append({
                "protocol": "default_negotiation",
                "supported": False,
                "error_type": type(exc).__name__,
            })
        else:
            cipher = snapshot.get("cipher")
            protocol_results.append({
                "protocol": "default_negotiation",
                "supported": True,
                "negotiated_protocol": snapshot.get("protocol"),
                "cipher": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "alpn_protocol": snapshot.get("alpn_protocol"),
            })
            successful.append((snapshot, certificate))

    trust = "not_evaluated"
    trust_error_type: str | None = None
    if successful:
        verified_context = ssl.create_default_context()
        verified_context.check_hostname = True
        verified_context.verify_mode = ssl.CERT_REQUIRED
        verified_context.set_alpn_protocols(["h2", "http/1.1"])
        try:
            await handshake(verified_context)
        except ssl.SSLCertVerificationError as exc:
            trust = "untrusted"
            trust_error_type = type(exc).__name__
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            trust_error_type = type(exc).__name__
        else:
            trust = "trusted"

    elapsed = min(
        timeout,
        max(1, math.ceil(time.perf_counter() - started)),
    )
    if not successful:
        return {
            "ok": False,
            "status": "failed",
            "error": "tls_handshake:no_supported_protocol",
            "observation": {
                "kind": "tls_protocol",
                "origin": normalized_origin,
                "server_hostname": parsed.hostname,
                "pinned_address": selected_address,
                "attempted_addresses": [selected_address],
                "connected_addresses": [],
                "address_policy": socket_factory.policy_receipt,
                "port": port,
                "status": "failed",
                "protocol_attempts": protocol_results,
                "certificate_trust": "not_evaluated",
            },
            "budget_consumed": {
                "tcp_ports_attempted": attempts,
                "tool_wall_seconds": elapsed,
            },
        }

    snapshot, certificate = successful[0]
    cipher = snapshot.get("cipher")
    certificate_details = _certificate_details(
        certificate,
        hostname=str(parsed.hostname),
        chain_certificates=tuple(snapshot.get("certificate_chain") or ()),
    )
    observation = {
        "kind": "tls_protocol",
        "origin": normalized_origin,
        "server_hostname": parsed.hostname,
        "pinned_address": selected_address,
        "attempted_addresses": [selected_address],
        "connected_addresses": [selected_address],
        "address_policy": socket_factory.policy_receipt,
        "port": port,
        "status": "success",
        "protocol": snapshot.get("protocol"),
        "supported_protocols": [
            item["protocol"] for item in protocol_results
            if item.get("supported") is True
            and item.get("protocol") != "default_negotiation"
        ],
        "protocol_attempts": protocol_results,
        "cipher": cipher[0] if cipher else None,
        "cipher_protocol": cipher[1] if cipher else None,
        "cipher_bits": cipher[2] if cipher else None,
        "weak_cipher": bool(
            cipher and (
                int(cipher[2] or 0) < 128
                or any(marker in str(cipher[0]).upper() for marker in (
                    "NULL", "RC4", "3DES", "DES-CBC", "EXPORT",
                ))
            )
        ),
        "legacy_protocol_negotiated": (
            str(snapshot.get("protocol") or "")
            not in {"TLSv1.2", "TLSv1.3"}
        ),
        "alpn_protocol": snapshot.get("alpn_protocol"),
        "certificate_sha256": (
            hashlib.sha256(certificate).hexdigest() if certificate else None
        ),
        "certificate_bytes": len(certificate),
        "certificate_trust": trust,
        "certificate_trust_error_type": trust_error_type,
        **certificate_details,
    }
    return {
        "ok": True,
        "status": "success",
        "observation": observation,
        "budget_consumed": {
            "tcp_ports_attempted": attempts,
            "tool_wall_seconds": elapsed,
        },
    }


def _certificate_chain(tls_object: Any, leaf: bytes) -> tuple[bytes, ...]:
    """Extract the peer-provided chain when supported, retaining the leaf fallback."""
    certificates: list[bytes] = []
    loader = getattr(tls_object, "get_unverified_chain", None)
    if callable(loader):
        try:
            chain = loader()
        except (OSError, ssl.SSLError, ValueError):
            chain = ()
        for item in chain or ():
            try:
                raw = item.public_bytes() if hasattr(item, "public_bytes") else item
            except (TypeError, ValueError):
                continue
            if isinstance(raw, str):
                try:
                    raw = ssl.PEM_cert_to_DER_cert(raw)
                except ValueError:
                    continue
            elif isinstance(raw, bytes) and raw.startswith(b"-----BEGIN"):
                try:
                    raw = ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))
                except (UnicodeDecodeError, ValueError):
                    continue
            if isinstance(raw, bytes) and raw and raw not in certificates:
                certificates.append(raw)
    if leaf and leaf not in certificates:
        certificates.insert(0, leaf)
    return tuple(certificates)


def _certificate_details(
    certificate: bytes,
    *,
    hostname: str,
    chain_certificates: tuple[bytes, ...] = (),
) -> dict[str, Any]:
    """Decode content-free certificate posture when the release dependency exists."""
    if not certificate or x509 is None:
        return {
            "certificate_parse_status": "unavailable",
            **_certificate_chain_summary(chain_certificates or (certificate,)),
        }
    try:
        parsed = x509.load_der_x509_certificate(certificate)
    except (TypeError, ValueError):
        return {
            "certificate_parse_status": "failed",
            **_certificate_chain_summary(chain_certificates or (certificate,)),
        }
    try:
        dns_names = tuple(parsed.extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        ).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        dns_names = ()
    not_before = getattr(parsed, "not_valid_before_utc", None)
    not_after = getattr(parsed, "not_valid_after_utc", None)
    if not_before is None:
        not_before = parsed.not_valid_before.replace(tzinfo=timezone.utc)
    if not_after is None:
        not_after = parsed.not_valid_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    public_key = parsed.public_key()
    signature_hash = None
    try:
        signature_hash = parsed.signature_hash_algorithm.name
    except (ValueError, TypeError):
        pass
    return {
        "certificate_parse_status": "parsed",
        "certificate_subject": parsed.subject.rfc4514_string(),
        "certificate_issuer": parsed.issuer.rfc4514_string(),
        "certificate_serial_hex": format(parsed.serial_number, "x"),
        "certificate_not_before": not_before.isoformat(),
        "certificate_not_after": not_after.isoformat(),
        "certificate_expired": now > not_after,
        "certificate_not_yet_valid": now < not_before,
        "certificate_days_remaining": math.floor(
            (not_after - now).total_seconds() / 86_400
        ),
        "certificate_expiring_within_30_days": (
            0 <= (not_after - now).total_seconds() <= 30 * 86_400
        ),
        "certificate_dns_names": list(dns_names[:100]),
        "certificate_hostname_matches": _hostname_matches(
            hostname, dns_names,
        ),
        "certificate_self_signed": parsed.subject == parsed.issuer,
        "certificate_signature_algorithm": (
            parsed.signature_algorithm_oid.dotted_string
        ),
        "certificate_signature_hash": signature_hash,
        "certificate_weak_signature": signature_hash in {"md5", "sha1"},
        "certificate_public_key_type": type(public_key).__name__,
        "certificate_public_key_bits": getattr(public_key, "key_size", None),
        "certificate_weak_public_key": bool(
            getattr(public_key, "key_size", 0)
            and (
                (
                    "RSA" in type(public_key).__name__.upper()
                    and int(public_key.key_size) < 2_048
                )
                or (
                    "ELLIPTIC" in type(public_key).__name__.upper()
                    and int(public_key.key_size) < 224
                )
            )
        ),
        **_certificate_chain_summary(chain_certificates or (certificate,)),
    }


def _certificate_chain_summary(certificates: tuple[bytes, ...]) -> dict[str, Any]:
    bounded = tuple(item for item in certificates[:20] if item)
    return {
        "certificate_chain_sha256": [
            hashlib.sha256(item).hexdigest() for item in bounded
        ],
        "certificate_chain_length": len(bounded),
        "certificate_chain_status": (
            "peer_chain" if len(bounded) > 1 else "leaf_only" if bounded else "missing"
        ),
    }


def _hostname_matches(hostname: str, dns_names: tuple[str, ...]) -> bool | None:
    if not dns_names:
        return None
    normalized = str(hostname or "").lower().rstrip(".")
    for raw_name in dns_names:
        name = str(raw_name or "").lower().rstrip(".")
        if name == normalized:
            return True
        if name.startswith("*.") and normalized.endswith(name[1:]) and (
            normalized.count(".") == name.count(".")
        ):
            return True
    return False


async def inspect_tls_binding(
    *,
    target: TargetBinding,
    timeout_seconds_per_target: int = 15,
) -> dict[str, Any]:
    """Inspect every frozen HTTPS origin/address pair under one exact action hold."""
    origins = tuple(sorted(
        str(item) for item in target.allowed_origins
        if str(item).lower().startswith("https://")
    ))
    try:
        socket_factory = FrozenTargetSocketFactory(
            hostname=target.canonical_host,
            port=443,
            frozen_addresses=target.allowed_addresses,
        )
    except ValueError:
        addresses = ()
    else:
        addresses = socket_factory.addresses
    if not origins or not addresses:
        return {
            "ok": False,
            "status": "not_applicable",
            "partial": False,
            "error": "tls binding has no HTTPS origin/address pairs",
            "errors": [],
            "observations": [],
            "budget_consumed": {
                "tcp_ports_attempted": 0,
                "tool_wall_seconds": 0,
            },
        }
    observations: list[Mapping[str, Any]] = []
    errors: list[str] = []
    consumed = {"tcp_ports_attempted": 0, "tool_wall_seconds": 0}
    successes = 0
    for origin in origins:
        for address in addresses:
            result = await inspect_tls_origin(
                origin,
                target=target,
                timeout_seconds=timeout_seconds_per_target,
                pinned_address=address,
            )
            measured = result.get("budget_consumed")
            if isinstance(measured, Mapping):
                for name in consumed:
                    consumed[name] += max(0, int(measured.get(name) or 0))
            if isinstance(result.get("observation"), Mapping):
                observations.append(dict(result["observation"]))
            if result.get("ok"):
                successes += 1
            elif result.get("error"):
                errors.append(str(result["error"])[:200])
    total = len(origins) * len(addresses)
    partial = 0 < successes < total
    return {
        "ok": successes > 0,
        "status": "partial" if partial else "success" if successes == total else "failed",
        "partial": partial,
        "error": "tls_binding_partial" if partial else errors[0] if errors else None,
        "errors": errors[:100],
        "observations": observations,
        "budget_consumed": consumed,
    }
