"""Shared target-bound TLS inspection used by Scan and Hunt."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import errno
import hashlib
import ipaddress
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

try:
    from capabilities.tls_legacy_probe import PROBE_COUNT as LEGACY_PROBE_COUNT, probe_legacy_tls
except ModuleNotFoundError:  # package imports in host-side tests
    from .tls_legacy_probe import PROBE_COUNT as LEGACY_PROBE_COUNT, probe_legacy_tls


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


def _origin_key(value: str):
    parsed = urllib.parse.urlsplit(value)
    return parsed.scheme.lower(), parsed.hostname.lower().rstrip("."), parsed.port or (443 if parsed.scheme == "https" else 80)


# A TCP connect failing with one of these is either this host's kernel refusing an
# address it has no route to (nothing is sent) or a remote router's ICMP answer. Only
# the first is a limit of the worker rather than an observation of the target.
_ROUTE_FAILURE_ERRNOS = frozenset({
    errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT,
})


def _socket_errno(exc: BaseException) -> int | None:
    if isinstance(exc, ssl.SSLError) or not isinstance(exc, OSError):
        return None
    return exc.errno if isinstance(exc.errno, int) else None


_PROC_IF_INET6 = "/proc/net/if_inet6"
_PROC_ROUTE = "/proc/net/route"


def _worker_has_family_egress(version: int) -> bool | None:
    """Whether this worker has a usable address/route in the IP family, from the kernel's own
    tables. None when they cannot be read (not Linux), so the caller keeps the failure."""
    try:
        if version == 6:
            with open(_PROC_IF_INET6, encoding="ascii") as handle:
                rows = [line.split() for line in handle if line.strip()]
            # address, ifindex, prefix length, scope, flags, interface; scope 00 is global.
            return any(len(row) >= 6 and row[5] != "lo" and int(row[3], 16) == 0 for row in rows)
        with open(_PROC_ROUTE, encoding="ascii") as handle:
            rows = [line.split() for line in handle][1:]
        return any(len(row) >= 2 and row[0] != "lo" for row in rows)
    except (OSError, ValueError):
        return None


def worker_route_gap(address: str, observed_errno: int | None = None) -> dict[str, Any] | None:
    """Return why this worker cannot originate traffic to ``address``, else None.

    Called after a connect failed with a route errno. A Docker bridge without IPv6 egress
    answers every frozen AAAA address with ENETUNREACH locally; a remote router can return the
    same errno for a target path that does exist. Only the first is a limit of the worker, and
    the kernel's interface and route tables tell them apart without opening a socket.
    """
    try:
        parsed = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return None
    family_label = f"ipv{parsed.version}"
    errno_name = (
        errno.errorcode.get(observed_errno, str(observed_errno))
        if observed_errno is not None else None
    )
    if observed_errno == errno.EAFNOSUPPORT:
        return {
            "reason": "worker_address_family_unavailable",
            "address_family": family_label,
            "errno": errno_name,
        }
    if _worker_has_family_egress(parsed.version) is not False:
        return None
    return {
        "reason": "worker_route_unavailable",
        "address_family": family_label,
        "errno": errno_name,
    }


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
        target.target_kind not in {"web", "api", "network", "device"}
        or parsed.hostname.lower().rstrip(".") != target.canonical_host
        or _origin_key(normalized_origin) not in {_origin_key(o) for o in target.allowed_origins}
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
    route_gap: dict[str, Any] | None = None

    def record_failure(label: str, exc: BaseException) -> None:
        nonlocal route_gap
        code = _socket_errno(exc)
        protocol_results.append({
            "protocol": label,
            "supported": False,
            "error_type": type(exc).__name__,
            **(
                {"error_errno": errno.errorcode.get(code, str(code))}
                if code is not None else {}
            ),
        })
        if code in _ROUTE_FAILURE_ERRNOS and route_gap is None:
            route_gap = worker_route_gap(selected_address, code)

    for label, version in (
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ):
        if route_gap is not None:
            break
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        context.set_alpn_protocols(["h2", "http/1.1"])
        try:
            snapshot, certificate = await handshake(context)
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            record_failure(label, exc)
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
    if not successful and route_gap is None:
        fallback = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        fallback.check_hostname = False
        fallback.verify_mode = ssl.CERT_NONE
        fallback.set_alpn_protocols(["h2", "http/1.1"])
        try:
            snapshot, certificate = await handshake(fallback)
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            record_failure("default_negotiation", exc)
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

    # Legacy protocols and weak suites the worker's own TLS library cannot offer, probed with raw
    # ClientHello messages (capabilities/tls_legacy_probe.py). A server that accepts only such
    # suites is still examined from the certificate its first flight carries.
    legacy: dict[str, Any] = {}
    legacy_only = False
    if route_gap is None:
        attempts += LEGACY_PROBE_COUNT
        async def plain_connection(address: str, probe_port: int) -> tuple[Any, Any]:
            # Plain TCP to the same frozen address the handshakes use; no TLS library.
            return await asyncio.open_connection(host=address, port=probe_port)

        legacy = await probe_legacy_tls(
            selected_address, port, parsed.hostname, timeout=float(attempt_timeout),
            connect=plain_connection,
        )
        best = legacy.get("best")
        if not successful and isinstance(best, Mapping) and legacy.get("certificates"):
            chain = tuple(legacy["certificates"])
            successful.append(({
                "protocol": best.get("protocol"),
                "cipher": (best.get("cipher"), best.get("protocol"), best.get("cipher_bits")),
                "alpn_protocol": None,
                "certificate_chain": chain,
            }, chain[0]))
            legacy_only = True

    trust = "not_evaluated"
    trust_error_type: str | None = None
    trust_error: dict[str, Any] = {}
    if successful and not legacy_only:
        # Chain trust only. The name check is the separate hostname-match evidence: with it on,
        # a publicly trusted certificate issued for another name was also reported as an
        # untrusted chain, one defect counted twice under two titles.
        verified_context = ssl.create_default_context()
        verified_context.check_hostname = False
        verified_context.verify_mode = ssl.CERT_REQUIRED
        verified_context.set_alpn_protocols(["h2", "http/1.1"])
        try:
            await handshake(verified_context)
        except ssl.SSLCertVerificationError as exc:
            trust = "untrusted"
            trust_error_type = type(exc).__name__
            trust_error = _trust_error(exc)
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            trust_error_type = type(exc).__name__
        else:
            trust = "trusted"

    elapsed = min(
        timeout,
        max(1, math.ceil(time.perf_counter() - started)),
    )
    if route_gap is not None and not successful:
        # The kernel refused the connect locally: nothing reached the target, so this
        # is a limit of the worker, not TLS evidence about the address. Say so instead
        # of reporting a handshake failure the target never had a chance to cause.
        return {
            "ok": False,
            "status": "not_examined",
            "error": f"tls_route_unavailable:{route_gap['reason']}",
            "observation": {
                "kind": "tls_protocol",
                "origin": normalized_origin,
                "server_hostname": parsed.hostname,
                "pinned_address": selected_address,
                "attempted_addresses": [selected_address],
                "connected_addresses": [],
                "address_policy": socket_factory.policy_receipt,
                "port": port,
                "status": "not_examined",
                "examination_gap": dict(route_gap),
                "protocol_attempts": protocol_results,
                "certificate_trust": "not_evaluated",
            },
            "budget_consumed": {
                "tcp_ports_attempted": attempts,
                "tool_wall_seconds": elapsed,
            },
        }
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
                    "NULL", "RC4", "3DES", "DES-CBC", "EXPORT", "EXP-", "ADH-", "AECDH-",
                ))
            )
        ) or bool(legacy.get("weak_ciphers_supported")),
        "legacy_protocol_negotiated": (
            str(snapshot.get("protocol") or "")
            not in {"TLSv1.2", "TLSv1.3"}
        ) or bool(legacy.get("legacy_protocols_supported")),
        "legacy_protocol_probes": list(legacy.get("legacy_protocol_probes") or ()),
        "weak_cipher_probes": list(legacy.get("weak_cipher_probes") or ()),
        "legacy_protocols_supported": list(legacy.get("legacy_protocols_supported") or ()),
        "weak_ciphers_supported": list(legacy.get("weak_ciphers_supported") or ()),
        **({"examined_by": "raw_client_hello"} if legacy_only else {}),
        "alpn_protocol": snapshot.get("alpn_protocol"),
        "certificate_sha256": (
            hashlib.sha256(certificate).hexdigest() if certificate else None
        ),
        "certificate_bytes": len(certificate),
        "certificate_trust": trust,
        "certificate_trust_error_type": (
            "legacy_handshake_only" if legacy_only else trust_error_type
        ),
        **trust_error,
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


# OpenSSL X509_V_ERR codes, named for what an operator does about them.
_TRUST_FAILURE_KINDS: Mapping[int, str] = {
    2: "issuer_not_found",          # unable to get issuer certificate
    9: "not_yet_valid",
    10: "expired",
    18: "self_signed",              # depth-0 self-signed certificate
    19: "untrusted_root",           # self-signed certificate in chain (a private CA)
    20: "issuer_not_found",         # unable to get local issuer certificate
    21: "issuer_not_found",         # unable to verify the first certificate
    23: "revoked",
    24: "issuer_public_key_missing",
    79: "invalid_ca",
    26: "invalid_purpose",
    27: "untrusted_root",           # certificate not trusted
    28: "rejected",
}


def _trust_error(exc: ssl.SSLCertVerificationError) -> dict[str, Any]:
    """The verifier's own reason for refusing the chain: OpenSSL's code and message."""
    code = getattr(exc, "verify_code", None)
    message = getattr(exc, "verify_message", None)
    out: dict[str, Any] = {}
    if isinstance(code, int):
        out["certificate_trust_error_code"] = code
        out["certificate_trust_failure"] = _TRUST_FAILURE_KINDS.get(code, "other")
    if isinstance(message, str) and message.strip():
        out["certificate_trust_error"] = message.strip()[:200]
    return out


_MAX_CHAIN_DETAILS = 6


def _name_attribute(name: Any, oid: Any) -> str | None:
    try:
        values = name.get_attributes_for_oid(oid)
    except (AttributeError, ValueError):
        return None
    for value in values or ():
        text = str(getattr(value, "value", "") or "").strip()
        if text:
            return text[:200]
    return None


def _chain_details(certificates: tuple[bytes, ...]) -> list[dict[str, Any]]:
    """Subject, issuer, validity and CA flag of each certificate the server presented.

    Public certificate metadata only (no key material); bounded to the first few certificates.
    """
    if x509 is None:
        return []
    details: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for raw in certificates[:_MAX_CHAIN_DETAILS]:
        try:
            parsed = x509.load_der_x509_certificate(raw)
        except (TypeError, ValueError):
            details.append({"sha256": hashlib.sha256(raw).hexdigest(), "parse_status": "failed"})
            continue
        not_after = getattr(parsed, "not_valid_after_utc", None) or parsed.not_valid_after.replace(
            tzinfo=timezone.utc,
        )
        not_before = getattr(parsed, "not_valid_before_utc", None) or parsed.not_valid_before.replace(
            tzinfo=timezone.utc,
        )
        try:
            is_ca = bool(parsed.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        except x509.ExtensionNotFound:
            is_ca = False
        details.append({
            "subject": parsed.subject.rfc4514_string()[:400],
            "subject_cn": _name_attribute(parsed.subject, x509.NameOID.COMMON_NAME),
            "issuer": parsed.issuer.rfc4514_string()[:400],
            "issuer_cn": _name_attribute(parsed.issuer, x509.NameOID.COMMON_NAME),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "expired": now > not_after,
            "self_signed": parsed.subject == parsed.issuer,
            "is_ca": is_ca,
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    return details


def _authority_access(parsed: Any) -> dict[str, list[str]]:
    """AIA URLs: where a client may fetch a missing intermediate (CA Issuers) and check status."""
    out: dict[str, list[str]] = {"ca_issuers": [], "ocsp": []}
    try:
        descriptions = parsed.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess,
        ).value
    except (x509.ExtensionNotFound, ValueError):
        return out
    for item in descriptions:
        location = getattr(getattr(item, "access_location", None), "value", None)
        if not isinstance(location, str) or not location.lower().startswith(("http://", "https://")):
            continue
        if item.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
            out["ca_issuers"].append(location[:300])
        elif item.access_method == x509.AuthorityInformationAccessOID.OCSP:
            out["ocsp"].append(location[:300])
    return {key: value[:3] for key, value in out.items()}


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
    try:
        ip_names = tuple(str(item) for item in parsed.extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        ).value.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        ip_names = ()
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
        "certificate_dns_name_count": len(dns_names),
        "certificate_ip_addresses": list(ip_names[:20]),
        "certificate_subject_cn": _name_attribute(parsed.subject, x509.NameOID.COMMON_NAME),
        "certificate_issuer_cn": _name_attribute(parsed.issuer, x509.NameOID.COMMON_NAME),
        "certificate_hostname_matches": _hostname_matches(
            hostname, dns_names, ip_names,
        ),
        **{
            f"certificate_aia_{key}": value
            for key, value in _authority_access(parsed).items() if value
        },
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
        "certificate_chain_details": _chain_details(chain_certificates or (certificate,)),
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


def _hostname_matches(
    hostname: str, dns_names: tuple[str, ...], ip_names: tuple[str, ...] = (),
) -> bool | None:
    normalized = str(hostname or "").lower().rstrip(".").strip("[]")
    try:
        literal = ipaddress.ip_address(normalized)
    except ValueError:
        literal = None
    if not dns_names and not ip_names:
        # RFC 9525 section 4.1: the common name cannot identify a service. An IP identity
        # matches only an IP SAN, independently of chain trust (section 6.4).
        return False
    if literal is not None:
        # An address is matched only by an IP SAN, never by a DNS name or the common name.
        return any(_same_address(literal, item) for item in ip_names)
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
    route_errors: list[str] = []
    consumed = {"tcp_ports_attempted": 0, "tool_wall_seconds": 0}
    successes = 0
    examined = 0
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
            if result.get("status") == "not_examined":
                # The frozen address stays in the record with its examination gap, but a
                # worker that cannot route it (a Docker bridge without IPv6 egress facing
                # a CDN's AAAA records) must not turn every such target partial forever.
                route_errors.append(str(result.get("error") or "")[:200])
                continue
            examined += 1
            if result.get("ok"):
                successes += 1
            elif result.get("error"):
                errors.append(str(result["error"])[:200])
    if not examined:
        # Nothing this worker could route: no TLS evidence exists, which is a failure,
        # never a clean result.
        errors = route_errors
    partial = 0 < successes < examined
    return {
        "ok": successes > 0,
        "status": (
            "partial" if partial
            else "success" if examined and successes == examined
            else "failed"
        ),
        "partial": partial,
        "error": "tls_binding_partial" if partial else errors[0] if errors else None,
        "errors": errors[:100],
        "observations": observations,
        "budget_consumed": consumed,
    }


def _same_address(literal: Any, candidate: str) -> bool:
    try:
        return ipaddress.ip_address(str(candidate)) == literal
    except ValueError:
        return False
