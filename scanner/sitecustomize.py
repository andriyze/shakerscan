"""Fail-closed frozen DNS resolver for canonical ShakerScan subprocesses.

Python imports ``sitecustomize`` before executing ``scanner.py``. Canonical Scan
workers pass the immutable ``native-scan-execution`` envelope in
``SHAKERSCAN_CANONICAL_SCAN_EXECUTION``. This module verifies the embedded target
binding and replaces process-local resolver functions so target-host connections
use only the frozen address set. Other hostnames keep the platform resolver.

The resolver is deliberately process-local. API/worker processes normally do not
carry the canonical execution environment variable and are therefore unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
import socket
import sys
from typing import Any, Mapping, MutableMapping
from urllib.parse import urlsplit


_ENV_NAME = "SHAKERSCAN_CANONICAL_SCAN_EXECUTION"
_ACTIVE_ENV_NAME = "SHAKERSCAN_FROZEN_DNS_ACTIVE"
_SUPPORTED_SCHEMAS = frozenset({
    "native-scan-execution/v2",
    "native-scan-execution/v3",
})
_MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
_MAX_ADDRESSES = 64
_TARGET_BINDING_KEYS = frozenset({
    "target_id",
    "target_kind",
    "canonical_host",
    "allowed_origins",
    "allowed_addresses",
    "allowed_root_domains",
    "environment",
    "scope_receipt_id",
})
_MARKER = "_shakerscan_frozen_dns_config"


class FrozenResolverError(RuntimeError):
    """Canonical target DNS authority is malformed or conflicting."""


@dataclass(frozen=True)
class FrozenResolverConfig:
    target_host: str
    allowed_addresses: tuple[str, ...]
    target_binding_digest: str


def _canonical_json_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalized_host(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return ""
    text = str(value or "").strip().rstrip(".")
    if not text or len(text) > 253 or any(ord(ch) < 33 for ch in text):
        return ""
    try:
        return text.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""


def _configuration_from_environment(
    environ: Mapping[str, str] | None = None,
) -> FrozenResolverConfig | None:
    source = os.environ if environ is None else environ
    raw = str(source.get(_ENV_NAME) or "")
    if not raw:
        return None
    if len(raw.encode("utf-8")) > _MAX_ENVELOPE_BYTES:
        raise FrozenResolverError("canonical Scan execution envelope is too large")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FrozenResolverError(
            "canonical Scan execution envelope is invalid JSON"
        ) from exc
    if not isinstance(payload, Mapping):
        raise FrozenResolverError("canonical Scan execution envelope must be an object")
    if payload.get("schema_version") not in _SUPPORTED_SCHEMAS:
        raise FrozenResolverError("canonical Scan execution schema is unsupported")
    binding = payload.get("target_binding")
    if not isinstance(binding, Mapping) or set(binding) != _TARGET_BINDING_KEYS:
        raise FrozenResolverError("canonical target binding fields are invalid")
    digest = str(payload.get("target_binding_digest") or "").strip().lower()
    if digest != _canonical_json_digest(binding):
        raise FrozenResolverError("canonical target binding digest mismatch")

    target_host = _normalized_host(binding.get("canonical_host"))
    if not target_host:
        raise FrozenResolverError("canonical target hostname is invalid")
    raw_addresses = binding.get("allowed_addresses")
    if (
        not isinstance(raw_addresses, list)
        or not 1 <= len(raw_addresses) <= _MAX_ADDRESSES
    ):
        raise FrozenResolverError("canonical target address set is invalid")
    addresses: list[str] = []
    for raw_address in raw_addresses:
        try:
            address = str(ipaddress.ip_address(str(raw_address).strip()))
        except ValueError as exc:
            raise FrozenResolverError("canonical target address is invalid") from exc
        if address in addresses:
            raise FrozenResolverError("canonical target address set contains duplicates")
        addresses.append(address)

    origins = binding.get("allowed_origins")
    if not isinstance(origins, list) or not origins:
        raise FrozenResolverError("canonical target origins are unavailable")
    for raw_origin in origins:
        try:
            parsed = urlsplit(str(raw_origin or "").strip())
            _ = parsed.port
        except ValueError as exc:
            raise FrozenResolverError("canonical target origin is invalid") from exc
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or _normalized_host(parsed.hostname) != target_host
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise FrozenResolverError(
                "canonical target origin does not match its hostname"
            )
    return FrozenResolverConfig(
        target_host=target_host,
        allowed_addresses=tuple(addresses),
        target_binding_digest=digest,
    )


def _address_family(socket_module: Any, address: str) -> int:
    return (
        socket_module.AF_INET6
        if ipaddress.ip_address(address).version == 6
        else socket_module.AF_INET
    )


def install_frozen_target_resolver(
    *,
    environ: MutableMapping[str, str] | None = None,
    socket_module: Any = socket,
) -> FrozenResolverConfig | None:
    """Install one target-host resolver backed only by the frozen address set."""
    environment = os.environ if environ is None else environ
    config = _configuration_from_environment(environment)
    if config is None:
        return None

    current = socket_module.getaddrinfo
    installed = getattr(current, _MARKER, None)
    if installed is not None:
        if installed != config:
            raise FrozenResolverError(
                "a different frozen target resolver is already installed"
            )
        environment[_ACTIVE_ENV_NAME] = config.target_binding_digest
        return config

    original_getaddrinfo = current
    original_gethostbyname = socket_module.gethostbyname
    original_gethostbyname_ex = socket_module.gethostbyname_ex
    af_unspec = getattr(socket_module, "AF_UNSPEC", 0)
    numeric_flag = getattr(socket_module, "AI_NUMERICHOST", 0)

    def frozen_getaddrinfo(
        host: Any,
        port: Any,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[Any]:
        if _normalized_host(host) != config.target_host:
            return original_getaddrinfo(host, port, family, type, proto, flags)
        results: list[Any] = []
        seen: set[tuple[Any, ...]] = set()
        for address in config.allowed_addresses:
            address_family = _address_family(socket_module, address)
            if family not in {0, af_unspec, address_family}:
                continue
            try:
                rows = original_getaddrinfo(
                    address,
                    port,
                    address_family if family in {0, af_unspec} else family,
                    type,
                    proto,
                    flags | numeric_flag,
                )
            except socket_module.gaierror:
                continue
            for row in rows:
                key = tuple(row[:4]) + (tuple(row[4]),)
                if key not in seen:
                    seen.add(key)
                    results.append(row)
        if not results:
            error_code = getattr(socket_module, "EAI_NONAME", -2)
            raise socket_module.gaierror(
                error_code,
                "canonical target has no frozen address for the requested family",
            )
        return results

    def frozen_gethostbyname(host: Any) -> str:
        if _normalized_host(host) != config.target_host:
            return original_gethostbyname(host)
        for address in config.allowed_addresses:
            if ipaddress.ip_address(address).version == 4:
                return address
        error_code = getattr(socket_module, "EAI_NONAME", -2)
        raise socket_module.gaierror(
            error_code,
            "canonical target has no frozen IPv4 address",
        )

    def frozen_gethostbyname_ex(host: Any) -> tuple[str, list[str], list[str]]:
        if _normalized_host(host) != config.target_host:
            return original_gethostbyname_ex(host)
        ipv4 = [
            address
            for address in config.allowed_addresses
            if ipaddress.ip_address(address).version == 4
        ]
        if not ipv4:
            error_code = getattr(socket_module, "EAI_NONAME", -2)
            raise socket_module.gaierror(
                error_code,
                "canonical target has no frozen IPv4 address",
            )
        return config.target_host, [], ipv4

    setattr(frozen_getaddrinfo, _MARKER, config)
    setattr(frozen_gethostbyname, _MARKER, config)
    setattr(frozen_gethostbyname_ex, _MARKER, config)
    socket_module.getaddrinfo = frozen_getaddrinfo
    socket_module.gethostbyname = frozen_gethostbyname
    socket_module.gethostbyname_ex = frozen_gethostbyname_ex
    environment[_ACTIVE_ENV_NAME] = config.target_binding_digest
    return config


def _install_at_interpreter_startup() -> None:
    try:
        install_frozen_target_resolver()
    except FrozenResolverError as exc:
        # Exceptions raised by sitecustomize are normally printed and ignored by
        # the site module. SystemExit is intentional: malformed canonical
        # authority must not fall through to an unpinned scanner process.
        print(f"[frozen-dns] {exc}", file=sys.stderr, flush=True)
        raise SystemExit(78) from exc


_install_at_interpreter_startup()
