"""Canonical immutable runtime models shared by Scan and Hunt."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
from typing import Any, Mapping
import urllib.parse


@dataclass(frozen=True)
class ScanPolicy:
    active_testing: bool = False
    allow_state_changing_http: bool = False
    network_discovery: bool = False
    subdomain_discovery: bool = False
    include_families: tuple[str, ...] = ()
    exclude_families: tuple[str, ...] = ()
    scope_receipt_id: str | None = None
    approval_receipt_id: str | None = None


@dataclass(frozen=True)
class ScanBudget:
    max_duration_seconds: int
    max_http_requests: int
    max_endpoints: int
    max_browser_actions: int
    max_tcp_ports: int
    max_tool_wall_seconds: int
    max_workers: int

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if isinstance(value, bool) or int(value) <= 0:
                raise ValueError(f"{name} must be a positive integer")

    def ledger_limits(self) -> dict[str, int]:
        return {
            "http_requests": self.max_http_requests,
            "browser_actions": self.max_browser_actions,
            "tcp_ports_attempted": self.max_tcp_ports,
            "tool_wall_seconds": self.max_tool_wall_seconds,
        }


@dataclass(frozen=True)
class TargetBinding:
    target_id: str
    target_kind: str
    canonical_host: str | None
    allowed_origins: tuple[str, ...] = ()
    allowed_addresses: tuple[str, ...] = ()
    allowed_root_domains: tuple[str, ...] = ()
    environment: str = "unknown"
    scope_receipt_id: str | None = None

    def __post_init__(self) -> None:
        kind = str(self.target_kind or "").strip().lower()
        if kind not in {"web", "api", "device", "network"}:
            raise ValueError("unsupported target kind")
        object.__setattr__(self, "target_kind", kind)
        host = str(self.canonical_host or "").strip().lower().rstrip(".") or None
        object.__setattr__(self, "canonical_host", host)
        addresses: list[str] = []
        for value in self.allowed_addresses:
            address = str(ipaddress.ip_address(str(value).strip()))
            if address not in addresses:
                addresses.append(address)
        object.__setattr__(self, "allowed_addresses", tuple(addresses))
        origins: list[str] = []
        for value in self.allowed_origins:
            parsed = urllib.parse.urlsplit(str(value).strip())
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                raise ValueError("allowed origins must be absolute HTTP(S) origins")
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
                raise ValueError("allowed origin must not contain path, query, fragment, or userinfo")
            origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
            if origin not in origins:
                origins.append(origin)
        object.__setattr__(self, "allowed_origins", tuple(origins))
        roots = tuple(dict.fromkeys(
            str(root).strip().lower().rstrip(".") for root in self.allowed_root_domains
            if str(root).strip()
        ))
        object.__setattr__(self, "allowed_root_domains", roots)
        if kind in {"web", "api", "device"} and not host:
            raise ValueError("web, API, and device bindings require a canonical host")

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "canonical_host": self.canonical_host,
            "allowed_origins": list(self.allowed_origins),
            "allowed_addresses": list(self.allowed_addresses),
            "allowed_root_domains": list(self.allowed_root_domains),
            "environment": self.environment,
            "scope_receipt_id": self.scope_receipt_id,
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class PreparedCommand:
    binary: str
    argv: tuple[str, ...]
    destination_address: str | None = None


@dataclass(frozen=True)
class PreparedExecution:
    capability_name: str
    adapter_name: str
    adapter_version: str
    commands: tuple[PreparedCommand, ...]
    estimated_budget: Mapping[str, int]
    input_digest: str
    redacted_execution: Mapping[str, Any]
    parser_version: str

    @staticmethod
    def digest_input(value: Mapping[str, Any]) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ParsedCapabilityResult:
    status: str
    observations: tuple[Mapping[str, Any], ...] = ()
    partial: bool = False
    timed_out: bool = False
    errors: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timed_out and not self.partial:
            raise ValueError("timed out capability results must be partial")
