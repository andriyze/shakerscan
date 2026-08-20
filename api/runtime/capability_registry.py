"""Canonical capability metadata for trusted Scan and Hunt execution.

The registry names security operations by intent. External binaries are adapter details and
legacy ``run_tool`` names are compatibility aliases only. This module deliberately contains no
planner logic and does not execute processes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Iterable, Literal, Mapping


ExecutionKind = Literal[
    "internal", "http", "browser", "network_tcp", "network_udp", "external_tool"
]
RiskTier = Literal["read_only", "passive", "active", "credential", "mutation"]


@dataclass(frozen=True)
class CapabilitySpec:
    """Immutable planner-facing and placement-facing capability contract."""

    name: str
    description: str
    execution_kind: ExecutionKind
    risk_tier: RiskTier
    target_kinds: frozenset[str]
    adapter: str
    adapter_version: str
    required_approval: str | None
    budget_cost: Mapping[str, int]
    placement_requirements: Mapping[str, Any]
    input_schema: Mapping[str, Any]
    output_schema: str
    evidence_contract: tuple[str, ...]
    binary: str | None = None
    legacy_tool_name: str | None = None
    default_timeout_ms: int = 30_000
    version_args: tuple[str, ...] = ("--version",)
    common_paths: tuple[str, ...] = ()
    arsenal_status: str = "wired"
    retest_contract: str | None = None
    redaction_contract: tuple[str, ...] = (
        "authorization headers", "cookies", "tokens", "private keys"
    )

    def __post_init__(self) -> None:
        if not self.name or "." not in self.name:
            raise ValueError("capability names must be non-empty dotted identifiers")
        if self.default_timeout_ms <= 0:
            raise ValueError("default_timeout_ms must be positive")
        if not self.target_kinds:
            raise ValueError("target_kinds must not be empty")
        for dimension, amount in self.budget_cost.items():
            if not str(dimension).strip() or int(amount) < 0:
                raise ValueError("budget costs require named non-negative dimensions")

    @property
    def requires_active_approval(self) -> bool:
        return bool(self.required_approval) or self.risk_tier in {
            "active", "credential", "mutation"
        }

    def legacy_template(self, builder: Any) -> dict[str, Any]:
        """Render the old scanner-template shape from canonical metadata."""
        if not self.binary or not self.legacy_tool_name:
            raise ValueError(f"{self.name} is not an external legacy-tool adapter")
        return {
            "binary": self.binary,
            "risk": "read_only" if self.risk_tier in {"read_only", "passive"} else "active",
            "default_timeout_ms": self.default_timeout_ms,
            "max_wire_requests": int(self.budget_cost.get("http_requests", 0)
                                     or self.budget_cost.get("tcp_ports_attempted", 0)
                                     or 1),
            "build": builder,
            "desc": self.description,
            "capability": self.name,
            "output_schema": self.output_schema,
            "evidence_contract": self.evidence_contract,
            "placement_requirements": dict(self.placement_requirements),
        }


class CapabilityRegistry:
    """Validated, immutable-by-convention source of capability truth."""

    def __init__(self, specs: Iterable[CapabilitySpec]) -> None:
        by_name: dict[str, CapabilitySpec] = {}
        by_legacy_tool: dict[str, CapabilitySpec] = {}
        for spec in specs:
            if spec.name in by_name:
                raise ValueError(f"duplicate capability: {spec.name}")
            by_name[spec.name] = spec
            if spec.legacy_tool_name:
                if spec.legacy_tool_name in by_legacy_tool:
                    raise ValueError(f"duplicate legacy tool alias: {spec.legacy_tool_name}")
                by_legacy_tool[spec.legacy_tool_name] = spec
        self._by_name = MappingProxyType(by_name)
        self._by_legacy_tool = MappingProxyType(by_legacy_tool)

    def require(self, name: str) -> CapabilitySpec:
        try:
            return self._by_name[str(name or "").strip().lower()]
        except KeyError as exc:
            raise KeyError(f"unknown capability: {name}") from exc

    def for_legacy_tool(self, tool_name: str) -> CapabilitySpec:
        try:
            return self._by_legacy_tool[str(tool_name or "").strip().lower()]
        except KeyError as exc:
            raise KeyError(f"unknown legacy tool: {tool_name}") from exc

    def list(
        self, *, target_kind: str | None = None, include_active: bool = True
    ) -> tuple[CapabilitySpec, ...]:
        specs = tuple(self._by_name.values())
        if target_kind:
            kind = str(target_kind).strip().lower()
            specs = tuple(spec for spec in specs if kind in spec.target_kinds)
        if not include_active:
            specs = tuple(spec for spec in specs if not spec.requires_active_approval)
        return specs

    def external_tools(self) -> tuple[CapabilitySpec, ...]:
        return tuple(spec for spec in self._by_name.values() if spec.binary)

    def legacy_tools(self) -> tuple[CapabilitySpec, ...]:
        return tuple(self._by_legacy_tool.values())

    def required_binaries(self) -> frozenset[str]:
        return frozenset(spec.binary for spec in self.external_tools() if spec.binary)


_HTTP_TARGETS = frozenset({"web", "api"})
_NETWORK_TARGETS = frozenset({"web", "api", "network"})


def _schema(
    properties: Mapping[str, Any] | None = None, *, required: tuple[str, ...] = (),
) -> Mapping[str, Any]:
    schema: dict[str, Any] = {
        "type": "object", "properties": dict(properties or {}), "additionalProperties": False,
    }
    if required:
        schema["required"] = list(required)
    return schema


CAPABILITY_REGISTRY = CapabilityRegistry(
    (
        CapabilitySpec(
            "web.probe", "Passive HTTP fingerprint of a target-bound URL.",
            "external_tool", "read_only", _HTTP_TARGETS, "httpx", "1",
            None, {"http_requests": 4, "tool_wall_seconds": 30},
            {"network_reachability": True, "binary": "httpx"}, _schema(),
            "httpx-json/v1", ("http_observation",), "httpx", "httpx", 30_000,
            ("-version",), ("/opt/tools/httpx",),
        ),
        CapabilitySpec(
            "templates.scan", "Bounded target-bound Nuclei HTTP template scan.",
            "external_tool", "active", _HTTP_TARGETS, "nuclei", "1",
            "active_testing", {"http_requests": 4_000, "tool_wall_seconds": 300},
            {"network_reachability": True, "binary": "nuclei"},
            _schema({"severity": {"type": "string"}, "tags": {"type": "string"}}),
            "nuclei-jsonl/v1", ("template_match", "request_response"),
            "nuclei", "nuclei", 300_000, ("-version",), ("/opt/tools/nuclei",),
            retest_contract="rerun-template-or-family-on-same-surface",
        ),
        CapabilitySpec(
            "web.crawl", "Bounded same-host crawl and JavaScript endpoint discovery.",
            "external_tool", "active", _HTTP_TARGETS, "katana", "1",
            "active_testing", {"http_requests": 150, "tool_wall_seconds": 75},
            {"network_reachability": True, "binary": "katana"}, _schema(),
            "katana-lines/v1", ("crawl_observation",), "katana", "katana", 75_000,
            ("-version",), ("/opt/tools/katana",),
        ),
        CapabilitySpec(
            "web.content_discover", "Bounded content discovery using a bundled wordlist.",
            "external_tool", "active", _HTTP_TARGETS, "ffuf", "1",
            "active_testing", {"http_requests": 220, "tool_wall_seconds": 75},
            {"network_reachability": True, "binary": "ffuf"},
            _schema({"wordlist": {"type": "string", "enum": ["common", "api", "admin"]}}),
            "ffuf-json/v1", ("content_discovery_observation",), "ffuf", "ffuf", 75_000,
            ("-V",), ("/opt/tools/ffuf",),
        ),
        CapabilitySpec(
            "xss.verify", "Bounded target-bound Dalfox XSS verification.",
            "external_tool", "active", _HTTP_TARGETS, "dalfox", "1",
            "active_testing", {"http_requests": 400, "tool_wall_seconds": 120},
            {"network_reachability": True, "binary": "dalfox"},
            _schema({"severity": {"type": "string", "enum": ["low", "medium", "high"]}}),
            "dalfox-jsonl/v1", ("xss_reflection_or_browser_proof",),
            "dalfox", "dalfox", 120_000, ("version",), ("/opt/tools/dalfox",),
        ),
        CapabilitySpec(
            "sqli.verify", "Bounded target-bound SQL injection verification.",
            "external_tool", "active", _HTTP_TARGETS, "sqlmap", "1",
            "active_testing", {"http_requests": 900, "tool_wall_seconds": 300},
            {"network_reachability": True, "binary": "sqlmap"}, _schema(),
            "sqlmap-output/v1", ("sqli_dbms_or_error_proof",),
            "sqlmap", "sqlmap", 300_000, ("--version",), ("/opt/tools/sqlmap",),
            arsenal_status="gated", retest_contract="rerun-request-with-sqli-proof",
        ),
        CapabilitySpec(
            "service.fingerprint", "Bounded connection-based service/version fingerprint.",
            "network_tcp", "active", _NETWORK_TARGETS, "nmap", "1",
            "network_discovery", {"tcp_ports_attempted": 60, "tool_wall_seconds": 90},
            {"network_reachability": True, "binary": "nmap"}, _schema({
                "ports": {"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 65535}, "minItems": 1, "maxItems": 256},
                "profile": {"type": "string", "enum": ["version_light", "version_default"]},
            }, required=("ports",)),
            "nmap-xml/v1", ("open_port_observation", "service_observation"),
            "nmap", "nmap", 90_000, ("--version",), ("/opt/tools/nmap",),
            arsenal_status="gated",
        ),
        CapabilitySpec(
            "ports.discover", "Bounded connection-based TCP port discovery.",
            "network_tcp", "active", _NETWORK_TARGETS, "naabu", "1",
            "network_discovery", {"tcp_ports_attempted": 1_200, "tool_wall_seconds": 120},
            {"network_reachability": True, "binary": "naabu"}, _schema({
                "profile": {"type": "string", "enum": ["known_services", "top_100", "top_1000"]},
                "ports": {"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 65535}, "minItems": 1, "maxItems": 1000},
            }),
            "naabu-jsonl/v1", ("open_port_observation",),
            "naabu", "naabu", 120_000, ("-version",), ("/opt/tools/naabu",),
            arsenal_status="gated",
        ),
        CapabilitySpec(
            "subdomains.discover", "Passive target-root-bound subdomain discovery.",
            "external_tool", "passive", frozenset({"web", "api", "network"}),
            "subfinder", "1", None, {"hosts_attempted": 1, "tool_wall_seconds": 120},
            {"network_reachability": True, "binary": "subfinder"},
            _schema({"root_domain": {"type": "string"}}), "subfinder-lines/v1",
            ("passive_discovery_observation",), binary="subfinder", default_timeout_ms=120_000,
            version_args=("-version",), common_paths=("/opt/tools/subfinder",),
        ),
        CapabilitySpec(
            "http.request", "Send one target-pinned read-only request, optionally as a managed principal.",
            "http", "passive", _HTTP_TARGETS, "agent.http_request", "1",
            None, {"http_requests": 1, "tool_wall_seconds": 15},
            {"network_reachability": True, "credentials_resolved_server_side": True},
            _schema({
                "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS"]},
                "path": {"type": "string"},
                "query": {"type": "object"},
                "headers": {"type": "object"},
                "as_principal": {"type": "string"},
                "follow_redirects": {"type": "boolean"},
            }),
            "http-observation/v1", ("http_observation", "tool_receipt"),
        ),
        CapabilitySpec(
            "tls.inspect", "Inspect TLS configuration for a target-bound origin.",
            "internal", "passive", _HTTP_TARGETS, "scanner.tls", "1", None,
            {"tcp_ports_attempted": 1, "tool_wall_seconds": 15},
            {"network_reachability": True}, _schema({"origin": {"type": "string"}}),
            "tls-observation/v1", ("tls_protocol_observation",),
        ),
        CapabilitySpec(
            "device.inspect", "Inspect the registered device, services, scans, and posture evidence.",
            "internal", "read_only", frozenset({"device"}), "device.inspect_device", "1",
            None, {"tool_wall_seconds": 5}, {"control_plane": True}, _schema(), "device-context/v1",
            ("device_inventory_observation",),
        ),
        CapabilitySpec(
            "device.capabilities.inspect", "Inspect device-class protocol and application capabilities.",
            "internal", "read_only", frozenset({"device"}), "device.inspect_capabilities", "1",
            None, {"tool_wall_seconds": 5}, {"control_plane": True}, _schema(), "device-capabilities/v1",
            ("device_capability_observation",),
        ),
        CapabilitySpec(
            "collections.inspect", "Inspect redacted request collections bound to this Hunt.",
            "internal", "read_only", frozenset({"web", "api", "device"}),
            "collections.inspect", "1", None, {"tool_wall_seconds": 5}, {"control_plane": True}, _schema(),
            "request-collection-index/v2", ("request_collection_observation",),
        ),
        CapabilitySpec(
            "collections.select", "Select a bounded redacted request subset from a bound collection.",
            "internal", "read_only", frozenset({"web", "api", "device"}),
            "collections.select", "1", None, {"tool_wall_seconds": 5}, {"control_plane": True},
            _schema({"collection_id": {"type": "string"}, "request_ids": {"type": "array"},
                     "methods": {"type": "array"}, "path_regex": {"type": "string"},
                     "limit": {"type": "integer", "maximum": 200}}),
            "request-collection-selection/v2", ("request_collection_observation",),
        ),
        CapabilitySpec(
            "collections.replay_safe", "Replay up to 25 safe-method requests from a bound collection.",
            "http", "passive", frozenset({"web", "api"}), "collections.replay_safe", "1", None,
            {"http_requests": 25, "tool_wall_seconds": 60}, {"network_reachability": True},
            _schema({"collection_id": {"type": "string"}, "request_ids": {"type": "array"},
                     "methods": {"type": "array"}, "path_regex": {"type": "string"},
                     "limit": {"type": "integer", "maximum": 25}}),
            "request-collection-replay/v2", ("http_observation", "tool_receipt"),
        ),
        CapabilitySpec(
            "device.http.probe", "Send one target-pinned read-only request to a confirmed device web origin.",
            "http", "passive", frozenset({"device"}), "device.device_http_request", "1",
            None, {"http_requests": 1, "tool_wall_seconds": 10}, {"network_reachability": True},
            _schema({"path": {"type": "string"}, "method": {"type": "string", "enum": ["GET", "HEAD"]}, "origin_port": {"type": "integer"}}),
            "device-http-observation/v1", ("http_observation",),
        ),
        CapabilitySpec(
            "device.scan", "Queue one bounded device posture scan through the canonical scanner pipeline.",
            "internal", "active", frozenset({"device"}), "device.queue_device_scan", "1",
            "active_testing", {"active_actions": 1, "tool_wall_seconds": 30}, {"device_worker": True},
            _schema({"coverage_profile": {"type": "string", "enum": ["top100", "posture"]}, "include_web_dast": {"type": "boolean"}, "reason": {"type": "string"}}),
            "device-scan-queue/v1", ("scan_receipt",),
        ),
        CapabilitySpec(
            "device.service.verify", "Queue a typed, fixed-port service-state verifier.",
            "internal", "active", frozenset({"device"}), "device.verify_service_state", "1",
            "active_testing", {"active_actions": 1, "tcp_ports_attempted": 1, "tool_wall_seconds": 30}, {"device_worker": True},
            _schema({"transport": {"type": "string", "enum": ["tcp", "udp"]}, "port": {"type": "integer"}, "expected_state": {"type": "string"}, "reason": {"type": "string"}}),
            "device-service-verification/v1", ("service_state_observation",),
        ),
    )
)


LEGACY_TOOL_TO_CAPABILITY: Mapping[str, str] = MappingProxyType(
    {spec.legacy_tool_name: spec.name for spec in CAPABILITY_REGISTRY.legacy_tools()
     if spec.legacy_tool_name}
)
