"""Canonical capability metadata for trusted Scan and Hunt execution.

The registry names security operations by intent. External binary/tool identifiers are adapter
details. This module deliberately contains no planner logic and does not execute processes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from types import MappingProxyType
from typing import Any, Iterable, Literal, Mapping


ExecutionKind = Literal[
    "internal", "http", "browser", "network_tcp", "network_udp", "external_tool"
]
RiskTier = Literal["read_only", "passive", "active", "credential", "mutation"]
HuntExecutor = Literal[
    "inline",
    "worker_auth",
    "worker_http",
    "worker_network",
    "worker_browser",
    "worker_scanner",
    "worker_replay",
    "device_control",
    "device_http",
    "device_queue",
    "device_ssh_proposal",
    "confirmation",
]


class CapabilityInputContractError(ValueError):
    """Planner input does not match the capability registry schema."""


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
    process_tool_name: str | None = None
    default_timeout_ms: int = 30_000
    version_args: tuple[str, ...] = ("--version",)
    common_paths: tuple[str, ...] = ()
    arsenal_status: str = "wired"
    retest_contract: str | None = None
    planner_visible: bool = True
    hunt_executor: HuntExecutor | None = None
    planner_input_schema: Mapping[str, Any] | None = None
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
        if self.planner_visible and self.hunt_executor is None:
            raise ValueError(
                f"planner-visible capability {self.name} requires a Hunt executor"
            )
        for dimension, amount in self.budget_cost.items():
            if not str(dimension).strip() or int(amount) < 0:
                raise ValueError("budget costs require named non-negative dimensions")

    @property
    def requires_active_approval(self) -> bool:
        return bool(self.required_approval) or self.risk_tier in {
            "active", "credential", "mutation"
        }

    def scanner_template(self, builder: Any) -> dict[str, Any]:
        """Render the fixed scanner-process template from canonical metadata."""
        if not self.binary or not self.process_tool_name:
            raise ValueError(f"{self.name} is not an external process adapter")
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

    def planner_contract(self) -> dict[str, Any]:
        """Return semantic planner authority without leaking adapter/tool selection."""
        placement_keys = {
            "network_reachability",
            "runtime_target_binding",
            "durable_reservation",
            "device_worker",
            "control_plane",
            "worker_private_result",
            "credentials_resolved_server_side",
            "user_confirmation",
        }
        return {
            "name": self.name,
            "description": self.description,
            "risk_tier": self.risk_tier,
            "target_kinds": sorted(self.target_kinds),
            "input_schema": dict(
                self.planner_input_schema or self.input_schema
            ),
            "output_schema": self.output_schema,
            "budget_cost": dict(self.budget_cost),
            "required_approval": self.required_approval,
            "placement": {
                key: value
                for key, value in self.placement_requirements.items()
                if key in placement_keys
            },
            "evidence_contract": list(self.evidence_contract),
        }


class CapabilityRegistry:
    """Validated, immutable-by-convention source of capability truth."""

    def __init__(self, specs: Iterable[CapabilitySpec]) -> None:
        by_name: dict[str, CapabilitySpec] = {}
        by_process_tool: dict[str, CapabilitySpec] = {}
        for spec in specs:
            if spec.name in by_name:
                raise ValueError(f"duplicate capability: {spec.name}")
            by_name[spec.name] = spec
            if spec.process_tool_name:
                existing = by_process_tool.get(spec.process_tool_name)
                if existing is not None:
                    if (
                        spec.planner_visible
                        or spec.binary != existing.binary
                        or spec.adapter != existing.adapter
                    ):
                        raise ValueError(
                            f"ambiguous process tool: {spec.process_tool_name}"
                        )
                    # A server-only fixed profile may reuse the same binary
                    # adapter. Tool-name lookup remains bound to the public
                    # canonical capability registered first.
                    continue
                by_process_tool[spec.process_tool_name] = spec
        self._by_name = MappingProxyType(by_name)
        self._by_process_tool = MappingProxyType(by_process_tool)

    def require(self, name: str) -> CapabilitySpec:
        try:
            return self._by_name[str(name or "").strip().lower()]
        except KeyError as exc:
            raise KeyError(f"unknown capability: {name}") from exc

    def for_process_tool(self, tool_name: str) -> CapabilitySpec:
        try:
            return self._by_process_tool[str(tool_name or "").strip().lower()]
        except KeyError as exc:
            raise KeyError(f"unknown process tool: {tool_name}") from exc

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

    def process_tools(self) -> tuple[CapabilitySpec, ...]:
        return tuple(self._by_process_tool.values())

    def required_binaries(self) -> frozenset[str]:
        return frozenset(spec.binary for spec in self.external_tools() if spec.binary)

    def for_hunt_executor(self, executor: HuntExecutor) -> tuple[CapabilitySpec, ...]:
        return tuple(
            spec for spec in self._by_name.values()
            if spec.hunt_executor == executor
        )

    def validate_input(self, name: str, value: Any) -> dict[str, Any]:
        spec = self.require(name)
        if not isinstance(value, Mapping):
            raise CapabilityInputContractError("capability input must be an object")
        try:
            encoded = json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise CapabilityInputContractError(
                "capability input must be JSON serializable"
            ) from exc
        if len(encoded) > 65_536:
            raise CapabilityInputContractError(
                "capability input exceeds the 65536-byte limit"
            )
        _validate_schema_value(spec.input_schema, value, path="input", depth=0)
        return dict(value)

    def validate_hunt_input(self, name: str, value: Any) -> dict[str, Any]:
        """Validate the planner projection without exposing Scan-private fields."""
        spec = self.require(name)
        if spec.planner_input_schema is None:
            return self.validate_input(name, value)
        if not isinstance(value, Mapping):
            raise CapabilityInputContractError("capability input must be an object")
        try:
            encoded = json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise CapabilityInputContractError(
                "capability input must be JSON serializable"
            ) from exc
        if len(encoded) > 65_536:
            raise CapabilityInputContractError(
                "capability input exceeds the 65536-byte limit"
            )
        _validate_schema_value(
            spec.planner_input_schema, value, path="input", depth=0,
        )
        return dict(value)


def _validate_schema_value(
    schema: Mapping[str, Any], value: Any, *, path: str, depth: int,
) -> None:
    """Enforce the bounded JSON-Schema subset used by the canonical registry."""
    if depth > 12:
        raise CapabilityInputContractError(f"{path} is nested too deeply")
    expected = schema.get("type")
    if expected == "object":
        if not isinstance(value, Mapping):
            raise CapabilityInputContractError(f"{path} must be an object")
        if len(value) > 256:
            raise CapabilityInputContractError(f"{path} has too many fields")
        properties = schema.get("properties") or {}
        required = set(schema.get("required") or ())
        missing = sorted(required - set(value))
        if missing:
            raise CapabilityInputContractError(
                f"{path} is missing required fields: {', '.join(missing)}"
            )
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise CapabilityInputContractError(
                    f"{path} contains unsupported fields: {', '.join(unknown)}"
                )
        for key, item in value.items():
            child = properties.get(key)
            if isinstance(child, Mapping):
                _validate_schema_value(
                    child, item, path=f"{path}.{key}", depth=depth + 1,
                )
    elif expected == "array":
        if not isinstance(value, (list, tuple)):
            raise CapabilityInputContractError(f"{path} must be an array")
        minimum = int(schema.get("minItems") or 0)
        maximum = int(schema.get("maxItems") or 2_048)
        if not minimum <= len(value) <= maximum:
            raise CapabilityInputContractError(
                f"{path} must contain between {minimum} and {maximum} items"
            )
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                _validate_schema_value(
                    item_schema, item, path=f"{path}[{index}]", depth=depth + 1,
                )
    elif expected == "string":
        if not isinstance(value, str):
            raise CapabilityInputContractError(f"{path} must be a string")
        if len(value) < int(schema.get("minLength") or 0):
            raise CapabilityInputContractError(f"{path} is too short")
        if len(value) > int(schema.get("maxLength") or 16_384):
            raise CapabilityInputContractError(f"{path} is too long")
        pattern = schema.get("pattern")
        if pattern and re.fullmatch(str(pattern), value) is None:
            raise CapabilityInputContractError(f"{path} has an invalid format")
    elif expected == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise CapabilityInputContractError(f"{path} must be an integer")
        if "minimum" in schema and value < int(schema["minimum"]):
            raise CapabilityInputContractError(f"{path} is below its minimum")
        if "maximum" in schema and value > int(schema["maximum"]):
            raise CapabilityInputContractError(f"{path} exceeds its maximum")
    elif expected == "boolean":
        if not isinstance(value, bool):
            raise CapabilityInputContractError(f"{path} must be a boolean")
    if "enum" in schema and value not in schema["enum"]:
        raise CapabilityInputContractError(f"{path} is not an allowed value")


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


_HTTP_PRINCIPAL_BINDING_PROPERTIES: Mapping[str, Any] = MappingProxyType({
    "as_principal": {
        "type": "string", "enum": ["primary", "secondary", "service"],
    },
    "principal_binding_digest": {
        "type": "string", "pattern": "^[0-9a-f]{64}$",
    },
})


def _http_principal_schema(
    properties: Mapping[str, Any] | None = None, *, required: tuple[str, ...] = (),
) -> Mapping[str, Any]:
    """Declare the content-free identity binding shared by HTTP capabilities."""
    merged = dict(properties or {})
    merged.update(_HTTP_PRINCIPAL_BINDING_PROPERTIES)
    return _schema(merged, required=required)


CAPABILITY_REGISTRY = CapabilityRegistry(
    (
        CapabilitySpec(
            "scan.finalize",
            "Build one deterministic report from immutable action receipts and manifests.",
            "internal", "passive", _HTTP_TARGETS, "scanner.report", "1",
            None,
            {"tool_wall_seconds": 1},
            {
                "network_reachability": False,
                "runtime_target_binding": False,
                "fixed_stage_plan": True,
                "durable_reservation": True,
                "placed_evidence_only": True,
                "offline_only": True,
            },
            _schema(),
            "scan-report/v2",
            ("scan_report", "coverage_summary", "tool_receipts"),
            planner_visible=False,
        ),
        CapabilitySpec(
            "scan.execute",
            "Deprecated compatibility identity for historical monolithic Scan receipts.",
            "internal", "passive", _HTTP_TARGETS, "scanner.dast.compat", "1",
            None,
            {"tool_wall_seconds": 1},
            {
                "network_reachability": False,
                "runtime_target_binding": False,
                "deprecated_compatibility": True,
            },
            _schema(),
            "scan-report/v1",
            ("historical_scan_report",),
            planner_visible=False,
        ),
        CapabilitySpec(
            "web.probe", "Passive HTTP fingerprint of a target-bound URL.",
            "external_tool", "read_only", _HTTP_TARGETS, "httpx", "1",
            None, {"http_requests": 1, "tool_wall_seconds": 30},
            {"network_reachability": True, "binary": "httpx"},
            _http_principal_schema(),
            "httpx-json/v1", ("http_observation",), "httpx", "httpx", 30_000,
            ("-version",), ("/opt/tools/httpx",),
            hunt_executor="worker_scanner",
        ),
        CapabilitySpec(
            "templates.scan", "Bounded target-bound Nuclei HTTP template scan.",
            "external_tool", "active", _HTTP_TARGETS, "nuclei", "1",
            "active_testing", {"http_requests": 4_000, "tool_wall_seconds": 300},
            {"network_reachability": True, "binary": "nuclei"},
            _http_principal_schema({
                "severity": {"type": "string"},
                "tags": {"type": "string"},
                "template_pack_digest": {
                    "type": "string", "pattern": "^[0-9a-f]{64}$",
                },
            }),
            "nuclei-jsonl/v1", ("template_match", "request_response"),
            "nuclei", "nuclei", 300_000, ("-version",), ("/opt/tools/nuclei",),
            retest_contract="rerun-template-or-family-on-same-surface",
            hunt_executor="worker_scanner",
        ),
        CapabilitySpec(
            "templates.passive_scan",
            "Reviewed target-bound GET-only Nuclei template allowlist.",
            "external_tool", "read_only", _HTTP_TARGETS, "nuclei", "1",
            None, {"http_requests": 7, "tool_wall_seconds": 30},
            {"network_reachability": True, "binary": "nuclei"},
            _http_principal_schema({
                "severity": {
                    "type": "string",
                    "enum": ["critical,high,medium,low,info"],
                },
                "template_ids": {
                    "type": "string", "pattern": "^[a-z0-9,-]{1,512}$",
                },
                "template_pack_digest": {
                    "type": "string", "pattern": "^[0-9a-f]{64}$",
                },
                "template_request_cost_upper_bound": {
                    "type": "integer", "enum": [7],
                },
            }),
            "nuclei-jsonl/v1", ("template_match", "request_response"),
            "nuclei", "nuclei", 30_000, ("-version",), ("/opt/tools/nuclei",),
            retest_contract="rerun-template-on-same-surface",
            planner_visible=False,
        ),
        CapabilitySpec(
            "templates.passive_batch",
            "Reviewed GET-only Nuclei pack over one immutable endpoint slice.",
            "internal", "read_only", _HTTP_TARGETS, "nuclei.batch", "1",
            None, {"http_requests": 350, "tool_wall_seconds": 60},
            {
                "network_reachability": True,
                "binary": "nuclei",
                "single_worker_batch": True,
                "durable_attempt_checkpoints": True,
            },
            _schema({
                "target_ref": {"type": "string"},
                "target_manifest_ref": {"type": "object"},
                "template_manifest_ref": {"type": "object"},
                "slice": {"type": "object"},
                "profile": {"type": "string"},
                "proof_policy": {"type": "string"},
            }, required=(
                "target_manifest_ref", "template_manifest_ref", "slice",
                "profile", "proof_policy",
            )),
            "nuclei-batch/v1", (
                "candidate_attempt", "template_match", "request_response",
            ),
            retest_contract="rerun-template-on-same-surface",
            planner_visible=False,
        ),
        CapabilitySpec(
            "templates.active_batch",
            "Active Nuclei pack over one immutable endpoint slice.",
            "internal", "active", _HTTP_TARGETS, "nuclei.batch", "1",
            "active_testing", {"http_requests": 4_000, "tool_wall_seconds": 300},
            {
                "network_reachability": True,
                "binary": "nuclei",
                "single_worker_batch": True,
                "durable_attempt_checkpoints": True,
            },
            _schema({
                "target_ref": {"type": "string"},
                "target_manifest_ref": {"type": "object"},
                "template_manifest_ref": {"type": "object"},
                "slice": {"type": "object"},
                "profile": {"type": "string"},
                "proof_policy": {"type": "string"},
            }, required=(
                "target_manifest_ref", "template_manifest_ref", "slice",
                "profile", "proof_policy",
            )),
            "nuclei-batch/v1", (
                "candidate_attempt", "template_match", "request_response",
            ),
            retest_contract="rerun-template-or-family-on-same-surface",
            planner_visible=False,
        ),
        CapabilitySpec(
            "web.crawl", "Bounded same-host crawl and JavaScript endpoint discovery.",
            "external_tool", "read_only", _HTTP_TARGETS, "katana", "1",
            None, {"http_requests": 150, "tool_wall_seconds": 75},
            {"network_reachability": True, "binary": "katana"},
            _http_principal_schema(),
            "katana-lines/v1", ("crawl_observation",), "katana", "katana", 75_000,
            ("-version",), ("/opt/tools/katana",),
            hunt_executor="worker_scanner",
        ),
        CapabilitySpec(
            "web.content_discover", "Bounded content discovery using a bundled wordlist.",
            "external_tool", "read_only", _HTTP_TARGETS, "ffuf", "1",
            None, {"http_requests": 220, "tool_wall_seconds": 75},
            {"network_reachability": True, "binary": "ffuf"},
            _http_principal_schema({
                "wordlist": {
                    "type": "string", "enum": ["common", "api", "admin"],
                },
            }),
            "ffuf-json/v1", ("content_discovery_observation",), "ffuf", "ffuf", 75_000,
            ("-V",), ("/opt/tools/ffuf",),
            hunt_executor="worker_scanner",
        ),
        CapabilitySpec(
            "xss.verify", "Bounded target-bound Dalfox XSS verification.",
            "external_tool", "active", _HTTP_TARGETS, "dalfox", "1",
            "active_testing", {"http_requests": 400, "tool_wall_seconds": 120},
            {"network_reachability": True, "binary": "dalfox"},
            _http_principal_schema({
                "severity": {
                    "type": "string", "enum": ["low", "medium", "high"],
                },
            }),
            "dalfox-jsonl/v1", ("xss_reflection_or_browser_proof",),
            "dalfox", "dalfox", 120_000, ("version",), ("/opt/tools/dalfox",),
            hunt_executor="worker_scanner",
        ),
        CapabilitySpec(
            "xss.verify_batch",
            "Bounded Dalfox verification over one immutable candidate slice.",
            "internal", "active", _HTTP_TARGETS, "dalfox.batch", "1",
            "active_testing", {"http_requests": 1_000, "tool_wall_seconds": 300},
            {
                "network_reachability": True,
                "binary": "dalfox",
                "single_worker_batch": True,
                "durable_attempt_checkpoints": True,
            },
            _schema({
                "candidate_manifest_ref": {"type": "object"},
                "endpoint_manifest_ref": {"type": "object"},
                "slice": {"type": "object"},
                "profile": {"type": "string"},
                "proof_policy": {"type": "string"},
            }, required=(
                "candidate_manifest_ref", "slice", "profile", "proof_policy",
            )),
            "dalfox-batch/v1", (
                "candidate_attempt", "xss_reflection_or_browser_proof",
            ),
            planner_visible=False,
        ),
        CapabilitySpec(
            "xss.browser_prove_batch",
            "Prove ranked XSS candidates in a target-bound Playwright runtime.",
            "browser", "active", _HTTP_TARGETS, "playwright.xss_proof_batch", "1",
            "active_testing",
            {"browser_actions": 20, "http_requests": 500, "tool_wall_seconds": 300},
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "browser_runtime": "playwright",
                "deterministic_proof_contract": True,
                "single_worker_batch": True,
                "durable_attempt_checkpoints": True,
            },
            _schema({
                "candidate_manifest_ref": {"type": "object"},
                "endpoint_manifest_ref": {"type": "object"},
                "slice": {"type": "object"},
                "profile": {"type": "string"},
                "proof_policy": {"type": "string"},
            }, required=(
                "candidate_manifest_ref", "slice", "profile", "proof_policy",
            )),
            "xss-browser-proof-batch/v1",
            ("candidate_attempt", "xss_browser_execution_proof"),
            planner_visible=False,
            retest_contract="rerun-exact-headless-xss-proof",
        ),
        CapabilitySpec(
            "sqli.verify", "Bounded target-bound SQL injection verification.",
            "external_tool", "active", _HTTP_TARGETS, "sqlmap", "1",
            "active_testing", {"http_requests": 900, "tool_wall_seconds": 300},
            {"network_reachability": True, "binary": "sqlmap"},
            _http_principal_schema(),
            "sqlmap-output/v1", ("sqli_dbms_or_error_proof",),
            "sqlmap", "sqlmap", 300_000, ("--version",), ("/opt/tools/sqlmap",),
            arsenal_status="gated", retest_contract="rerun-request-with-sqli-proof",
            hunt_executor="worker_scanner",
        ),
        CapabilitySpec(
            "sqli.verify_batch",
            "Bounded SQLMap verification over one immutable candidate slice.",
            "internal", "active", _HTTP_TARGETS, "sqlmap.batch", "1",
            "active_testing", {"http_requests": 1_800, "tool_wall_seconds": 300},
            {
                "network_reachability": True,
                "binary": "sqlmap",
                "single_worker_batch": True,
                "durable_attempt_checkpoints": True,
            },
            _schema({
                "candidate_manifest_ref": {"type": "object"},
                "endpoint_manifest_ref": {"type": "object"},
                "slice": {"type": "object"},
                "profile": {"type": "string"},
                "proof_policy": {"type": "string"},
            }, required=(
                "candidate_manifest_ref", "slice", "profile", "proof_policy",
            )),
            "sqlmap-batch/v1", (
                "candidate_attempt", "sqli_dbms_or_error_proof",
            ),
            arsenal_status="gated",
            retest_contract="rerun-request-with-sqli-proof",
            planner_visible=False,
        ),
        CapabilitySpec(
            "sqli.prove_batch",
            "Reproduce SQL injection candidates under deterministic differential proof contracts.",
            "internal", "active", _HTTP_TARGETS, "sqli.proof_batch", "1",
            "active_testing", {
                "http_requests": 200,
                "state_changing_requests": 200,
                "tool_wall_seconds": 180,
            },
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "deterministic_proof_contract": True,
                "single_worker_batch": True,
                "durable_attempt_checkpoints": True,
                "private_request_reference": True,
            },
            _schema({
                "candidate_manifest_ref": {"type": "object"},
                "endpoint_manifest_ref": {"type": "object"},
                "request_candidate_manifest_ref": {"type": "object"},
                "slice": {"type": "object"},
                "profile": {"type": "string"},
                "proof_policy": {"type": "string"},
            }, required=("slice", "profile", "proof_policy")),
            "sqli-proof-batch/v1", ("candidate_attempt", "sqli_deterministic_proof"),
            arsenal_status="wired",
            retest_contract="rerun-exact-sqli-proof-contract",
            planner_visible=False,
        ),
        CapabilitySpec(
            "xss.request_verify",
            "Verify reflection in one exact worker-private JSON or form request.",
            "http", "mutation", _HTTP_TARGETS, "request_mutation.xss", "1",
            "state_changing_http",
            {
                "http_requests": 2,
                "state_changing_requests": 2,
                "tool_wall_seconds": 20,
            },
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "private_request_reference": True,
            },
            _schema({
                "request_candidate_manifest_ref": {"type": "object"},
                "request_candidate_index": {
                    "type": "integer", "minimum": 0, "maximum": 1_999,
                },
            }, required=(
                "request_candidate_manifest_ref", "request_candidate_index",
            )),
            "request-xss-differential/v1",
            ("xss_reflection_differential", "tool_receipt"),
            planner_visible=False,
            retest_contract="rerun-exact-request-with-xss-differential",
        ),
        CapabilitySpec(
            "sqli.request_verify",
            "Verify SQL error differentials in one exact worker-private JSON or form request.",
            "http", "mutation", _HTTP_TARGETS, "request_mutation.sqli", "1",
            "state_changing_http",
            {
                "http_requests": 2,
                "state_changing_requests": 2,
                "tool_wall_seconds": 20,
            },
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "private_request_reference": True,
                "data_extraction": False,
                "time_based_techniques": False,
            },
            _schema({
                "request_candidate_manifest_ref": {"type": "object"},
                "request_candidate_index": {
                    "type": "integer", "minimum": 0, "maximum": 1_999,
                },
            }, required=(
                "request_candidate_manifest_ref", "request_candidate_index",
            )),
            "request-sqli-differential/v1",
            ("sqli_error_differential", "tool_receipt"),
            planner_visible=False,
            retest_contract="rerun-exact-request-with-sqli-differential",
        ),
        CapabilitySpec(
            "xss.request_verify_batch",
            "Verify exact worker-private JSON or form fields in one bounded batch.",
            "internal", "active", _HTTP_TARGETS, "request_mutation.xss_batch", "1",
            "active_testing",
            {
                "http_requests": 40,
                "state_changing_requests": 40,
                "tool_wall_seconds": 120,
            },
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "private_request_reference": True,
                "single_worker_batch": True,
                "durable_attempt_checkpoints": True,
            },
            _schema({
                "request_candidate_manifest_ref": {"type": "object"},
                "slice": {"type": "object"},
                "profile": {"type": "string"},
                "proof_policy": {"type": "string"},
            }, required=(
                "request_candidate_manifest_ref", "slice", "profile", "proof_policy",
            )),
            "request-xss-batch/v1",
            ("candidate_attempt", "xss_reflection_differential", "tool_receipt"),
            planner_visible=False,
            retest_contract="rerun-exact-request-with-xss-differential",
        ),
        CapabilitySpec(
            "sqli.request_verify_batch",
            "Verify exact worker-private JSON or form fields in one bounded batch.",
            "internal", "active", _HTTP_TARGETS, "request_mutation.sqli_batch", "1",
            "active_testing",
            {
                "http_requests": 40,
                "state_changing_requests": 40,
                "tool_wall_seconds": 120,
            },
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "private_request_reference": True,
                "data_extraction": False,
                "time_based_techniques": False,
                "single_worker_batch": True,
                "durable_attempt_checkpoints": True,
            },
            _schema({
                "request_candidate_manifest_ref": {"type": "object"},
                "slice": {"type": "object"},
                "profile": {"type": "string"},
                "proof_policy": {"type": "string"},
            }, required=(
                "request_candidate_manifest_ref", "slice", "profile", "proof_policy",
            )),
            "request-sqli-batch/v1",
            ("candidate_attempt", "sqli_error_differential", "tool_receipt"),
            planner_visible=False,
            retest_contract="rerun-exact-request-with-sqli-differential",
        ),
        CapabilitySpec(
            "exposure.verify_batch",
            "Probe endpoints and well-known sensitive locations for deterministic "
            "content disclosure over one bounded slice.",
            "internal", "active", _HTTP_TARGETS, "exposure.probe_batch", "1",
            "active_testing",
            {"http_requests": 300, "tool_wall_seconds": 180},
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "deterministic_proof_contract": True,
                "single_worker_batch": True,
                "durable_attempt_checkpoints": True,
            },
            _schema({
                "endpoint_manifest_ref": {"type": "object"},
                "slice": {"type": "object"},
                "profile": {"type": "string"},
                "proof_policy": {"type": "string"},
            }, required=("endpoint_manifest_ref", "slice", "profile", "proof_policy")),
            "exposure-probe-batch/v1",
            ("candidate_attempt", "sensitive_exposure_proof"),
            arsenal_status="wired",
            retest_contract="rerun-exact-exposure-probe",
            planner_visible=False,
        ),
        CapabilitySpec(
            "nosqli.verify_batch",
            "Prove NoSQL operator injection with a repeated sentinel differential "
            "over query and worker-private JSON candidates.",
            "internal", "active", _HTTP_TARGETS, "nosqli.verify_batch", "1",
            "active_testing",
            {
                "http_requests": 200,
                "state_changing_requests": 200,
                "tool_wall_seconds": 180,
            },
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "deterministic_proof_contract": True,
                "single_worker_batch": True,
                "durable_attempt_checkpoints": True,
            },
            _schema({
                "candidate_manifest_ref": {"type": "object"},
                "endpoint_manifest_ref": {"type": "object"},
                "request_candidate_manifest_ref": {"type": "object"},
                "slice": {"type": "object"},
                "profile": {"type": "string"},
                "proof_policy": {"type": "string"},
            }, required=("slice", "profile", "proof_policy")),
            "nosqli-verify-batch/v1",
            ("candidate_attempt", "nosqli_proof"),
            arsenal_status="wired",
            retest_contract="rerun-exact-nosqli-differential",
            planner_visible=False,
        ),
        CapabilitySpec(
            "authz_surface.verify_batch",
            "Prove broken function-level authorization by comparing anonymous and "
            "authenticated access across a bounded route slice.",
            "internal", "active", _HTTP_TARGETS, "authz_surface.verify_batch", "1",
            "active_testing",
            {"http_requests": 300, "tool_wall_seconds": 180},
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "deterministic_proof_contract": True,
                "requires_primary_principal": True,
                "single_worker_batch": True,
                "durable_attempt_checkpoints": True,
            },
            _schema({
                "endpoint_manifest_ref": {"type": "object"},
                "slice": {"type": "object"},
                "profile": {"type": "string"},
                "proof_policy": {"type": "string"},
            }, required=("endpoint_manifest_ref", "slice", "profile", "proof_policy")),
            "authz-surface-batch/v1",
            ("candidate_attempt", "authz_surface_proof"),
            arsenal_status="wired",
            retest_contract="rerun-exact-authz-surface-differential",
            planner_visible=False,
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
            hunt_executor="worker_network",
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
            hunt_executor="worker_network",
        ),
        CapabilitySpec(
            "subdomains.discover", "Passive target-root-bound subdomain discovery.",
            "external_tool", "passive", frozenset({"web", "api", "network"}),
            "subfinder", "1", None, {"hosts_attempted": 1, "tool_wall_seconds": 120},
            {"network_reachability": True, "binary": "subfinder"},
            _schema({"root_domain": {"type": "string"}}), "subfinder-lines/v1",
            ("passive_discovery_observation",), binary="subfinder", default_timeout_ms=120_000,
            version_args=("-version",), common_paths=("/opt/tools/subfinder",),
            hunt_executor="worker_network",
        ),
        CapabilitySpec(
            "http.request", "Send one target-pinned read-only request, optionally as a managed principal.",
            "http", "passive", _HTTP_TARGETS, "agent.http_request", "1",
            None, {"http_requests": 1, "tool_wall_seconds": 15},
            {"network_reachability": True, "credentials_resolved_server_side": True},
            _http_principal_schema({
                "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS"]},
                "path": {"type": "string"},
                "query": {"type": "object"},
                "headers": {"type": "object"},
                "follow_redirects": {"type": "boolean"},
                "session_ref": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                },
            }, required=("method", "path")),
            "http-observation/v1", ("http_observation", "tool_receipt"),
            hunt_executor="worker_http",
        ),
        CapabilitySpec(
            "auth.session.establish",
            "Establish one target-bound worker-private form or OAuth HTTP session.",
            "http", "credential", _HTTP_TARGETS, "auth.session", "1",
            "credential_use", {"http_requests": 4, "tool_wall_seconds": 45},
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "credentials_resolved_server_side": True,
                "worker_private_result": True,
            },
            _schema({
                "lane": {"type": "string", "enum": ["primary", "secondary"]},
                "auth_kind": {
                    "type": "string",
                    "enum": [
                        "form_login", "oauth_client_credentials", "oauth_password",
                    ],
                },
                "credential_binding_digest": {
                    "type": "string", "pattern": "^[0-9a-f]{64}$",
                },
                "endpoint_binding_digest": {
                    "type": "string", "pattern": "^[0-9a-f]{64}$",
                },
                "endpoint_path": {"type": "string"},
            }, required=(
                "lane", "auth_kind", "credential_binding_digest",
                "endpoint_binding_digest", "endpoint_path",
            )),
            "credential-session/v1",
            ("credential_session", "tool_receipt"),
            planner_visible=True,
            hunt_executor="worker_auth",
            planner_input_schema=_schema({
                "as_principal": {
                    "type": "string",
                    "enum": ["primary", "secondary", "service"],
                },
            }, required=("as_principal",)),
        ),
        CapabilitySpec(
            "auth.session.refresh",
            "Refresh one opaque target-bound session using its current managed profile.",
            "http", "credential", _HTTP_TARGETS, "auth.session", "1",
            "credential_use", {"http_requests": 4, "tool_wall_seconds": 45},
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "credentials_resolved_server_side": True,
                "worker_private_result": True,
            },
            _schema({
                "session_ref": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                },
            }, required=("session_ref",)),
            "credential-session/v1",
            ("credential_session", "tool_receipt"),
            hunt_executor="worker_auth",
        ),
        CapabilitySpec(
            "auth.session.revoke",
            "Revoke one opaque target-bound session and destroy its sealed identity.",
            "internal", "credential", _HTTP_TARGETS, "auth.session", "1",
            "credential_use", {"tool_wall_seconds": 5},
            {
                "network_reachability": False,
                "runtime_target_binding": True,
                "credentials_resolved_server_side": True,
                "worker_private_result": True,
            },
            _schema({
                "session_ref": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                },
            }, required=("session_ref",)),
            "credential-session/v1",
            ("credential_session_revocation", "tool_receipt"),
            hunt_executor="worker_auth",
        ),
        CapabilitySpec(
            "authz.verify",
            "Verify one read-only cross-principal object-authorization differential.",
            "http", "active", _HTTP_TARGETS, "authz.differential", "1",
            "active_testing", {"http_requests": 4, "tool_wall_seconds": 60},
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "credentials_resolved_server_side": True,
                "deterministic_proof_contract": True,
            },
            _schema({
                "primary_binding_digest": {
                    "type": "string", "pattern": "^[0-9a-f]{64}$",
                },
                "secondary_binding_digest": {
                    "type": "string", "pattern": "^[0-9a-f]{64}$",
                },
                "route_inventory_digest": {
                    "type": "string", "pattern": "^[0-9a-f]{64}$",
                },
                "route_count": {
                    "type": "integer", "minimum": 1, "maximum": 50,
                },
            }, required=(
                "primary_binding_digest", "secondary_binding_digest",
                "route_inventory_digest", "route_count",
            )),
            "authz-differential/v1",
            ("cross_principal_ownership_differential", "tool_receipt"),
            planner_visible=True,
            hunt_executor="worker_http",
            planner_input_schema=_schema({
                "primary_session_ref": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                },
                "secondary_session_ref": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                },
                "routes": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 4_000},
                    "minItems": 1,
                    "maxItems": 50,
                },
            }, required=(
                "primary_session_ref", "secondary_session_ref", "routes",
            )),
        ),
        CapabilitySpec(
            "tls.inspect", "Inspect TLS configuration for a target-bound origin.",
            "internal", "passive", _HTTP_TARGETS, "scanner.tls", "1", None,
            {"tcp_ports_attempted": 4, "tool_wall_seconds": 15},
            {"network_reachability": True},
            _schema({
                "origins_ref": {
                    "type": "string", "pattern": "^frozen_https_origins$",
                },
                "origin_count": {
                    "type": "integer", "minimum": 1, "maximum": 64,
                },
                "addresses_ref": {
                    "type": "string", "pattern": "^frozen_addresses$",
                },
                "address_count": {
                    "type": "integer", "minimum": 1, "maximum": 64,
                },
            }, required=(
                "origins_ref", "origin_count", "addresses_ref", "address_count",
            )),
            "tls-observation/v2", ("tls_posture_observation",),
            hunt_executor="inline",
        ),
        CapabilitySpec(
            "dns.inspect", "Inspect bounded DNS and mail-policy records for the frozen host.",
            "internal", "passive", _HTTP_TARGETS, "scanner.dns", "1", None,
            {"hosts_attempted": 4, "tool_wall_seconds": 15},
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "query_names_derived_from_binding": True,
            },
            _schema(),
            "dns-posture-observation/v1",
            ("dns_posture_observation", "tool_receipt"),
            planner_visible=False,
        ),
        CapabilitySpec(
            "browser.navigate",
            "Open one target-bound page while blocking cross-origin and state-changing requests.",
            "browser", "passive", _HTTP_TARGETS, "playwright", "1", None,
            {
                "browser_actions": 1,
                "http_requests": 50,
                "tool_wall_seconds": 30,
            },
            {
                "network_reachability": True,
                "browser_runtime": "playwright",
                "agent_tool_worker": True,
                "runtime_target_binding": True,
            },
            _schema({
                "path": {"type": "string", "maxLength": 2000},
                "wait_until": {
                    "type": "string", "enum": ["domcontentloaded", "load"],
                },
                "timeout_ms": {
                    "type": "integer", "minimum": 1000, "maximum": 30000,
                },
                "max_requests": {
                    "type": "integer", "minimum": 1, "maximum": 50,
                },
            }),
            "browser-navigation/v1",
            ("browser_navigation_observation", "http_observation", "tool_receipt"),
            default_timeout_ms=30_000,
            hunt_executor="worker_browser",
        ),
        CapabilitySpec(
            "browser.interact",
            "Click one strictly read-only target-bound link, disclosure, or tab.",
            "browser", "passive", _HTTP_TARGETS, "playwright", "1", None,
            {
                "browser_actions": 2,
                "http_requests": 50,
                "tool_wall_seconds": 30,
            },
            {
                "network_reachability": True,
                "browser_runtime": "playwright",
                "agent_tool_worker": True,
                "runtime_target_binding": True,
            },
            _schema({
                "path": {"type": "string", "maxLength": 2000},
                "selector": {"type": "string", "minLength": 1, "maxLength": 500},
                "wait_until": {
                    "type": "string", "enum": ["domcontentloaded", "load"],
                },
                "timeout_ms": {
                    "type": "integer", "minimum": 1000, "maximum": 30000,
                },
                "max_requests": {
                    "type": "integer", "minimum": 1, "maximum": 50,
                },
                "settle_ms": {
                    "type": "integer", "minimum": 0, "maximum": 2000,
                },
            }, required=("selector",)),
            "browser-interaction/v1",
            ("browser_interaction_observation", "http_observation", "tool_receipt"),
            default_timeout_ms=30_000,
            hunt_executor="worker_browser",
        ),
        CapabilitySpec(
            "device.inspect", "Inspect the registered device, services, scans, and posture evidence.",
            "internal", "read_only", frozenset({"device"}), "device.inspect_device", "1",
            None, {"tool_wall_seconds": 5}, {"control_plane": True}, _schema(), "device-context/v1",
            ("device_inventory_observation",),
            hunt_executor="device_control",
        ),
        CapabilitySpec(
            "device.capabilities.inspect", "Inspect device-class protocol and application capabilities.",
            "internal", "read_only", frozenset({"device"}), "device.inspect_capabilities", "1",
            None, {"tool_wall_seconds": 5}, {"control_plane": True}, _schema(), "device-capabilities/v1",
            ("device_capability_observation",),
            hunt_executor="device_control",
        ),
        CapabilitySpec(
            "collections.inspect", "Inspect redacted request collections bound to this Hunt.",
            "internal", "read_only", frozenset({"web", "api", "device"}),
            "collections.inspect", "1", None, {"tool_wall_seconds": 5}, {"control_plane": True}, _schema(),
            "request-collection-index/v2", ("request_collection_observation",),
            hunt_executor="inline",
        ),
        CapabilitySpec(
            "candidate.verify",
            "Run one server-owned deterministic verifier for a candidate produced by this Hunt.",
            "internal", "active", frozenset({"web", "api", "device"}),
            "candidate.deterministic_verifier", "1", "active_testing",
            {"tool_wall_seconds": 180},
            {
                "control_plane": True,
                "runtime_target_binding": True,
                "durable_reservation": True,
                "deterministic_proof_contract": True,
            },
            _schema({
                "candidate_id": {
                    "type": "string",
                    "pattern": "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
                },
            }, required=("candidate_id",)),
            "candidate-verification/v2",
            ("deterministic_verification", "tool_receipt"),
            default_timeout_ms=180_000,
            hunt_executor="inline",
        ),
        CapabilitySpec(
            "collections.select", "Select a bounded redacted request subset from a bound collection.",
            "internal", "read_only", frozenset({"web", "api", "device"}),
            "collections.select", "1", None, {"tool_wall_seconds": 5}, {"control_plane": True},
            _schema({"collection_id": {"type": "string"}, "request_ids": {"type": "array"},
                     "methods": {"type": "array"}, "path_regex": {"type": "string"},
                     "limit": {"type": "integer", "minimum": 1, "maximum": 200}},
                    required=("collection_id",)),
            "request-collection-selection/v2", ("request_collection_observation",),
            hunt_executor="inline",
        ),
        CapabilitySpec(
            "collections.replay_safe", "Replay up to 25 safe-method requests from a bound collection.",
            "http", "passive", frozenset({"web", "api", "device"}), "collections.replay", "1", None,
            {"http_requests": 25, "tool_wall_seconds": 60}, {"network_reachability": True},
            _schema({"collection_id": {"type": "string"}, "request_ids": {"type": "array"},
                     "methods": {"type": "array"}, "path_regex": {"type": "string"},
                     "limit": {"type": "integer", "minimum": 1, "maximum": 25},
                     "as_principal": {"type": "string", "enum": [
                         "anonymous", "primary", "secondary", "service",
                     ]}}, required=("collection_id",)),
            "request-collection-replay/v2", ("http_observation", "tool_receipt"),
            hunt_executor="worker_replay",
        ),
        CapabilitySpec(
            "collections.replay_active",
            "Replay an exact approved state-changing request selection from a bound collection.",
            "http", "active", frozenset({"web", "api"}), "collections.replay", "1",
            "state_changing_http",
            {
                "http_requests": 2_000,
                "state_changing_requests": 2_000,
                "tool_wall_seconds": 300,
            },
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "durable_reservation": True,
            },
            _schema({
                "collection_id": {"type": "string"},
                "selection_id": {"type": "string"},
                "as_principal": {
                    "type": "string", "enum": ["primary", "secondary", "service"],
                },
            }, required=("collection_id", "selection_id")),
            "request-collection-replay/v2", ("http_observation", "tool_receipt"),
            planner_visible=False,
        ),
        CapabilitySpec(
            "collections.replay_authentication",
            "Replay at most five exact POST authentication requests bound to disposable credentials.",
            "http", "active", frozenset({"web", "api"}), "collections.replay", "1",
            "active_testing",
            {"http_requests": 5, "tool_wall_seconds": 60},
            {
                "network_reachability": True,
                "runtime_target_binding": True,
                "durable_reservation": True,
                "safe_authentication_only": True,
                "disposable_credentials_required": True,
            },
            _schema({
                "collection_id": {"type": "string"},
                "selection_id": {"type": "string"},
                "as_principal": {
                    "type": "string", "enum": ["anonymous", "primary"],
                },
            }, required=("collection_id", "selection_id")),
            "request-collection-replay/v2", ("http_observation", "tool_receipt"),
            planner_visible=False,
        ),
        CapabilitySpec(
            "device.http.probe", "Send one target-pinned read-only request to a confirmed device web origin.",
            "http", "passive", frozenset({"device"}), "device.device_http_request", "1",
            None, {"http_requests": 1, "tool_wall_seconds": 10, "device_fragility_points": 1}, {"network_reachability": True},
            _schema({"path": {"type": "string", "minLength": 1, "maxLength": 2048}, "method": {"type": "string", "enum": ["GET", "HEAD"]}, "origin_port": {"type": "integer", "minimum": 1, "maximum": 65535}}, required=("path",)),
            "device-http-observation/v1", ("http_observation",),
            hunt_executor="device_http",
        ),
        CapabilitySpec(
            "device.scan", "Queue one bounded device posture scan through the canonical scanner pipeline.",
            "internal", "active", frozenset({"device"}), "device.queue_device_scan", "1",
            "active_testing", {"active_actions": 1, "tool_wall_seconds": 30, "device_fragility_points": 22}, {"device_worker": True},
            _schema({
                "coverage_profile": {"type": "string", "enum": ["inventory", "posture", "thorough"]},
                "include_web_dast": {"type": "boolean"},
                "web_budget_profile": {"type": "string", "enum": ["fast", "balanced", "thorough"]},
                "include_imported_requests": {"type": "boolean"},
                "reason": {"type": "string", "maxLength": 500},
                "capability_ids": {"type": "array", "items": {"type": "string", "enum": ["ssh-authenticated-host-review"]}, "maxItems": 1},
            }, required=("coverage_profile", "reason")),
            "device-scan-queue/v1", ("scan_receipt",),
            hunt_executor="device_queue",
        ),
        CapabilitySpec(
            "device.service.verify", "Queue a typed, fixed-port service-state verifier.",
            "internal", "active", frozenset({"device"}), "device.verify_service_state", "1",
            "active_testing", {"active_actions": 1, "tcp_ports_attempted": 1, "udp_ports_attempted": 1, "tool_wall_seconds": 30, "device_fragility_points": 6}, {"device_worker": True},
            _schema({"transport": {"type": "string", "enum": ["tcp", "udp"]}, "port": {"type": "integer", "minimum": 1, "maximum": 65535}, "expected_state": {"type": "string", "enum": ["open", "closed"]}, "reason": {"type": "string", "minLength": 1, "maxLength": 500}}, required=("transport", "port", "expected_state", "reason")),
            "device-service-verification/v1", ("service_state_observation",),
            hunt_executor="device_queue",
        ),
        CapabilitySpec(
            "device.ssh.propose", "Propose an immutable command plan for a bound, host-key-pinned SSH service; this does not execute it.",
            "internal", "credential", frozenset({"device"}), "device.propose_ssh_shell", "1",
            "active_testing", {"active_actions": 1, "tool_wall_seconds": 5}, {"control_plane": True, "credential_binding": "ssh"},
            _schema({
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "commands": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 4096}, "minItems": 1, "maxItems": 8},
                "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 60},
                "purpose": {"type": "string", "minLength": 1, "maxLength": 1000},
                "risk_summary": {"type": "string", "minLength": 1, "maxLength": 1000},
            }, required=("port", "commands", "purpose", "risk_summary")),
            "device-ssh-plan/v1", ("immutable_shell_plan", "user_confirmation_required"),
            hunt_executor="device_ssh_proposal",
        ),
        CapabilitySpec(
            "device.ssh.execute_confirmed", "Queue one immutable SSH command plan only after the user confirms its exact digest and remote-device effects.",
            "internal", "credential", frozenset({"device"}), "device.confirm_ssh_shell", "1",
            "active_testing", {"active_actions": 1, "tool_wall_seconds": 30, "device_fragility_points": 12},
            {"device_worker": True, "credential_binding": "ssh", "user_confirmation": True},
            _schema({
                "plan_id": {"type": "string"},
                "plan_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "confirmation_phrase_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "confirm_exact_commands": {"type": "boolean"},
                "confirm_remote_device_effects": {"type": "boolean"},
            }, required=("plan_id", "plan_digest", "confirmation_phrase_sha256", "confirm_exact_commands", "confirm_remote_device_effects")),
            "device-ssh-execution-queue/v1",
            ("immutable_shell_plan", "user_confirmation_receipt", "scan_receipt"),
            planner_visible=False,
            hunt_executor="confirmation",
        ),
    )
)


PROCESS_TOOL_TO_CAPABILITY: Mapping[str, str] = MappingProxyType(
    {spec.process_tool_name: spec.name for spec in CAPABILITY_REGISTRY.process_tools()
     if spec.process_tool_name}
)
