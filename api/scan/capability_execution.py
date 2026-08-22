"""Canonical contracts for executable capabilities owned by one Scan."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from typing import Any, Mapping
import urllib.parse

try:
    from runtime.capability_registry import CapabilitySpec
    from runtime.models import PreparedExecution, ScanPolicy, TargetBinding
except ModuleNotFoundError:  # package imports in host-side tests
    from ..runtime.capability_registry import CapabilitySpec
    from ..runtime.models import PreparedExecution, ScanPolicy, TargetBinding


class ScanCapabilityContractError(ValueError):
    """A capability cannot execute within its immutable Scan authority."""


# Stable, deliberately small TCP service set used by deterministic Scan. Hunt can
# request broader registry profiles, but Scan divides its exact port ceiling
# between discovery and follow-up fingerprinting instead of hiding an unbounded
# second pass inside the scanner subprocess.
CANONICAL_SCAN_NETWORK_PORTS: tuple[int, ...] = (
    21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
    1433, 1521, 1883, 3000, 3306, 5432, 6379, 8080, 8443, 8883, 9200,
)


def _budget_integer(
    budget: Mapping[str, Any], name: str, *, allow_zero: bool = False,
) -> int:
    value = budget.get(name)
    if isinstance(value, bool):
        raise ScanCapabilityContractError(f"Scan {name} must be an integer")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise ScanCapabilityContractError(f"Scan {name} must be an integer") from exc
    if normalized < (0 if allow_zero else 1):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ScanCapabilityContractError(
            f"Scan {name} must be a {qualifier} integer"
        )
    return normalized


def scan_network_capability_allocation(
    budget: Mapping[str, Any],
    *,
    available_address_count: int,
    reserved_tcp_ports: int = 0,
) -> dict[str, Any]:
    """Partition exact Scan ceilings across port discovery and fingerprinting."""
    addresses = int(available_address_count)
    if addresses <= 0:
        raise ScanCapabilityContractError(
            "network discovery requires at least one bound address"
        )
    endpoints = _budget_integer(budget, "max_endpoints")
    ports = _budget_integer(budget, "max_tcp_ports")
    reserve = max(0, min(ports - 1, int(reserved_tcp_ports)))
    ports -= reserve
    wall = _budget_integer(budget, "max_tool_wall_seconds")
    can_fingerprint = endpoints >= 2 and ports >= 2 and wall >= 2
    passes = 2 if can_fingerprint else 1
    address_count = min(
        addresses,
        max(1, endpoints // passes),
        max(1, ports // passes),
    )
    port_capacity = max(1, ports // passes)
    ports_per_address = max(1, port_capacity // address_count)
    selected_ports = CANONICAL_SCAN_NETWORK_PORTS[
        :min(len(CANONICAL_SCAN_NETWORK_PORTS), ports_per_address)
    ]
    attempt_count = len(selected_ports) * address_count
    first_wall = max(1, wall // passes)
    result: dict[str, Any] = {
        "address_count": address_count,
        "reserved_tcp_ports": reserve,
        "ports": selected_ports,
        "port_discovery_limits": {
            "hosts_attempted": address_count,
            "tcp_ports_attempted": attempt_count,
            "tool_wall_seconds": first_wall,
        },
        "fingerprint_limits": None,
    }
    if can_fingerprint:
        result["fingerprint_limits"] = {
            "hosts_attempted": address_count,
            "tcp_ports_attempted": attempt_count,
            "tool_wall_seconds": wall - first_wall,
        }
    return result


def scan_template_capability_allocation(
    budget: Mapping[str, Any],
) -> dict[str, int] | None:
    """Reserve a bounded Nuclei slice without starving the baseline Scan."""
    http = _budget_integer(budget, "max_http_requests")
    wall = _budget_integer(budget, "max_tool_wall_seconds")
    if http < 2 or wall < 2:
        return None
    return {
        "http_requests": min(4_000, max(1, http // 4)),
        "tool_wall_seconds": min(300, max(1, wall // 4)),
    }


def scan_web_probe_capability_allocation(
    budget: Mapping[str, Any],
    *,
    preserve_http_requests: int = 1,
    preserve_tool_wall_seconds: int = 1,
) -> dict[str, int] | None:
    """Reserve HTTPX while preserving capacity for later canonical stages."""
    http = _budget_integer(budget, "max_http_requests")
    wall = _budget_integer(budget, "max_tool_wall_seconds")
    preserved_http = max(1, int(preserve_http_requests))
    preserved_wall = max(1, int(preserve_tool_wall_seconds))
    if http <= preserved_http or wall <= preserved_wall:
        return None
    return {
        "http_requests": min(4, http - preserved_http),
        "tool_wall_seconds": min(30, wall - preserved_wall),
    }


def scan_web_crawl_capability_allocation(
    budget: Mapping[str, Any],
) -> dict[str, int] | None:
    """Reserve a bounded crawl slice while retaining the Scan backbone."""
    http = _budget_integer(budget, "max_http_requests")
    wall = _budget_integer(budget, "max_tool_wall_seconds")
    if http < 4 or wall < 4:
        return None
    return {
        "http_requests": min(150, max(1, http // 10)),
        "tool_wall_seconds": min(75, max(1, wall // 10)),
    }


def scan_content_discovery_capability_allocation(
    budget: Mapping[str, Any],
) -> dict[str, int] | None:
    """Reserve one fixed-wordlist discovery slice inside Scan ceilings."""
    http = _budget_integer(budget, "max_http_requests")
    wall = _budget_integer(budget, "max_tool_wall_seconds")
    if http < 4 or wall < 4:
        return None
    return {
        "http_requests": min(220, max(1, http // 10)),
        "tool_wall_seconds": min(75, max(1, wall // 10)),
    }


def scan_external_execution_target(
    target_url: str,
    *,
    target: TargetBinding,
) -> str:
    """Bind an external web tool to one exact frozen Scan origin."""
    try:
        parsed = urllib.parse.urlsplit(str(target_url or "").strip())
        _ = parsed.port
    except ValueError as exc:
        raise ScanCapabilityContractError(
            "external Scan target has an invalid authority"
        ) from exc
    host = str(parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        raise ScanCapabilityContractError(
            "external Scan target must be an absolute HTTP(S) URL"
        )
    if parsed.username or parsed.password:
        raise ScanCapabilityContractError(
            "external Scan target must not contain user information"
        )
    if host != target.canonical_host:
        raise ScanCapabilityContractError(
            "external Scan target host does not match its frozen binding"
        )
    origin = urllib.parse.urlunsplit((
        parsed.scheme.lower(), parsed.netloc.lower(), "", "", "",
    ))
    if origin not in target.allowed_origins:
        raise ScanCapabilityContractError(
            "external Scan target origin is outside its frozen binding"
        )
    return urllib.parse.urlunsplit((
        parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/",
        parsed.query, "",
    ))


def scan_budget_ledger_limits(
    budget: Mapping[str, Any], *, allow_zero: bool = False,
) -> dict[str, int]:
    """Map one canonical Scan budget to the shared reservation dimensions."""
    http = _budget_integer(
        budget, "max_http_requests", allow_zero=allow_zero,
    )
    endpoints = _budget_integer(
        budget, "max_endpoints", allow_zero=allow_zero,
    )
    return {
        "http_requests": http,
        # Scan has no independent mutation ceiling yet. Permission is enforced by
        # policy, while this prevents writes from exceeding total HTTP authority.
        "state_changing_requests": http,
        "browser_actions": _budget_integer(
            budget, "max_browser_actions", allow_zero=allow_zero,
        ),
        "tcp_ports_attempted": _budget_integer(
            budget, "max_tcp_ports", allow_zero=allow_zero,
        ),
        # A root-bound discovery action consumes one host attempt. The endpoint
        # ceiling is the existing Scan-level bound until max_hosts becomes a
        # separately configurable public Scan field.
        "hosts_attempted": endpoints,
        "tool_wall_seconds": _budget_integer(
            budget, "max_tool_wall_seconds", allow_zero=allow_zero,
        ),
    }


def prepare_scan_process_capability(
    *,
    execution_plan_digest: str,
    target: TargetBinding,
    stage_rows: tuple[Mapping[str, Any], ...],
    ledger_limits: Mapping[str, int],
    consumed: Mapping[str, int],
    allow_state_changing_http: bool,
    allocation_limits: Mapping[str, int] | None = None,
) -> tuple[PreparedExecution, dict[str, int]]:
    """Bind the deterministic scanner to the exact remaining durable hold.

    Missing mandatory HTTP/host/wall capacity is represented as a one-unit
    request that the locked ledger will reject. This still yields a durable
    blocked reservation and receipt without allowing the scanner to start.
    """
    limits = {str(name): max(0, int(amount)) for name, amount in ledger_limits.items()}
    used = {str(name): max(0, int(amount)) for name, amount in consumed.items()}
    remaining = {
        name: max(0, amount - used.get(name, 0))
        for name, amount in limits.items()
    }
    for raw_name, raw_amount in dict(allocation_limits or {}).items():
        name = str(raw_name or "").strip()
        if name not in remaining:
            raise ScanCapabilityContractError(
                f"unknown Scan process allocation dimension: {name}"
            )
        amount = int(raw_amount)
        if amount < 0:
            raise ScanCapabilityContractError(
                f"Scan process allocation must be non-negative: {name}"
            )
        remaining[name] = min(remaining[name], amount)
    runtime_budget = {
        "http_requests": remaining.get("http_requests", 0),
        "state_changing_requests": (
            min(
                remaining.get("state_changing_requests", 0),
                remaining.get("http_requests", 0),
            )
            if allow_state_changing_http else 0
        ),
        "browser_actions": remaining.get("browser_actions", 0),
        # Network discovery is separately reserved. The native scanner may use
        # one residual port for a frozen-address TLS handshake and no other
        # canonical TCP analyzer.
        "tcp_ports_attempted": min(
            remaining.get("tcp_ports_attempted", 0),
            1 if any(
                str(origin).lower().startswith("https://")
                for origin in target.allowed_origins
            ) else 0,
        ),
        "hosts_attempted": remaining.get("hosts_attempted", 0),
        "tool_wall_seconds": remaining.get("tool_wall_seconds", 0),
    }
    requested = {
        name: amount
        for name, amount in runtime_budget.items()
        if amount > 0
    }
    for mandatory in (
        "http_requests", "hosts_attempted", "tool_wall_seconds",
    ):
        if runtime_budget[mandatory] <= 0:
            requested[mandatory] = 1
    input_payload = {
        "schema_version": "deterministic-scan-capability/v1",
        "execution_plan_digest": str(execution_plan_digest).lower(),
        "target_binding_digest": target.digest,
        "stages": [dict(item) for item in stage_rows],
        "runtime_budget": runtime_budget,
    }
    prepared = PreparedExecution(
        capability_name="scan.execute",
        adapter_name="scanner.dast",
        adapter_version="1",
        commands=(),
        estimated_budget=requested,
        input_digest=PreparedExecution.digest_input(input_payload),
        redacted_execution=input_payload,
        parser_version="scan-report/v2",
    )
    return prepared, runtime_budget


def _normalize_external_capability_args(
    specification: CapabilitySpec,
    args: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the small registry-owned option surface used by Scan tools."""
    schema = dict(specification.input_schema or {})
    properties = dict(schema.get("properties") or {})
    unknown = set(args) - set(properties)
    if unknown or schema.get("additionalProperties") is not False:
        rendered = ", ".join(sorted(str(name) for name in unknown)) or "schema"
        raise ScanCapabilityContractError(
            f"unsupported {specification.name} input: {rendered}"
        )
    missing = [
        str(name) for name in schema.get("required") or ()
        if name not in args
    ]
    if missing:
        raise ScanCapabilityContractError(
            f"missing {specification.name} input: {', '.join(missing)}"
        )
    normalized: dict[str, Any] = {}
    for raw_name, value in args.items():
        name = str(raw_name)
        field = dict(properties.get(name) or {})
        expected = str(field.get("type") or "")
        if expected == "string":
            if not isinstance(value, str):
                raise ScanCapabilityContractError(
                    f"{specification.name} input {name} must be a string"
                )
            if len(value) > 2_000 or any(ord(ch) < 0x20 for ch in value):
                raise ScanCapabilityContractError(
                    f"{specification.name} input {name} is invalid"
                )
        elif expected == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ScanCapabilityContractError(
                    f"{specification.name} input {name} must be an integer"
                )
            if field.get("minimum") is not None and value < int(field["minimum"]):
                raise ScanCapabilityContractError(
                    f"{specification.name} input {name} is below its minimum"
                )
            if field.get("maximum") is not None and value > int(field["maximum"]):
                raise ScanCapabilityContractError(
                    f"{specification.name} input {name} exceeds its maximum"
                )
        elif expected == "boolean" and not isinstance(value, bool):
            raise ScanCapabilityContractError(
                f"{specification.name} input {name} must be a boolean"
            )
        allowed = field.get("enum")
        if isinstance(allowed, list) and value not in allowed:
            raise ScanCapabilityContractError(
                f"{specification.name} input {name} is outside its enum"
            )
        normalized[name] = value
    return normalized


def prepare_scan_external_capability(
    *,
    specification: CapabilitySpec,
    target: TargetBinding,
    args: Mapping[str, Any],
    policy: ScanPolicy,
) -> PreparedExecution:
    """Prepare one registry-owned external tool under immutable Scan authority."""
    if specification.execution_kind != "external_tool":
        raise ScanCapabilityContractError(
            f"{specification.name} is not an external Scan capability"
        )
    if not specification.binary or not specification.legacy_tool_name:
        raise ScanCapabilityContractError(
            f"{specification.name} has no fixed-template adapter"
        )
    if target.target_kind not in specification.target_kinds:
        raise ScanCapabilityContractError(
            f"{specification.name} does not support {target.target_kind} targets"
        )
    if not target.allowed_origins or not target.allowed_addresses:
        raise ScanCapabilityContractError(
            f"{specification.name} requires a frozen web target binding"
        )
    if specification.requires_active_approval and not (
        policy.active_testing and policy.approval_receipt_id
    ):
        raise ScanCapabilityContractError(
            f"{specification.name} requires active testing approval"
        )
    normalized = _normalize_external_capability_args(specification, args)
    estimated = {
        str(name): int(amount)
        for name, amount in dict(specification.budget_cost).items()
        if int(amount) > 0
    }
    if not estimated:
        raise ScanCapabilityContractError(
            f"{specification.name} has no reservable budget"
        )
    redacted = {
        "schema_version": "scan-external-capability/v1",
        "capability_name": specification.name,
        "target_binding_digest": target.digest,
        "input": normalized,
    }
    return PreparedExecution(
        capability_name=specification.name,
        adapter_name=specification.adapter,
        adapter_version=specification.adapter_version,
        commands=(),
        estimated_budget=estimated,
        input_digest=PreparedExecution.digest_input(redacted),
        redacted_execution=redacted,
        parser_version=specification.output_schema,
    )


def fit_prepared_scan_capability(
    prepared: PreparedExecution,
    *,
    ledger_limits: Mapping[str, int],
) -> PreparedExecution:
    """Clamp an adapter estimate to exact Scan ceilings before reservation."""
    requested: dict[str, int] = {}
    for raw_name, raw_amount in dict(prepared.estimated_budget).items():
        name = str(raw_name or "").strip()
        if name not in ledger_limits:
            raise ScanCapabilityContractError(
                f"capability requires undeclared Scan budget dimension: {name}"
            )
        amount = int(raw_amount)
        ceiling = int(ledger_limits[name])
        if amount <= 0 or ceiling <= 0:
            raise ScanCapabilityContractError(
                f"Scan budget leaves no capacity for capability dimension: {name}"
            )
        requested[name] = min(amount, ceiling)
    if not requested:
        raise ScanCapabilityContractError("capability did not declare a budget")
    return replace(prepared, estimated_budget=requested)


def scan_capability_action_digest(
    *,
    scan_id: str,
    execution_plan_digest: str,
    target: TargetBinding,
    prepared: PreparedExecution,
) -> str:
    """Bind idempotency to the exact Scan plan, target, input, and hold."""
    payload = {
        "schema_version": "scan-capability-action/v1",
        "scan_id": str(scan_id),
        "execution_plan_digest": str(execution_plan_digest).lower(),
        "target_binding": target.canonical_dict(),
        "target_binding_digest": target.digest,
        "capability_name": prepared.capability_name,
        "adapter_name": prepared.adapter_name,
        "adapter_version": prepared.adapter_version,
        "input_digest": prepared.input_digest,
        "requested_budget": {
            str(name): int(amount)
            for name, amount in sorted(dict(prepared.estimated_budget).items())
        },
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
