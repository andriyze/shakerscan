"""Immutable, content-addressed action graph for one canonical Scan."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence
import uuid

try:
    from runtime.budgets import BUDGET_DIMENSIONS
    from runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityRegistry
    from runtime.credentials import (
        CredentialContractError,
        HTTP_CREDENTIAL_KINDS,
        normalize_credential_kind,
    )
    from runtime.models import TargetBinding
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.budgets import BUDGET_DIMENSIONS
    from ..runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityRegistry
    from ..runtime.credentials import (
        CredentialContractError,
        HTTP_CREDENTIAL_KINDS,
        normalize_credential_kind,
    )
    from ..runtime.models import TargetBinding

from .execution import ScanExecutionPlan
from .work_manifests import (
    CANONICAL_PASSIVE_NUCLEI_TEMPLATES,
    ScanWorkManifestError,
    ScanWorkManifestKind,
    ScanWorkManifestReference,
)
from .external_process import minimum_reservation_scaled_profile


SCAN_ACTION_PLAN_SCHEMA = "scan-action-plan/v1"
SCAN_ACTION_SCHEMA = "scan-action/v1"
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_SCHEMA_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+/-]{0,127}$")
_MAX_CANONICAL_BYTES = 512 * 1024
_MAX_ACTIONS = 512
_MAX_DEPENDENCIES = 511
_BATCH_CAPABILITIES = frozenset({
    "xss.verify_batch",
    "sqli.verify_batch",
    "templates.passive_batch",
    "templates.active_batch",
    "xss.request_verify_batch",
    "sqli.request_verify_batch",
    "sqli.prove_batch",
    "xss.browser_prove_batch",
    "exposure.verify_batch",
    "nosqli.verify_batch",
})
_BATCH_PROFILES: Mapping[str, Mapping[str, tuple[int, Mapping[str, int]]]] = {
    "fast": {
        "xss.verify_batch": (5, {"http_requests": 100, "tool_wall_seconds": 90}),
        "sqli.verify_batch": (5, {"http_requests": 400, "tool_wall_seconds": 120}),
        "templates.passive_batch": (50, {"http_requests": 350, "tool_wall_seconds": 60}),
        "templates.active_batch": (25, {"http_requests": 2_000, "tool_wall_seconds": 180}),
        "xss.request_verify_batch": (5, {"http_requests": 10, "state_changing_requests": 10, "tool_wall_seconds": 60}),
        "sqli.request_verify_batch": (5, {"http_requests": 10, "state_changing_requests": 10, "tool_wall_seconds": 60}),
        "sqli.prove_batch": (5, {"http_requests": 40, "state_changing_requests": 40, "tool_wall_seconds": 90}),
        "xss.browser_prove_batch": (5, {"browser_actions": 10, "http_requests": 250, "tool_wall_seconds": 150}),
        "exposure.verify_batch": (40, {"http_requests": 200, "tool_wall_seconds": 120}),
        "nosqli.verify_batch": (5, {"http_requests": 40, "state_changing_requests": 40, "tool_wall_seconds": 90}),
    },
    "balanced": {
        "xss.verify_batch": (20, {"http_requests": 400, "tool_wall_seconds": 180}),
        "sqli.verify_batch": (10, {"http_requests": 800, "tool_wall_seconds": 180}),
        "templates.passive_batch": (50, {"http_requests": 350, "tool_wall_seconds": 60}),
        "templates.active_batch": (50, {"http_requests": 4_000, "tool_wall_seconds": 300}),
        "xss.request_verify_batch": (10, {"http_requests": 20, "state_changing_requests": 20, "tool_wall_seconds": 120}),
        "sqli.request_verify_batch": (10, {"http_requests": 20, "state_changing_requests": 20, "tool_wall_seconds": 120}),
        "sqli.prove_batch": (10, {"http_requests": 80, "state_changing_requests": 80, "tool_wall_seconds": 120}),
        "xss.browser_prove_batch": (10, {"browser_actions": 20, "http_requests": 500, "tool_wall_seconds": 240}),
        "exposure.verify_batch": (60, {"http_requests": 400, "tool_wall_seconds": 180}),
        "nosqli.verify_batch": (10, {"http_requests": 80, "state_changing_requests": 80, "tool_wall_seconds": 120}),
    },
    "thorough": {
        "xss.verify_batch": (50, {"http_requests": 1_000, "tool_wall_seconds": 300}),
        "sqli.verify_batch": (25, {"http_requests": 1_800, "tool_wall_seconds": 300}),
        "templates.passive_batch": (50, {"http_requests": 350, "tool_wall_seconds": 60}),
        "templates.active_batch": (50, {"http_requests": 4_000, "tool_wall_seconds": 300}),
        "xss.request_verify_batch": (20, {"http_requests": 40, "state_changing_requests": 40, "tool_wall_seconds": 180}),
        "sqli.request_verify_batch": (20, {"http_requests": 40, "state_changing_requests": 40, "tool_wall_seconds": 180}),
        "sqli.prove_batch": (25, {"http_requests": 200, "state_changing_requests": 200, "tool_wall_seconds": 180}),
        "xss.browser_prove_batch": (25, {"browser_actions": 50, "http_requests": 1_250, "tool_wall_seconds": 600}),
        "exposure.verify_batch": (80, {"http_requests": 600, "tool_wall_seconds": 240}),
        "nosqli.verify_batch": (25, {"http_requests": 200, "state_changing_requests": 200, "tool_wall_seconds": 180}),
    },
}
_FORBIDDEN_ACTION_KEYS = frozenset({
    "password", "passwd", "secret", "token", "authorization", "cookie", "cookies",
    "private_key", "client_secret", "api_key", "auth_header", "auth_cookies",
    "headers", "body", "raw_request", "command", "argv", "shell",
})


class ScanActionPlanError(ValueError):
    """Action authority is malformed, ambiguous, or not content-addressed."""


class ScanActionPlacementError(ScanActionPlanError):
    """No selected backend can execute the complete deterministic action plan."""


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _hex_digest(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _HEX_64_RE.fullmatch(normalized):
        raise ScanActionPlanError(f"{name} must be 64 lowercase hex characters")
    return normalized


def _token(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip()
    if not _TOKEN_RE.fullmatch(normalized):
        raise ScanActionPlanError(f"{name} is invalid")
    return normalized


def _schema(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip()
    if not _SCHEMA_RE.fullmatch(normalized):
        raise ScanActionPlanError(f"{name} is invalid")
    return normalized


def _canonical_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 12:
        raise ScanActionPlanError("action input nesting is too deep")
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str) and len(value.encode("utf-8")) > 131_072:
            raise ScanActionPlanError("action input string is too large")
        return value
    if isinstance(value, Mapping):
        if len(value) > 1_024:
            raise ScanActionPlanError("action input object has too many fields")
        normalized: dict[str, Any] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str) or not raw_key or len(raw_key) > 128:
                raise ScanActionPlanError("action input keys must be bounded strings")
            if raw_key.strip().lower() in _FORBIDDEN_ACTION_KEYS:
                raise ScanActionPlanError(
                    f"secret-bearing action input key is forbidden: {raw_key}"
                )
            if raw_key in normalized:
                raise ScanActionPlanError("action input contains duplicate keys")
            normalized[raw_key] = _canonical_value(item, depth=depth + 1)
        return {key: normalized[key] for key in sorted(normalized)}
    if isinstance(value, (list, tuple)):
        if len(value) > 5_000:
            raise ScanActionPlanError("action input list is too large")
        return [_canonical_value(item, depth=depth + 1) for item in value]
    raise ScanActionPlanError(
        f"action input contains unsupported value type: {type(value).__name__}"
    )


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _budget(value: Mapping[str, Any]) -> Mapping[str, int]:
    normalized: dict[str, int] = {}
    for raw_name, raw_amount in dict(value or {}).items():
        name = str(raw_name or "").strip()
        if name not in BUDGET_DIMENSIONS:
            raise ScanActionPlanError(f"unknown action budget dimension: {name}")
        if isinstance(raw_amount, bool) or not isinstance(raw_amount, int):
            raise ScanActionPlanError(f"action budget {name} must be an integer")
        if raw_amount < 0:
            raise ScanActionPlanError(f"action budget {name} must be non-negative")
        if raw_amount:
            normalized[name] = raw_amount
    return MappingProxyType({key: normalized[key] for key in sorted(normalized)})


def digest_input_bindings(value: Mapping[str, Any]) -> str:
    """Digest opaque IDs/versions and manifest digests without secret values."""
    canonical = _canonical_value(value)
    encoded = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    if len(encoded) > _MAX_CANONICAL_BYTES:
        raise ScanActionPlanError("input binding material is too large")
    return hashlib.sha256(encoded).hexdigest()


def credential_profile_action_refs(
    refs: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Reduce admitted profile metadata to versioned, content-free plan refs."""
    result: list[dict[str, Any]] = []
    for raw in refs:
        profile_id = str(raw.get("profile_id") or "").strip()
        lane = str(raw.get("scan_lane") or raw.get("lane") or "").strip().lower()
        try:
            version = int(raw.get("profile_version") or raw.get("version") or 0)
        except (TypeError, ValueError) as exc:
            raise ScanActionPlanError("credential profile version is invalid") from exc
        if not profile_id or lane not in {"primary", "secondary", "service", "ssh"} or version < 1:
            raise ScanActionPlanError("credential profile action reference is incomplete")
        try:
            auth_kind = normalize_credential_kind(
                raw.get("auth_kind"), accept_legacy_alias=True,
            )
        except CredentialContractError as exc:
            raise ScanActionPlanError(
                "credential profile action auth kind is unsupported"
            ) from exc
        if auth_kind not in HTTP_CREDENTIAL_KINDS:
            raise ScanActionPlanError(
                "credential profile action auth kind is unsupported"
            )
        material = {
            "profile_id": profile_id,
            "version": version,
            "lane": lane,
            "target_kind": str(raw.get("target_kind") or "").strip().lower(),
            "auth_kind": auth_kind,
        }
        result.append({
            "profile_id": profile_id,
            "version": version,
            "digest": digest_input_bindings(material),
            "lane": lane,
            "auth_kind": material["auth_kind"],
        })
    return tuple(result)


def request_collection_action_refs(
    refs: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Reduce saved executable selections to immutable Scan plan refs."""
    result: list[dict[str, Any]] = []
    for raw in refs:
        collection_id = str(raw.get("collection_id") or "").strip()
        selection_id = str(raw.get("selection_id") or "").strip()
        binding_id = str(raw.get("binding_id") or "").strip()
        selection_digest = str(raw.get("selection_digest") or "").strip().lower()
        replay_policy = str(raw.get("replay_policy") or "").strip().lower()
        if replay_policy not in {
            "safe_reads", "safe_authentication", "confirmed_active",
        }:
            continue
        try:
            selected = int(raw.get("selected_requests") or 0)
        except (TypeError, ValueError) as exc:
            raise ScanActionPlanError("request collection selected count is invalid") from exc
        selector = raw.get("selector") if isinstance(raw.get("selector"), Mapping) else {}
        try:
            selector_limit = int(selector.get("max_requests") or selector.get("limit") or 500)
        except (TypeError, ValueError) as exc:
            raise ScanActionPlanError("request collection limit is invalid") from exc
        if (
            not collection_id
            or not selection_id
            or not binding_id
            or not _HEX_64_RE.fullmatch(selection_digest)
            or selected < 1
            or selector_limit < 1
        ):
            raise ScanActionPlanError("request collection action reference is incomplete")
        result.append({
            "collection_id": collection_id,
            "selection_id": selection_id,
            "binding_id": binding_id,
            "version": 1,
            "selection_digest": selection_digest,
            "active": replay_policy == "confirmed_active",
            "replay_policy": replay_policy,
            "max_requests": min(2_000, selected, selector_limit),
        })
    return tuple(result)


@dataclass(frozen=True)
class ScanAction:
    action_id: str
    stage: str
    ordinal: int
    capability_name: str
    capability_args: Mapping[str, Any]
    target_binding_digest: str
    input_binding_digest: str
    requested_budget: Mapping[str, int]
    placement: Mapping[str, Any]
    dependencies: tuple[str, ...]
    required: bool
    supporting: bool
    output_schema: str
    admission_status: str = "planned"
    reason_code: str | None = None
    schema_version: str = SCAN_ACTION_SCHEMA
    action_digest: str | None = field(default=None, compare=True)

    def __post_init__(self) -> None:
        if self.schema_version != SCAN_ACTION_SCHEMA:
            raise ScanActionPlanError("unsupported Scan action schema")
        action_id = _token(self.action_id, name="action_id")
        stage = _token(self.stage, name="stage")
        capability = _token(self.capability_name, name="capability_name")
        if isinstance(self.ordinal, bool) or not isinstance(self.ordinal, int) or self.ordinal < 0:
            raise ScanActionPlanError("action ordinal must be a non-negative integer")
        if not isinstance(self.required, bool) or not isinstance(self.supporting, bool):
            raise ScanActionPlanError("action classification flags must be booleans")
        admission_status = str(self.admission_status or "").strip()
        reason_code = str(self.reason_code or "").strip() or None
        if admission_status not in {"planned", "skipped"}:
            raise ScanActionPlanError("action admission_status is invalid")
        if admission_status == "planned" and reason_code is not None:
            raise ScanActionPlanError("planned action cannot have a skip reason")
        if admission_status == "skipped" and reason_code not in {
            "insufficient_plan_budget", "dependency_failed", "policy_disabled",
        }:
            raise ScanActionPlanError("skipped action requires a stable reason_code")
        dependencies = tuple(
            _token(item, name="dependency action_id") for item in self.dependencies
        )
        if len(dependencies) > _MAX_DEPENDENCIES or len(set(dependencies)) != len(dependencies):
            raise ScanActionPlanError("action dependencies are too large or contain duplicates")
        if action_id in dependencies:
            raise ScanActionPlanError("an action cannot depend on itself")

        args = _canonical_value(self.capability_args)
        placement = _canonical_value(self.placement)
        if not isinstance(args, Mapping) or not isinstance(placement, Mapping):
            raise ScanActionPlanError("capability_args and placement must be objects")
        canonical_size = len(json.dumps(
            {"capability_args": args, "placement": placement},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8"))
        if canonical_size > _MAX_CANONICAL_BYTES:
            raise ScanActionPlanError("action authority is too large")

        object.__setattr__(self, "action_id", action_id)
        object.__setattr__(self, "stage", stage)
        object.__setattr__(self, "capability_name", capability)
        object.__setattr__(self, "capability_args", _freeze(args))
        object.__setattr__(self, "target_binding_digest", _hex_digest(
            self.target_binding_digest, name="target_binding_digest",
        ))
        object.__setattr__(self, "input_binding_digest", _hex_digest(
            self.input_binding_digest, name="input_binding_digest",
        ))
        object.__setattr__(self, "requested_budget", _budget(self.requested_budget))
        object.__setattr__(self, "placement", _freeze(placement))
        object.__setattr__(self, "dependencies", dependencies)
        object.__setattr__(self, "admission_status", admission_status)
        object.__setattr__(self, "reason_code", reason_code)
        object.__setattr__(self, "output_schema", _schema(
            self.output_schema, name="output_schema",
        ))
        expected = _digest(self.digest_material())
        supplied = self.action_digest
        if supplied is not None and _hex_digest(supplied, name="action_digest") != expected:
            raise ScanActionPlanError("action_digest does not match canonical action authority")
        object.__setattr__(self, "action_digest", expected)

    def digest_material(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "action_id": self.action_id,
            "stage": self.stage,
            "ordinal": self.ordinal,
            "capability_name": self.capability_name,
            "capability_args": _thaw(self.capability_args),
            "target_binding_digest": self.target_binding_digest,
            "input_binding_digest": self.input_binding_digest,
            "requested_budget": dict(self.requested_budget),
            "placement": _thaw(self.placement),
            "dependencies": list(self.dependencies),
            "required": self.required,
            "supporting": self.supporting,
            "output_schema": self.output_schema,
            "admission_status": self.admission_status,
            "reason_code": self.reason_code,
        }

    def canonical_dict(self) -> dict[str, Any]:
        return {**self.digest_material(), "action_digest": self.action_digest}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScanAction":
        expected = {
            "schema_version", "action_id", "stage", "ordinal", "capability_name",
            "capability_args", "target_binding_digest", "input_binding_digest",
            "requested_budget", "placement", "dependencies", "required", "supporting",
            "output_schema", "admission_status", "reason_code", "action_digest",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ScanActionPlanError("Scan action fields are invalid")
        if not isinstance(value["dependencies"], list):
            raise ScanActionPlanError("action dependencies must be a list")
        return cls(**dict(value))


@dataclass(frozen=True)
class ScanActionPlan:
    scan_id: str
    execution_plan_digest: str
    target_binding_digest: str
    actions: tuple[ScanAction, ...]
    schema_version: str = SCAN_ACTION_PLAN_SCHEMA
    plan_digest: str | None = field(default=None, compare=True)

    def __post_init__(self) -> None:
        if self.schema_version != SCAN_ACTION_PLAN_SCHEMA:
            raise ScanActionPlanError("unsupported Scan action-plan schema")
        try:
            scan_id = str(uuid.UUID(str(self.scan_id)))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ScanActionPlanError("scan_id must be a UUID") from exc
        actions = tuple(self.actions)
        if len(actions) > _MAX_ACTIONS:
            raise ScanActionPlanError("Scan action plan contains too many actions")
        ids = [action.action_id for action in actions]
        if len(set(ids)) != len(ids):
            raise ScanActionPlanError("Scan action IDs must be unique")
        positions = {action_id: index for index, action_id in enumerate(ids)}
        target_digest = _hex_digest(
            self.target_binding_digest, name="target_binding_digest",
        )
        for index, action in enumerate(actions):
            if action.ordinal != index:
                raise ScanActionPlanError("Scan action ordinals must be contiguous and ordered")
            if action.target_binding_digest != target_digest:
                raise ScanActionPlanError("action target binding differs from the action plan")
            for dependency in action.dependencies:
                if dependency not in positions:
                    raise ScanActionPlanError("action dependency is absent from the plan")
                if positions[dependency] >= index:
                    raise ScanActionPlanError("action dependencies must precede their consumer")
        object.__setattr__(self, "scan_id", scan_id)
        object.__setattr__(self, "execution_plan_digest", _hex_digest(
            self.execution_plan_digest, name="execution_plan_digest",
        ))
        object.__setattr__(self, "target_binding_digest", target_digest)
        object.__setattr__(self, "actions", actions)
        expected = _digest(self.digest_material())
        supplied = self.plan_digest
        if supplied is not None and _hex_digest(supplied, name="plan_digest") != expected:
            raise ScanActionPlanError("plan_digest does not match canonical action plan")
        object.__setattr__(self, "plan_digest", expected)

    def digest_material(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "execution_plan_digest": self.execution_plan_digest,
            "target_binding_digest": self.target_binding_digest,
            "actions": [action.canonical_dict() for action in self.actions],
        }

    def canonical_dict(self) -> dict[str, Any]:
        return {**self.digest_material(), "plan_digest": self.plan_digest}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScanActionPlan":
        expected = {
            "schema_version", "scan_id", "execution_plan_digest",
            "target_binding_digest", "actions", "plan_digest",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ScanActionPlanError("Scan action-plan fields are invalid")
        raw_actions = value.get("actions")
        if not isinstance(raw_actions, list):
            raise ScanActionPlanError("Scan action-plan actions must be a list")
        return cls(
            schema_version=value["schema_version"],
            scan_id=value["scan_id"],
            execution_plan_digest=value["execution_plan_digest"],
            target_binding_digest=value["target_binding_digest"],
            actions=tuple(ScanAction.from_dict(item) for item in raw_actions),
            plan_digest=value["plan_digest"],
        )


@dataclass(frozen=True)
class _ActionBlueprint:
    action_id: str
    stage: str
    capability_name: str
    capability_args: Mapping[str, Any]
    dependencies: tuple[str, ...] = ()
    required: bool = False
    supporting: bool = False


def _reference_list(
    value: Sequence[Mapping[str, Any]],
    *,
    name: str,
    allowed_keys: frozenset[str],
    required_keys: frozenset[str],
    maximum: int,
) -> tuple[dict[str, Any], ...]:
    if len(value) > maximum:
        raise ScanActionPlanError(f"too many {name} references")
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ScanActionPlanError(f"{name} reference must be an object")
        keys = set(item)
        if not required_keys <= keys or keys - allowed_keys:
            raise ScanActionPlanError(f"{name} reference fields are invalid")
        canonical = _canonical_value(item)
        if not isinstance(canonical, dict):
            raise ScanActionPlanError(f"{name} reference must be an object")
        result.append(canonical)
    result.sort(key=lambda item: json.dumps(
        item, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ))
    return tuple(result)


def _work_manifest_reference(
    value: Mapping[str, Any] | None,
    *,
    kind: ScanWorkManifestKind,
) -> dict[str, Any]:
    if not value:
        return {}
    try:
        reference = ScanWorkManifestReference.from_dict(value)
    except (ScanWorkManifestError, TypeError, ValueError) as exc:
        raise ScanActionPlanError(f"{kind.value} manifest reference is invalid") from exc
    if reference.kind is not kind:
        raise ScanActionPlanError(
            f"{kind.value} manifest reference has the wrong kind"
        )
    return reference.canonical_dict()


class ScanActionPlanCompiler:
    """Compile policy plus opaque references into one deterministic action DAG.

    This compiler selects actions and closes prerequisites. The next admission
    boundary may pass a complete ``action_budgets`` allocation; otherwise the
    registry's conservative fixed profiles are used as exact maximum holds.
    """

    plan_schema_version = SCAN_ACTION_PLAN_SCHEMA

    def __init__(self, registry: CapabilityRegistry = CAPABILITY_REGISTRY) -> None:
        self._registry = registry

    @staticmethod
    def _family_enabled(plan: ScanExecutionPlan, family: str) -> bool:
        if plan.resolved_families:
            return family in set(plan.resolved_families)
        include = set(plan.policy.include_families)
        exclude = set(plan.policy.exclude_families)
        return family not in exclude and (not include or family in include)

    def compile(
        self,
        *,
        scan_id: str,
        execution_plan: ScanExecutionPlan,
        target_binding: TargetBinding,
        credential_profile_refs: Sequence[Mapping[str, Any]] = (),
        request_collection_refs: Sequence[Mapping[str, Any]] = (),
        request_manifest_refs: Mapping[str, Mapping[str, Any]] | None = None,
        endpoint_manifest_ref: Mapping[str, Any] | None = None,
        candidate_manifest_ref: Mapping[str, Any] | None = None,
        request_candidate_manifest_ref: Mapping[str, Any] | None = None,
        template_manifest_ref: Mapping[str, Any] | None = None,
        authority_refs: Mapping[str, Any] | None = None,
        shard_authority: Mapping[str, Any] | None = None,
        action_scope: str = "full",
        family_scope: Sequence[str] | None = None,
        defer_manifest_actions: bool = False,
        include_finalizer: bool = True,
        available_placement_capabilities: Iterable[str] | None = None,
        placement_backends: Sequence[str] = ("local", "broker"),
        action_budgets: Mapping[str, Mapping[str, int]] | None = None,
    ) -> ScanActionPlan:
        scope = str(action_scope or "").strip().lower()
        if scope not in {"full", "global", "discovery", "endpoint"}:
            raise ScanActionPlanError("action_scope is invalid")
        if not isinstance(defer_manifest_actions, bool):
            raise ScanActionPlanError("defer_manifest_actions must be a boolean")
        if not isinstance(include_finalizer, bool):
            raise ScanActionPlanError("include_finalizer must be a boolean")
        if defer_manifest_actions and scope != "full":
            raise ScanActionPlanError(
                "manifest action deferral is only valid for a full admission phase"
            )
        narrowed_families = tuple(dict.fromkeys(
            _token(item, name="family scope") for item in (family_scope or ())
        ))
        if any(
            not self._family_enabled(execution_plan, family)
            for family in narrowed_families
        ):
            raise ScanActionPlanError(
                "family_scope cannot widen the immutable Scan policy"
            )
        credentials = _reference_list(
            credential_profile_refs,
            name="credential profile",
            allowed_keys=frozenset({
                "profile_id", "version", "digest", "lane", "auth_kind",
                "principal_ref",
            }),
            required_keys=frozenset({
                "profile_id", "version", "digest", "lane", "auth_kind",
            }),
            maximum=4,
        )
        collections = _reference_list(
            request_collection_refs,
            name="request collection",
            allowed_keys=frozenset({
                "collection_id", "selection_id", "binding_id", "version",
                "selection_digest", "principal_ref", "active", "max_requests",
                "replay_policy",
            }),
            required_keys=frozenset({
                "collection_id", "selection_id", "binding_id", "version",
                "selection_digest",
            }),
            maximum=32,
        )
        for reference in credentials:
            if (
                isinstance(reference.get("version"), bool)
                or not isinstance(reference.get("version"), int)
                or int(reference["version"]) < 1
                or not _HEX_64_RE.fullmatch(str(reference.get("digest") or ""))
                or reference.get("lane") not in {"primary", "secondary", "service", "ssh"}
            ):
                raise ScanActionPlanError("credential profile reference is invalid")
        for reference in collections:
            if (
                isinstance(reference.get("version"), bool)
                or not isinstance(reference.get("version"), int)
                or int(reference["version"]) < 1
                or not _HEX_64_RE.fullmatch(
                    str(reference.get("selection_digest") or "")
                )
                or not isinstance(reference.get("active", False), bool)
                or (
                    "max_requests" in reference
                    and (
                        isinstance(reference["max_requests"], bool)
                        or not isinstance(reference["max_requests"], int)
                        or not 1 <= reference["max_requests"] <= 2_000
                    )
                )
            ):
                raise ScanActionPlanError("request collection reference is invalid")
        request_refs: dict[str, dict[str, Any]] = {}
        for raw_digest, raw_reference in dict(request_manifest_refs or {}).items():
            digest = str(raw_digest or "").strip().lower()
            if not _HEX_64_RE.fullmatch(digest):
                raise ScanActionPlanError("request manifest selection digest is invalid")
            reference = _work_manifest_reference(
                raw_reference, kind=ScanWorkManifestKind.REQUEST,
            )
            request_refs[digest] = reference
        collection_digests = {
            str(reference["selection_digest"]) for reference in collections
        }
        if set(request_refs) != collection_digests:
            raise ScanActionPlanError(
                "request manifests must exactly cover executable collection selections"
            )
        endpoint_ref = _work_manifest_reference(
            endpoint_manifest_ref, kind=ScanWorkManifestKind.ENDPOINT,
        )
        candidate_ref = _work_manifest_reference(
            candidate_manifest_ref, kind=ScanWorkManifestKind.CANDIDATE,
        )
        request_candidate_ref = _work_manifest_reference(
            request_candidate_manifest_ref,
            kind=ScanWorkManifestKind.REQUEST_CANDIDATE,
        )
        template_ref = _work_manifest_reference(
            template_manifest_ref, kind=ScanWorkManifestKind.TEMPLATE,
        )
        authority = _canonical_value({
            "scope_receipt_id": execution_plan.policy.scope_receipt_id,
            "approval_receipt_id": execution_plan.policy.approval_receipt_id,
            "parallel_family_scope": list(narrowed_families),
            **dict(authority_refs or {}),
        })
        shard = _canonical_value(shard_authority or {})
        for name, value in (
            ("endpoint_manifest_ref", endpoint_ref),
            ("candidate_manifest_ref", candidate_ref),
            ("request_candidate_manifest_ref", request_candidate_ref),
            ("template_manifest_ref", template_ref),
            ("authority_refs", authority),
            ("shard_authority", shard),
        ):
            if not isinstance(value, Mapping):
                raise ScanActionPlanError(f"{name} must be an object")

        backends = tuple(dict.fromkeys(_token(item, name="placement backend") for item in placement_backends))
        if not backends:
            raise ScanActionPlacementError("at least one placement backend is required")
        available = (
            None
            if available_placement_capabilities is None
            else frozenset(
                _token(item, name="available placement capability")
                for item in available_placement_capabilities
            )
        )

        policy = execution_plan.policy
        active = policy.active_testing
        family_filter = set(narrowed_families)

        def enabled(family: str) -> bool:
            return self._family_enabled(execution_plan, family) and (
                not family_filter or family in family_filter
            )

        passive_nuclei = enabled("nuclei_passive")
        xss = active and enabled("xss")
        sqli = active and enabled("sqli")
        active_nuclei = active and enabled("nuclei_active")
        bola = active and enabled("bola")
        sensitive_exposure = active and enabled("sensitive_exposure")
        nosqli = active and enabled("nosqli")
        template_actions_expected = (
            (scope in {"full", "endpoint"} and passive_nuclei and not defer_manifest_actions)
            or (scope in {"full", "endpoint"} and active_nuclei and not defer_manifest_actions)
        )
        if template_actions_expected and (
            not template_ref
            or int(template_ref.get("entry_count") or 0)
            < len(CANONICAL_PASSIVE_NUCLEI_TEMPLATES)
            or template_ref.get("status") != "complete"
        ):
            raise ScanActionPlanError(
                "Nuclei actions require an immutable template manifest with the complete passive pack"
            )
        explicitly_requested = set(
            execution_plan.resolved_families or policy.include_families
        )
        needs_candidates = xss or sqli or active_nuclei or passive_nuclei
        lane_refs = {str(item.get("lane") or ""): item for item in credentials}

        blueprints: list[_ActionBlueprint] = []

        def add(
            action_id: str,
            stage: str,
            capability_name: str,
            capability_args: Mapping[str, Any],
            *,
            dependencies: Sequence[str] = (),
            required: bool = False,
            supporting: bool = False,
        ) -> None:
            blueprints.append(_ActionBlueprint(
                action_id=action_id,
                stage=stage,
                capability_name=capability_name,
                capability_args=capability_args,
                dependencies=tuple(dependencies),
                required=required,
                supporting=supporting,
            ))

        for lane in ("primary", "secondary", "service", "ssh"):
            reference = lane_refs.get(lane)
            if (
                scope != "discovery"
                and reference is not None
                and lane in {"primary", "secondary"}
                and str(reference.get("auth_kind") or "") in {
                    "form_login", "oauth_client_credentials", "oauth_password",
                }
            ):
                add(
                    f"inputs.auth_{lane}",
                    "resolve_inputs",
                    "auth.session.establish",
                    {"lane": lane, "credential_profile_ref": reference},
                    required=True,
                    supporting=True,
                )

        auth_dependencies = tuple(
            row.action_id for row in blueprints if row.capability_name == "auth.session.establish"
        )
        primary_dependency = (
            ("inputs.auth_primary",)
            if any(row.action_id == "inputs.auth_primary" for row in blueprints)
            else ()
        )
        if scope in {"full", "global"}:
            add(
                "baseline.http",
                "deterministic_baseline",
                "http.request",
                {"method": "GET", "path": "/", "follow_redirects": False, "principal": "primary" if primary_dependency else None},
                dependencies=primary_dependency,
                required=True,
            )
            add(
                "baseline.http_redirect",
                "deterministic_baseline",
                "http.request",
                {"method": "GET", "path": "/", "scheme": "http", "follow_redirects": True, "max_redirects": 1},
                dependencies=("baseline.http",),
            )
            add(
                "baseline.security_txt",
                "deterministic_baseline",
                "http.request",
                {"method": "GET", "path": "/.well-known/security.txt", "follow_redirects": False},
                dependencies=("baseline.http",),
            )
            if target_binding.canonical_host:
                add(
                    "baseline.dns",
                    "deterministic_baseline",
                    "dns.inspect",
                    {"canonical_host": target_binding.canonical_host},
                )
            https_origin_count = sum(
                1 for origin in target_binding.allowed_origins
                if origin.startswith("https://")
            )
            if https_origin_count:
                if (
                    https_origin_count > 64
                    or not target_binding.allowed_addresses
                    or len(target_binding.allowed_addresses) > 64
                ):
                    raise ScanActionPlanError(
                        "TLS target matrix exceeds the canonical bounded profile"
                    )
                add(
                    "baseline.tls",
                    "deterministic_baseline",
                    "tls.inspect",
                    {
                        "origins_ref": "frozen_https_origins",
                        "origin_count": https_origin_count,
                        "addresses_ref": "frozen_addresses",
                        "address_count": len(target_binding.allowed_addresses),
                    },
                    required=True,
                )
        if scope in {"full", "discovery"}:
            add(
                "discover.web_probe",
                "discover_surface",
                "web.probe",
                {"target_ref": "canonical_origin", "endpoint_manifest_ref": endpoint_ref or None},
                dependencies=primary_dependency,
                required=True,
                supporting=needs_candidates,
            )

        crawl_required = bool(explicitly_requested) and needs_candidates and not endpoint_ref and not candidate_ref
        if (
            scope in {"full", "discovery"}
            and (self._family_enabled(execution_plan, "recon") or needs_candidates)
        ):
            add(
                "discover.web_crawl",
                "discover_surface",
                "web.crawl",
                {"endpoint_manifest_ref": endpoint_ref or None, "read_only": True},
                dependencies=("discover.web_probe",),
                required=crawl_required,
                supporting=needs_candidates,
            )
            if self._family_enabled(execution_plan, "recon"):
                add(
                    "discover.web_content",
                    "discover_surface",
                    "web.content_discover",
                    {"target_manifest_ref": endpoint_ref or None},
                    dependencies=("discover.web_probe",),
                )
        if scope in {"full", "discovery"} and policy.subdomain_discovery:
            add(
                "discover.subdomains",
                "discover_surface",
                "subdomains.discover",
                {"root_domains": list(target_binding.allowed_root_domains)},
                required=True,
                supporting=True,
            )
        if scope in {"full", "discovery"} and policy.network_discovery:
            add(
                "discover.ports",
                "discover_network",
                "ports.discover",
                {"address_ref": "frozen_target_addresses"},
                required=True,
                supporting=True,
            )
            add(
                "discover.services",
                "discover_network",
                "service.fingerprint",
                {"open_port_manifest_ref": "discover.ports"},
                dependencies=("discover.ports",),
                required=True,
                supporting=True,
            )
        replay_inputs_required = scope in {"full", "endpoint"}
        if (
            scope == "endpoint"
            and bool(request_candidate_ref)
            and policy.allow_state_changing_http
            and (xss or sqli)
            and not collections
        ):
            raise ScanActionPlanError(
                "request verification requires immutable collection replay inputs"
            )
        for index, reference in enumerate(
            collections if replay_inputs_required else ()
        ):
            capability_name = (
                "collections.replay_active"
                if reference.get("active") is True and policy.allow_state_changing_http
                else "collections.replay_authentication"
                if reference.get("replay_policy") == "safe_authentication"
                else "collections.replay_safe"
            )
            add(
                f"inputs.collection_{index:02d}",
                "discover_surface",
                capability_name,
                {
                    "request_collection_ref": reference,
                    "request_manifest_ref": request_refs[
                        str(reference["selection_digest"])
                    ],
                },
                dependencies=primary_dependency,
                required=True,
                supporting=True,
            )

        discovery_dependencies = tuple(
            row.action_id for row in blueprints
            if row.stage == "discover_surface" and row.capability_name != "subdomains.discover"
        )
        candidate_dependencies = (
            ()
            if candidate_ref or (scope == "endpoint" and endpoint_ref)
            else tuple(
                item for item in ("discover.web_probe", "discover.web_crawl")
                if any(row.action_id == item for row in blueprints)
            )
        )
        active_dependencies = tuple(dict.fromkeys((
            *primary_dependency, *candidate_dependencies,
        )))

        def blueprint_budget(blueprint: _ActionBlueprint) -> Mapping[str, int]:
            override = dict(action_budgets or {}).get(blueprint.action_id)
            if override is not None:
                return override
            if blueprint.capability_name in _BATCH_CAPABILITIES:
                profile = _BATCH_PROFILES.get(
                    execution_plan.budget_profile, _BATCH_PROFILES["balanced"],
                )
                batch_size, maximum = profile[blueprint.capability_name]
                raw_slice = blueprint.capability_args.get("slice")
                slice_count = (
                    int(raw_slice.get("count") or 0)
                    if isinstance(raw_slice, Mapping) else batch_size
                )
                wall_floor = {
                    "templates.passive_batch": 10,
                    "templates.active_batch": 30,
                    "xss.verify_batch": 10,
                    "sqli.verify_batch": 20,
                    "xss.request_verify_batch": 10,
                    "sqli.request_verify_batch": 10,
                    "sqli.prove_batch": 20,
                    "xss.browser_prove_batch": 50,
                    "exposure.verify_batch": 15,
                    "nosqli.verify_batch": 20,
                }[blueprint.capability_name]
                budget = {
                    name: max(
                        wall_floor if name == "tool_wall_seconds" else 1,
                        (int(amount) * slice_count + batch_size - 1) // batch_size,
                    )
                    for name, amount in maximum.items()
                }
                if (
                    blueprint.capability_name in {
                        "xss.request_verify_batch", "sqli.request_verify_batch",
                        "sqli.prove_batch", "nosqli.verify_batch",
                    }
                    and not policy.allow_state_changing_http
                ):
                    budget.pop("state_changing_requests", None)
                if (
                    blueprint.capability_name in {"sqli.prove_batch", "nosqli.verify_batch"}
                    and "candidate_manifest_ref" in blueprint.capability_args
                ):
                    budget.pop("state_changing_requests", None)
                return budget
            specification = self._registry.require(blueprint.capability_name)
            requested = dict(specification.budget_cost)
            if (
                blueprint.capability_name == "http.request"
                and blueprint.action_id == "baseline.http_redirect"
            ):
                requested["http_requests"] = 1 + int(
                    blueprint.capability_args.get("max_redirects") or 0
                )
            if blueprint.capability_name in {
                "collections.replay_safe", "collections.replay_authentication",
                "collections.replay_active",
            }:
                reference = blueprint.capability_args.get("request_collection_ref")
                if isinstance(reference, Mapping):
                    request_limit = int(reference.get("max_requests") or 0)
                    requested = {
                        name: min(amount, request_limit)
                        if name in {"http_requests", "state_changing_requests"}
                        else amount
                        for name, amount in requested.items()
                    }
            if blueprint.capability_name == "tls.inspect":
                pair_count = (
                    int(blueprint.capability_args.get("origin_count") or 0)
                    * int(blueprint.capability_args.get("address_count") or 0)
                )
                requested = {
                    "tcp_ports_attempted": 4 * pair_count,
                    "tool_wall_seconds": 15 * pair_count,
                }
            return requested

        def add_manifest_breadth(
            base_action_id: str,
            stage: str,
            capability_name: str,
            capability_args: Mapping[str, Any],
            *,
            manifest_ref: Mapping[str, Any],
            index_name: str,
            dependencies: Sequence[str],
            required: bool,
            reserve_dependency_slots: int = 0,
            minimum_count: int = 0,
        ) -> None:
            """Compile every exact manifest item affordable by the Scan ceiling."""
            if not manifest_ref:
                add(
                    base_action_id,
                    stage,
                    capability_name,
                    capability_args,
                    dependencies=dependencies,
                    required=required,
                )
                return
            entry_count = int(manifest_ref.get("entry_count") or 0)
            if entry_count < 1:
                if required:
                    add(
                        base_action_id,
                        stage,
                        capability_name,
                        {**dict(capability_args), index_name: 0},
                        dependencies=dependencies,
                        required=True,
                    )
                return
            specification = self._registry.require(capability_name)
            per_item_budget = (
                minimum_reservation_scaled_profile(capability_name)
                or dict(specification.budget_cost)
            )
            limits = execution_plan.budget.ledger_limits()
            reserved = {name: 0 for name in limits}
            finalizer_budget = dict(action_budgets or {}).get(
                "finalize.report",
                self._registry.require("scan.finalize").budget_cost,
            )
            for name, amount in finalizer_budget.items():
                reserved[name] = reserved.get(name, 0) + amount
            for blueprint in blueprints:
                if not (
                    blueprint.required
                    or blueprint.action_id in {
                        "baseline.http", "baseline.tls", "discover.web_probe",
                    }
                ):
                    continue
                for name, amount in blueprint_budget(blueprint).items():
                    reserved[name] = reserved.get(name, 0) + amount
            affordable = entry_count
            for name, amount in per_item_budget.items():
                if amount > 0:
                    available = max(0, limits.get(name, 0) - reserved.get(name, 0))
                    affordable = min(affordable, available // amount)
            # Preserve an explicit family request as a required admission check
            # even when its first fixed-profile action cannot fit.
            count = max(1 if required else 0, int(minimum_count), affordable)
            available_dependencies = (
                _MAX_DEPENDENCIES - len(blueprints) - reserve_dependency_slots
            )
            count = min(entry_count, count, max(0, available_dependencies))
            if required and count < 1:
                raise ScanActionPlanError(
                    f"required manifest action {base_action_id} exceeds plan graph capacity"
                )
            for index in range(count):
                action_id = (
                    base_action_id
                    if index == 0
                    else f"{base_action_id}.{index:05d}"
                )
                add(
                    action_id,
                    stage,
                    capability_name,
                    {**dict(capability_args), index_name: index},
                    dependencies=dependencies,
                    # An explicitly resolved family requires its published
                    # minimum quota; remaining ranked entries are optional.
                    required=required and index < max(1, int(minimum_count)),
                )

        def has_manifest_work(
            enabled: bool, reference: Mapping[str, Any],
        ) -> bool:
            return enabled and (
                not reference or int(reference.get("entry_count") or 0) > 0
            )

        def add_manifest_batches(
            base_action_id: str,
            stage: str,
            capability_name: str,
            capability_args: Mapping[str, Any],
            *,
            manifest_ref: Mapping[str, Any],
            dependencies: Sequence[str],
            required: bool,
            minimum_batches: int = 1,
            reserve_dependency_slots: int = 0,
        ) -> None:
            """Compile bounded ranked slices instead of one process per candidate."""
            profile = _BATCH_PROFILES.get(
                execution_plan.budget_profile, _BATCH_PROFILES["balanced"],
            )
            batch_size, batch_budget = profile[capability_name]
            entry_count = int(manifest_ref.get("entry_count") or 0) if manifest_ref else 0
            total_batches = max(
                1,
                (entry_count + batch_size - 1) // batch_size if entry_count else 0,
            )
            limits = execution_plan.budget.ledger_limits()
            reserved = {name: 0 for name in limits}
            finalizer_budget = dict(action_budgets or {}).get(
                "finalize.report",
                self._registry.require("scan.finalize").budget_cost,
            )
            for name, amount in finalizer_budget.items():
                reserved[name] = reserved.get(name, 0) + amount
            for blueprint in blueprints:
                if not blueprint.required:
                    continue
                for name, amount in blueprint_budget(blueprint).items():
                    reserved[name] = reserved.get(name, 0) + amount
            affordable = total_batches
            for name, amount in batch_budget.items():
                if amount > 0:
                    available_amount = max(
                        0, limits.get(name, 0) - reserved.get(name, 0),
                    )
                    affordable = min(affordable, available_amount // amount)
            count = max(1, minimum_batches if required else 0, affordable)
            count = min(
                total_batches,
                count,
                32,
                max(0, _MAX_DEPENDENCIES - len(blueprints) - reserve_dependency_slots),
            )
            if required and count < minimum_batches:
                raise ScanActionPlanError(
                    f"required batch action {base_action_id} exceeds plan graph capacity"
                )
            for batch_index in range(count):
                start = batch_index * batch_size
                slice_count = (
                    min(batch_size, max(0, entry_count - start))
                    if entry_count else 1
                )
                add(
                    base_action_id if batch_index == 0 else f"{base_action_id}.{batch_index:03d}",
                    stage,
                    capability_name,
                    {
                        **dict(capability_args),
                        "slice": {"start": start, "count": slice_count},
                        "profile": f"{execution_plan.budget_profile}_batch_v1",
                        "proof_policy": (
                            "deterministic_differential_required"
                            if capability_name == "sqli.verify_batch"
                            else "deterministic_proof_contract_required"
                        ),
                    },
                    dependencies=dependencies,
                    required=required and batch_index < minimum_batches,
                )

        authz_will_run = (
            scope in {"full", "endpoint"}
            and bola
            and {"primary", "secondary"} <= set(lane_refs)
        )
        if scope in {"full", "endpoint"} and passive_nuclei and not defer_manifest_actions:
            add_manifest_batches(
                "passive.templates",
                "deterministic_baseline",
                "templates.passive_batch",
                {
                    "target_ref": "canonical_origin",
                    **(
                        {"target_manifest_ref": endpoint_ref}
                        if endpoint_ref else {}
                    ),
                    "template_manifest_ref": template_ref,
                },
                manifest_ref=endpoint_ref,
                # The reviewed GET-only pack is executable against the frozen
                # canonical origin. Optional crawl/content breadth must not be
                # able to block this required passive baseline.
                dependencies=primary_dependency,
                required=True,
                reserve_dependency_slots=(
                    int(active_nuclei and not defer_manifest_actions)
                    + int(has_manifest_work(xss, candidate_ref))
                    + int(has_manifest_work(sqli, candidate_ref))
                    + int(authz_will_run)
                ),
            )
        if scope in {"full", "endpoint"} and active_nuclei and not defer_manifest_actions:
            add_manifest_batches(
                "active.templates",
                "deterministic_active",
                "templates.active_batch",
                {
                    "target_manifest_ref": endpoint_ref or "discover.web_crawl",
                    "template_manifest_ref": template_ref or None,
                },
                manifest_ref=endpoint_ref,
                dependencies=active_dependencies,
                required="nuclei_active" in explicitly_requested,
                reserve_dependency_slots=(
                    int(has_manifest_work(xss, candidate_ref))
                    + int(has_manifest_work(sqli, candidate_ref))
                    + int(authz_will_run)
                ),
            )
        if scope in {"full", "endpoint"} and xss and not defer_manifest_actions:
            xss_verify_start = len(blueprints)
            add_manifest_batches(
                "verify.xss",
                "verify_candidates",
                "xss.verify_batch",
                {
                    "candidate_manifest_ref": candidate_ref or "discover.web_crawl",
                    "endpoint_manifest_ref": endpoint_ref or None,
                },
                manifest_ref=candidate_ref,
                dependencies=active_dependencies,
                required="xss" in explicitly_requested,
                minimum_batches=(
                    2 if execution_plan.budget_profile == "thorough" else 1
                ),
                reserve_dependency_slots=(
                    int(has_manifest_work(sqli, candidate_ref))
                    + int(authz_will_run) + 1
                ),
            )
            xss_verify_dependencies = tuple(
                row.action_id for row in blueprints[xss_verify_start:]
                if row.capability_name == "xss.verify_batch"
            )
            if xss_verify_dependencies:
                add_manifest_batches(
                    "prove.xss",
                    "prove_candidates",
                    "xss.browser_prove_batch",
                    {
                        "candidate_manifest_ref": candidate_ref or "discover.web_crawl",
                        "endpoint_manifest_ref": endpoint_ref or None,
                    },
                    manifest_ref=candidate_ref,
                    dependencies=xss_verify_dependencies,
                    # Browser proof consumes ``browser_actions``, a backbone-only
                    # budget: parallel endpoint shards structurally carry none, so a
                    # strictly-required browser proof would make every sharded active
                    # XSS scan un-plannable. It stays a best-effort escalation that
                    # still compiles and runs whenever browser budget exists (always
                    # in the single-worker authoritative path), and degrades to a
                    # coverage gap in a shard that cannot fund a browser.
                    required=False,
                    minimum_batches=1,
                    reserve_dependency_slots=(
                        int(has_manifest_work(sqli, candidate_ref))
                        + int(authz_will_run)
                    ),
                )
        if scope in {"full", "endpoint"} and sqli and not defer_manifest_actions:
            sqli_verify_start = len(blueprints)
            add_manifest_batches(
                "verify.sqli",
                "verify_candidates",
                "sqli.verify_batch",
                {
                    "candidate_manifest_ref": candidate_ref or "discover.web_crawl",
                    "endpoint_manifest_ref": endpoint_ref or None,
                },
                manifest_ref=candidate_ref,
                dependencies=active_dependencies,
                required="sqli" in explicitly_requested,
                minimum_batches=(
                    2 if execution_plan.budget_profile == "thorough" else 1
                ),
                reserve_dependency_slots=int(authz_will_run) + 1,
            )
            sqli_verify_dependencies = tuple(
                row.action_id for row in blueprints[sqli_verify_start:]
                if row.capability_name == "sqli.verify_batch"
            )
            if sqli_verify_dependencies:
                add_manifest_batches(
                    "prove.sqli",
                    "prove_candidates",
                    "sqli.prove_batch",
                    {
                        "candidate_manifest_ref": candidate_ref or "discover.web_crawl",
                        "endpoint_manifest_ref": endpoint_ref or None,
                    },
                    manifest_ref=candidate_ref,
                    dependencies=sqli_verify_dependencies,
                    required="sqli" in explicitly_requested,
                    minimum_batches=1,
                    reserve_dependency_slots=int(authz_will_run),
                )
        if (
            scope in {"full", "endpoint"}
            and sensitive_exposure
            and not defer_manifest_actions
        ):
            add_manifest_batches(
                "verify.exposure",
                "verify_candidates",
                "exposure.verify_batch",
                {"endpoint_manifest_ref": endpoint_ref or None},
                manifest_ref=endpoint_ref,
                dependencies=active_dependencies,
                required="sensitive_exposure" in explicitly_requested,
                minimum_batches=1,
                reserve_dependency_slots=int(authz_will_run),
            )
        if scope in {"full", "endpoint"} and nosqli and not defer_manifest_actions:
            add_manifest_batches(
                "verify.nosqli",
                "verify_candidates",
                "nosqli.verify_batch",
                {
                    "candidate_manifest_ref": candidate_ref or "discover.web_crawl",
                    "endpoint_manifest_ref": endpoint_ref or None,
                },
                manifest_ref=candidate_ref,
                dependencies=active_dependencies,
                required="nosqli" in explicitly_requested,
                minimum_batches=1,
                reserve_dependency_slots=int(authz_will_run),
            )
        private_request_dependencies = tuple(
            row.action_id for row in blueprints
            if row.action_id.startswith("inputs.collection_")
        )
        if (
            scope in {"full", "endpoint"}
            and policy.active_testing
            and not defer_manifest_actions
            and request_candidate_ref
        ):
            if xss:
                add_manifest_batches(
                    "verify.request_xss",
                    "verify_candidates",
                    "xss.request_verify_batch",
                    {"request_candidate_manifest_ref": request_candidate_ref},
                    manifest_ref=request_candidate_ref,
                    dependencies=tuple(dict.fromkeys((
                        *primary_dependency, *private_request_dependencies,
                    ))),
                    required=False,
                    reserve_dependency_slots=int(sqli),
                )
            if sqli:
                request_sqli_start = len(blueprints)
                add_manifest_batches(
                    "verify.request_sqli",
                    "verify_candidates",
                    "sqli.request_verify_batch",
                    {"request_candidate_manifest_ref": request_candidate_ref},
                    manifest_ref=request_candidate_ref,
                    dependencies=tuple(dict.fromkeys((
                        *primary_dependency, *private_request_dependencies,
                    ))),
                    required=False,
                    reserve_dependency_slots=1,
                )
                request_sqli_dependencies = tuple(
                    row.action_id for row in blueprints[request_sqli_start:]
                    if row.capability_name == "sqli.request_verify_batch"
                )
                if request_sqli_dependencies:
                    add_manifest_batches(
                        "prove.request_sqli",
                        "prove_candidates",
                        "sqli.prove_batch",
                        {"request_candidate_manifest_ref": request_candidate_ref},
                        manifest_ref=request_candidate_ref,
                        dependencies=tuple(dict.fromkeys((
                            *private_request_dependencies,
                            *request_sqli_dependencies,
                        ))),
                        required=False,
                    )
            if nosqli:
                add_manifest_batches(
                    "verify.request_nosqli",
                    "verify_candidates",
                    "nosqli.verify_batch",
                    {"request_candidate_manifest_ref": request_candidate_ref},
                    manifest_ref=request_candidate_ref,
                    dependencies=tuple(dict.fromkeys((
                        *primary_dependency, *private_request_dependencies,
                    ))),
                    required=False,
                )
        if authz_will_run and not defer_manifest_actions:
            add(
                "verify.authz",
                "verify_candidates",
                "authz.verify",
                {"principal_lanes": ["primary", "secondary"], "endpoint_manifest_ref": endpoint_ref or None},
                dependencies=tuple(dict.fromkeys((
                    *auth_dependencies,
                    *(() if endpoint_ref else discovery_dependencies),
                ))),
                required="bola" in explicitly_requested,
            )

        if include_finalizer:
            add(
                "finalize.report",
                "finalize_evidence",
                "scan.finalize",
                {"report_only": True},
                dependencies=tuple(row.action_id for row in blueprints),
                required=True,
            )

        stage_order = {
            name: index for index, name in enumerate((
                "bind_target", "resolve_inputs", "discover_surface", "discover_network",
                "deterministic_baseline", "deterministic_active", "verify_candidates",
                "prove_candidates", "finalize_evidence",
            ))
        }
        blueprints.sort(key=lambda row: stage_order[row.stage])

        override_budgets = dict(action_budgets or {})
        known_action_ids = {row.action_id for row in blueprints}
        unknown_allocations = set(override_budgets) - known_action_ids
        if unknown_allocations:
            raise ScanActionPlanError(
                "action budget allocation contains unknown actions: "
                + ", ".join(sorted(unknown_allocations))
            )
        global_bindings = {
            "execution_plan_digest": execution_plan.digest,
            "target_binding_digest": target_binding.digest,
            "credential_profile_refs": list(credentials),
            "request_collection_refs": list(collections),
            "request_manifest_refs": request_refs,
            "endpoint_manifest_ref": endpoint_ref,
            "candidate_manifest_ref": candidate_ref,
            "request_candidate_manifest_ref": request_candidate_ref,
            "template_manifest_ref": template_ref,
            "authority_refs": authority,
            "shard_authority": shard,
            "action_scope": scope,
            "defer_manifest_actions": defer_manifest_actions,
            "include_finalizer": include_finalizer,
        }
        actions: list[ScanAction] = []
        for ordinal, blueprint in enumerate(blueprints):
            try:
                specification = self._registry.require(blueprint.capability_name)
            except KeyError as exc:
                raise ScanActionPlanError(
                    f"action capability is absent from the canonical registry: {blueprint.capability_name}"
                ) from exc
            if target_binding.target_kind not in specification.target_kinds:
                raise ScanActionPlanError(
                    f"{blueprint.capability_name} does not support target kind {target_binding.target_kind}"
                )
            if available is not None and blueprint.capability_name not in available:
                raise ScanActionPlacementError(
                    f"placement cannot execute capability {blueprint.capability_name}"
                )
            if (
                blueprint.capability_name in _BATCH_CAPABILITIES
                and "local" not in backends
            ):
                raise ScanActionPlacementError(
                    f"{blueprint.capability_name} requires the single-worker local adapter"
                )
            requested = blueprint_budget(blueprint)
            action_bindings = {
                **global_bindings,
                "action_id": blueprint.action_id,
                "capability_args": blueprint.capability_args,
            }
            placement = {
                "schema_version": "scan-action-placement/v1",
                "eligible_backends": list(
                    ("local",)
                    if blueprint.capability_name in _BATCH_CAPABILITIES
                    else backends
                ),
                "requirements": dict(specification.placement_requirements),
                "adapter_name": specification.adapter,
                "adapter_version": specification.adapter_version,
            }
            actions.append(ScanAction(
                action_id=blueprint.action_id,
                stage=blueprint.stage,
                ordinal=ordinal,
                capability_name=blueprint.capability_name,
                capability_args=blueprint.capability_args,
                target_binding_digest=target_binding.digest,
                input_binding_digest=digest_input_bindings(action_bindings),
                requested_budget=requested,
                placement=placement,
                dependencies=blueprint.dependencies,
                required=blueprint.required,
                supporting=blueprint.supporting,
                output_schema=specification.output_schema,
            ))
        return ScanActionPlan(
            scan_id=scan_id,
            execution_plan_digest=execution_plan.digest,
            target_binding_digest=target_binding.digest,
            actions=tuple(actions),
        )
