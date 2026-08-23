"""Immutable, content-addressed action graph for one canonical Scan."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping
import uuid

try:
    from runtime.budgets import BUDGET_DIMENSIONS
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.budgets import BUDGET_DIMENSIONS


SCAN_ACTION_PLAN_SCHEMA = "scan-action-plan/v1"
SCAN_ACTION_SCHEMA = "scan-action/v1"
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_SCHEMA_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+/-]{0,127}$")
_MAX_CANONICAL_BYTES = 512 * 1024
_MAX_ACTIONS = 512
_MAX_DEPENDENCIES = 64


class ScanActionPlanError(ValueError):
    """Action authority is malformed, ambiguous, or not content-addressed."""


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
        }

    def canonical_dict(self) -> dict[str, Any]:
        return {**self.digest_material(), "action_digest": self.action_digest}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScanAction":
        expected = {
            "schema_version", "action_id", "stage", "ordinal", "capability_name",
            "capability_args", "target_binding_digest", "input_binding_digest",
            "requested_budget", "placement", "dependencies", "required", "supporting",
            "output_schema", "action_digest",
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
