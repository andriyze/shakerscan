"""Mode-free queue contract for the canonical deterministic Scan runtime.

The public API may continue accepting legacy aliases during migration, but they are
translated before this boundary. A ``scan-job/v2`` payload contains one immutable Scan
plan, a frozen target binding, and opaque references to credentials/collections. It
never contains old mode selectors or secret material.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
from typing import Any, Iterable, Mapping, Sequence
from uuid import uuid4

try:
    from runtime.models import ScanBudget, ScanPolicy, TargetBinding
except ModuleNotFoundError:  # package import through api.scan
    from ..runtime.models import ScanBudget, ScanPolicy, TargetBinding

from .execution import (
    SCAN_ENGINE,
    SCAN_EXECUTION_SCHEMA,
    SCAN_GENERATION,
    ScanExecutionPlan,
)


SCAN_JOB_SCHEMA = "scan-job/v2"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_FAMILY_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,79}$")
_REPLAY_MODES = frozenset({"discovery_only", "safe_reads", "confirmed_active"})
_FORBIDDEN_JOB_KEYS = frozenset({
    # Superseded Scan-mode selectors.
    "scan_type", "execution_scan_type", "legacy_scan_type", "legacy_executor_alias",
    "quick", "standard", "deep", "full", "aggressive", "smart", "thorough", "active",
    # Secret-bearing execution material. Canonical jobs carry opaque references instead.
    "password", "passwd", "secret", "token", "authorization", "cookie", "cookies",
    "private_key", "client_secret", "api_key", "auth_header", "auth_cookies",
    "headers", "body", "raw_request", "command", "argv", "shell",
})
_PLAN_KEYS = frozenset({
    "schema_version", "generation", "engine", "budget_profile", "policy", "budget",
})
_POLICY_KEYS = frozenset({
    "active_testing", "allow_state_changing_http", "network_discovery",
    "subdomain_discovery", "include_families", "exclude_families",
    "scope_receipt_id", "approval_receipt_id",
})
_BUDGET_KEYS = frozenset({
    "max_duration_seconds", "max_http_requests", "max_endpoints", "max_browser_actions",
    "max_tcp_ports", "max_tool_wall_seconds", "max_workers",
})
_TARGET_KEYS = frozenset({
    "target_id", "target_kind", "canonical_host", "allowed_origins", "allowed_addresses",
    "allowed_root_domains", "environment", "scope_receipt_id",
})
_COLLECTION_KEYS = frozenset({
    "collection_id", "binding_id", "selection_id", "replay_mode", "max_requests",
})
_JOB_KEYS = frozenset({
    "schema_version", "job_id", "scan_id", "created_at", "target",
    "execution_plan", "execution_plan_digest", "request_collections",
    "credential_profile_ids", "endpoint_manifest_id",
})
_QUEUE_TRANSPORT_KEYS = frozenset({"placement", "_base_queue_name"})
_PLACEMENT_SCALAR_KEYS = frozenset({
    "region", "egress_group", "network", "scan_tier", "tier",
    "data_residency", "node_id", "node_scope",
})
_BUDGET_CEILINGS: Mapping[str, int] = {
    "max_duration_seconds": 172_800,
    "max_http_requests": 1_000_000,
    "max_endpoints": 100_000,
    "max_browser_actions": 20_000,
    "max_tcp_ports": 262_140,
    "max_tool_wall_seconds": 86_400,
    "max_workers": 128,
}


class CanonicalScanJobError(ValueError):
    """A queue payload cannot be admitted as an authoritative Scan V2 job."""


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], *, name: str) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if not missing and not unknown:
        return
    details: list[str] = []
    if missing:
        details.append("missing " + ", ".join(missing))
    if unknown:
        details.append("unknown " + ", ".join(unknown))
    raise CanonicalScanJobError(f"{name} fields are invalid: {'; '.join(details)}")


def _identifier(value: Any, *, name: str, required: bool = True) -> str | None:
    normalized = str(value or "").strip() or None
    if normalized is None:
        if required:
            raise CanonicalScanJobError(f"{name} is required")
        return None
    if not _ID_RE.fullmatch(normalized):
        raise CanonicalScanJobError(f"{name} is invalid")
    return normalized


def _utc_timestamp(value: Any) -> str:
    normalized = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CanonicalScanJobError("created_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise CanonicalScanJobError("created_at must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _reject_forbidden_keys(value: Any, *, path: str = "job") -> None:
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key or "").strip().lower()
            if key in _FORBIDDEN_JOB_KEYS:
                raise CanonicalScanJobError(f"{path}.{key} is forbidden in scan-job/v2")
            _reject_forbidden_keys(item, path=f"{path}.{key or '<empty>'}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_forbidden_keys(item, path=f"{path}[{index}]")


def _placement_payload(value: Any) -> dict[str, Any]:
    if value in (None, {}):
        return {}
    if not isinstance(value, Mapping):
        raise CanonicalScanJobError("queue placement must be an object")
    raw = dict(value)
    unknown = sorted(set(raw) - _PLACEMENT_SCALAR_KEYS - {"requires"})
    if unknown:
        raise CanonicalScanJobError(
            f"queue placement has unknown fields: {', '.join(unknown)}"
        )
    normalized: dict[str, Any] = {}
    for key in sorted(_PLACEMENT_SCALAR_KEYS):
        item = raw.get(key)
        if item is None:
            continue
        text = str(item).strip().lower()
        if text:
            normalized[key] = text[:128]
    requires = raw.get("requires")
    if isinstance(requires, str):
        requires = [requires]
    if requires is not None and not isinstance(requires, list):
        raise CanonicalScanJobError("queue placement requires must be an array")
    if isinstance(requires, list):
        clean = sorted({
            str(item).strip().lower()[:64]
            for item in requires if str(item).strip()
        })
        if clean:
            normalized["requires"] = clean[:32]
    if raw != normalized:
        raise CanonicalScanJobError("queue placement is not canonical")
    return normalized


def scan_job_queue_transport(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return routing metadata that cannot alter Scan authority."""
    unknown = sorted(set(value) - _JOB_KEYS - _QUEUE_TRANSPORT_KEYS)
    if unknown:
        raise CanonicalScanJobError(
            f"scan job queue fields are invalid: unknown {', '.join(unknown)}"
        )
    transport: dict[str, Any] = {}
    if "placement" in value:
        placement = _placement_payload(value.get("placement"))
        if not placement:
            raise CanonicalScanJobError("queue placement must not be empty")
        transport["placement"] = placement
    if "_base_queue_name" in value:
        base = _identifier(
            value.get("_base_queue_name"), name="_base_queue_name"
        )
        transport["_base_queue_name"] = base
    return transport


def _families(value: Any, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > 100:
        raise CanonicalScanJobError(f"{name} must be an array of at most 100 items")
    result: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise CanonicalScanJobError(f"{name} entries must be strings")
        item = raw.strip().lower()
        if item != raw or not _FAMILY_RE.fullmatch(item) or item in result:
            raise CanonicalScanJobError(f"{name} contains an invalid or duplicate family")
        result.append(item)
    return tuple(result)


def _optional_receipt(value: Any, *, name: str) -> str | None:
    return _identifier(value, name=name, required=False)


def _plan_from_payload(value: Any, supplied_digest: Any) -> ScanExecutionPlan:
    if not isinstance(value, Mapping):
        raise CanonicalScanJobError("execution_plan must be an object")
    raw = dict(value)
    _exact_keys(raw, _PLAN_KEYS, name="execution_plan")
    if raw["schema_version"] != SCAN_EXECUTION_SCHEMA:
        raise CanonicalScanJobError(f"execution_plan schema must be {SCAN_EXECUTION_SCHEMA}")
    if raw["generation"] != SCAN_GENERATION or raw["engine"] != SCAN_ENGINE:
        raise CanonicalScanJobError("execution_plan must use the canonical Scan V2 engine")

    policy_raw = raw["policy"]
    if not isinstance(policy_raw, Mapping):
        raise CanonicalScanJobError("execution_plan.policy must be an object")
    policy_raw = dict(policy_raw)
    _exact_keys(policy_raw, _POLICY_KEYS, name="execution_plan.policy")
    for name in (
        "active_testing", "allow_state_changing_http", "network_discovery",
        "subdomain_discovery",
    ):
        if not isinstance(policy_raw[name], bool):
            raise CanonicalScanJobError(f"execution_plan.policy.{name} must be a boolean")
    include = _families(policy_raw["include_families"], name="include_families")
    exclude = _families(policy_raw["exclude_families"], name="exclude_families")
    if set(include) & set(exclude):
        raise CanonicalScanJobError("include_families and exclude_families must not overlap")
    policy = ScanPolicy(
        active_testing=policy_raw["active_testing"],
        allow_state_changing_http=policy_raw["allow_state_changing_http"],
        network_discovery=policy_raw["network_discovery"],
        subdomain_discovery=policy_raw["subdomain_discovery"],
        include_families=include,
        exclude_families=exclude,
        scope_receipt_id=_optional_receipt(
            policy_raw["scope_receipt_id"], name="scope_receipt_id"
        ),
        approval_receipt_id=_optional_receipt(
            policy_raw["approval_receipt_id"], name="approval_receipt_id"
        ),
    )
    if policy.allow_state_changing_http and not (
        policy.active_testing and policy.approval_receipt_id
    ):
        raise CanonicalScanJobError(
            "state-changing HTTP requires active_testing and an approval receipt"
        )
    if policy.network_discovery and not (
        policy.active_testing and policy.approval_receipt_id
    ):
        raise CanonicalScanJobError(
            "network discovery requires active_testing and an approval receipt"
        )

    budget_raw = raw["budget"]
    if not isinstance(budget_raw, Mapping):
        raise CanonicalScanJobError("execution_plan.budget must be an object")
    budget_raw = dict(budget_raw)
    _exact_keys(budget_raw, _BUDGET_KEYS, name="execution_plan.budget")
    normalized_budget: dict[str, int] = {}
    for name, ceiling in _BUDGET_CEILINGS.items():
        amount = budget_raw[name]
        if isinstance(amount, bool) or not isinstance(amount, int) or not 1 <= amount <= ceiling:
            raise CanonicalScanJobError(f"execution_plan.budget.{name} is outside its ceiling")
        normalized_budget[name] = amount

    profile = str(raw["budget_profile"] or "").strip().lower()
    if profile not in {"fast", "balanced", "thorough"} or profile != raw["budget_profile"]:
        raise CanonicalScanJobError(
            "execution_plan.budget_profile must be fast, balanced, or thorough"
        )
    plan = ScanExecutionPlan(
        policy=policy,
        budget_profile=profile,
        budget=ScanBudget(**normalized_budget),
    )
    if raw != plan.canonical_dict():
        raise CanonicalScanJobError("execution_plan is not canonical")
    digest = str(supplied_digest or "").strip().lower()
    if digest != plan.digest:
        raise CanonicalScanJobError("execution_plan_digest does not match the plan")
    return plan


def _target_payload(target: TargetBinding) -> dict[str, Any]:
    return {
        "target_id": target.target_id,
        "target_kind": target.target_kind,
        "canonical_host": target.canonical_host,
        "allowed_origins": list(target.allowed_origins),
        "allowed_addresses": list(target.allowed_addresses),
        "allowed_root_domains": list(target.allowed_root_domains),
        "environment": target.environment,
        "scope_receipt_id": target.scope_receipt_id,
    }


def _target_from_payload(value: Any) -> TargetBinding:
    if not isinstance(value, Mapping):
        raise CanonicalScanJobError("target must be an object")
    raw = dict(value)
    _exact_keys(raw, _TARGET_KEYS, name="target")
    for name in ("allowed_origins", "allowed_addresses", "allowed_root_domains"):
        if not isinstance(raw[name], list) or len(raw[name]) > 256:
            raise CanonicalScanJobError(f"target.{name} must be a bounded array")
    try:
        target = TargetBinding(
            target_id=_identifier(raw["target_id"], name="target.target_id") or "",
            target_kind=str(raw["target_kind"] or ""),
            canonical_host=raw["canonical_host"],
            allowed_origins=tuple(raw["allowed_origins"]),
            allowed_addresses=tuple(raw["allowed_addresses"]),
            allowed_root_domains=tuple(raw["allowed_root_domains"]),
            environment=str(raw["environment"] or "unknown")[:80],
            scope_receipt_id=_optional_receipt(
                raw["scope_receipt_id"], name="target.scope_receipt_id"
            ),
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalScanJobError(f"target binding is invalid: {exc}") from exc
    if raw != _target_payload(target):
        raise CanonicalScanJobError("target binding is not canonical")
    return target


@dataclass(frozen=True)
class RequestCollectionJobRef:
    collection_id: str
    binding_id: str
    selection_id: str
    replay_mode: str = "safe_reads"
    max_requests: int = 500

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "collection_id", _identifier(self.collection_id, name="collection_id") or ""
        )
        object.__setattr__(
            self, "binding_id", _identifier(self.binding_id, name="binding_id") or ""
        )
        object.__setattr__(
            self, "selection_id", _identifier(self.selection_id, name="selection_id") or ""
        )
        mode = str(self.replay_mode or "").strip().lower()
        if mode not in _REPLAY_MODES:
            raise CanonicalScanJobError("replay_mode is invalid")
        object.__setattr__(self, "replay_mode", mode)
        if isinstance(self.max_requests, bool) or not 1 <= int(self.max_requests) <= 2_000:
            raise CanonicalScanJobError("max_requests must be between 1 and 2000")
        object.__setattr__(self, "max_requests", int(self.max_requests))

    def payload(self) -> dict[str, Any]:
        return {
            "collection_id": self.collection_id,
            "binding_id": self.binding_id,
            "selection_id": self.selection_id,
            "replay_mode": self.replay_mode,
            "max_requests": self.max_requests,
        }

    @classmethod
    def from_payload(cls, value: Any) -> "RequestCollectionJobRef":
        if not isinstance(value, Mapping):
            raise CanonicalScanJobError("request collection reference must be an object")
        raw = dict(value)
        _exact_keys(raw, _COLLECTION_KEYS, name="request collection reference")
        return cls(**raw)


def admitted_request_collection_job_refs(
    refs: Sequence[Mapping[str, Any]],
) -> tuple[RequestCollectionJobRef, ...]:
    """Reduce admitted collection metadata to opaque durable queue references.

    A collection attached only by its collection identity has no durable selection
    identity yet and remains discovery input in the persisted Scan options. Only a
    saved target-bound selection may authorize worker replay through the canonical
    queue contract.
    """
    result: list[RequestCollectionJobRef] = []
    for raw in refs:
        selection_id = str(raw.get("selection_id") or "").strip()
        replay_mode = str(raw.get("replay_policy") or "").strip().lower()
        if not selection_id or replay_mode not in _REPLAY_MODES:
            continue
        selector = raw.get("selector") if isinstance(raw.get("selector"), Mapping) else {}
        raw_limit = selector.get("max_requests", selector.get("limit", 500))
        try:
            max_requests = int(raw_limit)
        except (TypeError, ValueError) as exc:
            raise CanonicalScanJobError(
                "request collection selector max_requests is invalid"
            ) from exc
        result.append(RequestCollectionJobRef(
            collection_id=str(raw.get("collection_id") or ""),
            binding_id=str(raw.get("binding_id") or ""),
            selection_id=selection_id,
            replay_mode=replay_mode,
            max_requests=max_requests,
        ))
    return tuple(result)


def admitted_credential_profile_ids(
    refs: Sequence[Mapping[str, Any]],
) -> tuple[str, ...]:
    """Return only immutable generic profile identities for a Scan queue job."""
    return tuple(str(ref.get("profile_id") or "").strip() for ref in refs)


@dataclass(frozen=True)
class CanonicalScanJob:
    job_id: str
    scan_id: str
    target: TargetBinding
    execution_plan: ScanExecutionPlan
    request_collections: tuple[RequestCollectionJobRef, ...] = ()
    credential_profile_ids: tuple[str, ...] = ()
    endpoint_manifest_id: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    schema_version: str = SCAN_JOB_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != SCAN_JOB_SCHEMA:
            raise CanonicalScanJobError(f"schema_version must be {SCAN_JOB_SCHEMA}")
        object.__setattr__(self, "job_id", _identifier(self.job_id, name="job_id") or "")
        object.__setattr__(self, "scan_id", _identifier(self.scan_id, name="scan_id") or "")
        object.__setattr__(self, "created_at", _utc_timestamp(self.created_at))
        if len(self.request_collections) > 16:
            raise CanonicalScanJobError("at most 16 request collections may be bound to one job")
        refs = tuple(
            item if isinstance(item, RequestCollectionJobRef)
            else RequestCollectionJobRef.from_payload(item)
            for item in self.request_collections
        )
        seen = {(item.collection_id, item.binding_id, item.selection_id) for item in refs}
        if len(seen) != len(refs):
            raise CanonicalScanJobError("request collection references must be unique")
        if any(item.replay_mode == "confirmed_active" for item in refs):
            policy = self.execution_plan.policy
            if not (
                policy.active_testing
                and policy.allow_state_changing_http
                and policy.approval_receipt_id
            ):
                raise CanonicalScanJobError(
                    "confirmed_active collection replay requires active state-changing authority"
                )
        credentials = tuple(dict.fromkeys(
            _identifier(item, name="credential_profile_id") or ""
            for item in self.credential_profile_ids
        ))
        if len(credentials) > 16:
            raise CanonicalScanJobError("at most 16 credential profiles may be bound to one job")
        endpoint_manifest_id = _identifier(
            self.endpoint_manifest_id, name="endpoint_manifest_id", required=False
        )
        if (
            self.target.scope_receipt_id
            and self.execution_plan.policy.scope_receipt_id
            and self.target.scope_receipt_id != self.execution_plan.policy.scope_receipt_id
        ):
            raise CanonicalScanJobError("target and execution plan scope receipts do not match")
        object.__setattr__(self, "request_collections", refs)
        object.__setattr__(self, "credential_profile_ids", credentials)
        object.__setattr__(self, "endpoint_manifest_id", endpoint_manifest_id)

    @classmethod
    def create(
        cls,
        *,
        scan_id: str,
        target: TargetBinding,
        execution_plan: ScanExecutionPlan,
        job_id: str | None = None,
        request_collections: Iterable[RequestCollectionJobRef] = (),
        credential_profile_ids: Iterable[str] = (),
        endpoint_manifest_id: str | None = None,
        created_at: str | None = None,
    ) -> "CanonicalScanJob":
        return cls(
            job_id=job_id or str(uuid4()),
            scan_id=scan_id,
            target=target,
            execution_plan=execution_plan,
            request_collections=tuple(request_collections),
            credential_profile_ids=tuple(credential_profile_ids),
            endpoint_manifest_id=endpoint_manifest_id,
            created_at=created_at or datetime.now(timezone.utc).isoformat(),
        )

    def payload(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "job_id": self.job_id,
            "scan_id": self.scan_id,
            "created_at": self.created_at,
            "target": _target_payload(self.target),
            "execution_plan": self.execution_plan.canonical_dict(),
            "execution_plan_digest": self.execution_plan.digest,
            "request_collections": [item.payload() for item in self.request_collections],
            "credential_profile_ids": list(self.credential_profile_ids),
            "endpoint_manifest_id": self.endpoint_manifest_id,
        }
        _reject_forbidden_keys(payload)
        return payload

    def queue_payload(
        self, *, placement: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return the canonical job plus optional non-authority routing metadata."""
        payload = self.payload()
        normalized_placement = _placement_payload(placement)
        if normalized_placement:
            payload["placement"] = normalized_placement
        _reject_forbidden_keys(payload)
        return payload

    @classmethod
    def from_payload(cls, value: Any) -> "CanonicalScanJob":
        if not isinstance(value, Mapping):
            raise CanonicalScanJobError("scan job must be an object")
        raw = dict(value)
        _reject_forbidden_keys(raw)
        _exact_keys(raw, _JOB_KEYS, name="scan job")
        if raw["schema_version"] != SCAN_JOB_SCHEMA:
            raise CanonicalScanJobError(f"schema_version must be {SCAN_JOB_SCHEMA}")
        if not isinstance(raw["request_collections"], list):
            raise CanonicalScanJobError("request_collections must be an array")
        if not isinstance(raw["credential_profile_ids"], list):
            raise CanonicalScanJobError("credential_profile_ids must be an array")
        job = cls(
            schema_version=raw["schema_version"],
            job_id=raw["job_id"],
            scan_id=raw["scan_id"],
            created_at=raw["created_at"],
            target=_target_from_payload(raw["target"]),
            execution_plan=_plan_from_payload(
                raw["execution_plan"], raw["execution_plan_digest"]
            ),
            request_collections=tuple(
                RequestCollectionJobRef.from_payload(item)
                for item in raw["request_collections"]
            ),
            credential_profile_ids=tuple(raw["credential_profile_ids"]),
            endpoint_manifest_id=raw["endpoint_manifest_id"],
        )
        if raw != job.payload():
            raise CanonicalScanJobError("scan job payload is not canonical")
        return job

    @classmethod
    def from_queue_payload(cls, value: Any) -> "CanonicalScanJob":
        if not isinstance(value, Mapping):
            raise CanonicalScanJobError("scan job queue payload must be an object")
        raw = dict(value)
        _reject_forbidden_keys(raw)
        scan_job_queue_transport(raw)
        return cls.from_payload({key: raw[key] for key in _JOB_KEYS if key in raw})

    @property
    def payload_digest(self) -> str:
        import hashlib

        encoded = json.dumps(
            self.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
