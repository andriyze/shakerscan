"""Content-addressed compiler for canonical parallel Scan action partitions."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Sequence

try:
    from runtime.models import ScanBudget, TargetBinding
except ModuleNotFoundError:
    from ..runtime.models import ScanBudget, TargetBinding

try:
    from runtime.capability_registry import CAPABILITY_REGISTRY
except ImportError:  # package import in host-side tests
    from ..runtime.capability_registry import CAPABILITY_REGISTRY

from .action_plan import ScanActionPlan
from .continuation import ScanContinuationAllocation
from .execution import ScanExecutionPlan
from .jobs import ScanShardBudget


PARALLEL_ACTION_PARTITION_SCHEMA = "parallel-action-partition/v2"
PARALLEL_ACTION_PARTITION_RECORD_SCHEMA = "parallel-action-partition-record/v2"
PARALLEL_PARENT_PLAN_SCHEMA = "parallel-parent-action-plan/v1"
PARALLEL_ACTION_EXECUTION_MERGE_SCHEMA = "parallel-action-execution-merge/v1"
_LEGACY_PARALLEL_ACTION_PARTITION_RECORD_SCHEMA = (
    "parallel-action-partition-record/v1"
)
_VALID_STRATEGIES = frozenset({
    "auto", "scope", "family", "coverage", "coverage_family", "auth_split",
})
_LEDGER_TO_BUDGET = {
    "http_requests": "max_http_requests",
    "state_changing_requests": "max_state_changing_requests",
    "browser_actions": "max_browser_actions",
    "tcp_ports_attempted": "max_tcp_ports",
    "hosts_attempted": "max_hosts",
    "tool_wall_seconds": "max_tool_wall_seconds",
}


class ParallelActionPlanError(ValueError):
    """A parent plan cannot be partitioned without widening its authority."""


def _canonical_mapping(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    raw = dict(value or {})
    encoded = json.dumps(
        raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return MappingProxyType(json.loads(encoded))


@dataclass(frozen=True)
class ParallelPrincipalLane:
    """One explicit principal context; it contains opaque profile IDs only."""

    name: str
    credential_profile_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        name = str(self.name or "").strip().lower()
        if name not in {"anonymous", "primary", "secondary", "comparison", "service"}:
            raise ParallelActionPlanError("parallel principal lane is invalid")
        profiles = tuple(dict.fromkeys(
            str(item or "").strip() for item in self.credential_profile_ids
            if str(item or "").strip()
        ))
        if name == "anonymous" and profiles:
            raise ParallelActionPlanError(
                "anonymous parallel principal lane cannot carry credentials"
            )
        if name in {"primary", "secondary", "service"} and len(profiles) != 1:
            raise ParallelActionPlanError(
                f"{name} parallel principal lane requires exactly one profile"
            )
        if name == "comparison" and len(profiles) < 1:
            raise ParallelActionPlanError(
                "comparison parallel principal lane requires a profile"
            )
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "credential_profile_ids", profiles)

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "credential_profile_ids": list(self.credential_profile_ids),
        }


@dataclass(frozen=True)
class ParallelPlacementCapacity:
    """A routable execution lane and the number of concurrent slots it exposes."""

    name: str
    capacity: int
    routing: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        name = str(self.name or "").strip().lower()
        if not name or isinstance(self.capacity, bool) or int(self.capacity) < 1:
            raise ParallelActionPlanError("parallel placement capacity is invalid")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "capacity", int(self.capacity))
        object.__setattr__(self, "routing", _canonical_mapping(self.routing))

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "capacity": self.capacity,
            "routing": dict(self.routing),
        }


@dataclass(frozen=True)
class ParallelRequestWork:
    """A content-free saved-request selection bound to one principal lane."""

    selection_digest: str
    principal_lane: str = "comparison"

    def __post_init__(self) -> None:
        digest = str(self.selection_digest or "").strip().lower()
        lane = str(self.principal_lane or "").strip().lower()
        if (
            len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
            or lane not in {"anonymous", "primary", "secondary", "comparison", "service"}
        ):
            raise ParallelActionPlanError("parallel request work is invalid")
        object.__setattr__(self, "selection_digest", digest)
        object.__setattr__(self, "principal_lane", lane)

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "selection_digest": self.selection_digest,
            "principal_lane": self.principal_lane,
        }


@dataclass(frozen=True)
class ParallelPlannedChild:
    """Immutable scheduling result before a durable child Scan ID is minted."""

    index: int
    label: str
    role: str
    endpoints: tuple[str, ...]
    request_selection_digests: tuple[str, ...]
    candidate_manifest_refs: tuple[Mapping[str, Any], ...]
    principal_lane: ParallelPrincipalLane
    family_scope: tuple[str, ...]
    placement: ParallelPlacementCapacity
    # The compiled action scope for this child. The planner owns this decision so
    # the ownership set it derives cannot drift from what the worker compiles.
    # Empty resolves to the conservative default for the role: a global child
    # that is not told discovery ran elsewhere still owns ``discover.*``.
    action_scope: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or self.index < 0:
            raise ParallelActionPlanError("parallel planned child index is invalid")
        role = str(self.role or "").strip().lower()
        if role not in {"global", "endpoint"}:
            raise ParallelActionPlanError("parallel planned child role is invalid")
        scope = _resolve_child_action_scope(self.action_scope, role=role)
        endpoints = tuple(sorted({
            str(item).strip() for item in self.endpoints if str(item).strip()
        }))
        requests = tuple(sorted(set(self.request_selection_digests)))
        refs = tuple(
            _canonical_mapping(item) for item in sorted(
                (dict(item) for item in self.candidate_manifest_refs),
                key=lambda item: json.dumps(
                    item, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                ),
            )
        )
        families = tuple(sorted({
            str(item).strip().lower() for item in self.family_scope
            if str(item).strip()
        }))
        if role == "global" and (endpoints or requests or refs or families):
            raise ParallelActionPlanError(
                "global parallel child cannot own endpoint-scoped work"
            )
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "action_scope", scope)
        object.__setattr__(self, "endpoints", endpoints)
        object.__setattr__(self, "request_selection_digests", requests)
        object.__setattr__(self, "candidate_manifest_refs", refs)
        object.__setattr__(self, "family_scope", families)

    @property
    def work_weight(self) -> int:
        # Saved requests and evidence-backed candidates carry more expensive
        # active verification work than a plain endpoint. Parameterized URLs
        # are also more likely to produce mutation candidates. Weighting them
        # here divides the existing immutable parent ceiling; it never widens
        # traffic or time authority.
        endpoint_weight = sum(
            3 if "?" in endpoint else 1 for endpoint in self.endpoints
        )
        return max(
            1,
            endpoint_weight
            + (2 * len(self.request_selection_digests))
            + (4 * len(self.candidate_manifest_refs)),
        )

    def canonical_dict(self) -> dict[str, Any]:
        endpoint_ids = sorted(
            _work_item_id("endpoint", item) for item in self.endpoints
        )
        return {
            "index": self.index,
            "label": self.label,
            "role": self.role,
            "action_scope": self.action_scope,
            "endpoint_work_ids": endpoint_ids,
            "request_selection_digests": list(self.request_selection_digests),
            "candidate_manifest_refs": [dict(item) for item in self.candidate_manifest_refs],
            "principal_lane": self.principal_lane.canonical_dict(),
            "family_scope": list(self.family_scope),
            "placement": self.placement.canonical_dict(),
        }

    def compiler_spec(self, *, scan_id: str) -> dict[str, Any]:
        return {
            "scan_id": scan_id,
            "index": self.index,
            "label": self.label,
            "role": self.role,
            "action_scope": self.action_scope,
            "work_weight": self.work_weight,
            "principal_lane": self.principal_lane.name,
            "placement_name": self.placement.name,
            "family_scope": list(self.family_scope),
            "work_partition_digest": _digest({
                "endpoint_work_ids": sorted(
                    _work_item_id("endpoint", item) for item in self.endpoints
                ),
                "request_selection_digests": list(self.request_selection_digests),
                "candidate_manifest_refs": [
                    dict(item) for item in self.candidate_manifest_refs
                ],
                "principal_lane": self.principal_lane.canonical_dict(),
                "family_scope": list(self.family_scope),
            }),
        }


@dataclass(frozen=True)
class ParallelParentPlan:
    parent_scan_id: str
    parent_execution_plan_digest: str
    parent_action_plan_digest: str
    target_binding_digest: str
    scheduling_hint: str
    children: tuple[ParallelPlannedChild, ...]
    notes: tuple[str, ...] = ()
    schema_version: str = PARALLEL_PARENT_PLAN_SCHEMA

    def __post_init__(self) -> None:
        if [child.index for child in self.children] != list(range(len(self.children))):
            raise ParallelActionPlanError("parallel planned child indices must be contiguous")
        if sum(child.role == "global" for child in self.children) != 1:
            raise ParallelActionPlanError("parallel parent plan requires one global child")

    @property
    def is_parallel(self) -> bool:
        return len(self.children) >= 2

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "parent_scan_id": self.parent_scan_id,
            "parent_execution_plan_digest": self.parent_execution_plan_digest,
            "parent_action_plan_digest": self.parent_action_plan_digest,
            "target_binding_digest": self.target_binding_digest,
            "scheduling_hint": self.scheduling_hint,
            "children": [child.canonical_dict() for child in self.children],
            "notes": list(self.notes),
        }

    @property
    def plan_digest(self) -> str:
        return _digest(self.canonical_dict())


def _digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parallel_action_occurrence_id(scan_id: str, action_id: str) -> str:
    """Return a content-free identity for one child action occurrence."""
    owner = str(scan_id or "").strip()
    action = str(action_id or "").strip()
    if not owner or not action:
        raise ParallelActionPlanError(
            "parallel action occurrence requires scan and action identities"
        )
    return hashlib.sha256(f"{owner}:{action}".encode("utf-8")).hexdigest()


def _weighted_shares(
    total: int,
    weights: Sequence[int],
    *,
    minimum: int,
) -> tuple[int, ...]:
    count = len(weights)
    if count < 1:
        return ()
    if total < minimum * count:
        raise ParallelActionPlanError(
            f"parallel budget {total} cannot fund {count} child minimums of {minimum}"
        )
    remaining = total - (minimum * count)
    normalized = [max(1, int(item)) for item in weights]
    denominator = sum(normalized)
    result: list[int] = []
    assigned_weight = 0
    for weight in normalized:
        start = (remaining * assigned_weight) // denominator
        assigned_weight += weight
        end = (remaining * assigned_weight) // denominator
        result.append(minimum + end - start)
    return tuple(result)


def _entry_weight(options: Mapping[str, Any]) -> int:
    endpoints = options.get("custom_endpoints")
    if isinstance(endpoints, (list, tuple)):
        return max(1, len(endpoints))
    return 1


def _work_partition_digest(options: Mapping[str, Any]) -> str:
    endpoints = options.get("custom_endpoints")
    endpoint_hashes = [
        hashlib.sha256(str(item).encode("utf-8")).hexdigest()
        for item in endpoints or ()
        if isinstance(item, str) and item.strip()
    ] if isinstance(endpoints, (list, tuple)) else []
    request_refs = options.get("request_manifest_refs")
    request_digests = sorted(
        str(key).lower()
        for key in request_refs
        if isinstance(key, str)
    ) if isinstance(request_refs, Mapping) else []
    return _digest({
        "endpoint_hashes": endpoint_hashes,
        "request_selection_digests": request_digests,
        "auth_state": str(options.get("auth_state") or "anonymous"),
        "family": str(
            options.get("coverage_attempt_family")
            or "all"
        ).lower(),
    })


def _work_item_id(kind: str, value: Any) -> str:
    return _digest({"kind": kind, "value": value})


def build_parallel_work_assignment(
    *,
    endpoints: Sequence[Any] = (),
    request_entries: Sequence[Mapping[str, Any]] = (),
    work_manifest_refs: Sequence[Mapping[str, Any]] = (),
    allowed_family_scope: Sequence[str] = (),
    work_scope: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a content-free exact work binding for one parallel child."""
    attempt_scope = {
        str(key).strip(): str(value).strip().lower()
        for key, value in dict(work_scope or {}).items()
        if str(key).strip() and str(value).strip()
    }

    def scoped(value: Any) -> Any:
        if not attempt_scope:
            return value
        return {"attempt_scope": attempt_scope, "value": value}

    endpoint_work_ids = sorted({
        _work_item_id("endpoint", scoped(str(item).strip()))
        for item in endpoints
        if str(item).strip()
    })
    request_work_ids = sorted({
        _work_item_id("request", scoped({
            key: nested
            for key, nested in dict(item).items()
            if key != "selected_shard"
        }))
        for item in request_entries
        if isinstance(item, Mapping)
    })
    refs = [dict(item) for item in work_manifest_refs if isinstance(item, Mapping)]
    refs.sort(key=lambda item: json.dumps(
        item, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ))
    families = sorted({
        str(item).strip().lower()
        for item in allowed_family_scope
        if str(item).strip()
    })
    material = {
        "endpoint_work_ids": endpoint_work_ids,
        "request_work_ids": request_work_ids,
        "work_manifest_refs": refs,
        "allowed_family_scope": families,
    }
    return {**material, "work_partition_digest": _digest(material)}


def _canonical_work_assignment(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ParallelActionPlanError("parallel child work assignment is invalid")
    endpoint_ids = value.get("endpoint_work_ids")
    request_ids = value.get("request_work_ids")
    refs = value.get("work_manifest_refs")
    families = value.get("allowed_family_scope")
    if not all(isinstance(item, list) for item in (
        endpoint_ids, request_ids, refs, families,
    )):
        raise ParallelActionPlanError("parallel child work assignment fields are invalid")
    if (
        len(endpoint_ids) != len(set(endpoint_ids))
        or len(request_ids) != len(set(request_ids))
        or any(
            not isinstance(item, str)
            or len(item) != 64
            or any(char not in "0123456789abcdef" for char in item)
            for item in (*endpoint_ids, *request_ids)
        )
        or any(not isinstance(item, Mapping) for item in refs)
        or any(not isinstance(item, str) or not item for item in families)
    ):
        raise ParallelActionPlanError("parallel child work assignment content is invalid")
    material = {
        "endpoint_work_ids": sorted(endpoint_ids),
        "request_work_ids": sorted(request_ids),
        "work_manifest_refs": sorted(
            (dict(item) for item in refs),
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            ),
        ),
        "allowed_family_scope": sorted(set(families)),
    }
    if str(value.get("work_partition_digest") or "") != _digest(material):
        raise ParallelActionPlanError("parallel child work partition digest is invalid")
    return {**material, "work_partition_digest": _digest(material)}


def merge_parallel_work_assignments(
    assignments: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Freeze the exact union of already-scoped child work assignments."""
    canonical = tuple(_canonical_work_assignment(item) for item in assignments)
    refs_by_value: dict[str, dict[str, Any]] = {}
    for assignment in canonical:
        for reference in assignment["work_manifest_refs"]:
            encoded = json.dumps(
                reference, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            )
            refs_by_value[encoded] = dict(reference)
    material = {
        "endpoint_work_ids": sorted({
            work_id
            for assignment in canonical
            for work_id in assignment["endpoint_work_ids"]
        }),
        "request_work_ids": sorted({
            work_id
            for assignment in canonical
            for work_id in assignment["request_work_ids"]
        }),
        "work_manifest_refs": [
            refs_by_value[key] for key in sorted(refs_by_value)
        ],
        "allowed_family_scope": sorted({
            family
            for assignment in canonical
            for family in assignment["allowed_family_scope"]
        }),
    }
    return {**material, "work_partition_digest": _digest(material)}


def _projection_id(action_id: str) -> str:
    """Reduce an occurrence id to the logical action the parent authorised.

    Two suffixes are occurrence markers, not distinct authority: a five-digit
    per-endpoint occurrence and a three-digit batch index. Only the former was
    stripped, so a child that sliced its work into more batches than the parent
    happened to -- which is exactly what happens once a slice is sized to what
    its reservation funds -- produced ids like ``verify.xss.001`` that the parent
    had never projected, and the whole partition was rejected as introducing an
    action outside parent authority.
    """
    projected = action_id
    for width in (5, 3):
        head, dot, tail = projected.rpartition(".")
        if dot and len(tail) == width and tail.isdigit():
            projected = head
    return projected


def _capability_family(capability_name: str) -> str:
    if capability_name.startswith("xss."):
        return "xss"
    if capability_name.startswith("sqli."):
        return "sqli"
    if capability_name in {"templates.passive_scan", "templates.passive_batch"}:
        return "nuclei_passive"
    if capability_name in {"templates.scan", "templates.active_batch"}:
        return "nuclei_active"
    if capability_name.startswith("authz."):
        return "bola"
    if capability_name.startswith(("web.", "http.", "dns.", "tls.", "ports.", "service.", "subdomains.")):
        return "recon"
    if capability_name.startswith(("auth.", "collections.")):
        return "inputs"
    if capability_name == "scan.finalize":
        return "finalizer"
    return capability_name.split(".", 1)[0]


def parallel_capability_family_scope(
    capability_names: Sequence[str],
) -> tuple[str, ...]:
    return tuple(sorted({_capability_family(item) for item in capability_names}))


def _is_global_action(action_id: str) -> bool:
    return action_id.startswith(("baseline.", "discover."))


def _is_discovery_action(action_id: str) -> bool:
    return action_id.startswith("discover.")


CHILD_ACTION_SCOPES = frozenset({"full", "global", "endpoint"})


def _resolve_child_action_scope(value: Any, *, role: str) -> str:
    """Resolve the compiled action scope for one planned parallel child.

    ``global`` means the backbone runs baseline posture only because a placed
    discovery stage already owns ``discover.*``. ``full`` means no separate
    discovery stage ran, so the backbone must still perform discovery itself.
    An unset value resolves to the conservative option for the role: never drop
    discovery coverage unless the planner explicitly said it ran elsewhere.
    """
    scope = str(value or "").strip().lower()
    if not scope:
        scope = "full" if role == "global" else "endpoint"
    if scope not in CHILD_ACTION_SCOPES:
        raise ParallelActionPlanError("parallel child action scope is invalid")
    if role == "global" and scope not in {"full", "global"}:
        raise ParallelActionPlanError(
            "global parallel child requires a backbone action scope"
        )
    if role != "global" and scope != "endpoint":
        raise ParallelActionPlanError(
            "endpoint parallel child requires the endpoint action scope"
        )
    return scope


@dataclass(frozen=True)
class ParallelChildPartition:
    scan_id: str
    index: int
    label: str
    role: str
    budget: ScanShardBudget
    work_partition_digest: str
    principal_lane: str = "comparison"
    placement_name: str = "local"
    family_scope: tuple[str, ...] = ()
    action_scope: str = ""

    def __post_init__(self) -> None:
        if (
            len(self.work_partition_digest) != 64
            or any(
                char not in "0123456789abcdef"
                for char in self.work_partition_digest
            )
        ):
            raise ParallelActionPlanError(
                "parallel child work partition digest is invalid"
            )
        if self.role not in {"global", "endpoint"}:
            raise ParallelActionPlanError("parallel child role is invalid")
        object.__setattr__(self, "action_scope", _resolve_child_action_scope(
            self.action_scope, role=self.role,
        ))
        if not self.principal_lane or not self.placement_name:
            raise ParallelActionPlanError(
                "parallel child principal or placement lane is invalid"
            )

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "index": self.index,
            "label": self.label,
            "role": self.role,
            "action_scope": self.action_scope,
            "budget": self.budget.payload(),
            "work_partition_digest": self.work_partition_digest,
            "principal_lane": self.principal_lane,
            "placement_name": self.placement_name,
            "family_scope": list(self.family_scope),
        }


@dataclass(frozen=True)
class ParallelActionPartition:
    parent_scan_id: str
    parent_execution_plan_digest: str
    parent_action_plan_digest: str
    target_binding_digest: str
    strategy: str
    available_worker_count: int
    children: tuple[ParallelChildPartition, ...]
    parent_owned_action_ids: tuple[str, ...]
    globally_assigned_action_ids: tuple[str, ...]
    discovery_stage_action_ids: tuple[str, ...]
    assigned_parent_action_ids: tuple[str, ...]
    required_parent_action_ids: tuple[str, ...]
    allowed_parent_capabilities: tuple[str, ...]
    continuation_allocation_digest: str | None
    allowed_continuation_capabilities: tuple[str, ...]
    required_continuation_capabilities: tuple[str, ...]
    schema_version: str = PARALLEL_ACTION_PARTITION_SCHEMA

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "parent_scan_id": self.parent_scan_id,
            "parent_execution_plan_digest": self.parent_execution_plan_digest,
            "parent_action_plan_digest": self.parent_action_plan_digest,
            "target_binding_digest": self.target_binding_digest,
            "strategy": self.strategy,
            "available_worker_count": self.available_worker_count,
            "children": [item.canonical_dict() for item in self.children],
            "parent_owned_action_ids": list(self.parent_owned_action_ids),
            "globally_assigned_action_ids": list(self.globally_assigned_action_ids),
            "discovery_stage_action_ids": list(self.discovery_stage_action_ids),
            "assigned_parent_action_ids": list(self.assigned_parent_action_ids),
            "required_parent_action_ids": list(self.required_parent_action_ids),
            "allowed_parent_capabilities": list(self.allowed_parent_capabilities),
            "continuation_allocation_digest": self.continuation_allocation_digest,
            "allowed_continuation_capabilities": list(
                self.allowed_continuation_capabilities
            ),
            "required_continuation_capabilities": list(
                self.required_continuation_capabilities
            ),
        }

    @property
    def partition_digest(self) -> str:
        return _digest(self.canonical_dict())

    def record(
        self,
        child_action_plans: Mapping[str, ScanActionPlan],
        *,
        child_work_assignments: Mapping[str, Mapping[str, Any]] | None = None,
        parent_work_assignment: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        expected = {child.scan_id for child in self.children}
        if set(child_action_plans) != expected:
            raise ParallelActionPlanError(
                "child action plans do not exactly cover the parallel partition"
            )
        supplied_assignments = dict(child_work_assignments or {})
        if supplied_assignments and set(supplied_assignments) != expected:
            raise ParallelActionPlanError(
                "child work assignments do not exactly cover the parallel partition"
            )
        # Parent plans are not children. Use the immutable parent plan authority
        # captured by compile() below rather than accepting caller-supplied data.
        parent_projection_ids = set(self.assigned_parent_action_ids)
        required_parent_ids = set(self.required_parent_action_ids)
        parent_capabilities = set(self.allowed_parent_capabilities)
        continuation_capabilities = set(
            self.allowed_continuation_capabilities
        )
        required_continuation = set(
            self.required_continuation_capabilities
        )
        global_action_ids = set(self.globally_assigned_action_ids)
        parent_owned_ids = set(self.parent_owned_action_ids)
        child_records = []
        endpoint_owners: dict[str, str] = {}
        request_owners: dict[str, str] = {}
        assigned_projection_ids: set[str] = set()
        assigned_continuation_capabilities: set[str] = set()
        global_occurrences: dict[str, int] = {
            action_id: 0 for action_id in global_action_ids
        }
        for child in self.children:
            plan = child_action_plans[child.scan_id]
            if plan.scan_id != child.scan_id:
                raise ParallelActionPlanError(
                    "child action plan owner differs from its partition"
                )
            finalizers = [
                action for action in plan.actions
                if action.capability_name == "scan.finalize"
            ]
            if (
                len(finalizers) != 1
                or finalizers[0].action_id != "finalize.report"
                or plan.actions[-1] != finalizers[0]
            ):
                raise ParallelActionPlanError(
                    "parallel child must end with exactly one report finalizer"
                )
            if any(
                action.action_id in parent_owned_ids
                and action.capability_name != "scan.finalize"
                for action in plan.actions
            ):
                raise ParallelActionPlanError(
                    "parent-owned action cannot execute on a parallel child"
                )
            action_projection_ids = {
                _projection_id(action.action_id) for action in plan.actions
                if action.capability_name != "scan.finalize"
            }
            unauthorized_projection = {
                _projection_id(action.action_id)
                for action in plan.actions
                if (
                    action.capability_name != "scan.finalize"
                    and _projection_id(action.action_id)
                    not in parent_projection_ids
                    and action.capability_name not in continuation_capabilities
                )
            }
            if unauthorized_projection:
                raise ParallelActionPlanError(
                    "parallel child introduced an action outside parent authority"
                )
            if any(
                action.capability_name != "scan.finalize"
                and action.capability_name not in parent_capabilities
                and action.capability_name not in continuation_capabilities
                for action in plan.actions
            ):
                raise ParallelActionPlanError(
                    "parallel child introduced an unauthorized capability family"
                )
            child_global = {
                action.action_id for action in plan.actions
                if action.action_id in global_action_ids
            }
            if child.role == "global":
                if child_global != global_action_ids:
                    raise ParallelActionPlanError(
                        "global child does not exactly own the global action set"
                    )
            elif child_global:
                raise ParallelActionPlanError(
                    "endpoint child duplicates a global action"
                )
            for action_id in child_global:
                global_occurrences[action_id] += 1
            assigned_projection_ids.update(action_projection_ids)
            assigned_continuation_capabilities.update(
                action.capability_name
                for action in plan.actions
                if action.capability_name in continuation_capabilities
            )

            if supplied_assignments:
                assignment = _canonical_work_assignment(
                    supplied_assignments[child.scan_id]
                )
            else:
                assignment = build_parallel_work_assignment()
            for kind, owners, ids in (
                ("endpoint", endpoint_owners, assignment["endpoint_work_ids"]),
                ("request", request_owners, assignment["request_work_ids"]),
            ):
                for work_id in ids:
                    previous = owners.setdefault(work_id, child.scan_id)
                    if previous != child.scan_id:
                        raise ParallelActionPlanError(
                            f"duplicate {kind} work across parallel children"
                        )
            actual_families = sorted({
                _capability_family(action.capability_name)
                for action in plan.actions
                if action.capability_name != "scan.finalize"
            })
            declared_families = set(assignment["allowed_family_scope"])
            if declared_families and not set(actual_families) <= declared_families:
                raise ParallelActionPlanError(
                    "parallel child action family exceeds its allowed family scope"
                )
            effective_families = (
                assignment["allowed_family_scope"] or actual_families
            )
            assignment_material = {
                "endpoint_work_ids": assignment["endpoint_work_ids"],
                "request_work_ids": assignment["request_work_ids"],
                "work_manifest_refs": assignment["work_manifest_refs"],
                "allowed_family_scope": effective_families,
            }
            effective_work_digest = _digest(assignment_material)
            aggregate_input_digest = _digest({
                "work_partition_digest": effective_work_digest,
                "action_input_binding_digests": [
                    action.input_binding_digest for action in plan.actions
                ],
            })
            child_records.append({
                "scan_id": child.scan_id,
                "index": child.index,
                "role": child.role,
                "action_plan_digest": plan.plan_digest,
                "expected_action_ids": [
                    action.action_id for action in plan.actions
                ],
                "expected_global_action_ids": sorted(child_global),
                "work_manifest_refs": assignment["work_manifest_refs"],
                "work_partition_digest": effective_work_digest,
                "endpoint_work_ids": assignment["endpoint_work_ids"],
                "request_work_ids": assignment["request_work_ids"],
                "allowed_family_scope": effective_families,
                "input_binding_digest": aggregate_input_digest,
            })
        if any(count != 1 for count in global_occurrences.values()):
            raise ParallelActionPlanError(
                "global actions must occur exactly once across parallel children"
            )
        if not required_parent_ids <= assigned_projection_ids:
            raise ParallelActionPlanError(
                "parallel children left required parent work unassigned"
            )
        if not required_continuation <= assigned_continuation_capabilities:
            raise ParallelActionPlanError(
                "parallel children left required continuation work unassigned"
            )
        observed_parent_work = build_parallel_work_assignment(
            endpoints=(),
            request_entries=(),
        )
        observed_parent_work.update({
            "endpoint_work_ids": sorted(endpoint_owners),
            "request_work_ids": sorted(request_owners),
        })
        observed_material = {
            key: observed_parent_work[key]
            for key in (
                "endpoint_work_ids", "request_work_ids",
                "work_manifest_refs", "allowed_family_scope",
            )
        }
        observed_parent_work["work_partition_digest"] = _digest(observed_material)
        if parent_work_assignment is not None:
            expected_parent_work = _canonical_work_assignment(
                parent_work_assignment
            )
            if (
                expected_parent_work["endpoint_work_ids"]
                != observed_parent_work["endpoint_work_ids"]
                or expected_parent_work["request_work_ids"]
                != observed_parent_work["request_work_ids"]
            ):
                raise ParallelActionPlanError(
                    "parallel child work union differs from parent-assigned work"
                )
        else:
            expected_parent_work = observed_parent_work
        payload = {
            "schema_version": PARALLEL_ACTION_PARTITION_RECORD_SCHEMA,
            "partition_digest": self.partition_digest,
            "parent_scan_id": self.parent_scan_id,
            "parent_action_plan_digest": self.parent_action_plan_digest,
            "parent_owned_action_ids": list(self.parent_owned_action_ids),
            "allowed_parent_action_ids": list(self.assigned_parent_action_ids),
            "allowed_parent_capabilities": list(self.allowed_parent_capabilities),
            "required_parent_action_ids": list(self.required_parent_action_ids),
            "continuation_allocation_digest": self.continuation_allocation_digest,
            "allowed_continuation_capabilities": list(
                self.allowed_continuation_capabilities
            ),
            "required_continuation_capabilities": list(
                self.required_continuation_capabilities
            ),
            "expected_global_action_ids": list(self.globally_assigned_action_ids),
            "discovery_stage_action_ids": list(self.discovery_stage_action_ids),
            "parent_endpoint_work_ids": expected_parent_work["endpoint_work_ids"],
            "parent_request_work_ids": expected_parent_work["request_work_ids"],
            "children": child_records,
        }
        return {**payload, "record_digest": _digest(payload)}


class ParallelActionPlanCompiler:
    """Compile immutable child roles and budgets from canonical parent authority."""

    @staticmethod
    def resolve_strategy(
        execution_plan: ScanExecutionPlan,
        *,
        requested: str | None,
        known_endpoint_count: int,
    ) -> str:
        strategy = str(requested or "auto").strip().lower()
        if strategy not in _VALID_STRATEGIES:
            strategy = "auto"
        if strategy != "auto":
            return strategy
        if known_endpoint_count >= 2:
            return "scope"
        return "coverage" if execution_plan.policy.active_testing else "family"

    @staticmethod
    def discovery_stage_cost(*, include_network: bool, include_subdomains: bool) -> dict[str, int]:
        """Sum the registry cost of every capability the discovery stage can plan.

        Derived from the registry rather than written down here, so adding a
        discovery capability cannot silently shrink the stage's budget below
        what its own plan costs.
        """
        names = [
            "web.probe", "web.crawl", "web.browser_crawl", "web.content_discover",
        ]
        if include_subdomains:
            names.append("subdomains.discover")
        if include_network:
            names.extend(("ports.discover", "service.fingerprint"))
        totals: dict[str, int] = {}
        for name in names:
            try:
                specification = CAPABILITY_REGISTRY.require(name)
            except Exception:  # an unregistered capability simply cannot be planned
                continue
            for dimension, amount in dict(specification.budget_cost).items():
                totals[str(dimension)] = totals.get(str(dimension), 0) + int(amount)
        return totals

    @staticmethod
    def discovery_budget(
        execution_plan: ScanExecutionPlan,
        *,
        include_network: bool,
    ) -> ScanShardBudget:
        """Reserve a typed producer budget that funds the whole discovery stage.

        This shard is the only owner of ``discover.*`` once fan-out happens, so
        a ceiling below its own plan cost does not merely slow it down -- it
        drops actions. A flat 180-second wall funded only probe plus the static
        crawl, so ``discover.browser_crawl`` was skipped as
        ``insufficient_plan_budget`` on every sharded scan. A single-page
        application builds its API calls in JavaScript, and candidates are only
        made from observed parameters, so losing the browser crawl left xss,
        sqli and nosqli with zero candidates and a truthful but empty
        ``zero_attempts`` result. Size the floor from the registry instead, and
        keep the parent ceiling as the upper bound.
        """
        parent = execution_plan.budget
        endpoints = min(parent.max_endpoints, 500)
        cost = ParallelActionPlanCompiler.discovery_stage_cost(
            include_network=include_network,
            include_subdomains=bool(execution_plan.policy.subdomain_discovery),
        )
        # Headroom for per-action reservation rounding; never above the parent.
        wall = min(parent.max_tool_wall_seconds, max(180, int(cost.get("tool_wall_seconds", 0) * 1.2)))
        http = min(parent.max_http_requests, max(1_000, int(cost.get("http_requests", 0) * 1.2)))
        return ScanShardBudget(
            max_duration_seconds=min(parent.max_duration_seconds, max(180, wall)),
            max_http_requests=http,
            max_endpoints=endpoints,
            max_browser_actions=min(parent.max_browser_actions, cost.get("browser_actions", 0)),
            max_tcp_ports=parent.max_tcp_ports if include_network else 0,
            max_tool_wall_seconds=wall,
            max_workers=1,
            max_state_changing_requests=0,
            max_hosts=min(int(parent.max_hosts or endpoints), endpoints),
        )

    def plan_parent(
        self,
        *,
        parent_execution_plan: ScanExecutionPlan,
        parent_action_plan: ScanActionPlan,
        target_binding: TargetBinding,
        continuation_allocation: ScanContinuationAllocation | None = None,
        endpoint_manifest_entries: Sequence[str] = (),
        request_work: Sequence[ParallelRequestWork] = (),
        candidate_manifest_refs: Sequence[Mapping[str, Any]] = (),
        principal_lanes: Sequence[ParallelPrincipalLane] = (),
        placements: Sequence[ParallelPlacementCapacity] = (),
        scheduling_hint: str | None = None,
        discovery_owned_externally: bool = False,
    ) -> ParallelParentPlan:
        """Plan immutable work slices without consulting compatibility options.

        The hint changes grouping only. Policy, capabilities, principals, target
        scope, and every budget dimension come from typed canonical authority.
        """
        if (
            parent_action_plan.scan_id == ""
            or parent_action_plan.execution_plan_digest
            != parent_execution_plan.digest
            or parent_action_plan.target_binding_digest != target_binding.digest
        ):
            raise ParallelActionPlanError(
                "parallel parent planning authority is inconsistent"
            )
        if continuation_allocation is not None and (
            continuation_allocation.scan_id != parent_action_plan.scan_id
            or continuation_allocation.parent_plan_digest
            != parent_action_plan.plan_digest
            or continuation_allocation.execution_plan_digest
            != parent_execution_plan.digest
            or continuation_allocation.target_binding_digest
            != target_binding.digest
        ):
            raise ParallelActionPlanError(
                "parallel parent planning continuation is inconsistent"
            )

        endpoints = tuple(sorted({
            str(item).strip() for item in endpoint_manifest_entries
            if str(item).strip()
        }))
        requests = tuple(sorted(
            (
                item if isinstance(item, ParallelRequestWork)
                else ParallelRequestWork(**dict(item))
                for item in request_work
            ),
            key=lambda item: (item.principal_lane, item.selection_digest),
        ))
        if len({item.selection_digest for item in requests}) != len(requests):
            raise ParallelActionPlanError(
                "parallel request work selection is duplicated"
            )
        candidate_refs = tuple(
            _canonical_mapping(item) for item in sorted(
                (dict(item) for item in candidate_manifest_refs),
                key=lambda item: json.dumps(
                    item, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                ),
            )
        )
        lanes = tuple(
            item if isinstance(item, ParallelPrincipalLane)
            else ParallelPrincipalLane(**dict(item))
            for item in principal_lanes
        ) or (ParallelPrincipalLane("anonymous"),)
        if len({item.name for item in lanes}) != len(lanes):
            raise ParallelActionPlanError("parallel principal lanes are duplicated")
        placement_lanes = tuple(
            item if isinstance(item, ParallelPlacementCapacity)
            else ParallelPlacementCapacity(**dict(item))
            for item in placements
        ) or (ParallelPlacementCapacity(
            "local",
            parent_execution_plan.budget.max_workers,
            {"node_scope": "local"},
        ),)
        if len({item.name for item in placement_lanes}) != len(placement_lanes):
            raise ParallelActionPlanError("parallel placement lanes are duplicated")

        hint = self.resolve_strategy(
            parent_execution_plan,
            requested=scheduling_hint,
            known_endpoint_count=len(endpoints),
        )
        notes: list[str] = []
        if scheduling_hint and str(scheduling_hint).strip().lower() != hint:
            notes.append("unknown scheduling hint normalized to canonical auto planning")

        comparison = next(
            (lane for lane in lanes if lane.name == "comparison"), None,
        )
        global_lane = comparison or next(
            (lane for lane in lanes if lane.name != "anonymous"), lanes[0],
        )
        global_placement = next(
            (item for item in placement_lanes if item.name == "local"),
            placement_lanes[0],
        )
        # A placed discovery stage already executed ``discover.*`` against this
        # target, so the backbone must not repeat it. Without that stage the
        # backbone remains the only owner of discovery and keeps ``full`` scope.
        global_scope = "global" if discovery_owned_externally else "full"
        children: list[ParallelPlannedChild] = [ParallelPlannedChild(
            index=0,
            label="global",
            role="global",
            endpoints=(),
            request_selection_digests=(),
            candidate_manifest_refs=(),
            principal_lane=global_lane,
            family_scope=(),
            placement=global_placement,
            action_scope=global_scope,
        )]

        has_endpoint_authority = any(
            action.action_id not in {"finalize.report"}
            and not _is_global_action(action.action_id)
            for action in parent_action_plan.actions
        ) or bool(
            continuation_allocation
            and continuation_allocation.allowed_capabilities
        )
        if not has_endpoint_authority or not (
            endpoints or requests or candidate_refs
        ):
            notes.append("no immutable endpoint-scoped work requires fan-out")
            return ParallelParentPlan(
                parent_scan_id=parent_action_plan.scan_id,
                parent_execution_plan_digest=parent_execution_plan.digest,
                parent_action_plan_digest=str(parent_action_plan.plan_digest),
                target_binding_digest=target_binding.digest,
                scheduling_hint=hint,
                children=tuple(children),
                notes=tuple(notes),
            )

        family_candidates = tuple(sorted({
            _capability_family(action.capability_name)
            for action in parent_action_plan.actions
            if _capability_family(action.capability_name)
            in {"xss", "sqli", "nuclei_active", "bola", "auth"}
        }))
        family_groups: tuple[tuple[str, ...], ...] = ((),)
        if hint in {"family", "coverage_family"} and family_candidates:
            family_groups = tuple((item,) for item in family_candidates)

        endpoint_lanes = tuple(lanes)
        # Placement capacity is a concurrency ceiling, not a child-count
        # ceiling. Keep at least one endpoint partition beside the global
        # partition even for max_workers=1; the leased per-parent semaphore
        # executes them sequentially. Explicit principal lanes also remain
        # separate when they must share one worker over time.
        concurrent_capacity = sum(item.capacity for item in placement_lanes)
        available_endpoint_slots = max(
            1,
            concurrent_capacity - 1,
            len(endpoint_lanes),
        )
        if len(endpoint_lanes) * len(family_groups) > available_endpoint_slots:
            family_groups = (family_candidates,) if family_candidates else ((),)
            notes.append(
                "family scheduling lanes coalesced to preserve principal isolation"
            )
        axis_count = len(endpoint_lanes) * len(family_groups)
        available_endpoint_slots = max(available_endpoint_slots, axis_count)

        work_count = max(1, len(endpoints), len(requests), len(candidate_refs))
        per_axis_slots = max(1, min(
            max(1, available_endpoint_slots // max(1, axis_count)),
            work_count,
        ))
        expanded_placements: list[ParallelPlacementCapacity] = []
        for placement in placement_lanes:
            expanded_placements.extend([placement] * placement.capacity)
        placement_cursor = 0
        lane_children: dict[str, list[int]] = {}
        for lane in endpoint_lanes:
            for family_scope in family_groups:
                endpoint_buckets = [list() for _ in range(per_axis_slots)]
                for offset, endpoint in enumerate(endpoints):
                    endpoint_buckets[offset % per_axis_slots].append(endpoint)
                for bucket_index in range(per_axis_slots):
                    placement = expanded_placements[
                        placement_cursor % len(expanded_placements)
                    ]
                    placement_cursor += 1
                    child_index = len(children)
                    lane_children.setdefault(lane.name, []).append(child_index)
                    suffix = ":" + "+".join(family_scope) if family_scope else ""
                    children.append(ParallelPlannedChild(
                        index=child_index,
                        label=f"work:{lane.name}[{bucket_index}]{suffix}",
                        role="endpoint",
                        endpoints=tuple(endpoint_buckets[bucket_index]),
                        request_selection_digests=(),
                        candidate_manifest_refs=(),
                        principal_lane=lane,
                        family_scope=family_scope,
                        placement=placement,
                    ))

        mutable = [
            {
                "requests": list(child.request_selection_digests),
                "candidates": list(child.candidate_manifest_refs),
            }
            for child in children
        ]
        all_endpoint_indices = [
            child.index for child in children if child.role == "endpoint"
        ]
        for request in requests:
            eligible = lane_children.get(request.principal_lane)
            if not eligible and request.principal_lane == "comparison":
                eligible = lane_children.get(global_lane.name)
            if not eligible:
                raise ParallelActionPlanError(
                    "parallel request work has no matching principal lane"
                )
            selected = eligible[
                int(request.selection_digest[:16], 16) % len(eligible)
            ]
            mutable[selected]["requests"].append(request.selection_digest)
        for reference in candidate_refs:
            reference_digest = _digest(dict(reference))
            selected = all_endpoint_indices[
                int(reference_digest[:16], 16) % len(all_endpoint_indices)
            ]
            mutable[selected]["candidates"].append(reference)
        children = [
            ParallelPlannedChild(
                index=child.index,
                label=child.label,
                role=child.role,
                endpoints=child.endpoints,
                request_selection_digests=tuple(mutable[child.index]["requests"]),
                candidate_manifest_refs=tuple(mutable[child.index]["candidates"]),
                principal_lane=child.principal_lane,
                family_scope=child.family_scope,
                placement=child.placement,
                action_scope=child.action_scope,
            )
            for child in children
        ]
        return ParallelParentPlan(
            parent_scan_id=parent_action_plan.scan_id,
            parent_execution_plan_digest=parent_execution_plan.digest,
            parent_action_plan_digest=str(parent_action_plan.plan_digest),
            target_binding_digest=target_binding.digest,
            scheduling_hint=hint,
            children=tuple(children),
            notes=tuple(notes),
        )

    def compile(
        self,
        *,
        parent_execution_plan: ScanExecutionPlan,
        parent_action_plan: ScanActionPlan,
        target_binding: TargetBinding,
        child_specs: Sequence[Mapping[str, Any]],
        consumed_budget: Mapping[str, Any] | None = None,
        continuation_allocation: ScanContinuationAllocation | None = None,
        strategy: str,
        available_worker_count: int = 0,
    ) -> ParallelActionPartition:
        if (
            parent_action_plan.scan_id == ""
            or parent_action_plan.execution_plan_digest != parent_execution_plan.digest
            or parent_action_plan.target_binding_digest != target_binding.digest
        ):
            raise ParallelActionPlanError(
                "parallel parent action authority does not match execution authority"
            )
        if len(child_specs) < 2:
            raise ParallelActionPlanError("parallel partition requires at least two children")
        indices = [int(item.get("index", -1)) for item in child_specs]
        if indices != list(range(len(child_specs))):
            raise ParallelActionPlanError("parallel child indices must be contiguous")
        scan_ids = [str(item.get("scan_id") or "") for item in child_specs]
        if any(not item for item in scan_ids) or len(set(scan_ids)) != len(scan_ids):
            raise ParallelActionPlanError("parallel child Scan identities must be unique")
        if continuation_allocation is not None and (
            continuation_allocation.scan_id != parent_action_plan.scan_id
            or continuation_allocation.parent_plan_digest
            != parent_action_plan.plan_digest
            or continuation_allocation.execution_plan_digest
            != parent_execution_plan.digest
            or continuation_allocation.target_binding_digest
            != target_binding.digest
            or continuation_allocation.parent_action_ids
            != tuple(action.action_id for action in parent_action_plan.actions)
        ):
            raise ParallelActionPlanError(
                "parallel continuation allocation differs from parent authority"
            )

        backbone = [
            index for index, item in enumerate(child_specs)
            if (
                str(item.get("role") or "").strip().lower() == "global"
                or bool((item.get("options") or {}).get("parallel_backbone"))
            )
        ]
        if len(backbone) > 1:
            raise ParallelActionPlanError("parallel partition has multiple global backbones")
        global_index = backbone[0] if backbone else 0
        base_weights = [
            max(1, int(item.get("work_weight") or 0))
            if item.get("work_weight") is not None
            else _entry_weight(item.get("options") or {})
            for item in child_specs
        ]
        weights = list(base_weights)
        endpoint_weight = sum(base_weights) - base_weights[global_index]
        if parent_execution_plan.policy.active_testing:
            # Active candidate shards need enough of the fixed parent ceiling
            # for complete deterministic verifiers. Discovery still receives
            # a bounded share, but no longer automatically owns half the scan.
            weights[global_index] += max(1, endpoint_weight // 4)
        else:
            weights[global_index] += max(1, endpoint_weight)

        parent_budget: ScanBudget = parent_execution_plan.budget
        consumed = dict(consumed_budget or {})
        remaining = {
            ledger_name: max(0, int(limit) - max(0, int(consumed.get(ledger_name) or 0)))
            for ledger_name, limit in parent_budget.ledger_limits().items()
        }
        http = _weighted_shares(remaining["http_requests"], weights, minimum=1)
        endpoints = _weighted_shares(parent_budget.max_endpoints, weights, minimum=1)
        hosts = _weighted_shares(remaining["hosts_attempted"], weights, minimum=1)
        mutation = _weighted_shares(
            remaining["state_changing_requests"], weights, minimum=0,
        )
        tool = _weighted_shares(
            # Every child owns one offline scan.finalize action. Reserve its
            # minimum wall-time before distributing the remaining tool budget.
            remaining["tool_wall_seconds"], weights, minimum=1,
        )
        browser = [0] * len(child_specs)
        browser[global_index] = remaining["browser_actions"]
        tcp = [0] * len(child_specs)
        tcp[global_index] = remaining["tcp_ports_attempted"]

        children: list[ParallelChildPartition] = []
        for index, item in enumerate(child_specs):
            budget = ScanShardBudget(
                max_duration_seconds=parent_budget.max_duration_seconds,
                max_http_requests=http[index],
                max_endpoints=endpoints[index],
                max_browser_actions=browser[index],
                max_tcp_ports=tcp[index],
                max_tool_wall_seconds=tool[index],
                max_workers=1,
                max_state_changing_requests=min(mutation[index], http[index]),
                max_hosts=min(hosts[index], endpoints[index]),
            )
            children.append(ParallelChildPartition(
                scan_id=str(item["scan_id"]),
                index=index,
                label=str(item.get("label") or f"shard[{index}]"),
                role="global" if index == global_index else "endpoint",
                budget=budget,
                work_partition_digest=(
                    str(item.get("work_partition_digest") or "")
                    or _work_partition_digest(item.get("options") or {})
                ),
                principal_lane=str(
                    item.get("principal_lane")
                    or (item.get("options") or {}).get("parallel_principal_lane")
                    or (item.get("options") or {}).get("auth_state")
                    or "comparison"
                ),
                placement_name=str(
                    item.get("placement_name")
                    or (item.get("options") or {}).get("parallel_placement_name")
                    or "local"
                ),
                family_scope=tuple(sorted({
                    str(value).strip().lower()
                    for value in (
                        item.get("family_scope")
                        or (() if not (item.get("options") or {}).get(
                            "coverage_attempt_family"
                        ) else ((item.get("options") or {}).get(
                            "coverage_attempt_family"
                        ),))
                    )
                    if str(value).strip() and str(value).strip().lower() != "all"
                })),
                action_scope=str(item.get("action_scope") or ""),
            ))

        for ledger_name, budget_name in _LEDGER_TO_BUDGET.items():
            allocated = sum(getattr(child.budget, budget_name) for child in children)
            if allocated > remaining[ledger_name]:
                raise ParallelActionPlanError(
                    f"parallel child {ledger_name} authority exceeds parent remainder"
                )
        parent_owned = tuple(
            action.action_id for action in parent_action_plan.actions
            if action.action_id == "finalize.report"
        )
        # The backbone's compiled scope is the single authority for who owns
        # discovery. When a placed discovery stage already ran it, the fan-out
        # children own only baseline posture, and ``discover.*`` is recorded as
        # discovery-stage work rather than silently dropped from the partition.
        discovery_owned_externally = any(
            child.role == "global" and child.action_scope == "global"
            for child in children
        )
        discovery_stage = tuple(
            action.action_id for action in parent_action_plan.actions
            if _is_discovery_action(action.action_id)
        ) if discovery_owned_externally else ()
        global_actions = tuple(
            action.action_id for action in parent_action_plan.actions
            if _is_global_action(action.action_id)
            and action.action_id not in discovery_stage
        )
        fanout_excluded = set(parent_owned) | set(discovery_stage)
        assigned_parent = tuple(dict.fromkeys(
            _projection_id(action.action_id)
            for action in parent_action_plan.actions
            if action.action_id not in fanout_excluded
        ))
        required_parent = tuple(dict.fromkeys(
            _projection_id(action.action_id)
            for action in parent_action_plan.actions
            if action.required and action.action_id not in fanout_excluded
        ))
        return ParallelActionPartition(
            parent_scan_id=parent_action_plan.scan_id,
            parent_execution_plan_digest=parent_execution_plan.digest,
            parent_action_plan_digest=str(parent_action_plan.plan_digest),
            target_binding_digest=target_binding.digest,
            strategy=strategy,
            available_worker_count=max(0, int(available_worker_count or 0)),
            children=tuple(children),
            parent_owned_action_ids=parent_owned,
            globally_assigned_action_ids=global_actions,
            discovery_stage_action_ids=discovery_stage,
            assigned_parent_action_ids=assigned_parent,
            required_parent_action_ids=required_parent,
            allowed_parent_capabilities=tuple(sorted({
                action.capability_name for action in parent_action_plan.actions
                if action.action_id not in parent_owned
            })),
            continuation_allocation_digest=(
                continuation_allocation.allocation_digest
                if continuation_allocation is not None else None
            ),
            allowed_continuation_capabilities=(
                continuation_allocation.allowed_capabilities
                if continuation_allocation is not None else ()
            ),
            required_continuation_capabilities=(
                continuation_allocation.required_capabilities
                if continuation_allocation is not None else ()
            ),
        )


def validate_parallel_partition_record(
    record: Mapping[str, Any],
    *,
    parent_scan_id: str,
    child_plan_digests: Mapping[str, str],
    child_action_plans: Mapping[str, ScanActionPlan | Mapping[str, Any]] | None = None,
) -> None:
    raw = dict(record)
    supplied_record_digest = str(raw.pop("record_digest", ""))
    if (
        raw.get("schema_version") not in {
            PARALLEL_ACTION_PARTITION_RECORD_SCHEMA,
            _LEGACY_PARALLEL_ACTION_PARTITION_RECORD_SCHEMA,
        }
        or raw.get("parent_scan_id") != parent_scan_id
        or supplied_record_digest != _digest(raw)
    ):
        raise ParallelActionPlanError("parallel action partition record is invalid")
    children = raw.get("children")
    if not isinstance(children, list):
        raise ParallelActionPlanError("parallel action partition children are invalid")
    expected = {
        str(item.get("scan_id") or ""): str(item.get("action_plan_digest") or "")
        for item in children if isinstance(item, Mapping)
    }
    if expected != dict(child_plan_digests):
        raise ParallelActionPlanError(
            "persisted child action plans differ from the parent partition"
        )
    semantic_authority_v2 = (
        raw.get("schema_version") == PARALLEL_ACTION_PARTITION_RECORD_SCHEMA
    )
    parent_owned = set(raw.get("parent_owned_action_ids") or ())
    allowed_parent_actions = set(raw.get("allowed_parent_action_ids") or ())
    allowed_parent_capabilities = set(
        raw.get("allowed_parent_capabilities") or ()
    )
    required_parent = set(raw.get("required_parent_action_ids") or ())
    allowed_continuation = set(
        raw.get("allowed_continuation_capabilities") or ()
    )
    required_continuation = set(
        raw.get("required_continuation_capabilities") or ()
    )
    expected_global = set(raw.get("expected_global_action_ids") or ())
    parent_endpoints = list(raw.get("parent_endpoint_work_ids") or ())
    parent_requests = list(raw.get("parent_request_work_ids") or ())
    authority_lists = (
        raw.get("allowed_parent_action_ids"),
        raw.get("allowed_parent_capabilities"),
        raw.get("allowed_continuation_capabilities"),
        raw.get("required_continuation_capabilities"),
        # Discovery actions owned by a placed discovery stage. They are excluded
        # from both the global set and the fan-out authority lists, so a child
        # that still carries one fails the parent-authority check below.
        raw.get("discovery_stage_action_ids"),
    ) if semantic_authority_v2 else ()
    if any(
        not isinstance(value, list)
        for value in (
            raw.get("parent_owned_action_ids"),
            raw.get("required_parent_action_ids"),
            raw.get("expected_global_action_ids"),
            raw.get("parent_endpoint_work_ids"),
            raw.get("parent_request_work_ids"),
            *authority_lists,
        )
    ):
        raise ParallelActionPlanError("parallel action partition authority is invalid")
    global_occurrences = {action_id: 0 for action_id in expected_global}
    observed_endpoints: list[str] = []
    observed_requests: list[str] = []
    observed_projection_ids: set[str] = set()
    observed_continuation_capabilities: set[str] = set()
    plans = dict(child_action_plans or {})
    if plans and set(plans) != set(expected):
        raise ParallelActionPlanError(
            "persisted child action plan bodies do not cover the partition"
        )
    for item in children:
        if not isinstance(item, Mapping):
            raise ParallelActionPlanError("parallel action partition child is invalid")
        scan_id = str(item.get("scan_id") or "")
        role = str(item.get("role") or "")
        action_ids = item.get("expected_action_ids")
        child_global = item.get("expected_global_action_ids")
        endpoint_ids = item.get("endpoint_work_ids")
        request_ids = item.get("request_work_ids")
        refs = item.get("work_manifest_refs")
        families = item.get("allowed_family_scope")
        if not all(isinstance(value, list) for value in (
            action_ids, child_global, endpoint_ids, request_ids, refs, families,
        )):
            raise ParallelActionPlanError("parallel action partition child fields are invalid")
        if semantic_authority_v2 and (
            action_ids.count("finalize.report") != 1
            or action_ids[-1:] != ["finalize.report"]
        ):
            raise ParallelActionPlanError(
                "parallel child report finalizer is invalid"
            )
        if parent_owned.intersection(
            action_id for action_id in action_ids
            if action_id != "finalize.report"
        ):
            raise ParallelActionPlanError(
                "parent-owned action appears in a child action plan"
            )
        if role == "global":
            if set(child_global) != expected_global:
                raise ParallelActionPlanError(
                    "global child action ownership differs from the partition"
                )
        elif child_global:
            raise ParallelActionPlanError("endpoint child duplicates a global action")
        for action_id in child_global:
            if action_id not in global_occurrences:
                raise ParallelActionPlanError(
                    "child introduced an unassigned global action"
                )
            global_occurrences[action_id] += 1
        observed_projection_ids.update(
            _projection_id(item) for item in action_ids
            if item != "finalize.report"
        )
        assignment = _canonical_work_assignment({
            "endpoint_work_ids": endpoint_ids,
            "request_work_ids": request_ids,
            "work_manifest_refs": refs,
            "allowed_family_scope": families,
            "work_partition_digest": item.get("work_partition_digest"),
        })
        observed_endpoints.extend(assignment["endpoint_work_ids"])
        observed_requests.extend(assignment["request_work_ids"])
        if plans:
            plan_value = plans[scan_id]
            try:
                plan = (
                    plan_value
                    if isinstance(plan_value, ScanActionPlan)
                    else ScanActionPlan.from_dict(plan_value)
                )
            except (TypeError, ValueError) as exc:
                raise ParallelActionPlanError(
                    "persisted child action plan body is invalid"
                ) from exc
            if (
                plan.scan_id != scan_id
                or plan.plan_digest != item.get("action_plan_digest")
                or [action.action_id for action in plan.actions] != action_ids
                or not set({
                    _capability_family(action.capability_name)
                    for action in plan.actions
                    if action.capability_name != "scan.finalize"
                }) <= set(families)
                or _digest({
                    "work_partition_digest": assignment["work_partition_digest"],
                    "action_input_binding_digests": [
                        action.input_binding_digest for action in plan.actions
                    ],
                }) != item.get("input_binding_digest")
            ):
                raise ParallelActionPlanError(
                    "persisted child action authority differs from the semantic partition"
                )
            for action in plan.actions:
                projection = _projection_id(action.action_id)
                capability = action.capability_name
                if semantic_authority_v2 and (
                    capability != "scan.finalize"
                    and projection not in allowed_parent_actions
                    and capability not in allowed_continuation
                ):
                    raise ParallelActionPlanError(
                        "persisted child action exceeds parent authority"
                    )
                if semantic_authority_v2 and (
                    capability != "scan.finalize"
                    and capability not in allowed_parent_capabilities
                    and capability not in allowed_continuation
                ):
                    raise ParallelActionPlanError(
                        "persisted child capability exceeds parent authority"
                    )
                if capability in allowed_continuation:
                    observed_continuation_capabilities.add(capability)
    if any(count != 1 for count in global_occurrences.values()):
        raise ParallelActionPlanError(
            "global actions do not occur exactly once in the partition"
        )
    if len(observed_endpoints) != len(set(observed_endpoints)):
        raise ParallelActionPlanError("parallel endpoint work is duplicated")
    if len(observed_requests) != len(set(observed_requests)):
        raise ParallelActionPlanError("parallel request work is duplicated")
    if sorted(observed_endpoints) != sorted(parent_endpoints):
        raise ParallelActionPlanError("parallel endpoint work is incomplete")
    if sorted(observed_requests) != sorted(parent_requests):
        raise ParallelActionPlanError("parallel request work is incomplete")
    if not required_parent <= observed_projection_ids:
        raise ParallelActionPlanError("required parent action work is unassigned")
    if (
        semantic_authority_v2
        and plans
        and not required_continuation <= observed_continuation_capabilities
    ):
        raise ParallelActionPlanError(
            "required continuation capability work is unassigned"
        )


def merge_parallel_action_executions(
    record: Mapping[str, Any],
    *,
    child_results: Mapping[str, Mapping[str, Any] | None],
    child_statuses: Mapping[str, str],
) -> dict[str, Any]:
    """Validate and merge content-free child action/observation provenance.

    Human-facing reports remain a projection. This is the authoritative merge
    seam: an action row or observation reference not frozen in the partition is
    rejected before findings or report fragments are considered.
    """
    raw_children = record.get("children")
    if not isinstance(raw_children, list):
        raise ParallelActionPlanError(
            "parallel action execution merge requires a partition record"
        )
    expected = {
        str(item.get("scan_id") or ""): item
        for item in raw_children if isinstance(item, Mapping)
    }
    if (
        not expected
        or set(child_results) != set(expected)
        or set(child_statuses) != set(expected)
    ):
        raise ParallelActionPlanError(
            "parallel action execution children differ from the partition"
        )
    merged_actions: list[dict[str, Any]] = []
    observation_refs: list[dict[str, Any]] = []
    children: list[dict[str, Any]] = []
    incomplete_children: list[str] = []
    candidate_coverage: dict[str, dict[str, Any]] = {}
    family_coverage: dict[str, dict[str, Any]] = {}
    for scan_id in sorted(expected, key=lambda key: int(expected[key].get("index", 0))):
        partition_child = expected[scan_id]
        status = str(child_statuses[scan_id] or "unknown").strip().lower()
        report = child_results[scan_id]
        if not isinstance(report, Mapping):
            if status == "completed":
                raise ParallelActionPlanError(
                    "completed parallel child has no canonical action report"
                )
            incomplete_children.append(scan_id)
            children.append({
                "scan_id": scan_id,
                "status": status,
                "action_plan_digest": partition_child.get("action_plan_digest"),
                "action_count": 0,
                "observation_manifest_count": 0,
            })
            continue
        execution = report.get("canonical_action_execution")
        if not isinstance(execution, Mapping):
            raise ParallelActionPlanError(
                "parallel child report has no canonical action execution"
            )
        action_rows = execution.get("actions")
        finalizer = execution.get("finalization_action")
        if not isinstance(action_rows, list) or not isinstance(finalizer, Mapping):
            raise ParallelActionPlanError(
                "parallel child canonical action execution is malformed"
            )
        child_coverage = (
            report.get("coverage")
            if isinstance(report.get("coverage"), Mapping) else {}
        )
        for family, raw in (
            child_coverage.get("candidate_coverage") or {}
        ).items():
            if not isinstance(raw, Mapping) or not str(family).strip():
                continue
            family_name = str(family).strip()
            aggregate = candidate_coverage.setdefault(family_name, {
                "status": "complete",
                "batch_actions": 0,
                "planned_candidates": 0,
                "attempted_candidates": 0,
                "completed_candidates": 0,
                "incomplete_candidates": 0,
                "unattempted_candidates": 0,
            })
            for key in (
                "batch_actions", "planned_candidates", "attempted_candidates",
                "completed_candidates", "incomplete_candidates",
                "unattempted_candidates",
            ):
                aggregate[key] += max(0, int(raw.get(key) or 0))
            if str(raw.get("status") or "complete").lower() != "complete":
                aggregate["status"] = "partial"
        for raw in child_coverage.get("family_coverage") or ():
            if not isinstance(raw, Mapping) or not str(raw.get("family") or "").strip():
                continue
            family_name = str(raw.get("family")).strip()
            aggregate = family_coverage.setdefault(family_name, {
                "family": family_name,
                "selected": False,
                "required": False,
                "coverage_status": "complete",
                "reason": None,
                "batch_actions": 0,
                "planned_candidates": 0,
                "attempted_candidates": 0,
                "completed_candidates": 0,
                "incomplete_candidates": 0,
                "unattempted_candidates": 0,
                "verified_findings": 0,
                "suspected_findings": 0,
            })
            aggregate["selected"] = aggregate["selected"] or raw.get("selected") is True
            aggregate["required"] = aggregate["required"] or raw.get("required") is True
            for key in (
                "batch_actions", "planned_candidates", "attempted_candidates",
                "completed_candidates", "incomplete_candidates",
                "unattempted_candidates", "verified_findings", "suspected_findings",
            ):
                aggregate[key] += max(0, int(raw.get(key) or 0))
            if str(raw.get("coverage_status") or "complete").lower() != "complete":
                aggregate["coverage_status"] = "partial"
                aggregate["reason"] = aggregate["reason"] or raw.get("reason") or "child_family_incomplete"
        expected_ids = list(partition_child.get("expected_action_ids") or ())
        actual_ids = [
            str(item.get("action_id") or "")
            for item in action_rows if isinstance(item, Mapping)
        ]
        actual_ids.append(str(finalizer.get("action_id") or ""))
        if (
            len(action_rows) != sum(isinstance(item, Mapping) for item in action_rows)
            or execution.get("plan_digest")
            != partition_child.get("action_plan_digest")
            or actual_ids != expected_ids
            or finalizer.get("status") != "success"
        ):
            raise ParallelActionPlanError(
                "parallel child result is outside its exact action partition"
            )
        child_observation_count = 0
        for row in action_rows:
            normalized = dict(row)
            normalized["scan_id"] = scan_id
            normalized["occurrence_id"] = parallel_action_occurrence_id(
                scan_id, str(row.get("action_id") or ""),
            )
            merged_actions.append(normalized)
            reference = row.get("observation_manifest")
            if reference is not None:
                if not isinstance(reference, Mapping):
                    raise ParallelActionPlanError(
                        "parallel child observation manifest reference is invalid"
                    )
                observation_refs.append({
                    "action_id": row.get("action_id"),
                    "occurrence_id": normalized["occurrence_id"],
                    "reference": dict(reference),
                })
                child_observation_count += 1
        if status != "completed" or bool(
            (report.get("scan_metadata") or {}).get("partial")
            if isinstance(report.get("scan_metadata"), Mapping) else False
        ):
            incomplete_children.append(scan_id)
        children.append({
            "scan_id": scan_id,
            "status": status,
            "action_plan_digest": partition_child.get("action_plan_digest"),
            "action_count": len(action_rows) + 1,
            "observation_manifest_count": child_observation_count,
        })
    payload = {
        "schema_version": PARALLEL_ACTION_EXECUTION_MERGE_SCHEMA,
        "partition_record_digest": record.get("record_digest"),
        "children": children,
        "actions": merged_actions,
        "observation_manifests": observation_refs,
        "incomplete_child_scan_ids": incomplete_children,
        "partial": bool(incomplete_children),
        "candidate_coverage": {
            key: candidate_coverage[key] for key in sorted(candidate_coverage)
        },
        "family_coverage": [family_coverage[key] for key in sorted(family_coverage)],
    }
    return {**payload, "merge_digest": _digest(payload)}


def summarize_parallel_action_coverage(
    execution: Mapping[str, Any] | None,
    *,
    additional_reliability_reasons: Sequence[str] = (),
) -> dict[str, Any]:
    """Project one truthful parent coverage block from the verified child merge.

    A parallel parent's original action rows are allocation placeholders.  Only
    the partition-bound child merge proves which actions actually terminated.
    This projection intentionally contains no child IDs or observation bodies.
    """
    merge = dict(execution or {})
    actions = [
        dict(item) for item in merge.get("actions") or ()
        if isinstance(item, Mapping) and str(item.get("action_id") or "").strip()
    ]
    counts = Counter(str(item.get("status") or "missing") for item in actions)
    required = [item for item in actions if item.get("required") is True]
    required_incomplete = [
        item for item in required if str(item.get("status") or "missing") != "success"
    ]
    reliability_reasons = {
        str(item.get("reason_code") or "missing_terminal_result")
        for item in required_incomplete
    }
    reliability_reasons.update(
        str(item).strip()[:100]
        for item in additional_reliability_reasons
        if str(item).strip()
    )
    if merge.get("partial") is True:
        reliability_reasons.add("parallel_child_incomplete")
    sorted_reasons = sorted(reliability_reasons)
    optional_gaps = [
        {
            "action_id": str(item.get("action_id")),
            "occurrence_id": str(item.get("occurrence_id") or ""),
            "capability_name": str(item.get("capability_name") or "unknown"),
            "status": str(item.get("status") or "missing"),
            "reason_code": item.get("reason_code"),
        }
        for item in actions
        if item.get("required") is not True
        and str(item.get("status") or "missing") != "success"
    ]
    return {
        "status": "partial" if sorted_reasons else "complete",
        "reasons": sorted_reasons,
        "planned_action_count": len(actions),
        "terminal_action_count": sum(
            counts.get(status, 0)
            for status in (
                "success", "partial", "skipped", "blocked", "failed",
                "cancelled", "timed_out",
            )
        ),
        "finalization_action_id": "finalize.report",
        "placement_executed": bool(actions) and not any(
            str(item.get("reason_code") or "") == "placement_unavailable"
            for item in actions
        ),
        "capability_coverage": {
            "total": len(actions),
            "required": len(required),
            "completed": counts.get("success", 0),
            "partial": counts.get("partial", 0) + counts.get("timed_out", 0),
            "blocked": counts.get("blocked", 0),
            "failed": counts.get("failed", 0),
            "skipped": counts.get("skipped", 0),
            "cancelled": counts.get("cancelled", 0),
            "pending": sum(
                counts.get(status, 0)
                for status in ("planned", "leased", "running", "missing")
            ),
            "actions": [
                {
                    "action_id": str(item.get("action_id")),
                    "occurrence_id": str(item.get("occurrence_id") or ""),
                    "capability_name": str(item.get("capability_name") or "unknown"),
                    "required": item.get("required") is True,
                    "status": str(item.get("status") or "missing"),
                    "reason_code": item.get("reason_code"),
                }
                for item in actions
            ],
        },
        "grade_reliability": {
            "reliable": not sorted_reasons,
            "reasons": sorted_reasons,
        },
        "optional_gaps": optional_gaps,
        "active_zero_attempt_actions": [],
        "candidate_coverage": {
            str(key): dict(value)
            for key, value in (merge.get("candidate_coverage") or {}).items()
            if isinstance(value, Mapping)
        },
        "family_coverage": [
            dict(item) for item in merge.get("family_coverage") or ()
            if isinstance(item, Mapping)
        ],
        "selected_family_gaps": sorted({
            str(item.get("family"))
            for item in merge.get("family_coverage") or ()
            if isinstance(item, Mapping)
            and item.get("required") is True
            and str(item.get("coverage_status") or "").lower() != "complete"
        }),
    }
