"""Content-addressed two-phase Scan planning after bounded discovery."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
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

from .action_plan import ScanAction, ScanActionPlan, ScanActionPlanError
from .capability_result import CapabilityResultReference
from .surface_manifest import build_scan_surface_manifest
from .work_manifests import (
    ScanWorkManifest,
    ScanWorkManifestReference,
    build_candidate_manifest,
    build_endpoint_manifest,
)
try:
    from runtime.models import TargetBinding
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.models import TargetBinding


SCAN_CONTINUATION_ALLOCATION_SCHEMA_V1 = "scan-continuation-allocation/v1"
SCAN_CONTINUATION_ALLOCATION_SCHEMA = "scan-continuation-allocation/v2"
SCAN_PLAN_REVISION_SCHEMA = "scan-plan-revision/v1"
SCAN_DISCOVERY_RESULT_SET_SCHEMA = "scan-discovery-result-set/v1"
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_ACTIONS = 512
_LEGACY_CONTINUATION_CAPABILITIES = (
    "authz.verify",
    "authz_surface.verify_batch",
    "exposure.verify_batch",
    "nosqli.verify_batch",
    "sqli.prove_batch",
    "sqli.request_verify",
    "sqli.verify",
    "sqli.verify_batch",
    "sqli.request_verify_batch",
    "templates.scan",
    "templates.passive_batch",
    "templates.active_batch",
    "xss.browser_prove_batch",
    "xss.request_verify",
    "xss.verify",
    "xss.verify_batch",
    "xss.request_verify_batch",
)


class ScanContinuationError(ValueError):
    """A continuation differs from its frozen parent or budget authority."""


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def _hex(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _HEX_64_RE.fullmatch(normalized):
        raise ScanContinuationError(f"{name} must be a SHA-256 digest")
    return normalized


def _budget(value: Mapping[str, Any]) -> Mapping[str, int]:
    normalized: dict[str, int] = {}
    for raw_name, raw_amount in dict(value or {}).items():
        name = str(raw_name or "").strip()
        if name not in BUDGET_DIMENSIONS:
            raise ScanContinuationError(
                f"unknown continuation budget dimension: {name}"
            )
        if isinstance(raw_amount, bool) or not isinstance(raw_amount, int):
            raise ScanContinuationError(
                f"continuation budget {name} must be an integer"
            )
        if raw_amount < 0:
            raise ScanContinuationError(
                f"continuation budget {name} must be non-negative"
            )
        normalized[name] = raw_amount
    if not normalized:
        raise ScanContinuationError("continuation budget ceiling is empty")
    return MappingProxyType({name: normalized[name] for name in sorted(normalized)})


@dataclass(frozen=True)
class ContinuationBudgetCeiling:
    """Allocator-compatible view of one already-frozen residual ceiling."""

    limits: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "limits", _budget(self.limits))

    def ledger_limits(self) -> Mapping[str, int]:
        return self.limits


@dataclass(frozen=True)
class ScanContinuationAllocation:
    scan_id: str
    parent_plan_digest: str
    execution_plan_digest: str
    target_binding_digest: str
    parent_action_ids: tuple[str, ...]
    budget_ceiling: Mapping[str, int]
    max_endpoint_entries: int
    max_candidate_entries: int
    required_capabilities: tuple[str, ...] = ()
    allowed_capabilities: tuple[str, ...] = ()
    schema_version: str = SCAN_CONTINUATION_ALLOCATION_SCHEMA
    allocation_digest: str | None = field(default=None, compare=True)

    def __post_init__(self) -> None:
        if self.schema_version not in {
            SCAN_CONTINUATION_ALLOCATION_SCHEMA_V1,
            SCAN_CONTINUATION_ALLOCATION_SCHEMA,
        }:
            raise ScanContinuationError("unsupported Scan continuation allocation")
        try:
            scan_id = str(uuid.UUID(str(self.scan_id)))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ScanContinuationError("continuation scan_id must be a UUID") from exc
        action_ids = tuple(str(item or "").strip() for item in self.parent_action_ids)
        if (
            not action_ids
            or any(not item for item in action_ids)
            or len(action_ids) > _MAX_ACTIONS
            or len(set(action_ids)) != len(action_ids)
        ):
            raise ScanContinuationError("continuation parent actions are invalid")
        capabilities = tuple(sorted({
            str(item or "").strip() for item in self.required_capabilities
            if str(item or "").strip()
        }))
        if len(capabilities) > 32:
            raise ScanContinuationError("too many required continuation capabilities")
        allowed_capabilities = tuple(sorted({
            str(item or "").strip() for item in self.allowed_capabilities
            if str(item or "").strip()
        }))
        if self.schema_version == SCAN_CONTINUATION_ALLOCATION_SCHEMA_V1:
            allowed_capabilities = tuple(sorted(set(
                _LEGACY_CONTINUATION_CAPABILITIES
            ) | set(capabilities)))
        if len(allowed_capabilities) > 32:
            raise ScanContinuationError("too many allowed continuation capabilities")
        if set(capabilities) - set(allowed_capabilities):
            raise ScanContinuationError(
                "required continuation capabilities exceed the allowed families"
            )
        for name, value, maximum in (
            ("max_endpoint_entries", self.max_endpoint_entries, 100_000),
            ("max_candidate_entries", self.max_candidate_entries, 20_000),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ScanContinuationError(f"{name} is outside its bound")
        object.__setattr__(self, "scan_id", scan_id)
        object.__setattr__(self, "parent_plan_digest", _hex(
            self.parent_plan_digest, name="parent_plan_digest",
        ))
        object.__setattr__(self, "execution_plan_digest", _hex(
            self.execution_plan_digest, name="execution_plan_digest",
        ))
        object.__setattr__(self, "target_binding_digest", _hex(
            self.target_binding_digest, name="target_binding_digest",
        ))
        object.__setattr__(self, "parent_action_ids", action_ids)
        object.__setattr__(self, "budget_ceiling", _budget(self.budget_ceiling))
        object.__setattr__(self, "required_capabilities", capabilities)
        object.__setattr__(self, "allowed_capabilities", allowed_capabilities)
        expected = _digest(self.digest_material())
        if self.allocation_digest is not None and _hex(
            self.allocation_digest, name="allocation_digest",
        ) != expected:
            raise ScanContinuationError(
                "allocation_digest does not match continuation authority"
            )
        object.__setattr__(self, "allocation_digest", expected)

    def digest_material(self) -> dict[str, Any]:
        material = {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "parent_plan_digest": self.parent_plan_digest,
            "execution_plan_digest": self.execution_plan_digest,
            "target_binding_digest": self.target_binding_digest,
            "parent_action_ids": list(self.parent_action_ids),
            "budget_ceiling": dict(self.budget_ceiling),
            "max_endpoint_entries": self.max_endpoint_entries,
            "max_candidate_entries": self.max_candidate_entries,
            "required_capabilities": list(self.required_capabilities),
        }
        if self.schema_version != SCAN_CONTINUATION_ALLOCATION_SCHEMA_V1:
            material["allowed_capabilities"] = list(self.allowed_capabilities)
        return material

    def canonical_dict(self) -> dict[str, Any]:
        return {**self.digest_material(), "allocation_digest": self.allocation_digest}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScanContinuationAllocation":
        expected = {
            "schema_version", "scan_id", "parent_plan_digest",
            "execution_plan_digest", "target_binding_digest", "parent_action_ids",
            "budget_ceiling", "max_endpoint_entries", "max_candidate_entries",
            "required_capabilities", "allocation_digest",
        }
        if value.get("schema_version") == SCAN_CONTINUATION_ALLOCATION_SCHEMA:
            expected.add("allowed_capabilities")
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ScanContinuationError("continuation allocation fields are invalid")
        return cls(**dict(value))


@dataclass(frozen=True)
class ScanPlanRevision:
    """Content-free identity of the root plan or its sole amendment."""

    scan_id: str
    revision: int
    plan_digest: str
    parent_plan_digest: str | None = None
    continuation_allocation_digest: str | None = None
    discovery_result_digest: str | None = None
    work_manifest_references: tuple[Mapping[str, Any], ...] = ()
    continuation_plan_digest: str | None = None
    schema_version: str = SCAN_PLAN_REVISION_SCHEMA
    revision_digest: str | None = field(default=None, compare=True)

    def __post_init__(self) -> None:
        if self.schema_version != SCAN_PLAN_REVISION_SCHEMA:
            raise ScanContinuationError("unsupported Scan plan revision")
        try:
            scan_id = str(uuid.UUID(str(self.scan_id)))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ScanContinuationError("revision scan_id must be a UUID") from exc
        if isinstance(self.revision, bool) or self.revision not in {0, 1}:
            raise ScanContinuationError("Scan plan revision must be zero or one")
        references: list[Mapping[str, Any]] = []
        for raw in self.work_manifest_references:
            try:
                reference = ScanWorkManifestReference.from_dict(raw)
            except (TypeError, ValueError) as exc:
                raise ScanContinuationError(
                    "plan revision work manifest reference is invalid"
                ) from exc
            references.append(MappingProxyType(reference.canonical_dict()))
        references.sort(key=lambda item: (
            str(item["kind"]), str(item["manifest_digest"]),
            str(item["manifest_id"]),
        ))
        if len(references) > _MAX_ACTIONS or len({
            (item["kind"], item["manifest_digest"], item["manifest_id"])
            for item in references
        }) != len(references):
            raise ScanContinuationError(
                "plan revision work manifest references are invalid"
            )
        parent = (
            _hex(self.parent_plan_digest, name="parent_plan_digest")
            if self.parent_plan_digest is not None else None
        )
        allocation = (
            _hex(
                self.continuation_allocation_digest,
                name="continuation_allocation_digest",
            )
            if self.continuation_allocation_digest is not None else None
        )
        discovery = (
            _hex(self.discovery_result_digest, name="discovery_result_digest")
            if self.discovery_result_digest is not None else None
        )
        continuation = (
            _hex(self.continuation_plan_digest, name="continuation_plan_digest")
            if self.continuation_plan_digest is not None else None
        )
        if self.revision == 0:
            if (
                parent is not None
                or allocation is not None
                or discovery is not None
                or continuation is not None
                or references
            ):
                raise ScanContinuationError(
                    "root Scan plan revision must be allocation-free"
                )
        elif not all((parent, allocation, discovery, continuation)) or not references:
            raise ScanContinuationError(
                "amended Scan plan revision is missing its immutable chain"
            )
        object.__setattr__(self, "scan_id", scan_id)
        object.__setattr__(self, "plan_digest", _hex(
            self.plan_digest, name="plan_digest",
        ))
        object.__setattr__(self, "parent_plan_digest", parent)
        object.__setattr__(self, "continuation_allocation_digest", allocation)
        object.__setattr__(self, "discovery_result_digest", discovery)
        object.__setattr__(self, "continuation_plan_digest", continuation)
        object.__setattr__(self, "work_manifest_references", tuple(references))
        expected = _digest(self.digest_material())
        if self.revision_digest is not None and _hex(
            self.revision_digest, name="revision_digest",
        ) != expected:
            raise ScanContinuationError(
                "revision_digest does not match the Scan plan revision"
            )
        object.__setattr__(self, "revision_digest", expected)

    def digest_material(self) -> dict[str, Any]:
        material: dict[str, Any] = {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "revision": self.revision,
            "plan_digest": self.plan_digest,
        }
        if self.revision == 1:
            material.update({
                "parent_plan_digest": self.parent_plan_digest,
                "continuation_allocation_digest": (
                    self.continuation_allocation_digest
                ),
                "discovery_result_digest": self.discovery_result_digest,
                "work_manifest_references": [
                    dict(item) for item in self.work_manifest_references
                ],
                "continuation_plan_digest": self.continuation_plan_digest,
            })
        return material

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "revision": self.revision,
            "plan_digest": self.plan_digest,
            "parent_plan_digest": self.parent_plan_digest,
            "continuation_allocation_digest": (
                self.continuation_allocation_digest
            ),
            "discovery_result_digest": self.discovery_result_digest,
            "work_manifest_references": [
                dict(item) for item in self.work_manifest_references
            ],
            "continuation_plan_digest": self.continuation_plan_digest,
            "revision_digest": self.revision_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScanPlanRevision":
        expected = {
            "schema_version", "scan_id", "revision", "plan_digest",
            "parent_plan_digest", "continuation_allocation_digest",
            "discovery_result_digest", "work_manifest_references",
            "continuation_plan_digest", "revision_digest",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ScanContinuationError("Scan plan revision fields are invalid")
        return cls(**dict(value))


def root_scan_plan_revision(
    plan: ScanActionPlan,
) -> ScanPlanRevision:
    return ScanPlanRevision(
        scan_id=plan.scan_id,
        revision=0,
        plan_digest=str(plan.plan_digest),
    )


def scan_discovery_result_digest(
    results: Mapping[str, CapabilityResultReference],
) -> str:
    if not results:
        raise ScanContinuationError("discovery result set is empty")
    return _digest({
        "schema_version": SCAN_DISCOVERY_RESULT_SET_SCHEMA,
        "results": [
            results[action_id].canonical_dict()
            for action_id in sorted(results)
        ],
    })


def amended_scan_plan_revision(
    *,
    parent_plan: ScanActionPlan,
    continuation_plan: ScanActionPlan,
    amended_plan: ScanActionPlan,
    allocation: ScanContinuationAllocation,
    discovery_results: Mapping[str, CapabilityResultReference],
    work_manifest_references: tuple[Mapping[str, Any], ...],
) -> ScanPlanRevision:
    if (
        allocation.parent_plan_digest != parent_plan.plan_digest
        or amended_plan.scan_id != parent_plan.scan_id
        or set(discovery_results) != set(allocation.parent_action_ids)
        or tuple(amended_plan.actions[:len(parent_plan.actions)])
        != parent_plan.actions
    ):
        raise ScanContinuationError(
            "Scan plan revision differs from its immutable amendment inputs"
        )
    return ScanPlanRevision(
        scan_id=amended_plan.scan_id,
        revision=1,
        plan_digest=str(amended_plan.plan_digest),
        parent_plan_digest=str(parent_plan.plan_digest),
        continuation_allocation_digest=allocation.allocation_digest,
        discovery_result_digest=scan_discovery_result_digest(discovery_results),
        work_manifest_references=work_manifest_references,
        continuation_plan_digest=str(continuation_plan.plan_digest),
    )


def merge_scan_action_continuation(
    *,
    parent_plan: ScanActionPlan,
    continuation_plan: ScanActionPlan,
    allocation: ScanContinuationAllocation,
) -> ScanActionPlan:
    """Append a digest-bound continuation without changing executed actions."""
    if (
        parent_plan.scan_id != allocation.scan_id
        or parent_plan.plan_digest != allocation.parent_plan_digest
        or parent_plan.execution_plan_digest != allocation.execution_plan_digest
        or parent_plan.target_binding_digest != allocation.target_binding_digest
        or tuple(action.action_id for action in parent_plan.actions)
        != allocation.parent_action_ids
    ):
        raise ScanContinuationError(
            "continuation allocation differs from its immutable parent plan"
        )
    if (
        continuation_plan.scan_id != parent_plan.scan_id
        or continuation_plan.execution_plan_digest != parent_plan.execution_plan_digest
        or continuation_plan.target_binding_digest != parent_plan.target_binding_digest
    ):
        raise ScanContinuationError(
            "continuation plan differs from parent Scan authority"
        )
    finalizers = [
        action for action in continuation_plan.actions
        if action.action_id == "finalize.report"
    ]
    if len(finalizers) != 1:
        raise ScanContinuationError(
            "continuation plan must contain exactly one finalizer"
        )

    parent_by_id = {
        action.action_id: action for action in parent_plan.actions
    }
    parent_ids = set(parent_by_id)
    appended: list[ScanAction] = []
    for action in continuation_plan.actions:
        if action.action_id == "finalize.report":
            continue
        if action.action_id in parent_ids:
            if action.action_id.startswith((
                "inputs.auth_", "inputs.collection_",
            )):
                parent_action = parent_by_id[action.action_id]
                if (
                    action.capability_name != parent_action.capability_name
                    or action.capability_args != parent_action.capability_args
                    or action.target_binding_digest
                    != parent_action.target_binding_digest
                ):
                    raise ScanContinuationError(
                        "continuation changed credential or collection authority: "
                        f"{action.action_id}"
                    )
                continue
            raise ScanContinuationError(
                f"continuation action duplicates parent authority: {action.action_id}"
            )
        if action.action_id.startswith(("inputs.auth_", "inputs.collection_")):
            raise ScanContinuationError(
                f"continuation introduced new private input authority: {action.action_id}"
            )
        if action.capability_name not in set(allocation.allowed_capabilities):
            raise ScanContinuationError(
                "continuation introduced a capability outside its allocation: "
                f"{action.capability_name}"
            )
        appended.append(action)

    consumed = {name: 0 for name in allocation.budget_ceiling}
    for action in (*appended, finalizers[0]):
        for name, amount in action.requested_budget.items():
            if name not in consumed:
                raise ScanContinuationError(
                    f"continuation action uses undeclared budget: {name}"
                )
            consumed[name] += amount
    shortages = {
        name: consumed[name] - allocation.budget_ceiling[name]
        for name in consumed
        if consumed[name] > allocation.budget_ceiling[name]
    }
    if shortages:
        raise ScanContinuationError(
            f"continuation exceeds its upfront allocation: {shortages}"
        )

    actions: list[ScanAction] = list(parent_plan.actions)
    for action in appended:
        actions.append(replace(
            action, ordinal=len(actions), action_digest=None,
        ))
    finalizer = replace(
        finalizers[0],
        ordinal=len(actions),
        dependencies=tuple(action.action_id for action in actions),
        action_digest=None,
    )
    actions.append(finalizer)
    if len(actions) > _MAX_ACTIONS:
        raise ScanContinuationError("continued Scan plan exceeds its action bound")
    try:
        return ScanActionPlan(
            scan_id=parent_plan.scan_id,
            execution_plan_digest=parent_plan.execution_plan_digest,
            target_binding_digest=parent_plan.target_binding_digest,
            actions=tuple(actions),
        )
    except ScanActionPlanError as exc:
        raise ScanContinuationError(str(exc)) from exc


def build_discovery_continuation_manifests(
    *,
    allocation: ScanContinuationAllocation,
    target_url: str,
    target: TargetBinding,
    options: Mapping[str, Any],
    action_results: Mapping[str, CapabilityResultReference],
    observations: Mapping[str, tuple[Mapping[str, Any], ...]],
    request_manifests: tuple[ScanWorkManifest, ...] = (),
) -> tuple[ScanWorkManifest, ScanWorkManifest]:
    """Normalize terminal discovery receipts into exact continuation manifests."""
    if (
        target.digest != allocation.target_binding_digest
        or set(action_results) != set(allocation.parent_action_ids)
    ):
        raise ScanContinuationError(
            "discovery receipts differ from continuation target authority"
        )

    def summary(action_ids: tuple[str, ...]) -> dict[str, Any]:
        rows = [
            action_results[action_id]
            for action_id in action_ids if action_id in action_results
        ]
        combined = [
            dict(item)
            for action_id in action_ids
            for item in observations.get(action_id, ())
        ]
        statuses = {row.status.value for row in rows}
        if "cancelled" in statuses:
            status = "cancelled"
        elif statuses & {"failed", "blocked", "timed_out"}:
            status = "failed"
        elif "partial" in statuses:
            status = "partial"
        elif rows and statuses <= {"success", "skipped"}:
            status = "success"
        else:
            status = "skipped"
        reasons = sorted({
            row.reason_code.value
            for row in rows if row.reason_code is not None
        })
        return {
            "status": status,
            "reason": ";".join(reasons)[:200] or None,
            "observations": combined,
        }

    collection_ids = tuple(sorted(
        action_id for action_id in action_results
        if action_id.startswith("inputs.collection_")
    ))
    surface = build_scan_surface_manifest(
        target_url=target_url,
        target=target,
        options=options,
        collection_replay=summary(collection_ids),
        subdomains=summary(("discover.subdomains",)),
        probe=summary(("discover.web_probe",)),
        crawl=summary(("discover.web_crawl",)),
        browser=summary(("discover.browser_crawl",)),
        content=summary(("discover.web_content",)),
        max_endpoints=allocation.max_endpoint_entries,
    )
    request_refs_by_route: dict[str, list[str]] = {}
    auth_lane_by_route: dict[str, str] = {}
    for manifest in request_manifests:
        for entry in manifest.entries:
            route = str(entry.get("route_id") or "")
            request_ref = str(entry.get("request_ref_id") or "")
            if not route or not request_ref:
                continue
            request_refs_by_route.setdefault(route, []).append(request_ref)
            lane = str(entry.get("auth_lane") or "anonymous")
            if lane != "anonymous":
                auth_lane_by_route[route] = lane
    source_action_ids = tuple(
        action_id for action_id in allocation.parent_action_ids
        if action_id.startswith("discover.")
        or action_id.startswith("inputs.collection_")
    ) or (allocation.parent_action_ids[0],)
    endpoints = build_endpoint_manifest(
        scan_id=allocation.scan_id,
        target_binding_digest=target.digest,
        surface_manifest=surface,
        source_action_ids=source_action_ids,
        auth_lane="anonymous",
        request_ref_ids_by_route={
            route: tuple(dict.fromkeys(values))
            for route, values in request_refs_by_route.items()
        },
        auth_lane_by_route=auth_lane_by_route,
    )
    scan_policy = options.get("scan_policy")
    candidates = build_candidate_manifest(
        endpoints,
        source_action_ids=source_action_ids,
        maximum=allocation.max_candidate_entries,
        # Continuation rebuilds the candidate manifest the plan actually executes, so it needs the
        # same authority as admission. Reading it from the persisted policy keeps the two from
        # disagreeing: they did, and the plan ran against an empty manifest while admission's
        # carried the body candidates.
        allow_state_changing_http=bool(
            isinstance(scan_policy, Mapping)
            and scan_policy.get("allow_state_changing_http")
        ),
    )
    return endpoints, candidates


__all__ = [
    "ContinuationBudgetCeiling",
    "SCAN_CONTINUATION_ALLOCATION_SCHEMA",
    "SCAN_CONTINUATION_ALLOCATION_SCHEMA_V1",
    "ScanContinuationAllocation",
    "ScanContinuationError",
    "ScanPlanRevision",
    "amended_scan_plan_revision",
    "build_discovery_continuation_manifests",
    "merge_scan_action_continuation",
    "root_scan_plan_revision",
    "scan_discovery_result_digest",
]
