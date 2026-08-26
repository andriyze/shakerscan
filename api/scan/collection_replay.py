"""Scan-specific admission helpers for the shared exact request replay executor.

This module does not implement another replay engine.  It converts the immutable
Scan policy/budget plus one saved collection selection into the contracts consumed by
``runtime.request_replay_executor.execute_replay_plan``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

try:
    from runtime.request_collection_store import RequestCollectionSelection
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.request_collection_store import RequestCollectionSelection

try:
    from scanner_tools.request_collections import RequestSelector
    from scanner_tools.request_replay import ReplayAuthorization, ReplayPlan
except ModuleNotFoundError:  # package import in host-side tests
    from scanner.scanner_tools.request_collections import RequestSelector
    from scanner.scanner_tools.request_replay import ReplayAuthorization, ReplayPlan

from .capability_execution import scan_budget_ledger_limits
from .work_manifests import ScanWorkManifest


EXECUTABLE_REPLAY_POLICIES = frozenset({
    "safe_reads", "safe_authentication", "confirmed_active",
})


class ScanCollectionReplayContractError(ValueError):
    """Saved replay input cannot execute under the immutable Scan contract."""


def validate_scan_replay_request_manifest(
    plan: Any,
    manifest: ScanWorkManifest,
) -> None:
    """Fail closed if decrypted replay work differs from its public manifest."""
    expected_requests = tuple(
        (
            str(item["request_ref_id"]),
            str(item["method"]),
            str(item["request_class"]),
        )
        for item in manifest.entries
    )
    actual_requests = tuple(
        (
            request.request_id,
            request.method,
            (
                "safe_read"
                if request.method in {"GET", "HEAD", "OPTIONS"}
                else "safe_authentication"
                if plan.authorization.safe_authentication_only
                else "confirmed_mutation"
            ),
        )
        for request in plan.requests
    )
    if actual_requests != expected_requests:
        raise ScanCollectionReplayContractError(
            "decrypted replay plan differs from its immutable request manifest"
        )


def narrow_replay_plan_to_request_manifest(
    plan: ReplayPlan,
    manifest: ScanWorkManifest,
) -> ReplayPlan:
    """Project a decrypted saved selection onto one child's exact authority.

    Parallel children may resolve the same encrypted selection artifact, but
    they may execute only the opaque request references assigned to their own
    immutable manifest.  Rebuilding ordinals makes the resulting private plan
    independently sealable for a broker lease.
    """
    if manifest.kind.value != "request":
        raise ScanCollectionReplayContractError(
            "exact replay authority requires a request manifest"
        )
    by_id = {request.request_id: request for request in plan.requests}
    if len(by_id) != len(plan.requests):
        raise ScanCollectionReplayContractError(
            "decrypted replay plan contains ambiguous request references"
        )
    expected_ids = [str(entry["request_ref_id"]) for entry in manifest.entries]
    if len(set(expected_ids)) != len(expected_ids):
        raise ScanCollectionReplayContractError(
            "immutable request manifest contains ambiguous references"
        )
    missing = [request_id for request_id in expected_ids if request_id not in by_id]
    if missing:
        raise ScanCollectionReplayContractError(
            "decrypted replay plan is missing child request authority"
        )
    narrowed = ReplayPlan(
        requests=tuple(
            replace(by_id[request_id], ordinal=index)
            for index, request_id in enumerate(expected_ids)
        ),
        allowed_origins=plan.allowed_origins,
        default_origin=plan.default_origin,
        authorization=plan.authorization,
        schema_version=plan.schema_version,
    )
    validate_scan_replay_request_manifest(narrowed, manifest)
    return narrowed


def _positive_integer(value: Any, *, name: str) -> int:
    if isinstance(value, bool):
        raise ScanCollectionReplayContractError(f"{name} must be a positive integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ScanCollectionReplayContractError(
            f"{name} must be a positive integer"
        ) from exc
    if result <= 0:
        raise ScanCollectionReplayContractError(f"{name} must be a positive integer")
    return result


def scan_replay_authorization(
    replay_policy: Any,
    scan_policy: Mapping[str, Any],
    *,
    approval_receipt_id: Any = None,
) -> ReplayAuthorization:
    """Derive exact wire authority from server-owned Scan policy.

    Safe replay never inherits active permission.  Confirmed active replay requires
    all three independent signals even if the imported collection itself contains a
    state-changing request.
    """
    policy = str(replay_policy or "").strip().lower()
    if policy not in EXECUTABLE_REPLAY_POLICIES:
        raise ScanCollectionReplayContractError(
            "collection replay policy is not executable by Scan"
        )
    if policy == "safe_reads":
        return ReplayAuthorization()
    active_testing = scan_policy.get("active_testing") is True
    allow_state_changing = scan_policy.get("allow_state_changing_http") is True
    approval = str(
        approval_receipt_id
        or scan_policy.get("approval_receipt_id")
        or ""
    ).strip()
    if policy == "safe_authentication":
        if not active_testing:
            raise ScanCollectionReplayContractError(
                "safe_authentication collection replay requires active_testing"
            )
        if not approval:
            raise ScanCollectionReplayContractError(
                "safe_authentication collection replay requires a target-bound approval receipt"
            )
        return ReplayAuthorization(
            active_testing=True,
            approval_receipt_id=approval,
            safe_authentication_only=True,
        )

    if not active_testing:
        raise ScanCollectionReplayContractError(
            "confirmed_active collection replay requires active_testing"
        )
    if not allow_state_changing:
        raise ScanCollectionReplayContractError(
            "confirmed_active collection replay requires state-changing HTTP permission"
        )
    if not approval:
        raise ScanCollectionReplayContractError(
            "confirmed_active collection replay requires a target-bound approval receipt"
        )
    return ReplayAuthorization(
        active_testing=True,
        allow_state_changing_http=True,
        approval_receipt_id=approval,
    )


def scan_replay_selector(
    selection: RequestCollectionSelection,
    replay_policy: Any,
    *,
    runtime_limit: int,
) -> RequestSelector:
    """Preserve the saved selection while applying runtime budget narrowing."""
    policy = str(replay_policy or "").strip().lower()
    if policy not in EXECUTABLE_REPLAY_POLICIES:
        raise ScanCollectionReplayContractError(
            "collection replay policy is not executable by Scan"
        )
    limit = min(
        selection.max_requests,
        _positive_integer(runtime_limit, name="collection replay runtime_limit"),
        2_000,
    )
    return RequestSelector(
        request_ids=selection.request_ids,
        folders=selection.folders,
        methods=selection.methods,
        path_regex=selection.path_regex,
        tags=selection.tags,
        # A safe replay remains read-only even if a corrupted stored selector says
        # otherwise.  Confirmed active still honors a user's stricter saved selector.
        safe_methods_only=(
            True if policy == "safe_reads" else selection.safe_methods_only
        ),
        limit=limit,
    )


def scan_replay_ledger_limits(budget: Mapping[str, Any]) -> dict[str, int]:
    """Map the canonical Scan budget into shared reservation dimensions.

    A parallel child receives zero for dimensions it cannot execute. Exact HTTP
    replay still requires positive request/time authority, but it must not reject
    a child merely because browser, network, or host-discovery capacity is zero.
    """
    limits = scan_budget_ledger_limits(budget, allow_zero=True)
    _positive_integer(
        limits.get("http_requests"), name="Scan max_http_requests",
    )
    _positive_integer(
        limits.get("tool_wall_seconds"), name="Scan max_tool_wall_seconds",
    )
    return limits


def scan_replay_runtime_http_ceiling(
    options: Mapping[str, Any], budget: Mapping[str, Any],
) -> int:
    """Resolve the exact replay HTTP ceiling without mixing budget dimensions.

    Compatibility scans reserve domain-rate capacity in active-endpoint units and
    still use the historical ``request_budget_reserved`` field.  That value is an
    HTTP ceiling only when request-budget enforcement is authoritative.
    """
    candidates = [
        _positive_integer(
            budget.get("max_http_requests"), name="Scan max_http_requests"
        )
    ]
    custom = options.get("custom_budget")
    if isinstance(custom, Mapping) and custom.get("request_max") is not None:
        candidates.append(
            _positive_integer(
                custom.get("request_max"), name="Scan custom request_max"
            )
        )
    request_budget_mode = str(
        options.get("request_budget_mode") or "compatibility"
    ).strip().lower()
    if (
        request_budget_mode == "enforce"
        and options.get("request_budget_reserved") is not None
    ):
        candidates.append(
            _positive_integer(
                options.get("request_budget_reserved"),
                name="Scan reserved request budget",
            )
        )
    return min(candidates)


@dataclass(frozen=True)
class ScanReplayCapacity:
    http_requests: int
    tool_wall_seconds: int


def remaining_scan_replay_capacity(
    *,
    limits: Mapping[str, int],
    consumed: Mapping[str, Any],
    runtime_http_ceiling: int | None = None,
    reserve_http_requests: int = 1,
    reserve_tool_wall_seconds: int = 1,
) -> ScanReplayCapacity:
    """Return replay capacity while retaining a minimal deterministic baseline lane."""
    http_limit = _positive_integer(
        limits.get("http_requests"), name="Scan HTTP ledger limit"
    )
    if runtime_http_ceiling is not None:
        http_limit = min(
            http_limit,
            _positive_integer(runtime_http_ceiling, name="runtime HTTP ceiling"),
        )
    wall_limit = _positive_integer(
        limits.get("tool_wall_seconds"), name="Scan wall-time ledger limit"
    )
    used_http = max(0, int(consumed.get("http_requests") or 0))
    used_wall = max(0, int(consumed.get("tool_wall_seconds") or 0))
    return ScanReplayCapacity(
        http_requests=max(0, http_limit - used_http - max(0, reserve_http_requests)),
        tool_wall_seconds=max(
            0, wall_limit - used_wall - max(0, reserve_tool_wall_seconds)
        ),
    )


def merge_scan_budget_usage(
    persisted: Mapping[str, Any], produced: Mapping[str, Any],
) -> dict[str, int]:
    """Add independent executor usage without erasing already settled reservations."""
    merged: dict[str, int] = {}
    for source in (persisted, produced):
        for raw_name, raw_value in dict(source or {}).items():
            name = str(raw_name or "").strip()
            if not name or isinstance(raw_value, bool):
                continue
            try:
                value = int(raw_value)
            except (TypeError, ValueError):
                continue
            if value < 0:
                continue
            merged[name] = int(merged.get(name) or 0) + value
    return merged
