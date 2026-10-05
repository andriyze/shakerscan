"""Shared-executor adapter for exact request-collection replay."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
from runtime.capability_registry import CapabilitySpec
from runtime.request_replay_executor import execute_replay_plan
from hunt.service_binding import replay_uses_service_origin
from hunt.target_binding import web_hunt_target



REPLAY_CAPABILITIES = frozenset({"collections.replay_safe", "collections.replay_active"})


def require_hunt_replay_authority(
    capability_name: str, policy: Mapping[str, Any], *, replay_policy: str | None = None,
) -> bool:
    """A live saved write grant enables exact replay; a tool name never grants it."""
    if capability_name not in REPLAY_CAPABILITIES:
        raise ValueError("unknown Hunt replay capability")
    active = capability_name == "collections.replay_active"
    if active:
        if policy.get("active_testing") is not True or policy.get("allow_state_changing_http") is not True:
            raise ValueError("active replay requires the Hunt's existing state-changing HTTP permission")
        if replay_policy is not None and replay_policy != "confirmed_active":
            raise ValueError("active replay requires a bound confirmed_active collection selection")
    elif replay_policy == "discovery_only":
        raise ValueError("the bound collection is discovery-only")
    return active

async def revalidate_hunt_replay_authority(conn: Any, *, run: Mapping[str, Any], target: Any,
    target_url: str, capability_name: str, replay_policy: str, revalidate: Any) -> None:
    """Revalidate the same saved authority before decrypting and between writes."""
    import json
    from runtime.models import ScanPolicy
    policy = run["policy_json"]
    policy = json.loads(policy) if isinstance(policy, str) else policy
    require_hunt_replay_authority(capability_name, policy, replay_policy=replay_policy)
    if capability_name not in policy.get("allowed_capabilities", ()):
        raise ValueError("replay is outside the persisted Hunt manifest")
    await revalidate(conn, run=run, target=target, target_url=target_url,
        policy=ScanPolicy(active_testing=bool(policy.get("active_testing")),
            allow_state_changing_http=bool(policy.get("allow_state_changing_http")),
            scope_receipt_id=target.scope_receipt_id,
            approval_receipt_id=policy.get("approval_receipt_id")), capability_name=capability_name)


def hunt_replay_additional_budget(
    *, wall_seconds: int, device_requests: int = 0, managed_principal: bool = False,
    uses_service_origin: bool = False, active_replay: bool = False,
) -> dict[str, int]:
    """Reserve Hunt dimensions owned by the worker alongside the exact replay plan."""
    budget = {
        "agent_actions": 1,
        "tool_wall_seconds": max(1, min(int(wall_seconds), 300)),
    }
    if device_requests:
        budget["device_fragility_points"] = int(device_requests)
    if managed_principal or uses_service_origin or active_replay:
        budget["active_actions"] = 1
    return budget


def worker_hunt_replay_budget(
    *, run: Mapping[str, Any], context: Mapping[str, Any], policy: Mapping[str, Any],
    origins: Sequence[str], wall_seconds: int, request_count: int, managed_principal: bool,
    active_replay: bool = False,
) -> dict[str, int]:
    """Derive the durable worker charge from revalidated server-owned selection.

    Do not trust an active/passive flag supplied by the planner or queued caller.
    Reuse the same normalized-origin predicate as admission, and never ask the
    operator for another receipt merely because the selected port changed.
    """
    original, _ = web_hunt_target(run, context, policy)
    return hunt_replay_additional_budget(
        wall_seconds=wall_seconds,
        device_requests=request_count if run.get("device_target_id") else 0,
        managed_principal=managed_principal,
        uses_service_origin=replay_uses_service_origin(original, origins),
        active_replay=active_replay,
    )


class ReplayExecutionAdapter:
    """Run the durable exact-replay engine behind the canonical capability seam."""

    manages_cancellation = True

    def __init__(
        self,
        *,
        specification: CapabilitySpec,
        execution_kwargs: Mapping[str, Any],
    ) -> None:
        self.capability_name = specification.name
        self.adapter_name = specification.adapter
        self.adapter_version = specification.adapter_version
        self._execution_kwargs = dict(execution_kwargs)
        self.outcome: Any | None = None

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        # The exact replay engine persists a heartbeat after each request and
        # owns the reservation transition callbacks supplied by the worker.
        # ``heartbeat`` is therefore represented by those durable callbacks.
        del heartbeat
        outcome = await execute_replay_plan(
            **self._execution_kwargs,
            cancelled=cancelled,
        )
        self.outcome = outcome
        receipt = outcome.receipt
        status = {
            "succeeded": "success",
            "partial": "partial",
            "cancelled": "cancelled",
            "blocked": "blocked",
        }.get(str(outcome.status), "failed")
        actual = dict(outcome.reservation.actual)
        return CapabilityAdapterResult(
            status=status,
            observations=tuple(
                dict(item) for item in receipt.observations
                if isinstance(item, Mapping)
            ),
            errors=tuple(str(item) for item in receipt.errors),
            actual_budget=actual,
            partial=bool(receipt.partial),
            timed_out=bool(receipt.timed_out),
            execution_started=(
                int(actual.get("http_requests") or 0) > 0
                or int(actual.get("state_changing_requests") or 0) > 0
            ),
            parser_version=str(receipt.parser_version),
            redacted_execution=dict(receipt.redacted_execution),
        )


class RecordedReplayTransport:
    """Archive the exact request plan and bounded response through the existing store.

    The transport may add framing headers, so fidelity is explicitly plan-level,
    not a complete packet capture. Values go only to the private archive callback.

    ``principal_slot`` is recorded as given; ``None`` means the transport carries more
    than one principal (or none is known) and no single slot can be claimed. ``private``
    marks rows whose header and body values may be workflow secrets under arbitrary
    names, so masked archive views withhold them.
    """

    def __init__(
        self, transport: Any, recorder: Any, *, principal_slot: str | None,
        private: bool = False,
    ) -> None:
        self.transport, self.recorder, self.principal_slot = transport, recorder, principal_slot
        self.private = private

    async def send(self, request: Any, **kwargs: Any) -> Any:
        from datetime import datetime, timezone
        started_at = datetime.now(timezone.utc)
        result = None
        try:
            result = await self.transport.send(request, **kwargs)
            return result
        finally:
            self.recorder({"method": request.method, "url": request.url,
                "request_headers": dict(request.headers), "request_body": request.body,
                "response_headers": dict(result.response_headers) if result else None,
                "response_body": result.response_body if result else None,
                "status_code": result.status_code if result else None,
                "remote_ip": result.connected_address if result else None,
                "elapsed_ms": result.elapsed_ms if result else None,
                "error": result.error_code if result else "cancelled_or_failed",
                "response_body_truncated": result is None or bool(result.error_code),
                "started_at": started_at, "principal_slot": self.principal_slot,
                "workflow_values_private": self.private,
                "fidelity": "exact_replay_plan_bounded_response"})


class RecordedHuntReplayTransport(RecordedReplayTransport):
    """Hunt replay acts as exactly one principal; an unnamed one is anonymous."""

    def __init__(self, transport: Any, recorder: Any, *, principal_slot: str | None) -> None:
        super().__init__(transport, recorder, principal_slot=principal_slot or "anonymous")
