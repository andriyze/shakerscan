"""One typed execution boundary for canonical Hunt capability adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping, Protocol

try:
    from runtime.capability_registry import CapabilitySpec
    from runtime.models import TargetBinding
except ModuleNotFoundError:  # package imports in host-side tests
    from ..runtime.capability_registry import CapabilitySpec
    from ..runtime.models import TargetBinding


Heartbeat = Callable[[], Awaitable[None]]
Cancelled = Callable[[], bool]


@dataclass(frozen=True)
class CapabilityAdapterResult:
    status: str
    observations: tuple[Mapping[str, Any], ...] = ()
    errors: tuple[str, ...] = ()
    actual_budget: Mapping[str, int] = field(default_factory=dict)
    partial: bool = False
    timed_out: bool = False
    execution_started: bool = False
    parser_version: str = "canonical/v1"
    redacted_execution: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in {"success", "partial", "failed", "blocked", "cancelled"}:
            raise ValueError("capability adapter returned an invalid status")
        if self.timed_out and not self.partial:
            raise ValueError("timed out capability results must be partial")


class ExecutableCapabilityAdapter(Protocol):
    capability_name: str
    adapter_name: str
    adapter_version: str

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult: ...


@dataclass(frozen=True)
class CapabilityExecutionContext:
    specification: CapabilitySpec
    target: TargetBinding
    requested_budget: Mapping[str, int]
    adapter_managed_cancellation: bool = False


class CapabilityExecutor:
    """Validate one adapter, execute it once, and clamp measured consumption."""

    async def execute(
        self,
        context: CapabilityExecutionContext,
        adapter: ExecutableCapabilityAdapter,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        spec = context.specification
        if adapter.capability_name != spec.name:
            raise ValueError("capability adapter name does not match the registry")
        if adapter.adapter_name != spec.adapter:
            raise ValueError("capability adapter implementation does not match the registry")
        if adapter.adapter_version != spec.adapter_version:
            raise ValueError("capability adapter version does not match the registry")
        if context.adapter_managed_cancellation and not bool(
            getattr(adapter, "manages_cancellation", False)
        ):
            raise ValueError(
                "capability adapter does not implement managed cancellation"
            )
        if context.target.target_kind not in spec.target_kinds:
            raise ValueError("capability does not support the bound target kind")
        requested = {
            str(name): int(amount)
            for name, amount in dict(context.requested_budget).items()
        }
        if any(not name or amount < 0 for name, amount in requested.items()):
            raise ValueError("requested capability budget is invalid")
        if cancelled() and not context.adapter_managed_cancellation:
            return self._normalize(
                CapabilityAdapterResult(
                    status="cancelled",
                    errors=("cancelled_before_execution",),
                    actual_budget={"agent_actions": 1},
                ),
                requested,
            )
        try:
            result = await adapter.execute(
                heartbeat=heartbeat,
                cancelled=cancelled,
            )
        except Exception as exc:
            # An adapter exception cannot prove which in-flight browser or socket
            # operations completed. Charge the full hold and let the caller persist
            # a terminal failure rather than guessing that target traffic was zero.
            return CapabilityAdapterResult(
                status="failed",
                errors=(f"adapter_fault:{type(exc).__name__}",),
                actual_budget=requested,
                execution_started=True,
                parser_version=f"{adapter.adapter_name}/{adapter.adapter_version}",
            )
        return self._normalize(result, requested)

    @staticmethod
    def _normalize(
        result: CapabilityAdapterResult,
        requested: Mapping[str, int],
    ) -> CapabilityAdapterResult:
        actual: dict[str, int] = {}
        for name, amount in dict(result.actual_budget).items():
            if name not in requested:
                continue
            actual[name] = min(int(requested[name]), max(0, int(amount)))
        if "agent_actions" in requested:
            actual["agent_actions"] = min(1, int(requested["agent_actions"]))
        if "active_actions" in requested and result.execution_started:
            actual["active_actions"] = min(1, int(requested["active_actions"]))
        return CapabilityAdapterResult(
            status=result.status,
            observations=tuple(dict(item) for item in result.observations),
            errors=tuple(str(item) for item in result.errors),
            actual_budget=actual,
            partial=result.partial,
            timed_out=result.timed_out,
            execution_started=result.execution_started,
            parser_version=result.parser_version,
            redacted_execution=dict(result.redacted_execution),
        )
