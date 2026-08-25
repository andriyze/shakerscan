"""One registry-driven dispatch boundary for every native Hunt action.

The dispatcher deliberately does not encode lists of capabilities.  The
canonical registry owns adapter identity, supported target kinds, placement,
risk, and evidence contracts.  Control-plane and worker callers use this same
object to resolve an action and, where execution is local to the caller, to
construct and execute its registered adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

try:
    from hunt.capability_executor import (
        Cancelled,
        CapabilityAdapterResult,
        CapabilityExecutionContext,
        CapabilityExecutor,
        ExecutableCapabilityAdapter,
        Heartbeat,
    )
    from runtime.capability_registry import (
        CAPABILITY_REGISTRY,
        CapabilityRegistry,
        CapabilitySpec,
        HuntExecutor,
    )
    from runtime.models import TargetBinding
except ModuleNotFoundError:  # package imports in host-side tests
    from .capability_executor import (
        Cancelled,
        CapabilityAdapterResult,
        CapabilityExecutionContext,
        CapabilityExecutor,
        ExecutableCapabilityAdapter,
        Heartbeat,
    )
    from ..runtime.capability_registry import (
        CAPABILITY_REGISTRY,
        CapabilityRegistry,
        CapabilitySpec,
        HuntExecutor,
    )
    from ..runtime.models import TargetBinding


AdapterProvider = Callable[
    [CapabilitySpec, "HuntActionRequest"], ExecutableCapabilityAdapter
]


class HuntDispatchError(ValueError):
    """A Hunt action cannot be resolved through the canonical runtime."""


class HuntAdapterFactory(Protocol):
    def create(
        self, specification: CapabilitySpec, request: "HuntActionRequest"
    ) -> ExecutableCapabilityAdapter: ...


@dataclass(frozen=True)
class RegisteredHuntAdapterFactory:
    """Resolve adapter implementations by the registry's exact adapter ID."""

    providers: Mapping[str, AdapterProvider]

    def create(
        self, specification: CapabilitySpec, request: "HuntActionRequest"
    ) -> ExecutableCapabilityAdapter:
        provider = self.providers.get(specification.adapter)
        if provider is None:
            raise HuntDispatchError(
                f"no Hunt adapter provider is registered for {specification.adapter}"
            )
        adapter = provider(specification, request)
        if (
            adapter.capability_name != specification.name
            or adapter.adapter_name != specification.adapter
            or adapter.adapter_version != specification.adapter_version
        ):
            raise HuntDispatchError(
                "Hunt adapter factory returned an implementation outside registry authority"
            )
        return adapter


@dataclass(frozen=True)
class HuntActionRequest:
    """Target-independent action schema shared by every Hunt target kind."""

    hunt_id: str
    action_id: str
    capability_name: str
    target: TargetBinding
    capability_input: Mapping[str, Any] = field(default_factory=dict)
    requested_budget: Mapping[str, int] = field(default_factory=dict)
    reservation_id: str | None = None
    action_digest: str | None = None

    def __post_init__(self) -> None:
        if not str(self.hunt_id).strip() or not str(self.action_id).strip():
            raise HuntDispatchError("Hunt action identity is required")
        if not str(self.capability_name).strip():
            raise HuntDispatchError("Hunt capability name is required")
        if any(
            not str(name).strip() or isinstance(amount, bool) or int(amount) < 0
            for name, amount in dict(self.requested_budget).items()
        ):
            raise HuntDispatchError("Hunt action budget is invalid")


@dataclass(frozen=True)
class HuntActionResult:
    """One result schema for web, API, network, and device Hunt actions."""

    hunt_id: str
    action_id: str
    capability_name: str
    target_kind: str
    placement: HuntExecutor
    status: str
    observations: tuple[Mapping[str, Any], ...] = ()
    errors: tuple[str, ...] = ()
    actual_budget: Mapping[str, int] = field(default_factory=dict)
    partial: bool = False
    timed_out: bool = False
    execution_started: bool = False
    parser_version: str = "canonical/v1"
    redacted_execution: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_execution(
        cls,
        request: HuntActionRequest,
        specification: CapabilitySpec,
        result: CapabilityAdapterResult,
    ) -> "HuntActionResult":
        if specification.hunt_executor is None:
            raise HuntDispatchError("Hunt capability has no placement metadata")
        return cls(
            hunt_id=request.hunt_id,
            action_id=request.action_id,
            capability_name=specification.name,
            target_kind=request.target.target_kind,
            placement=specification.hunt_executor,
            status=result.status,
            observations=tuple(dict(item) for item in result.observations),
            errors=tuple(result.errors),
            actual_budget=dict(result.actual_budget),
            partial=result.partial,
            timed_out=result.timed_out,
            execution_started=result.execution_started,
            parser_version=result.parser_version,
            redacted_execution=dict(result.redacted_execution),
        )

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "hunt-action-result/v2",
            "hunt_id": self.hunt_id,
            "action_id": self.action_id,
            "capability": self.capability_name,
            "target_kind": self.target_kind,
            "placement": self.placement,
            "status": self.status,
            "observations": [dict(item) for item in self.observations],
            "errors": list(self.errors),
            "budget_consumed": dict(self.actual_budget),
            "partial": self.partial,
            "timed_out": self.timed_out,
            "execution_started": self.execution_started,
            "parser_version": self.parser_version,
            "redacted_execution": dict(self.redacted_execution),
        }


class HuntActionDispatcher:
    """Resolve and execute native Hunt actions without capability-set routing."""

    def __init__(
        self,
        *,
        registry: CapabilityRegistry = CAPABILITY_REGISTRY,
        executor: CapabilityExecutor | None = None,
    ) -> None:
        self.registry = registry
        self.executor = executor or CapabilityExecutor()

    def require(self, capability_name: str) -> CapabilitySpec:
        try:
            spec = self.registry.require(capability_name)
        except KeyError as exc:
            raise HuntDispatchError(str(exc)) from exc
        if not spec.planner_visible or spec.hunt_executor is None:
            raise HuntDispatchError(
                "capability is not exposed to the native Hunt runtime"
            )
        return spec

    def placement(self, capability_name: str) -> HuntExecutor:
        placement = self.require(capability_name).hunt_executor
        if placement is None:  # narrowed by require(), retained for type checkers
            raise HuntDispatchError("capability has no Hunt placement")
        return placement

    def has_placement(
        self, capability_name: str, *placements: HuntExecutor
    ) -> bool:
        return self.placement(capability_name) in placements

    def validate(
        self, request: HuntActionRequest
    ) -> tuple[CapabilitySpec, dict[str, Any]]:
        spec = self.require(request.capability_name)
        if request.target.target_kind not in spec.target_kinds:
            raise HuntDispatchError(
                f"{spec.name} does not support {request.target.target_kind} Hunts"
            )
        try:
            validated = self.registry.validate_hunt_input(
                spec.name, request.capability_input
            )
        except ValueError as exc:
            raise HuntDispatchError(str(exc)) from exc
        return spec, validated

    async def execute(
        self,
        request: HuntActionRequest,
        factory: HuntAdapterFactory,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
        adapter_managed_cancellation: bool = False,
    ) -> HuntActionResult:
        spec, _validated = self.validate(request)
        adapter = factory.create(spec, request)
        execution = await self.executor.execute(
            CapabilityExecutionContext(
                specification=spec,
                target=request.target,
                requested_budget=request.requested_budget,
                adapter_managed_cancellation=adapter_managed_cancellation,
            ),
            adapter,
            heartbeat=heartbeat,
            cancelled=cancelled,
        )
        return HuntActionResult.from_execution(request, spec, execution)


HUNT_ACTION_DISPATCHER = HuntActionDispatcher()

