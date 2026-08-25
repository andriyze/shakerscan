"""One fixed lifecycle owner for every canonical Hunt capability action."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import threading
import time
from typing import Any, Awaitable, Callable, Mapping

try:
    from hunt.action_dispatcher import (
        HUNT_ACTION_DISPATCHER,
        HuntActionDispatcher,
    )
    from runtime.capability_registry import CapabilitySpec, HuntExecutor
except ModuleNotFoundError:
    from .action_dispatcher import HUNT_ACTION_DISPATCHER, HuntActionDispatcher
    from ..runtime.capability_registry import CapabilitySpec, HuntExecutor


LIFECYCLE_PHASES = (
    "validated",
    "revalidated",
    "admitted",
    "dispatching",
    "persisting",
    "settled",
    "returned",
)


class HuntActionServiceError(ValueError):
    """A capability could not enter the canonical action lifecycle."""


class HuntActionNotFound(HuntActionServiceError):
    """The public registry has no planner-visible capability by this name."""


class HuntActionInputError(HuntActionServiceError):
    """The capability input violates its one registry schema."""


class HuntActionLifecycleError(RuntimeError):
    """A lifecycle phase was skipped, duplicated, or reordered."""


@dataclass
class HuntActionLifecycle:
    """Per-action phase ledger; placement is metadata, never control flow here."""

    specification: CapabilitySpec
    started_monotonic: float = field(default_factory=time.monotonic)
    phases: list[dict[str, Any]] = field(default_factory=list)
    replayed: bool = False
    failure: str | None = None

    @property
    def placement(self) -> HuntExecutor:
        placement = self.specification.hunt_executor
        if placement is None:
            raise HuntActionLifecycleError("Hunt capability has no placement metadata")
        return placement

    def advance(self, phase: str) -> None:
        if self.replayed:
            raise HuntActionLifecycleError("an idempotent replay cannot execute new phases")
        expected_index = len(self.phases)
        if expected_index >= len(LIFECYCLE_PHASES):
            raise HuntActionLifecycleError("Hunt action lifecycle is already complete")
        expected = LIFECYCLE_PHASES[expected_index]
        if phase != expected:
            raise HuntActionLifecycleError(
                f"Hunt action lifecycle expected {expected}, got {phase}"
            )
        self.phases.append({
            "phase": phase,
            "elapsed_ms": max(
                0, int((time.monotonic() - self.started_monotonic) * 1_000)
            ),
        })

    def mark_replayed(self) -> None:
        if [item["phase"] for item in self.phases] != ["validated"]:
            raise HuntActionLifecycleError(
                "idempotent replay must resolve immediately after validation"
            )
        self.replayed = True

    def mark_failure(self, exc: BaseException) -> None:
        self.failure = type(exc).__name__

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "hunt-action-lifecycle/v1",
            "placement": self.placement,
            "outcome": (
                "failed" if self.failure else "replayed" if self.replayed else "completed"
            ),
            "phases": [dict(item) for item in self.phases],
            "failure_class": self.failure,
        }


class HuntActionLifecycleMetrics:
    """Content-free reconciliation counters shared by all placements."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._outcomes: Counter[tuple[str, str]] = Counter()
        self._phase_counts: Counter[tuple[str, str]] = Counter()

    def record(self, lifecycle: HuntActionLifecycle) -> None:
        payload = lifecycle.public_dict()
        placement = str(payload["placement"])
        with self._lock:
            self._outcomes[(placement, str(payload["outcome"]))] += 1
            for phase in lifecycle.phases:
                self._phase_counts[(placement, str(phase["phase"]))] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            outcomes = dict(self._outcomes)
            phases = dict(self._phase_counts)
        placements = sorted({placement for placement, _ in outcomes} | {
            placement for placement, _ in phases
        })
        return {
            "schema_version": "hunt-action-lifecycle-metrics/v1",
            "placements": {
                placement: {
                    "outcomes": {
                        outcome: count
                        for (item_placement, outcome), count in sorted(outcomes.items())
                        if item_placement == placement
                    },
                    "phases": {
                        phase: count
                        for (item_placement, phase), count in sorted(phases.items())
                        if item_placement == placement
                    },
                }
                for placement in placements
            },
        }


LifecycleOperation = Callable[[HuntActionLifecycle], Awaitable[Mapping[str, Any]]]


class HuntActionService:
    """Validate, reconcile, and expose one fixed lifecycle for every action."""

    def __init__(
        self,
        *,
        dispatcher: HuntActionDispatcher = HUNT_ACTION_DISPATCHER,
        metrics: HuntActionLifecycleMetrics | None = None,
    ) -> None:
        self.dispatcher = dispatcher
        self.metrics = metrics or HuntActionLifecycleMetrics()

    def prepare(
        self, capability_name: str, capability_input: Mapping[str, Any]
    ) -> HuntActionLifecycle:
        try:
            specification = self.dispatcher.require(capability_name)
        except ValueError as exc:
            raise HuntActionNotFound(str(exc)) from exc
        try:
            self.dispatcher.registry.validate_hunt_input(
                specification.name, capability_input
            )
        except ValueError as exc:
            raise HuntActionInputError(str(exc)) from exc
        lifecycle = HuntActionLifecycle(specification=specification)
        lifecycle.advance("validated")
        return lifecycle

    async def execute(
        self,
        capability_name: str,
        capability_input: Mapping[str, Any],
        operation: LifecycleOperation,
    ) -> dict[str, Any]:
        lifecycle = self.prepare(capability_name, capability_input)
        try:
            raw_result = await operation(lifecycle)
            result = dict(raw_result)
            if not lifecycle.replayed:
                lifecycle.advance("returned")
            result["lifecycle"] = lifecycle.public_dict()
            return result
        except BaseException as exc:
            lifecycle.mark_failure(exc)
            raise
        finally:
            self.metrics.record(lifecycle)


HUNT_ACTION_SERVICE = HuntActionService()
