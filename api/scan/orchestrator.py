"""One dependency-aware scheduler for local, broker, and parallel Scan actions."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .action_plan import SCAN_ACTION_PLAN_SCHEMA, ScanAction, ScanActionPlan
from .capability_result import (
    CapabilityResultReason,
    CapabilityResultReference,
    CapabilityResultStatus,
    placement_from_stored_result,
)
from .execution_backend import (
    ActionAlreadyTerminal,
    ActionLeaseLost,
    ScanActionExecutor,
    ScanExecutionBackend,
    ScanExecutionBackendError,
    validate_action_lease,
)


_TERMINAL_STATUSES = frozenset(item.value for item in CapabilityResultStatus)
_DEPENDENCY_SATISFIED = frozenset({
    CapabilityResultStatus.SUCCESS,
    CapabilityResultStatus.PARTIAL,
})


class ScanOrchestrationError(RuntimeError):
    """The immutable action graph cannot make safe scheduler progress."""


@dataclass(frozen=True)
class ScanOrchestrationResult:
    scan_id: str
    plan_digest: str
    action_results: Mapping[str, CapabilityResultReference]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "action_results",
            MappingProxyType(dict(self.action_results)),
        )

    @property
    def action_ids(self) -> tuple[str, ...]:
        return tuple(self.action_results)

    @property
    def status_matrix(self) -> Mapping[str, str]:
        return MappingProxyType({
            action_id: result.status.value
            for action_id, result in self.action_results.items()
        })


def resumable_action_ids(
    *,
    plan_action_ids: tuple[str, ...],
    terminal_receipts: Mapping[str, str],
) -> tuple[str, ...]:
    """Return only actions without a recognized terminal result."""
    return tuple(
        action_id
        for action_id in plan_action_ids
        if str(terminal_receipts.get(action_id) or "").strip().lower()
        not in _TERMINAL_STATUSES | {"completed"}
    )


class ScanOrchestrator:
    """Execute one persisted action DAG using a placement-neutral backend."""

    plan_schema_version = SCAN_ACTION_PLAN_SCHEMA

    def __init__(
        self,
        *,
        backend: ScanExecutionBackend,
        executor: ScanActionExecutor,
    ) -> None:
        self._backend = backend
        self._executor = executor

    @staticmethod
    def _validate_result(action: ScanAction, result: CapabilityResultReference) -> None:
        placement_from_stored_result(action=action, stored=result)
        expected_adapter = str(action.placement.get("adapter_name") or "")
        expected_version = str(action.placement.get("adapter_version") or "")
        if (
            result.adapter_name != expected_adapter
            or result.adapter_version != expected_version
        ):
            raise ScanOrchestrationError(
                f"result adapter identity differs from action {action.action_id}"
            )
        if dict(result.budget_reserved) != dict(action.requested_budget):
            raise ScanOrchestrationError(
                f"result reservation differs from action {action.action_id}"
            )

    async def _load_terminal_results(
        self, plan: ScanActionPlan,
    ) -> dict[str, CapabilityResultReference]:
        results: dict[str, CapabilityResultReference] = {}
        for action in plan.actions:
            result = await self._backend.load_result(action.action_id)
            if result is None:
                continue
            self._validate_result(action, result)
            results[action.action_id] = result
        return results

    async def _settle_without_execution(
        self,
        *,
        plan: ScanActionPlan,
        action: ScanAction,
        status: CapabilityResultStatus,
        reason: CapabilityResultReason,
        charge_full: bool = False,
    ) -> CapabilityResultReference:
        try:
            lease = await self._backend.acquire_action(action)
        except ActionAlreadyTerminal:
            stored = await self._backend.load_result(action.action_id)
            if stored is None:
                raise ScanOrchestrationError(
                    "backend reported terminal action without a result"
                )
            self._validate_result(action, stored)
            return stored
        validate_action_lease(lease, plan=plan, action=action)
        result = await self._executor.terminal_without_execution(
            action,
            lease,
            status=status.value,
            reason_code=reason.value,
            charge_full_reservation=charge_full,
        )
        settled = await self._backend.settle(lease, result)
        self._validate_result(action, settled)
        return settled

    async def _execute_action(
        self,
        *,
        plan: ScanActionPlan,
        action: ScanAction,
    ) -> CapabilityResultReference:
        try:
            lease = await self._backend.acquire_action(action)
        except ActionAlreadyTerminal:
            stored = await self._backend.load_result(action.action_id)
            if stored is None:
                raise ScanOrchestrationError(
                    "backend reported terminal action without a result"
                )
            self._validate_result(action, stored)
            return stored
        validate_action_lease(lease, plan=plan, action=action)
        try:
            await self._backend.heartbeat(lease)
            result = await self._executor.execute(
                action,
                lease,
                lambda: self._backend.heartbeat(lease),
            )
            await self._backend.heartbeat(lease)
        except ActionLeaseLost:
            result = await self._executor.terminal_without_execution(
                action,
                lease,
                status=CapabilityResultStatus.FAILED.value,
                reason_code=CapabilityResultReason.ADAPTER_FAILED.value,
                charge_full_reservation=True,
            )
        except Exception:
            # Adapter exception text is intentionally not copied to durable state.
            result = await self._executor.terminal_without_execution(
                action,
                lease,
                status=CapabilityResultStatus.FAILED.value,
                reason_code=CapabilityResultReason.ADAPTER_FAILED.value,
                charge_full_reservation=True,
            )
        settled = await self._backend.settle(lease, result)
        self._validate_result(action, settled)
        return settled

    async def run(self, plan: ScanActionPlan) -> ScanOrchestrationResult:
        if not isinstance(plan, ScanActionPlan):
            raise ScanOrchestrationError("ScanOrchestrator requires a canonical action plan")
        results = await self._load_terminal_results(plan)

        while len(results) < len(plan.actions):
            pending = [
                action for action in plan.actions if action.action_id not in results
            ]
            if await self._backend.cancellation_requested():
                for action in pending:
                    results[action.action_id] = await self._settle_without_execution(
                        plan=plan,
                        action=action,
                        status=CapabilityResultStatus.CANCELLED,
                        reason=CapabilityResultReason.CANCELLED,
                    )
                break

            progressed = False
            for action in pending:
                dependencies = [results.get(item) for item in action.dependencies]
                if any(item is None for item in dependencies):
                    continue
                if action.admission_status == "skipped":
                    reason = CapabilityResultReason(str(action.reason_code))
                    result = await self._settle_without_execution(
                        plan=plan,
                        action=action,
                        status=CapabilityResultStatus.SKIPPED,
                        reason=reason,
                    )
                elif (
                    action.action_id != "finalize.report"
                    and any(
                        item.status not in _DEPENDENCY_SATISFIED
                        for item in dependencies
                        if item is not None
                    )
                ):
                    result = await self._settle_without_execution(
                        plan=plan,
                        action=action,
                        status=CapabilityResultStatus.BLOCKED,
                        reason=CapabilityResultReason.DEPENDENCY_FAILED,
                    )
                else:
                    result = await self._execute_action(
                        plan=plan, action=action,
                    )
                self._validate_result(action, result)
                results[action.action_id] = result
                progressed = True
                break
            if not progressed:
                raise ScanOrchestrationError(
                    "Scan action graph cannot progress from its durable terminal state"
                )

        ordered = {
            action.action_id: results[action.action_id] for action in plan.actions
        }
        return ScanOrchestrationResult(
            scan_id=plan.scan_id,
            plan_digest=str(plan.plan_digest),
            action_results=ordered,
        )
