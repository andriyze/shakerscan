"""Database-free HTTPS backend for the canonical Scan action scheduler."""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Mapping

try:  # Preserve one receipt identity for top-level worker imports.
    from runtime.receipts import CapabilityReceipt
except (ImportError, ModuleNotFoundError):
    from ..runtime.receipts import CapabilityReceipt

from .action_plan import ScanAction, ScanActionPlan
from .capability_result import CapabilityResultReference
from .execution_backend import (
    ActionAlreadyTerminal,
    ActionLease,
    ActionLeaseLost,
    ScanExecutionBackendError,
    validate_action_lease,
)


BrokerActionRequest = Callable[
    [str, str, Mapping[str, Any] | None],
    Awaitable[Mapping[str, Any] | None],
]


class BrokerActionHTTPError(ScanExecutionBackendError):
    """A broker action endpoint rejected the database-free scheduler."""

    def __init__(self, status_code: int, detail: str = "") -> None:
        self.status_code = int(status_code)
        super().__init__(f"broker action endpoint returned {status_code}: {detail[:300]}")


class BrokerScanExecutionBackend:
    """Run the shared orchestrator through short-lived broker action leases.

    The request function owns HTTPS, node authentication, and retry policy.  This
    class sends only the outer job-lease token plus immutable action authority;
    it never receives database or Redis credentials.
    """

    backend_name = "broker"

    def __init__(
        self,
        *,
        plan: ScanActionPlan,
        worker_id: str,
        job_lease_token: str,
        base_path: str,
        request: BrokerActionRequest,
    ) -> None:
        if not isinstance(plan, ScanActionPlan):
            raise ScanExecutionBackendError(
                "broker backend requires a canonical Scan action plan"
            )
        normalized_worker = str(worker_id or "").strip()
        token = str(job_lease_token or "").strip()
        path = "/" + str(base_path or "").strip("/")
        if not normalized_worker or len(normalized_worker) > 200:
            raise ScanExecutionBackendError("broker backend worker_id is invalid")
        if len(token) < 32 or len(token) > 256:
            raise ScanExecutionBackendError("broker job lease token is invalid")
        if len(path) > 500 or "?" in path or "#" in path:
            raise ScanExecutionBackendError("broker action base path is invalid")
        if not callable(request):
            raise ScanExecutionBackendError("broker action request transport is invalid")
        self._plan = plan
        self._worker_id = normalized_worker
        self._job_lease_token = token
        self._base_path = path.rstrip("/")
        self._request = request
        self._actions = {action.action_id: action for action in plan.actions}

    def _action(self, action_id: str) -> ScanAction:
        action = self._actions.get(str(action_id or ""))
        if action is None:
            raise ScanExecutionBackendError(
                "broker action is absent from the immutable Scan plan"
            )
        return action

    def _path(self, action_id: str, operation: str) -> str:
        action = self._action(action_id)
        return f"{self._base_path}/actions/{action.action_id}/{operation}"

    def _authority(self, action: ScanAction) -> dict[str, Any]:
        return {
            "job_lease_token": self._job_lease_token,
            "worker_id": self._worker_id,
            "plan_digest": self._plan.plan_digest,
            "action_id": action.action_id,
            "action_digest": action.action_digest,
        }

    async def acquire_action(self, action: ScanAction) -> ActionLease:
        expected = self._action(action.action_id)
        if expected.action_digest != action.action_digest:
            raise ScanExecutionBackendError(
                "broker action differs from the immutable Scan plan"
            )
        try:
            response = await self._request(
                "POST", self._path(action.action_id, "lease"),
                self._authority(action),
            )
        except BrokerActionHTTPError as exc:
            if exc.status_code == 208:
                raise ActionAlreadyTerminal(action.action_id) from exc
            raise
        if not isinstance(response, Mapping) or set(response) != {"action_lease"}:
            raise ScanExecutionBackendError("broker action lease response is invalid")
        lease = ActionLease.from_remote_payload(response["action_lease"])
        validate_action_lease(lease, plan=self._plan, action=action)
        if lease.backend != self.backend_name or lease.worker_id != self._worker_id:
            raise ScanExecutionBackendError(
                "broker action lease placement differs from this worker"
            )
        return lease

    async def heartbeat(self, lease: ActionLease) -> None:
        action = self._action(lease.action.action_id)
        validate_action_lease(lease, plan=self._plan, action=action)
        payload = {
            **self._authority(action),
            "action_lease": lease.remote_payload(),
        }
        try:
            response = await self._request(
                "POST", self._path(action.action_id, "heartbeat"), payload,
            )
        except BrokerActionHTTPError as exc:
            if exc.status_code in {401, 404, 409, 410}:
                raise ActionLeaseLost("broker action lease authority was lost") from exc
            raise
        if not isinstance(response, Mapping) or response.get("status") != "running":
            raise ActionLeaseLost("broker action heartbeat was not acknowledged")

    async def settle(
        self,
        lease: ActionLease,
        result: CapabilityResultReference | CapabilityReceipt,
    ) -> CapabilityResultReference:
        action = self._action(lease.action.action_id)
        validate_action_lease(lease, plan=self._plan, action=action)
        if not isinstance(result, CapabilityReceipt):
            raise ScanExecutionBackendError(
                "broker workers may settle only canonical capability receipts"
            )
        payload = {
            **self._authority(action),
            "action_lease": lease.remote_payload(),
            "receipt": result.public_dict(),
        }
        try:
            response = await self._request(
                "POST", self._path(action.action_id, "result"), payload,
            )
        except BrokerActionHTTPError as exc:
            if exc.status_code in {401, 404, 409, 410}:
                raise ActionLeaseLost("broker action result authority was lost") from exc
            raise
        if not isinstance(response, Mapping) or set(response) != {"result"}:
            raise ScanExecutionBackendError("broker action result response is invalid")
        try:
            stored = CapabilityResultReference.from_dict(response["result"])
        except (TypeError, ValueError) as exc:
            raise ScanExecutionBackendError("broker stored action result is invalid") from exc
        return stored

    async def load_result(self, action_id: str) -> CapabilityResultReference | None:
        action = self._action(action_id)
        response = await self._request(
            "POST", self._path(action.action_id, "status"), self._authority(action),
        )
        if not isinstance(response, Mapping) or set(response) != {"result"}:
            raise ScanExecutionBackendError("broker action status response is invalid")
        if response["result"] is None:
            return None
        try:
            return CapabilityResultReference.from_dict(response["result"])
        except (TypeError, ValueError) as exc:
            raise ScanExecutionBackendError("broker stored action result is invalid") from exc

    async def cancellation_requested(self) -> bool:
        response = await self._request(
            "POST", f"{self._base_path}/cancel-status",
            {
                "job_lease_token": self._job_lease_token,
                "worker_id": self._worker_id,
                "plan_digest": self._plan.plan_digest,
            },
        )
        if not isinstance(response, Mapping) or set(response) != {"cancel_requested"}:
            raise ScanExecutionBackendError("broker cancellation response is invalid")
        if not isinstance(response["cancel_requested"], bool):
            raise ScanExecutionBackendError("broker cancellation status is invalid")
        return response["cancel_requested"]


__all__ = [
    "BrokerActionHTTPError",
    "BrokerActionRequest",
    "BrokerScanExecutionBackend",
]
