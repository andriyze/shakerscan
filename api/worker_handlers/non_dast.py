"""Composition-only dispatch for explicit non-DAST worker products."""

from __future__ import annotations

from typing import Any

try:
    from scan.worker_dispatch import is_deterministic_dast
except ModuleNotFoundError:
    from api.scan.worker_dispatch import is_deterministic_dast

from .ai_gate import AI_GATE_RUN_KINDS, AIGateWorkerHandler
from .device import DeviceWorkerHandler
from .model_intake import MODEL_INTAKE_RUN_KINDS, ModelIntakeWorkerHandler
from .services import NonDastWorkerServices


class NonDastWorkerHandler:
    """Route a non-DAST job to one product-owned handler."""

    def __init__(self, services: NonDastWorkerServices):
        self.device = DeviceWorkerHandler(services)
        self.model_intake = ModelIntakeWorkerHandler(services)
        self.ai_gate = AIGateWorkerHandler(services)

    async def run(
        self,
        target: str,
        options: dict[str, Any],
        scan_id: str | None = None,
        job_id: str | None = None,
    ) -> dict[str, Any]:
        if is_deterministic_dast(options):
            raise ValueError(
                "monolithic deterministic Scan execution has been removed; "
                "execute the persisted canonical action graph"
            )
        run_kind = str(options.get("run_kind") or "")
        if run_kind == "device_probe":
            return await self.device.run_probe(
                target, options, scan_id=scan_id, job_id=job_id,
            )
        if run_kind == "device_posture":
            return await self.device.run_posture(
                target, options, scan_id=scan_id, job_id=job_id,
            )
        if run_kind in MODEL_INTAKE_RUN_KINDS:
            return await self.model_intake.run(
                target, options, scan_id=scan_id, job_id=job_id,
            )
        if run_kind in AI_GATE_RUN_KINDS:
            return await self.ai_gate.run(
                target, options, scan_id=scan_id, job_id=job_id,
            )
        raise ValueError(
            "unsupported non-DAST worker run kind; expected Device, Model Intake, "
            "or AI Gate dispatch"
        )


__all__ = [
    "AI_GATE_RUN_KINDS",
    "MODEL_INTAKE_RUN_KINDS",
    "NonDastWorkerHandler",
    "NonDastWorkerServices",
]
