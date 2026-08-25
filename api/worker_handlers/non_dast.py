"""Device, Model Intake, and AI Gate execution owned outside ``worker.py``.

The handler contains the product behavior. Infrastructure that belongs to the
worker process (database-backed credential hydration, progress persistence,
Redis logs, and cancellation state) is injected as a small service contract so
this module remains independently importable and testable.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Any, AsyncContextManager, Awaitable, Callable, Mapping

try:
    from runtime.credential_resolver import CredentialResolutionError
    from scan.worker_dispatch import is_deterministic_dast
except ModuleNotFoundError:
    from api.runtime.credential_resolver import CredentialResolutionError
    from api.scan.worker_dispatch import is_deterministic_dast


AI_GATE_RUN_KINDS = frozenset({
    "ai_api", "ai_rag", "ai_trace", "ai_mcp", "ai_widget",
})
MODEL_INTAKE_RUN_KINDS = frozenset({"model_intake"})


@dataclass(frozen=True)
class NonDastWorkerServices:
    update_scan_progress: Callable[..., Awaitable[None]]
    scan_cancel_requested: Callable[[str | None], bool]
    append_device_activity: Callable[..., None]
    strip_null_bytes: Callable[[Any], Any]
    get_redis: Callable[[], Any]
    hydrate_ai_gate_options: Callable[
        [Mapping[str, Any], str], AsyncContextManager[dict[str, Any]]
    ]
    results_dir: Path
    scan_log_tail: int
    scan_log_ttl_seconds: int


class NonDastWorkerHandler:
    """Execute the three explicit non-DAST product workflows."""

    def __init__(self, services: NonDastWorkerServices):
        self.services = services

    async def _progress(
        self,
        scan_id: str | None,
        phase: str,
        progress: int,
        *,
        job_id: str | None,
    ) -> None:
        if scan_id:
            await self.services.update_scan_progress(
                scan_id, phase, progress, job_id=job_id,
            )

    @staticmethod
    def _device_enabled() -> bool:
        return str(os.environ.get("DEVICE_POSTURE_ENABLED", "true")).strip().lower() not in {
            "0", "false", "no", "off",
        }

    async def _run_device_probe(
        self,
        target: str,
        options: Mapping[str, Any],
        *,
        scan_id: str | None,
        job_id: str | None,
    ) -> dict[str, Any]:
        await self._progress(scan_id, "device_service_probe", 20, job_id=job_id)
        try:
            from scanner_tools.device_probe import run_device_service_probe
        except ImportError:
            from scanner.scanner_tools.device_probe import run_device_service_probe
        if not self._device_enabled():
            raise ValueError("connected-device posture is disabled on this worker")
        probe_options = dict(options)
        probe_options["_cancel_check"] = lambda: asyncio.to_thread(
            self.services.scan_cancel_requested, scan_id,
        )
        result = await run_device_service_probe(target, probe_options)
        await self._progress(scan_id, "device_service_verdict", 90, job_id=job_id)
        return self.services.strip_null_bytes(result) if isinstance(result, dict) else result

    async def _run_device_posture(
        self,
        target: str,
        options: Mapping[str, Any],
        *,
        scan_id: str | None,
        job_id: str | None,
    ) -> dict[str, Any]:
        await self._progress(scan_id, "device_inventory", 10, job_id=job_id)
        try:
            from scanner_tools.device_posture import run_device_posture_scan
        except ImportError:
            from scanner.scanner_tools.device_posture import run_device_posture_scan
        if not self._device_enabled():
            raise ValueError("connected-device posture is disabled on this worker")
        device_options = dict(options)
        device_options["_cancel_check"] = lambda: asyncio.to_thread(
            self.services.scan_cancel_requested, scan_id,
        )

        async def record_progress(event: dict[str, Any]) -> None:
            if not scan_id:
                return
            phase = str(event.get("phase") or "device_inventory")
            try:
                progress = max(10, min(89, int(event.get("progress") or 10)))
            except (TypeError, ValueError):
                progress = 10
            await self._progress(scan_id, phase, progress, job_id=job_id)
            self.services.append_device_activity(
                scan_id,
                kind="phase",
                phase=phase,
                progress=progress,
                details=(
                    event.get("details")
                    if isinstance(event.get("details"), dict) else None
                ),
            )

        device_options["_progress_callback"] = record_progress
        result = await run_device_posture_scan(target, device_options)
        await self._progress(scan_id, "device_policy", 90, job_id=job_id)
        return self.services.strip_null_bytes(result) if isinstance(result, dict) else result

    async def _run_model_intake(
        self,
        target: str,
        options: Mapping[str, Any],
        *,
        scan_id: str | None,
        job_id: str | None,
    ) -> dict[str, Any]:
        await self._progress(scan_id, "model_intake", 15, job_id=job_id)
        try:
            from scanner_tools.model_intake import run_model_intake_scan
        except ImportError:
            from scanner.scanner_tools.model_intake import run_model_intake_scan

        intake_options = dict(options)
        if scan_id:
            intake_options.setdefault("scan_id", scan_id)
            intake_options.setdefault(
                "quarantine_dir",
                str(self.services.results_dir / "model-intake-quarantine"),
            )

        async def record_event(event: dict[str, Any]) -> None:
            if not scan_id or not isinstance(event, dict):
                return
            line = str(event.get("line") or "").strip()
            if not line.startswith("[model-intake]") or len(line) > 1000:
                return

            def write_log_line() -> None:
                redis_client = self.services.get_redis()
                log_key = f"scan:{scan_id}:logs"
                redis_client.rpush(log_key, line)
                redis_client.ltrim(log_key, -self.services.scan_log_tail, -1)
                redis_client.expire(log_key, self.services.scan_log_ttl_seconds)

            try:
                await asyncio.to_thread(write_log_line)
            except Exception as exc:
                print(
                    f"[model-intake] live log write failed: {type(exc).__name__}",
                    flush=True,
                )
            print(f"[{(job_id or scan_id)[:8]}] {line}", flush=True)
            try:
                progress = max(15, min(95, int(event.get("progress") or 15)))
            except (TypeError, ValueError):
                progress = 15
            phase = re.sub(
                r"[^a-z0-9_]+",
                "_",
                str(event.get("phase") or "model_intake").lower(),
            )[:64]
            await self._progress(
                scan_id, phase or "model_intake", progress, job_id=job_id,
            )

        result = await run_model_intake_scan(
            target,
            intake_options,
            event_callback=record_event,
        )
        await self._progress(scan_id, "model_intake_finalize", 95, job_id=job_id)
        return result

    async def _run_ai_gate(
        self,
        target: str,
        options: Mapping[str, Any],
        *,
        scan_id: str | None,
        job_id: str | None,
    ) -> dict[str, Any]:
        await self._progress(scan_id, "ai_gate", 15, job_id=job_id)
        try:
            from ai_gate_scan import run_ai_target_scan
        except ModuleNotFoundError:
            from api.ai_gate_scan import run_ai_target_scan
        if not scan_id:
            raise CredentialResolutionError("AI Gate scan identity is unavailable")
        async with self.services.hydrate_ai_gate_options(
            options, scan_id,
        ) as hydrated_options:
            result = await run_ai_target_scan(target, hydrated_options)
        await self._progress(scan_id, "ai_gate_finalize", 95, job_id=job_id)
        return result

    async def run(
        self,
        target: str,
        options: dict[str, Any],
        scan_id: str | None = None,
        job_id: str | None = None,
    ) -> dict[str, Any]:
        """Dispatch one explicitly non-DAST job to its owned product handler."""
        if is_deterministic_dast(options):
            raise ValueError(
                "monolithic deterministic Scan execution has been removed; "
                "execute the persisted canonical action graph"
            )
        run_kind = str(options.get("run_kind") or "")
        if run_kind == "device_probe":
            return await self._run_device_probe(
                target, options, scan_id=scan_id, job_id=job_id,
            )
        if run_kind == "device_posture":
            return await self._run_device_posture(
                target, options, scan_id=scan_id, job_id=job_id,
            )
        if run_kind in MODEL_INTAKE_RUN_KINDS:
            return await self._run_model_intake(
                target, options, scan_id=scan_id, job_id=job_id,
            )
        if run_kind in AI_GATE_RUN_KINDS:
            return await self._run_ai_gate(
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
