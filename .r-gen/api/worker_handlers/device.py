"""Connected-device worker jobs."""

from __future__ import annotations

import asyncio
import os
from typing import Any, Mapping

from .services import ProductWorkerHandler


class DeviceWorkerHandler(ProductWorkerHandler):
    @staticmethod
    def enabled() -> bool:
        return str(os.environ.get("DEVICE_POSTURE_ENABLED", "true")).strip().lower() not in {
            "0", "false", "no", "off",
        }

    async def run_probe(
        self,
        target: str,
        options: Mapping[str, Any],
        *,
        scan_id: str | None,
        job_id: str | None,
    ) -> dict[str, Any]:
        await self.progress(scan_id, "device_service_probe", 20, job_id=job_id)
        try:
            from scanner_tools.device_probe import run_device_service_probe
        except ImportError:
            from scanner.scanner_tools.device_probe import run_device_service_probe
        if not self.enabled():
            raise ValueError("connected-device posture is disabled on this worker")
        probe_options = dict(options)
        probe_options["_cancel_check"] = lambda: asyncio.to_thread(
            self.services.scan_cancel_requested, scan_id,
        )
        result = await run_device_service_probe(target, probe_options)
        await self.progress(scan_id, "device_service_verdict", 90, job_id=job_id)
        return self.services.strip_null_bytes(result) if isinstance(result, dict) else result

    async def run_posture(
        self,
        target: str,
        options: Mapping[str, Any],
        *,
        scan_id: str | None,
        job_id: str | None,
    ) -> dict[str, Any]:
        await self.progress(scan_id, "device_inventory", 10, job_id=job_id)
        try:
            from scanner_tools.device_posture import run_device_posture_scan
        except ImportError:
            from scanner.scanner_tools.device_posture import run_device_posture_scan
        if not self.enabled():
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
            await self.progress(scan_id, phase, progress, job_id=job_id)
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
        await self.progress(scan_id, "device_policy", 90, job_id=job_id)
        return self.services.strip_null_bytes(result) if isinstance(result, dict) else result


__all__ = ["DeviceWorkerHandler"]
