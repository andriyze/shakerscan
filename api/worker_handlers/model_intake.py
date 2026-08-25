"""Model Intake worker jobs."""

from __future__ import annotations

import asyncio
import re
from typing import Any, Mapping

from .services import ProductWorkerHandler


MODEL_INTAKE_RUN_KINDS = frozenset({"model_intake"})


class ModelIntakeWorkerHandler(ProductWorkerHandler):
    async def run(
        self,
        target: str,
        options: Mapping[str, Any],
        *,
        scan_id: str | None,
        job_id: str | None,
    ) -> dict[str, Any]:
        await self.progress(scan_id, "model_intake", 15, job_id=job_id)
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
            await self.progress(
                scan_id, phase or "model_intake", progress, job_id=job_id,
            )

        result = await run_model_intake_scan(
            target,
            intake_options,
            event_callback=record_event,
        )
        await self.progress(scan_id, "model_intake_finalize", 95, job_id=job_id)
        return result


__all__ = ["MODEL_INTAKE_RUN_KINDS", "ModelIntakeWorkerHandler"]
