"""Injected infrastructure shared by product-owned worker handlers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncContextManager, Awaitable, Callable, Mapping


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


class ProductWorkerHandler:
    def __init__(self, services: NonDastWorkerServices):
        self.services = services

    async def progress(
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


__all__ = ["NonDastWorkerServices", "ProductWorkerHandler"]
