"""AI Gate worker jobs."""

from __future__ import annotations

from typing import Any, Mapping

try:
    from runtime.credential_resolver import CredentialResolutionError
except ModuleNotFoundError:
    from api.runtime.credential_resolver import CredentialResolutionError

from .services import ProductWorkerHandler


AI_GATE_RUN_KINDS = frozenset({
    "ai_api", "ai_rag", "ai_trace", "ai_mcp", "ai_widget",
})


class AIGateWorkerHandler(ProductWorkerHandler):
    async def run(
        self,
        target: str,
        options: Mapping[str, Any],
        *,
        scan_id: str | None,
        job_id: str | None,
    ) -> dict[str, Any]:
        await self.progress(scan_id, "ai_gate", 15, job_id=job_id)
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
        await self.progress(scan_id, "ai_gate_finalize", 95, job_id=job_id)
        return result


__all__ = ["AI_GATE_RUN_KINDS", "AIGateWorkerHandler"]
