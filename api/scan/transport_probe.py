"""Execute ``transport.resolve`` as one reserved, receipted ``http.request`` action."""
from __future__ import annotations

import math
import time
from typing import Any, Mapping

try:
    from capabilities.inline import _InlineAdapter
    from hunt.capability_executor import CapabilityAdapterResult
except ModuleNotFoundError:  # package imports in host-side tests
    from ..capabilities.inline import _InlineAdapter
    from ..hunt.capability_executor import CapabilityAdapterResult

from .transport import choose_effective_origin


class TransportProbeExecutionAdapter(_InlineAdapter):
    """Execute the bounded probe as one reserved ``http.request`` action.

    One ``http_observation`` is recorded per attempt, including a refused one, each carrying
    its ``transport_probe`` classification; exactly one is marked ``selected`` when an origin
    answered. Usage is the number of requests actually sent.
    """

    async def execute(self, *, heartbeat: Any, cancelled: Any) -> CapabilityAdapterResult:
        del heartbeat, cancelled
        started = time.perf_counter()
        result = dict(await self._operation())
        self.result = result
        attempts = list(result.get("attempts") or ())
        raw = list(result.get("raw") or ())
        exact = bool(result.get("exact"))
        chosen = None if exact else choose_effective_origin(attempts)
        sent = sum(1 for item in raw if isinstance(item.get("request"), Mapping))
        actual: dict[str, int] = {}
        if "http_requests" in self._requested_budget:
            actual["http_requests"] = min(int(self._requested_budget["http_requests"]), sent)
        if sent and "tool_wall_seconds" in self._requested_budget:
            actual["tool_wall_seconds"] = min(
                int(self._requested_budget["tool_wall_seconds"]),
                max(1, math.ceil(time.perf_counter() - started)),
            )
        observations = tuple(
            {
                "kind": "http_observation",
                "request": dict(item.get("request") or {}),
                "response": dict(item.get("response") or {}),
                "redirect_chain": [],
                "transport_probe": {**attempt, "selected": attempt["origin"] == chosen},
            }
            for attempt, item in zip(attempts, raw)
            if isinstance(item.get("request"), Mapping)
        )
        if exact:
            status, errors = "success", ()
        elif chosen is not None:
            status, errors = "success", ()
        else:
            status = "failed"
            errors = tuple(
                f"target_unreachable:{item['origin']}:{item.get('error') or 'no_response'}"
                for item in attempts
            ) or ("target_unreachable:no_frozen_origin",)
        return CapabilityAdapterResult(
            status=status,
            observations=observations,
            errors=errors,
            actual_budget=actual,
            execution_started=bool(sent),
            parser_version=self._specification.output_schema,
            redacted_execution={
                **self._redacted_execution,
                "transport": "exact" if exact else "probed",
                "candidates": list(result.get("candidates") or ()),
            },
        )


__all__ = ["TransportProbeExecutionAdapter"]
