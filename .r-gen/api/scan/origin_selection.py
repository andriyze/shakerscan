"""Measured transport selection within an immutable Scan target binding."""

from __future__ import annotations

import math
import time
import urllib.parse
from collections.abc import Callable, Mapping
from typing import Any

try:
    from capabilities.http import execute_bound_http_request
    from runtime.models import TargetBinding
except ModuleNotFoundError:  # package-native import layout
    from api.capabilities.http import execute_bound_http_request
    from api.runtime.models import TargetBinding


async def select_inferred_scan_origin(
    *,
    target: TargetBinding,
    transaction_recorder: Callable[[Mapping[str, Any]], Any] | None = None,
    timeout_seconds: int = 20,
) -> dict[str, Any]:
    """Probe only the two frozen origins, recording each attempted request."""
    started = time.monotonic()
    attempts: list[dict[str, Any]] = []
    selected: str | None = None
    for origin in target.inferred_origins:
        remaining = max(1, timeout_seconds - math.ceil(time.monotonic() - started))
        result = await execute_bound_http_request(
            origin, {"method": "GET", "path": "/", "follow_redirects": False},
            target=target, allow_write=False,
            transaction_recorder=transaction_recorder,
            timeout_seconds=min(10, remaining),
        )
        attempted = isinstance(result.get("request"), Mapping)
        response = result.get("response") if isinstance(result.get("response"), Mapping) else {}
        attempts.append({
            "origin": origin,
            "attempted": attempted,
            "reachable": bool(result.get("ok") and response.get("status")),
            "status": response.get("status"),
            "error": str(result.get("error") or "")[:200] or None,
        })
        if attempts[-1]["reachable"]:
            selected = origin
            break
    consumed = sum(1 for attempt in attempts if attempt["attempted"])
    return {
        "ok": selected is not None,
        "status": "success" if selected else "failed",
        "observation": {
            "kind": "origin_selection_observation",
            "selected_origin": selected,
            "attempts": attempts,
        },
        "budget_consumed": {
            "http_requests": consumed,
            "tool_wall_seconds": min(timeout_seconds, max(1, math.ceil(time.monotonic() - started))),
        },
        "errors": [str(item["error"]) for item in attempts if item["error"]],
    }


def selected_origin_from_observations(
    observations: tuple[Mapping[str, Any], ...], target: TargetBinding,
) -> str | None:
    """Accept a completed selection only if it still names a frozen candidate."""
    for item in observations:
        if item.get("kind") == "origin_selection_observation":
            try:
                parsed = urllib.parse.urlsplit(str(item.get("selected_origin") or ""))
                _ = parsed.port
            except ValueError:
                continue
            selected = (
                f"{parsed.scheme}://{parsed.netloc}"
                if parsed.path in {"", "/"} and not (
                    parsed.query or parsed.fragment or parsed.username or parsed.password
                ) else ""
            )
            if selected in target.inferred_origins:
                return selected
    return None
