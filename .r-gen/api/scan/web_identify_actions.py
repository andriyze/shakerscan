"""Scan execution of ``web.identify``: product recipes over the Scan's frozen origin.

Read-only GETs of fixed catalogue paths (``scanner_tools.web_identity``), redirects off,
anonymous, over the pinned replay transport so every request is in the Scan's HTTP archive. The
reservation is the catalogue's exact request ceiling; the receipt names the catalogue version,
the bases examined and how many probes answered like the negative control. Observations are
``http_component`` claims: catalogue labels, plain versions, fixed source-field names, the
connected address -- never response text.
"""

from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Any
import urllib.parse

try:
    from scanner_tools import web_identity
    from scanner_tools.request_replay import ReplayRequest
except (ImportError, ModuleNotFoundError):  # package import layout
    from scanner.scanner_tools import web_identity
    from scanner.scanner_tools.request_replay import ReplayRequest

PARSER_VERSION = "web-identity/v1"
REQUEST_TIMEOUT_SECONDS = 10.0


def observation(component: dict[str, Any], *, origin: str, host: str, scheme: str) -> dict[str, Any]:
    """The public observation of one component claim."""
    item = {key: component.get(key) for key in (
        "role", "base_path", "product_key", "product", "product_status", "version", "version_status",
        "package_version", "distribution", "basis", "product_source_field", "version_source_field",
        "recipe", "recipe_version", "signals", "connected_address", "status",
    )}
    item.update({
        "kind": "http_component", "url": origin + component["base_path"],
        "host": host, "sni": host if scheme == "https" else None,
    })
    return item


async def execute_web_identify(dispatcher: Any, action: Any, heartbeat: Any) -> Any:
    origin_info = dispatcher._exposure_origin()
    if origin_info is None:
        return dispatcher._skip(action, "no_canonical_origin")
    origin, scheme = origin_info
    host = str(urllib.parse.urlsplit(origin).hostname or "")
    request_limit = int(action.requested_budget.get("http_requests") or 0)
    wall = max(1, int(action.requested_budget.get("tool_wall_seconds") or 1))
    transport = dispatcher._scan_replay_transport(action, principal_slot="anonymous")
    started_at = datetime.now(timezone.utc).isoformat()
    began = time.monotonic()
    ordinal = 0

    async def fetch(path: str) -> Any:
        nonlocal ordinal
        request = ReplayRequest(
            request_id=f"identify:{ordinal}", ordinal=ordinal, name="product recipe",
            folder="", method="GET", url=origin + urllib.parse.quote(path, safe="/+-._~"),
            headers=(), body=b"", body_mode="none", auth_type="none",
            has_sensitive_material=False,
        )
        ordinal += 1
        remaining = max(1.0, wall - (time.monotonic() - began))
        result = await transport.send(
            request, target=dispatcher.target,
            timeout_seconds=max(0.5, min(REQUEST_TIMEOUT_SECONDS, remaining)),
            follow_redirects=False,
        )
        await heartbeat()
        if result.error_code or result.status_code is None:
            raise OSError(str(result.error_code or "no_response"))
        return web_identity.response_from(
            result.status_code, result.response_headers, result.response_body,
            connected_address=result.connected_address, requested_path=path,
        )

    target_path = urllib.parse.urlsplit(str(dispatcher.target_url or "")).path or "/"
    result = await web_identity.identify(
        bases=("/", web_identity.base_of_url_path(target_path)), fetch=fetch,
        request_limit=request_limit, deadline_seconds=wall, cancelled=dispatcher.cancelled,
    )
    observations = tuple(
        observation(item, origin=origin, host=host, scheme=scheme) for item in result.components
    )
    partial = result.budget_exhausted or result.timed_out
    consumed = {name: 0 for name in action.requested_budget}
    if "http_requests" in consumed:
        consumed["http_requests"] = min(request_limit, result.requests)
    if "tool_wall_seconds" in consumed:
        consumed["tool_wall_seconds"] = min(wall, max(1, int(time.monotonic() - began) + 1))
    errors = sorted(set(result.errors))[:10]
    if result.budget_exhausted:
        errors.insert(0, "budget_exhausted")
    if result.timed_out:
        errors.insert(0, "deadline_reached")
    return dispatcher._receipt(
        action,
        status="cancelled" if result.cancelled else "partial" if partial else "success",
        parser_version=PARSER_VERSION,
        started_at=started_at,
        observations=observations,
        errors=tuple(errors),
        consumed=consumed,
        partial=partial,
        redacted_execution={"action_id": action.action_id, **result.receipt()},
    )


__all__ = ["PARSER_VERSION", "execute_web_identify", "observation"]
