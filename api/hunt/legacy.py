"""Migration quarantine for the superseded web and device Hunt engines."""

from __future__ import annotations

import json
import re
from typing import Any


LEGACY_HUNT_SUNSET = "Wed, 30 Sep 2026 23:59:59 GMT"


def is_legacy_hunt_surface(path: str) -> bool:
    normalized = str(path or "").rstrip("/") or "/"
    return bool(
        normalized == "/agent/hunt"
        or normalized.startswith("/agent/hunt/")
        or normalized == "/device-agent"
        or normalized.startswith("/device-agent/")
        or re.fullmatch(r"/devices/[^/]+/agent/session", normalized)
    )


def legacy_hunt_write_blocked(path: str, method: str) -> bool:
    """Retire duplicate Hunt writes while preserving history and cancellation."""
    if not is_legacy_hunt_surface(path):
        return False
    if str(method or "GET").upper() in {"GET", "HEAD", "OPTIONS"}:
        return False
    return not str(path or "").rstrip("/").endswith("/cancel")


class LegacyHuntIsolationMiddleware:
    """Make legacy web/device Hunt APIs permanently read-only except cancellation."""

    _HEADERS = (
        (b"deprecation", b"true"),
        (b"sunset", LEGACY_HUNT_SUNSET.encode("ascii")),
        (b"link", b'</hunts>; rel="successor-version"'),
        (b"warning", b'299 ShakerScan "Legacy Hunt engine; use /hunts"'),
    )

    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path") or "")
        if not is_legacy_hunt_surface(path):
            await self.app(scope, receive, send)
            return
        if legacy_hunt_write_blocked(
            path, str(scope.get("method") or "GET"),
        ):
            body = json.dumps({
                "detail": "This legacy Hunt engine is retired; create and drive investigations through /hunts",
                "canonical_endpoint": "/hunts",
                "legacy_history_readable": True,
                "legacy_cancel_allowed": True,
            }).encode("utf-8")
            await send({
                "type": "http.response.start", "status": 410,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    *self._HEADERS,
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return

        async def send_deprecated(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                message["headers"] = [*message.get("headers", []), *self._HEADERS]
            await send(message)

        await self.app(scope, receive, send_deprecated)
