"""Shared public V2 API contract and request-boundary helpers.

The application has a large compatibility surface, but the release-critical V2
products below are intentionally small enough to characterize exhaustively.
This module is dependency-light so generation and contract tests can use the
same surface classification and body limits as the running ASGI application.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Awaitable, Callable, Mapping


PUBLIC_V2_SURFACE_PREFIXES: dict[str, tuple[str, ...]] = {
    "scan": ("/scan/contracts", "/scans"),
    "hunt": ("/hunts",),
    "credentials": ("/credential-profiles",),
    "collections": ("/request-collections",),
    "evidence": ("/evidence",),
    "model_intake": ("/model-intake",),
}

# JSON limits include structural overhead around the bounded fields declared by
# each request model. Request collections deliberately allow large imported
# documents; all other control-plane writes stay compact.
PUBLIC_V2_WRITE_BODY_LIMITS: dict[str, int] = {
    "scan": 2 * 1024 * 1024,
    "hunt": 1024 * 1024,
    "credentials": 1024 * 1024,
    "collections": 64 * 1024 * 1024,
    "evidence": 2 * 1024 * 1024,
    "model_intake": 16 * 1024 * 1024,
}

SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def public_v2_surface(path: str) -> str | None:
    """Return the canonical product surface for one exact route path."""
    normalized = str(path or "")
    for surface, prefixes in PUBLIC_V2_SURFACE_PREFIXES.items():
        if any(
            normalized == prefix or normalized.startswith(prefix + "/")
            for prefix in prefixes
        ):
            return surface
    return None


def public_v2_write_body_limit(method: str, path: str) -> int | None:
    if str(method or "GET").upper() in SAFE_HTTP_METHODS:
        return None
    surface = public_v2_surface(path)
    return PUBLIC_V2_WRITE_BODY_LIMITS.get(surface or "")


@dataclass(frozen=True)
class _RequestBodyTooLarge(Exception):
    maximum: int


class PublicV2BodyLimitMiddleware:
    """Bound every release-critical public write before model validation.

    The middleware checks both Content-Length and streamed/chunked request
    bodies. Rejected content is never decoded, logged, or copied into the error
    response, which matters for credential and collection payloads.
    """

    def __init__(self, app: Any):
        self.app = app

    @staticmethod
    async def _reject(send: Callable[[dict[str, Any]], Awaitable[None]], limit: int) -> None:
        body = json.dumps({
            "detail": {
                "error": "request_body_too_large",
                "message": "Request body exceeds the public API limit.",
                "max_bytes": limit,
            }
        }, separators=(",", ":")).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Mapping[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        limit = public_v2_write_body_limit(
            str(scope.get("method") or "GET"), str(scope.get("path") or ""),
        )
        if limit is None:
            await self.app(scope, receive, send)
            return

        headers = {
            bytes(key).decode("latin-1").lower(): bytes(value).decode("latin-1")
            for key, value in scope.get("headers") or ()
        }
        raw_length = headers.get("content-length")
        if raw_length:
            try:
                if int(raw_length) > limit:
                    await self._reject(send, limit)
                    return
            except ValueError:
                # Let the HTTP server/framework report malformed transport
                # metadata; never trust it to bypass the streamed-byte check.
                pass

        messages: list[dict[str, Any]] = []
        observed = 0
        while True:
            message = await receive()
            messages.append(message)
            if message.get("type") == "http.request":
                observed += len(message.get("body") or b"")
                if observed > limit:
                    await self._reject(send, limit)
                    return
                if not message.get("more_body", False):
                    break
            elif message.get("type") == "http.disconnect":
                break

        index = 0

        async def replay_receive() -> dict[str, Any]:
            nonlocal index
            if index < len(messages):
                message = messages[index]
                index += 1
                return message
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)


def public_v2_write_paths(openapi: Mapping[str, Any]) -> tuple[str, ...]:
    """Return stable ``METHOD path`` keys for all characterized writes."""
    writes: list[str] = []
    for path, path_item in (openapi.get("paths") or {}).items():
        if public_v2_surface(str(path)) is None or not isinstance(path_item, Mapping):
            continue
        for method in path_item:
            if str(method).upper() in SAFE_HTTP_METHODS:
                continue
            if str(method).lower() in {"post", "put", "patch", "delete"}:
                writes.append(f"{str(method).upper()} {path}")
    return tuple(sorted(writes))


__all__ = [
    "PUBLIC_V2_SURFACE_PREFIXES",
    "PUBLIC_V2_WRITE_BODY_LIMITS",
    "PublicV2BodyLimitMiddleware",
    "public_v2_surface",
    "public_v2_write_body_limit",
    "public_v2_write_paths",
]
