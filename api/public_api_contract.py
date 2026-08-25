"""Shared public V2 API contract and request-boundary helpers.

The application has a large compatibility surface, but the release-critical V2
products below are intentionally small enough to characterize exhaustively.
This module is dependency-light so generation and contract tests can use the
same surface classification and body limits as the running ASGI application.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
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
PUBLIC_V2_IDEMPOTENCY_HEADER = "idempotency-key"
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,199}$")
_MAX_IDEMPOTENT_RESPONSE_BYTES = 4 * 1024 * 1024


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


class PublicV2IdempotencyMiddleware:
    """Replay successful public V2 writes by an opaque client retry key.

    The database stores only SHA-256 digests of the key and request body plus
    the already-public response. Credential and collection request bodies are
    never persisted here. A key is bound to one HTTP method, concrete route,
    and exact body digest; reusing it for different input fails closed.
    """

    def __init__(self, app: Any):
        self.app = app

    @staticmethod
    async def _json_response(
        send: Callable[[dict[str, Any]], Awaitable[None]],
        status: int,
        detail: Mapping[str, Any],
    ) -> None:
        body = json.dumps(
            {"detail": dict(detail)}, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    async def _replay(send: Any, row: Mapping[str, Any]) -> None:
        body = bytes(row.get("response_body") or b"")
        raw_headers = row.get("response_headers") or {}
        if isinstance(raw_headers, str):
            try:
                raw_headers = json.loads(raw_headers)
            except json.JSONDecodeError:
                raw_headers = {}
        headers = [
            (str(name).encode("latin-1"), str(value).encode("latin-1"))
            for name, value in dict(raw_headers).items()
            if str(name).lower() not in {"content-length", "idempotency-replayed"}
        ]
        headers.extend([
            (b"content-length", str(len(body)).encode("ascii")),
            (b"idempotency-replayed", b"true"),
        ])
        await send({
            "type": "http.response.start",
            "status": int(row.get("response_status") or 200),
            "headers": headers,
        })
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Mapping[str, Any], receive: Any, send: Any) -> None:
        method = str(scope.get("method") or "GET").upper()
        path = str(scope.get("path") or "")
        if (
            scope.get("type") != "http"
            or method in SAFE_HTTP_METHODS
            or public_v2_surface(path) is None
        ):
            await self.app(scope, receive, send)
            return

        headers = {
            bytes(key).decode("latin-1").lower(): bytes(value).decode("latin-1")
            for key, value in scope.get("headers") or ()
        }
        key = headers.get(PUBLIC_V2_IDEMPOTENCY_HEADER)
        if not key:
            await self.app(scope, receive, send)
            return
        if not _IDEMPOTENCY_KEY_RE.fullmatch(key):
            await self._json_response(send, 400, {
                "error": "invalid_idempotency_key",
                "message": (
                    "Idempotency-Key must contain 8 to 200 safe characters and "
                    "start with an alphanumeric character."
                ),
            })
            return

        messages: list[dict[str, Any]] = []
        request_body = bytearray()
        while True:
            message = await receive()
            messages.append(message)
            if message.get("type") == "http.request":
                request_body.extend(message.get("body") or b"")
                if not message.get("more_body", False):
                    break
            elif message.get("type") == "http.disconnect":
                break

        key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        request_digest = hashlib.sha256(bytes(request_body)).hexdigest()
        app = scope.get("app")
        pool = getattr(getattr(app, "state", None), "db_pool", None)
        if pool is None:
            # Startup and focused test applications may not own the production
            # database. Fail closed rather than pretending the retry is durable.
            await self._json_response(send, 503, {
                "error": "idempotency_store_unavailable",
                "message": "The public API retry store is unavailable.",
            })
            return

        claimed = False
        async with pool.acquire() as conn:
            inserted = await conn.fetchrow(
                """INSERT INTO public_api_idempotency (
                       method, path, key_sha256, request_sha256, state
                   ) VALUES ($1,$2,$3,$4,'processing')
                   ON CONFLICT (method, path, key_sha256) DO NOTHING
                   RETURNING method""",
                method, path, key_digest, request_digest,
            )
            if inserted:
                claimed = True
            else:
                row = await conn.fetchrow(
                    """SELECT * FROM public_api_idempotency
                       WHERE method=$1 AND path=$2 AND key_sha256=$3""",
                    method, path, key_digest,
                )
                if row and str(row.get("request_sha256") or "") != request_digest:
                    await self._json_response(send, 409, {
                        "error": "idempotency_key_reused",
                        "message": "Idempotency-Key was already used for different input.",
                    })
                    return
                if row and row.get("state") == "completed":
                    await self._replay(send, row)
                    return
                reclaimed = await conn.fetchrow(
                    """UPDATE public_api_idempotency
                       SET updated_at=NOW()
                       WHERE method=$1 AND path=$2 AND key_sha256=$3
                         AND request_sha256=$4 AND state='processing'
                         AND updated_at < NOW() - INTERVAL '10 minutes'
                       RETURNING method""",
                    method, path, key_digest, request_digest,
                )
                if reclaimed:
                    claimed = True
                else:
                    await self._json_response(send, 409, {
                        "error": "idempotency_request_in_progress",
                        "message": "A request with this Idempotency-Key is still processing.",
                    })
                    return

        index = 0

        async def replay_receive() -> dict[str, Any]:
            nonlocal index
            if index < len(messages):
                message = messages[index]
                index += 1
                return message
            return {"type": "http.request", "body": b"", "more_body": False}

        response_messages: list[dict[str, Any]] = []

        async def capture_send(message: dict[str, Any]) -> None:
            response_messages.append(message)

        try:
            await self.app(scope, replay_receive, capture_send)
        except BaseException:
            if claimed:
                async with pool.acquire() as conn:
                    await conn.execute(
                        """DELETE FROM public_api_idempotency
                           WHERE method=$1 AND path=$2 AND key_sha256=$3
                             AND request_sha256=$4 AND state='processing'""",
                        method, path, key_digest, request_digest,
                    )
            raise

        start = next((
            item for item in response_messages
            if item.get("type") == "http.response.start"
        ), None)
        response_body = b"".join(
            bytes(item.get("body") or b"")
            for item in response_messages
            if item.get("type") == "http.response.body"
        )
        status = int((start or {}).get("status") or 500)
        response_headers = {
            bytes(name).decode("latin-1").lower(): bytes(value).decode("latin-1")
            for name, value in (start or {}).get("headers") or ()
            if bytes(name).decode("latin-1").lower() in {
                "content-type", "location", "x-shakerscan-hunt-contract",
            }
        }
        content_type = response_headers.get("content-type", "").lower()
        cacheable = (
            200 <= status < 300
            and "json" in content_type
            and len(response_body) <= _MAX_IDEMPOTENT_RESPONSE_BYTES
        )
        async with pool.acquire() as conn:
            if cacheable:
                await conn.execute(
                    """UPDATE public_api_idempotency
                       SET state='completed', response_status=$5,
                           response_headers=$6::jsonb, response_body=$7,
                           updated_at=NOW(), completed_at=NOW()
                       WHERE method=$1 AND path=$2 AND key_sha256=$3
                         AND request_sha256=$4 AND state='processing'""",
                    method, path, key_digest, request_digest, status,
                    json.dumps(response_headers, sort_keys=True), response_body,
                )
            else:
                await conn.execute(
                    """DELETE FROM public_api_idempotency
                       WHERE method=$1 AND path=$2 AND key_sha256=$3
                         AND request_sha256=$4 AND state='processing'""",
                    method, path, key_digest, request_digest,
                )
        for message in response_messages:
            await send(message)


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


def add_public_v2_idempotency_openapi(openapi: dict[str, Any]) -> dict[str, Any]:
    """Declare the optional durable retry header on every public V2 write."""
    for path, path_item in (openapi.get("paths") or {}).items():
        if public_v2_surface(str(path)) is None or not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if (
                str(method).upper() in SAFE_HTTP_METHODS
                or str(method).lower() not in {"post", "put", "patch", "delete"}
                or not isinstance(operation, dict)
            ):
                continue
            parameters = operation.setdefault("parameters", [])
            if not any(
                isinstance(item, Mapping)
                and item.get("in") == "header"
                and str(item.get("name") or "").lower() == "idempotency-key"
                for item in parameters
            ):
                parameters.append({
                    "name": "Idempotency-Key",
                    "in": "header",
                    "required": False,
                    "description": (
                        "Opaque 8-200 character retry key. The key is bound to the "
                        "exact method, concrete path, and request-body digest."
                    ),
                    "schema": {
                        "type": "string", "minLength": 8, "maxLength": 200,
                        "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:-]{7,199}$",
                    },
                })
    return openapi


__all__ = [
    "PUBLIC_V2_SURFACE_PREFIXES",
    "PUBLIC_V2_WRITE_BODY_LIMITS",
    "PUBLIC_V2_IDEMPOTENCY_HEADER",
    "PublicV2BodyLimitMiddleware",
    "PublicV2IdempotencyMiddleware",
    "add_public_v2_idempotency_openapi",
    "public_v2_surface",
    "public_v2_write_body_limit",
    "public_v2_write_paths",
]
