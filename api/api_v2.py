#!/usr/bin/env python3
"""V2 API entrypoint layered over the existing control-plane application.

The legacy application still owns the mature database, queue, fleet, evidence, and route
implementation.  This wrapper adds a fail-closed, structured Hunt start contract without
editing the multi-megabyte compatibility module.  It can be removed after `/hunts` natively
accepts the same contract.
"""

from __future__ import annotations

import json
import os
from typing import Any, Awaitable, Callable, Mapping

import api as _legacy_api
from hunt.start_contract import (
    MAX_HUNT_BODY_BYTES,
    HuntStartContractError,
    normalize_hunt_start_payload,
)


ASGIApp = Callable[[dict[str, Any], Callable[[], Awaitable[dict[str, Any]]], Callable[[dict[str, Any]], Awaitable[None]]], Awaitable[None]]


async def _json_response(
    send: Callable[[dict[str, Any]], Awaitable[None]],
    status: int,
    payload: Mapping[str, Any],
) -> None:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": int(status),
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"x-shakerscan-hunt-contract", b"v2"),
        ],
    })
    await send({"type": "http.response.body", "body": body, "more_body": False})


class HuntStartContractMiddleware:
    """Validate explicit Hunt authority before the compatibility route sees a request."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    @staticmethod
    def _is_hunt_start(scope: Mapping[str, Any]) -> bool:
        if scope.get("type") != "http" or str(scope.get("method") or "").upper() != "POST":
            return False
        path = str(scope.get("path") or "").rstrip("/")
        return path == "/hunts" or path.endswith("/hunts")

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if not self._is_hunt_start(scope):
            await self.app(scope, receive, send)
            return

        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message.get("type") != "http.request":
                await _json_response(send, 400, {"detail": "invalid HTTP request body"})
                return
            chunk = bytes(message.get("body") or b"")
            total += len(chunk)
            if total > MAX_HUNT_BODY_BYTES:
                await _json_response(send, 413, {"detail": "Hunt request body is too large"})
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        raw_body = b"".join(chunks)
        try:
            decoded = json.loads(raw_body.decode("utf-8"))
            contract = normalize_hunt_start_payload(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError):
            await _json_response(send, 400, {"detail": "Hunt request body must be valid JSON"})
            return
        except HuntStartContractError as exc:
            await _json_response(
                send,
                422,
                {"detail": str(exc), "schema_version": "hunt-start/v2"},
            )
            return

        # The compatibility route predates the structured policy object. The wrapper enforces it,
        # then forwards only fields the existing route already understands. It intentionally never
        # inserts raw credentials; all credential values remain opaque profile references.
        forwarded = json.dumps(
            contract.legacy_payload(decoded),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        delivered = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": forwarded, "more_body": False}

        async def contract_send(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers") or [])
                headers.append((b"x-shakerscan-hunt-contract", b"v2"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, replay_receive, contract_send)


app = HuntStartContractMiddleware(_legacy_api.app)


def main() -> None:
    import uvicorn

    host = str(os.environ.get("SHAKERSCAN_API_HOST") or "0.0.0.0")
    try:
        port = int(os.environ.get("SHAKERSCAN_API_PORT") or "8080")
    except ValueError as exc:
        raise SystemExit("SHAKERSCAN_API_PORT must be an integer") from exc
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
