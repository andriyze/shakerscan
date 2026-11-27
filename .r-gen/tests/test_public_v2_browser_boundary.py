"""The browser boundary must wrap the public-V2 retry and body-limit middleware.

CORS and the unsafe-origin guard are the OUTERMOST layers, so an early response from
the idempotency-replay or body-limit middleware still carries request-scoped CORS
headers, and a disallowed browser origin is rejected before the replay layer runs.
These paths short-circuit before the retry store, so no database double is required.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest
from starlette.middleware.cors import CORSMiddleware

from api.public_api_contract import (
    PublicV2BodyLimitMiddleware,
    PublicV2IdempotencyMiddleware,
    UnsafeOriginGuardMiddleware,
)

ORIGIN = "http://127.0.0.1:3000"
OTHER = "https://untrusted.invalid"
WRITE_PATH = "/request-collections"


async def _inner(scope, receive, send):
    # A trivially successful endpoint; the boundary paths under test never reach it.
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": b"{}"})


def boundary_app():
    # Same nesting api.py installs: CORS(origin-guard(body-limit(idempotency(app)))).
    stack = PublicV2IdempotencyMiddleware(_inner)
    stack = PublicV2BodyLimitMiddleware(stack)
    stack = UnsafeOriginGuardMiddleware(stack, allow_origins=[ORIGIN])
    return CORSMiddleware(stack, allow_origins=[ORIGIN], allow_methods=["*"],
                          allow_headers=["*"])


def _post(app, **kw):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.post(WRITE_PATH, **kw)
    return asyncio.run(run())


def test_disallowed_browser_origin_is_rejected_before_the_retry_layer():
    # The origin guard is outside the idempotency middleware, so a cross-origin mutation
    # cannot reach — much less replay through — the retry store.
    resp = _post(boundary_app(), json={},
                 headers={"Origin": OTHER, "Idempotency-Key": "upload:browser"})
    assert resp.status_code == 403
    assert "idempotency-replayed" not in resp.headers


def test_early_idempotency_error_is_readable_by_the_allowed_ui():
    # An invalid idempotency key is rejected early by the retry layer; CORS wraps it.
    resp = _post(boundary_app(), json={},
                 headers={"Origin": ORIGIN, "Idempotency-Key": "x"})
    assert resp.status_code == 400
    assert resp.headers.get("access-control-allow-origin") == ORIGIN


def test_body_limit_error_is_readable_by_the_allowed_ui():
    # An over-sized write is rejected by the body-limit layer; CORS still applies.
    resp = _post(boundary_app(), content=b"{}",
                 headers={"Origin": ORIGIN, "Content-Length": str(65 * 1024 * 1024)})
    assert resp.status_code == 413
    assert resp.headers.get("access-control-allow-origin") == ORIGIN


def test_allowed_origin_safe_request_passes_through_with_cors():
    resp = _post(boundary_app(), json={}, headers={"Origin": ORIGIN})
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == ORIGIN
