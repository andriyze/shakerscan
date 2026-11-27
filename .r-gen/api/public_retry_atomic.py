"""Atomic retry receipts for explicitly integrated PostgreSQL-only mutations.

Do not use for queue, filesystem, network, Scan or Hunt execution. A handler
must acquire every mutation connection through acquire_for_atomic_retry. The
side effects and the existing public_api_idempotency response commit together.
Pre-upgrade ambiguous reservations remain blocked, never erased by age.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import hashlib
import json
from typing import Any


@dataclass
class _Binding:
    pool: Any
    conn: Any
    active: bool = True
    borrower: Any = None


_connection: ContextVar[_Binding | None] = ContextVar("public_atomic_retry_connection", default=None)


@asynccontextmanager
async def acquire_for_atomic_retry(pool):
    binding = _connection.get()
    if binding is None:
        async with pool.acquire() as conn:
            yield conn
        return
    task = asyncio.current_task()
    if (pool is not binding.pool or not binding.active
            or binding.borrower is not None and binding.borrower is not task):
        raise RuntimeError("Atomic retry connection is unavailable for this operation")
    # ASGI middleware can hand the request to an awaited child task. Permit
    # serial borrowing across that boundary, never concurrent or late use.
    previous = binding.borrower
    binding.borrower = task
    try:
        yield binding.conn
    finally:
        binding.borrower = previous


class _RollbackResponse(Exception):
    """Roll back a rejected mutation before forwarding its HTTP response."""


class _InvalidResponse(Exception):
    """No mutation may commit without a bounded replayable response."""


async def execute_atomic_write(
    middleware, *, scope, messages, send, pool, key_digest, request_digest,
    max_response_bytes, receive_after_body=None,
):
    method, path = scope["method"].upper(), scope["path"]
    # A narrow allowlist makes accidentally wrapping external effects impossible.
    if (method, path) != ("POST", "/request-collections"):
        raise ValueError("Mutation has not integrated atomic PostgreSQL retries")
    lock_key = int.from_bytes(hashlib.sha256(
        f"{method}\0{path}\0{key_digest}".encode()
    ).digest()[:8], "big", signed=True)
    responses = []
    response_size = 0

    async def capture(message):
        nonlocal response_size
        response_size += len(message.get("body") or b"")
        if response_size > max_response_bytes or len(responses) >= 1024:
            raise _InvalidResponse
        responses.append(dict(message))

    async def reject(code, error, message):
        await middleware._json_response(capture, code, {"error": error, "message": message})

    try:
        async with pool.acquire() as conn, conn.transaction():
            # Nonblocking serialization avoids waiting for a concurrent upload.
            # A process/connection loss releases this PostgreSQL transaction lock.
            locked = await conn.fetchval("SELECT pg_try_advisory_xact_lock($1)", lock_key)
            if not locked:
                await reject(409, "idempotency_request_in_progress", "This request is still processing.")
            else:
                inserted = await conn.fetchrow(
                    """INSERT INTO public_api_idempotency
                    (method,path,key_sha256,request_sha256,state)
                    VALUES($1,$2,$3,$4,'processing')
                    ON CONFLICT (method,path,key_sha256) DO NOTHING RETURNING method""",
                    method, path, key_digest, request_digest,
                )
                if not inserted:
                    row = await conn.fetchrow(
                        "SELECT * FROM public_api_idempotency WHERE method=$1 AND path=$2 AND key_sha256=$3",
                        method, path, key_digest,
                    )
                    if row and row["request_sha256"] != request_digest:
                        await reject(409, "idempotency_key_reused", "Idempotency-Key was already used for different input.")
                    elif row and row["state"] == "completed":
                        await middleware._replay(capture, row)
                    else:
                        # The old middleware may have recorded a side effect
                        # without its receipt. A free lock is NOT proof otherwise.
                        await reject(409, "idempotency_request_in_progress", "An earlier request has an unconfirmed outcome; reconciliation is required.")
                else:
                    index = 0

                    async def receive():
                        nonlocal index
                        if index < len(messages):
                            message = messages[index]
                            index += 1
                            return message
                        if receive_after_body is not None:
                            return await receive_after_body()
                        return {"type": "http.request", "body": b"", "more_body": False}

                    binding = _Binding(pool, conn)
                    token = _connection.set(binding)
                    try:
                        await middleware.app(scope, receive, capture)
                    finally:
                        binding.active = False
                        _connection.reset(token)
                    if binding.borrower is not None:
                        raise RuntimeError("Atomic retry handler returned with an active database borrower")
                    starts = [m for m in responses if m.get("type") == "http.response.start"]
                    bodies = [m for m in responses if m.get("type") == "http.response.body"]
                    if len(starts) != 1 or not bodies or bodies[-1].get("more_body", False):
                        raise _InvalidResponse
                    status = int(starts[0]["status"])
                    if not 200 <= status < 300:
                        raise _RollbackResponse
                    headers = {
                        bytes(k).decode("latin-1").lower(): bytes(v).decode("latin-1")
                        for k, v in starts[0].get("headers", ())
                        if bytes(k).decode("latin-1").lower() in {"content-type", "location"}
                    }
                    body = b"".join(bytes(m.get("body") or b"") for m in bodies)
                    if "json" not in headers.get("content-type", "").lower():
                        raise _InvalidResponse
                    try:
                        json.loads(body)
                    except (ValueError, UnicodeError):
                        raise _InvalidResponse from None
                    updated = await conn.execute(
                        """UPDATE public_api_idempotency SET state='completed',response_status=$5,
                        response_headers=$6::jsonb,response_body=$7,updated_at=NOW(),completed_at=NOW()
                        WHERE method=$1 AND path=$2 AND key_sha256=$3
                        AND request_sha256=$4 AND state='processing'""",
                        method, path, key_digest, request_digest, status,
                        json.dumps(headers, sort_keys=True), body,
                    )
                    if updated != "UPDATE 1":
                        raise RuntimeError("Atomic retry receipt could not be committed")
    except _RollbackResponse:
        pass
    except _InvalidResponse:
        responses.clear()
        response_size = 0
        await reject(503, "atomic_response_not_recorded", "The database mutation was rolled back; retry with the same key.")
    # Only after COMMIT (or confirmed ROLLBACK) can the client see a response.
    # A send failure leaves either both the effect and receipt, or neither.
    for message in responses:
        await send(message)
