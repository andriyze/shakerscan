"""Server guards: no single request class can exhaust the API process or the database.

One pure-ASGI middleware (``RequestGuardMiddleware``) classifies every HTTP request once and
applies three guards; the pool hooks and the uvicorn options apply the rest.

* **Statement timeout per request class.** The pool's session default (``server_settings``,
  which survives the ``RESET ALL`` asyncpg runs on every release) is ``DB_STATEMENT_TIMEOUT_MS``.
  On each ``acquire`` the pool ``setup`` hook sets the timeout of the request class that is
  acquiring, read from a context variable the middleware sets:

  ========================  ==========================================  ===============
  class                     requests                                    default
  ========================  ==========================================  ===============
  ``interactive``           GET/HEAD reads                              5 s
  ``heavy``                 admission-controlled reads (below)          30 s
  ``export``                exports, reports, archive downloads         120 s
  default                   writes, background loops, worker processes  30 s API, 60 s worker
  ``unbounded_statements``  startup schema migrations                   none
  ========================  ==========================================  ===============

  A statement over its budget is cancelled by PostgreSQL; an unhandled cancellation answers
  504 ``statement_timeout`` instead of a 500.

* **Admission control for heavy reads.** Exposure, dashboard, grouped targets, the inventory
  when it computes facets/groups/risk, and exports each have their own small pool of slots
  (``SHAKERSCAN_API_HEAVY_CONCURRENCY``, default 2). A request waits up to
  ``SHAKERSCAN_API_HEAVY_ADMISSION_WAIT_SECONDS`` for a slot, then gets 429 with
  ``Retry-After``. A slot is held until the response has been sent. Archive transaction
  exports and Hunt records keep their own export slots and are only timeout-classed here.

* **Response byte budget.** A JSON response larger than ``SHAKERSCAN_API_RESPONSE_MAX_BYTES``
  (50 MiB; exports ``SHAKERSCAN_API_EXPORT_RESPONSE_MAX_BYTES``, 512 MiB) is refused with 500
  ``response_too_large`` when its length is declared, and its connection is aborted when it is
  streamed past the budget. Event streams and file downloads are not JSON and are not budgeted.

* **Process ceilings.** ``uvicorn_options()`` passes ``limit_concurrency``
  (``SHAKERSCAN_API_LIMIT_CONCURRENCY``, default 256; uvicorn answers 503 beyond it), and the
  Compose files cap the API container's memory (``SHAKERSCAN_API_MEMORY_LIMIT``) so an OOM kills
  and restarts the API instead of the host.

Every knob is an environment variable read at import; ``0`` disables a numeric guard.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import json
import logging
import os
import re
from typing import Any, Awaitable, Callable, Iterator, Mapping
from urllib.parse import parse_qs
import weakref

logger = logging.getLogger(__name__)

INTERACTIVE = "interactive"
HEAVY = "heavy"
EXPORT = "export"
DEFAULT = "default"

MIB = 1024 * 1024


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except ValueError:
        return default
    return max(0, value)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    try:
        value = float(raw) if raw not in (None, "") else default
    except ValueError:
        return default
    return max(0.0, value)


@dataclass(frozen=True)
class GuardSettings:
    default_timeout_ms: int = 30_000
    interactive_timeout_ms: int = 5_000
    heavy_timeout_ms: int = 30_000
    export_timeout_ms: int = 120_000
    heavy_concurrency: int = 2
    admission_wait_seconds: float = 1.0
    retry_after_seconds: int = 5
    response_max_bytes: int = 50 * MIB
    export_response_max_bytes: int = 512 * MIB
    limit_concurrency: int = 256

    @classmethod
    def from_env(cls) -> "GuardSettings":
        return cls(
            default_timeout_ms=_env_int("DB_STATEMENT_TIMEOUT_MS", 30_000),
            interactive_timeout_ms=_env_int("SHAKERSCAN_API_READ_STATEMENT_TIMEOUT_MS", 5_000),
            heavy_timeout_ms=_env_int("SHAKERSCAN_API_HEAVY_STATEMENT_TIMEOUT_MS", 30_000),
            export_timeout_ms=_env_int("SHAKERSCAN_API_EXPORT_STATEMENT_TIMEOUT_MS", 120_000),
            heavy_concurrency=_env_int("SHAKERSCAN_API_HEAVY_CONCURRENCY", 2),
            admission_wait_seconds=_env_float("SHAKERSCAN_API_HEAVY_ADMISSION_WAIT_SECONDS", 1.0),
            retry_after_seconds=max(1, _env_int("SHAKERSCAN_API_HEAVY_RETRY_AFTER_SECONDS", 5)),
            response_max_bytes=_env_int("SHAKERSCAN_API_RESPONSE_MAX_BYTES", 50 * MIB),
            export_response_max_bytes=_env_int("SHAKERSCAN_API_EXPORT_RESPONSE_MAX_BYTES", 512 * MIB),
            limit_concurrency=_env_int("SHAKERSCAN_API_LIMIT_CONCURRENCY", 256),
        )

    def timeout_for(self, kind: str) -> int:
        return {
            INTERACTIVE: self.interactive_timeout_ms,
            HEAVY: self.heavy_timeout_ms,
            EXPORT: self.export_timeout_ms,
        }.get(kind, self.default_timeout_ms)

    def response_budget_for(self, kind: str) -> int:
        return self.export_response_max_bytes if kind == EXPORT else self.response_max_bytes


SETTINGS = GuardSettings.from_env()


# --- Request classification --------------------------------------------------------------------


@dataclass(frozen=True)
class RequestClass:
    kind: str
    admission_group: str | None = None


_SAFE = frozenset({"GET", "HEAD"})
_DEFAULT_CLASS = RequestClass(DEFAULT)
_INTERACTIVE_CLASS = RequestClass(INTERACTIVE)

# Exports with no admission of their own: one slot pool ("exports").
_EXPORT_PATHS = tuple(re.compile(pattern) for pattern in (
    r"^/evidence/export-(?:bundle|manifest)$",
    r"^/model-intake/scans/[^/]+/evidence-export$",
    r"^/model-intake/submissions/[^/]+/report$",
    r"^/model-intake/automatic-reviews/[^/]+/report$",
    r"^/ai/test-cases/export$",
    r"^/ai/targets/[^/]+/campaign-history/export$",
    r"^/scans/[^/]+/ai-redteam-report$",
))
# Exports that already take an archive export slot: a longer timeout and budget only.
_SELF_ADMITTED_EXPORT_PATHS = tuple(re.compile(pattern) for pattern in (
    r"^/(?:scans|hunts)/[^/]+/http-transactions$",
    r"^/hunts/[^/]+/record$",
))


def _truthy(values: list[str]) -> bool:
    return bool(values) and values[-1].strip().lower() in {"1", "true", "yes", "on"}


def classify_request(method: str, path: str, query_string: bytes | str = b"") -> RequestClass:
    """The guard class of one request; only GET/HEAD reads are ever narrowed."""
    if method.upper() not in _SAFE:
        return _DEFAULT_CLASS
    path = path.rstrip("/") or "/"
    if path == "/dashboard":
        return RequestClass(HEAVY, "dashboard")
    if path.startswith("/exposure/"):
        return RequestClass(HEAVY, "exposure")
    if path == "/targets/grouped":
        return RequestClass(HEAVY, "inventory")
    if path == "/targets/inventory":
        raw = query_string.decode("latin-1") if isinstance(query_string, bytes) else query_string
        query = parse_qs(raw, keep_blank_values=True)
        if (_truthy(query.get("include_facets", [])) or any(query.get("group_by", []))
                or (query.get("sort") or [""])[-1] == "risk"):
            return RequestClass(HEAVY, "inventory")
        return _INTERACTIVE_CLASS
    if any(pattern.match(path) for pattern in _EXPORT_PATHS):
        return RequestClass(EXPORT, "exports")
    if any(pattern.match(path) for pattern in _SELF_ADMITTED_EXPORT_PATHS):
        return RequestClass(EXPORT)
    return _INTERACTIVE_CLASS


# --- Statement timeouts ------------------------------------------------------------------------

_statement_timeout_ms: ContextVar[int | None] = ContextVar("shakerscan_statement_timeout_ms", default=None)


@contextmanager
def statement_timeout(milliseconds: int) -> Iterator[None]:
    """Run the enclosed pool acquisitions under ``milliseconds`` (0: unbounded)."""
    token = _statement_timeout_ms.set(max(0, int(milliseconds)))
    try:
        yield
    finally:
        _statement_timeout_ms.reset(token)


def unbounded_statements() -> Any:
    """For startup schema migrations: an index build on a large table must not be cancelled."""
    return statement_timeout(0)


def statement_timeout_pool_options(default_timeout_ms: int) -> dict[str, Any]:
    """``create_pool`` options: a session default that survives the release reset, plus a
    per-acquire override for the current request class."""
    default = max(0, int(default_timeout_ms))

    async def setup(connection: Any) -> None:
        wanted = _statement_timeout_ms.get()
        if wanted is not None and wanted != default:
            await connection.execute(f"SET statement_timeout = {int(wanted)}")

    return {"server_settings": {"statement_timeout": str(default)}, "setup": setup}


# --- Admission ---------------------------------------------------------------------------------


class _Slots:
    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.active = 0
        self.changed = asyncio.Condition()

    async def acquire(self, wait_seconds: float) -> bool:
        async with self.changed:
            if self.active >= self.capacity:
                try:
                    await asyncio.wait_for(
                        self.changed.wait_for(lambda: self.active < self.capacity), wait_seconds,
                    )
                except TimeoutError:
                    return False
            self.active += 1
            return True

    async def release(self) -> None:
        async with self.changed:
            self.active -= 1
            self.changed.notify()


class AdmissionGate:
    """Per-group slot pools, one set per event loop."""

    def __init__(self, capacity: int, wait_seconds: float) -> None:
        self.capacity = capacity
        self.wait_seconds = wait_seconds
        self._pools: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, _Slots]] = (
            weakref.WeakKeyDictionary()
        )

    def _slots(self, group: str) -> _Slots:
        loop = asyncio.get_running_loop()
        pools = self._pools.setdefault(loop, {})
        if group not in pools:
            pools[group] = _Slots(self.capacity)
        return pools[group]

    def active(self, group: str) -> int:
        return self._slots(group).active

    async def acquire(self, group: str) -> bool:
        if self.capacity <= 0:
            return True
        return await self._slots(group).acquire(self.wait_seconds)

    async def release(self, group: str) -> None:
        if self.capacity > 0:
            await self._slots(group).release()


# --- The middleware ----------------------------------------------------------------------------


class ResponseBudgetExceeded(RuntimeError):
    """A streamed JSON response passed its byte budget after its status line was sent."""


Send = Callable[[Mapping[str, Any]], Awaitable[None]]


async def _send_json(send: Send, status: int, detail: Mapping[str, Any],
                     headers: tuple[tuple[bytes, bytes], ...] = ()) -> None:
    body = json.dumps({"detail": dict(detail)}, separators=(",", ":")).encode("utf-8")
    await send({
        "type": "http.response.start", "status": status,
        "headers": [(b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")), *headers],
    })
    await send({"type": "http.response.body", "body": body})


def _is_json(headers: list[tuple[bytes, bytes]]) -> tuple[bool, int | None]:
    content_type, length = b"", None
    for key, value in headers:
        name = bytes(key).lower()
        if name == b"content-type":
            content_type = bytes(value).split(b";", 1)[0].strip().lower()
        elif name == b"content-length":
            try:
                length = int(value)
            except ValueError:
                length = None
    is_json = content_type == b"application/json" or content_type.endswith(b"+json")
    return is_json, length


class RequestGuardMiddleware:
    def __init__(self, app: Any, *, settings: GuardSettings | None = None,
                 gate: AdmissionGate | None = None) -> None:
        self.app = app
        self.settings = settings or SETTINGS
        self.gate = gate or AdmissionGate(self.settings.heavy_concurrency,
                                          self.settings.admission_wait_seconds)

    async def __call__(self, scope: Mapping[str, Any], receive: Any, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        request_class = classify_request(
            str(scope.get("method") or "GET"), str(scope.get("path") or "/"),
            scope.get("query_string") or b"",
        )
        group = request_class.admission_group
        if group and not await self.gate.acquire(group):
            retry_after = self.settings.retry_after_seconds
            await _send_json(send, 429, {
                "error": "server_busy",
                "message": f"Too many concurrent {group} requests; retry after {retry_after} s.",
                "retry_after": retry_after,
            }, headers=((b"retry-after", str(retry_after).encode("ascii")),))
            return
        token = None
        if request_class.kind != DEFAULT:
            token = _statement_timeout_ms.set(self.settings.timeout_for(request_class.kind))
        try:
            await self.app(scope, receive, self._budgeted(
                send, self.settings.response_budget_for(request_class.kind), str(scope.get("path")),
            ))
        finally:
            if token is not None:
                _statement_timeout_ms.reset(token)
            if group:
                await self.gate.release(group)

    @staticmethod
    def _budgeted(send: Send, budget: int, path: str) -> Send:
        if budget <= 0:
            return send
        state = {"counting": False, "sent": 0, "refused": False}

        async def guarded(message: Mapping[str, Any]) -> None:
            kind = message.get("type")
            if kind == "http.response.start":
                is_json, length = _is_json(list(message.get("headers") or []))
                if is_json and length is not None and length > budget:
                    state["refused"] = True
                    logger.warning("refused a %d-byte response for %s (budget %d)", length, path, budget)
                    await _send_json(send, 500, {
                        "error": "response_too_large",
                        "message": ("The response exceeds this server's per-request budget; "
                                    "request a smaller page, fewer fields or a narrower filter."),
                        "max_bytes": budget,
                    })
                    return
                state["counting"] = is_json
            elif kind == "http.response.body":
                if state["refused"]:
                    return
                if state["counting"]:
                    state["sent"] += len(message.get("body") or b"")
                    if state["sent"] > budget:
                        logger.warning("aborted a streamed response for %s past %d bytes", path, budget)
                        raise ResponseBudgetExceeded(f"response for {path} exceeded {budget} bytes")
            await send(message)

        return guarded


# --- Composition -------------------------------------------------------------------------------


def _is_query_cancelled(exc: BaseException) -> bool:
    return type(exc).__name__ == "QueryCanceledError"


def configure_request_guards(app: Any, settings: GuardSettings | None = None) -> None:
    """Install the middleware and the statement-timeout answer on a FastAPI app."""
    from starlette.responses import JSONResponse

    try:
        from asyncpg.exceptions import QueryCanceledError
    except ModuleNotFoundError:  # asyncpg-free test environments
        QueryCanceledError = None  # noqa: N806

    app.add_middleware(RequestGuardMiddleware, settings=settings or SETTINGS)

    if QueryCanceledError is not None:
        async def _statement_cancelled(request: Any, exc: Exception) -> Any:
            logger.warning("statement timeout on %s %s", request.method, request.url.path)
            return JSONResponse(status_code=504, content={"detail": {
                "error": "statement_timeout",
                "message": "The database query exceeded this request's time budget.",
            }})

        app.add_exception_handler(QueryCanceledError, _statement_cancelled)


def uvicorn_options(settings: GuardSettings | None = None) -> dict[str, Any]:
    settings = settings or SETTINGS
    return {"limit_concurrency": settings.limit_concurrency} if settings.limit_concurrency else {}


__all__ = [
    "AdmissionGate",
    "GuardSettings",
    "RequestClass",
    "RequestGuardMiddleware",
    "ResponseBudgetExceeded",
    "SETTINGS",
    "classify_request",
    "configure_request_guards",
    "statement_timeout",
    "statement_timeout_pool_options",
    "unbounded_statements",
    "uvicorn_options",
]
