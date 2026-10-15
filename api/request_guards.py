"""Server guards: no single request class can exhaust the API process or the database.

One pure-ASGI middleware (``RequestGuardMiddleware``) classifies every HTTP request once, from
the single ``ROUTE_CLASSES`` table, and applies the guards below; the pool hooks apply the
statement timeouts.

* **Statement timeout per request class.** The pool's session default (``server_settings``,
  which survives the ``RESET ALL`` asyncpg runs on every release) is ``DB_STATEMENT_TIMEOUT_MS``.
  On each ``acquire`` the pool ``setup`` hook sets the timeout of the request class that is
  acquiring, read from a context variable the middleware sets:

  ========================  ==========================================  ===============
  class                     requests                                    default
  ========================  ==========================================  ===============
  ``interactive``           GET/HEAD reads                              5 s
  ``heavy``                 admission-controlled reads (the table)      30 s
  ``export``                exports, reports, archive downloads         120 s
  default                   writes, background loops, worker processes  30 s API, 60 s worker
  ``unbounded_statements``  startup schema migrations                   none
  ========================  ==========================================  ===============

  A statement over its budget is cancelled by PostgreSQL; an unhandled cancellation answers
  504 ``statement_timeout`` instead of a 500. Code that catches broad exceptions around a query
  calls ``reraise_statement_timeout(exc)`` first so a cancellation is not reported as an empty
  or "unavailable" result.

* **Admission control for heavy reads.** Every ``ROUTE_CLASSES`` row with a group has its own
  small pool of slots (``SHAKERSCAN_API_HEAVY_CONCURRENCY``, default 2). A request waits up to
  ``SHAKERSCAN_API_HEAVY_ADMISSION_WAIT_SECONDS`` for a slot, then gets 429 with
  ``Retry-After``. The slot is returned as soon as the response body has been produced (before
  the last body chunk is written), so a slow client does not hold it. Instead, every body write
  of a heavy response must complete within ``SHAKERSCAN_API_HEAVY_SEND_TIMEOUT_SECONDS`` (30 s)
  or the connection is aborted, so rendered bodies parked behind clients that do not read are
  bounded too.

* **In-flight request ceiling.** At most ``SHAKERSCAN_API_MAX_IN_FLIGHT_REQUESTS`` (256)
  requests may be producing a response at once; beyond that a request gets 503 with
  ``Retry-After`` (and CORS headers, since this middleware sits inside CORS). A request counts
  from reaching the app until its response starts, except while it waits on the client
  (``receive``: a request body still arriving, a disconnect): open idle connections, slow
  uploaders and long event streams never fill the ceiling. (uvicorn's ``limit_concurrency`` is deliberately not used: it
  counts idle connections, so a few hundred bare TCP sockets would refuse every request.)

* **Response byte budget (wire bytes only).** A JSON response larger than
  ``SHAKERSCAN_API_RESPONSE_MAX_BYTES`` (50 MiB; exports
  ``SHAKERSCAN_API_EXPORT_RESPONSE_MAX_BYTES``, 512 MiB) is not sent: refused with 500
  ``response_too_large`` when its length is declared, its connection aborted when streamed past
  the budget. This bounds what leaves the process, not the memory used to build the response:
  a ``JSONResponse`` is fully rendered before this guard sees it. Memory is bounded by the
  container limit (``SHAKERSCAN_API_MEMORY_LIMIT`` in Compose) and, per endpoint, by the list
  contract. Event streams and file downloads are not JSON and are not budgeted.

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

from pydantic import TypeAdapter, ValidationError

logger = logging.getLogger(__name__)

INTERACTIVE = "interactive"
HEAVY = "heavy"
EXPORT = "export"
DEFAULT = "default"

MIB = 1024 * 1024
_BOOL = TypeAdapter(bool)


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
    max_in_flight: int = 256
    heavy_send_timeout_seconds: float = 30.0

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
            max_in_flight=_env_int("SHAKERSCAN_API_MAX_IN_FLIGHT_REQUESTS", 256),
            heavy_send_timeout_seconds=_env_float("SHAKERSCAN_API_HEAVY_SEND_TIMEOUT_SECONDS", 30.0),
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


def _query(query_string: bytes | str) -> dict[str, list[str]]:
    raw = query_string.decode("latin-1") if isinstance(query_string, bytes) else query_string
    return parse_qs(raw, keep_blank_values=True)


def _query_bool(query: Mapping[str, list[str]], name: str) -> bool:
    """The request's boolean exactly as the endpoint's FastAPI/pydantic ``bool`` reads it."""
    values = query.get(name) or []
    if not values:
        return False
    try:
        return bool(_BOOL.validate_python(values[-1]))
    except ValidationError:
        return False  # the endpoint answers 422; nothing heavy runs


def _inventory_is_heavy(query: Mapping[str, list[str]]) -> bool:
    return (_query_bool(query, "include_facets") or any(query.get("group_by") or [])
            or (query.get("sort") or [""])[-1] == "risk")


def _legacy_list_shape(query: Mapping[str, list[str]]) -> bool:
    """A reworked list answered in its deprecated legacy shape: no list/v1 opt-in parameter
    (``list_compat.LIST_V1_OPT_IN``) is present."""
    return not any(name in query for name in ("cursor", "count", "fields", "since"))


@dataclass(frozen=True)
class RouteRule:
    """One row of ``ROUTE_CLASSES``: GET/HEAD paths matching ``pattern`` (and ``when``, if
    given, over the parsed query) get ``kind`` and, with a ``group``, admission slots."""

    pattern: re.Pattern[str]
    kind: str
    group: str | None = None
    when: Callable[[Mapping[str, list[str]]], bool] | None = None


def _rule(pattern: str, kind: str, group: str | None = None, when=None) -> RouteRule:
    return RouteRule(re.compile(pattern), kind, group, when)


#: The one classification table, first match wins; unmatched reads are ``interactive`` and
#: everything that is not GET/HEAD is ``default``. When an endpoint becomes bounded (list
#: contract, summary tables), delete its row here so it returns to the 5 s interactive budget.
ROUTE_CLASSES: tuple[RouteRule, ...] = (
    _rule(r"^/dashboard$", HEAVY, "dashboard"),
    _rule(r"^/exposure/.+$", HEAVY, "exposure"),
    _rule(r"^/targets/grouped$", HEAVY, "inventory"),
    _rule(r"^/targets/inventory$", HEAVY, "inventory", _inventory_is_heavy),
    # Unbounded today, measured or suspected over 5 s at scale. Interim rows until each
    # endpoint's rework lands; then delete the row.
    _rule(r"^/findings$", HEAVY, "findings"),
    # The graph's list/v1 pages are bounded; its deprecated whole-graph response is not.
    _rule(r"^/targets/[^/]+/graph$", HEAVY, "target_graph", _legacy_list_shape),
    # /asm/coverage is counted in SQL (one row); the other ASM reads are not reworked yet.
    _rule(r"^/targets/[^/]+/asm/(?!coverage$).+$", HEAVY, "asm"),
    # Exports with no admission of their own share one slot pool.
    _rule(r"^/evidence/export-(?:bundle|manifest)$", EXPORT, "exports"),
    _rule(r"^/model-intake/scans/[^/]+/evidence-export$", EXPORT, "exports"),
    _rule(r"^/model-intake/submissions/[^/]+/report$", EXPORT, "exports"),
    _rule(r"^/model-intake/automatic-reviews/[^/]+/report$", EXPORT, "exports"),
    _rule(r"^/ai/test-cases/export$", EXPORT, "exports"),
    _rule(r"^/ai/targets/[^/]+/campaign-history/export$", EXPORT, "exports"),
    _rule(r"^/scans/[^/]+/ai-redteam-report$", EXPORT, "exports"),
    # Archive exports and Hunt records already take an archive export slot: timeout and
    # byte budget only.
    _rule(r"^/(?:scans|hunts)/[^/]+/http-transactions$", EXPORT),
    _rule(r"^/hunts/[^/]+/record$", EXPORT),
)

#: Liveness answers even when the in-flight ceiling is reached.
UNCAPPED_PATHS = frozenset({"/health"})

_SAFE = frozenset({"GET", "HEAD"})
_DEFAULT_CLASS = RequestClass(DEFAULT)
_INTERACTIVE_CLASS = RequestClass(INTERACTIVE)


def classify_request(method: str, path: str, query_string: bytes | str = b"") -> RequestClass:
    """The guard class of one request; only GET/HEAD reads are ever narrowed."""
    if method.upper() not in _SAFE:
        return _DEFAULT_CLASS
    path = path.rstrip("/") or "/"
    query: dict[str, list[str]] | None = None
    for rule in ROUTE_CLASSES:
        if not rule.pattern.match(path):
            continue
        if rule.when is not None:
            if query is None:
                query = _query(query_string)
            if not rule.when(query):
                continue
        return RequestClass(rule.kind, rule.group)
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


@contextmanager
def detached_statements() -> Iterator[None]:
    """Back to the pool's session default, for work a request starts that outlives it.

    The request class lives in a context variable, and ``asyncio.create_task`` copies the
    context: a task spawned while serving a GET would keep the 5 s interactive budget for its
    whole life. Start such a task inside ``with detached_statements():`` (or from a background
    loop, which has no request class).
    """
    token = _statement_timeout_ms.set(None)
    try:
        yield
    finally:
        _statement_timeout_ms.reset(token)


def statement_timeout_pool_options(default_timeout_ms: int) -> dict[str, Any]:
    """``create_pool`` options: a session default that survives the release reset, plus a
    per-acquire override for the current request class.

    The override is read from the acquiring task's context. Tasks spawned during a request
    inherit that request's class (contexts are copied into new tasks); see
    ``detached_statements`` for work that must not.
    """
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


class _InFlight:
    """Requests that have reached the app and not yet started their response."""

    def __init__(self, ceiling: int) -> None:
        self.ceiling = ceiling
        self.active = 0

    def enter(self) -> bool:
        if self.ceiling and self.active >= self.ceiling:
            return False
        self.active += 1
        return True

    def leave(self) -> None:
        self.active -= 1

    def resume(self) -> None:
        """Back after waiting on the client: already admitted, so never refused here."""
        self.active += 1


class SlowClientAborted(RuntimeError):
    """A heavy response's body write did not complete within the send deadline."""


class RequestGuardMiddleware:
    def __init__(self, app: Any, *, settings: GuardSettings | None = None,
                 gate: AdmissionGate | None = None) -> None:
        self.app = app
        self.settings = settings or SETTINGS
        self.gate = gate or AdmissionGate(self.settings.heavy_concurrency,
                                          self.settings.admission_wait_seconds)
        self.in_flight = _InFlight(self.settings.max_in_flight)

    async def __call__(self, scope: Mapping[str, Any], receive: Any, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path") or "/")
        retry_after = self.settings.retry_after_seconds
        retry_header = ((b"retry-after", str(retry_after).encode("ascii")),)
        counted = path not in UNCAPPED_PATHS
        if counted and not self.in_flight.enter():
            await _send_json(send, 503, {
                "error": "server_overloaded",
                "message": f"The API is serving its maximum number of requests; retry after {retry_after} s.",
                "retry_after": retry_after,
            }, headers=retry_header)
            return
        held = {"in_flight": counted, "slot": False, "started": False}
        group: str | None = None
        token = None

        def leave_in_flight() -> None:
            if held["in_flight"]:
                held["in_flight"] = False
                self.in_flight.leave()

        async def release_slot() -> None:
            if held["slot"]:
                held["slot"] = False
                await self.gate.release(group)

        async def receiving() -> Mapping[str, Any]:
            # Waiting for the client (a request body arriving slowly, or a disconnect) is not
            # producing a response: a slow uploader must not hold a place under the ceiling.
            waiting = held["in_flight"]
            leave_in_flight()
            try:
                return await receive()
            finally:
                if waiting and not held["started"]:
                    self.in_flight.resume()
                    held["in_flight"] = True

        try:
            request_class = classify_request(
                str(scope.get("method") or "GET"), path, scope.get("query_string") or b"",
            )
            group = request_class.admission_group
            if group:
                if not await self.gate.acquire(group):
                    await _send_json(send, 429, {
                        "error": "server_busy",
                        "message": f"Too many concurrent {group} requests; retry after {retry_after} s.",
                        "retry_after": retry_after,
                    }, headers=retry_header)
                    return
                held["slot"] = True
            if request_class.kind != DEFAULT:
                token = _statement_timeout_ms.set(self.settings.timeout_for(request_class.kind))
            transport = send
            if group and self.settings.heavy_send_timeout_seconds > 0:
                transport = self._deadlined(send, self.settings.heavy_send_timeout_seconds, path)
            budgeted = self._budgeted(transport, self.settings.response_budget_for(request_class.kind), path)

            async def releasing(message: Mapping[str, Any]) -> None:
                kind = message.get("type")
                if kind == "http.response.start":
                    held["started"] = True
                    leave_in_flight()  # an event stream or slow body no longer counts
                elif kind == "http.response.body" and not message.get("more_body", False):
                    await release_slot()  # produced: never wait on a slow client with the slot
                await budgeted(message)

            await self.app(scope, receiving, releasing)
        finally:
            if token is not None:
                _statement_timeout_ms.reset(token)
            leave_in_flight()
            await release_slot()

    @staticmethod
    def _deadlined(send: Send, seconds: float, path: str) -> Send:
        """Bound how long a rendered heavy body can sit waiting for a client that does not read:
        a write that has not completed in ``seconds`` aborts the connection."""

        async def deadlined(message: Mapping[str, Any]) -> None:
            try:
                await asyncio.wait_for(send(message), seconds)
            except TimeoutError as exc:
                logger.warning("aborted a heavy response for %s: the client read nothing for %s s",
                               path, seconds)
                raise SlowClientAborted(f"client did not read the response for {path}") from exc

        return deadlined

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


try:
    from asyncpg.exceptions import QueryCanceledError as _QueryCanceledError
except ModuleNotFoundError:  # asyncpg-free environments
    _QueryCanceledError = None


def reraise_statement_timeout(exc: BaseException) -> None:
    """Re-raise a statement cancellation caught by a broad ``except`` so it answers 504."""
    if _QueryCanceledError is not None and isinstance(exc, _QueryCanceledError):
        raise exc


def configure_request_guards(app: Any, settings: GuardSettings | None = None) -> None:
    """Install the middleware and the statement-timeout answer on a FastAPI app."""
    from starlette.responses import JSONResponse

    app.add_middleware(RequestGuardMiddleware, settings=settings or SETTINGS)

    if _QueryCanceledError is not None:
        async def _statement_cancelled(request: Any, exc: Exception) -> Any:
            logger.warning("statement timeout on %s %s", request.method, request.url.path)
            return JSONResponse(status_code=504, content={"detail": {
                "error": "statement_timeout",
                "message": "The database query exceeded this request's time budget.",
            }})

        app.add_exception_handler(_QueryCanceledError, _statement_cancelled)


__all__ = [
    "AdmissionGate",
    "GuardSettings",
    "ROUTE_CLASSES",
    "RequestClass",
    "RequestGuardMiddleware",
    "ResponseBudgetExceeded",
    "RouteRule",
    "SETTINGS",
    "SlowClientAborted",
    "classify_request",
    "configure_request_guards",
    "detached_statements",
    "reraise_statement_timeout",
    "statement_timeout",
    "statement_timeout_pool_options",
    "unbounded_statements",
]
