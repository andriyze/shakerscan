"""The target tells a scanner to wait; the pinned tunnel makes the scanner wait.

External scanners (nuclei, sqlmap, Dalfox, ffuf, katana) reach a target through the pinned SOCKS
proxy, and none of them honours a ``429 Too Many Requests`` with ``Retry-After``, nor notices that
a WAF has started refusing everything it sends. The Scan's adaptive pacing (``target_pacing``)
acts only between tool attempts, from the answers in the request archive -- and the tunnel's
archived request lines carried no status, so one tool attempt kept sending through a whole
cooldown. Measured in the finding zoo: 2,078 requests while the target said to wait, 2,316 while
a WAF ban was in force.

The tunnel now reads each cleartext HTTP/1 answer's status line (``ResponseReader``: it frames
responses the way ``RequestCounter`` frames requests, so a status-shaped string inside a body is
data) and pairs it with the request it answers. ``TargetBackoff`` turns those answers into a hold
on the origin, which every tunnel to that origin in this worker process observes before it relays
the next request or opens the next connection:

* ``429`` (or ``403``/``503`` with ``Retry-After``): hold for the ``Retry-After`` the target asked for
  (seconds or an HTTP date, at most ``MAX_HOLD_SECONDS``), or, without one, an exponential
  backoff from ``THROTTLE_BASE_SECONDS``.
* ``423 Locked``: the request locked something (an account after failed sign-ins). Further
  requests with that method and path are refused in the tunnel for ``LOCK_HOLD_SECONDS``: more
  sign-in attempts would only keep a real user locked out (nuclei's default-login templates try
  several passwords per account).
* A ban: ``BAN_REPLAY_REFUSALS`` ``403`` answers to replays of requests the origin had answered
  without one, with nothing served in between. Refusals across protected paths alone do not
  establish a ban: authorization tests expect them. A replay is the same request from the same sender: the same
  identity (``principal``: an opaque key the caller gives, anonymous distinct from every
  signed-in identity), method, whole request-target (query included) and, for a request with a
  body, the same body (``fingerprint``). So a 403 for another account reading an object the first
  account was served, for another query value on a served path, or for one attack payload a WAF
  blocks is that request's own answer and never a ban; a ban answers everything with 403,
  including requests it served before. Holds for a ban back off from ``BAN_BASE_SECONDS`` and
  double while the ban persists; ``BAN_DECAY_SECONDS`` after the last ban hold ended the count
  starts again.

An encrypted (TLS) tunnel's answers cannot be read, so they set no hold; such a tunnel still
waits out a hold set by readable traffic to the same origin. Holds are shared by every worker
through Redis (``share``; key ``scan:origin_hold:<origin>``, expiring with the hold), so a tool in
another worker container waits too; without Redis they hold this process only. Every
hold is counted in the tunnel record (``holds``), and the answers' statuses reach the archive,
where ``target_pacing`` sees them for the next attempt.
"""
from __future__ import annotations

import asyncio
from collections import deque
from email.utils import parsedate_to_datetime
import re
import time
from typing import Any, Callable

MAX_HOLD_SECONDS = 120.0
THROTTLE_BASE_SECONDS = 5.0
BAN_BASE_SECONDS = 30.0
MAX_BAN_HOLD_SECONDS = 300.0
# Replays of served requests that must be refused, with nothing served in between, before the
# origin is held: one 403 for one request is that request's answer (a rule that fired, a session
# that ended), not a ban.
BAN_REPLAY_REFUSALS = 2
# After this long without a ban the next one backs off from BAN_BASE_SECONDS again.
BAN_DECAY_SECONDS = 900.0
# Methods whose request is the request line alone; any other is a replay only when the caller
# says its body is the same (``fingerprint``).
_BODILESS_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_KNOWN_GOOD = 4_096
LOCK_HOLD_SECONDS = 900.0
# A target that stops answering (timeouts, refused or unanswered connections, nothing else in
# between) is held: an overloaded application gets room to recover, and a hung one is not sent
# minutes of requests that can only time out. Any answer clears the streak.
SILENT_STREAK = 5
SILENT_BASE_SECONDS = 15.0
SHARED_KEY = "scan:origin_hold:{origin}"
SHARED_CHECK_SECONDS = 1.0
# Extend the shared hold only when this one ends later (PTTL in ms; -2 missing, -1 no expiry).
_EXTEND = """
local left = redis.call('PTTL', KEYS[1])
if left < tonumber(ARGV[1]) then redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[1]) end
return 1
"""
_STATUS_LINE = re.compile(rb"^HTTP/1\.[01] (\d{3})(?: .*)?$")
_MAX_HEADER_BYTES = 64 * 1024
# A chunk-size line is a hex number and optional extensions; a longer one is not HTTP framing.
_MAX_CHUNK_SIZE_LINE_BYTES = 256


def retry_after_seconds(value: Any, *, now: float | None = None) -> float | None:
    """Seconds a ``Retry-After`` value asks for (delta-seconds or an HTTP date), or None."""
    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit():
        return float(int(text))
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    return max(0.0, when.timestamp() - (time.time() if now is None else now))


class ResponseReader:
    """Read the status of each HTTP/1 response in the bytes one connection receives.

    ``methods`` is the connection's queue of request methods, in the order they were sent (a
    HEAD response has no body). Anything not framed as HTTP/1 -- TLS, another protocol, a body
    delimited by the connection closing, an upgrade -- stops the reader; what it read stands.
    """

    def __init__(self, methods: deque, on_response: Callable[[int, dict[bytes, bytes], dict | None], None]) -> None:
        self._methods = methods
        self._on_response = on_response
        self._buffer = b""
        self._state = "status_line"
        self._remaining = 0
        self._status = 0
        self.readable = True

    def _stop(self) -> None:
        self.readable = False
        self._state = "opaque"
        self._buffer = b""

    def feed(self, chunk: bytes) -> None:
        if self._state == "opaque":
            return
        self._buffer += chunk
        while self._buffer:
            if self._state == "status_line":
                if b"\r\n" not in self._buffer:
                    if len(self._buffer) > 8192 or not b"HTTP/1.".startswith(self._buffer[:7]):
                        self._stop()
                    return
                line, rest = self._buffer.split(b"\r\n", 1)
                match = _STATUS_LINE.match(line)
                if not match:
                    return self._stop()
                self._status, self._buffer, self._state = int(match.group(1)), rest, "headers"
            if self._state == "headers":
                if self._buffer.startswith(b"\r\n"):  # no header fields at all
                    block, self._buffer = b"", self._buffer[2:]
                else:
                    idx = self._buffer.find(b"\r\n\r\n")
                    if idx < 0:
                        if len(self._buffer) > _MAX_HEADER_BYTES:
                            self._stop()
                        return
                    block, self._buffer = self._buffer[:idx], self._buffer[idx + 4:]
                headers: dict[bytes, bytes] = {}
                for raw in block.split(b"\r\n"):
                    name, sep, value = raw.partition(b":")
                    if sep:
                        headers[name.strip().lower()] = value.strip()
                status = self._status
                if 100 <= status < 200:
                    if status == 101:
                        return self._stop()
                    self._state = "status_line"
                    continue
                request = self._methods.popleft() if self._methods else None
                self._on_response(status, headers, request)
                method = str((request or {}).get("method") or "").upper()
                if method == "HEAD" or status in {204, 304}:
                    self._state = "status_line"
                    continue
                if b"chunked" in headers.get(b"transfer-encoding", b"").lower():
                    self._state = "chunk_size"
                    continue
                try:
                    length = int(headers[b"content-length"])
                except KeyError:
                    return self._stop()  # delimited by the connection closing
                except ValueError:
                    return self._stop()
                self._remaining, self._state = length, ("body" if length > 0 else "status_line")
                continue
            if self._state in {"body", "chunk_data"}:
                take = min(self._remaining, len(self._buffer))
                self._buffer, self._remaining = self._buffer[take:], self._remaining - take
                if self._remaining > 0:
                    return
                self._state = "status_line" if self._state == "body" else "chunk_size"
                continue
            if self._state == "chunk_size":
                end_of_line = self._buffer.find(b"\r\n", 0, _MAX_CHUNK_SIZE_LINE_BYTES + 2)
                if end_of_line < 0:
                    if len(self._buffer) > _MAX_CHUNK_SIZE_LINE_BYTES:
                        self._stop()  # no size line within the bound: never buffered further
                    return
                size_line, rest = self._buffer[:end_of_line], self._buffer[end_of_line + 2:]
                try:
                    size = int(size_line.split(b";", 1)[0].strip() or b"0", 16)
                except ValueError:
                    return self._stop()
                if size == 0:
                    idx = rest.find(b"\r\n")
                    if idx < 0:
                        return
                    if idx == 0:
                        self._buffer, self._state = rest[2:], "status_line"
                    else:  # trailers: skip to the blank line
                        end = rest.find(b"\r\n\r\n")
                        if end < 0:
                            if len(rest) > _MAX_HEADER_BYTES:
                                self._stop()
                            return
                        self._buffer, self._state = rest[end + 4:], "status_line"
                    continue
                self._remaining, self._buffer, self._state = size + 2, rest, "chunk_data"


class _Origin:
    __slots__ = ("until", "reason", "throttles", "bans", "known_good", "locked",
                 "silent", "outages", "replays_refused", "ban_until")

    def __init__(self) -> None:
        self.until = 0.0
        self.reason = ""
        self.throttles = 0
        self.bans = 0
        # Requests the origin served: (sender identity, method, whole request-target, body print).
        self.known_good: set[tuple[str, str, str, str]] = set()
        self.locked: dict[tuple[str, str], float] = {}
        self.silent = 0
        self.outages = 0
        # Refusals of replays of served requests, since the origin last served anything.
        self.replays_refused: dict[tuple[str, str, str, str], int] = {}
        self.ban_until = 0.0


class TargetBackoff:
    """Holds per origin, set by the target's answers and observed by every tunnel to it."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, *, lazy_store: bool = False) -> None:
        self._clock = clock
        self._origins: dict[str, _Origin] = {}
        self._store: Any = None
        self._store_tried = not lazy_store
        self._shared: dict[str, tuple[float, float]] = {}  # origin -> (checked at, held until)

    def share(self, store: Any) -> None:
        """Share holds through this Redis client (the first one given is kept)."""
        if store is not None and self._store is None:
            self._store = store

    def _lazy_store(self) -> None:
        """A worker process that never called ``share`` (the engine's own HTTP client) connects
        to the workers' Redis by itself (``REDIS_URL``), once."""
        if self._store is not None or self._store_tried:
            return
        self._store_tried = True
        import os
        url = os.environ.get("REDIS_URL")
        if not url:
            return
        try:
            import redis  # type: ignore
            self._store = redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
        except Exception:  # noqa: BLE001 - holds stay process-local
            self._store = None

    def _publish(self, origin: str, seconds: float, reason: str) -> None:
        self._lazy_store()
        if self._store is None:
            return
        try:
            self._store.eval(_EXTEND, 1, SHARED_KEY.format(origin=origin), str(int(seconds * 1000)), reason)
        except Exception:  # noqa: BLE001 - the shared store failed: this process still holds
            pass

    def _shared_remaining(self, origin: str) -> float:
        self._lazy_store()
        if self._store is None:
            return 0.0
        now = self._clock()
        checked, until = self._shared.get(origin, (-1e9, 0.0))
        if now - checked >= SHARED_CHECK_SECONDS:
            try:
                left = int(self._store.pttl(SHARED_KEY.format(origin=origin)))
            except Exception:  # noqa: BLE001
                left = -2
            until = now + left / 1000.0 if left > 0 else 0.0
            self._shared[origin] = (now, until)
        return max(0.0, until - now)

    def _get(self, origin: str) -> _Origin:
        state = self._origins.get(origin)
        if state is None:
            state = self._origins[origin] = _Origin()
        return state

    def observe(self, origin: str, status: int, headers: dict[bytes, bytes], request: dict | None) -> str | None:
        """Account one answer; returns ``throttled`` or ``banned`` when it set a hold.

        ``request`` names what was answered: ``method``, ``target`` (the whole request-target,
        query included) and, when the caller knows them, ``principal`` (an opaque key for the
        identity that sent it; absent or empty is anonymous) and ``fingerprint`` (an opaque print
        of the request body). They decide what counts as a replay of a served request."""
        state = self._get(origin)
        state.silent, state.outages = 0, 0  # it answered
        method = str((request or {}).get("method") or "").upper()
        target = str((request or {}).get("target") or "")
        fingerprint = str((request or {}).get("fingerprint") or "")
        key = (str((request or {}).get("principal") or ""), method, target, fingerprint)
        # A request with a body is comparable only when the caller says what the body was.
        comparable = bool(target) and (method in _BODILESS_METHODS or bool(fingerprint))
        path = target.split("?", 1)[0]
        retry = retry_after_seconds(headers.get(b"retry-after", b"").decode("latin-1"))
        if status == 423 and target:
            state.locked[(method, path)] = self._clock() + LOCK_HOLD_SECONDS
            return "locked"
        if status == 429 or (status in {403, 503} and retry is not None):
            state.throttles += 1
            hold = retry if retry is not None else THROTTLE_BASE_SECONDS * 2 ** min(state.throttles - 1, 5)
            self._hold(origin, state, min(MAX_HOLD_SECONDS, max(1.0, hold)), f"{status} from the target")
            return "throttled"
        if status == 403:
            if comparable and (key in state.known_good or key in state.replays_refused):
                state.replays_refused[key] = state.replays_refused.get(key, 0) + 1
            refused_known = sum(state.replays_refused.values()) >= BAN_REPLAY_REFUSALS
            if refused_known:
                now = self._clock()
                if state.bans and now - state.ban_until > BAN_DECAY_SECONDS:
                    state.bans = 0  # a quiet period: the next ban starts from the base hold
                state.bans += 1
                state.known_good.difference_update(state.replays_refused)
                state.replays_refused = {}
                hold = min(MAX_BAN_HOLD_SECONDS, BAN_BASE_SECONDS * 2 ** min(state.bans - 1, 4))
                state.ban_until = max(state.ban_until, now + hold)
                self._hold(origin, state, hold, "403 for requests the target served before")
                return "banned"
            return None
        if status < 500:
            state.throttles = 0
            if status < 400:
                # It serves: whatever was refused before this was not a ban.
                state.replays_refused = {}
                if comparable and len(state.known_good) < MAX_KNOWN_GOOD:
                    state.known_good.add(key)
        return None

    def observe_silence(self, origin: str) -> str | None:
        """Account one request the target never answered (a timeout, a connection it refused or
        left unanswered); returns ``unreachable`` when the streak set a hold."""
        state = self._get(origin)
        state.silent += 1
        if state.silent < SILENT_STREAK:
            return None
        state.silent = 0
        state.outages += 1
        hold = min(MAX_HOLD_SECONDS, SILENT_BASE_SECONDS * 2 ** min(state.outages - 1, 3))
        self._hold(origin, state, hold, f"{SILENT_STREAK} requests in a row got no answer")
        return "unreachable"

    def _hold(self, origin: str, state: _Origin, seconds: float, reason: str) -> None:
        until = self._clock() + seconds
        if until > state.until:
            state.until, state.reason = until, reason
        self._publish(origin, seconds, reason)

    def is_locked(self, origin: str, request: dict | None) -> bool:
        """Whether a request goes to a method and path the target answered 423 for."""
        state = self._origins.get(origin)
        if state is None or not state.locked:
            return False
        key = (str((request or {}).get("method") or "").upper(),
               str((request or {}).get("target") or "").split("?", 1)[0])
        until = state.locked.get(key)
        return until is not None and until > self._clock()

    def remaining(self, origin: str) -> float:
        state = self._origins.get(origin)
        local = max(0.0, state.until - self._clock()) if state else 0.0
        return max(local, self._shared_remaining(origin))

    def reason(self, origin: str) -> str:
        """Why the origin is held by this process's own observations ("" when it is not, or when
        only another worker's shared hold applies)."""
        state = self._origins.get(origin)
        return state.reason if state is not None and state.until > self._clock() else ""

    async def _remaining(self, origin: str) -> float:
        self._lazy_store()
        if self._store is None:
            return self.remaining(origin)
        return await asyncio.to_thread(self.remaining, origin)

    async def wait(self, origin: str, sleep: Callable[[float], Any] = asyncio.sleep, *,
                   max_seconds: float | None = None) -> float:
        """Wait while the origin is held (here or by another worker); returns the seconds waited.

        With ``max_seconds`` the wait never exceeds it: a caller that holds something with a
        deadline of its own (a capability action's reservation lease) checks ``wait_or_refuse``
        instead of waiting a long hold out."""
        waited = 0.0
        while (left := await self._remaining(origin)) > 0:
            step = min(left, 5.0)
            if max_seconds is not None:
                if waited >= max_seconds:
                    break
                step = min(step, max_seconds - waited)
            await sleep(step)
            waited += step
        return waited

    async def wait_or_refuse(self, origin: str, max_seconds: float,
                             sleep: Callable[[float], Any] = asyncio.sleep) -> float:
        """Wait out a hold of at most ``max_seconds``; returns 0 when the origin is then free, else
        the seconds the hold still has (nothing was waited for a hold longer than the bound: the
        caller reports it and sends nothing)."""
        left = await self._remaining(origin)
        if left <= 0:
            return 0.0
        if left > max_seconds:
            return left
        await self.wait(origin, sleep, max_seconds=max_seconds)
        return await self._remaining(origin)

    def reset(self) -> None:
        self._origins.clear()
        self._shared.clear()
        self._store = None
        self._store_tried = True  # a reset (tests) never connects by itself


BACKOFF = TargetBackoff(lazy_store=True)

__all__ = ["BACKOFF", "ResponseReader", "TargetBackoff", "retry_after_seconds"]
