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

* ``429`` (or ``503`` with ``Retry-After``): hold for the ``Retry-After`` the target asked for
  (seconds or an HTTP date, at most ``MAX_HOLD_SECONDS``), or, without one, an exponential
  backoff from ``THROTTLE_BASE_SECONDS``.
* ``423 Locked``: the request locked something (an account after failed sign-ins). Further
  requests with that method and path are refused in the tunnel for ``LOCK_HOLD_SECONDS``: more
  sign-in attempts would only keep a real user locked out (nuclei's default-login templates try
  several passwords per account).
* A ban: a ``403`` for exactly a request (method and target) the origin had answered without one,
  or ``BAN_STREAK`` consecutive 403s across at least ``BAN_STREAK_PATHS`` paths. Ordinary 403s on
  attack payloads (a WAF blocking one request) do not hold the origin; a ban answers everything
  with 403, including requests it served before. Holds for a ban back off from
  ``BAN_BASE_SECONDS`` and double while the ban persists.

An encrypted (TLS) tunnel's answers cannot be read, so they set no hold; such a tunnel still
waits out a hold set by readable traffic to the same origin. Holds are per worker process. Every
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
BAN_STREAK = 20
BAN_STREAK_PATHS = 3
MAX_KNOWN_GOOD = 4_096
LOCK_HOLD_SECONDS = 900.0
_STATUS_LINE = re.compile(rb"^HTTP/1\.[01] (\d{3})(?: .*)?$")
_MAX_HEADER_BYTES = 64 * 1024


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
                if b"\r\n" not in self._buffer:
                    return
                size_line, rest = self._buffer.split(b"\r\n", 1)
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
                            return
                        self._buffer, self._state = rest[end + 4:], "status_line"
                    continue
                self._remaining, self._buffer, self._state = size + 2, rest, "chunk_data"


class _Origin:
    __slots__ = ("until", "reason", "throttles", "bans", "streak", "streak_paths", "known_good", "locked")

    def __init__(self) -> None:
        self.until = 0.0
        self.reason = ""
        self.throttles = 0
        self.bans = 0
        self.streak = 0
        self.streak_paths: set[str] = set()
        self.known_good: set[tuple[str, str]] = set()
        self.locked: dict[tuple[str, str], float] = {}


class TargetBackoff:
    """Holds per origin, set by the target's answers and observed by every tunnel to it."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._origins: dict[str, _Origin] = {}

    def _get(self, origin: str) -> _Origin:
        state = self._origins.get(origin)
        if state is None:
            state = self._origins[origin] = _Origin()
        return state

    def observe(self, origin: str, status: int, headers: dict[bytes, bytes], request: dict | None) -> str | None:
        """Account one answer; returns ``throttled`` or ``banned`` when it set a hold."""
        state = self._get(origin)
        method = str((request or {}).get("method") or "").upper()
        target = str((request or {}).get("target") or "")
        key = (method, target)
        path = target.split("?", 1)[0]
        retry = retry_after_seconds(headers.get(b"retry-after", b"").decode("latin-1"))
        if status == 423 and target:
            state.locked[(method, path)] = self._clock() + LOCK_HOLD_SECONDS
            return "locked"
        if status == 429 or (status == 503 and retry is not None):
            state.throttles += 1
            hold = retry if retry is not None else THROTTLE_BASE_SECONDS * 2 ** min(state.throttles - 1, 5)
            self._hold(state, min(MAX_HOLD_SECONDS, max(1.0, hold)), f"{status} from the target")
            return "throttled"
        if status == 403:
            state.streak += 1
            state.streak_paths.add(path)
            refused_known = bool(target) and key in state.known_good
            if refused_known or (state.streak >= BAN_STREAK and len(state.streak_paths) >= BAN_STREAK_PATHS):
                state.bans += 1
                state.streak, state.streak_paths = 0, set()
                state.known_good.discard(key)
                hold = min(MAX_BAN_HOLD_SECONDS, BAN_BASE_SECONDS * 2 ** min(state.bans - 1, 4))
                self._hold(state, hold, "403 for requests the target served before" if refused_known
                           else f"{BAN_STREAK} consecutive 403s across paths")
                return "banned"
            return None
        state.streak, state.streak_paths = 0, set()
        if status < 500:
            state.throttles = 0
            if status < 400 and target and len(state.known_good) < MAX_KNOWN_GOOD:
                state.known_good.add(key)
        return None

    def _hold(self, state: _Origin, seconds: float, reason: str) -> None:
        until = self._clock() + seconds
        if until > state.until:
            state.until, state.reason = until, reason

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
        return max(0.0, state.until - self._clock()) if state else 0.0

    async def wait(self, origin: str, sleep: Callable[[float], Any] = asyncio.sleep) -> float:
        """Wait while the origin is held; returns the seconds waited."""
        waited = 0.0
        while (left := self.remaining(origin)) > 0:
            step = min(left, 5.0)
            await sleep(step)
            waited += step
        return waited

    def reset(self) -> None:
        self._origins.clear()


BACKOFF = TargetBackoff()

__all__ = ["BACKOFF", "ResponseReader", "TargetBackoff", "retry_after_seconds"]
