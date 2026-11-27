"""Weak ETags and 304 answers for polled list and summary reads.

A poller that sends back the ``ETag`` it was given (``If-None-Match``) gets ``304 Not Modified``
with no body while the answer is unchanged, so an open page that polls every few seconds stops
re-downloading the same rows. The body is still computed: this saves transfer and parsing, not
the query (the summary tables and caches behind the endpoints do that).

It is an ASGI middleware over a fixed set of read paths (``ETAG_PATHS``), so the route functions
keep returning plain data to their in-process callers (adapters, MCP, tests). Rules:

* Only ``GET`` answers with status 200 and a JSON body; everything else passes through untouched.
* Weak validators (``W/"..."``): the tag names the JSON content, not a byte-exact entity.
* The tag is a keyed hash over the identity the request carries (the operator a trusted gateway
  asserted, ``gateway_identity.py``) and the body, so a validator one identity was given never
  validates another identity's answer, and the tag reveals nothing about the content by itself.
* Volatile top-level keys (``generated_at``) are left out of the tag: an answer that differs only
  in when it was computed is the same answer. A client that keeps its cached body keeps its older
  ``generated_at``, which is the safe direction for a ``since=`` watermark (inclusive: it re-reads
  a little more, never less).
* Bounded: a body above ``MAX_ETAG_BYTES`` is streamed on without a tag and never answered 304.
* ``Cache-Control: private, no-cache`` and ``Vary`` on the identity-bearing headers keep shared
  caches from serving one person's answer to another; the browser revalidates every time.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from typing import Any, Awaitable, Callable, Iterable

MAX_ETAG_BYTES = 8 * 1024 * 1024
VOLATILE_KEYS = ("generated_at",)
CACHE_CONTROL = "private, no-cache"
VARY = "Authorization, Cookie, X-ShakerScan-Operator"
_IDENTITY_SCOPE_KEY = "shakerscan.operator_identity"
_MAX_IF_NONE_MATCH_TAGS = 32
# Per process: a restart only turns the next poll into a full answer.
_TAG_KEY = secrets.token_bytes(32)

#: The polled list and summary reads that answer with ETags.
ETAG_PATHS = tuple(re.compile(pattern) for pattern in (
    r"/dashboard",
    r"/timeline",
    r"/scans",
    r"/scans/[0-9a-fA-F-]{36}/logs",
    r"/findings",
    r"/findings/groups",
    r"/targets/grouped",
    r"/targets/inventory",
    r"/hunts",
))


def weak_etag(body: bytes, *, identity: str = "") -> str:
    digest = hmac.new(_TAG_KEY, identity.encode("utf-8") + b"\x00" + body, hashlib.sha256).hexdigest()[:32]
    return f'W/"{digest}"'


def matches(header: str | None, etag: str) -> bool:
    """Weak comparison (RFC 9110 13.1.2): ``*`` or a listed tag with the same opaque value."""
    if not header:
        return False
    opaque = etag.removeprefix("W/")
    tags = [part.strip() for part in header.split(",") if part.strip()][:_MAX_IF_NONE_MATCH_TAGS]
    return any(tag == "*" or tag.removeprefix("W/") == opaque for tag in tags)


def tag_material(body: bytes, volatile_keys: Iterable[str] = VOLATILE_KEYS) -> bytes:
    """The bytes the tag is computed over: the body without its volatile top-level keys."""
    keys = tuple(volatile_keys)
    if not keys or not any(f'"{key}"'.encode() in body for key in keys):
        return body
    try:
        parsed = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return body
    if not isinstance(parsed, dict):
        return body
    for key in keys:
        parsed.pop(key, None)
    return json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _header(scope: dict[str, Any], name: bytes) -> str | None:
    for key, value in scope.get("headers") or ():
        if key.lower() == name:
            return value.decode("latin-1")
    return None


class ListETagMiddleware:
    """Adds weak ETags to ``ETAG_PATHS`` and answers a matching ``If-None-Match`` with 304."""

    def __init__(self, app: Callable[..., Awaitable[None]], *, paths: Iterable[re.Pattern[str]] = ETAG_PATHS,
                 max_bytes: int = MAX_ETAG_BYTES) -> None:
        self.app = app
        self.paths = tuple(paths)
        self.max_bytes = max_bytes

    def _applies(self, scope: dict[str, Any]) -> bool:
        if scope.get("type") != "http" or scope.get("method") != "GET":
            return False
        path = str(scope.get("path") or "")
        return any(pattern.fullmatch(path) for pattern in self.paths)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if not self._applies(scope):
            await self.app(scope, receive, send)
            return
        start: dict[str, Any] | None = None
        chunks: list[bytes] = []
        size = 0
        passthrough = False

        async def capture(message: dict[str, Any]) -> None:
            nonlocal start, size, passthrough
            if passthrough:
                await send(message)
                return
            if message["type"] == "http.response.start":
                start = message
                headers = {k.lower(): v for k, v in message.get("headers") or ()}
                content_type = headers.get(b"content-type", b"").split(b";")[0].strip()
                if message.get("status") != 200 or content_type != b"application/json" or b"etag" in headers:
                    passthrough = True
                    await send(message)
                return
            if message["type"] != "http.response.body":
                await send(message)
                return
            chunks.append(message.get("body", b""))
            size += len(chunks[-1])
            if size > self.max_bytes:
                # Too large to tag: send what is buffered and stream the rest unchanged.
                passthrough = True
                await send(start)
                await send({"type": "http.response.body", "body": b"".join(chunks),
                            "more_body": message.get("more_body", False)})
                chunks.clear()
                return
            if message.get("more_body", False):
                return
            await self._finish(scope, send, start, b"".join(chunks))

        await self.app(scope, receive, capture)

    async def _finish(self, scope: dict[str, Any], send: Any, start: dict[str, Any] | None, body: bytes) -> None:
        assert start is not None
        identity = str(scope.get(_IDENTITY_SCOPE_KEY) or "")
        etag = weak_etag(tag_material(body), identity=identity)
        kept = [(k, v) for k, v in start.get("headers") or ()
                if k.lower() not in (b"content-length", b"cache-control", b"vary", b"etag")]
        validators = [(b"etag", etag.encode("latin-1")), (b"cache-control", CACHE_CONTROL.encode("latin-1")),
                      (b"vary", VARY.encode("latin-1"))]
        if matches(_header(scope, b"if-none-match"), etag):
            headers = [(k, v) for k, v in kept if k.lower() != b"content-type"] + validators
            await send({"type": "http.response.start", "status": 304, "headers": headers})
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return
        headers = kept + validators + [(b"content-length", str(len(body)).encode("latin-1"))]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})


__all__ = [
    "CACHE_CONTROL", "ETAG_PATHS", "ListETagMiddleware", "MAX_ETAG_BYTES", "VARY", "VOLATILE_KEYS",
    "matches", "tag_material", "weak_etag",
]
