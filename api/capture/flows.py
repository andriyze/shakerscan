"""Browser-capture flows: the upload contract, the scope check and the stored HAR entry.

A capture is a request collection (``format = 'capture'``) whose encrypted document is an
ordinary HAR 1.2 payload, so every consumer of collections (Scan seeds and replay, Hunt
``collections.*``, the library) reads it unchanged. This module is pure: it validates one
uploaded flow, decides whether its origin is inside the capture's binding, and builds the HAR
entry the document keeps. Raw values (cookies, authorization, bodies) exist only in that
encrypted document; nothing here logs or returns them.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, Optional, Sequence
import urllib.parse

from pydantic import BaseModel, ConfigDict, Field, model_validator

try:
    from runtime.request_collection_store import (
        RequestCollectionContractError,
        canonical_collection_origin,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.request_collection_store import (
        RequestCollectionContractError,
        canonical_collection_origin,
    )


CAPTURE_FORMAT = "capture"
CAPTURE_SCHEMA = "browser-capture/v1"
MAX_FLOWS_PER_BATCH = 100
# The encoded JSON body of one batch; public_api_contract.CAPTURE_BATCH_BODY_LIMIT enforces it
# (413) before the body is parsed, and the Enterprise gateway applies the same cap.
MAX_BATCH_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_FLOWS = 20_000
MAX_DOCUMENT_BYTES = 25 * 1024 * 1024
MAX_REQUEST_BODY_BYTES = 256 * 1024
MAX_RESPONSE_BODY_BYTES = 1024 * 1024
# Scripts are kept, but bundles are large and rarely what an investigation reads: a lower cap
# keeps them from filling the document before the application's own responses do.
MAX_SCRIPT_BODY_BYTES = 256 * 1024
MAX_WEBSOCKET_FRAMES = 50
WEBSOCKET_PREVIEW_BYTES = 4 * 1024
MAX_HEADERS = 100
MAX_HEADER_BYTES = 64 * 1024
MAX_URL_CHARS = 16 * 1024
MAX_SEQ = 1_000_000
IDLE_CLOSE_SECONDS = 30 * 60
# Who acted when no gateway asserts an identity (the open-source engine has one operator).
LOCAL_OPERATOR = "local-operator"

# A body arrives as text, or base64 for binary: allow the base64 expansion of the byte cap; the
# decoded bytes are cut to the cap below.
_REQUEST_BODY_CHARS = MAX_REQUEST_BODY_BYTES * 4 // 3 + 8
_RESPONSE_BODY_CHARS = MAX_RESPONSE_BODY_BYTES * 4 // 3 + 8
_WEBSOCKET_SCHEMES = {"ws": "http", "wss": "https"}


def _no_lone_surrogates(value: Any) -> Any:
    """Refuse text that is not valid Unicode (a lone UTF-16 surrogate, as ``"\\ud800"`` decodes):
    it cannot be stored as UTF-8, so it is a 422 here rather than a failure after admission."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("text must be valid Unicode (no lone surrogate)") from None
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _no_lone_surrogates(key)
            _no_lone_surrogates(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _no_lone_surrogates(item)
    return value


def stored_size(value: Any) -> int:
    """The bytes ``value`` takes in the stored (UTF-8 JSON) document, escapes included: a NUL is
    six bytes there, whatever its length as text."""
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def capture_limits() -> dict[str, int]:
    """The bounds a recorder must respect, returned when a capture is created."""
    return {
        "max_flows_per_batch": MAX_FLOWS_PER_BATCH,
        "max_batch_bytes": MAX_BATCH_BYTES,
        "max_flows": MAX_CAPTURE_FLOWS,
        "max_document_bytes": MAX_DOCUMENT_BYTES,
        "max_request_body_bytes": MAX_REQUEST_BODY_BYTES,
        "max_response_body_bytes": MAX_RESPONSE_BODY_BYTES,
        "max_script_body_bytes": MAX_SCRIPT_BODY_BYTES,
        "max_websocket_frames": MAX_WEBSOCKET_FRAMES,
        "websocket_preview_bytes": WEBSOCKET_PREVIEW_BYTES,
        "idle_close_seconds": IDLE_CLOSE_SECONDS,
    }


class CaptureHeader(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=256)
    value: str = Field(default="", max_length=16 * 1024)


class CaptureWebSocketFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")
    direction: Literal["sent", "received"]
    opcode: int = Field(default=1, ge=0, le=15)
    preview: str = Field(default="", max_length=WEBSOCKET_PREVIEW_BYTES)
    truncated: bool = False
    at: Optional[float] = Field(default=None, ge=0)


class CaptureFlow(BaseModel):
    """One request and its response as the recorder saw them."""

    model_config = ConfigDict(extra="forbid")
    method: str = Field(min_length=1, max_length=16, pattern=r"^[A-Za-z]{1,16}$")
    url: str = Field(min_length=1, max_length=MAX_URL_CHARS)
    resource_type: str = Field(default="other", max_length=40, pattern=r"^[A-Za-z_-]{1,40}$")
    started_at: Optional[datetime] = None
    duration_ms: Optional[float] = Field(default=None, ge=0, le=86_400_000)
    request_headers: list[CaptureHeader] = Field(default_factory=list, max_length=200)
    request_body: Optional[str] = Field(default=None, max_length=_REQUEST_BODY_CHARS)
    request_body_encoding: Optional[Literal["base64"]] = None
    request_body_truncated: bool = False
    status: Optional[int] = Field(default=None, ge=0, le=999)
    status_text: Optional[str] = Field(default=None, max_length=200)
    response_headers: list[CaptureHeader] = Field(default_factory=list, max_length=200)
    response_mime_type: Optional[str] = Field(default=None, max_length=200)
    response_body: Optional[str] = Field(default=None, max_length=_RESPONSE_BODY_CHARS)
    response_body_encoding: Optional[Literal["base64"]] = None
    response_body_truncated: bool = False
    response_body_size: Optional[int] = Field(default=None, ge=0, le=2**40)
    websocket_frames: list[CaptureWebSocketFrame] = Field(
        default_factory=list, max_length=MAX_WEBSOCKET_FRAMES,
    )


class CaptureDropCounts(BaseModel):
    """What the recorder dropped before upload (cumulative), for the capture's summary only."""

    model_config = ConfigDict(extra="forbid")
    out_of_scope: int = Field(default=0, ge=0, le=10**9)
    assets: int = Field(default=0, ge=0, le=10**9)


class CaptureCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: Optional[str] = Field(default=None, max_length=64)
    target_url: Optional[str] = Field(default=None, max_length=2048)
    name: Optional[str] = Field(default=None, max_length=160)

    @model_validator(mode="before")
    @classmethod
    def _valid_text(cls, value: Any) -> Any:
        return _no_lone_surrogates(value)

    @model_validator(mode="after")
    def _one_target(self) -> "CaptureCreate":
        if bool(self.target_id) == bool(self.target_url):
            raise ValueError("send exactly one of target_id or target_url")
        return self


class CaptureBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seq: int = Field(ge=1, le=MAX_SEQ)
    flows: list[CaptureFlow] = Field(default_factory=list, max_length=MAX_FLOWS_PER_BATCH)
    client_dropped: Optional[CaptureDropCounts] = None

    @model_validator(mode="before")
    @classmethod
    def _valid_text(cls, value: Any) -> Any:
        return _no_lone_surrogates(value)

    def digest(self) -> str:
        """What the recorder sent for this ``seq`` (its drop counts aside, which a retry may
        update): a retry must send exactly this again."""
        material = {"seq": self.seq, "flows": [flow.model_dump(mode="json") for flow in self.flows]}
        return hashlib.sha256(json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()


class CaptureClose(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_dropped: Optional[CaptureDropCounts] = None


def http_url(url: str) -> str:
    """The HTTP(S) form of a flow URL: a WebSocket handshake (``ws``/``wss``) is an HTTP GET to
    the same origin, and stored and scope-checked as one."""
    parsed = urllib.parse.urlsplit(url)
    scheme = _WEBSOCKET_SCHEMES.get(parsed.scheme.lower())
    return urllib.parse.urlunsplit((scheme, *parsed[1:])) if scheme else url


def flow_origin(url: str) -> str | None:
    """The canonical origin of a flow URL, or None when it has none (data:, blob:, malformed)."""
    text = str(url or "")
    _scheme, separator, rest = text.partition("://")
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0] if separator else ""
    if "\\" in authority or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in authority):
        # A backslash or a control character in the authority: parsers (and browsers) disagree
        # about where it ends, so the origin is not decided from it.
        return None
    try:
        parsed = urllib.parse.urlsplit(http_url(text))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if "@" in parsed.netloc:
            # Userinfo in the authority: refused, not stripped (``https://target@other/``).
            return None
        return canonical_collection_origin(f"{parsed.scheme}://{parsed.netloc}")
    except (ValueError, RequestCollectionContractError):
        return None


def in_scope(url: str, allowed_origins: Sequence[str]) -> bool:
    """Whether a flow's origin is one of the capture binding's exact origins."""
    origin = flow_origin(url)
    return origin is not None and origin in set(allowed_origins)


def _headers(items: Sequence[CaptureHeader]) -> list[dict[str, str]]:
    """Header rows as HAR keeps them: no HTTP/2 pseudo headers, no line breaks, bounded."""
    kept: list[dict[str, str]] = []
    used = 0
    for item in items:
        name = item.name.strip()
        if not name or name.startswith(":") or any(ch in name for ch in "\r\n:"):
            continue
        if "\r" in item.value or "\n" in item.value:
            continue
        cost = len(name) + len(item.value)
        if used + cost > MAX_HEADER_BYTES or len(kept) >= MAX_HEADERS:
            break
        kept.append({"name": name, "value": item.value})
        used += cost
    return kept


def bounded_body(
    text: str | None, encoding: str | None, cap: int,
) -> tuple[str | None, str | None, bool, int]:
    """``(text, encoding, truncated, byte size)`` with the body cut to ``cap`` bytes.

    Text stays text when it fits; a cut is made on bytes and re-encoded as base64 when the cut
    would split a character. An undecodable base64 body is dropped and counted as truncated."""
    if text is None:
        return None, None, False, 0
    if encoding == "base64":
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            return None, None, True, 0
        size = len(raw)
        if size <= cap:
            return text, "base64", False, size
        return base64.b64encode(raw[:cap]).decode("ascii"), "base64", True, size
    raw = text.encode("utf-8", errors="surrogatepass")
    size = len(raw)
    if size <= cap:
        return text, None, False, size
    cut = raw[:cap].decode("utf-8", errors="ignore")
    return cut, None, True, size


def flow_tags(flow: CaptureFlow) -> list[str]:
    """Index labels for one flow: where it came from, its resource type and its status."""
    tags = ["capture", f"resource:{flow.resource_type.lower()}"]
    if flow.status:
        tags.append(f"status:{int(flow.status)}")
    return tags


def _content_type(headers: Sequence[Mapping[str, str]]) -> str:
    for header in headers:
        if header["name"].lower() == "content-type":
            return header["value"][:200]
    return ""


_SECRET_HEADER_NAMES = frozenset({
    "cookie", "set-cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token",
})
_SECRET_HEADER_WORDS = ("token", "secret", "session", "password", "api-key", "apikey", "auth")
SCRIPT_MIME_MARKERS = ("javascript", "ecmascript")


def is_secret_header(name: str) -> bool:
    """A header whose value is a credential: cookies, authorization, token-named headers."""
    lowered = name.strip().lower()
    return lowered in _SECRET_HEADER_NAMES or any(word in lowered for word in _SECRET_HEADER_WORDS)


def is_script(flow: CaptureFlow) -> bool:
    mime = str(flow.response_mime_type or "").lower()
    return flow.resource_type.lower() == "script" or any(marker in mime for marker in SCRIPT_MIME_MARKERS)


def response_body_cap(flow: CaptureFlow) -> int:
    """Scripts keep at most MAX_SCRIPT_BODY_BYTES; HTML, JSON and the rest MAX_RESPONSE_BODY_BYTES."""
    return MAX_SCRIPT_BODY_BYTES if is_script(flow) else MAX_RESPONSE_BODY_BYTES


def har_entry(flow: CaptureFlow, *, metadata_only: bool = False) -> tuple[dict[str, Any], int]:
    """The HAR 1.2 entry kept in the encrypted document, and its stored size in bytes (the UTF-8
    JSON the document holds, so escapes count as what they cost).

    ``metadata_only`` (the document is full): method, URL, status and headers, with every
    credential header value withheld and no body. Only the encrypted document holds what this
    returns."""
    url = http_url(flow.url)
    request_headers = _headers(flow.request_headers)
    response_headers = _headers(flow.response_headers)
    if metadata_only:
        for header in (*request_headers, *response_headers):
            if is_secret_header(header["name"]) and header["value"]:
                header["value"] = "***"
        request_text, request_encoding, request_cut, request_size = None, None, flow.request_body is not None, 0
        response_text, response_encoding, response_cut, response_size = None, None, flow.response_body is not None, 0
    else:
        request_text, request_encoding, request_cut, request_size = bounded_body(
            flow.request_body, flow.request_body_encoding, MAX_REQUEST_BODY_BYTES,
        )
        response_text, response_encoding, response_cut, response_size = bounded_body(
            flow.response_body, flow.response_body_encoding, response_body_cap(flow),
        )
    started = flow.started_at or datetime.now(timezone.utc)
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    request: dict[str, Any] = {
        "method": flow.method.upper(),
        "url": url,
        "httpVersion": "HTTP/1.1",
        "headers": request_headers,
        "queryString": [],
        "cookies": [],
        "headersSize": -1,
        "bodySize": request_size if request_text is not None else 0,
    }
    if request_text is not None:
        post_data: dict[str, Any] = {
            "mimeType": _content_type(request_headers) or "application/octet-stream",
            "text": request_text,
        }
        if request_encoding:
            post_data["encoding"] = request_encoding
        request["postData"] = post_data
    content: dict[str, Any] = {
        "size": int(flow.response_body_size if flow.response_body_size is not None else response_size),
        "mimeType": (flow.response_mime_type or _content_type(response_headers))[:200],
    }
    if response_text is not None:
        content["text"] = response_text
        if response_encoding:
            content["encoding"] = response_encoding
    entry: dict[str, Any] = {
        "startedDateTime": started.isoformat(),
        "time": float(flow.duration_ms or 0),
        "request": request,
        "response": {
            "status": int(flow.status or 0),
            "statusText": (flow.status_text or "")[:200],
            "httpVersion": "HTTP/1.1",
            "headers": response_headers,
            "cookies": [],
            "content": content,
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": -1,
        },
        "cache": {},
        "timings": {"send": 0, "wait": float(flow.duration_ms or 0), "receive": 0},
        "_resourceType": flow.resource_type.lower(),
        "_requestBodyTruncated": bool(flow.request_body_truncated or request_cut),
        "_responseBodyTruncated": bool(flow.response_body_truncated or response_cut),
    }
    if metadata_only:
        entry["_bodiesDropped"] = True
    if flow.websocket_frames and not metadata_only:
        entry["_webSocketMessages"] = [
            {
                "type": "send" if frame.direction == "sent" else "receive",
                "time": float(frame.at or 0),
                "opcode": int(frame.opcode),
                "data": frame.preview[:WEBSOCKET_PREVIEW_BYTES],
                "_truncated": bool(frame.truncated),
            }
            for frame in flow.websocket_frames[:MAX_WEBSOCKET_FRAMES]
        ]
    # One separator in the entries array.
    return entry, stored_size(entry) + 1


def empty_capture_document() -> dict[str, Any]:
    """The encrypted payload of a capture: a HAR log under ``format = "capture"``, which
    ``resolve_imported_requests`` reads as HAR with every recorded credential header removed.
    It holds no entries while the capture is open; closing it assembles the batches here."""
    return {
        "format": CAPTURE_FORMAT,
        "document": {
            "log": {
                "version": "1.2",
                "creator": {"name": "ShakerScan browser capture", "version": CAPTURE_SCHEMA},
                # Survives a relabelled payload: resolve_imported_requests strips any log with it.
                "_shakerscanCapture": CAPTURE_SCHEMA,
                "entries": [],
            },
        },
    }


def new_capture_state(*, allowed_origins: Sequence[str], opened_at: str) -> dict[str, Any]:
    """The capture's own bookkeeping, kept in the collection's ``metadata_json.capture``."""
    return {
        "schema": CAPTURE_SCHEMA,
        "state": "open",
        "last_seq": 0,
        "flow_count": 0,
        "endpoint_count": 0,
        "refused_out_of_scope": 0,
        "refused_over_limit": 0,
        "bodies_dropped": 0,
        "client_dropped": {"out_of_scope": 0, "assets": 0},
        "document_bytes": 0,
        "limit_reached": False,
        "allowed_origins": list(allowed_origins),
        "opened_at": opened_at,
        "last_batch_at": None,
        "closed_at": None,
        "closed_reason": None,
    }


_PUBLIC_STATE_KEYS = (
    "state", "last_seq", "flow_count", "endpoint_count", "refused_out_of_scope",
    "refused_over_limit", "bodies_dropped", "client_dropped", "document_bytes", "limit_reached", "allowed_origins",
    "opened_at", "last_batch_at", "closed_at", "closed_reason",
)


def public_capture_state(metadata: Any) -> dict[str, Any] | None:
    """The capture block an API or MCP view shows: counts, state and times, never values."""
    if not isinstance(metadata, Mapping):
        return None
    state = metadata.get("capture")
    if not isinstance(state, Mapping) or state.get("schema") != CAPTURE_SCHEMA:
        return None
    public = {key: state.get(key) for key in _PUBLIC_STATE_KEYS}
    public["idle_close_seconds"] = IDLE_CLOSE_SECONDS
    return public


__all__ = [
    "CAPTURE_FORMAT",
    "CAPTURE_SCHEMA",
    "CaptureBatch",
    "CaptureClose",
    "CaptureCreate",
    "CaptureDropCounts",
    "CaptureFlow",
    "IDLE_CLOSE_SECONDS",
    "LOCAL_OPERATOR",
    "MAX_BATCH_BYTES",
    "MAX_CAPTURE_FLOWS",
    "MAX_DOCUMENT_BYTES",
    "MAX_FLOWS_PER_BATCH",
    "bounded_body",
    "capture_limits",
    "empty_capture_document",
    "flow_origin",
    "flow_tags",
    "har_entry",
    "is_script",
    "is_secret_header",
    "response_body_cap",
    "stored_size",
    "http_url",
    "in_scope",
    "new_capture_state",
    "public_capture_state",
]
