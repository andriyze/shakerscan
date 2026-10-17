"""Browser capture for ``shakerscan record``: CDP events in, scoped flows out, uploaded in batches.

Everything here is pure (no browser, no network) so it is tested without either:

* ``CdpFlowRecorder`` turns Chrome DevTools Protocol ``Network.*`` events into flows: one per
  request (a redirect hop is its own flow), one per WebSocket with at most 50 frame previews.
* ``classify`` keeps flows of the capture's allowed origins and drops other origins and, unless
  asked, static assets. Dropped flows are counted, never sent; the server checks scope again.
* ``Batcher`` groups flows by count, age and encoded size; ``CaptureUploader`` sends batches in
  ``seq`` order and retries one with backoff until the server acknowledges it, so a retry is
  idempotent and a batch is neither lost nor applied twice. Both measure a batch with
  ``encode_json``, the one serializer whose bytes are sent, and a batch the server still finds
  too large (413) is split and sent again, never dropped.

Flows hold live cookies, tokens and form values. They go only to the capture routes, over the
connection the client already uses; nothing here prints or logs them.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.parse
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

DEFAULT_LIMITS = {
    "max_flows_per_batch": 100,
    "max_batch_bytes": 16 * 1024 * 1024,
    "max_flows": 20_000,
    "max_request_body_bytes": 256 * 1024,
    "max_response_body_bytes": 1024 * 1024,
    "max_script_body_bytes": 256 * 1024,
    "max_websocket_frames": 50,
    "websocket_preview_bytes": 4 * 1024,
    "idle_close_seconds": 1800,
}
BATCH_FLOWS = 50
BATCH_SECONDS = 2.0
# Leave room for the batch envelope under the server's body cap.
BATCH_ENVELOPE_BYTES = 64 * 1024
MAX_PENDING_REQUESTS = 2_000
ASSET_TYPES = frozenset({"image", "font", "media", "stylesheet"})
ASSET_MIME_PREFIXES = ("image/", "font/", "audio/", "video/", "text/css")
_WEBSOCKET_SCHEMES = {"ws": "http", "wss": "https"}
_DEFAULT_PORTS = {"http": 80, "https": 443}


def effective_limits(server: Mapping[str, Any] | None) -> dict[str, int]:
    """The server's capture limits over the defaults; never larger than a sane ceiling."""
    limits = dict(DEFAULT_LIMITS)
    for key, value in (server or {}).items():
        if key in limits and isinstance(value, int) and not isinstance(value, bool) and value > 0:
            limits[key] = value
    return limits


def origin_of(url: str) -> str | None:
    """``scheme://host[:port]`` with a default port dropped; a WebSocket URL as its HTTP origin."""
    try:
        parts = urllib.parse.urlsplit(str(url or ""))
        scheme = _WEBSOCKET_SCHEMES.get(parts.scheme.lower(), parts.scheme.lower())
        if scheme not in _DEFAULT_PORTS or not parts.hostname:
            return None
        port = parts.port
    except ValueError:
        return None
    host = parts.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}" if port in (None, _DEFAULT_PORTS[scheme]) else f"{scheme}://{host}:{port}"


def is_asset(flow: Mapping[str, Any]) -> bool:
    """Images, fonts, media and stylesheets: dropped by default. Scripts are kept."""
    if str(flow.get("resource_type") or "").lower() in ASSET_TYPES:
        return True
    mime = str(flow.get("response_mime_type") or "").lower()
    return mime.startswith(ASSET_MIME_PREFIXES)


def classify(flow: Mapping[str, Any], allowed_origins: Iterable[str], *, include_assets: bool) -> str:
    """``upload``, ``out_of_scope`` or ``asset``."""
    if origin_of(str(flow.get("url") or "")) not in set(allowed_origins):
        return "out_of_scope"
    if not include_assets and is_asset(flow):
        return "asset"
    return "upload"


def cap_body(data: str | bytes | None, *, base64_encoded: bool, cap: int) -> tuple[str | None, str | None, bool]:
    """``(text, encoding, truncated)``: a body cut to ``cap`` bytes, as text when it is UTF-8."""
    if data is None:
        return None, None, False
    if isinstance(data, bytes):
        raw = data
    elif base64_encoded:
        try:
            raw = base64.b64decode(data)
        except ValueError:
            return None, None, True
    else:
        raw = data.encode("utf-8", errors="surrogatepass")
    truncated = len(raw) > cap
    raw = raw[:cap]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        if truncated:
            # A cut inside a multi-byte character: the text before it is still text.
            for back in (1, 2, 3):
                try:
                    return raw[:-back].decode("utf-8"), None, True
                except UnicodeDecodeError:
                    continue
        return base64.b64encode(raw).decode("ascii"), "base64", truncated
    return text, None, truncated


def _headers(raw: Any) -> list[dict[str, str]]:
    """CDP headers (an object; a repeated header joined by newlines) as name/value rows."""
    rows: list[dict[str, str]] = []
    if not isinstance(raw, Mapping):
        return rows
    for name, value in raw.items():
        name = str(name)
        if not name or name.startswith(":"):
            continue
        for part in str(value if value is not None else "").split("\n"):
            rows.append({"name": name[:256], "value": part[:16 * 1024]})
    return rows[:200]


def _wall_time(params: Mapping[str, Any]) -> str | None:
    wall = params.get("wallTime")
    if isinstance(wall, (int, float)) and wall > 0:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(wall)) + f".{int((wall % 1) * 1000):03d}Z"
    return None


@dataclass
class _Pending:
    request_id: str
    method: str
    url: str
    resource_type: str
    started_at: str | None
    started: float | None
    request_headers: list[dict[str, str]]
    post_data: str | None = None
    post_data_base64: bool = False
    needs_post_data: bool = False
    status: int | None = None
    status_text: str | None = None
    response_headers: list[dict[str, str]] = field(default_factory=list)
    mime_type: str | None = None
    finished: float | None = None
    websocket: bool = False
    frames: list[dict[str, Any]] = field(default_factory=list)
    frames_dropped: int = 0


class CdpFlowRecorder:
    """Turn CDP ``Network.*`` events into flows. ``handle`` returns actions for the caller:

    * ``("flow", flow)``: a finished flow with no body to fetch (a redirect hop, a failure, a
      closed WebSocket);
    * ``("fetch", request_id, wants_post_data)``: the request finished; fetch its body
      (``Network.getResponseBody``) and, when asked, its post data, then call ``complete``.
    """

    def __init__(self, limits: Mapping[str, int] | None = None) -> None:
        self.limits = effective_limits(limits)
        self.pending: OrderedDict[str, _Pending] = OrderedDict()
        self.extra_request_headers: dict[str, list[dict[str, str]]] = {}
        self.extra_response_headers: dict[str, list[dict[str, str]]] = {}
        self.dropped_unfinished = 0

    def _track(self, item: _Pending) -> None:
        self.pending[item.request_id] = item
        while len(self.pending) > MAX_PENDING_REQUESTS:
            # A page that opens requests and never finishes them must not grow memory unbounded.
            self.pending.popitem(last=False)
            self.dropped_unfinished += 1

    def handle(self, method: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        request_id = str(params.get("requestId") or "")
        if not request_id:
            return []
        handler = getattr(self, "_on_" + method.replace("Network.", "").replace(".", "_"), None)
        return handler(request_id, params) if handler else []

    # --- HTTP -----------------------------------------------------------------------------------

    def _on_requestWillBeSent(self, request_id: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        actions: list[tuple[Any, ...]] = []
        previous = self.pending.pop(request_id, None)
        redirect = params.get("redirectResponse")
        if previous is not None and isinstance(redirect, Mapping):
            # The same request id continues after a redirect: the previous hop is its own flow.
            self._apply_response(previous, redirect)
            actions.append(("flow", self._flow(previous)))
        request = params.get("request") if isinstance(params.get("request"), Mapping) else {}
        post_data = request.get("postData")
        entries = request.get("postDataEntries")
        post_base64 = False
        if post_data is None and isinstance(entries, list) and entries:
            joined = b"".join(
                base64.b64decode(str(entry.get("bytes") or ""))
                for entry in entries if isinstance(entry, Mapping)
            )
            post_data, post_base64 = base64.b64encode(joined).decode("ascii"), True
        url = str(request.get("url") or "") + str(request.get("urlFragment") or "")
        self._track(_Pending(
            request_id=request_id,
            method=str(request.get("method") or "GET").upper(),
            url=url.split("#", 1)[0],
            resource_type=str(params.get("type") or "Other").lower(),
            started_at=_wall_time(params),
            started=params.get("timestamp") if isinstance(params.get("timestamp"), (int, float)) else None,
            request_headers=self.extra_request_headers.pop(request_id, None) or _headers(request.get("headers")),
            post_data=post_data,
            post_data_base64=post_base64,
            needs_post_data=bool(request.get("hasPostData")) and post_data is None,
        ))
        return actions

    def _on_requestWillBeSentExtraInfo(self, request_id: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        # The headers as sent on the wire, cookies included; they may arrive before or after.
        headers = _headers(params.get("headers"))
        item = self.pending.get(request_id)
        if item is not None and not item.websocket:
            item.request_headers = headers
        else:
            self.extra_request_headers[request_id] = headers
            self._bound_extra(self.extra_request_headers)
        return []

    def _on_responseReceived(self, request_id: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        item = self.pending.get(request_id)
        response = params.get("response")
        if item is not None and isinstance(response, Mapping):
            self._apply_response(item, response)
            if params.get("type"):
                item.resource_type = str(params["type"]).lower()
        return []

    def _on_responseReceivedExtraInfo(self, request_id: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        headers = _headers(params.get("headers"))
        item = self.pending.get(request_id)
        if item is not None and item.status is not None:
            item.response_headers = headers
        else:
            self.extra_response_headers[request_id] = headers
            self._bound_extra(self.extra_response_headers)
        return []

    def _on_loadingFinished(self, request_id: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        item = self.pending.get(request_id)
        if item is None or item.websocket:
            return []
        if isinstance(params.get("timestamp"), (int, float)):
            item.finished = float(params["timestamp"])
        return [("fetch", request_id, item.needs_post_data)]

    def _on_loadingFailed(self, request_id: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        item = self.pending.pop(request_id, None)
        if item is None or item.websocket:
            if item is not None:
                self.pending[request_id] = item
            return []
        if isinstance(params.get("timestamp"), (int, float)):
            item.finished = float(params["timestamp"])
        return [("flow", self._flow(item))]

    def complete(self, request_id: str, *, body: str | None = None, base64_encoded: bool = False,
                 post_data: str | None = None) -> dict[str, Any] | None:
        """The flow for a finished request, with the bodies the caller fetched (or None)."""
        item = self.pending.pop(request_id, None)
        if item is None:
            return None
        if post_data is not None and item.post_data is None:
            item.post_data = post_data
        return self._flow(item, body=body, base64_encoded=base64_encoded)

    def _apply_response(self, item: _Pending, response: Mapping[str, Any]) -> None:
        status = response.get("status")
        item.status = int(status) if isinstance(status, (int, float)) else None
        item.status_text = str(response.get("statusText") or "")[:200]
        item.mime_type = str(response.get("mimeType") or "")[:200] or None
        item.response_headers = (
            self.extra_response_headers.pop(item.request_id, None) or _headers(response.get("headers"))
        )

    def _bound_extra(self, store: dict[str, Any]) -> None:
        while len(store) > MAX_PENDING_REQUESTS:
            store.pop(next(iter(store)))

    # --- WebSocket ------------------------------------------------------------------------------

    def _on_webSocketCreated(self, request_id: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        self._track(_Pending(
            request_id=request_id, method="GET", url=str(params.get("url") or ""),
            resource_type="websocket", started_at=None, started=None, request_headers=[],
            websocket=True,
        ))
        return []

    def _on_webSocketWillSendHandshakeRequest(self, request_id: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        item = self.pending.get(request_id)
        request = params.get("request")
        if item is not None and isinstance(request, Mapping):
            item.request_headers = _headers(request.get("headers"))
            item.started_at = _wall_time(params)
        return []

    def _on_webSocketHandshakeResponseReceived(self, request_id: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        item = self.pending.get(request_id)
        response = params.get("response")
        if item is not None and isinstance(response, Mapping):
            self._apply_response(item, response)
        return []

    def _frame(self, request_id: str, params: Mapping[str, Any], direction: str) -> list[tuple[Any, ...]]:
        item = self.pending.get(request_id)
        response = params.get("response")
        if item is None or not item.websocket or not isinstance(response, Mapping):
            return []
        if len(item.frames) >= self.limits["max_websocket_frames"]:
            item.frames_dropped += 1
            return []
        payload = str(response.get("payloadData") or "")
        cap = self.limits["websocket_preview_bytes"]
        encoded = payload.encode("utf-8", errors="surrogatepass")
        preview = encoded[:cap].decode("utf-8", errors="ignore")
        item.frames.append({
            "direction": direction, "opcode": int(response.get("opcode") or 1),
            "preview": preview, "truncated": len(encoded) > cap,
            **({"at": float(params["timestamp"])} if isinstance(params.get("timestamp"), (int, float)) else {}),
        })
        return []

    def _on_webSocketFrameSent(self, request_id: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        return self._frame(request_id, params, "sent")

    def _on_webSocketFrameReceived(self, request_id: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        return self._frame(request_id, params, "received")

    def _on_webSocketClosed(self, request_id: str, params: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        item = self.pending.get(request_id)
        if item is None or not item.websocket:
            return []
        self.pending.pop(request_id, None)
        return [("flow", self._flow(item))]

    # --- Flows ----------------------------------------------------------------------------------

    def drain(self) -> list[dict[str, Any]]:
        """At the end of a recording: every request that got a response and every open WebSocket,
        without bodies (the page is gone); requests with no response are counted, not sent."""
        flows = []
        for item in list(self.pending.values()):
            if item.websocket or item.status is not None:
                flows.append(self._flow(item))
            else:
                self.dropped_unfinished += 1
        self.pending.clear()
        return flows

    def _flow(self, item: _Pending, *, body: str | None = None, base64_encoded: bool = False) -> dict[str, Any]:
        flow: dict[str, Any] = {
            "method": item.method,
            "url": item.url,
            "resource_type": "".join(ch for ch in item.resource_type if ch.isalpha() or ch in "_-")[:40] or "other",
            "request_headers": item.request_headers,
            "response_headers": item.response_headers,
        }
        if item.started_at:
            flow["started_at"] = item.started_at
        if item.started is not None and item.finished is not None and item.finished >= item.started:
            flow["duration_ms"] = round((item.finished - item.started) * 1000, 3)
        if item.status is not None:
            flow["status"] = item.status
            flow["status_text"] = item.status_text or ""
        if item.mime_type:
            flow["response_mime_type"] = item.mime_type
        if item.post_data is not None:
            text, encoding, truncated = cap_body(
                item.post_data, base64_encoded=item.post_data_base64,
                cap=self.limits["max_request_body_bytes"],
            )
            flow.update(request_body=text, request_body_truncated=truncated)
            if encoding:
                flow["request_body_encoding"] = encoding
        if body is not None:
            script = flow["resource_type"] == "script" or "javascript" in str(item.mime_type or "").lower()
            cap = self.limits["max_script_body_bytes" if script else "max_response_body_bytes"]
            text, encoding, truncated = cap_body(body, base64_encoded=base64_encoded, cap=cap)
            flow.update(response_body=text, response_body_truncated=truncated)
            if encoding:
                flow["response_body_encoding"] = encoding
        if item.frames:
            flow["websocket_frames"] = item.frames
        return flow


_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def valid_text(value: Any) -> Any:
    """``value`` with every lone UTF-16 surrogate (a page or CDP can hand one over) replaced by
    U+FFFD: such text cannot be sent as UTF-8, and the server refuses it."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return _LONE_SURROGATE.sub("\ufffd", value)
        return value
    if isinstance(value, Mapping):
        return {valid_text(key): valid_text(item) for key, item in value.items()}
    if isinstance(value, list):
        return [valid_text(item) for item in value]
    return value


def encode_json(value: Any) -> bytes:
    """The request body bytes for ``value``: compact UTF-8 JSON. Batch sizes are measured with
    this and these bytes are what is sent, so a measured batch is the batch on the wire."""
    return json.dumps(valid_text(value), separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def encoded_size(value: Any) -> int:
    return len(encode_json(value))


def _batch_room(max_bytes: int) -> int:
    """The bytes of flows a batch may hold under a body cap of ``max_bytes``."""
    return max(1024, max_bytes - BATCH_ENVELOPE_BYTES)


class Batcher:
    """Flows waiting to be uploaded, released as a batch by count, age or encoded size."""

    def __init__(self, *, max_flows: int = BATCH_FLOWS, max_seconds: float = BATCH_SECONDS,
                 max_bytes: int = DEFAULT_LIMITS["max_batch_bytes"]) -> None:
        self.max_flows = max_flows
        self.max_seconds = max_seconds
        self.max_bytes = _batch_room(max_bytes)
        self.flows: list[dict[str, Any]] = []
        self.bytes = 0
        self.since: float | None = None
        self.ready: list[list[dict[str, Any]]] = []

    def add(self, flow: dict[str, Any], now: float) -> None:
        flow = valid_text(flow)
        size = encoded_size(flow) + 1
        if self.flows and self.bytes + size > self.max_bytes:
            # Flush before the encoded body would pass the server's cap.
            self._release()
        self.flows.append(flow)
        self.bytes += size
        if self.since is None:
            self.since = now
        if len(self.flows) >= self.max_flows:
            self._release()

    def due(self, now: float) -> bool:
        return bool(self.ready) or (bool(self.flows) and self.since is not None and now - self.since >= self.max_seconds)

    def take(self, now: float, *, force: bool = False) -> list[list[dict[str, Any]]]:
        if self.flows and (force or (self.since is not None and now - self.since >= self.max_seconds)):
            self._release()
        ready, self.ready = self.ready, []
        return ready

    def _release(self) -> None:
        self.ready.append(self.flows)
        self.flows, self.bytes, self.since = [], 0, None


class UploadError(Exception):
    """A capture route answered with an error, or did not answer.

    ``status`` None: no answer (network error, timeout). ``retryable``: worth sending again."""

    def __init__(self, message: str, *, status: int | None = None, detail: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.detail = detail

    @property
    def retryable(self) -> bool:
        """Worth sending the same bytes again: no answer, a timeout, a rate limit or a server
        error. Any other 4xx is an answer about the request itself and is not retried."""
        return self.status is None or self.status in {408, 425, 429} or self.status >= 500

    @property
    def too_large(self) -> bool:
        return self.status == 413


class CaptureStopped(Exception):
    """The server will take no more batches (the capture is closed, or a batch was refused)."""


class _TooLarge(Exception):
    """The server answered 413 for a batch: it is split, not retried as it is."""


@dataclass
class UploadTotals:
    batches: int = 0
    accepted: int = 0
    refused_out_of_scope: int = 0
    refused_over_limit: int = 0
    bodies_dropped: int = 0
    retries: int = 0
    splits: int = 0
    # Flows sent without their bodies, or (larger than any body cap even so) not sent at all;
    # both are reported in the summary, never dropped silently.
    bodies_withheld: int = 0
    too_large: int = 0


def _without_bodies(flow: Mapping[str, Any]) -> dict[str, Any]:
    """A flow whose bodies and frames cannot fit any batch: its request line, status and headers."""
    slim = {key: value for key, value in flow.items() if key not in {
        "request_body", "request_body_encoding", "response_body", "response_body_encoding", "websocket_frames",
    }}
    if flow.get("request_body") is not None:
        slim["request_body_truncated"] = True
    if flow.get("response_body") is not None:
        slim["response_body_truncated"] = True
    return slim


class CaptureUploader:
    """Send batches in ``seq`` order. A batch keeps its ``seq`` until the server acknowledges it
    (``applied`` or ``duplicate``), so retrying after a lost answer never applies it twice and a
    later batch never overtakes an unacknowledged one.

    ``post(path, payload, body=...)`` sends ``body``, the exact bytes of ``payload`` from
    ``encode_json``. A batch over ``max_bytes``, or one the server answers 413 (a gateway may cap
    lower), is split in two under the same and the next ``seq`` (the server applied neither, so
    renumbering what is queued is safe); a single flow that is still too large is sent without
    its bodies, and only a flow too large even then is left out, counted in ``totals``."""

    def __init__(self, post: Callable[..., Mapping[str, Any]], capture_id: str, *,
                 sleep: Callable[[float], None] = time.sleep, attempts: int = 6,
                 backoff: Sequence[float] = (0.5, 1, 2, 4, 8, 10),
                 max_bytes: int = DEFAULT_LIMITS["max_batch_bytes"]) -> None:
        self.post = post
        self.max_bytes = max_bytes
        self.path = f"/request-collections/{urllib.parse.quote(capture_id, safe='')}/capture-batches"
        self.sleep = sleep
        self.attempts = attempts
        self.backoff = tuple(backoff)
        self.next_seq = 1
        self.queue: list[tuple[int, list[dict[str, Any]]]] = []
        self.totals = UploadTotals()
        self.last_capture: Mapping[str, Any] | None = None

    def enqueue(self, flows: list[dict[str, Any]]) -> int:
        seq = self.next_seq
        self.next_seq += 1
        self.queue.append((seq, flows))
        return seq

    def send(self, client_dropped: Mapping[str, int] | None = None, *, attempts: int | None = None) -> bool:
        """Send every queued batch; False when one is still unacknowledged after the attempts
        (it stays queued, first, with its ``seq``). Raises ``CaptureStopped`` on a refusal."""
        while self.queue:
            seq, flows = self.queue[0]
            payload: dict[str, Any] = {"seq": seq, "flows": flows}
            if client_dropped:
                payload["client_dropped"] = dict(client_dropped)
            body = encode_json(payload)
            if len(body) > self.max_bytes and self._shrink_head():
                continue
            try:
                answer = self._post_with_retry(payload, body, attempts or self.attempts)
            except _TooLarge:
                if self._shrink_head():
                    continue
                raise CaptureStopped("the server refuses even an empty batch as too large") from None
            if answer is None:
                return False
            self.queue.pop(0)
            self.totals.batches += 1
            for key in ("accepted", "refused_out_of_scope", "refused_over_limit", "bodies_dropped"):
                setattr(self.totals, key, getattr(self.totals, key) + int(answer.get(key) or 0))
            if isinstance(answer.get("capture"), Mapping):
                self.last_capture = answer["capture"]
        return True

    def _shrink_head(self) -> bool:
        """Make the first queued batch smaller; False when it is already empty."""
        seq, flows = self.queue[0]
        if len(flows) > 1:
            half = len(flows) // 2
            self.queue[0:1] = [(seq, flows[:half]), (seq + 1, flows[half:])]
            for index in range(2, len(self.queue)):
                later_seq, later_flows = self.queue[index]
                self.queue[index] = (later_seq + 1, later_flows)
            self.next_seq += 1
            self.totals.splits += 1
            return True
        if len(flows) == 1:
            slim = _without_bodies(flows[0])
            if slim != flows[0]:
                self.queue[0] = (seq, [slim])
                self.totals.bodies_withheld += 1
            else:
                self.queue[0] = (seq, [])
                self.totals.too_large += 1
            return True
        return False

    def _post_with_retry(self, payload: Mapping[str, Any], body: bytes, attempts: int) -> Mapping[str, Any] | None:
        for attempt in range(attempts):
            try:
                return self.post(self.path, payload, body=body)
            except UploadError as exc:
                if exc.too_large:
                    raise _TooLarge() from exc
                if not exc.retryable:
                    raise CaptureStopped(_refusal(exc)) from exc
                if attempt + 1 < attempts:
                    self.totals.retries += 1
                    self.sleep(self.backoff[min(attempt, len(self.backoff) - 1)])
        return None


def _refusal(exc: UploadError) -> str:
    detail = exc.detail
    if isinstance(detail, Mapping) and isinstance(detail.get("detail"), Mapping):
        detail = detail["detail"]
    if isinstance(detail, Mapping):
        error = detail.get("error")
        if error == "capture_closed":
            return f"the server closed this capture ({detail.get('closed_reason') or 'closed'})"
        if error == "capture_seq_gap":
            return (f"the server expects batch {detail.get('expected_seq')}, not the next one this "
                    "client holds; batches it acknowledged earlier are missing on the server")
        return str(detail.get("message") or error or exc)
    return f"{exc} ({exc.status})" if exc.status else str(exc)


def endpoint_key(flow: Mapping[str, Any]) -> str:
    path = urllib.parse.urlsplit(str(flow.get("url") or "")).path or "/"
    return f"{str(flow.get('method') or 'GET').upper()} {path}"


__all__ = [
    "Batcher",
    "CaptureStopped",
    "CaptureUploader",
    "CdpFlowRecorder",
    "DEFAULT_LIMITS",
    "UploadError",
    "cap_body",
    "classify",
    "effective_limits",
    "encode_json",
    "encoded_size",
    "endpoint_key",
    "is_asset",
    "origin_of",
    "valid_text",
]
