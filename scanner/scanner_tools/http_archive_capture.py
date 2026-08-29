"""Process-local capture of the calls scanner tools make.

The scanner runs in the worker process, so calls are collected here and drained by the
worker once the scan finishes. Nothing is written to a database from scanner code.

Fidelity differs by plane and is recorded rather than glossed over. A curl invocation
yields its argv -- method, URL and request headers -- plus whatever it wrote to stdout,
which is the response body only when the invocation did not redirect it elsewhere.
Response headers are absent unless the caller asked curl to dump them. Claiming otherwise
would make an archive look complete when it is a partial record.
"""

from __future__ import annotations

import contextvars
import os
import shlex
import time
from typing import Any, Iterable, Mapping, Sequence
import urllib.parse


CAPTURE_SCHEMA = "scanner-http-capture/v1"
# A thorough scan makes tens of thousands of calls. This bounds what one scan can hold in
# memory before the worker drains it; the count of dropped calls is reported so the archive
# never silently claims to be the whole run.
DEFAULT_MAX_CAPTURED = 50_000
# curl writes the response body to stdout unless told otherwise. Anything past this is not
# worth holding in memory for every call in a scan.
MAX_STDOUT_CAPTURE_BYTES = 2 * 1024 * 1024

_METHOD_FLAGS = {"-X", "--request"}
_HEADER_FLAGS = {"-H", "--header"}
_DATA_FLAGS = {"-d", "--data", "--data-raw", "--data-binary", "--data-ascii"}
_DISCARD_TARGETS = {"/dev/null", "nul"}


class _Capture:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.calls: list[dict[str, Any]] = []
        self.dropped = 0

    def add(self, call: Mapping[str, Any]) -> None:
        if len(self.calls) >= self.limit:
            self.dropped += 1
            return
        self.calls.append(dict(call))


_active: contextvars.ContextVar[_Capture | None] = contextvars.ContextVar(
    "shakerscan_http_capture", default=None,
)


def max_captured() -> int:
    raw = os.environ.get("HTTP_ARCHIVE_MAX_CAPTURED_CALLS")
    try:
        return max(0, int(str(raw).strip())) if raw else DEFAULT_MAX_CAPTURED
    except (TypeError, ValueError):
        return DEFAULT_MAX_CAPTURED


def start_capture() -> None:
    """Begin collecting for the current scan."""
    _active.set(_Capture(max_captured()))


def capture_active() -> bool:
    return _active.get() is not None


def drain_capture() -> dict[str, Any]:
    """Return everything captured and stop collecting."""
    capture = _active.get()
    _active.set(None)
    if capture is None:
        return {"schema_version": CAPTURE_SCHEMA, "calls": [], "dropped": 0}
    return {
        "schema_version": CAPTURE_SCHEMA,
        "calls": capture.calls,
        # Stated so a reader can tell a bounded archive from a complete one.
        "dropped": capture.dropped,
    }


def record(call: Mapping[str, Any]) -> None:
    capture = _active.get()
    if capture is not None:
        capture.add(call)


def parse_curl_command(cmd: Sequence[str]) -> dict[str, Any]:
    """Recover method, URL, headers and body from a curl invocation.

    argv is the only description of the request that exists for the curl plane, so it is
    read rather than guessed at. ``-o /dev/null`` is noted because it means stdout is not
    the response body, and treating it as one would archive an empty body as though the
    server returned nothing.
    """
    method = ""
    url = ""
    headers: dict[str, str] = {}
    body: str | None = None
    output_discarded = False
    dumps_headers = False
    index = 1
    while index < len(cmd):
        value = str(cmd[index])
        if value in _METHOD_FLAGS and index + 1 < len(cmd):
            method = str(cmd[index + 1]).upper()
            index += 2
            continue
        if value in _HEADER_FLAGS and index + 1 < len(cmd):
            raw = str(cmd[index + 1])
            name, separator, header_value = raw.partition(":")
            if separator:
                headers[name.strip().lower()] = header_value.strip()
            index += 2
            continue
        if value in _DATA_FLAGS and index + 1 < len(cmd):
            body = str(cmd[index + 1])
            index += 2
            continue
        if value in {"-o", "--output"} and index + 1 < len(cmd):
            output_discarded = str(cmd[index + 1]) in _DISCARD_TARGETS
            index += 2
            continue
        if value in {"-D", "--dump-header"}:
            dumps_headers = True
            index += 2
            continue
        if value.startswith(("http://", "https://")):
            url = value
        index += 1
    if not method:
        # curl defaults to GET, or POST when a body is supplied without -X.
        method = "POST" if body is not None else "GET"
    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "output_discarded": output_discarded,
        "dumps_headers": dumps_headers,
    }


def record_curl_invocation(
    cmd: Sequence[str],
    *,
    stdout: str,
    stderr: str,
    returncode: int,
    started: float,
) -> None:
    """Record one curl call, saying plainly what part of it could be recovered."""
    if not capture_active():
        return
    parsed = parse_curl_command(cmd)
    if not parsed["url"]:
        return
    body: str | None = None
    if not parsed["output_discarded"] and stdout:
        body = stdout[:MAX_STDOUT_CAPTURE_BYTES]
    record({
        "plane": "scan",
        "source": "curl",
        "method": parsed["method"],
        "url": parsed["url"],
        "request_headers": parsed["headers"],
        "request_body": parsed["body"],
        "response_body": body,
        # curl exposes no response headers unless the caller dumped them, and no status
        # code unless it was written out. Recorded as unknown rather than invented.
        "response_headers": {},
        "status_code": None,
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        "error": (stderr or "").strip()[:500] or None if returncode != 0 else None,
        "exit_code": returncode,
        "fidelity": "argv_and_stdout",
        "redacted_argv": _redacted_argv(cmd),
    })


def record_scan_call(captured: Mapping[str, Any]) -> None:
    """Record a call made through the shared target-bound HTTP executor.

    Takes the executor's own capture, which describes the request as built rather than as
    requested, so a Scan row carries the same fidelity a Hunt row does.
    """
    if not capture_active():
        return
    record({
        "plane": "scan",
        "source": "http.request",
        "method": captured.get("method") or "GET",
        "url": captured.get("url") or "",
        "request_headers": dict(captured.get("request_headers") or {}),
        "request_body": captured.get("request_body"),
        "response_headers": dict(captured.get("response_headers") or {}),
        "response_body": captured.get("response_body"),
        "status_code": captured.get("status_code"),
        "elapsed_ms": captured.get("elapsed_ms"),
        "error": captured.get("error"),
        "response_body_truncated": bool(captured.get("response_body_truncated")),
        "fidelity": captured.get("fidelity") or "wire_request",
    })


def record_client_call(
    *,
    method: Any,
    url: Any,
    status_code: int | None,
    response_headers: Mapping[str, str] | None = None,
    response_body: bytes | str | None = None,
    elapsed_ms: int | None = None,
    source: str = "httpx",
) -> None:
    """Record a call made by an in-process HTTP client rather than a subprocess."""
    if not capture_active():
        return
    record({
        "plane": "scan",
        "source": source,
        "method": str(method or "GET").upper(),
        "url": str(url or ""),
        "request_headers": {},
        "request_body": None,
        "response_headers": dict(response_headers or {}),
        "response_body": response_body,
        "status_code": status_code,
        "elapsed_ms": elapsed_ms,
        "error": None,
        "fidelity": "client_response",
    })


def _redacted_argv(cmd: Iterable[Any]) -> list[str]:
    """argv with credential-bearing flag values removed.

    The archive stores request headers separately and deliberately; the argv is provenance
    for how the tool was invoked, and duplicating a bearer token into it adds exposure
    without adding information.
    """
    out: list[str] = []
    redact_next = False
    for raw in cmd:
        value = str(raw)
        if redact_next:
            out.append("[REDACTED]")
            redact_next = False
            continue
        if value in _HEADER_FLAGS | _DATA_FLAGS | {"-b", "--cookie", "-u", "--user"}:
            redact_next = True
        out.append(shlex.quote(value) if " " in value else value)
    return out[:200]


def scan_target_host(url: str) -> str | None:
    try:
        return urllib.parse.urlsplit(url).hostname
    except ValueError:
        return None


__all__ = [
    "CAPTURE_SCHEMA",
    "DEFAULT_MAX_CAPTURED",
    "MAX_STDOUT_CAPTURE_BYTES",
    "capture_active",
    "drain_capture",
    "max_captured",
    "parse_curl_command",
    "record",
    "record_client_call",
    "record_curl_invocation",
    "record_scan_call",
    "scan_target_host",
    "start_capture",
]
