"""One archived body, decoded, masked and JSON-encoded for an export, in a worker process.

The masking passes are linear, but they are regex work, and CPython's regex engine holds the
interpreter lock for a whole pass over a body. Run on the API process, even on a thread, a
multi-megabyte body stalled the event loop for most of a second (external release audit,
2026-10-09). An export therefore sends each body to a small process pool and gets back the
JSON text of what the masked (or raw) view shows; the API process only splices those bytes
into the export. The functions here are also what the in-process ``export_document`` runs, so
both paths produce the same text.

This module stays light (masking, redaction, json): a worker imports only it, never the API
(see ``worker_context``).
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import types
from multiprocessing import context as _mp_context
from multiprocessing import popen_spawn_posix as _popen_spawn_posix
from multiprocessing import spawn as _spawn
from typing import Any

from .archive_body_masking import (
    MAX_MASKED_BODY_CHARS,
    archived_body_text,
    withhold_body_secrets,
)

try:
    from redaction import redact_sensitive
except ModuleNotFoundError:  # package import layout
    from scanner.redaction import redact_sensitive

# A worker's address space. Masking keeps per-line structures for a body, so a body of very many
# short lines costs several times its size; past this a worker fails that body (it is withheld)
# instead of growing the host's memory. Applied where the platform enforces it (Linux).
WORKER_ADDRESS_SPACE_BYTES = 1536 * 1024 * 1024

OVER_MASKING_LIMIT = "over_masking_limit"
MASKING_FAILED = "masking_failed"


def _decoded(value: Any) -> Any:
    """The storage serialization decoded; text that is not JSON (or nests too deeply) as is."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, RecursionError):
            return value
    return value


def _body_text(value: Any) -> str | None:
    """Project already decoded the storage serialization; strings are wire text."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    return json.dumps(value)


def legacy_json_string(value: Any, *, recorded_sha256: Any) -> Any:
    """Unwrap an old extra JSON encoding only when the wire digest proves it.

    A valid JSON string body (including its quotes/whitespace) otherwise looks identical
    to double-encoded legacy text. Missing provenance must not guess away wire bytes.
    """
    text = _decoded(value)
    if not isinstance(text, str) or not recorded_sha256:
        return value
    if hmac.compare_digest(hashlib.sha256(text.encode()).hexdigest(), str(recorded_sha256)):
        return value
    unwrapped = _decoded(text)
    if isinstance(unwrapped, str) and hmac.compare_digest(
        hashlib.sha256(unwrapped.encode()).hexdigest(), str(recorded_sha256),
    ):
        return json.dumps(unwrapped)
    return value


def legacy_bytes_repr(value: Any, *, recorded_sha256: Any) -> Any:
    """Compatibility for bodies archived before the batch writer decoded bytes.

    That writer serialized the bytes object itself, so a body was stored as its Python repr
    ("b'...'") instead of its text. Such a body is decoded here as the writer now stores it
    (UTF-8, undecodable bytes replaced). Text that merely looks like a bytes literal is kept
    when the recorded body digest shows it is the body verbatim, and text that is not
    entirely one bytes literal is never touched.
    """
    if not isinstance(value, str):
        return value
    text = _decoded(value)
    if (not isinstance(text, str) or len(text) < 3
            or text[:2] not in ("b'", 'b"') or text[-1] != text[1]):
        return value
    if recorded_sha256 and hmac.compare_digest(
        hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest(), str(recorded_sha256),
    ):
        return value
    try:
        literal = ast.literal_eval(text)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return value
    if not isinstance(literal, bytes):
        return value
    return json.dumps(literal.decode("utf-8", errors="replace"))


def legacy_body(value: Any, *, recorded_sha256: Any) -> Any:
    """A stored body with both legacy storage encodings undone, as ``read_transactions`` does."""
    value = legacy_bytes_repr(value, recorded_sha256=recorded_sha256)
    return legacy_json_string(value, recorded_sha256=recorded_sha256)


def stored_body_size(value: Any) -> int:
    """A cheap size of a stored body before any decoding: characters of text, bytes of bytes."""
    if isinstance(value, (str, bytes, bytearray)):
        return len(value)
    return 0  # a decoded object: its encoded size is charged once it is masked


def masked_body_text(value: Any) -> tuple[str | None, str | None]:
    """``(text, None)``: what a masked view shows of one stored body; ``(None, reason)`` withheld.

    The same steps the archive projection applies: decode the storage serialization, withhold
    body secrets, then the shared redactor over the result.
    """
    if stored_body_size(value) > MAX_MASKED_BODY_CHARS:
        return None, OVER_MASKING_LIMIT
    decoded = _decoded(value)
    text = archived_body_text(decoded)
    if isinstance(text, str) and len(text) > MAX_MASKED_BODY_CHARS:
        return None, OVER_MASKING_LIMIT
    masked = redact_sensitive(withhold_body_secrets(decoded), redact_strings=True, scrub_text=True)
    return _body_text(masked), None


def raw_body_text(value: Any) -> str | None:
    return _body_text(_decoded(value))


def well_formed(text: str) -> str:
    """``text`` with every lone surrogate replaced by U+FFFD, so it encodes as strict UTF-8.

    A captured body can decode to a lone surrogate (``"\\ud800"`` in JSON); written with
    ``surrogatepass`` it made the export invalid UTF-8, which strict clients reject.
    """
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


def utf8(text: str) -> bytes:
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        return well_formed(text).encode("utf-8")


def encode_text(text: str | None) -> bytes | None:
    """The JSON text of one body string, as the export response serializes it (strict UTF-8)."""
    if text is None:
        return None
    try:
        return json.dumps(text, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        return json.dumps(well_formed(text), ensure_ascii=False).encode("utf-8")


def encode_body(value: Any, masked: bool, legacy: tuple[Any] | None = None) -> tuple[bytes | None, str | None]:
    """Worker entry point: ``(JSON fragment or None, omission reason or None)``.

    ``legacy`` carries the recorded body digest when the stored value still needs the legacy
    decoding ``read_transactions`` applies. Any failure on one body withholds that body
    (``masking_failed``) rather than failing the export or showing it unmasked; nothing about
    the body is logged or raised, since an exception message can quote it.
    """
    try:
        if legacy is not None:
            value = legacy_body(value, recorded_sha256=legacy[0])
        if not masked:
            return encode_text(raw_body_text(value)), None
        text, reason = masked_body_text(value)
        return encode_text(text), reason
    except Exception:  # noqa: BLE001 - one hostile body must not fail the export
        return None, MASKING_FAILED


def encoded_headers(value: Any, masked: bool, private: bool) -> tuple[Any, int]:
    """One call's stored headers as the archive view shows them, and their encoded size.

    Masked: key-name and free-text redaction (the shared redactor), and for a private workflow
    every value withheld. Raw: decoded only.
    """
    headers = _decoded(value)
    if masked:
        headers = redact_sensitive(headers, redact_strings=True, scrub_text=True)
        if private:
            headers = {key: "[REDACTED]" for key in (headers or {})}
    size = len(utf8(json.dumps(headers, ensure_ascii=False)))
    return headers, size


def encode_payload(kind: str, value: Any, masked: bool, extra: Any = None) -> tuple[Any, int, str | None]:
    """Worker entry point for one payload: ``(value shown, encoded bytes, omission reason)``.

    A body comes back as its JSON fragment (``extra``: the recorded digest when legacy decoding
    is still due), headers as the redacted mapping (``extra``: private workflow). Any failure
    withholds the payload (``masking_failed``); nothing about it is logged or raised.
    """
    if kind == "headers":
        try:
            headers, size = encoded_headers(value, masked, bool(extra))
        except Exception:  # noqa: BLE001 - one hostile payload must not fail the export
            return None, 0, MASKING_FAILED
        return headers, size, None
    fragment, reason = encode_body(value, masked, extra)
    return fragment, len(fragment) if fragment is not None else 0, reason


def encode_payloads(work: list[tuple[str, Any, bool, Any]]) -> list[tuple[Any, int, str | None]]:
    """``encode_payload`` for several consecutive payloads in one round trip to the worker."""
    return [encode_payload(kind, value, masked, extra) for kind, value, masked, extra in work]


def initialize_worker() -> None:
    """Bound a worker's memory where the platform enforces an address-space limit."""
    try:
        import resource
    except ImportError:  # not POSIX
        return
    limit = WORKER_ADDRESS_SPACE_BYTES
    try:
        _soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        if hard == resource.RLIM_INFINITY or hard > limit:
            resource.setrlimit(resource.RLIMIT_AS, (limit, hard))
    except (ValueError, OSError):
        pass  # not enforced here (macOS); the size limits still bound each body


# --- Worker processes that never re-run the API ---------------------------------------------------
# A spawned child is told to re-run the parent's ``__main__`` before it unpickles its work. The
# API service runs ``python3 /app/api.py``, so every masking worker imported the whole API (about
# 1.8 s and 140 MB each; review of R2). The masking worker needs none of it: its work is
# ``encode_body`` above, importable by name. These classes are the standard spawn start method
# with that one instruction left out of the child's preparation data. The launch code itself is
# the standard library's own (``popen_spawn_posix.Popen._launch``), read through a ``spawn``
# module whose ``get_preparation_data`` drops the main-module entries.


class _SpawnWithoutMain:
    """``multiprocessing.spawn``, except the child is not told to re-run the parent's main."""

    def __getattr__(self, name: str) -> Any:
        return getattr(_spawn, name)

    @staticmethod
    def get_preparation_data(name: str) -> dict[str, Any]:
        data = _spawn.get_preparation_data(name)
        data.pop("init_main_from_name", None)
        data.pop("init_main_from_path", None)
        return data


_STANDARD_LAUNCH = getattr(_popen_spawn_posix.Popen, "_launch", None)


def _rebound_launch() -> Any | None:
    """The standard launch reading ``spawn`` through ``_SpawnWithoutMain``, or None when this
    Python's launch is not the shape it was checked against (it must look up
    ``spawn.get_preparation_data`` through the module global ``spawn``)."""
    code = getattr(_STANDARD_LAUNCH, "__code__", None)
    if code is None or "spawn" not in code.co_names or "get_preparation_data" not in code.co_names:
        return None
    if _STANDARD_LAUNCH.__closure__:
        return None
    return types.FunctionType(
        code, {**vars(_popen_spawn_posix), "spawn": _SpawnWithoutMain()},
        _STANDARD_LAUNCH.__name__, _STANDARD_LAUNCH.__defaults__, None,
    )


_launch_without_main = _rebound_launch()


class _WorkerPopen(_popen_spawn_posix.Popen):
    if _launch_without_main is not None:
        _launch = _launch_without_main


class _WorkerProcess(_mp_context.SpawnProcess):
    @staticmethod
    def _Popen(process_obj: Any) -> _WorkerPopen:
        return _WorkerPopen(process_obj)


class _WorkerContext(_mp_context.SpawnContext):
    Process = _WorkerProcess


def worker_context() -> _mp_context.BaseContext:
    """A context whose children import only what their work needs.

    Normally the spawn method without the main-module instruction. If this Python's spawn launch
    has changed shape, fall back to the forkserver: the parent's main is then imported once, in
    the server, and every worker forks from it with this module preloaded.
    """
    if _launch_without_main is not None:
        return _WorkerContext()
    import multiprocessing

    context = multiprocessing.get_context("forkserver")
    context.set_forkserver_preload(["__main__", __name__])
    return context
