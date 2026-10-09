"""One archived body, decoded, masked and JSON-encoded for an export, in a worker process.

The masking passes are linear, but they are regex work, and CPython's regex engine holds the
interpreter lock for a whole pass over a body. Run on the API process, even on a thread, a
multi-megabyte body stalled the event loop for most of a second (external release audit,
2026-10-09). An export therefore sends each body to a small process pool and gets back the
JSON text of what the masked (or raw) view shows; the API process only splices those bytes
into the export. The functions here are also what the in-process ``export_document`` runs, so
both paths produce the same text.

This module stays light (masking, redaction, json): a spawned worker imports only it.
"""

from __future__ import annotations

import json
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
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
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


def encode_text(text: str | None) -> bytes | None:
    """The JSON text of one body string, as the export response serializes it."""
    if text is None:
        return None
    return json.dumps(text, ensure_ascii=False).encode("utf-8", errors="surrogatepass")


def encode_body(value: Any, masked: bool) -> tuple[bytes | None, str | None]:
    """Worker entry point: ``(JSON fragment or None, omission reason or None)``."""
    if not masked:
        return encode_text(raw_body_text(value)), None
    try:
        text, reason = masked_body_text(value)
    except MemoryError:
        return None, MASKING_FAILED
    return encode_text(text), reason


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
