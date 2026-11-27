"""One secrecy boundary for what a Hunt action makes public.

Every observation a worker action publishes (the action answer the planner reads, the tool
receipt, the Hunt record, endpoint knowledge and the findings materialized from it) passes
``PublicSecrecy.observations`` once, after every phase of the action has run and before any of
those is written. It withholds two kinds of value:

- **Known values**: the identity the action sent (each header value; a cookie's every value; an
  ``Authorization`` value's credential, a Basic credential's user and password, a JWT's parts),
  in any encoding the target may echo it in (``KnownValueScrubber``), wherever it appears.
- **Labelled secrets**: a value the text itself names as one (a ``Cookie:`` or
  ``Authorization:`` line, a ``Bearer`` credential, an ``HTTP_COOKIE`` table row, a password
  field, a ``key=value`` assignment), in the free-text fields that carry target content.

A phase added to an action later (a proof, a follow-up request) is covered without wiring a
safeguard of its own: its observations join the action's before this boundary runs.
"""
from __future__ import annotations

import base64
import binascii
from typing import Any, Iterable, Mapping

try:
    from runtime.archive_body_masking import KnownValueScrubber, mask_body_text
except ModuleNotFoundError:  # package import layout
    from api.runtime.archive_body_masking import KnownValueScrubber, mask_body_text

try:
    from redaction import MASK, is_sensitive_key, redact_text, redact_url_credentials
except ModuleNotFoundError:  # package import layout
    from scanner.redaction import MASK, is_sensitive_key, redact_text, redact_url_credentials

# Observation fields that carry target content as free text (an excerpt around a database error,
# a tool's message, a body sample): labelled secrets in them are withheld by the body masking.
TARGET_TEXT_FIELDS = frozenset({
    "redacted_excerpt", "excerpt", "message", "body_sample", "text_sample", "snippet",
    "response_excerpt", "matched", "extracted_results", "detail", "evidence",
})
# A known value shorter than this is not searched for: it would match ordinary text.
MIN_KNOWN_VALUE_CHARS = 4
_MAX_DEPTH = 12


def identity_values(headers: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Every value an action's identity headers carry, as a target may echo it."""
    values: set[str] = set()
    for name, raw in (headers or {}).items():
        value = str(raw or "")
        values.add(value)
        lowered = str(name).lower()
        if lowered in {"authorization", "proxy-authorization"} and " " in value.strip():
            scheme, material = value.strip().split(" ", 1)
            material = material.strip()
            values.add(material)
            if scheme.lower() == "basic":
                try:
                    values.update(base64.b64decode(material, validate=True).decode().split(":", 1))
                except (ValueError, UnicodeError, binascii.Error):
                    pass
            values.update(_jwt_parts(material))
        if lowered == "cookie":
            for part in value.split(";"):
                cookie = part.partition("=")[2].strip().strip('"')
                values.add(cookie)
                values.update(_jwt_parts(cookie))
        values.update(_jwt_parts(value))
    return tuple(sorted(item for item in values if len(item) >= MIN_KNOWN_VALUE_CHARS))


def _jwt_parts(value: str) -> list[str]:
    """A JWT's header, claims and signature: each is echoed on its own (a decoded claim view)."""
    parts = value.strip().split(".")
    if len(parts) != 3 or not all(parts):
        return []
    return [part for part in parts if len(part) >= 8]


class PublicSecrecy:
    """The one sanitizer for an action's public output. Holds known values; never shows them."""

    def __init__(self, known_values: Iterable[str] = ()) -> None:
        known = sorted({str(item) for item in known_values if len(str(item)) >= MIN_KNOWN_VALUE_CHARS},
                       key=len, reverse=True)
        self._scrubber = KnownValueScrubber(known) if known else None

    @classmethod
    def for_headers(cls, headers: Mapping[str, Any] | None, extra: Iterable[str] = ()) -> "PublicSecrecy":
        return cls((*identity_values(headers), *extra))

    def __repr__(self) -> str:
        return "PublicSecrecy(values_visible=False)"

    def text(self, value: Any, *, target_text: bool = True) -> Any:
        """One string: known values, then (for target content) labelled secrets."""
        if not isinstance(value, str) or not value:
            return value
        if self._scrubber is not None:
            value = self._scrubber.scrub(value, lambda _value: MASK)
        if target_text:
            value = mask_body_text(value)
        return redact_text(redact_url_credentials(value))

    def observations(self, items: Any) -> list[dict[str, Any]]:
        """Every observation of an action, sanitized; non-mappings are dropped."""
        return [self._value(dict(item), 0, None) for item in items or () if isinstance(item, Mapping)]

    def value(self, item: Any) -> Any:
        return self._value(item, 0, None)

    def _value(self, item: Any, depth: int, key: str | None) -> Any:
        if depth > _MAX_DEPTH:
            return MASK if isinstance(item, (str, Mapping, list, tuple)) else item
        if isinstance(item, Mapping):
            out: dict[str, Any] = {}
            for name, nested in item.items():
                if isinstance(nested, str) and nested and is_sensitive_key(name):
                    out[name] = MASK
                else:
                    out[name] = self._value(nested, depth + 1, str(name))
            return out
        if isinstance(item, (list, tuple)):
            return [self._value(nested, depth + 1, key) for nested in item]
        if isinstance(item, str):
            return self.text(item, target_text=key in TARGET_TEXT_FIELDS)
        return item


__all__ = ["MIN_KNOWN_VALUE_CHARS", "PublicSecrecy", "TARGET_TEXT_FIELDS", "identity_values"]
