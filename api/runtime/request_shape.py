"""Derive a bounded, value-free request-body shape from crawler output."""

from __future__ import annotations

import json
from typing import Any, Mapping
import urllib.parse


MAX_REQUEST_BODY_SHAPE_BYTES = 256 * 1024
MAX_REQUEST_BODY_FIELDS = 128
MAX_REQUEST_BODY_FIELD_LENGTH = 200


def _field_names(values: Any) -> tuple[str, ...]:
    names: list[str] = []
    for raw in values:
        name = str(raw or "").strip()
        if (
            not name
            or len(name) > MAX_REQUEST_BODY_FIELD_LENGTH
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in name)
        ):
            continue
        if name not in names:
            names.append(name)
        if len(names) >= MAX_REQUEST_BODY_FIELDS:
            break
    return tuple(sorted(names))


def public_request_body_shape(value: Any) -> tuple[str | None, tuple[str, ...]]:
    """Return inferred media type and top-level field names, never field values."""
    text = str(value or "")
    if not text or len(text.encode("utf-8", "replace")) > MAX_REQUEST_BODY_SHAPE_BYTES:
        return None, ()
    try:
        decoded = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        decoded = None
    if isinstance(decoded, Mapping):
        names = _field_names(decoded.keys())
        return ("application/json", names) if names else (None, ())
    if "=" not in text:
        return None, ()
    try:
        pairs = urllib.parse.parse_qsl(
            text,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=MAX_REQUEST_BODY_FIELDS,
        )
    except ValueError:
        return None, ()
    names = _field_names(name for name, _value in pairs)
    return (
        ("application/x-www-form-urlencoded", names)
        if names else (None, ())
    )
