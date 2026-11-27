"""Derive a bounded, value-free request-body shape from crawler output."""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence
import urllib.parse


MAX_REQUEST_BODY_SHAPE_BYTES = 256 * 1024
MAX_REQUEST_BODY_FIELDS = 128
MAX_REQUEST_BODY_FIELD_LENGTH = 200
MAX_REQUEST_BODY_FIELD_DEPTH = 8


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
    # A crawler body is serialized text. Stringifying another JSON value (or
    # bytes) can turn its representation into bogus form field names.
    if not isinstance(value, str):
        return None, ()
    text = value
    if (
        not text
        or len(text) > MAX_REQUEST_BODY_SHAPE_BYTES
        or len(text.encode("utf-8", "replace")) > MAX_REQUEST_BODY_SHAPE_BYTES
    ):
        return None, ()
    try:
        decoded = json.loads(text)
    except RecursionError:
        # A byte-bounded body can still exceed the decoder's nesting limit.
        return None, ()
    except ValueError:
        # Truncated/malformed JSON must not fall through to parse_qsl: an '='
        # inside a field value would publish part of that value as a field name.
        if text.lstrip().startswith(("{", "[", '"', "\ufeff")):
            return None, ()
    else:
        if isinstance(decoded, Mapping):
            names = _field_names(decoded.keys())
            return ("application/json", names) if names else (None, ())
        # Valid JSON arrays and scalars have no top-level named fields. In
        # particular, never reinterpret a JSON string's contents as form data.
        return None, ()
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


def resolve_json_field_path(document: Any, field_name: str) -> tuple[str | int, ...]:
    """Resolve a flattened field to existing JSON nodes without creating any nodes.

    Collection paths use ``items[].name`` for the first array element; exact replay
    uses ``items.0.name``. Older discovery paths use ``items.name``. Resolve each
    against the actual document so all mutation/proof senders select the same field.
    Numeric object keys remain keys, and explicit indices preserve array siblings.
    """
    if (
        not isinstance(field_name, str) or not field_name
        or len(field_name) > MAX_REQUEST_BODY_FIELD_LENGTH
        or any(ord(char) < 0x20 or ord(char) == 0x7f for char in field_name)
    ):
        raise ValueError("invalid JSON field path")
    path: list[str | int] = []
    cursor = document

    def descend(component: str | int) -> None:
        nonlocal cursor
        if len(path) >= MAX_REQUEST_BODY_FIELD_DEPTH:
            raise ValueError("JSON field path exceeds depth limit")
        if isinstance(cursor, Mapping) and isinstance(component, str) and component in cursor:
            cursor = cursor[component]
        elif isinstance(cursor, list) and isinstance(component, int) and 0 <= component < len(cursor):
            cursor = cursor[component]
        else:
            raise ValueError("JSON field path does not match the body shape")
        path.append(component)

    for raw_part in field_name.split("."):
        key, arrays = raw_part, 0
        while key.endswith("[]"):
            key, arrays = key[:-2], arrays + 1
        if not key and not arrays:
            raise ValueError("invalid JSON field path")
        if key:
            if isinstance(cursor, list) and key.isdecimal():
                descend(int(key))
            else:
                # The older discovery convention omits the array marker.
                while isinstance(cursor, list):
                    descend(0)
                descend(key)
        for _ in range(arrays):
            descend(0)
    return tuple(path)


def _field_path(raw_name: str) -> list[tuple[str, bool]]:
    """Split one flattened field name into ``(key, is_array)`` segments.

    An explicit ``[]`` marker (imported collections) and a numeric index segment (exact
    replay paths such as ``items.0.id``) both mean the preceding key holds an array.
    """
    segments: list[tuple[str, bool]] = []
    for part in str(raw_name).split("."):
        if not part:
            continue
        if part.isdigit():
            if not segments:
                return []  # a top-level array has no named field to place
            segments[-1] = (segments[-1][0], True)
            continue
        is_array = part.endswith("[]")
        key = part[:-2] if is_array else part
        if not key:
            return []
        segments.append((key, is_array))
    return segments


def json_field_leaf_name(raw_name: str) -> str:
    """The key a nested body field is sent under (``profile.name`` -> ``name``)."""
    segments = _field_path(raw_name)
    return segments[-1][0] if segments else ""


def nested_json_body(
    field_names: Sequence[str], *, placeholder: str,
    values: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Rebuild the JSON object that a list of flattened body field names describes.

    Discovery records a nested body as dotted paths (``profile.email``), and an array of
    objects either as a parent plus children (``items``, ``items.id``) or with an explicit
    marker (``items[]``, ``items[].id``). A request built from literal dotted keys sends a
    schema the target does not have, so the target ignores the field and the test proves
    nothing. Every sender (proof, discovery tool, continuation worklist) rebuilds the real
    nesting here so they all agree on one shape.

    ``values`` places a value at an exact field name; every other leaf is ``placeholder``.
    When the names use explicit ``[]`` markers, a parent plus children is an object, because
    that convention lists every container and marks its arrays.
    """
    names = [str(name) for name in field_names if str(name).strip()]
    explicit_arrays = any("[]" in name for name in names)
    overrides = dict(values or {})
    body: dict[str, Any] = {}
    for raw_name in names:
        segments = _field_path(raw_name)
        if not segments:
            continue
        cursor: Any = body
        for key, is_array in segments[:-1]:
            child = cursor.get(key)
            if is_array or isinstance(child, list):
                if not isinstance(child, list):
                    child = cursor[key] = []
                if not child or not isinstance(child[0], dict):
                    child[:] = [{}]
                cursor = child[0]
                continue
            if isinstance(child, dict):
                cursor = child
                continue
            nested: dict[str, Any] = {}
            # Without explicit markers, a parent name plus child names is the flattened
            # shape emitted for an array of objects (items, items.id).
            cursor[key] = [nested] if child is not None and not explicit_arrays else nested
            cursor = nested
        key, is_array = segments[-1]
        value = overrides.get(raw_name, placeholder)
        existing = cursor.get(key)
        if is_array:
            if not isinstance(existing, list) or not existing:
                cursor[key] = [value]
            elif not isinstance(existing[0], (dict, list)):
                existing[0] = value
        elif not isinstance(existing, (dict, list)):
            cursor[key] = value
    return body
