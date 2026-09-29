"""Content-free HTTP workflow bindings on the existing Hunt request capability.

Captured values are data, never commands, destinations or authority. JSON pointers
use RFC 6901; destinations are only body fields or target HTTP headers.
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Mapping

_NAME = r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$"
_HEADER = r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,120}$"
_FORBIDDEN_HEADERS = frozenset({
    "host", "content-length", "connection", "transfer-encoding", "upgrade", "te", "trailer",
    "proxy-authorization", "proxy-connection", "keep-alive",
    "x-original-url", "x-rewrite-url", "x-http-method-override", "x-http-method", "x-method-override",
})
POINTER_SCHEMA = {"type": "string", "maxLength": 512}
HTTP_EXCHANGE_PROPERTIES: Mapping[str, Any] = {
    "capture": {"type": "array", "maxItems": 16, "items": {
        "type": "object", "additionalProperties": False, "required": ["name"],
        "properties": {"name": {"type": "string", "pattern": _NAME},
            "json_pointer": POINTER_SCHEMA, "header": {"type": "string", "pattern": _HEADER}},
    }},
    "request_bindings": {"type": "array", "maxItems": 16, "items": {
        "type": "object", "additionalProperties": False,
        "properties": {
            "source_action_id": {"type": "string", "maxLength": 36},
            "capture_name": {"type": "string", "pattern": _NAME},
            "principal": {"type": "string", "enum": ["primary", "secondary", "service"]},
            "profile_id": {"type": "string", "maxLength": 36},
            "profile_version": {"type": "integer", "minimum": 1},
            "credential_field": {"type": "string", "enum": ["secret", "username", "client_id"]},
            "body_pointer": POINTER_SCHEMA, "header": {"type": "string", "pattern": _HEADER},
            "prefix": {"type": "string", "maxLength": 32,
                "description": "Literal non-secret header prefix, for example Bearer followed by a space."},
        },
    }},
}


def pointer_parts(pointer: Any) -> tuple[str, ...]:
    if not isinstance(pointer, str) or len(pointer) > 512 or (pointer and not pointer.startswith('/')):
        raise ValueError("invalid HTTP workflow JSON pointer")
    if re.search(r"~(?![01])", pointer):
        raise ValueError("invalid HTTP workflow JSON pointer escape")
    parts = tuple(part.replace('~1', '/').replace('~0', '~') for part in pointer.split('/')[1:])
    if len(parts) > 16:
        raise ValueError("HTTP workflow JSON pointer is too deep")
    return parts


def pointer_get(value: Any, pointer: str) -> Any:
    for part in pointer_parts(pointer):
        if isinstance(value, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", part):
                raise ValueError("HTTP workflow array index is invalid")
            try:
                value = value[int(part)]
            except (ValueError, IndexError):
                raise ValueError("HTTP workflow response field is missing") from None
        elif isinstance(value, Mapping) and part in value:
            value = value[part]
        else:
            raise ValueError("HTTP workflow response field is missing")
    return value


def pointer_set(body: dict[str, Any], pointer: str, value: Any) -> None:
    parts = pointer_parts(pointer)
    if not parts:
        raise ValueError("HTTP workflow binding must name a body field")
    parent: Any = body
    for part in parts[:-1]:
        if isinstance(parent, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
            try:
                parent = parent[int(part)]
            except IndexError:
                raise ValueError("HTTP workflow body parent is missing") from None
        elif isinstance(parent, dict) and part in parent:
            parent = parent[part]
        else:
            raise ValueError("HTTP workflow body parent is missing")
    last = parts[-1]
    if isinstance(parent, dict):
        parent[last] = value
    elif isinstance(parent, list) and re.fullmatch(r"0|[1-9][0-9]*", last) and int(last) < len(parent):
        parent[int(last)] = value
    else:
        raise ValueError("HTTP workflow body destination is invalid")


def validate_exchange_input(values: Mapping[str, Any]) -> None:
    names: set[str] = set()
    for capture in values.get("capture") or ():
        if ("json_pointer" in capture) == ("header" in capture):
            raise ValueError("capture requires exactly one JSON pointer or header")
        name = capture["name"]
        if name in names:
            raise ValueError("capture names must be unique")
        names.add(name)
        if "json_pointer" in capture:
            pointer_parts(capture["json_pointer"])
    destinations: set[tuple[str, str]] = set()
    for binding in values.get("request_bindings") or ():
        sources = sum(key in binding for key in ("source_action_id", "principal", "profile_id"))
        if sources != 1 or (("body_pointer" in binding) == ("header" in binding)):
            raise ValueError("request binding requires one source and one body/header destination")
        if "source_action_id" in binding:
            uuid.UUID(binding["source_action_id"])
            if not binding.get("capture_name") or any(k in binding for k in ("credential_field", "profile_version")):
                raise ValueError("response binding requires a capture name, not credential fields")
        else:
            if binding.get("credential_field") not in {"secret", "username", "client_id"} or "capture_name" in binding:
                raise ValueError("credential binding requires a credential field, not a capture name")
            if "profile_id" in binding:
                uuid.UUID(binding["profile_id"])
                if type(binding.get("profile_version")) is not int or binding["profile_version"] < 1:
                    raise ValueError("newly selected profile requires its current version")
            elif "profile_version" in binding:
                raise ValueError("a named principal uses its saved Hunt profile version")
        if "prefix" in binding and ("header" not in binding or any(
                ord(char) < 32 or ord(char) > 126 for char in binding["prefix"])):
            raise ValueError("workflow prefix must be printable ASCII on a header binding")
        if "body_pointer" in binding:
            if not pointer_parts(binding["body_pointer"]):
                raise ValueError("body binding must name a field")
            if not any(key in values for key in ("json_body", "form_body")):
                raise ValueError("body bindings require a JSON or form body template")
            if "form_body" in values and len(pointer_parts(binding["body_pointer"])) != 1:
                raise ValueError("form binding must name one form field")
            destination = ("body", binding["body_pointer"])
        else:
            header = str(binding["header"]).lower()
            if header in _FORBIDDEN_HEADERS:
                raise ValueError("workflow bindings cannot change HTTP routing or framing headers")
            destination = ("header", header)
        if destination in destinations:
            raise ValueError("duplicate HTTP workflow binding destination")
        destinations.add(destination)


def public_capture_references(values: Any, *, source_action_id: Any) -> list[dict[str, str]]:
    """Expose only bounded same-action handles, never arbitrary persisted fields."""
    try:
        source = str(uuid.UUID(str(source_action_id)))
    except (TypeError, ValueError, AttributeError):
        return []
    result: list[dict[str, str]] = []
    if isinstance(values, list):
        for item in values[:16]:
            if (isinstance(item, Mapping) and item.get("source_action_id") == source
                    and isinstance(item.get("capture_name"), str)
                    and re.fullmatch(_NAME, item["capture_name"])):
                result.append({"source_action_id": source, "capture_name": item["capture_name"]})
    return result
