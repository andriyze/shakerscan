"""Bounded, value-free JSON structure for prospective Hunt boundary discovery.

Only a fixed vocabulary survives. Unknown property names, tool arguments and
secret-bearing subtrees never enter the public archive metadata. This is shape,
not a claim that a field has the meaning suggested by its name.
"""
from __future__ import annotations

import json
from typing import Any, Mapping

SCHEMA = "hunt-http-structure/v1"
MAX_BYTES = 65536
MAX_DEPTH = 6
MAX_FIELDS = 48
CONTAINERS = frozenset({"data", "result", "record", "resource", "identity", "output"})
LEAVES = frozenset({
    "id", "resource_id", "owner", "owner_id", "subject", "user_id", "tenant",
    "tenant_id", "marker", "answer", "text", "content", "status", "state",
})
TYPES = frozenset({"string", "number", "boolean", "null"})


def _object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate property")
        result[name] = value
    return result


def _invalid_constant(_value):
    raise ValueError("nonfinite JSON")


def response_structure(captured: Mapping[str, Any]) -> dict[str, Any]:
    """Inspect an eligible complete JSON response without retaining values."""
    def unavailable(reason):
        return {"schema_version": SCHEMA, "status": "unavailable", "reason": reason, "fields": []}

    body = captured.get("response_body")
    if captured.get("response_body_truncated") or captured.get("response_digest_scope") == "prefix":
        return unavailable("truncated_response")
    if not isinstance(body, bytes) or not body:
        return unavailable("body_unavailable")
    if len(body) > MAX_BYTES:
        return unavailable("body_limit")
    headers = captured.get("response_headers") or {}
    content_type = next((str(v).split(";", 1)[0].strip().lower()
                         for k, v in headers.items() if str(k).lower() == "content-type"), "")
    if content_type != "application/json" and not content_type.endswith("+json"):
        return unavailable("unsupported_content_type")
    try:
        raw = json.loads(body, object_pairs_hook=_object, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        return unavailable("invalid_json")
    if not isinstance(raw, dict):
        return unavailable("unsupported_root")
    fields: list[dict[str, str]] = []

    def visit(value, prefix="", depth=0):
        if depth > MAX_DEPTH:
            raise ValueError("structure_limit")
        for name, child in value.items():
            # Names are kept only when explicitly known; never stringify a name
            # or traverse an unknown subtree (including credentials/tool inputs).
            path = f"{prefix}.{name}" if prefix else name
            if name in CONTAINERS and isinstance(child, dict):
                visit(child, path, depth + 1)
            elif name in LEAVES and not isinstance(child, (dict, list)):
                kind = ("null" if child is None else "boolean" if isinstance(child, bool)
                        else "number" if isinstance(child, (int, float)) else "string")
                fields.append({"path": path, "type": kind})
                if len(fields) > MAX_FIELDS:
                    raise ValueError("structure_limit")
    try:
        visit(raw)
    except ValueError:
        return unavailable("structure_limit")
    return {"schema_version": SCHEMA, "status": "available", "fields": fields}


def structure_fields(raw: Any) -> dict[str, str]:
    """Validate stored shape metadata before interpreting it; reject extras."""
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "status", "fields"}:
        return {}
    if raw["schema_version"] != SCHEMA or raw["status"] != "available":
        return {}
    fields = raw["fields"]
    if not isinstance(fields, list) or len(fields) > MAX_FIELDS:
        return {}
    result = {}
    for item in fields:
        if not isinstance(item, dict) or set(item) != {"path", "type"}:
            return {}
        path, kind = item["path"], item["type"]
        if not isinstance(path, str) or not isinstance(kind, str) or kind not in TYPES:
            return {}
        parts = path.split(".")
        if (len(path) > 128 or len(parts) > MAX_DEPTH + 1 or path in result
                or parts[-1] not in LEAVES or any(p not in CONTAINERS for p in parts[:-1])):
            return {}
        result[path] = kind
    return result
