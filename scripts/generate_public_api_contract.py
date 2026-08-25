#!/usr/bin/env python3
"""Freeze OpenAPI drift and generate V2 client request/response types.

The manifest covers every operation and component schema so an unrelated API
change cannot silently rename an operation or mutate a schema. The TypeScript
surface is intentionally limited to the six release-critical public products.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "api"), str(ROOT / "scanner")]

from api import api as api_module  # noqa: E402
from api.public_api_contract import public_v2_surface  # noqa: E402


MANIFEST_OUTPUT = ROOT / "docs" / "generated" / "public-openapi-manifest.json"
TYPES_OUTPUT = ROOT / "ui" / "src" / "lib" / "publicApi.generated.ts"
HTTP_METHODS = ("get", "post", "put", "patch", "delete")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _json_schema_for_content(value: Any) -> Any:
    content = value.get("content") if isinstance(value, Mapping) else None
    if not isinstance(content, Mapping):
        return None
    for media_type in (
        "application/json", "application/problem+json", "application/octet-stream",
        "text/html", "text/plain",
    ):
        media = content.get(media_type)
        if isinstance(media, Mapping) and isinstance(media.get("schema"), Mapping):
            return media["schema"]
    for media in content.values():
        if isinstance(media, Mapping) and isinstance(media.get("schema"), Mapping):
            return media["schema"]
    return None


def build_manifest(openapi: Mapping[str, Any]) -> dict[str, Any]:
    operations: dict[str, Any] = {}
    operation_ids: dict[str, str] = {}
    surfaces: dict[str, list[str]] = {}
    for path, path_item in sorted((openapi.get("paths") or {}).items()):
        if not isinstance(path_item, Mapping):
            continue
        shared_parameters = path_item.get("parameters") or []
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, Mapping):
                continue
            key = f"{method.upper()} {path}"
            operation_id = str(operation.get("operationId") or "")
            if not operation_id:
                raise ValueError(f"OpenAPI operation has no operationId: {key}")
            previous = operation_ids.setdefault(operation_id, key)
            if previous != key:
                raise ValueError(
                    f"duplicate OpenAPI operationId {operation_id}: {previous}, {key}"
                )
            request_schema = _json_schema_for_content(operation.get("requestBody") or {})
            response_schemas = {
                str(status): _json_schema_for_content(response)
                for status, response in sorted((operation.get("responses") or {}).items())
                if _json_schema_for_content(response) is not None
            }
            surface = public_v2_surface(str(path))
            operations[key] = {
                "operation_id": operation_id,
                "surface": surface,
                "deprecated": bool(operation.get("deprecated", False)),
                "tags": sorted(str(tag) for tag in operation.get("tags") or []),
                "parameters_sha256": _digest([
                    *shared_parameters, *(operation.get("parameters") or []),
                ]),
                "request_schema_sha256": (
                    _digest(request_schema) if request_schema is not None else None
                ),
                "response_schema_sha256": {
                    status: _digest(schema)
                    for status, schema in response_schemas.items()
                },
                "security_sha256": _digest(operation.get("security") or []),
            }
            if surface:
                surfaces.setdefault(surface, []).append(key)

    components = openapi.get("components") or {}
    schemas = components.get("schemas") if isinstance(components, Mapping) else {}
    schema_digests = {
        str(name): _digest(schema)
        for name, schema in sorted((schemas or {}).items())
    }
    manifest: dict[str, Any] = {
        "schema_version": "shakerscan-public-openapi-manifest/v1",
        "openapi": str(openapi.get("openapi") or ""),
        "api": {
            "title": str((openapi.get("info") or {}).get("title") or ""),
            "version": str((openapi.get("info") or {}).get("version") or ""),
        },
        "operation_count": len(operations),
        "component_schema_count": len(schema_digests),
        "surfaces": {name: sorted(items) for name, items in sorted(surfaces.items())},
        "operations": operations,
        "component_schema_sha256": schema_digests,
    }
    manifest["contract_sha256"] = _digest(manifest)
    return manifest


def _schema_refs(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, Mapping):
        ref = value.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            refs.add(ref.rsplit("/", 1)[-1])
        for child in value.values():
            refs.update(_schema_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.update(_schema_refs(child))
    return refs


def _selected_operations(openapi: Mapping[str, Any]) -> list[tuple[str, str, Mapping[str, Any]]]:
    selected: list[tuple[str, str, Mapping[str, Any]]] = []
    for path, path_item in sorted((openapi.get("paths") or {}).items()):
        if public_v2_surface(str(path)) is None or not isinstance(path_item, Mapping):
            continue
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if isinstance(operation, Mapping):
                selected.append((method.upper(), str(path), operation))
    return selected


def _identifier(value: str, *, fallback: str = "GeneratedType") -> str:
    words = re.findall(r"[A-Za-z0-9]+", str(value))
    name = "".join(word[:1].upper() + word[1:] for word in words) or fallback
    if name[0].isdigit():
        name = "T" + name
    return name


def _property_name(value: str) -> str:
    return value if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value) else json.dumps(value)


def _literal(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def _render_schema(
    schema: Any,
    *,
    root: Mapping[str, Any] | None = None,
    indent: str = "",
) -> str:
    if not isinstance(schema, Mapping) or not schema:
        return "unknown"
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref.startswith("#/components/schemas/"):
            return _identifier(ref.rsplit("/", 1)[-1])
        if ref.startswith("#/$defs/") and isinstance(root, Mapping):
            definition = (root.get("$defs") or {}).get(ref.rsplit("/", 1)[-1])
            return _render_schema(definition, root=root, indent=indent)
        return "unknown"
    if "const" in schema:
        return _literal(schema["const"])
    if isinstance(schema.get("enum"), list):
        values = schema["enum"]
        return " | ".join(_literal(value) for value in values) if values else "never"
    for keyword, joiner in (("anyOf", " | "), ("oneOf", " | "), ("allOf", " & ")):
        children = schema.get(keyword)
        if isinstance(children, list) and children:
            rendered = [_render_schema(child, root=root or schema, indent=indent) for child in children]
            return joiner.join(dict.fromkeys(rendered))
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        return " | ".join(
            dict.fromkeys(_render_schema({**schema, "type": item}, root=root, indent=indent) for item in schema_type)
        )
    if schema_type == "null":
        return "null"
    if schema_type == "string":
        return "string"
    if schema_type in {"integer", "number"}:
        return "number"
    if schema_type == "boolean":
        return "boolean"
    if schema_type == "array" or "items" in schema:
        item = _render_schema(schema.get("items") or {}, root=root or schema, indent=indent)
        return f"Array<{item}>"
    if schema_type == "object" or "properties" in schema or "additionalProperties" in schema:
        properties = schema.get("properties") or {}
        required = set(schema.get("required") or [])
        lines: list[str] = []
        child_indent = indent + "  "
        for name, child in properties.items():
            optional = "" if name in required else "?"
            rendered = _render_schema(child, root=root or schema, indent=child_indent)
            lines.append(f"{child_indent}{_property_name(str(name))}{optional}: {rendered}")
        additional = schema.get("additionalProperties")
        if not properties:
            if additional is False:
                return "Record<string, never>"
            if isinstance(additional, Mapping):
                value = _render_schema(additional, root=root or schema, indent=child_indent)
                return f"Record<string, {value}>"
            return "Record<string, unknown>"
        object_type = "{\n" + "\n".join(lines) + f"\n{indent}}}"
        if isinstance(additional, Mapping):
            value = _render_schema(additional, root=root or schema, indent=child_indent)
            return f"({object_type} & Record<string, {value}>)"
        if additional is True:
            return f"({object_type} & Record<string, unknown>)"
        return object_type
    return "unknown"


def _operation_type_name(operation_id: str, suffix: str) -> str:
    return _identifier(operation_id) + suffix


def render_types(openapi: Mapping[str, Any], manifest: Mapping[str, Any]) -> str:
    selected = _selected_operations(openapi)
    components = ((openapi.get("components") or {}).get("schemas") or {})
    needed: set[str] = set()
    operation_schemas: list[tuple[str, str, str, Any, Any]] = []
    for method, path, operation in selected:
        operation_id = str(operation["operationId"])
        request_schema = _json_schema_for_content(operation.get("requestBody") or {})
        responses = operation.get("responses") or {}
        response_schema = None
        for status in sorted(responses, key=lambda value: (not str(value).startswith("2"), str(value))):
            candidate = _json_schema_for_content(responses[status])
            if candidate is not None:
                response_schema = candidate
                break
        needed.update(_schema_refs(request_schema))
        needed.update(_schema_refs(response_schema))
        operation_schemas.append((method, path, operation_id, request_schema, response_schema))

    queue = list(needed)
    while queue:
        name = queue.pop()
        for ref in _schema_refs(components.get(name)):
            if ref not in needed:
                needed.add(ref)
                queue.append(ref)

    lines = [
        "// Generated by scripts/generate_public_api_contract.py. Do not edit by hand.",
        "",
        f"export const PUBLIC_API_CONTRACT_SHA256 = {json.dumps(manifest['contract_sha256'])} as const",
        "",
        "export const PUBLIC_API_OPERATIONS = {",
    ]
    for method, path, operation_id, _request, _response in operation_schemas:
        lines.append(
            f"  {json.dumps(operation_id)}: {{ method: {json.dumps(method)}, path: {json.dumps(path)}, "
            f"surface: {json.dumps(public_v2_surface(path))} }},"
        )
    lines.extend(["} as const", ""])

    for name in sorted(needed):
        schema = components.get(name) or {}
        lines.append(
            f"export type {_identifier(name)} = {_render_schema(schema, root=schema)}"
        )
        lines.append("")

    request_map: list[str] = []
    response_map: list[str] = []
    for _method, _path, operation_id, request_schema, response_schema in operation_schemas:
        request_name = _operation_type_name(operation_id, "Request")
        response_name = _operation_type_name(operation_id, "Response")
        lines.append(
            f"export type {request_name} = "
            + ("never" if request_schema is None else _render_schema(request_schema, root=request_schema))
        )
        lines.append(
            f"export type {response_name} = "
            + ("unknown" if response_schema is None else _render_schema(response_schema, root=response_schema))
        )
        lines.append("")
        request_map.append(f"  {json.dumps(operation_id)}: {request_name}")
        response_map.append(f"  {json.dumps(operation_id)}: {response_name}")

    lines.extend([
        "export interface PublicApiRequestByOperation {",
        *request_map,
        "}",
        "",
        "export interface PublicApiResponseByOperation {",
        *response_map,
        "}",
        "",
        "export type PublicApiOperationId = keyof typeof PUBLIC_API_OPERATIONS",
        "",
    ])
    return "\n".join(lines)


def _write_or_check(path: Path, expected: str, *, check: bool) -> bool:
    current = path.read_text(encoding="utf-8") if path.exists() else None
    if current == expected:
        return True
    if check:
        print(f"out of date: {path.relative_to(ROOT)}", file=sys.stderr)
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(expected, encoding="utf-8")
    print(f"updated {path.relative_to(ROOT)}")
    return True


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    openapi = api_module.app.openapi()
    manifest = build_manifest(openapi)
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    types_text = render_types(openapi, manifest)
    results = (
        _write_or_check(MANIFEST_OUTPUT, manifest_text, check=args.check),
        _write_or_check(TYPES_OUTPUT, types_text, check=args.check),
    )
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
