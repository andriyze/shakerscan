"""Ingest an application's own OpenAPI/Swagger description into discovered routes.

A crawler only sees the endpoints an application happens to call while it is being browsed.
An API description declares the whole surface, including body-bearing routes a black-box crawl
never exercises, so ingesting it is the difference between testing the parameters the client
sent and testing the parameters the API accepts.

This module is pure parsing and normalization: it turns spec bytes into value-free
``discovered_route`` records. The bounded, pinned fetching lives in the dispatcher, which owns
target binding and budget. Nothing here performs I/O.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence
import urllib.parse


# The bounded set of conventional locations an OpenAPI/Swagger document is served from. Probing a
# fixed list keeps the capability's cost predictable; a target that publishes its spec elsewhere is
# still fully covered by the crawl producers.
SPEC_DISCOVERY_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api-docs.json",
    "/swagger/v1/swagger.json",
    "/openapi.yaml",
    "/swagger.yaml",
)

_HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "options", "head"})
_MAX_REF_DEPTH = 12
_MAX_ENDPOINTS = 1_000
_MAX_FIELDS_PER_BODY = 128
_BODY_CONTENT_TYPES = (
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
)


def parse_spec_document(body: bytes, *, content_type: str | None = None) -> dict[str, Any] | None:
    """Decode one spec body as JSON, then YAML, returning None when it is neither.

    The content type is only a hint: servers mislabel specs routinely, so the decode is attempted
    both ways regardless. YAML is parsed with the safe loader, which never constructs arbitrary
    objects from untrusted document content.
    """
    if not body:
        return None
    text = body.decode("utf-8", "replace")
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML ships in the runtime image
        return None
    try:
        parsed = yaml.safe_load(text)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def is_openapi_document(spec: Any) -> bool:
    """True when the object is an OpenAPI 3.x or Swagger 2.0 document with paths."""
    if not isinstance(spec, dict):
        return False
    is_openapi = str(spec.get("openapi") or "").startswith("3.")
    is_swagger = str(spec.get("swagger") or "").startswith("2.")
    return (is_openapi or is_swagger) and isinstance(spec.get("paths"), dict)


def _resolve_ref(spec: Mapping[str, Any], ref: str) -> Mapping[str, Any]:
    if not isinstance(ref, str):
        return {}
    if ref.startswith("#/components/schemas/"):
        name = ref.rsplit("/", 1)[-1]
        node = spec.get("components", {})
        node = node.get("schemas", {}) if isinstance(node, Mapping) else {}
        value = node.get(name) if isinstance(node, Mapping) else None
        return value if isinstance(value, Mapping) else {}
    if ref.startswith("#/definitions/"):
        name = ref.rsplit("/", 1)[-1]
        node = spec.get("definitions", {})
        value = node.get(name) if isinstance(node, Mapping) else None
        return value if isinstance(value, Mapping) else {}
    return {}


def _schema_field_names(
    schema: Any, spec: Mapping[str, Any], *, seen: set[str], depth: int,
) -> list[str]:
    """Collect the top-level property names a request-body schema declares.

    Only field NAMES are ever returned; a spec's example values never enter a manifest. ``$ref`` is
    resolved within the document with a visited-set so a recursive schema terminates, and the
    combiners (allOf/anyOf/oneOf) are flattened so a composed body still surfaces its fields.
    """
    if depth > _MAX_REF_DEPTH or not isinstance(schema, Mapping):
        return []
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in seen:
            return []
        seen.add(ref)
        return _schema_field_names(
            _resolve_ref(spec, ref), spec, seen=seen, depth=depth + 1,
        )
    names: list[str] = []
    for combiner in ("allOf", "anyOf", "oneOf"):
        entries = schema.get(combiner)
        if isinstance(entries, (list, tuple)):
            for entry in entries:
                for name in _schema_field_names(entry, spec, seen=seen, depth=depth + 1):
                    if name not in names:
                        names.append(name)
    properties = schema.get("properties")
    if isinstance(properties, Mapping):
        for name in properties:
            text = str(name)[:200]
            if text and text not in names:
                names.append(text)
    return names


def _operation_body(operation: Mapping[str, Any], spec: Mapping[str, Any]) -> tuple[str | None, list[str]]:
    """Return the (content_type, field_names) of an operation's request body, if any."""
    request_body = operation.get("requestBody")
    if isinstance(request_body, Mapping):
        content = request_body.get("content")
        if isinstance(content, Mapping):
            for content_type in _BODY_CONTENT_TYPES:
                media = content.get(content_type)
                if isinstance(media, Mapping):
                    fields = _schema_field_names(
                        media.get("schema"), spec, seen=set(), depth=0,
                    )
                    return content_type, fields[:_MAX_FIELDS_PER_BODY]
        # A declared body whose media type we do not model still marks the route as body-bearing.
        for content_type, media in content.items() if isinstance(content, Mapping) else ():
            if isinstance(media, Mapping):
                fields = _schema_field_names(media.get("schema"), spec, seen=set(), depth=0)
                return str(content_type)[:120], fields[:_MAX_FIELDS_PER_BODY]
    # Swagger 2.0 carries the body as an in:body parameter.
    for parameter in operation.get("parameters") or ():
        if isinstance(parameter, Mapping) and parameter.get("in") == "body":
            fields = _schema_field_names(parameter.get("schema"), spec, seen=set(), depth=0)
            return "application/json", fields[:_MAX_FIELDS_PER_BODY]
    return None, []


def _operation_query_names(operation: Mapping[str, Any]) -> list[str]:
    names: list[str] = []
    for parameter in operation.get("parameters") or ():
        if not isinstance(parameter, Mapping):
            continue
        if parameter.get("in") not in {"query", None}:
            continue
        name = str(parameter.get("name") or "").strip()[:200]
        if name and name not in names:
            names.append(name)
    return names


def _concrete_path(path: str) -> str:
    """Replace ``{template}`` path segments with an addressable value.

    A spec path like ``/rest/products/{id}/reviews`` is not requestable as written. Substituting a
    concrete placeholder makes the endpoint reachable and lets the endpoint normalizer collapse it
    to the same ``{int}`` route a crawler would record, so spec and crawl endpoints dedupe.
    """
    segments = []
    for segment in str(path or "/").split("/"):
        if segment.startswith("{") and segment.endswith("}") and len(segment) > 2:
            segments.append("1")
        else:
            segments.append(segment)
    joined = "/".join(segments)
    if not joined.startswith("/"):
        joined = "/" + joined
    return joined


def spec_endpoints(spec: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Extract every operation as a value-free route descriptor.

    Each descriptor carries the method, the concrete path, the declared query parameter names, and,
    for a body-bearing operation, the content type and body field names. Values, examples and
    descriptions are discarded.
    """
    if not is_openapi_document(spec):
        return []
    endpoints: list[dict[str, Any]] = []
    paths = spec.get("paths")
    if not isinstance(paths, Mapping):
        return []
    for raw_path, operations in paths.items():
        if not isinstance(operations, Mapping):
            continue
        path = str(raw_path or "")
        if not path.startswith("/"):
            continue
        shared_parameters = operations.get("parameters")
        for method, operation in operations.items():
            if str(method).lower() not in _HTTP_METHODS or not isinstance(operation, Mapping):
                continue
            merged = dict(operation)
            if isinstance(shared_parameters, (list, tuple)):
                own = list(merged.get("parameters") or ())
                merged["parameters"] = [*shared_parameters, *own]
            content_type, body_fields = _operation_body(merged, spec)
            endpoints.append({
                "method": str(method).upper(),
                "path": _concrete_path(path),
                "query_parameter_names": _operation_query_names(merged),
                "content_type": content_type,
                "body_field_names": body_fields,
            })
            if len(endpoints) >= _MAX_ENDPOINTS:
                return endpoints
    return endpoints


def discovered_route_records(
    spec: Mapping[str, Any], *, origin: str,
) -> list[dict[str, Any]]:
    """Render spec operations as ``discovered_route`` observations under one origin.

    The URL is built from the frozen target origin plus the spec's own path, never from a server
    field inside the document, so a spec that names a different host cannot redirect the scan off
    its bound target.
    """
    base = str(origin or "").rstrip("/")
    records: list[dict[str, Any]] = []
    for endpoint in spec_endpoints(spec):
        query_names = list(endpoint.get("query_parameter_names") or ())
        query = urllib.parse.urlencode([(name, "1") for name in query_names])
        url = f"{base}{endpoint['path']}"
        if query:
            url = f"{url}?{query}"
        record: dict[str, Any] = {
            "kind": "discovered_route",
            "url": url,
            "method": endpoint["method"],
            "source": "spec",
        }
        body_fields = list(endpoint.get("body_field_names") or ())
        if endpoint.get("content_type") or body_fields:
            record["content_type"] = endpoint.get("content_type")
            record["body_field_names"] = body_fields
        records.append(record)
    return records


def ingest_spec_bodies(
    documents: Sequence[tuple[str, bytes, str | None]], *, origin: str,
) -> list[dict[str, Any]]:
    """Parse fetched (url, body, content_type) tuples into deduped discovered routes.

    Multiple specs (a microservice app publishes several) are aggregated; identical
    method+URL routes across specs collapse to one record, preferring the first that
    declared a body shape so the richer descriptor wins.
    """
    by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for _url, body, content_type in documents:
        spec = parse_spec_document(body, content_type=content_type)
        if spec is None:
            continue
        for record in discovered_route_records(spec, origin=origin):
            identity = (record["method"], record["url"])
            existing = by_identity.get(identity)
            if existing is None or (
                not existing.get("body_field_names") and record.get("body_field_names")
            ):
                by_identity[identity] = record
    return list(by_identity.values())


__all__ = [
    "SPEC_DISCOVERY_PATHS",
    "parse_spec_document",
    "is_openapi_document",
    "spec_endpoints",
    "discovered_route_records",
    "ingest_spec_bodies",
]
