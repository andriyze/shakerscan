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
import re
from typing import Any, Mapping, Sequence
import urllib.parse


# The bounded set of conventional locations an OpenAPI/Swagger document is served from. Probing a
# fixed list keeps the capability's cost predictable. Specs published elsewhere may be
# discovered by crawling, but their ingestion is not guaranteed by this capability.
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


def _issue(issues: list[str] | None, reason: str) -> None:
    # Metadata only: never echo spec values, external URLs, or secrets in diagnostics.
    if issues is not None and reason not in issues and len(issues) < 20:
        issues.append(reason)


def _resolve_ref(spec: Mapping[str, Any], ref: str) -> Mapping[str, Any]:
    """Resolve a bounded same-document JSON Pointer; never fetch an external reference."""
    if not isinstance(ref, str) or not ref.startswith("#/") or len(ref) > 2_048:
        return {}
    parts = urllib.parse.unquote(ref[2:]).split("/")
    if len(parts) > 32:
        return {}
    node: Any = spec
    for part in parts:
        if re.search(r"~(?![01])", part):
            return {}
        key = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, Mapping) or key not in node:
            return {}
        node = node[key]
    return node if isinstance(node, Mapping) else {}


def _object(value: Any, spec: Mapping[str, Any], issues: list[str] | None = None) -> Mapping[str, Any]:
    seen: set[str] = set()
    for _ in range(_MAX_REF_DEPTH + 1):
        if not isinstance(value, Mapping):
            _issue(issues, "spec_invalid_object")
            return {}
        if "$ref" not in value:
            return value
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            _issue(issues, "spec_external_or_invalid_reference")
            return {}
        if ref in seen:
            _issue(issues, "spec_reference_cycle")
            return {}
        seen.add(ref)
        value = _resolve_ref(spec, ref)
        if not value:
            _issue(issues, "spec_unresolved_reference")
            return {}
    _issue(issues, "spec_reference_depth_limit")
    return {}


def _parameters(value: Any, spec: Mapping[str, Any], issues: list[str] | None) -> list[Mapping[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        _issue(issues, "spec_invalid_parameters")
        return []
    if len(value) > 256:
        _issue(issues, "spec_parameter_limit")
    return [_object(item, spec, issues) for item in value[:256]]


def _origin_key(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        return (parsed.scheme.lower(), parsed.hostname.lower().rstrip("."),
                parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
    except ValueError:
        return None


def _safe_path(path: str) -> bool:
    decoded = path
    for _ in range(3):
        decoded = urllib.parse.unquote(decoded)
    return (path.startswith("/") and not path.startswith("//")
            and not any(c in decoded for c in "\\\r\n\x00?#")
            and not any(part in {".", ".."} for part in decoded.split("/")))


def _server_bases(
    spec: Mapping[str, Any], path_item: Mapping[str, Any], operation: Mapping[str, Any],
    *, origin: str, document_url: str | None, issues: list[str] | None,
) -> list[str]:
    """Preserve authorized server paths, including override precedence and relative URLs."""
    source = document_url or origin.rstrip("/") + "/"
    # A caller without a fetch URL can resolve root-relative servers, but never use
    # an untrusted/off-origin document URL as authority for relative servers.
    if _origin_key(source) != _origin_key(origin):
        source = origin.rstrip("/") + "/"
    if str(spec.get("swagger", "")).startswith("2."):
        host = spec.get("host")
        schemes = spec.get("schemes")
        if schemes and (not isinstance(schemes, list) or urllib.parse.urlsplit(origin).scheme not in schemes):
            _issue(issues, "spec_off_origin_server")
            return []
        base_path = str(spec.get("basePath") or "/")
        if not _safe_path(base_path):
            _issue(issues, "spec_invalid_server_path")
            return []
        scheme = urllib.parse.urlsplit(origin).scheme
        raw_servers = [{"url": f"{scheme}://{host}{base_path}" if host else base_path}]
    else:
        owner = next((item for item in (operation, path_item, spec) if "servers" in item), {})
        raw_servers = owner.get("servers", [])
        if not isinstance(raw_servers, list):
            _issue(issues, "spec_invalid_servers")
            return []
        raw_servers = raw_servers or [{"url": "/"}]
    if len(raw_servers) > 16:
        _issue(issues, "spec_server_limit")
    bases: list[str] = []
    for server in raw_servers[:16]:
        if not isinstance(server, Mapping) or not isinstance(server.get("url"), str):
            _issue(issues, "spec_invalid_server")
            continue
        url = server["url"]
        variables = server.get("variables") or {}
        for name in re.findall(r"\{([^{}]+)\}", url):
            variable = variables.get(name) if isinstance(variables, Mapping) else None
            default = variable.get("default") if isinstance(variable, Mapping) else None
            if not isinstance(default, str) or len(default) > 200:
                break
            url = url.replace("{" + name + "}", default)
        if ("{" in url or "}" in url or len(url) > 2_048
                or any(ord(c) < 32 for c in url) or "\\" in url):
            _issue(issues, "spec_invalid_server")
            continue
        # Relative Server URLs are relative to the specification document, not the target root.
        resolved = urllib.parse.urljoin(source, url)
        if _origin_key(resolved) != _origin_key(origin) or _origin_key(origin) is None:
            _issue(issues, "spec_off_origin_server")
            continue
        parsed = urllib.parse.urlsplit(resolved)
        if parsed.query or parsed.fragment or not _safe_path(parsed.path or "/"):
            _issue(issues, "spec_invalid_server_path")
            continue
        base = origin.rstrip("/") + (parsed.path or "/").rstrip("/")
        if base not in bases:
            bases.append(base)
    return bases


def _schema_field_names(
    schema: Any, spec: Mapping[str, Any], *, seen: set[str], depth: int,
    issues: list[str] | None = None,
) -> list[str]:
    """Collect the top-level property names a request-body schema declares.

    Only field NAMES are ever returned; a spec's example values never enter a manifest. ``$ref`` is
    resolved within the document with a visited-set so a recursive schema terminates, and the
    combiners (allOf/anyOf/oneOf) are flattened so a composed body still surfaces its fields.
    """
    if depth > _MAX_REF_DEPTH or not isinstance(schema, Mapping):
        _issue(issues, "spec_schema_limit_or_invalid")
        return []
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in seen:
            _issue(issues, "spec_reference_cycle")
            return []
        seen.add(ref)
        return _schema_field_names(
            _object(schema, spec, issues), spec, seen=seen, depth=depth + 1, issues=issues,
        )
    names: list[str] = []
    for combiner in ("allOf", "anyOf", "oneOf"):
        entries = schema.get(combiner)
        if isinstance(entries, (list, tuple)):
            for entry in entries:
                for name in _schema_field_names(entry, spec, seen=seen, depth=depth + 1, issues=issues):
                    if name not in names:
                        names.append(name)
    properties = schema.get("properties")
    if isinstance(properties, Mapping):
        for name in properties:
            text = str(name)[:200]
            if text and text not in names:
                names.append(text)
    return names


def _operation_body(operation: Mapping[str, Any], spec: Mapping[str, Any], issues: list[str] | None = None) -> tuple[str | None, list[str]]:
    """Return the (content_type, field_names) of an operation's request body, if any."""
    request_body = (_object(operation["requestBody"], spec, issues)
                    if "requestBody" in operation else None)
    if isinstance(request_body, Mapping):
        content = request_body.get("content")
        if isinstance(content, Mapping):
            for content_type in _BODY_CONTENT_TYPES:
                media = content.get(content_type)
                if isinstance(media, Mapping):
                    fields = _schema_field_names(
                        media.get("schema"), spec, seen=set(), depth=0, issues=issues,
                    )
                    return content_type, fields[:_MAX_FIELDS_PER_BODY]
        # A declared body whose media type we do not model still marks the route as body-bearing.
        for content_type, media in content.items() if isinstance(content, Mapping) else ():
            if isinstance(media, Mapping):
                fields = _schema_field_names(media.get("schema"), spec, seen=set(), depth=0, issues=issues)
                _issue(issues, "spec_unsupported_body_media_type")
                return str(content_type)[:120], fields[:_MAX_FIELDS_PER_BODY]
    # Swagger 2.0 carries the body as an in:body parameter.
    for parameter in operation.get("parameters") or ():
        if isinstance(parameter, Mapping) and parameter.get("in") == "body":
            fields = _schema_field_names(parameter.get("schema"), spec, seen=set(), depth=0, issues=issues)
            consumes = operation.get("consumes", spec.get("consumes")) or ["application/json"]
            media_type = consumes[0] if isinstance(consumes, list) and consumes else "application/json"
            if media_type not in _BODY_CONTENT_TYPES:
                _issue(issues, "spec_unsupported_body_media_type")
            return str(media_type)[:120], fields[:_MAX_FIELDS_PER_BODY]
    form = [p for p in operation.get("parameters") or ()
            if isinstance(p, Mapping) and p.get("in") == "formData"]
    if form:
        consumes = operation.get("consumes", spec.get("consumes")) or []
        supported = [c for c in consumes if c in _BODY_CONTENT_TYPES[1:]] if isinstance(consumes, list) else []
        if not supported:
            _issue(issues, "spec_unsupported_form_media_type")
            return None, []
        if any(p.get("type") == "file" for p in form):
            _issue(issues, "spec_file_upload_not_modeled")
        fields = list(dict.fromkeys(str(p["name"])[:200] for p in form
                                   if p.get("name") and p.get("type") != "file"))
        return supported[0], fields[:_MAX_FIELDS_PER_BODY]
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


def spec_endpoints(
    spec: Mapping[str, Any], *, origin: str | None = None,
    document_url: str | None = None, issues: list[str] | None = None,
) -> list[dict[str, Any]]:
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
        operations = _object(operations, spec, issues)
        path = str(raw_path or "")
        if not _safe_path(path):
            _issue(issues, "spec_invalid_operation_path")
            continue
        shared_parameters = _parameters(operations.get("parameters"), spec, issues)
        for method, operation in operations.items():
            if str(method).lower() not in _HTTP_METHODS or not isinstance(operation, Mapping):
                continue
            merged = dict(operation)
            own = _parameters(merged.get("parameters"), spec, issues)
            # Operation parameters override the same (name, location) on the Path Item.
            parameters = {(p.get("name", "__body__"), p.get("in")): p
                          for p in (*shared_parameters, *own)
                          if isinstance(p.get("name", "__body__"), str)
                          and isinstance(p.get("in"), str)}
            merged["parameters"] = list(parameters.values())
            content_type, body_fields = _operation_body(merged, spec, issues)
            bases = (_server_bases(spec, operations, operation, origin=origin,
                                   document_url=document_url, issues=issues)
                     if origin is not None else [None])
            for base in bases:
                endpoints.append({
                    "method": str(method).upper(),
                    "path": _concrete_path(path),
                    "query_parameter_names": _operation_query_names(merged),
                    "content_type": content_type,
                    "body_field_names": body_fields,
                    **({"base_url": base} if base is not None else {}),
                })
                if len(endpoints) >= _MAX_ENDPOINTS:
                    _issue(issues, "spec_endpoint_limit")
                    return endpoints
    return endpoints


def discovered_route_records(
    spec: Mapping[str, Any], *, origin: str, document_url: str | None = None,
    issues: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Render spec operations as ``discovered_route`` observations under one origin.

    Server paths are preserved, but only for the frozen target origin. Off-origin servers
    are reported as unsupported, never silently remapped or fetched.
    """
    base = str(origin or "").rstrip("/")
    records: list[dict[str, Any]] = []
    for endpoint in spec_endpoints(spec, origin=origin, document_url=document_url, issues=issues):
        query_names = list(endpoint.get("query_parameter_names") or ())
        query = urllib.parse.urlencode([(name, "1") for name in query_names])
        url = f"{endpoint.get('base_url', base)}{endpoint['path']}"
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
    issues: list[str] | None = None,
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
        for record in discovered_route_records(spec, origin=origin, document_url=_url, issues=issues):
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
