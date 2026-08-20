"""Encrypted request-document formats for connected-device Web/API assessment.

This module extends the original Postman pipeline with HAR 1.2 and
OpenAPI/Swagger inputs.  It deliberately produces the same resolved-request
contract, so destination pinning and state-changing authorization remain in
``device_web`` rather than being reimplemented per format.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from collections import Counter
from typing import Any

from .device_postman import (
    MAX_BODY_BYTES,
    MAX_COLLECTION_BYTES,
    MAX_HEADERS,
    MAX_REQUESTS,
    HARD_MAX_COLLECTION_BYTES,
    HARD_MAX_REQUESTS,
    SAFE_METHODS,
    STATE_CHANGING_METHODS,
    SUPPORTED_METHODS,
    PostmanCollectionError,
    public_request_url,
    resolve_requests as resolve_postman_requests,
    validate_and_summarize as validate_postman,
)


IMPORT_FORMATS = {"auto", "postman_collection", "har", "openapi"}
HTTP_METHODS = {"get", "head", "options", "post", "put", "patch", "delete", "trace"}
_SENSITIVE_NAME_RE = re.compile(
    r"(?:authorization|api[-_]?key|token|secret|password|passwd|cookie|session|credential|private[-_]?key)",
    re.I,
)
_SERVER_VARIABLE_RE = re.compile(r"\{([^{}]+)\}")


class RequestImportError(ValueError):
    """A request document is invalid, unsupported, or exceeds safe bounds."""


def _json_size(value: Any) -> int:
    try:
        return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise RequestImportError("Request import must be valid JSON data") from exc


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _port_hint(url: str) -> int | None:
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.port:
            return int(parsed.port)
        if parsed.scheme == "https":
            return 443
        if parsed.scheme == "http":
            return 80
    except ValueError:
        return None
    return None


def _header_rows(raw: Any) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("key") or "").strip()
        value = str(item.get("value") or "")
        if not name or any(ch in name for ch in "\r\n:") or "\r" in value or "\n" in value:
            continue
        result.append((name[:500], value))
        if len(result) >= MAX_HEADERS:
            break
    return result


def _request_id(prefix: str, index: int, method: str, url: str) -> str:
    return hashlib.sha256(
        json.dumps([prefix, index, method, url], separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()[:24]


def detect_format(document: Any) -> str:
    if not isinstance(document, dict):
        raise RequestImportError("Request import must be one JSON object")
    if isinstance(document.get("log"), dict) and isinstance(document["log"].get("entries"), list):
        return "har"
    if isinstance(document.get("openapi"), str) or isinstance(document.get("swagger"), str):
        return "openapi"
    if isinstance(document.get("item"), list) or isinstance(document.get("info"), dict) and "schema" in document.get("info", {}):
        return "postman_collection"
    raise RequestImportError("Could not detect Postman, HAR 1.2, OpenAPI, or Swagger JSON")


def validate_request_document(
    document: Any,
    environment: Any = None,
    *,
    requested_name: str | None = None,
    import_format: str = "auto",
    base_url: str | None = None,
    max_requests: int = MAX_REQUESTS,
    max_document_bytes: int = MAX_COLLECTION_BYTES,
) -> tuple[dict[str, Any], dict[str, Any]]:
    max_requests = int(max_requests)
    max_document_bytes = int(max_document_bytes)
    if not 1 <= max_requests <= HARD_MAX_REQUESTS:
        raise RequestImportError(f"request limit must be between 1 and {HARD_MAX_REQUESTS}")
    if not 1 <= max_document_bytes <= HARD_MAX_COLLECTION_BYTES:
        raise RequestImportError(
            f"document limit must be between 1 and {HARD_MAX_COLLECTION_BYTES} bytes"
        )
    requested_format = str(import_format or "auto").strip().lower()
    if requested_format not in IMPORT_FORMATS:
        raise RequestImportError("format must be auto, postman_collection, har, or openapi")
    actual = detect_format(document) if requested_format == "auto" else requested_format
    if actual == "postman_collection":
        try:
            return validate_postman(
                document, environment, requested_name=requested_name,
                max_requests=max_requests, max_collection_bytes=max_document_bytes,
            )
        except PostmanCollectionError as exc:
            raise RequestImportError(str(exc)) from exc
    if environment is not None:
        raise RequestImportError("Environment JSON is supported only for Postman collections")
    if actual == "har":
        if base_url:
            raise RequestImportError("base_url is supported only for OpenAPI and Swagger imports")
        return _validate_har(
            document, requested_name=requested_name, max_requests=max_requests,
            max_document_bytes=max_document_bytes,
        )
    return _validate_openapi(
        document, requested_name=requested_name, base_url=base_url,
        max_requests=max_requests, max_document_bytes=max_document_bytes,
    )


def resolve_imported_requests(
    payload: dict[str, Any], *, max_requests: int = MAX_REQUESTS
) -> list[dict[str, Any]]:
    """Resolve a worker-only encrypted payload into the shared replay contract."""
    if not isinstance(payload, dict):
        raise RequestImportError("Encrypted request payload is invalid")
    format_name = str(payload.get("format") or "")
    if not format_name and isinstance(payload.get("collection"), dict):
        return resolve_postman_requests(payload, max_requests=max_requests)  # legacy payloads
    if format_name == "postman_collection":
        return resolve_postman_requests(
            {"collection": payload.get("document"), "environment": payload.get("environment")},
            max_requests=max_requests,
        )
    if format_name == "har":
        return _resolve_har(payload.get("document"), max_requests=max_requests)
    if format_name == "openapi":
        requests, _metadata = _openapi_requests(
            payload.get("document"), base_url=payload.get("base_url"), max_requests=max_requests
        )
        return requests
    raise RequestImportError("Encrypted request payload has an unsupported format")


def _validate_har(
    document: Any, *, requested_name: str | None, max_requests: int = MAX_REQUESTS,
    max_document_bytes: int = MAX_COLLECTION_BYTES,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("log"), dict):
        raise RequestImportError("HAR import must contain one log object")
    if _json_size(document) > max_document_bytes:
        raise RequestImportError(f"HAR import exceeds the {max_document_bytes}-byte limit")
    log = document["log"]
    version = str(log.get("version") or "")
    if version and version != "1.2":
        raise RequestImportError("Only HAR 1.2 is supported")
    entries = log.get("entries")
    if not isinstance(entries, list) or not entries:
        raise RequestImportError("HAR import contains no request entries")
    if len(entries) > max_requests:
        raise RequestImportError(f"HAR import exceeds the {max_requests}-request limit")
    resolved = _resolve_har(document, max_requests=max_requests)
    if not resolved:
        raise RequestImportError("HAR import contains no valid requests")
    creator = log.get("creator") if isinstance(log.get("creator"), dict) else {}
    name = str(requested_name or creator.get("name") and f"{creator.get('name')} HAR" or "Imported HAR traffic").strip()[:160]
    payload = {"format": "har", "document": document}
    summary = _summary(
        name=name,
        format_name="har",
        requests=resolved,
        digest=_digest(payload),
        extra={
            "har_version": version or "1.2",
            "captured_response_bodies_ignored": True,
            "scripts_ignored": 0,
            "environment_variable_names": [],
            "collection_variable_names": [],
        },
    )
    return payload, summary


def _resolve_har(document: Any, *, max_requests: int = MAX_REQUESTS) -> list[dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("log"), dict):
        raise RequestImportError("Encrypted HAR payload is invalid")
    entries = document["log"].get("entries")
    if not isinstance(entries, list):
        raise RequestImportError("Encrypted HAR entries are invalid")
    result: list[dict[str, Any]] = []
    for index, entry in enumerate(entries[:max_requests]):
        request = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(request, dict):
            continue
        method = str(request.get("method") or "GET").strip().upper()
        url = str(request.get("url") or "").strip()
        headers = dict(_header_rows(request.get("headers")))
        cookies = []
        for cookie in request.get("cookies") or []:
            if isinstance(cookie, dict) and cookie.get("name"):
                cookies.append(f"{cookie['name']}={cookie.get('value', '')}")
        if cookies and not any(key.lower() == "cookie" for key in headers):
            headers["Cookie"] = "; ".join(cookies)
        post_data = request.get("postData") if isinstance(request.get("postData"), dict) else {}
        body = b""
        body_error = None
        if isinstance(post_data.get("text"), str):
            body = post_data["text"].encode("utf-8")
        elif isinstance(post_data.get("params"), list):
            pairs = [
                (str(item.get("name")), str(item.get("value") or ""))
                for item in post_data["params"] if isinstance(item, dict) and item.get("name")
            ]
            body = urllib.parse.urlencode(pairs).encode()
        mime_type = str(post_data.get("mimeType") or "").strip()
        if body and mime_type and not any(key.lower() == "content-type" for key in headers):
            headers["Content-Type"] = mime_type
        if len(body) > MAX_BODY_BYTES:
            body, body_error = b"", "request_body_exceeds_512_kib"
        has_sensitive = bool(cookies) or any(_SENSITIVE_NAME_RE.search(key) for key in headers)
        result.append({
            "id": _request_id("har", index, method, url),
            "name": str(entry.get("pageref") or f"Captured request {index + 1}")[:300],
            "folder": "HAR capture",
            "method": method,
            "url": url,
            "url_template": url,
            "headers": headers,
            "sensitive_header_names": sorted(key.lower() for key in headers if _SENSITIVE_NAME_RE.search(key)),
            "body": body,
            "body_mode": mime_type or ("raw" if body else "none"),
            "auth_type": "captured" if has_sensitive else "none",
            "has_sensitive_material": has_sensitive,
            "unresolved_variables": [],
            "error": body_error,
        })
    return result


class _LocalRefResolver:
    def __init__(self, document: dict[str, Any]):
        self.document = document
        self.external_refs_ignored = 0
        self.invalid_refs_ignored = 0

    def resolve(self, value: Any, *, depth: int = 0) -> Any:
        if depth > 12 or not isinstance(value, dict) or "$ref" not in value:
            return value
        ref = str(value.get("$ref") or "")
        if not ref.startswith("#/"):
            self.external_refs_ignored += 1
            return {}
        current: Any = self.document
        try:
            for part in ref[2:].split("/"):
                key = part.replace("~1", "/").replace("~0", "~")
                current = current[key]
        except (KeyError, TypeError):
            self.invalid_refs_ignored += 1
            return {}
        return self.resolve(current, depth=depth + 1)


def _example(schema: Any, resolver: _LocalRefResolver, *, depth: int = 0) -> Any:
    if depth > 8:
        return None
    schema = resolver.resolve(schema, depth=depth)
    if not isinstance(schema, dict):
        return None
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    for key in ("oneOf", "anyOf", "allOf"):
        variants = schema.get(key)
        if isinstance(variants, list) and variants:
            if key == "allOf":
                merged: dict[str, Any] = {}
                for item in variants:
                    value = _example(item, resolver, depth=depth + 1)
                    if isinstance(value, dict):
                        merged.update(value)
                return merged
            return _example(variants[0], resolver, depth=depth + 1)
    kind = str(schema.get("type") or ("object" if schema.get("properties") else "string"))
    if kind == "object":
        return {
            str(name): _example(child, resolver, depth=depth + 1)
            for name, child in list((schema.get("properties") or {}).items())[:50]
        }
    if kind == "array":
        return [_example(schema.get("items") or {}, resolver, depth=depth + 1)]
    if kind == "integer":
        return int(schema.get("minimum") or 1)
    if kind == "number":
        return float(schema.get("minimum") or 1)
    if kind == "boolean":
        return True
    fmt = str(schema.get("format") or "")
    return {"uuid": "00000000-0000-4000-8000-000000000001", "date": "2026-01-01", "date-time": "2026-01-01T00:00:00Z"}.get(fmt, "sample")


def _parameter_value(parameter: dict[str, Any], resolver: _LocalRefResolver) -> Any:
    if "example" in parameter:
        return parameter["example"]
    examples = parameter.get("examples")
    if isinstance(examples, dict) and examples:
        first = resolver.resolve(next(iter(examples.values())))
        if isinstance(first, dict) and "value" in first:
            return first["value"]
    schema = parameter.get("schema") if isinstance(parameter.get("schema"), dict) else parameter
    return _example(schema, resolver)


def _server_url(server: Any) -> tuple[str, list[str]]:
    if not isinstance(server, dict):
        return "", []
    url = str(server.get("url") or "").strip()
    variables = server.get("variables") if isinstance(server.get("variables"), dict) else {}
    unresolved: list[str] = []

    def replace(match: re.Match[str]) -> str:
        item = variables.get(match.group(1)) if isinstance(variables, dict) else None
        if isinstance(item, dict) and item.get("default") is not None:
            return str(item["default"])
        unresolved.append(match.group(1))
        return match.group(0)

    return _SERVER_VARIABLE_RE.sub(replace, url), unresolved


def _swagger_server(document: dict[str, Any]) -> str:
    host = str(document.get("host") or "").strip()
    if not host:
        return ""
    schemes = document.get("schemes") if isinstance(document.get("schemes"), list) else []
    scheme = str(schemes[0] if schemes else "http")
    base_path = "/" + str(document.get("basePath") or "").strip("/") if document.get("basePath") else ""
    return f"{scheme}://{host}{base_path}"


def _security_type(document: dict[str, Any], operation: dict[str, Any]) -> str:
    security = operation.get("security", document.get("security"))
    if security == []:
        return "none"
    if not isinstance(security, list) or not security:
        return "none"
    names = sorted({str(name) for requirement in security if isinstance(requirement, dict) for name in requirement})
    return "declared:" + ",".join(names[:10]) if names else "declared"


def _openapi_body(
    document: dict[str, Any], operation: dict[str, Any], parameters: list[dict[str, Any]], resolver: _LocalRefResolver,
) -> tuple[bytes, str, str | None]:
    request_body = resolver.resolve(operation.get("requestBody"))
    if isinstance(request_body, dict):
        content = request_body.get("content") if isinstance(request_body.get("content"), dict) else {}
        for mime in ("application/json", "application/x-www-form-urlencoded", "text/plain"):
            media = resolver.resolve(content.get(mime))
            if not isinstance(media, dict):
                continue
            value = media.get("example")
            if value is None and isinstance(media.get("examples"), dict) and media["examples"]:
                first = resolver.resolve(next(iter(media["examples"].values())))
                value = first.get("value") if isinstance(first, dict) else first
            if value is None:
                value = _example(media.get("schema") or {}, resolver)
            if mime == "application/json":
                body = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
            elif mime == "application/x-www-form-urlencoded" and isinstance(value, dict):
                body = urllib.parse.urlencode(value, doseq=True).encode()
            else:
                body = str(value if value is not None else "").encode()
            return (b"", mime, "request_body_exceeds_512_kib") if len(body) > MAX_BODY_BYTES else (body, mime, None)
    body_parameter = next((item for item in parameters if str(item.get("in")) == "body"), None)
    if body_parameter:
        value = body_parameter.get("x-example", body_parameter.get("example"))
        if value is None:
            value = _example(body_parameter.get("schema") or {}, resolver)
        body = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
        consumes = operation.get("consumes") or document.get("consumes") or ["application/json"]
        mime = str(consumes[0]) if isinstance(consumes, list) and consumes else "application/json"
        return (b"", mime, "request_body_exceeds_512_kib") if len(body) > MAX_BODY_BYTES else (body, mime, None)
    form = [(str(item.get("name")), _parameter_value(item, resolver)) for item in parameters if str(item.get("in")) == "formData" and item.get("name")]
    if form:
        body = urllib.parse.urlencode(form, doseq=True).encode()
        return body, "application/x-www-form-urlencoded", None
    return b"", "", None


def _openapi_requests(
    document: Any, *, base_url: Any = None, max_requests: int = MAX_REQUESTS
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(document, dict):
        raise RequestImportError("Encrypted OpenAPI payload is invalid")
    is_swagger = str(document.get("swagger") or "").startswith("2.")
    is_openapi = str(document.get("openapi") or "").startswith("3.")
    if not is_swagger and not is_openapi:
        raise RequestImportError("OpenAPI import must be OpenAPI 3.x or Swagger 2.0")
    paths = document.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise RequestImportError("OpenAPI import contains no paths")
    override = str(base_url or "").strip().rstrip("/")
    if override:
        parsed_override = urllib.parse.urlsplit(override)
        if parsed_override.scheme not in {"http", "https"} or not parsed_override.hostname or parsed_override.query or parsed_override.fragment:
            raise RequestImportError("base_url must be one absolute HTTP(S) URL without a query or fragment")
    resolver = _LocalRefResolver(document)
    root_server, root_unresolved = ("", [])
    if is_openapi and isinstance(document.get("servers"), list) and document["servers"]:
        root_server, root_unresolved = _server_url(document["servers"][0])
    elif is_swagger:
        root_server = _swagger_server(document)
    requests: list[dict[str, Any]] = []
    for path_name, raw_path_item in paths.items():
        path_item = resolver.resolve(raw_path_item)
        if not isinstance(path_item, dict):
            continue
        for method_name, raw_operation in path_item.items():
            method_lower = str(method_name).lower()
            if method_lower not in HTTP_METHODS:
                continue
            operation = resolver.resolve(raw_operation)
            if not isinstance(operation, dict):
                continue
            if len(requests) >= max_requests:
                raise RequestImportError(f"OpenAPI import exceeds the {max_requests}-operation limit")
            server, unresolved = root_server, list(root_unresolved)
            if is_openapi and isinstance(path_item.get("servers"), list) and path_item["servers"]:
                server, unresolved = _server_url(path_item["servers"][0])
            if is_openapi and isinstance(operation.get("servers"), list) and operation["servers"]:
                server, unresolved = _server_url(operation["servers"][0])
            if override:
                server, unresolved = override, []
            parameters: list[dict[str, Any]] = []
            keyed: dict[tuple[str, str], dict[str, Any]] = {}
            for raw_parameter in list(path_item.get("parameters") or []) + list(operation.get("parameters") or []):
                parameter = resolver.resolve(raw_parameter)
                if isinstance(parameter, dict):
                    keyed[(str(parameter.get("name") or ""), str(parameter.get("in") or ""))] = parameter
            parameters = list(keyed.values())
            rendered_path = str(path_name)
            query: list[tuple[str, str]] = []
            headers: dict[str, str] = {}
            for parameter in parameters:
                name = str(parameter.get("name") or "")
                location = str(parameter.get("in") or "")
                if not name:
                    continue
                value = _parameter_value(parameter, resolver)
                value_text = str(value if value is not None else "sample")
                if location == "path":
                    rendered_path = rendered_path.replace("{" + name + "}", urllib.parse.quote(value_text, safe=""))
                elif location == "query":
                    query.append((name, value_text))
                elif location == "header" and not any(ch in name for ch in "\r\n:") and "\r" not in value_text and "\n" not in value_text:
                    headers[name] = value_text
            url = (server.rstrip("/") + "/" + rendered_path.lstrip("/")) if server else "/" + rendered_path.lstrip("/")
            if query:
                url += ("&" if "?" in url else "?") + urllib.parse.urlencode(query)
            body, content_type, body_error = _openapi_body(document, operation, parameters, resolver)
            if body and content_type:
                headers.setdefault("Content-Type", content_type)
            method = method_lower.upper()
            auth_type = _security_type(document, operation)
            unresolved += re.findall(r"\{([^{}]+)\}", rendered_path)
            requests.append({
                "id": _request_id("openapi", len(requests), method, f"{path_name}:{operation.get('operationId', '')}"),
                "name": str(operation.get("summary") or operation.get("operationId") or f"{method} {path_name}")[:300],
                "folder": "OpenAPI" if is_openapi else "Swagger",
                "method": method,
                "url": url,
                "url_template": str(path_name),
                "headers": headers,
                "sensitive_header_names": sorted(key.lower() for key in headers if _SENSITIVE_NAME_RE.search(key)),
                "body": body,
                "body_mode": content_type or "none",
                "auth_type": auth_type,
                "has_sensitive_material": any(_SENSITIVE_NAME_RE.search(key) for key in headers),
                "unresolved_variables": sorted(set(unresolved)),
                "error": body_error,
            })
    return requests, {
        "spec_version": str(document.get("openapi") or document.get("swagger") or ""),
        "external_refs_ignored": resolver.external_refs_ignored,
        "invalid_refs_ignored": resolver.invalid_refs_ignored,
    }


def _validate_openapi(
    document: Any, *, requested_name: str | None, base_url: str | None,
    max_requests: int = MAX_REQUESTS, max_document_bytes: int = MAX_COLLECTION_BYTES,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(document, dict):
        raise RequestImportError("OpenAPI import must be one JSON object")
    if _json_size(document) > max_document_bytes:
        raise RequestImportError(f"OpenAPI import exceeds the {max_document_bytes}-byte limit")
    requests, metadata = _openapi_requests(
        document, base_url=base_url, max_requests=max_requests
    )
    if not requests:
        raise RequestImportError("OpenAPI import contains no supported operations")
    info = document.get("info") if isinstance(document.get("info"), dict) else {}
    name = str(requested_name or info.get("title") or "Imported OpenAPI specification").strip()[:160]
    payload = {"format": "openapi", "document": document, "base_url": str(base_url or "").strip() or None}
    summary = _summary(
        name=name,
        format_name="openapi",
        requests=requests,
        digest=_digest(payload),
        extra={
            **metadata,
            "scripts_ignored": 0,
            "environment_variable_names": [],
            "collection_variable_names": [],
            "generated_examples": True,
        },
    )
    return payload, summary


def _summary(
    *, name: str, format_name: str, requests: list[dict[str, Any]], digest: str, extra: dict[str, Any],
) -> dict[str, Any]:
    methods = Counter(str(item.get("method") or "") for item in requests)
    port_hints = sorted({port for item in requests if (port := _port_hint(str(item.get("url") or ""))) is not None})
    public_requests = []
    for item in requests:
        method = str(item.get("method") or "")
        public_requests.append({
            "id": item.get("id"),
            "name": item.get("name"),
            "folder": item.get("folder"),
            "method": method,
            "url": public_request_url(str(item.get("url") or "")),
            "header_names": sorted(str(key)[:120] for key in (item.get("headers") or {}))[:MAX_HEADERS],
            "body_mode": str(item.get("body_mode") or "none")[:100],
            "auth_type": str(item.get("auth_type") or "none")[:200],
            "safe_method": method in SAFE_METHODS,
            "supported": method in SUPPORTED_METHODS and bool(item.get("url")) and not item.get("error") and not item.get("unresolved_variables"),
        })
    return {
        "schema_version": "device-request-collection/v1",
        "name": name,
        "format": format_name,
        "document_sha256": digest,
        "request_count": len(requests),
        "safe_request_count": sum(1 for item in public_requests if item["safe_method"]),
        "state_changing_request_count": sum(1 for item in public_requests if item["method"] in STATE_CHANGING_METHODS),
        "unsupported_request_count": sum(1 for item in public_requests if not item["supported"]),
        "methods": dict(sorted(methods.items())),
        "port_hints": port_hints,
        "requests": public_requests,
        "secrets_redacted": True,
        **extra,
    }
