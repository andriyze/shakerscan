"""Postman collection parsing and device-scoped request resolution.

Collections may contain credentials, tokens, cookies, and request bodies.  The
API stores the original documents encrypted and exposes only the redacted
summary produced here.  Workers resolve variables in memory and never accept a
network destination from the collection: callers must bind each request to a
previously discovered device web origin.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
from collections import Counter
from typing import Any, Iterator


MAX_COLLECTION_BYTES = 5 * 1024 * 1024
MAX_ENVIRONMENT_BYTES = 2 * 1024 * 1024
MAX_REQUESTS = 500
MAX_HEADERS = 100
MAX_BODY_BYTES = 512 * 1024
MAX_EXPANDED_VALUE_CHARS = MAX_BODY_BYTES
MAX_VARIABLE_MAP_CHARS = 8 * 1024 * 1024
MAX_URL_CHARS = 64 * 1024
MAX_HEADER_VALUE_CHARS = 64 * 1024
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SUPPORTED_METHODS = SAFE_METHODS | STATE_CHANGING_METHODS
_VARIABLE_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")
_SENSITIVE_NAME_RE = re.compile(
    r"(?:authorization|api[-_]?key|token|secret|password|passwd|cookie|session|credential|private[-_]?key)",
    re.I,
)


class PostmanCollectionError(ValueError):
    pass


def _json_size(value: Any) -> int:
    try:
        return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise PostmanCollectionError("Postman input must be valid JSON data") from exc


def _variable_rows(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []
    raw = document.get("variable")
    if not isinstance(raw, list):
        raw = document.get("values")
    return [dict(item) for item in raw or [] if isinstance(item, dict)]


def _variable_map(collection: dict[str, Any], environment: dict[str, Any] | None) -> dict[str, str]:
    values: dict[str, str] = {}
    for document in (collection, environment or {}):
        for item in _variable_rows(document):
            if item.get("enabled") is False:
                continue
            key = str(item.get("key") or item.get("id") or "").strip()
            if not key:
                continue
            value = item.get("current", item.get("value", item.get("initial", "")))
            if isinstance(value, (dict, list)):
                value = json.dumps(value, separators=(",", ":"))
            values[key] = str(value if value is not None else "")
            if len(values[key]) > MAX_EXPANDED_VALUE_CHARS:
                raise PostmanCollectionError("Postman variable exceeds the expanded-value limit")
    # Postman variables frequently reference other variables (for example,
    # baseUrl -> scheme + host + port). Resolve a bounded number of passes so
    # imports behave like Postman without allowing recursive expansion loops.
    for _ in range(8):
        changed = False
        total_size = sum(len(key) + len(value) for key, value in values.items())
        for key, value in list(values.items()):
            rendered, _ = _substitute(value, values)
            if rendered != value:
                total_size += len(rendered) - len(value)
                if total_size > MAX_VARIABLE_MAP_CHARS:
                    raise PostmanCollectionError("Postman variable expansion exceeds the total size limit")
                values[key] = rendered
                changed = True
        if not changed:
            break
    return values


def _url_variables(url: Any, variables: dict[str, str]) -> dict[str, str]:
    merged = dict(variables)
    if not isinstance(url, dict):
        return merged
    for item in url.get("variable") or []:
        if not isinstance(item, dict) or item.get("disabled") is True:
            continue
        key = str(item.get("key") or item.get("id") or "").strip()
        if not key:
            continue
        value, _ = _substitute(item.get("value", item.get("default", "")), merged)
        merged[key] = value
    return merged


def _substitute_path_variables(value: str, variables: dict[str, str]) -> tuple[str, list[str]]:
    """Resolve Postman's :name path variables without changing schemes or ports."""
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return value, []
    unresolved: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key in variables:
            return urllib.parse.quote(variables[key], safe="")
        unresolved.add(key)
        return match.group(0)

    path = re.sub(r"(?<=/):([A-Za-z_][A-Za-z0-9_.-]*)", replace, parsed.path)
    rendered = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))
    if len(rendered) > MAX_URL_CHARS:
        raise PostmanCollectionError("Postman URL exceeds the expanded size limit")
    return rendered, sorted(unresolved)


def _substitute(value: Any, variables: dict[str, str]) -> tuple[str, list[str]]:
    text = str(value or "")
    if len(text) > MAX_EXPANDED_VALUE_CHARS:
        raise PostmanCollectionError("Postman expanded value exceeds the size limit")
    unresolved: set[str] = set()
    rendered: list[str] = []
    rendered_size = 0
    cursor = 0
    for match in _VARIABLE_RE.finditer(text):
        prefix = text[cursor:match.start()]
        key = match.group(1).strip()
        if key in variables:
            replacement = variables[key]
        else:
            unresolved.add(key)
            replacement = match.group(0)
        rendered_size += len(prefix) + len(replacement)
        if rendered_size > MAX_EXPANDED_VALUE_CHARS:
            raise PostmanCollectionError("Postman variable expansion exceeds the size limit")
        rendered.extend((prefix, replacement))
        cursor = match.end()
    suffix = text[cursor:]
    if rendered_size + len(suffix) > MAX_EXPANDED_VALUE_CHARS:
        raise PostmanCollectionError("Postman variable expansion exceeds the size limit")
    rendered.append(suffix)
    return "".join(rendered), sorted(unresolved)


def _url_raw(url: Any) -> str:
    if isinstance(url, str):
        return url.strip()
    if not isinstance(url, dict):
        return ""
    if str(url.get("raw") or "").strip():
        return str(url["raw"]).strip()
    protocol = str(url.get("protocol") or "").strip()
    host_raw = url.get("host")
    host = ".".join(str(item) for item in host_raw) if isinstance(host_raw, list) else str(host_raw or "")
    port = str(url.get("port") or "").strip()
    path_raw = url.get("path")
    path = "/".join(str(item) for item in path_raw) if isinstance(path_raw, list) else str(path_raw or "")
    query_parts = []
    for item in url.get("query") or []:
        if not isinstance(item, dict) or item.get("disabled") is True or not item.get("key"):
            continue
        query_parts.append((str(item["key"]), str(item.get("value") or "")))
    authority = host + (f":{port}" if port else "")
    prefix = f"{protocol}://{authority}" if protocol and authority else authority
    rendered = f"{prefix}/{path.lstrip('/')}" if path else prefix
    if query_parts:
        rendered += "?" + urllib.parse.urlencode(query_parts)
    return rendered


def _auth_type(auth: Any) -> str:
    return str(auth.get("type") or "inherit").strip().lower() if isinstance(auth, dict) else "inherit"


def _walk_items(
    items: Any,
    *,
    folder: tuple[str, ...] = (),
    inherited_auth: Any = None,
) -> Iterator[tuple[tuple[str, ...], dict[str, Any], Any]]:
    for index, item in enumerate(items or []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or f"Request {index + 1}").strip()[:300]
        item_auth = item.get("auth", inherited_auth)
        if _auth_type(item_auth) == "inherit" and inherited_auth is not None:
            item_auth = inherited_auth
        if isinstance(item.get("item"), list):
            yield from _walk_items(item["item"], folder=folder + (name,), inherited_auth=item_auth)
            continue
        request = item.get("request")
        if isinstance(request, str):
            request = {"method": "GET", "url": request}
        if isinstance(request, dict):
            request_auth = request.get("auth", item_auth)
            if _auth_type(request_auth) == "inherit" and item_auth is not None:
                request_auth = item_auth
            yield folder + (name,), request, request_auth


def _redacted_label(value: Any) -> str:
    text = str(value or "")
    return re.sub(r"(?<![A-Za-z0-9])[A-Za-z0-9_=-]{24,}(?![A-Za-z0-9])", "<redacted>", text)[:300]


def _redacted_path(path: str) -> str:
    segments = path.split("/")
    previous_sensitive = False
    output: list[str] = []
    for segment in segments:
        decoded = urllib.parse.unquote(segment)
        high_entropy = bool(re.fullmatch(r"[A-Za-z0-9_.~+=-]{24,}", decoded))
        if segment and (previous_sensitive or high_entropy):
            output.append("<redacted>")
        else:
            output.append(segment)
        previous_sensitive = bool(segment and _SENSITIVE_NAME_RE.search(decoded))
    return "/".join(output)


def _redacted_url(raw: str) -> str:
    if not raw:
        return ""
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return raw[:1000]
    if not parsed.scheme and not parsed.netloc:
        path, separator, query = raw.partition("?")
        path = _redacted_path(path)
        if not separator:
            return path[:1000]
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        return (path + "?" + urllib.parse.urlencode([(key, "<redacted>") for key, _ in pairs]))[:1000]
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    query = urllib.parse.urlencode([(key, "<redacted>") for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)])
    return urllib.parse.urlunsplit((parsed.scheme, host, _redacted_path(parsed.path or "/"), query, ""))[:1000]


def validate_and_summarize(
    collection: Any,
    environment: Any = None,
    *,
    requested_name: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(collection, dict):
        raise PostmanCollectionError("Postman collection must be one JSON object")
    if environment is not None and not isinstance(environment, dict):
        raise PostmanCollectionError("Postman environment must be one JSON object")
    collection_size = _json_size(collection)
    environment_size = _json_size(environment) if environment is not None else 0
    if collection_size > MAX_COLLECTION_BYTES:
        raise PostmanCollectionError("Postman collection exceeds the 5 MiB limit")
    if environment_size > MAX_ENVIRONMENT_BYTES:
        raise PostmanCollectionError("Postman environment exceeds the 2 MiB limit")
    info = collection.get("info") if isinstance(collection.get("info"), dict) else {}
    name = str(requested_name or info.get("name") or "Imported Postman collection").strip()[:160]
    if not name:
        raise PostmanCollectionError("Collection name cannot be empty")
    rows = list(_walk_items(collection.get("item"), inherited_auth=collection.get("auth")))
    if not rows:
        raise PostmanCollectionError("Postman collection contains no requests")
    if len(rows) > MAX_REQUESTS:
        raise PostmanCollectionError(f"Postman collection exceeds the {MAX_REQUESTS}-request limit")
    requests: list[dict[str, Any]] = []
    methods: Counter[str] = Counter()
    port_hints: set[int] = set()
    summary_variables = _variable_map(collection, environment if isinstance(environment, dict) else None)
    ignored_scripts = len(collection.get("event") or [])
    for path, request, auth in rows:
        method = str(request.get("method") or "GET").strip().upper()
        raw_url = _url_raw(request.get("url"))
        headers = [item for item in request.get("header") or [] if isinstance(item, dict) and item.get("disabled") is not True]
        body = request.get("body") if isinstance(request.get("body"), dict) else {}
        auth_kind = _auth_type(auth)
        request_id = hashlib.sha256(
            json.dumps([list(path), method, raw_url], separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()[:24]
        methods[method] += 1
        try:
            url_variables = _url_variables(request.get("url"), summary_variables)
            resolved_for_port, _ = _substitute(raw_url, url_variables)
            resolved_for_port, _ = _substitute_path_variables(resolved_for_port, url_variables)
            parsed_url = urllib.parse.urlsplit(resolved_for_port)
            if parsed_url.port:
                port_hints.add(int(parsed_url.port))
            elif parsed_url.scheme == "https":
                port_hints.add(443)
            elif parsed_url.scheme == "http":
                port_hints.add(80)
        except ValueError:
            pass
        ignored_scripts += len(request.get("event") or [])
        requests.append({
            "id": request_id,
            "name": _redacted_label(path[-1]),
            "folder": " / ".join(_redacted_label(item) for item in path[:-1]),
            "method": method,
            "url": _redacted_url(raw_url),
            "header_names": sorted({str(item.get("key") or "")[:120] for item in headers if item.get("key")})[:MAX_HEADERS],
            "body_mode": str(body.get("mode") or "none")[:40],
            "auth_type": auth_kind,
            "safe_method": method in SAFE_METHODS,
            "supported": method in SUPPORTED_METHODS and bool(raw_url),
        })
    schema = str(info.get("schema") or "")[:500]
    payload = {"collection": collection, "environment": environment or None}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    summary = {
        "schema_version": "device-request-collection/v1",
        "name": name,
        "format": "postman_collection",
        "postman_schema": schema,
        "document_sha256": digest,
        "request_count": len(requests),
        "safe_request_count": sum(1 for item in requests if item["safe_method"]),
        "state_changing_request_count": sum(1 for item in requests if item["method"] in STATE_CHANGING_METHODS),
        "unsupported_request_count": sum(1 for item in requests if not item["supported"]),
        "methods": dict(sorted(methods.items())),
        "port_hints": sorted(port_hints),
        "environment_variable_names": sorted(_variable_map({}, environment or {}).keys())[:500],
        "collection_variable_names": sorted(_variable_map(collection, {}).keys())[:500],
        "scripts_ignored": ignored_scripts,
        "requests": requests,
        "secrets_redacted": True,
    }
    return payload, summary


def _auth_values(auth: Any, variables: dict[str, str]) -> dict[str, str]:
    if not isinstance(auth, dict):
        return {}
    kind = _auth_type(auth)
    rows = auth.get(kind)
    if not isinstance(rows, list):
        return {}
    values: dict[str, str] = {}
    for item in rows:
        if not isinstance(item, dict) or not item.get("key"):
            continue
        rendered, _ = _substitute(item.get("value"), variables)
        values[str(item["key"]).lower()] = rendered
    return values


def _request_headers(request: dict[str, Any], auth: Any, variables: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    headers: dict[str, str] = {}
    unresolved: set[str] = set()
    for item in request.get("header") or []:
        if not isinstance(item, dict) or item.get("disabled") is True:
            continue
        key = str(item.get("key") or "").strip()
        if not key or any(ch in key for ch in "\r\n:"):
            continue
        value, missing = _substitute(item.get("value"), variables)
        unresolved.update(missing)
        if len(value) > MAX_HEADER_VALUE_CHARS:
            raise PostmanCollectionError("Postman header value exceeds the expanded size limit")
        if "\r" not in value and "\n" not in value:
            headers[key] = value
        if len(headers) >= MAX_HEADERS:
            break
    kind = _auth_type(auth)
    values = _auth_values(auth, variables)
    if kind == "bearer" and values.get("token"):
        headers.setdefault("Authorization", f"Bearer {values['token']}")
    elif kind == "basic":
        username, password = values.get("username", ""), values.get("password", "")
        headers.setdefault("Authorization", "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode())
    elif kind == "apikey" and values.get("in", "header") == "header" and values.get("key"):
        headers.setdefault(values["key"], values.get("value", ""))
    return headers, sorted(unresolved)


def _request_body(request: dict[str, Any], variables: dict[str, str]) -> tuple[bytes, str | None, list[str], str | None]:
    body = request.get("body") if isinstance(request.get("body"), dict) else {}
    mode = str(body.get("mode") or "none")
    unresolved: set[str] = set()
    content_type: str | None = None
    error: str | None = None
    rendered = b""
    if mode == "raw":
        text, missing = _substitute(body.get("raw"), variables)
        unresolved.update(missing)
        rendered = text.encode("utf-8")
        raw_options = body.get("options") if isinstance(body.get("options"), dict) else {}
        language = str((raw_options.get("raw") or {}).get("language") or "") if isinstance(raw_options.get("raw"), dict) else ""
        content_type = "application/json" if language == "json" else "text/plain"
    elif mode == "urlencoded":
        pairs = []
        for item in body.get("urlencoded") or []:
            if not isinstance(item, dict) or item.get("disabled") is True or not item.get("key"):
                continue
            key, missing_key = _substitute(item.get("key"), variables)
            value, missing_value = _substitute(item.get("value"), variables)
            unresolved.update(missing_key + missing_value)
            pairs.append((key, value))
            if sum(len(pair_key) + len(pair_value) for pair_key, pair_value in pairs) > MAX_BODY_BYTES:
                return b"", content_type, sorted(unresolved), "request_body_exceeds_512_kib"
        rendered = urllib.parse.urlencode(pairs).encode()
        content_type = "application/x-www-form-urlencoded"
    elif mode == "formdata":
        boundary = "----ShakerScanPostmanBoundary"
        parts: list[bytes] = []
        for item in body.get("formdata") or []:
            if not isinstance(item, dict) or item.get("disabled") is True or not item.get("key"):
                continue
            if str(item.get("type") or "text") == "file":
                error = "file_upload_not_replayed"
                continue
            key, missing_key = _substitute(item.get("key"), variables)
            value, missing_value = _substitute(item.get("value"), variables)
            unresolved.update(missing_key + missing_value)
            safe_key = key.replace('"', "").replace("\r", "").replace("\n", "")[:500]
            part_type = str(item.get("contentType") or "").replace("\r", "").replace("\n", "")[:200]
            header = f'--{boundary}\r\nContent-Disposition: form-data; name="{safe_key}"\r\n'
            if part_type:
                header += f"Content-Type: {part_type}\r\n"
            parts.append(header.encode("utf-8") + b"\r\n" + value.encode("utf-8") + b"\r\n")
            if sum(len(part) for part in parts) > MAX_BODY_BYTES:
                return b"", content_type, sorted(unresolved), "request_body_exceeds_512_kib"
        rendered = b"".join(parts) + f"--{boundary}--\r\n".encode()
        content_type = f"multipart/form-data; boundary={boundary}"
    elif mode == "graphql":
        graphql = body.get("graphql") if isinstance(body.get("graphql"), dict) else {}
        query, missing_query = _substitute(graphql.get("query"), variables)
        variables_text, missing_variables = _substitute(graphql.get("variables") or "{}", variables)
        unresolved.update(missing_query + missing_variables)
        try:
            graph_variables = json.loads(variables_text)
        except json.JSONDecodeError:
            graph_variables = variables_text
        rendered = json.dumps({"query": query, "variables": graph_variables}, separators=(",", ":")).encode()
        content_type = "application/json"
    elif mode not in {"none", ""}:
        error = f"unsupported_body_mode:{mode}"
    if len(rendered) > MAX_BODY_BYTES:
        return b"", content_type, sorted(unresolved), "request_body_exceeds_512_kib"
    return rendered, content_type, sorted(unresolved), error


def resolve_requests(payload: dict[str, Any]) -> list[dict[str, Any]]:
    collection = payload.get("collection") if isinstance(payload, dict) else None
    environment = payload.get("environment") if isinstance(payload, dict) else None
    if not isinstance(collection, dict):
        raise PostmanCollectionError("Encrypted collection payload is invalid")
    variables = _variable_map(collection, environment if isinstance(environment, dict) else None)
    resolved: list[dict[str, Any]] = []
    for path, request, auth in _walk_items(collection.get("item"), inherited_auth=collection.get("auth")):
        method = str(request.get("method") or "GET").strip().upper()
        raw_template = _url_raw(request.get("url"))
        request_variables = _url_variables(request.get("url"), variables)
        url, unresolved_url = _substitute(raw_template, request_variables)
        if len(url) > MAX_URL_CHARS:
            raise PostmanCollectionError("Postman URL exceeds the expanded size limit")
        url, unresolved_path = _substitute_path_variables(url, request_variables)
        headers, unresolved_headers = _request_headers(request, auth, request_variables)
        body, content_type, unresolved_body, body_error = _request_body(request, request_variables)
        if content_type and not any(key.lower() == "content-type" for key in headers):
            headers["Content-Type"] = content_type
        auth_kind = _auth_type(auth)
        auth_values = _auth_values(auth, request_variables)
        if auth_kind == "apikey" and auth_values.get("in") == "query" and auth_values.get("key"):
            separator = "&" if "?" in url else "?"
            url += separator + urllib.parse.urlencode([(auth_values["key"], auth_values.get("value", ""))])
        resolved.append({
            "id": hashlib.sha256(json.dumps([list(path), method, raw_template], separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()[:24],
            "name": _redacted_label(path[-1]),
            "folder": " / ".join(_redacted_label(item) for item in path[:-1]),
            "method": method,
            "url": url,
            "url_template": raw_template,
            "headers": headers,
            "sensitive_header_names": sorted(key.lower() for key in headers if _SENSITIVE_NAME_RE.search(key)),
            "body": body,
            "auth_type": auth_kind,
            "has_sensitive_material": auth_kind not in {"inherit", "noauth", ""} or any(_SENSITIVE_NAME_RE.search(key) for key in headers),
            "unresolved_variables": sorted(set(unresolved_url + unresolved_path + unresolved_headers + unresolved_body)),
            "error": body_error,
        })
    return resolved[:MAX_REQUESTS]


def public_request_url(url: str) -> str:
    """Remove query values and credentials from an executed request URL."""
    return _redacted_url(url)


def redacted_header_names(headers: dict[str, str]) -> list[str]:
    return sorted(str(key)[:120] for key in headers)[:MAX_HEADERS]
