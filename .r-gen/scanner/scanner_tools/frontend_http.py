"""Static frontend request shapes shared by deterministic discovery and Hunt.

No JavaScript runs here. Literal call facts are leads; execution still requires the receiving
runtime target binding, policy, approvals and budgets. No request body values are returned.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any

_FRONTEND_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


def _extract_balanced_js_segment(content: str, start: int, opener: str, closer: str) -> str | None:
    """Extract one balanced JS segment while ignoring delimiters inside strings."""
    if start >= len(content) or content[start] != opener:
        return None
    depth = 0
    quote = ""
    escaped = False
    index = start
    while index < len(content):
        char = content[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in ("'", '"', "`"):
            quote = char
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return content[start:index + 1]
        index += 1
    return None


_JS_OBJECT_SCAN_MAX_CHARS = 64_000
_JS_OBJECT_KEY_LIMIT = 30


def _js_object_depth_profile(content: str) -> list[int]:
    """Return quote-aware object depth at each position in one bounded pass."""
    depths = [0] * (len(content) + 1)
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(content):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in ("'", '"', "`"):
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        depths[index + 1] = depth
    return depths


def _js_object_property_value(object_text: str, property_name: str) -> str | None:
    """Return a static top-level object-property value from a JS object literal."""
    if not object_text.startswith("{"):
        return None
    object_text = object_text[:_JS_OBJECT_SCAN_MAX_CHARS]
    depth_at = _js_object_depth_profile(object_text)
    property_re = re.compile(
        rf"(?:^|[,{{])\s*(?:['\"]{re.escape(property_name)}['\"]|{re.escape(property_name)})\s*:\s*",
        re.IGNORECASE,
    )
    for match in property_re.finditer(object_text):
        if depth_at[match.end()] != 1:
            continue
        cursor = match.end()
        if cursor >= len(object_text):
            return None
        if object_text[cursor] == "{":
            return _extract_balanced_js_segment(object_text, cursor, "{", "}")
        if object_text.startswith("JSON.stringify", cursor):
            open_paren = object_text.find("(", cursor + len("JSON.stringify"))
            if open_paren >= 0:
                call = _extract_balanced_js_segment(object_text, open_paren, "(", ")")
                if call:
                    return call
        if object_text.startswith("new URLSearchParams", cursor):
            open_paren = object_text.find("(", cursor + len("new URLSearchParams"))
            if open_paren >= 0:
                call = _extract_balanced_js_segment(object_text, open_paren, "(", ")")
                if call:
                    return call
        quote = object_text[cursor]
        if quote in ("'", '"', "`"):
            end = cursor + 1
            escaped = False
            while end < len(object_text):
                char = object_text[end]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    return object_text[cursor:end + 1]
                end += 1
        end = cursor
        while end < len(object_text) and object_text[end] not in ",}":
            end += 1
        return object_text[cursor:end].strip() or None
    return None


def _js_object_keys(object_text: str | None) -> list[str]:
    """Extract top-level keys from a static JS object without evaluating it."""
    if not object_text:
        return []
    first_brace = object_text.find("{")
    if first_brace < 0:
        return []
    object_text = object_text[first_brace:first_brace + _JS_OBJECT_SCAN_MAX_CHARS]
    if not object_text:
        return []
    depth_at = _js_object_depth_profile(object_text)
    keys: list[str] = []
    seen: set[str] = set()
    key_re = re.compile(r"(?:^|[,{}])\s*(?:['\"]([^'\"]+)['\"]|([A-Za-z_$][\w$-]*))\s*:")
    for match in key_re.finditer(object_text):
        if depth_at[match.end()] != 1:
            continue
        key = match.group(1) or match.group(2)
        if key and key not in seen:
            seen.add(key)
            keys.append(key)
            if len(keys) >= _JS_OBJECT_KEY_LIMIT:
                return keys
    shorthand_re = re.compile(r"(?:^|,)\s*([A-Za-z_$][\w$]*)\s*(?=,|})")
    for match in shorthand_re.finditer(object_text):
        if depth_at[match.end()] != 1:
            continue
        key = match.group(1)
        if key and key not in seen:
            seen.add(key)
            keys.append(key)
            if len(keys) >= _JS_OBJECT_KEY_LIMIT:
                break
    return keys


def _static_js_call_config(content: str, after_url: int) -> str | None:
    cursor = after_url
    while cursor < len(content) and content[cursor].isspace():
        cursor += 1
    if cursor >= len(content) or content[cursor] != ",":
        return None
    cursor += 1
    while cursor < len(content) and content[cursor].isspace():
        cursor += 1
    if cursor < len(content) and content[cursor] == "{":
        return _extract_balanced_js_segment(content, cursor, "{", "}")
    return None


def _normalize_frontend_request_url(raw_url: str) -> str | None:
    url = str(raw_url or "").strip()
    if not url or url.startswith(("data:", "javascript:")):
        return None
    if "${" in url:
        url = re.sub(r"\$\{\s*([A-Za-z_$][\w$.-]*)\s*\}", r"{\1}", url)
    if not url.startswith(("/", "http://", "https://")):
        return None
    return url


def extract_frontend_http_client_bases(content: str) -> dict[str, str]:
    """Map statically configured axios client variables to their literal base URLs."""
    clients: dict[str, str] = {}
    create_re = re.compile(
        r"(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*axios\s*\.\s*create\s*\(\s*",
        re.IGNORECASE,
    )
    for match in create_re.finditer(content or ""):
        cursor = match.end()
        if cursor >= len(content) or content[cursor] != "{":
            continue
        config = _extract_balanced_js_segment(content, cursor, "{", "}")
        base_value = _js_object_property_value(config or "", "baseURL")
        base = str(base_value or "").strip("'\"` ")
        normalized = _normalize_frontend_request_url(base)
        if normalized:
            clients[match.group(1)] = normalized.rstrip("/")
    return clients


def _compose_frontend_client_url(client_base: str | None, request_url: str) -> str:
    if not client_base or request_url.startswith(("http://", "https://")):
        return request_url
    if client_base.startswith(("http://", "https://")):
        return client_base.rstrip("/") + "/" + request_url.lstrip("/")
    return "/" + "/".join(
        part.strip("/") for part in (client_base, request_url) if part.strip("/")
    )


def extract_frontend_http_requests(content: str, *, max_requests: int = 500) -> list[dict[str, Any]]:
    """Recover static HTTP call facts from frontend bundles without executing JS.

    This intentionally requires a literal URL inside a recognized call expression.
    Loose route strings remain discovery hints and never gain an invented method/body.
    """
    requests: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = set()
    client_bases = extract_frontend_http_client_bases(content)

    def add_request(url: str, method: str, *, body_params=None, query_params=None, content_type=None):
        normalized_url = _normalize_frontend_request_url(url)
        method = str(method or "GET").upper()
        if not normalized_url or method not in _FRONTEND_HTTP_METHODS:
            return
        parsed_query = list(urllib.parse.parse_qs(urllib.parse.urlparse(normalized_url).query).keys())
        body = list(dict.fromkeys(str(p) for p in (body_params or []) if p))[:30]
        query = list(dict.fromkeys(parsed_query + [str(p) for p in (query_params or []) if p]))[:30]
        key = (method, normalized_url, tuple(body), tuple(query))
        if key in seen or len(requests) >= max_requests:
            return
        seen.add(key)
        item: dict[str, Any] = {"url": normalized_url, "method": method, "source": "js_bundle_analysis"}
        if body and method in {"POST", "PUT", "PATCH"}:
            item["body_params"] = body
            item["content_type"] = content_type or "application/json"
        if query:
            item["params"] = query
        requests.append(item)

    method_call_re = re.compile(
        r"\b(axios|[A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*(['\"`])([^'\"`\s]+)\3",
        re.IGNORECASE,
    )
    for match in method_call_re.finditer(content or ""):
        client = match.group(1)
        if client.lower() != "axios" and client not in client_bases:
            continue
        method = match.group(2).upper()
        request_url = _compose_frontend_client_url(client_bases.get(client), match.group(4))
        config = _static_js_call_config(content, match.end())
        if method == "GET":
            params_value = _js_object_property_value(config or "", "params")
            add_request(request_url, method, query_params=_js_object_keys(params_value))
        else:
            add_request(request_url, method, body_params=_js_object_keys(config))

    fetch_re = re.compile(r"\bfetch\s*\(\s*(['\"`])([^'\"`\s]+)\1", re.IGNORECASE)
    for match in fetch_re.finditer(content or ""):
        config = _static_js_call_config(content, match.end())
        method_value = _js_object_property_value(config or "", "method")
        method = str(method_value or "GET").strip("'\"` ").upper()
        body_value = _js_object_property_value(config or "", "body")
        body_params = _js_object_keys(body_value)
        content_type = "application/x-www-form-urlencoded" if body_value and "URLSearchParams" in body_value else None
        add_request(match.group(2), method, body_params=body_params, content_type=content_type)

    config_call_re = re.compile(
        r"\b(axios|[A-Za-z_$][\w$]*)\s*(\.\s*request\s*)?\(\s*(\{)",
        re.IGNORECASE,
    )
    for match in config_call_re.finditer(content or ""):
        client = match.group(1)
        if client.lower() != "axios" and not match.group(2) and client not in client_bases:
            continue
        config = _extract_balanced_js_segment(content, match.start(3), "{", "}")
        url_value = _js_object_property_value(config or "", "url")
        method_value = _js_object_property_value(config or "", "method")
        request_url = str(url_value or "").strip("'\"` ")
        method = str(method_value or "").strip("'\"` ").upper()
        if not request_url or method not in _FRONTEND_HTTP_METHODS:
            continue
        request_url = _compose_frontend_client_url(client_bases.get(client), request_url)
        data_value = _js_object_property_value(config or "", "data")
        params_value = _js_object_property_value(config or "", "params")
        add_request(
            request_url,
            method,
            body_params=_js_object_keys(data_value),
            query_params=_js_object_keys(params_value),
        )

    return requests


