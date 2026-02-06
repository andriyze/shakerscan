"""
HAR-First Discovery Module

Extracts endpoints, parameters, and attack surface from browser network capture.
This is the primary discovery source for Smart Scan, capturing real application
traffic including:
- API endpoints (XHR/fetch)
- Query parameters
- Request body parameters (JSON/form)
- Authentication patterns
- WebSocket endpoints

Philosophy: "Real traffic reveals real attack surface"
"""

import copy
import json
import re
import sys
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from .common import is_in_scope_url

@dataclass
class DiscoveredEndpoint:
    """An endpoint discovered from network capture."""
    url: str
    method: str = "GET"
    path: str = ""
    query_params: dict[str, list[str]] = field(default_factory=dict)
    body_params: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    is_api: bool = False
    has_auth: bool = False
    response_status: int | None = None
    response_content_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON output."""
        return {
            "url": self.url,
            "method": self.method,
            "path": self.path,
            "query_params": self.query_params,
            "body_params": self.body_params,
            "content_type": self.content_type,
            "is_api": self.is_api,
            "has_auth": self.has_auth,
            "response_status": self.response_status,
        }


@dataclass
class DiscoveredParameter:
    """A parameter discovered from network capture."""
    name: str
    location: str  # query, body, path, header
    sample_value: str = ""
    endpoint_url: str = ""
    param_type: str = "string"  # string, number, boolean, object, array
    is_id: bool = False  # Likely an ID field (for BOLA testing)
    is_auth: bool = False  # Part of auth flow

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "sample_value": self.sample_value[:100] if self.sample_value else "",
            "endpoint_url": self.endpoint_url,
            "param_type": self.param_type,
            "is_id": self.is_id,
            "is_auth": self.is_auth,
        }


@dataclass
class HARDiscoveryResult:
    """Results from HAR-based discovery."""
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    parameters: list[DiscoveredParameter] = field(default_factory=list)
    websocket_endpoints: list[str] = field(default_factory=list)
    auth_patterns: dict[str, Any] = field(default_factory=dict)
    total_requests: int = 0
    api_requests: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoints": [e.to_dict() for e in self.endpoints],
            "parameters": [p.to_dict() for p in self.parameters],
            "websocket_endpoints": self.websocket_endpoints,
            "auth_patterns": self.auth_patterns,
            "stats": {
                "total_requests": self.total_requests,
                "api_requests": self.api_requests,
                "unique_endpoints": len(self.endpoints),
                "unique_params": len(self.parameters),
            },
        }


# Patterns for identifying ID-like parameters (BOLA candidates)
ID_PATTERNS = [
    r"^id$",
    r"^.*_id$",
    r"^.*Id$",
    r"^uuid$",
    r"^guid$",
    r"^user_?id$",
    r"^account_?id$",
    r"^customer_?id$",
    r"^order_?id$",
    r"^item_?id$",
    r"^product_?id$",
    r"^resource_?id$",
]

# Auth-related parameter names
AUTH_PARAM_NAMES = {
    "token", "access_token", "refresh_token", "api_key", "apikey",
    "auth", "authorization", "session", "session_id", "sessionid",
    "jwt", "bearer", "password", "secret", "key", "credential",
}


def _is_id_param(name: str) -> bool:
    """Check if parameter name looks like an ID field."""
    name_lower = name.lower()
    for pattern in ID_PATTERNS:
        if re.match(pattern, name_lower):
            return True
    return False


def _is_auth_param(name: str) -> bool:
    """Check if parameter name is auth-related."""
    return name.lower() in AUTH_PARAM_NAMES


def _infer_param_type(value: Any) -> str:
    """Infer parameter type from sample value."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "number"
    if isinstance(value, float):
        return "number"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    # String type checks
    str_val = str(value)
    if str_val.isdigit():
        return "number"
    if str_val.lower() in ("true", "false"):
        return "boolean"
    return "string"


def _parse_json_params(
    body: str | None,
    endpoint_url: str,
    prefix: str = ""
) -> list[DiscoveredParameter]:
    """Parse parameters from JSON request body."""
    if not body:
        return []

    params = []
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            for key, value in data.items():
                full_name = f"{prefix}.{key}" if prefix else key
                params.append(DiscoveredParameter(
                    name=full_name,
                    location="body",
                    sample_value=str(value)[:100] if value is not None else "",
                    endpoint_url=endpoint_url,
                    param_type=_infer_param_type(value),
                    is_id=_is_id_param(key),
                    is_auth=_is_auth_param(key),
                ))
                # Recurse into nested objects (1 level)
                if isinstance(value, dict):
                    for nested_key, nested_val in value.items():
                        nested_name = f"{full_name}.{nested_key}"
                        params.append(DiscoveredParameter(
                            name=nested_name,
                            location="body",
                            sample_value=str(nested_val)[:100] if nested_val is not None else "",
                            endpoint_url=endpoint_url,
                            param_type=_infer_param_type(nested_val),
                            is_id=_is_id_param(nested_key),
                            is_auth=_is_auth_param(nested_key),
                        ))
    except (json.JSONDecodeError, TypeError):
        pass

    return params


def _parse_form_params(
    body: str | None,
    endpoint_url: str
) -> list[DiscoveredParameter]:
    """Parse parameters from form-encoded request body."""
    if not body:
        return []

    params = []
    try:
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
        for key, values in parsed.items():
            sample = values[0] if values else ""
            params.append(DiscoveredParameter(
                name=key,
                location="body",
                sample_value=sample[:100],
                endpoint_url=endpoint_url,
                param_type=_infer_param_type(sample),
                is_id=_is_id_param(key),
                is_auth=_is_auth_param(key),
            ))
    except Exception:
        pass

    return params


def _parse_query_params(
    query_string: str | None,
    endpoint_url: str
) -> tuple[dict[str, list[str]], list[DiscoveredParameter]]:
    """Parse query string parameters."""
    # Fallback: extract query from URL if query_string is empty
    if not query_string and endpoint_url:
        parsed_url = urllib.parse.urlparse(endpoint_url)
        query_string = parsed_url.query
    if not query_string:
        return {}, []

    params_dict: dict[str, list[str]] = {}
    discovered: list[DiscoveredParameter] = []

    try:
        parsed = urllib.parse.parse_qs(query_string, keep_blank_values=True)
        for key, values in parsed.items():
            params_dict[key] = values
            sample = values[0] if values else ""
            discovered.append(DiscoveredParameter(
                name=key,
                location="query",
                sample_value=sample[:100],
                endpoint_url=endpoint_url,
                param_type=_infer_param_type(sample),
                is_id=_is_id_param(key),
                is_auth=_is_auth_param(key),
            ))
    except Exception:
        pass

    return params_dict, discovered


def _extract_path_params(path: str, endpoint_url: str) -> list[DiscoveredParameter]:
    """Extract potential path parameters (numeric IDs, UUIDs)."""
    params = []
    segments = path.strip("/").split("/")

    for i, segment in enumerate(segments):
        # Check for numeric IDs
        if segment.isdigit():
            # Previous segment is likely the resource name
            resource = segments[i - 1] if i > 0 else "id"
            params.append(DiscoveredParameter(
                name=f"{resource}_id",
                location="path",
                sample_value=segment,
                endpoint_url=endpoint_url,
                param_type="number",
                is_id=True,
                is_auth=False,
            ))
        # Check for UUIDs
        elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", segment, re.I):
            resource = segments[i - 1] if i > 0 else "id"
            params.append(DiscoveredParameter(
                name=f"{resource}_uuid",
                location="path",
                sample_value=segment,
                endpoint_url=endpoint_url,
                param_type="string",
                is_id=True,
                is_auth=False,
            ))

    return params


def extract_discovery_from_har(
    captured_requests: list[dict[str, Any]],
    websocket_endpoints: list[str] | None = None,
    base_url: str | None = None,
) -> HARDiscoveryResult:
    """
    Extract endpoints and parameters from browser network capture.

    Args:
        captured_requests: List of request dicts from browser_fetch
        websocket_endpoints: List of WebSocket URLs from browser_fetch
        base_url: Base URL for filtering (optional)

    Returns:
        HARDiscoveryResult with extracted endpoints and parameters
    """
    result = HARDiscoveryResult()
    result.total_requests = len(captured_requests)
    result.websocket_endpoints = websocket_endpoints or []
    if base_url:
        result.websocket_endpoints = [
            ws for ws in result.websocket_endpoints if is_in_scope_url(ws, base_url)
        ]

    seen_endpoints: set[str] = set()  # url+method dedup
    seen_params: set[str] = set()  # name+location+endpoint dedup
    auth_headers_seen: list[str] = []

    for req in captured_requests:
        url = req.get("url", "")
        if base_url and not is_in_scope_url(url, base_url):
            continue
        method = req.get("method", "GET").upper()
        path = req.get("path", "")
        query = req.get("query", "")
        content_type = req.get("content_type", "")
        post_data = req.get("post_data")
        headers = req.get("headers", {})
        is_api = req.get("is_api_call", False)
        has_auth = req.get("has_auth", False)
        status = req.get("status")
        resp_content_type = req.get("response_content_type", "")

        if is_api:
            result.api_requests += 1

        # Dedup by url+method
        endpoint_key = f"{method}:{url}"
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)

        # Parse query parameters
        query_params, query_discovered = _parse_query_params(query, url)

        # Parse body parameters based on content type (with fallback inference)
        body_params: dict[str, Any] = {}
        body_discovered: list[DiscoveredParameter] = []
        if post_data:
            body_text = post_data if isinstance(post_data, str) else str(post_data)
            content_type_lower = (content_type or "").lower()
            looks_like_json = body_text.lstrip().startswith(("{", "["))

            if "json" in content_type_lower or (looks_like_json and not content_type_lower):
                body_discovered = _parse_json_params(body_text, url)
                try:
                    body_params = json.loads(body_text)
                    if not content_type:
                        content_type = "application/json"
                except Exception:
                    pass
            elif "form" in content_type_lower or "urlencoded" in content_type_lower:
                body_discovered = _parse_form_params(body_text, url)
                try:
                    body_params = dict(urllib.parse.parse_qsl(body_text, keep_blank_values=True))
                    if not content_type:
                        content_type = "application/x-www-form-urlencoded"
                except Exception:
                    pass
            elif looks_like_json:
                body_discovered = _parse_json_params(body_text, url)
                try:
                    body_params = json.loads(body_text)
                    if not content_type:
                        content_type = "application/json"
                except Exception:
                    pass
            elif "=" in body_text and "&" in body_text:
                body_discovered = _parse_form_params(body_text, url)
                try:
                    body_params = dict(urllib.parse.parse_qsl(body_text, keep_blank_values=True))
                    if not content_type:
                        content_type = "application/x-www-form-urlencoded"
                except Exception:
                    pass

        # Extract path parameters
        path_discovered = _extract_path_params(path, url)

        # Create endpoint
        endpoint = DiscoveredEndpoint(
            url=url,
            method=method,
            path=path,
            query_params=query_params,
            body_params=body_params,
            headers=headers,
            content_type=content_type,
            is_api=is_api,
            has_auth=has_auth,
            response_status=status,
            response_content_type=resp_content_type,
        )
        result.endpoints.append(endpoint)

        # Add discovered parameters (deduplicated)
        for param in query_discovered + body_discovered + path_discovered:
            param_key = f"{param.name}:{param.location}:{param.endpoint_url}"
            if param_key not in seen_params:
                seen_params.add(param_key)
                result.parameters.append(param)

        # Track auth patterns
        if has_auth:
            auth_header = headers.get("authorization", "")
            if auth_header and auth_header not in auth_headers_seen:
                auth_headers_seen.append(auth_header[:50])  # Truncate for safety

    # Summarize auth patterns
    if auth_headers_seen:
        result.auth_patterns["auth_types"] = list(set(
            "bearer" if "bearer" in h.lower() else
            "basic" if "basic" in h.lower() else
            "custom"
            for h in auth_headers_seen
        ))
        result.auth_patterns["auth_header_count"] = len(auth_headers_seen)

    return result


def get_testable_endpoints(
    discovery: HARDiscoveryResult,
    prioritize_api: bool = True,
    max_endpoints: int = 50
) -> list[dict[str, Any]]:
    """
    Get endpoints suitable for security testing, prioritized by value.

    Priority order:
    1. API endpoints with parameters (highest attack surface)
    2. API endpoints without parameters
    3. Non-API endpoints with parameters
    4. Non-API endpoints

    Args:
        discovery: HARDiscoveryResult from extract_discovery_from_har
        prioritize_api: Prioritize API endpoints
        max_endpoints: Maximum endpoints to return

    Returns:
        List of endpoint dicts ready for testing
    """
    # Score endpoints for prioritization
    scored = []
    for endpoint in discovery.endpoints:
        score = 0

        # API endpoints get priority
        if endpoint.is_api:
            score += 100

        # POST/PUT/DELETE higher risk than GET
        if endpoint.method in ("POST", "PUT", "PATCH", "DELETE"):
            score += 50

        # Endpoints with parameters are more interesting
        param_count = len(endpoint.query_params) + len(endpoint.body_params)
        score += param_count * 10

        # Auth endpoints are sensitive
        if endpoint.has_auth:
            score += 30

        # JSON APIs often have more injection points
        if "json" in endpoint.content_type.lower():
            score += 20

        scored.append((score, endpoint))

    # Sort by score descending
    scored.sort(key=lambda x: x[0], reverse=True)

    # Ensure a minimum share of POST/PUT/PATCH endpoints for active testing
    post_methods = {"POST", "PUT", "PATCH"}
    post_scored = [(s, e) for s, e in scored if e.method in post_methods]
    get_scored = [(s, e) for s, e in scored if e.method not in post_methods]

    min_post = 0
    if post_scored:
        min_post = min(len(post_scored), max(5, max_endpoints // 4))

    selected: list[tuple[int, DiscoveredEndpoint]] = []
    selected_keys: set[str] = set()

    for score, endpoint in post_scored[:min_post]:
        key = f"{endpoint.method}:{endpoint.url}"
        if key in selected_keys:
            continue
        selected.append((score, endpoint))
        selected_keys.add(key)

    for score, endpoint in scored:
        if len(selected) >= max_endpoints:
            break
        key = f"{endpoint.method}:{endpoint.url}"
        if key in selected_keys:
            continue
        selected.append((score, endpoint))
        selected_keys.add(key)

    def _normalize_defaults(params: dict[str, Any], allow_list: bool = False) -> dict[str, Any]:
        """Normalize param values for replay fidelity."""
        normalized = {}
        for key, val in params.items():
            if isinstance(val, list):
                if allow_list:
                    normalized[key] = val
                else:
                    normalized[key] = val[0] if val else ""
            else:
                normalized[key] = val
        return normalized

    def _safe_body_keys(body_params: Any) -> list[str]:
        """Safely extract keys from body_params, handling non-dict JSON (e.g., arrays)."""
        if isinstance(body_params, dict):
            return list(body_params.keys())
        if isinstance(body_params, list):
            if body_params and isinstance(body_params[0], dict):
                return list(body_params[0].keys())
            if body_params:
                return ["__item__"]
        # JSON arrays or other non-dict bodies: no extractable param names
        return []

    def _safe_body_defaults(body_params: Any, allow_list: bool) -> dict[str, Any]:
        """Safely normalize body_params for defaults, handling non-dict JSON."""
        if isinstance(body_params, dict):
            return _normalize_defaults(body_params, allow_list=allow_list)
        if isinstance(body_params, list):
            if body_params and isinstance(body_params[0], dict):
                return _normalize_defaults(body_params[0], allow_list=allow_list)
        # JSON arrays or other non-dict bodies: no defaults to provide
        return {}

    def _safe_body_template(body_params: Any) -> Any | None:
        """Build a minimal body template for array bodies."""
        if isinstance(body_params, list):
            if not body_params:
                return []
            return [copy.deepcopy(body_params[0])]
        return None

    # Return top N as dicts
    return [
        {
            "url": e.url,
            "method": e.method,
            "params": {
                "query": list(e.query_params.keys()),
                "body": _safe_body_keys(e.body_params),
            },
            "param_values": {
                "query": _normalize_defaults(e.query_params, allow_list=False),
                "body": _safe_body_defaults(
                    e.body_params,
                    allow_list="json" in (e.content_type or "").lower(),
                ),
            },
            "content_type": e.content_type,
            "body_template": _safe_body_template(e.body_params),
            "has_auth": e.has_auth,
            "score": s,
        }
        for s, e in selected[:max_endpoints]
    ]


def get_bola_candidates(discovery: HARDiscoveryResult) -> list[dict[str, Any]]:
    """
    Get endpoints with ID parameters for BOLA/IDOR testing.

    Returns endpoints where ID manipulation could reveal unauthorized data.
    """
    candidates = []

    for endpoint in discovery.endpoints:
        # Find ID parameters associated with this endpoint
        id_params = [
            p for p in discovery.parameters
            if p.endpoint_url == endpoint.url and p.is_id
        ]

        if id_params:
            candidates.append({
                "url": endpoint.url,
                "method": endpoint.method,
                "id_params": [
                    {
                        "name": p.name,
                        "location": p.location,
                        "sample_value": p.sample_value,
                    }
                    for p in id_params
                ],
                "has_auth": endpoint.has_auth,
            })

    return candidates


async def discover_from_browser(
    url: str,
    auth_session: Any | None = None,
    max_pages: int = 10,
) -> HARDiscoveryResult:
    """
    Primary discovery method: capture real traffic via browser.

    This is the main entry point for HAR-first discovery.
    Falls back to empty result if browser unavailable.

    Args:
        url: Target URL
        auth_session: Optional auth session for authenticated crawl
        max_pages: Maximum pages to crawl

    Returns:
        HARDiscoveryResult with discovered endpoints and parameters
    """
    from .http_scanner import browser_fetch

    print(f"[har_discovery] Starting browser-based discovery for {url}", file=sys.stderr)

    try:
        browser_result = await browser_fetch(
            url=url,
            auth_session=auth_session,
            crawl=True,
            max_pages=max_pages,
        )

        captured_requests = browser_result.get("captured_requests", [])
        websocket_endpoints = browser_result.get("websocket_endpoints", [])

        if captured_requests:
            print(
                f"[har_discovery] Captured {len(captured_requests)} requests, "
                f"{len(websocket_endpoints)} WebSocket endpoints",
                file=sys.stderr
            )

        result = extract_discovery_from_har(
            captured_requests=captured_requests,
            websocket_endpoints=websocket_endpoints,
            base_url=url,
        )

        print(
            f"[har_discovery] Extracted {len(result.endpoints)} endpoints, "
            f"{len(result.parameters)} parameters",
            file=sys.stderr
        )

        return result

    except Exception as e:
        print(f"[har_discovery] Browser discovery failed: {e}", file=sys.stderr)
        return HARDiscoveryResult()
