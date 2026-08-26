"""Generic encrypted request-collection parsing, indexing, selection, and pagination.

The legacy device modules remain compatibility format adapters. This module owns V2 limits and
the target-agnostic redacted inventory contract used by Scan and Hunt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Iterable, Mapping
import urllib.parse

from .device_postman import HARD_MAX_COLLECTION_BYTES, HARD_MAX_REQUESTS, SAFE_METHODS
from .device_request_formats import (
    RequestImportError,
    resolve_imported_requests,
    validate_request_document,
)


REQUEST_COLLECTION_IMPORT_DEFAULT = 5_000
REQUEST_COLLECTION_IMPORT_HARD_MAX = HARD_MAX_REQUESTS
REQUEST_COLLECTION_REPLAY_DEFAULT = 500
REQUEST_COLLECTION_REPLAY_HARD_MAX = 2_000
REQUEST_COLLECTION_AGENT_PREVIEW_MAX = 200
REQUEST_COLLECTION_PAGE_MAX = 500
REQUEST_COLLECTION_DOCUMENT_DEFAULT_BYTES = 25 * 1024 * 1024
REQUEST_COLLECTION_DOCUMENT_HARD_MAX_BYTES = HARD_MAX_COLLECTION_BYTES


def _flatten_body_field_names(value: Any, *, prefix: str = "", depth: int = 0) -> list[str]:
    if depth > 8:
        return []
    names: list[str] = []
    if isinstance(value, Mapping):
        for raw_key, child in list(value.items())[:128]:
            key = str(raw_key).strip()[:160]
            if not key:
                continue
            path = f"{prefix}.{key}" if prefix else key
            names.append(path)
            names.extend(_flatten_body_field_names(child, prefix=path, depth=depth + 1))
            if len(names) >= 128:
                break
    elif isinstance(value, list) and value:
        path = f"{prefix}[]" if prefix else "[]"
        names.append(path)
        names.extend(_flatten_body_field_names(value[0], prefix=path, depth=depth + 1))
    return list(dict.fromkeys(names))[:128]


def _public_body_metadata(request: Mapping[str, Any]) -> tuple[str, list[str]]:
    """Extract only encoding and field paths from one worker-private request body."""
    content_type = str(request.get("body_mode") or "none").strip().lower()[:160]
    body = request.get("body")
    if isinstance(body, str):
        raw = body.encode("utf-8", errors="replace")
    elif isinstance(body, (bytes, bytearray)):
        raw = bytes(body)
    else:
        raw = b""
    if not raw or len(raw) > 512 * 1024:
        return content_type, []
    fields: list[str] = []
    try:
        if "json" in content_type:
            fields = _flatten_body_field_names(json.loads(raw.decode("utf-8")))
        elif "x-www-form-urlencoded" in content_type or content_type == "urlencoded":
            fields = [
                str(name).strip()[:160]
                for name, _value in urllib.parse.parse_qsl(
                    raw.decode("utf-8", errors="replace"), keep_blank_values=True,
                )[:128]
                if str(name).strip()
            ]
        elif "multipart/form-data" in content_type:
            fields = [
                match.decode("utf-8", errors="replace")[:160]
                for match in re.findall(br'name="([^"\r\n]{1,160})"', raw[:512 * 1024])[:128]
            ]
    except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
        fields = []
    return content_type, list(dict.fromkeys(fields))[:128]


def _canonical_index_path(value: Any) -> str:
    """Reduce one already-redacted request URL to a query-free route path."""
    raw = str(value or "").strip()
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return "/"
    path = parsed.path if parsed.scheme or parsed.netloc else raw.partition("?")[0]
    path = path.partition("#")[0].strip()
    if not path.startswith("/"):
        path = "/" + path.lstrip("/")
    return (path or "/")[:4_096]


def _compile_safe_path_regex(value: str) -> re.Pattern[str]:
    """Compile the deliberately small selector-regex subset.

    Python's backtracking engine has no per-match deadline. These expressions run across as many
    as 20k attacker-influenced paths, so reject group repetition and heavily variable patterns
    instead of trying to enumerate known catastrophic spellings.
    """
    if len(value) > 500:
        raise ValueError("selector path_regex exceeds complexity bounds")
    if re.search(r"\\[1-9]|\(\?(?:[=!]|<[=!]|P=|\()", value):
        raise ValueError("selector path_regex contains unsupported backtracking constructs")

    escaped = False
    in_class = False
    group_depth = 0
    closed_group = False
    variable_quantifiers = 0
    unbounded_quantifiers = 0
    index = 0
    while index < len(value):
        character = value[index]
        if escaped:
            escaped = False
            closed_group = False
            index += 1
            continue
        if character == "\\":
            escaped = True
            closed_group = False
            index += 1
            continue
        if in_class:
            if character == "]":
                in_class = False
            index += 1
            continue
        if character == "[":
            in_class = True
            closed_group = False
            index += 1
            continue
        if character == "(":
            group_depth += 1
            closed_group = False
            index += 1
            continue
        if character == ")":
            group_depth = max(0, group_depth - 1)
            closed_group = True
            index += 1
            continue

        is_variable = character in "*+?"
        is_unbounded = character in "*+"
        if character == "{":
            match = re.match(r"\{(\d+)(?:,(\d*)?)?\}", value[index:])
            if match:
                lower = int(match.group(1))
                upper_text = match.group(2)
                has_comma = "," in match.group(0)
                upper = int(upper_text) if upper_text else None
                is_variable = has_comma and upper != lower
                is_unbounded = has_comma and upper is None
                if upper is not None and upper - lower > 100:
                    raise ValueError("selector path_regex repeat range is too wide")
                index += len(match.group(0))
            else:
                closed_group = False
                index += 1
                continue
        else:
            index += 1
        if is_variable:
            if closed_group:
                raise ValueError("selector path_regex contains unsupported backtracking constructs")
            variable_quantifiers += 1
            unbounded_quantifiers += int(is_unbounded)
            if variable_quantifiers > 8 or unbounded_quantifiers > 1:
                raise ValueError("selector path_regex exceeds repetition bounds")
        closed_group = False

    try:
        compiled = re.compile(value)
    except re.error as exc:
        raise ValueError("selector path_regex is invalid") from exc
    if compiled.groups > 20:
        raise ValueError("selector path_regex exceeds complexity bounds")
    return compiled


@dataclass(frozen=True)
class RequestSelector:
    request_ids: tuple[str, ...] = ()
    folders: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()
    path_regex: str | None = None
    tags: tuple[str, ...] = ()
    safe_methods_only: bool = True
    limit: int = REQUEST_COLLECTION_REPLAY_DEFAULT
    _path_pattern: re.Pattern[str] | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not 1 <= int(self.limit) <= REQUEST_COLLECTION_REPLAY_HARD_MAX:
            raise ValueError(
                f"selector limit must be between 1 and {REQUEST_COLLECTION_REPLAY_HARD_MAX}"
            )
        methods = tuple(dict.fromkeys(str(item).strip().upper() for item in self.methods if str(item).strip()))
        if any(not re.fullmatch(r"[A-Z]{3,10}", method) for method in methods):
            raise ValueError("selector methods are invalid")
        object.__setattr__(self, "methods", methods)
        tags = tuple(dict.fromkeys(
            str(item).strip()[:120] for item in self.tags if str(item).strip()
        ))
        if len(tags) > 200:
            raise ValueError("selector accepts at most 200 tags")
        object.__setattr__(self, "tags", tags)
        if self.path_regex:
            object.__setattr__(self, "_path_pattern", _compile_safe_path_regex(self.path_regex))

    def matches_path(self, value: str) -> bool:
        if self._path_pattern is None:
            return True
        return self._path_pattern.search(str(value)) is not None


def validate_and_index(
    document: Any,
    environment: Any = None,
    *,
    requested_name: str | None = None,
    import_format: str = "auto",
    base_url: str | None = None,
    import_limit: int = REQUEST_COLLECTION_IMPORT_DEFAULT,
    max_document_bytes: int = REQUEST_COLLECTION_DOCUMENT_DEFAULT_BYTES,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    """Validate one supported document and return encrypted payload input + safe public index."""
    if not 1 <= int(import_limit) <= REQUEST_COLLECTION_IMPORT_HARD_MAX:
        raise RequestImportError(
            f"import_limit must be between 1 and {REQUEST_COLLECTION_IMPORT_HARD_MAX}"
        )
    if not 1 <= int(max_document_bytes) <= REQUEST_COLLECTION_DOCUMENT_HARD_MAX_BYTES:
        raise RequestImportError(
            f"max_document_bytes must be between 1 and {REQUEST_COLLECTION_DOCUMENT_HARD_MAX_BYTES}"
        )
    payload, summary = validate_request_document(
        document, environment, requested_name=requested_name, import_format=import_format,
        base_url=base_url, max_requests=int(import_limit),
        max_document_bytes=int(max_document_bytes),
    )
    summary = dict(summary)
    summary["schema_version"] = "request-collection/v2"
    private_requests = resolve_imported_requests(
        dict(payload), max_requests=int(import_limit),
    )
    private_by_id = {
        str(item.get("id") or ""): item for item in private_requests if item.get("id")
    }
    public_requests = []
    for request in summary.get("requests") or []:
        enriched = dict(request)
        private = private_by_id.get(str(request.get("id") or ""))
        if private is not None:
            content_type, body_field_names = _public_body_metadata(private)
            enriched["content_type"] = content_type
            enriched["body_field_names"] = body_field_names
        public_requests.append(enriched)
    rows = redacted_index(public_requests)
    summary["requests"] = rows
    return payload, summary, rows


def validate_request_collection(*args: Any, **kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Compatibility return shape for existing device routes using the generic V2 limits."""
    payload, summary, _rows = validate_and_index(*args, **kwargs)
    return payload, summary


def redacted_index(requests: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return metadata-only rows; never copy header values, bodies, cookies, or tokens."""
    rows: list[dict[str, Any]] = []
    for ordinal, request in enumerate(requests):
        method = str(request.get("method") or "GET").strip().upper()
        redacted_url = str(request.get("url") or "")[:2_000]
        rows.append({
            "request_id": str(request.get("id") or "")[:64],
            "ordinal": ordinal,
            "folder": str(request.get("folder") or "")[:500],
            "name": str(request.get("name") or "")[:300],
            "method": method,
            "redacted_url": redacted_url,
            "normalized_path": _canonical_index_path(redacted_url),
            "body_mode": str(request.get("body_mode") or "none")[:80],
            "content_type": str(
                request.get("content_type") or request.get("body_mode") or "none"
            )[:160],
            "body_field_names": [
                str(name).strip()[:160]
                for name in list(request.get("body_field_names") or [])[:128]
                if str(name).strip()
            ],
            "auth_type": str(request.get("auth_type") or "none")[:160],
            "tags": [
                str(tag).strip()[:120]
                for tag in list(request.get("tags") or [])[:200]
                if str(tag).strip()
            ],
            "safe_method": bool(request.get("safe_method", method in SAFE_METHODS)),
            "supported": bool(request.get("supported", True)),
        })
    return rows


def page_index(
    rows: list[Mapping[str, Any]], *, offset: int = 0, limit: int = 100
) -> dict[str, Any]:
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if not 1 <= limit <= REQUEST_COLLECTION_PAGE_MAX:
        raise ValueError(f"limit must be between 1 and {REQUEST_COLLECTION_PAGE_MAX}")
    page = [dict(row) for row in rows[offset:offset + limit]]
    return {
        "requests": page,
        "count": len(page),
        "total": len(rows),
        "offset": offset,
        "limit": limit,
        "next_offset": offset + len(page) if offset + len(page) < len(rows) else None,
    }


def select_requests(
    payload: Mapping[str, Any], selector: RequestSelector
) -> list[dict[str, Any]]:
    """Select worker-only resolved requests without exposing secret values to the planner."""
    resolved = resolve_imported_requests(
        dict(payload), max_requests=REQUEST_COLLECTION_IMPORT_HARD_MAX
    )
    ids = set(selector.request_ids)
    folders = set(selector.folders)
    methods = set(selector.methods)
    tags = set(selector.tags)
    selected: list[dict[str, Any]] = []
    for request in resolved:
        method = str(request.get("method") or "GET").upper()
        if selector.safe_methods_only and method not in SAFE_METHODS:
            continue
        if ids and str(request.get("id") or "") not in ids:
            continue
        if folders and str(request.get("folder") or "") not in folders:
            continue
        if methods and method not in methods:
            continue
        if tags and not tags.intersection(
            str(tag) for tag in request.get("tags") or []
        ):
            continue
        candidate_path = str(request.get("url_template") or request.get("url") or "")
        if not selector.matches_path(candidate_path):
            continue
        selected.append(dict(request))
        if len(selected) >= selector.limit:
            break
    return selected
