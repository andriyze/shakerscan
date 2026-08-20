"""Generic encrypted request-collection parsing, indexing, selection, and pagination.

The legacy device modules remain compatibility format adapters. This module owns V2 limits and
the target-agnostic redacted inventory contract used by Scan and Hunt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Iterable, Mapping

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
    rows = redacted_index(summary.get("requests") or [])
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
        rows.append({
            "request_id": str(request.get("id") or "")[:64],
            "ordinal": ordinal,
            "folder": str(request.get("folder") or "")[:500],
            "name": str(request.get("name") or "")[:300],
            "method": method,
            "redacted_url": str(request.get("url") or "")[:2_000],
            "normalized_path": str(request.get("url_template") or request.get("url") or "")[:2_000],
            "body_mode": str(request.get("body_mode") or "none")[:80],
            "auth_type": str(request.get("auth_type") or "none")[:160],
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
        candidate_path = str(request.get("url_template") or request.get("url") or "")
        if not selector.matches_path(candidate_path):
            continue
        selected.append(dict(request))
        if len(selected) >= selector.limit:
            break
    return selected
