"""Exact, target-bound replay plans for imported HTTP request collections.

This module is intentionally transport-agnostic. The control plane selects request IDs;
the worker decrypts the collection and builds this immutable plan immediately before
execution. Secret header/body values never appear in the public representation.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import re
from typing import Any, Iterable, Mapping
import urllib.parse

try:
    from .url_redaction import redact_url
except ImportError:  # direct host-side import in focused tests
    from url_redaction import redact_url

try:
    from .device_postman import (
        MAX_BODY_BYTES,
        SAFE_METHODS,
        STATE_CHANGING_METHODS,
        SUPPORTED_METHODS,
    )
except ImportError:  # direct host-side import in focused tests
    MAX_BODY_BYTES = 512 * 1024
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    SUPPORTED_METHODS = SAFE_METHODS | STATE_CHANGING_METHODS


REQUEST_REPLAY_SCHEMA = "request-replay-plan/v1"
REQUEST_REPLAY_HARD_MAX = 2_000
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_FORBIDDEN_WIRE_HEADERS = frozenset({
    "host", "content-length", "connection", "transfer-encoding",
    "proxy-authorization", "proxy-connection", "keep-alive", "te", "trailer", "upgrade",
})
_MAX_PUBLIC_BODY_FIELDS = 128
_MAX_PUBLIC_JSON_DEPTH = 8


class RequestReplayError(ValueError):
    """A selected request cannot be replayed within the target/approval contract."""


def _sha256(value: bytes | str) -> str:
    data = value if isinstance(value, bytes) else str(value).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _canonical_origin(value: Any) -> str:
    text = str(value or "").strip()
    try:
        parsed = urllib.parse.urlsplit(text)
        port = parsed.port
    except ValueError as exc:
        raise RequestReplayError("origin has an invalid authority") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise RequestReplayError("origin must be an absolute HTTP(S) origin")
    if parsed.username is not None or parsed.password is not None:
        raise RequestReplayError("origin must not contain user information")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise RequestReplayError("origin must not contain path, query, or fragment")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise RequestReplayError("origin hostname is invalid") from exc
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    authority = display_host if port in {None, default_port} else f"{display_host}:{port}"
    return f"{parsed.scheme.lower()}://{authority}"


def _normalize_allowed_origins(values: Iterable[Any]) -> tuple[str, ...]:
    origins = tuple(dict.fromkeys(_canonical_origin(value) for value in values))
    if not origins:
        raise RequestReplayError("at least one allowed origin is required")
    return origins


def _resolve_url(value: Any, *, allowed_origins: tuple[str, ...], default_origin: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        raise RequestReplayError("request URL is empty")
    try:
        parsed = urllib.parse.urlsplit(text)
        _ = parsed.port
    except ValueError as exc:
        raise RequestReplayError("request URL has an invalid authority") from exc
    if parsed.fragment:
        raise RequestReplayError("request URL must not contain a fragment")
    if parsed.scheme or parsed.netloc:
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise RequestReplayError("request URL must use HTTP or HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise RequestReplayError("request URL must not contain user information")
        origin = _canonical_origin(
            urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        )
        if origin not in allowed_origins:
            raise RequestReplayError("request URL origin is outside the target binding")
        return urllib.parse.urlunsplit((origin.split("://", 1)[0], origin.split("://", 1)[1],
                                       parsed.path or "/", parsed.query, ""))
    if not text.startswith("/") or text.startswith("//"):
        raise RequestReplayError("relative request URL must be an absolute same-origin path")
    if default_origin is None:
        if len(allowed_origins) != 1:
            raise RequestReplayError("relative request URL requires an explicit default origin")
        default_origin = allowed_origins[0]
    canonical_default = _canonical_origin(default_origin)
    if canonical_default not in allowed_origins:
        raise RequestReplayError("default origin is outside the target binding")
    return canonical_default + text


def _redacted_url(value: str) -> str:
    """Return a secret-free URL for public receipts and recovery artifacts."""
    return redact_url(value)


def _wire_headers(value: Any) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if isinstance(value, Mapping):
        raw_rows = list(value.items())
    elif isinstance(value, (list, tuple)):
        raw_rows = []
        for item in value:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise RequestReplayError(
                    "request header items must contain name/value pairs"
                )
            raw_rows.append((item[0], item[1]))
    else:
        raise RequestReplayError(
            "request headers must be an object or ordered name/value pairs"
        )
    rows: list[tuple[str, str]] = []
    for raw_name, raw_value in raw_rows:
        name = str(raw_name or "").strip()
        header_value = str(raw_value or "")
        if not name or len(name) > 200 or not _HEADER_NAME_RE.fullmatch(name):
            raise RequestReplayError("request contains an invalid header name")
        if any(ord(ch) < 0x20 and ch != "\t" or ord(ch) == 0x7F for ch in header_value):
            raise RequestReplayError("request header value contains control characters")
        if len(header_value.encode("utf-8")) > 8_192:
            raise RequestReplayError("request header value exceeds the replay limit")
        if name.lower() in _FORBIDDEN_WIRE_HEADERS:
            continue
        rows.append((name, header_value))
        if len(rows) > 100:
            raise RequestReplayError("request contains too many headers")
    return tuple(rows)


def _body_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        body = value
    elif isinstance(value, bytearray):
        body = bytes(value)
    elif isinstance(value, str):
        body = value.encode("utf-8")
    else:
        raise RequestReplayError("request body must be bytes or text")
    if len(body) > MAX_BODY_BYTES:
        raise RequestReplayError(f"request body exceeds the {MAX_BODY_BYTES}-byte replay limit")
    return body


def _request_content_type(
    headers: tuple[tuple[str, str], ...], body_mode: str, body: bytes,
) -> str | None:
    for name, value in headers:
        if name.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()[:200] or None
    mode = str(body_mode or "").lower()
    if "json" in mode or body.lstrip().startswith((b"{", b"[")):
        return "application/json"
    if "urlencoded" in mode or "form" in mode:
        return "application/x-www-form-urlencoded"
    return None


def _json_body_fields(
    value: Any, *, prefix: tuple[str | int, ...] = (), depth: int = 0,
) -> list[str]:
    if depth > _MAX_PUBLIC_JSON_DEPTH:
        return []
    rows: list[str] = []
    if isinstance(value, Mapping):
        for key in sorted(value, key=lambda item: str(item)):
            rows.extend(_json_body_fields(
                value[key], prefix=(*prefix, str(key)), depth=depth + 1,
            ))
            if len(rows) >= _MAX_PUBLIC_BODY_FIELDS:
                break
    elif isinstance(value, list):
        for index, item in enumerate(value[:_MAX_PUBLIC_BODY_FIELDS]):
            rows.extend(_json_body_fields(
                item, prefix=(*prefix, index), depth=depth + 1,
            ))
            if len(rows) >= _MAX_PUBLIC_BODY_FIELDS:
                break
    elif prefix and isinstance(value, (str, int, float)) and not isinstance(value, bool):
        rows.append(".".join(str(item) for item in prefix)[:300])
    return rows[:_MAX_PUBLIC_BODY_FIELDS]


def _request_body_field_names(body: bytes, content_type: str | None) -> tuple[str, ...]:
    if not body:
        return ()
    try:
        if content_type and (content_type == "application/json" or content_type.endswith("+json")):
            fields = _json_body_fields(json.loads(body.decode("utf-8")))
        elif content_type == "application/x-www-form-urlencoded":
            fields = [
                str(name)[:300] for name, _value in urllib.parse.parse_qsl(
                    body.decode("utf-8"), keep_blank_values=True,
                    max_num_fields=_MAX_PUBLIC_BODY_FIELDS,
                )
            ]
        else:
            fields = []
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        fields = []
    return tuple(dict.fromkeys(field for field in fields if field))[:_MAX_PUBLIC_BODY_FIELDS]


@dataclass(frozen=True)
class ReplayAuthorization:
    active_testing: bool = False
    allow_state_changing_http: bool = False
    approval_receipt_id: str | None = None
    safe_authentication_only: bool = False

    def authorize(self, method: str) -> None:
        if method in SAFE_METHODS:
            return
        if self.safe_authentication_only:
            if method != "POST":
                raise RequestReplayError(
                    "safe authentication replay permits exact POST requests only"
                )
            return
        if method not in STATE_CHANGING_METHODS:
            raise RequestReplayError(f"unsupported replay method: {method}")
        if not self.active_testing:
            raise RequestReplayError("state-changing replay requires active_testing")
        if not self.allow_state_changing_http:
            raise RequestReplayError("state-changing replay is not enabled by policy")
        if not str(self.approval_receipt_id or "").strip():
            raise RequestReplayError("state-changing replay requires an approval receipt")

    def public_dict(self) -> dict[str, Any]:
        result = {
            "active_testing": self.active_testing,
            "allow_state_changing_http": self.allow_state_changing_http,
            "approval_bound": bool(str(self.approval_receipt_id or "").strip()),
        }
        if self.safe_authentication_only:
            result["safe_authentication_only"] = True
        return result


@dataclass(frozen=True)
class ReplayRequest:
    request_id: str
    ordinal: int
    name: str
    folder: str
    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    body_mode: str
    auth_type: str
    has_sensitive_material: bool

    def wire_dict(self) -> dict[str, Any]:
        """Worker-only exact request. Never return this object through a public API."""
        return {
            "request_id": self.request_id,
            "method": self.method,
            "url": self.url,
            # ``headers`` is retained for worker-private compatibility consumers.
            # ``header_items`` is authoritative because an HTTP collection may
            # intentionally contain repeated field lines.
            "headers": dict(self.headers),
            "header_items": list(self.headers),
            "body": self.body,
            "body_mode": self.body_mode,
            "auth_type": self.auth_type,
        }

    def digest_dict(self) -> dict[str, Any]:
        content_type = _request_content_type(self.headers, self.body_mode, self.body)
        return {
            "request_id": self.request_id,
            "ordinal": self.ordinal,
            "method": self.method,
            "url_sha256": _sha256(self.url),
            "headers": [
                {"name": name.lower(), "value_sha256": _sha256(value)}
                for name, value in self.headers
            ],
            "body_sha256": _sha256(self.body),
            "content_type": content_type,
            "body_field_names": list(_request_body_field_names(self.body, content_type)),
            "body_mode": self.body_mode,
            "auth_type": self.auth_type,
        }

    def public_dict(self) -> dict[str, Any]:
        content_type = _request_content_type(self.headers, self.body_mode, self.body)
        return {
            "request_id": self.request_id,
            "ordinal": self.ordinal,
            "name": self.name,
            "folder": self.folder,
            "method": self.method,
            "redacted_url": _redacted_url(self.url),
            "url_sha256": _sha256(self.url),
            "header_names": [name for name, _ in self.headers],
            "body_mode": self.body_mode,
            "body_length": len(self.body),
            "body_sha256": _sha256(self.body),
            "content_type": content_type,
            "body_field_names": list(_request_body_field_names(self.body, content_type)),
            "auth_type": self.auth_type,
            "safe_method": self.method in SAFE_METHODS,
            "state_changing": self.method in STATE_CHANGING_METHODS,
            "has_sensitive_material": self.has_sensitive_material,
        }


@dataclass(frozen=True)
class ReplayPlan:
    requests: tuple[ReplayRequest, ...]
    allowed_origins: tuple[str, ...]
    default_origin: str | None
    authorization: ReplayAuthorization
    schema_version: str = REQUEST_REPLAY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != REQUEST_REPLAY_SCHEMA:
            raise RequestReplayError(f"schema_version must be {REQUEST_REPLAY_SCHEMA}")
        if not self.requests:
            raise RequestReplayError("replay plan contains no requests")
        if len(self.requests) > REQUEST_REPLAY_HARD_MAX:
            raise RequestReplayError(
                f"replay plan exceeds the {REQUEST_REPLAY_HARD_MAX}-request hard limit"
            )
        if self.authorization.safe_authentication_only and (
            len(self.requests) > 5
            or any(request.method != "POST" for request in self.requests)
        ):
            raise RequestReplayError(
                "safe authentication replay exceeds its exact POST ceiling"
            )

    @property
    def estimated_budget(self) -> dict[str, int]:
        """Typed reserve-before-send cost for the exact selected requests."""
        state_changing = sum(
            request.method in STATE_CHANGING_METHODS for request in self.requests
        )
        budget = {"http_requests": len(self.requests)}
        if state_changing and not self.authorization.safe_authentication_only:
            budget["state_changing_requests"] = int(state_changing)
        return budget

    @property
    def input_digest(self) -> str:
        approval = str(self.authorization.approval_receipt_id or "").strip()
        material = {
            "schema_version": self.schema_version,
            "allowed_origins": list(self.allowed_origins),
            "default_origin": self.default_origin,
            "authorization": self.authorization.public_dict(),
            "approval_receipt_sha256": _sha256(approval) if approval else None,
            "requests": [request.digest_dict() for request in self.requests],
        }
        return _sha256(json.dumps(material, sort_keys=True, separators=(",", ":")))

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_count": len(self.requests),
            "allowed_origins": list(self.allowed_origins),
            "default_origin": self.default_origin,
            "authorization": self.authorization.public_dict(),
            "retry_semantics": {
                # A queue redelivery reuses the terminal durable receipt. It does
                # not send the imported request a second time.
                "durable_redelivery": "reuse_terminal_receipt",
                # Read failures may be retried only by admitting a new action and
                # reserving a new attempt; the adapter never retries implicitly.
                "safe_methods": "new_action_new_reservation",
                # Writes are never automatically retried because a missing
                # response cannot prove the target did not commit the mutation.
                "state_changing_methods": "no_automatic_retry_fresh_approval",
                "automatic_attempts_per_request": 1,
            },
            "input_digest": self.input_digest,
            "requests": [request.public_dict() for request in self.requests],
            "secret_values_visible": False,
        }

    def wire_requests(self) -> tuple[dict[str, Any], ...]:
        return tuple(request.wire_dict() for request in self.requests)


def build_replay_plan(
    requests: Iterable[Mapping[str, Any]],
    *,
    allowed_origins: Iterable[Any],
    default_origin: str | None = None,
    authorization: ReplayAuthorization | None = None,
    limit: int = 500,
) -> ReplayPlan:
    """Validate selected worker-only rows and preserve their exact request semantics."""
    if not 1 <= int(limit) <= REQUEST_REPLAY_HARD_MAX:
        raise RequestReplayError(
            f"replay limit must be between 1 and {REQUEST_REPLAY_HARD_MAX}"
        )
    origins = _normalize_allowed_origins(allowed_origins)
    resolved_default = _canonical_origin(default_origin) if default_origin else None
    if resolved_default is not None and resolved_default not in origins:
        raise RequestReplayError("default origin is outside the target binding")
    authz = authorization or ReplayAuthorization()
    result: list[ReplayRequest] = []
    seen_ids: set[str] = set()
    for ordinal, row in enumerate(requests):
        if len(result) >= int(limit):
            break
        if not isinstance(row, Mapping):
            raise RequestReplayError("selected request is not an object")
        method = str(row.get("method") or "GET").strip().upper()
        if method not in SUPPORTED_METHODS:
            raise RequestReplayError(f"unsupported replay method: {method}")
        if row.get("error"):
            raise RequestReplayError("selected request has an unresolved import error")
        if row.get("unresolved_variables"):
            raise RequestReplayError("selected request has unresolved variables")
        authz.authorize(method)
        url = _resolve_url(
            row.get("url"), allowed_origins=origins, default_origin=resolved_default
        )
        request_id = str(row.get("id") or row.get("request_id") or "").strip()
        if not request_id:
            request_id = _sha256(f"{ordinal}:{method}:{url}")[:24]
        if request_id in seen_ids:
            raise RequestReplayError("selected request IDs must be unique")
        seen_ids.add(request_id)
        result.append(ReplayRequest(
            request_id=request_id[:64],
            ordinal=ordinal,
            name=str(row.get("name") or "")[:300],
            folder=str(row.get("folder") or "")[:500],
            method=method,
            url=url,
            headers=_wire_headers(
                row.get("header_items")
                if row.get("header_items") is not None
                else row.get("headers")
            ),
            body=_body_bytes(row.get("body")),
            body_mode=str(row.get("body_mode") or "none")[:100],
            auth_type=str(row.get("auth_type") or "none")[:200],
            has_sensitive_material=bool(row.get("has_sensitive_material")),
        ))
    return ReplayPlan(
        requests=tuple(result),
        allowed_origins=origins,
        default_origin=resolved_default,
        authorization=authz,
    )


def build_selected_replay_plan(
    payload: Mapping[str, Any],
    selector: Any,
    *,
    allowed_origins: Iterable[Any],
    default_origin: str | None = None,
    authorization: ReplayAuthorization | None = None,
) -> ReplayPlan:
    """Resolve one encrypted collection selection directly into an exact replay plan.

    The import is lazy to keep parsing/indexing independent from the replay runtime and
    to avoid a module cycle. Decryption still happens only on the executing worker.
    """
    from .request_collections import select_requests

    selected = select_requests(payload, selector)
    selector_limit = int(getattr(selector, "limit", len(selected) or 1))
    return build_replay_plan(
        selected,
        allowed_origins=allowed_origins,
        default_origin=default_origin,
        authorization=authorization,
        limit=selector_limit,
    )


def bind_replay_credential_headers(
    plan: ReplayPlan,
    headers: Mapping[str, Any],
    *,
    auth_kind: str,
) -> ReplayPlan:
    """Replace captured principal headers with one worker-resolved profile.

    This function is worker-private: the returned plan contains wire values and must
    never cross a public API boundary.  Captured Authorization/Cookie material is
    always removed when a managed principal is selected, even when the new profile
    uses a different header name.
    """
    managed_headers = _wire_headers(headers)
    if not managed_headers:
        raise RequestReplayError("managed replay credential produced no HTTP headers")
    normalized_kind = str(auth_kind or "").strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", normalized_kind):
        raise RequestReplayError("managed replay credential auth kind is invalid")
    replaced_names = {name.lower() for name, _ in managed_headers}
    removed_names = replaced_names | {"authorization", "cookie"}
    bound_requests: list[ReplayRequest] = []
    for request in plan.requests:
        retained = tuple(
            (name, value)
            for name, value in request.headers
            if name.lower() not in removed_names
        )
        combined = (*retained, *managed_headers)
        if len(combined) > 100:
            raise RequestReplayError("managed replay request contains too many headers")
        bound_requests.append(replace(
            request,
            headers=combined,
            auth_type=f"managed:{normalized_kind}",
            has_sensitive_material=True,
        ))
    return replace(plan, requests=tuple(bound_requests))
