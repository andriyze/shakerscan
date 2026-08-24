"""Target-bound, worker-private HTTP credential session establishment."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
from html.parser import HTMLParser
import json
import re
from typing import Any, Awaitable, Callable, Mapping
import urllib.parse
import uuid

from capabilities.http import WorkerPrivateHTTPResponse, execute_bound_http_request
from runtime.models import TargetBinding

try:
    from scanner_tools.url_redaction import redact_path
except ModuleNotFoundError:
    from scanner.scanner_tools.url_redaction import redact_path


SESSION_AUTH_KINDS = frozenset({
    "form_login", "oauth_client_credentials", "oauth_password",
})
MAX_SESSION_FORM_BYTES = 16_384
MAX_SESSION_FIELDS = 50
DEFAULT_SESSION_TTL_SECONDS = 3_600
MIN_SESSION_TTL_SECONDS = 1
MAX_SESSION_TTL_SECONDS = 86_400
_FIELD_NAME = re.compile(r"^[^\x00-\x20\x7f]{1,120}$")
_COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,120}$")
_TOKEN_TYPE = re.compile(r"^[A-Za-z][A-Za-z0-9._~-]{0,39}$")
_USERNAME_FIELD = re.compile(
    r"(?:^|[-_.])(user(?:name)?|email|login|identifier|j_username)(?:$|[-_.])",
    re.IGNORECASE,
)
_ADDITIONAL_FACTOR_FIELD = re.compile(
    r"(?:^|[-_.])(?:mfa|otp|totp|one[-_.]?time|verification[-_.]?code)(?:$|[-_.])",
    re.IGNORECASE,
)
_SUCCESS_REDIRECTS = frozenset({301, 302, 303, 307, 308})


class SessionCredentialContractError(ValueError):
    """Interactive material or a target-derived login form exceeded its authority."""


@dataclass(frozen=True, repr=False)
class TargetBoundSessionCredential:
    lane: str
    auth_kind: str
    endpoint_url: str
    binding_digest: str
    username: str | None = field(default=None, repr=False)
    secret: str = field(default="", repr=False)
    client_id: str | None = field(default=None, repr=False)
    scopes: tuple[str, ...] = ()
    profile_id: str | None = None
    profile_version: int = 0
    principal: str | None = None
    compatible_capabilities: tuple[str, ...] = ()
    oauth_password_explicitly_allowed: bool = False

    def __repr__(self) -> str:
        return (
            "TargetBoundSessionCredential("
            f"lane={self.lane!r}, auth_kind={self.auth_kind!r}, "
            f"endpoint_configured={bool(self.endpoint_url)}, "
            f"scope_count={len(self.scopes)}, values_visible=False)"
        )


@dataclass(frozen=True, repr=False)
class WorkerPrivateScanSession:
    lane: str
    auth_kind: str
    binding_digest: str
    established: bool
    observation: Mapping[str, Any]
    error: str | None
    request_count: int
    _headers: Mapping[str, str] = field(repr=False)
    session_ref: str | None = None
    profile_id: str | None = None
    profile_version: int = 0
    principal: str | None = None
    established_at: datetime | None = None
    expires_at: datetime | None = None
    refresh_after: datetime | None = None
    compatible_capabilities: tuple[str, ...] = ()
    evidence_receipt_digest: str | None = None

    def __repr__(self) -> str:
        return (
            "WorkerPrivateScanSession("
            f"lane={self.lane!r}, auth_kind={self.auth_kind!r}, "
            f"established={self.established}, "
            f"header_names={sorted(self._headers)}, values_visible=False)"
        )

    def headers(self) -> dict[str, str]:
        return dict(self._headers)

    def close(self) -> None:
        """Best-effort clearing for worker-private identity material."""
        if isinstance(self._headers, dict):
            for name in list(self._headers):
                self._headers[name] = ""
            self._headers.clear()

    def execution_result(self) -> dict[str, Any]:
        return {
            "ok": self.established,
            "status": "success" if self.established else "failed",
            "error": self.error,
            "observation": dict(self.observation),
            "budget_consumed": {
                "http_requests": self.request_count,
                "tool_wall_seconds": 1 if self.request_count else 0,
            },
        }


SessionRequestExecutor = Callable[..., Awaitable[dict[str, Any]]]


class _LoginFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]],
    ) -> None:
        values = {str(name).lower(): str(value or "") for name, value in attrs}
        if tag.lower() == "form" and self._current is None:
            self._current = {
                "action": values.get("action", ""),
                "method": values.get("method", "POST").upper(),
                "inputs": [],
            }
        elif tag.lower() == "input" and self._current is not None:
            self._current["inputs"].append({
                "name": values.get("name", ""),
                "type": values.get("type", "text").lower(),
                "value": values.get("value", ""),
                "autocomplete": values.get("autocomplete", "").lower(),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def _validate_material(credential: TargetBoundSessionCredential) -> None:
    if credential.lane not in {"primary", "secondary"}:
        raise SessionCredentialContractError("session principal lane is invalid")
    if credential.auth_kind not in SESSION_AUTH_KINDS:
        raise SessionCredentialContractError("session credential kind is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", credential.binding_digest):
        raise SessionCredentialContractError("session credential binding is invalid")
    values = [
        credential.endpoint_url, credential.username or "", credential.secret,
        credential.client_id or "", *credential.scopes,
    ]
    if any(
        any(ord(character) < 32 or ord(character) == 127 for character in value)
        for value in values
    ):
        raise SessionCredentialContractError("session credential material is invalid")
    if not credential.endpoint_url or not credential.secret:
        raise SessionCredentialContractError("session credential material is incomplete")
    if credential.auth_kind == "form_login" and not credential.username:
        raise SessionCredentialContractError("form login requires a username")
    if credential.auth_kind == "oauth_client_credentials" and not credential.client_id:
        raise SessionCredentialContractError("OAuth client credentials require a client ID")
    if credential.auth_kind == "oauth_password" and not credential.username:
        raise SessionCredentialContractError("OAuth password flow requires a username")
    if (
        credential.auth_kind == "oauth_password"
        and not credential.oauth_password_explicitly_allowed
    ):
        raise SessionCredentialContractError(
            "OAuth password flow requires explicit profile authorization"
        )
    if credential.profile_version < 0:
        raise SessionCredentialContractError("session credential version is invalid")
    if credential.profile_id and credential.profile_version < 1:
        raise SessionCredentialContractError("session credential version is invalid")


def _endpoint_args(
    endpoint_url: str,
    *,
    target: TargetBinding,
    relative_to: str | None = None,
) -> tuple[str, str, str]:
    base_origin = (
        relative_to
        if relative_to is not None
        else target.allowed_origins[0] if target.allowed_origins else ""
    )
    candidate = urllib.parse.urljoin(base_origin.rstrip("/") + "/", endpoint_url)
    try:
        parsed = urllib.parse.urlsplit(candidate)
        _ = parsed.port
    except ValueError as exc:
        raise SessionCredentialContractError(
            "session endpoint has an invalid authority"
        ) from exc
    origin = urllib.parse.urlunsplit((
        parsed.scheme.lower(), parsed.netloc.lower(), "", "", "",
    ))
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.fragment
        or parsed.hostname.lower().rstrip(".") != target.canonical_host
        or origin not in target.allowed_origins
    ):
        raise SessionCredentialContractError(
            "session endpoint is outside the frozen target binding"
        )
    path = urllib.parse.urlunsplit((
        "", "", parsed.path or "/", parsed.query, "",
    ))
    public_path = urllib.parse.urlunsplit((
        "", "", redact_path(parsed.path or "/"),
        "<redacted-query>" if parsed.query else "", "",
    ))
    return origin, path, public_path


def _form_fields(html: str, page_url: str) -> tuple[str, str, dict[str, str]]:
    parser = _LoginFormParser()
    parser.feed(html)
    for form in parser.forms[:20]:
        inputs = [item for item in form.get("inputs") or [] if isinstance(item, dict)]
        password = next((
            str(item.get("name") or "") for item in inputs
            if item.get("type") == "password" and item.get("name")
        ), "")
        if not password:
            continue
        if any(
            item.get("type") != "hidden"
            and _ADDITIONAL_FACTOR_FIELD.search(str(item.get("name") or ""))
            for item in inputs
        ):
            raise SessionCredentialContractError(
                "target login form requires an unsupported additional factor"
            )
        username = next((
            str(item.get("name") or "") for item in inputs
            if item.get("name") and (
                item.get("type") == "email"
                or item.get("autocomplete") in {"username", "email"}
                or _USERNAME_FIELD.search(str(item.get("name") or ""))
            )
        ), "")
        if not username:
            continue
        fields: dict[str, str] = {}
        for item in inputs:
            name = str(item.get("name") or "")
            if item.get("type") != "hidden" or not name:
                continue
            if len(fields) >= MAX_SESSION_FIELDS or not _FIELD_NAME.fullmatch(name):
                raise SessionCredentialContractError("login form fields are invalid")
            value = str(item.get("value") or "")
            if any(ord(character) < 32 or ord(character) == 127 for character in value):
                raise SessionCredentialContractError("login form fields are invalid")
            fields[name] = value[:4_000]
        action = urllib.parse.urljoin(page_url, str(form.get("action") or page_url))
        method = str(form.get("method") or "POST").upper()
        if method != "POST":
            raise SessionCredentialContractError(
                "login form must submit credentials with POST"
            )
        if not _FIELD_NAME.fullmatch(username) or not _FIELD_NAME.fullmatch(password):
            raise SessionCredentialContractError("login form fields are invalid")
        return action, username, {**fields, "__password_field__": password}
    raise SessionCredentialContractError("target login form was not identified")


def _session_headers(
    response: WorkerPrivateHTTPResponse,
    *,
    inherited_cookies: Mapping[str, str] | None = None,
) -> tuple[dict[str, str], list[str]]:
    headers = response.headers()
    cookies = {**dict(inherited_cookies or {}), **response.cookies()}
    result: dict[str, str] = {}
    authorization = str(headers.get("authorization") or "").strip()
    if (
        authorization
        and authorization.isascii()
        and len(authorization.encode("ascii")) <= 8_192
        and not any(ord(character) < 32 or ord(character) == 127
                    for character in authorization)
    ):
        result["Authorization"] = authorization
    try:
        payload = json.loads(response.body().decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, dict) and isinstance(payload.get("access_token"), str):
        token = str(payload["access_token"])
        token_type = str(payload.get("token_type") or "Bearer")
        if (
            token
            and token.isascii()
            and len(token.encode("ascii")) <= 8_000
            and not any(ord(character) < 32 or ord(character) == 127
                        for character in token)
            and _TOKEN_TYPE.fullmatch(token_type)
        ):
            result["Authorization"] = f"{token_type} {token}"
    safe_cookies: dict[str, str] = {}
    for raw_name, raw_value in cookies.items():
        name, value = str(raw_name), str(raw_value)
        if (
            _COOKIE_NAME.fullmatch(name)
            and value
            and value.isascii()
            and len(value.encode("ascii")) <= 8_192
            and ";" not in value
            and not any(ord(character) < 32 or ord(character) == 127
                        for character in value)
        ):
            safe_cookies[name] = value
    if safe_cookies:
        cookie_header = "; ".join(
            f"{name}={safe_cookies[name]}" for name in sorted(safe_cookies)
        )
        if len(cookie_header.encode("ascii")) <= 8_192:
            result["Cookie"] = cookie_header
        else:
            safe_cookies = {}
    return result, sorted(safe_cookies)


def _session_timing(
    response: WorkerPrivateHTTPResponse,
    *,
    now: datetime,
) -> tuple[datetime, datetime]:
    """Return bounded expiry/refresh times without retaining token response values."""
    ttl = DEFAULT_SESSION_TTL_SECONDS
    try:
        payload = json.loads(response.body().decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    supplied_ttl = False
    if isinstance(payload, Mapping):
        raw_ttl = payload.get("expires_in")
        if isinstance(raw_ttl, (int, float)) and not isinstance(raw_ttl, bool):
            ttl = int(raw_ttl)
            supplied_ttl = True
        elif isinstance(raw_ttl, str) and raw_ttl.strip().isdigit():
            ttl = int(raw_ttl.strip())
            supplied_ttl = True
    if supplied_ttl and ttl <= 0:
        raise SessionCredentialContractError(
            "session exchange returned an expired identity"
        )
    ttl = max(MIN_SESSION_TTL_SECONDS, min(MAX_SESSION_TTL_SECONDS, ttl))
    expires_at = now + timedelta(seconds=ttl)
    refresh_lead = min(ttl, max(1, min(300, ttl // 10)))
    return expires_at, expires_at - timedelta(seconds=refresh_lead)


def _session_evidence_digest(observation: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(
        dict(observation), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


def _bounded_form_size(value: Mapping[str, Any]) -> None:
    encoded = urllib.parse.urlencode({str(key): str(item) for key, item in value.items()})
    if len(encoded.encode("utf-8")) > MAX_SESSION_FORM_BYTES:
        raise SessionCredentialContractError("session request body exceeds its limit")


def _public_observation(
    credential: TargetBoundSessionCredential,
    *,
    public_path: str,
    established: bool,
    headers: Mapping[str, str],
    cookie_names: list[str],
    response_status: int | None,
    request_count: int,
    reason: str | None,
) -> dict[str, Any]:
    return {
        "kind": "credential_session",
        "lane": credential.lane,
        "auth_kind": credential.auth_kind,
        "status": "established" if established else "failed",
        "endpoint_path": public_path,
        "response_status": response_status,
        "request_count": request_count,
        "header_names": sorted(headers),
        "cookie_names": cookie_names,
        "reason": reason,
        "secret_values_visible": False,
    }


async def establish_target_bound_http_session(
    credential: TargetBoundSessionCredential,
    *,
    target: TargetBinding,
    request_executor: SessionRequestExecutor = execute_bound_http_request,
    now: datetime | None = None,
    session_ref: str | None = None,
) -> WorkerPrivateScanSession:
    """Perform one explicit, pinned form/OAuth exchange and retain values in memory."""
    _validate_material(credential)
    origin, endpoint_path, public_path = _endpoint_args(
        credential.endpoint_url, target=target,
    )
    request_count = 0
    latest: WorkerPrivateHTTPResponse | None = None
    established_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    def capture(response: WorkerPrivateHTTPResponse) -> None:
        nonlocal latest
        latest = response

    try:
        inherited_cookies: dict[str, str] = {}
        if credential.auth_kind == "form_login":
            get_result = await request_executor(
                origin,
                {"method": "GET", "path": endpoint_path},
                target=target,
                allow_write=False,
                timeout_seconds=15,
                private_response_sink=capture,
                principal_slot=credential.lane,
            )
            request_count += 1 if isinstance(get_result.get("request"), Mapping) else 0
            if not get_result.get("ok") or latest is None or latest.status_code != 200:
                raise SessionCredentialContractError("login page request failed")
            page = latest
            inherited_cookies = page.cookies()
            page_url = urllib.parse.urljoin(origin + "/", endpoint_path.lstrip("/"))
            action, username_field, form = _form_fields(
                page.body().decode("utf-8", errors="replace"), page_url,
            )
            password_field = form.pop("__password_field__")
            form[username_field] = str(credential.username)
            form[password_field] = credential.secret
            _bounded_form_size(form)
            action_origin, action_path, _public_action = _endpoint_args(
                action, target=target, relative_to=origin,
            )
            latest = None
            post_result = await request_executor(
                action_origin,
                {"method": "POST", "path": action_path, "form_body": form},
                target=target,
                allow_write=True,
                cookies=inherited_cookies,
                timeout_seconds=15,
                private_response_sink=capture,
                principal_slot=credential.lane,
            )
            request_count += 1 if isinstance(post_result.get("request"), Mapping) else 0
        else:
            form = {
                "grant_type": (
                    "client_credentials"
                    if credential.auth_kind == "oauth_client_credentials"
                    else "password"
                ),
            }
            if credential.client_id:
                form["client_id"] = credential.client_id
            if credential.auth_kind == "oauth_client_credentials":
                form["client_secret"] = credential.secret
            else:
                form["username"] = str(credential.username)
                form["password"] = credential.secret
            if credential.scopes:
                form["scope"] = " ".join(credential.scopes)
            _bounded_form_size(form)
            post_result = await request_executor(
                origin,
                {"method": "POST", "path": endpoint_path, "form_body": form},
                target=target,
                allow_write=True,
                trusted_headers={"Accept": "application/json"},
                timeout_seconds=15,
                private_response_sink=capture,
                principal_slot=credential.lane,
            )
            request_count += 1 if isinstance(post_result.get("request"), Mapping) else 0
        if not post_result.get("ok") or latest is None:
            raise SessionCredentialContractError("session exchange request failed")
        response_identity, _response_cookie_names = _session_headers(latest)
        headers, cookie_names = _session_headers(
            latest, inherited_cookies=inherited_cookies,
        )
        acceptable_status = (
            200 <= latest.status_code < 300
            or latest.status_code in _SUCCESS_REDIRECTS
        )
        if not acceptable_status or not headers or not response_identity:
            raise SessionCredentialContractError(
                "session exchange produced no usable identity"
            )
        observation = _public_observation(
            credential,
            public_path=public_path,
            established=True,
            headers=headers,
            cookie_names=cookie_names,
            response_status=latest.status_code,
            request_count=request_count,
            reason=None,
        )
        expires_at, refresh_after = _session_timing(
            latest, now=established_at,
        )
        opaque_session_ref = str(session_ref or uuid.uuid4())
        try:
            uuid.UUID(opaque_session_ref)
        except (TypeError, ValueError, AttributeError) as exc:
            raise SessionCredentialContractError(
                "session reference is invalid"
            ) from exc
        principal = credential.principal or credential.lane
        observation.update({
            "session_ref": opaque_session_ref,
            "profile_id": credential.profile_id,
            "profile_version": credential.profile_version or None,
            "principal": principal,
            "established_at": established_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "refresh_after": refresh_after.isoformat(),
            "compatible_capabilities": sorted(
                set(credential.compatible_capabilities)
            ),
        })
        evidence_digest = _session_evidence_digest(observation)
        observation["evidence_receipt_digest"] = evidence_digest
        return WorkerPrivateScanSession(
            lane=credential.lane,
            auth_kind=credential.auth_kind,
            binding_digest=credential.binding_digest,
            established=True,
            observation=observation,
            error=None,
            request_count=request_count,
            _headers=headers,
            session_ref=opaque_session_ref,
            profile_id=credential.profile_id,
            profile_version=credential.profile_version,
            principal=principal,
            established_at=established_at,
            expires_at=expires_at,
            refresh_after=refresh_after,
            compatible_capabilities=tuple(sorted(
                set(credential.compatible_capabilities)
            )),
            evidence_receipt_digest=evidence_digest,
        )
    except SessionCredentialContractError as exc:
        reason = str(exc)
        observation = _public_observation(
            credential,
            public_path=public_path,
            established=False,
            headers={},
            cookie_names=[],
            response_status=latest.status_code if latest is not None else None,
            request_count=request_count,
            reason=reason,
        )
        return WorkerPrivateScanSession(
            lane=credential.lane,
            auth_kind=credential.auth_kind,
            binding_digest=credential.binding_digest,
            established=False,
            observation=observation,
            error=reason,
            request_count=request_count,
            _headers={},
        )
