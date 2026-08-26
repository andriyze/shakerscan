"""Canonical generic credential admission and worker-private Scan binding."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
import urllib.parse
from typing import Any, Mapping, Sequence

from .credential_resolver import CredentialResolutionError, ResolvedCredential
from .credential_store import CredentialProfileMetadata
from .credentials import HTTP_CREDENTIAL_KINDS, IMMEDIATE_HTTP_HEADER_KINDS


SCAN_CREDENTIAL_CAPABILITY = "scan.execute"
SCAN_SEMANTIC_CREDENTIAL_CAPABILITIES = frozenset({
    "auth.session.establish",
    "http.request",
    "web.probe",
    "web.crawl",
    "web.content_discover",
    "templates.passive_scan",
    "templates.scan",
    "templates.passive_batch",
    "templates.active_batch",
    "collections.replay_safe",
    "collections.replay_authentication",
    "collections.replay_active",
    "xss.verify",
    "sqli.verify",
    "xss.verify_batch",
    "sqli.verify_batch",
    "authz.verify",
    "xss.request_verify",
    "sqli.request_verify",
    "xss.request_verify_batch",
    "sqli.request_verify_batch",
})
_INTERACTIVE_HTTP_KINDS = frozenset({
    "form_login", "oauth_client_credentials", "oauth_password",
})
MAX_SCAN_CREDENTIAL_PROFILES = 2
_PRIMARY_SLOTS = frozenset({"primary", "service"})
_SECONDARY_KINDS = frozenset({
    "authorization_header",
    "bearer_token",
    "cookie",
    "basic_auth",
    "form_login",
})


class ScanCredentialError(ValueError):
    """A Scan credential selection is ambiguous, unsupported, or no longer valid."""


def scan_credential_resolution_capability(
    allowed_capabilities: Sequence[str], *, auth_kind: str,
) -> str | None:
    """Select one semantic custody receipt without expanding profile authority."""
    allowed = tuple(dict.fromkeys(
        str(item or "").strip() for item in allowed_capabilities if str(item or "").strip()
    ))
    if not allowed:
        return (
            "auth.session.establish"
            if auth_kind in _INTERACTIVE_HTTP_KINDS else "http.request"
        )
    if SCAN_CREDENTIAL_CAPABILITY in allowed:
        return SCAN_CREDENTIAL_CAPABILITY
    if auth_kind in _INTERACTIVE_HTTP_KINDS:
        return (
            "auth.session.establish"
            if "auth.session.establish" in allowed else None
        )
    compatible = sorted(set(allowed) & SCAN_SEMANTIC_CREDENTIAL_CAPABILITIES)
    return compatible[0] if compatible else None


def scan_credential_allows_capability(
    allowed_capabilities: Sequence[str], capability_name: str,
) -> bool:
    """Apply a profile's semantic allowlist at the actual action boundary."""
    allowed = {
        str(item or "").strip() for item in allowed_capabilities if str(item or "").strip()
    }
    return (
        not allowed
        or SCAN_CREDENTIAL_CAPABILITY in allowed
        or str(capability_name or "").strip() in allowed
    )


@dataclass(frozen=True, repr=False)
class ScanHTTPPrincipal:
    """Worker-private immediate HTTP identity with content-free public metadata."""

    lane: str
    _headers: Mapping[str, str] = field(repr=False)
    binding_digest: str | None
    source: str
    reason: str | None = None
    profile_reference_count: int = 0

    def __repr__(self) -> str:
        return (
            f"ScanHTTPPrincipal(lane={self.lane!r}, source={self.source!r}, "
            f"header_names={sorted(self._headers)}, authenticated={self.authenticated}, "
            "values_visible=False)"
        )

    @property
    def authenticated(self) -> bool:
        return bool(self._headers and self.binding_digest)

    def headers(self) -> dict[str, str]:
        return dict(self._headers)

    def capability_args(self) -> dict[str, str]:
        if not self.authenticated or not self.binding_digest:
            return {}
        return {
            "as_principal": self.lane,
            "principal_binding_digest": self.binding_digest,
        }

    def public_dict(self) -> dict[str, Any]:
        return {
            "lane": self.lane,
            "authenticated": self.authenticated,
            "source": self.source,
            "reason": self.reason,
            "header_names": sorted(self._headers),
            "profile_reference_count": self.profile_reference_count,
            "secret_values_visible": False,
        }


@dataclass(frozen=True, repr=False)
class ScanInteractiveCredential:
    """Worker-private form/OAuth material plus content-free action binding."""

    lane: str
    auth_kind: str
    endpoint_url: str
    binding_digest: str
    endpoint_binding_digest: str
    public_endpoint_path: str
    source: str
    profile_reference_count: int
    profile_id: str | None
    profile_version: int
    principal: str
    allowed_capabilities: tuple[str, ...]
    _username: str | None = field(default=None, repr=False)
    _secret: str = field(default="", repr=False)
    _client_id: str | None = field(default=None, repr=False)
    _scopes: tuple[str, ...] = field(default=(), repr=False)

    def __repr__(self) -> str:
        return (
            "ScanInteractiveCredential("
            f"lane={self.lane!r}, auth_kind={self.auth_kind!r}, "
            f"endpoint_path={self.public_endpoint_path!r}, "
            f"profile_reference_count={self.profile_reference_count}, "
            "values_visible=False)"
        )

    def capability_args(self) -> dict[str, str]:
        return {
            "lane": self.lane,
            "auth_kind": self.auth_kind,
            "credential_binding_digest": self.binding_digest,
            "endpoint_binding_digest": self.endpoint_binding_digest,
            "endpoint_path": self.public_endpoint_path,
        }

    def session_credential(self):
        from capabilities.auth import TargetBoundSessionCredential

        return TargetBoundSessionCredential(
            lane=self.lane,
            auth_kind=self.auth_kind,
            endpoint_url=self.endpoint_url,
            binding_digest=self.binding_digest,
            username=self._username,
            secret=self._secret,
            client_id=self._client_id,
            scopes=self._scopes,
            profile_id=self.profile_id,
            profile_version=self.profile_version,
            principal=self.principal,
            compatible_capabilities=self.allowed_capabilities,
            oauth_password_explicitly_allowed=(
                self.auth_kind == "oauth_password"
                and self.source == "credential_profiles"
            ),
        )

    def public_dict(self) -> dict[str, Any]:
        return {
            "lane": self.lane,
            "auth_kind": self.auth_kind,
            "endpoint_path": self.public_endpoint_path,
            "source": self.source,
            "profile_reference_count": self.profile_reference_count,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version or None,
            "principal": self.principal,
            "compatible_capabilities": list(self.allowed_capabilities),
            "secret_values_visible": False,
        }

_HTTP_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,120}$")
_RESERVED_HTTP_HEADERS = frozenset({
    "connection", "content-length", "host", "transfer-encoding",
})


def _safe_scan_http_headers(values: Mapping[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    normalized_names: set[str] = set()
    for raw_name, raw_value in values.items():
        name = str(raw_name or "").strip()
        value = str(raw_value or "")
        normalized_name = name.lower()
        if (
            not _HTTP_HEADER_NAME.fullmatch(name)
            or normalized_name in _RESERVED_HTTP_HEADERS
            or normalized_name in normalized_names
            or not value
            or not value.isascii()
            or len(value.encode("ascii")) > 8_192
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in value
            )
        ):
            raise ScanCredentialError("Scan HTTP credential headers are invalid")
        normalized_names.add(normalized_name)
        headers[name] = value
    return headers


def resolve_scan_http_principal(
    options: Mapping[str, Any], *, lane: str = "primary",
    capability_name: str | None = None,
) -> ScanHTTPPrincipal:
    """Resolve an already-hydrated immediate identity without exposing its values."""
    normalized_lane = str(lane or "").strip().lower()
    if normalized_lane not in {"primary", "secondary"}:
        raise ScanCredentialError("Scan HTTP principal lane is invalid")
    headers: dict[str, Any] = {}
    if normalized_lane == "primary":
        if options.get("auth_header"):
            headers["Authorization"] = options["auth_header"]
        if options.get("auth_cookies"):
            headers["Cookie"] = options["auth_cookies"]
        raw_custom = options.get("auth_headers_json")
        if raw_custom:
            try:
                custom = json.loads(str(raw_custom))
            except json.JSONDecodeError as exc:
                raise ScanCredentialError(
                    "Scan custom authentication headers are invalid"
                ) from exc
            if not isinstance(custom, dict):
                raise ScanCredentialError(
                    "Scan custom authentication headers must be an object"
                )
            headers.update(custom)
        interactive = any(options.get(key) for key in (
            "login_username", "login_password", "oauth_client_id",
            "oauth_client_secret", "oauth_username", "oauth_password",
        ))
    else:
        if options.get("user2_header"):
            headers["Authorization"] = options["user2_header"]
        if options.get("user2_cookies"):
            headers["Cookie"] = options["user2_cookies"]
        interactive = any(options.get(key) for key in (
            "user2_login_username", "user2_login_password",
        ))

    safe_headers = _safe_scan_http_headers(headers) if headers else {}
    refs = []
    lane_refs = []
    for item in options.get("resolved_credential_profiles") or []:
        if not isinstance(item, Mapping):
            continue
        item_lane = str(item.get("scan_lane") or "").strip().lower()
        auth_state = str(item.get("auth_state") or "").strip().lower()
        lane_matches = (
            item_lane == normalized_lane
            or (normalized_lane == "primary" and auth_state == "user1")
            or (normalized_lane == "secondary" and auth_state == "user2")
        )
        if not lane_matches:
            continue
        lane_refs.append(item)
        if capability_name and not scan_credential_allows_capability(
            item.get("allowed_capabilities") or (), capability_name,
        ):
            continue
        refs.append({
            "profile_id": str(item.get("profile_id") or ""),
            "profile_version": int(item.get("profile_version") or 0),
            "auth_kind": str(item.get("auth_kind") or ""),
            "principal_slot": str(item.get("principal_slot") or ""),
            "principal_label": str(item.get("principal_label") or "") or None,
            "lane": normalized_lane,
            "allowed_capabilities": sorted(
                str(value) for value in item.get("allowed_capabilities") or ()
                if str(value)
            ),
        })
    capability_denied = bool(capability_name and lane_refs and not refs)
    if capability_denied:
        safe_headers = {}
    binding = {
        "schema_version": "scan-http-principal-binding/v1",
        "lane": normalized_lane,
        "profile_references": sorted(
            refs, key=lambda item: (item["profile_id"], item["profile_version"]),
        ),
        "header_names": sorted(name.lower() for name in safe_headers),
        "source": "credential_profiles" if refs else "legacy_worker_private",
        "capability_name": str(capability_name or "") or None,
    }
    digest = (
        hashlib.sha256(json.dumps(
            binding, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        if safe_headers else None
    )
    reason = "credential_capability_not_allowed" if capability_denied else None
    source = binding["source"] if safe_headers else "anonymous"
    if interactive and not safe_headers and not capability_denied:
        source = "interactive_profile"
        reason = "interactive_session_not_established"
    return ScanHTTPPrincipal(
        lane=normalized_lane,
        _headers=safe_headers,
        binding_digest=digest,
        source=source,
        reason=reason,
        profile_reference_count=len(refs),
    )


def _public_session_endpoint_path(endpoint_url: str) -> str:
    parsed = urllib.parse.urlsplit(endpoint_url)
    path = parsed.path or "/"
    # Endpoint route structure is useful, but query values can be credentials.
    try:
        from scanner_tools.url_redaction import redact_path
    except ModuleNotFoundError:
        from scanner.scanner_tools.url_redaction import redact_path
    return urllib.parse.urlunsplit((
        "", "", redact_path(path),
        "<redacted-query>" if parsed.query else "", "",
    ))


def resolve_scan_interactive_credential(
    options: Mapping[str, Any], *, lane: str = "primary",
    capability_name: str | None = None,
) -> ScanInteractiveCredential | None:
    """Resolve hydrated form/OAuth values into one worker-private session contract."""
    normalized_lane = str(lane or "").strip().lower()
    if normalized_lane not in {"primary", "secondary"}:
        raise ScanCredentialError("Scan interactive credential lane is invalid")
    candidates: list[dict[str, Any]] = []
    endpoint_key = (
        "user2_login_url" if normalized_lane == "secondary" else "login_url"
    )
    endpoint = str(
        options.get(endpoint_key) or options.get("login_url") or ""
    ).strip()
    if normalized_lane == "primary":
        if options.get("login_username") or options.get("login_password"):
            candidates.append({
                "auth_kind": "form_login",
                "username": options.get("login_username"),
                "secret": options.get("login_password"),
                "client_id": None,
                "scopes": (),
                "endpoint_url": endpoint,
            })
        oauth_endpoint = str(options.get("oauth_token_url") or "").strip()
        if options.get("oauth_client_secret"):
            candidates.append({
                "auth_kind": "oauth_client_credentials",
                "username": None,
                "secret": options.get("oauth_client_secret"),
                "client_id": options.get("oauth_client_id"),
                "scopes": tuple(str(options.get("oauth_scope") or "").split()),
                "endpoint_url": oauth_endpoint,
            })
        if options.get("oauth_username") or options.get("oauth_password"):
            candidates.append({
                "auth_kind": "oauth_password",
                "username": options.get("oauth_username"),
                "secret": options.get("oauth_password"),
                "client_id": options.get("oauth_client_id"),
                "scopes": tuple(str(options.get("oauth_scope") or "").split()),
                "endpoint_url": oauth_endpoint,
            })
    elif options.get("user2_login_username") or options.get("user2_login_password"):
        candidates.append({
            "auth_kind": "form_login",
            "username": options.get("user2_login_username"),
            "secret": options.get("user2_login_password"),
            "client_id": None,
            "scopes": (),
            "endpoint_url": endpoint,
        })
    if not candidates:
        return None
    if len(candidates) != 1:
        raise ScanCredentialError(
            "Scan interactive credential selects multiple session flows"
        )
    selected = candidates[0]
    if not selected["username"] and selected["auth_kind"] in {
        "form_login", "oauth_password",
    }:
        raise ScanCredentialError("Scan interactive credential username is missing")
    if not selected["secret"] or not selected["endpoint_url"]:
        raise ScanCredentialError("Scan interactive credential material is incomplete")
    if (
        selected["auth_kind"] == "oauth_client_credentials"
        and not selected["client_id"]
    ):
        raise ScanCredentialError("OAuth Scan credential requires a client ID")

    refs: list[dict[str, Any]] = []
    lane_refs: list[Mapping[str, Any]] = []
    for item in options.get("resolved_credential_profiles") or []:
        if not isinstance(item, Mapping):
            continue
        item_lane = str(item.get("scan_lane") or "").strip().lower()
        auth_state = str(item.get("auth_state") or "").strip().lower()
        lane_matches = (
            item_lane == normalized_lane
            or (normalized_lane == "primary" and auth_state == "user1")
            or (normalized_lane == "secondary" and auth_state == "user2")
        )
        if not lane_matches:
            continue
        lane_refs.append(item)
        if capability_name and not scan_credential_allows_capability(
            item.get("allowed_capabilities") or (), capability_name,
        ):
            continue
        refs.append({
            "profile_id": str(item.get("profile_id") or ""),
            "profile_version": int(item.get("profile_version") or 0),
            "auth_kind": str(item.get("auth_kind") or ""),
            "principal_slot": str(item.get("principal_slot") or ""),
            "principal_label": str(item.get("principal_label") or "") or None,
            "lane": normalized_lane,
            "allowed_capabilities": sorted(
                str(value) for value in item.get("allowed_capabilities") or ()
                if str(value)
            ),
        })
    if capability_name and lane_refs and not refs:
        return None
    if len(refs) > 1:
        raise ScanCredentialError(
            "Scan session principal resolves to more than one profile"
        )
    ref_kinds = {item["auth_kind"] for item in refs if item["auth_kind"]}
    if ref_kinds and ref_kinds != {selected["auth_kind"]}:
        raise ScanCredentialError(
            "hydrated Scan session kind does not match its profile reference"
        )
    endpoint_binding_digest = hashlib.sha256(
        str(selected["endpoint_url"]).encode("utf-8")
    ).hexdigest()
    binding = {
        "schema_version": "scan-interactive-credential-binding/v1",
        "lane": normalized_lane,
        "auth_kind": selected["auth_kind"],
        "endpoint_binding_digest": endpoint_binding_digest,
        "profile_references": sorted(
            refs, key=lambda item: (item["profile_id"], item["profile_version"]),
        ),
        "source": "credential_profiles" if refs else "legacy_worker_private",
    }
    binding_digest = hashlib.sha256(json.dumps(
        binding, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    profile_ref = refs[0] if refs else {}
    principal = str(
        profile_ref.get("principal_label")
        or profile_ref.get("principal_slot")
        or normalized_lane
    )
    return ScanInteractiveCredential(
        lane=normalized_lane,
        auth_kind=str(selected["auth_kind"]),
        endpoint_url=str(selected["endpoint_url"]),
        binding_digest=binding_digest,
        endpoint_binding_digest=endpoint_binding_digest,
        public_endpoint_path=_public_session_endpoint_path(
            str(selected["endpoint_url"]),
        ),
        source=str(binding["source"]),
        profile_reference_count=len(refs),
        profile_id=str(profile_ref.get("profile_id") or "") or None,
        profile_version=int(profile_ref.get("profile_version") or 0),
        principal=principal,
        allowed_capabilities=tuple(
            str(item) for item in profile_ref.get("allowed_capabilities") or ()
            if str(item)
        ),
        _username=(
            str(selected["username"]) if selected["username"] is not None else None
        ),
        _secret=str(selected["secret"]),
        _client_id=(
            str(selected["client_id"]) if selected["client_id"] is not None else None
        ),
        _scopes=tuple(str(item) for item in selected["scopes"]),
    )


def bind_scan_session_headers(
    options: Mapping[str, Any], headers: Mapping[str, Any], *, lane: str,
) -> dict[str, Any]:
    """Project established session values into worker-private Scan options."""
    normalized_lane = str(lane or "").strip().lower()
    safe_headers = _safe_scan_http_headers(headers)
    lowered = {name.lower(): name for name in safe_headers}
    result = dict(options)
    if normalized_lane == "secondary":
        if set(lowered) == {"authorization"}:
            result["user2_header"] = safe_headers[lowered["authorization"]]
        elif set(lowered) == {"cookie"}:
            result["user2_cookies"] = safe_headers[lowered["cookie"]]
        else:
            raise ScanCredentialError(
                "secondary Scan session must resolve to Authorization or Cookie"
            )
    elif normalized_lane == "primary":
        result.pop("auth_header", None)
        result.pop("auth_cookies", None)
        result.pop("auth_headers_json", None)
        if set(lowered) == {"authorization"}:
            result["auth_header"] = safe_headers[lowered["authorization"]]
        elif set(lowered) == {"cookie"}:
            result["auth_cookies"] = safe_headers[lowered["cookie"]]
        else:
            result["auth_headers_json"] = json.dumps(
                safe_headers, sort_keys=True, separators=(",", ":"),
            )
    else:
        raise ScanCredentialError("Scan session principal lane is invalid")
    return result


def admit_scan_credential_profiles(
    profile_ids: Sequence[Any],
    profiles: Sequence[CredentialProfileMetadata],
    *,
    target_id: Any,
    target_kind: str,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Freeze content-free profile/version references for one Scan."""
    requested = [str(value or "").strip() for value in profile_ids]
    if not requested or any(not value for value in requested):
        return []
    if len(requested) > MAX_SCAN_CREDENTIAL_PROFILES:
        raise ScanCredentialError(
            f"Scan accepts at most {MAX_SCAN_CREDENTIAL_PROFILES} credential profiles"
        )
    if len(requested) != len(set(requested)):
        raise ScanCredentialError("Scan credential profile IDs must be distinct")
    normalized_kind = str(target_kind or "").strip().lower()
    if normalized_kind not in {"web", "api"}:
        raise ScanCredentialError("Scan credential target kind must be web or api")
    normalized_target_id = str(target_id or "").strip()
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ScanCredentialError("Scan credential validation time must be timezone-aware")

    by_id = {profile.profile_id: profile for profile in profiles}
    rows: list[dict[str, Any]] = []
    lanes: set[str] = set()
    for profile_id in requested:
        profile = by_id.get(profile_id)
        if profile is None:
            raise ScanCredentialError(
                "Scan credential profile is unavailable or bound to another target"
            )
        expires_at = profile.expires_at
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if not profile.is_active or (expires_at is not None and expires_at <= current):
            raise ScanCredentialError("Scan credential profile is inactive or expired")
        if profile.target_id != normalized_target_id or profile.target_kind != normalized_kind:
            raise ScanCredentialError("Scan credential profile target binding does not match")
        if profile.auth_kind not in HTTP_CREDENTIAL_KINDS:
            raise ScanCredentialError("Scan credentials must use an HTTP authentication kind")
        if profile.auth_kind == "query_parameter":
            raise ScanCredentialError(
                "query-parameter credentials require the target-bound request replay executor"
            )
        slot = profile.principal_slot
        if slot in _PRIMARY_SLOTS:
            lane = "primary"
        elif slot == "secondary":
            lane = "secondary"
        else:
            raise ScanCredentialError("Scan credentials must use primary, secondary, or service slots")
        if lane in lanes:
            raise ScanCredentialError(f"Scan has more than one {lane} credential profile")
        if lane == "secondary" and profile.auth_kind not in _SECONDARY_KINDS:
            raise ScanCredentialError(
                f"secondary Scan identity does not support {profile.auth_kind}"
            )
        if (
            profile.auth_kind == "oauth_password"
            and not bool(profile.configuration.get("client_id_configured"))
        ):
            raise ScanCredentialError("OAuth password Scan credentials require a client ID")
        allowed = tuple(profile.allowed_capabilities)
        resolution_capability = scan_credential_resolution_capability(
            allowed, auth_kind=profile.auth_kind,
        )
        if resolution_capability is None:
            raise ScanCredentialError(
                "Scan credential profile does not allow a compatible semantic capability"
            )
        lanes.add(lane)
        rows.append({
            "profile_id": profile.profile_id,
            "profile_version": profile.current_version,
            "target_kind": profile.target_kind,
            "principal_slot": slot,
            "scan_lane": lane,
            "auth_kind": profile.auth_kind,
            "principal_label": profile.principal_label,
            "allowed_capabilities": list(allowed),
            "credential_resolution_capability": resolution_capability,
            "source": "credential_profiles",
            "secret_values_visible": False,
        })
    return rows


def bind_resolved_scan_credential(
    options: Mapping[str, Any],
    resolved: ResolvedCredential,
    *,
    scan_lane: str,
) -> dict[str, Any]:
    """Project a worker-private resolved profile into the legacy scanner handoff."""
    lane = str(scan_lane or "").strip().lower()
    if lane not in {"primary", "secondary"}:
        raise ScanCredentialError("resolved Scan credential lane is invalid")
    kind = resolved.profile.auth_kind
    result = dict(options)

    if kind in IMMEDIATE_HTTP_HEADER_KINDS:
        headers = resolved.http_headers().as_dict()
        lowered = {name.lower(): name for name in headers}
        if lane == "secondary":
            if set(lowered) == {"authorization"}:
                result["user2_header"] = headers[lowered["authorization"]]
            elif set(lowered) == {"cookie"}:
                result["user2_cookies"] = headers[lowered["cookie"]]
            else:
                raise ScanCredentialError(
                    "secondary Scan credentials must resolve to Authorization or Cookie"
                )
        elif set(lowered) == {"authorization"}:
            result["auth_header"] = headers[lowered["authorization"]]
        elif set(lowered) == {"cookie"}:
            result["auth_cookies"] = headers[lowered["cookie"]]
        else:
            result["auth_headers_json"] = json.dumps(
                headers, sort_keys=True, separators=(",", ":")
            )
        return result

    interactive = resolved.interactive_http()
    if kind == "form_login":
        if lane == "secondary":
            result["user2_login_username"] = interactive.username
            result["user2_login_password"] = interactive.secret
            result["user2_login_url"] = interactive.endpoint_url
        else:
            result["login_username"] = interactive.username
            result["login_password"] = interactive.secret
            result["auto_auth"] = True
            result["login_url"] = interactive.endpoint_url
        return result

    if lane == "secondary":
        raise ScanCredentialError("secondary Scan credentials cannot use OAuth exchange")
    if not interactive.client_id:
        raise CredentialResolutionError("OAuth Scan credential requires a client ID")
    result["oauth_client_id"] = interactive.client_id
    result["oauth_client_secret"] = (
        interactive.secret if kind == "oauth_client_credentials" else None
    )
    result["oauth_username"] = interactive.username if kind == "oauth_password" else None
    result["oauth_password"] = interactive.secret if kind == "oauth_password" else None
    result["oauth_token_url"] = interactive.endpoint_url
    result["oauth_scope"] = " ".join(interactive.scopes)
    return result
