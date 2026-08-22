"""Canonical encrypted credential material for Scan and Hunt workers.

Public control-plane objects carry only profile IDs and non-secret configuration flags.
This module validates the plaintext envelope immediately before encryption and again
after worker-only decryption.  It never performs network login or token exchange; those
actions remain target-bound executable capabilities with their own budget and receipt.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Mapping, Sequence
import urllib.parse


CREDENTIAL_SECRET_SCHEMA = "credential-secret/v2"
HTTP_CREDENTIAL_KINDS = frozenset({
    "authorization_header",
    "bearer_token",
    "api_key_header",
    "cookie",
    "basic_auth",
    "form_login",
    "oauth_client_credentials",
    "oauth_password",
    "custom_headers",
    "query_parameter",
})
SSH_CREDENTIAL_KINDS = frozenset({
    "ssh_password",
    "ssh_private_key",
    "ssh_private_key_with_passphrase",
})
CREDENTIAL_KINDS = HTTP_CREDENTIAL_KINDS | SSH_CREDENTIAL_KINDS
IMMEDIATE_HTTP_HEADER_KINDS = frozenset({
    "authorization_header", "bearer_token", "api_key_header", "cookie",
    "basic_auth", "custom_headers",
})
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,200}$")
_FORBIDDEN_HEADERS = frozenset({
    "host", "content-length", "connection", "transfer-encoding",
    "proxy-authorization", "proxy-connection", "keep-alive", "te", "trailer", "upgrade",
})


class CredentialContractError(ValueError):
    """Credential material is incomplete or unsafe for worker execution."""


def _text(
    value: Any,
    *,
    name: str,
    required: bool = False,
    maximum: int = 65_536,
    allow_lines: bool = False,
) -> str | None:
    normalized = str(value or "")
    if allow_lines:
        if not normalized.strip():
            normalized = ""
    else:
        normalized = normalized.strip()
    if not normalized:
        if required:
            raise CredentialContractError(f"{name} is required")
        return None
    if len(normalized.encode("utf-8")) > maximum:
        raise CredentialContractError(f"{name} exceeds its encrypted profile limit")
    if not allow_lines and ("\r" in normalized or "\n" in normalized):
        raise CredentialContractError(f"{name} cannot contain line breaks")
    return normalized


def _header_name(
    value: Any, *, required: bool, field_name: str = "header_name"
) -> str | None:
    name = _text(value, name=field_name, required=required, maximum=200)
    if name is None:
        return None
    if not _HEADER_NAME_RE.fullmatch(name) or name.lower() in _FORBIDDEN_HEADERS:
        raise CredentialContractError(f"{field_name} is not allowed")
    return name


def _endpoint(value: Any, *, name: str, required: bool) -> str | None:
    endpoint = _text(value, name=name, required=required, maximum=2_000)
    if endpoint is None:
        return None
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        _ = parsed.port
    except ValueError as exc:
        raise CredentialContractError(f"{name} has an invalid authority") from exc
    if parsed.fragment or parsed.username is not None or parsed.password is not None:
        raise CredentialContractError(f"{name} cannot contain userinfo or a fragment")
    if parsed.scheme or parsed.netloc:
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise CredentialContractError(f"{name} must use HTTP or HTTPS")
    elif not endpoint.startswith("/") or endpoint.startswith("//"):
        raise CredentialContractError(f"{name} must be an absolute URL or same-origin path")
    return endpoint


def _headers(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or not 1 <= len(value) <= 32:
        raise CredentialContractError("custom_headers must contain 1 to 32 headers")
    result: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = _header_name(raw_name, required=True)
        assert name is not None
        secret = _text(raw_value, name=f"custom header {name}", required=True, maximum=8_192)
        assert secret is not None
        if name.lower() in {item.lower() for item in result}:
            raise CredentialContractError("custom_headers contains duplicate names")
        result[name] = secret
    return result


def _scopes(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or len(value) > 32:
        raise CredentialContractError("scopes must be an array of at most 32 strings")
    result: list[str] = []
    for raw in value:
        item = _text(raw, name="scope", required=True, maximum=300)
        assert item is not None
        if item not in result:
            result.append(item)
    return result


def build_credential_secret(
    auth_kind: Any,
    *,
    secret: Any = None,
    username: Any = None,
    secondary_secret: Any = None,
    header_name: Any = None,
    endpoint_url: Any = None,
    client_id: Any = None,
    scopes: Any = None,
    custom_headers: Any = None,
    parameter_name: Any = None,
) -> str:
    """Validate and serialize one plaintext envelope for immediate encryption."""
    kind = str(auth_kind or "").strip().lower()
    if kind not in CREDENTIAL_KINDS:
        raise CredentialContractError("auth_kind is not supported")
    needs_secret = kind != "custom_headers"
    primary = _text(
        secret,
        name="secret",
        required=needs_secret,
        allow_lines=kind in {"ssh_private_key", "ssh_private_key_with_passphrase"},
        maximum=(
            262_144
            if kind in {"ssh_private_key", "ssh_private_key_with_passphrase"}
            else 65_536
        ),
    )
    user = _text(
        username,
        name="username",
        required=kind in {"basic_auth", "form_login", "oauth_password", *SSH_CREDENTIAL_KINDS},
        maximum=1_000,
    )
    secondary = _text(
        secondary_secret,
        name="secondary_secret",
        required=False,
        maximum=65_536,
    )
    if kind == "ssh_private_key_with_passphrase" and not secondary:
        raise CredentialContractError(
            "secondary_secret is required for ssh_private_key_with_passphrase"
        )
    if secondary and kind != "ssh_private_key_with_passphrase":
        raise CredentialContractError(
            "secondary_secret is valid only for ssh_private_key_with_passphrase"
        )
    resolved_header = _header_name(header_name, required=kind == "api_key_header")
    if resolved_header and kind != "api_key_header":
        raise CredentialContractError("header_name is valid only for api_key_header")
    resolved_parameter = _header_name(
        parameter_name,
        required=kind == "query_parameter",
        field_name="parameter_name",
    )
    if resolved_parameter and kind != "query_parameter":
        raise CredentialContractError(
            "parameter_name is valid only for query_parameter"
        )
    endpoint = _endpoint(
        endpoint_url,
        name="endpoint_url",
        required=kind in {"form_login", "oauth_client_credentials", "oauth_password"},
    )
    client = _text(
        client_id,
        name="client_id",
        required=kind == "oauth_client_credentials",
        maximum=2_000,
    )
    resolved_scopes = _scopes(scopes)
    if (client or resolved_scopes) and kind not in {"oauth_client_credentials", "oauth_password"}:
        raise CredentialContractError("client_id and scopes are valid only for OAuth profiles")
    headers = _headers(custom_headers) if kind == "custom_headers" else {}
    if custom_headers is not None and kind != "custom_headers":
        raise CredentialContractError("custom_headers is valid only for custom_headers auth")
    payload = {
        "schema_version": CREDENTIAL_SECRET_SCHEMA,
        "auth_kind": kind,
        "secret": primary,
        "username": user,
        "secondary_secret": secondary,
        "header_name": resolved_header,
        "endpoint_url": endpoint,
        "client_id": client,
        "scopes": resolved_scopes,
        "custom_headers": headers,
        "parameter_name": resolved_parameter,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_credential_secret(auth_kind: Any, decrypted_value: Any) -> dict[str, Any]:
    """Revalidate worker-decrypted material and accept the two legacy raw formats."""
    kind = str(auth_kind or "").strip().lower()
    if kind not in CREDENTIAL_KINDS:
        raise CredentialContractError("stored auth_kind is not supported")
    raw = str(decrypted_value or "")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = None
    if not isinstance(value, Mapping) or value.get("schema_version") != CREDENTIAL_SECRET_SCHEMA:
        if kind not in {"authorization_header", "cookie"}:
            raise CredentialContractError("stored credential envelope is invalid")
        encoded = build_credential_secret(kind, secret=raw)
        return json.loads(encoded)
    if str(value.get("auth_kind") or "") != kind:
        raise CredentialContractError("stored credential kind does not match its envelope")
    encoded = build_credential_secret(
        kind,
        secret=value.get("secret"),
        username=value.get("username"),
        secondary_secret=value.get("secondary_secret"),
        header_name=value.get("header_name"),
        endpoint_url=value.get("endpoint_url"),
        client_id=value.get("client_id"),
        scopes=value.get("scopes"),
        custom_headers=(
            value.get("custom_headers") if kind == "custom_headers" else None
        ),
        parameter_name=(
            value.get("parameter_name") if kind == "query_parameter" else None
        ),
    )
    return json.loads(encoded)


def immediate_http_headers(material: Mapping[str, Any]) -> dict[str, str]:
    """Project non-interactive HTTP profiles into worker-private request headers."""
    kind = str(material.get("auth_kind") or "")
    if kind not in IMMEDIATE_HTTP_HEADER_KINDS:
        raise CredentialContractError(
            "credential requires a target-bound login or token-exchange capability"
        )
    secret = str(material.get("secret") or "")
    if kind == "authorization_header":
        return {"Authorization": secret}
    if kind == "bearer_token":
        return {"Authorization": f"Bearer {secret}"}
    if kind == "api_key_header":
        return {str(material["header_name"]): secret}
    if kind == "cookie":
        return {"Cookie": secret}
    if kind == "basic_auth":
        token = base64.b64encode(
            f"{material.get('username') or ''}:{secret}".encode("utf-8")
        ).decode("ascii")
        return {"Authorization": f"Basic {token}"}
    return {str(name): str(value) for name, value in dict(material["custom_headers"]).items()}


def public_credential_configuration(material: Mapping[str, Any]) -> dict[str, Any]:
    """Return content-free configuration flags safe for profile APIs and receipts."""
    kind = str(material.get("auth_kind") or "")
    return {
        "schema_version": CREDENTIAL_SECRET_SCHEMA,
        "auth_kind": kind,
        "username_configured": bool(material.get("username")),
        "secondary_secret_configured": bool(material.get("secondary_secret")),
        "header_name": material.get("header_name"),
        "endpoint_configured": bool(material.get("endpoint_url")),
        "client_id_configured": bool(material.get("client_id")),
        "scope_count": len(material.get("scopes") or ()),
        "custom_header_names": sorted(dict(material.get("custom_headers") or {})),
        "parameter_name": material.get("parameter_name"),
        "interactive_exchange_required": kind in {
            "form_login", "oauth_client_credentials", "oauth_password",
        },
        "secret_values_visible": False,
    }
