"""Operator authentication and local-session helpers for Fleet and Model Intake.

Extracted verbatim from the api.py monolith. These functions derive a
server-owned operator identity from the request (bearer credential, configured
hashed credential map, or a short-lived loopback browser session) and enforce
the transport requirements for operator access. They depend only on the standard
library and the FastAPI request/exception types — no database pool, no Redis, and
nothing from ``api.api`` — so any router peeled off the monolith can import them
directly instead of reaching back into it.

Security-critical: identity is always server-derived here. Approver identity is
never accepted from a request body, and the automatic-review controller's
principal is carried in a server-only ASGI scope key that HTTP clients cannot set.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import time
from typing import Any, Mapping
import urllib.parse

from fastapi import HTTPException, Request


def _fleet_bearer_credential(request: Request, *, principal: str = "node") -> str:
    scheme, separator, value = request.headers.get("authorization", "").partition(" ")
    if not separator or scheme.lower() != "bearer" or not value.strip():
        raise HTTPException(status_code=401, detail=f"{principal} bearer credential is required")
    return value.strip()


def _require_fleet_operator(request: Request) -> None:
    """Authorize fleet operators from the real peer or a configured bearer secret.

    ``SHAKERSCAN_BIND_HOST`` describes host-port publishing, not the request peer.
    It may relax the HTTPS requirement for a loopback-published port, but it can
    never bypass authentication for Docker-network callers.
    """
    configured_bind = os.environ.get("SHAKERSCAN_BIND_HOST", "").strip()
    peer = getattr(getattr(request, "client", None), "host", None)
    try:
        peer_is_loopback = bool(peer) and ipaddress.ip_address(peer).is_loopback
    except ValueError:
        peer_is_loopback = False
    if peer_is_loopback:
        return
    try:
        configured_bind_ip = ipaddress.ip_address(configured_bind) if configured_bind else None
        host_publish_is_loopback = bool(configured_bind_ip and configured_bind_ip.is_loopback)
    except ValueError:
        configured_bind_ip = None
        host_publish_is_loopback = False
    trusted_tailscale_http = bool(
        os.environ.get("SHAKERSCAN_TRUSTED_REMOTE_TRANSPORT", "").strip().lower() == "tailscale"
        and isinstance(configured_bind_ip, ipaddress.IPv4Address)
        and configured_bind_ip in ipaddress.ip_network("100.64.0.0/10")
    )
    if request.url.scheme != "https" and not host_publish_is_loopback and not trusted_tailscale_http:
        raise HTTPException(
            status_code=403,
            detail="fleet operator access requires loopback, verified Tailscale, or authenticated HTTPS",
        )
    expected = os.environ.get("FLEET_OPERATOR_TOKEN", "")
    if len(expected) < 32:
        raise HTTPException(status_code=403, detail="fleet operator access is not enabled remotely")
    presented = _fleet_bearer_credential(request, principal="fleet operator")
    if not secrets.compare_digest(presented, expected):
        raise HTTPException(status_code=403, detail="fleet operator authentication failed")


_MODEL_INTAKE_LOCAL_SESSION_VERSION = "mi-local-v1"
_MODEL_INTAKE_LOCAL_SESSION_MAX_SECONDS = 8 * 60 * 60


def _model_intake_local_session_allowed() -> bool:
    configured_bind = os.environ.get("SHAKERSCAN_BIND_HOST", "127.0.0.1").strip()
    configured_public = os.environ.get("SHAKERSCAN_PUBLIC_HOST", "").strip()
    try:
        if not ipaddress.ip_address(configured_bind).is_loopback:
            return False
        return not configured_public or ipaddress.ip_address(
            "127.0.0.1" if configured_public == "localhost" else configured_public
        ).is_loopback
    except ValueError:
        return False


def _mint_model_intake_local_session() -> tuple[str, int]:
    secret = os.environ.get("MODEL_INTAKE_LOCAL_SESSION_SECRET", "").strip()
    if len(secret) < 32:
        raise HTTPException(status_code=503, detail="local Model Intake session is not configured")
    expires_at = int(time.time()) + _MODEL_INTAKE_LOCAL_SESSION_MAX_SECONDS
    unsigned = f"{_MODEL_INTAKE_LOCAL_SESSION_VERSION}.{expires_at}.{secrets.token_hex(16)}"
    signature = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).hexdigest()
    return f"{unsigned}.{signature}", expires_at


def _model_intake_local_session_valid(request: Request, credential: str) -> bool:
    """Validate a short-lived browser session without exposing the operator token.

    The UI can mint this only when both the configured deployment and the actual
    browser hostname are loopback. Remote and managed deployments stay on named
    reviewer credentials.
    """
    secret = os.environ.get("MODEL_INTAKE_LOCAL_SESSION_SECRET", "").strip()
    if len(secret) < 32 or not _model_intake_local_session_allowed():
        return False
    # Browser calls from the UI to the API cross ports and therefore carry an
    # Origin. Requiring it prevents a session minted by a mistakenly exposed
    # loopback UI proxy from becoming a general-purpose remote bearer token.
    origin = request.headers.get("origin", "").strip()
    if not origin:
        return False
    try:
        parsed = urllib.parse.urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or not ipaddress.ip_address(
            "127.0.0.1" if parsed.hostname == "localhost" else str(parsed.hostname or "")
        ).is_loopback:
            return False
    except ValueError:
        return False
    parts = credential.split(".")
    if len(parts) != 4 or parts[0] != _MODEL_INTAKE_LOCAL_SESSION_VERSION:
        return False
    _, expires_raw, nonce, signature = parts
    if not re.fullmatch(r"[0-9]{10}", expires_raw) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        return False
    if not re.fullmatch(r"[0-9a-f]{64}", signature):
        return False
    now = int(time.time())
    expires_at = int(expires_raw)
    if expires_at <= now or expires_at > now + _MODEL_INTAKE_LOCAL_SESSION_MAX_SECONDS + 60:
        return False
    unsigned = f"{parts[0]}.{expires_raw}.{nonce}"
    expected = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).hexdigest()
    return secrets.compare_digest(signature, expected)


def _require_model_intake_operator(request: Request) -> None:
    """Authorize deployment verification and Model Intake trust mutations."""
    # Requests created by the durable automatic-review controller carry a
    # server-only ASGI scope value. HTTP clients cannot set ASGI scope keys.
    # This principal is used only to call the existing evidence-generation
    # functions; the controller has no path to approvals, exceptions, policy
    # decisions, promotion, or signer issuance.
    scope = getattr(request, "scope", {})
    if isinstance(scope, Mapping) and scope.get("shakerscan.model_intake_system_actor") == "system:model-intake-auto":
        return
    peer = getattr(getattr(request, "client", None), "host", None)
    try:
        peer_is_loopback = bool(peer) and ipaddress.ip_address(peer).is_loopback
    except ValueError:
        peer_is_loopback = False
    configured_bind = os.environ.get("SHAKERSCAN_BIND_HOST", "").strip()
    try:
        configured_bind_ip = ipaddress.ip_address(configured_bind) if configured_bind else None
        host_publish_is_loopback = bool(configured_bind_ip and configured_bind_ip.is_loopback)
    except ValueError:
        configured_bind_ip = None
        host_publish_is_loopback = False
    trusted_tailscale_http = bool(
        os.environ.get("SHAKERSCAN_TRUSTED_REMOTE_TRANSPORT", "").strip().lower() == "tailscale"
        and isinstance(configured_bind_ip, ipaddress.IPv4Address)
        and configured_bind_ip in ipaddress.ip_network("100.64.0.0/10")
    )
    if (
        request.url.scheme != "https"
        and not peer_is_loopback
        and not host_publish_is_loopback
        and not trusted_tailscale_http
    ):
        raise HTTPException(
            status_code=403,
            detail="Model Intake operator access requires loopback, verified Tailscale, or authenticated HTTPS",
        )
    presented = _fleet_bearer_credential(request, principal="Model Intake operator")
    if _model_intake_local_session_valid(request, presented):
        return
    configured = _model_intake_configured_operator_credentials()
    legacy = (
        os.environ.get("MODEL_INTAKE_OPERATOR_TOKEN", "").strip()
        or os.environ.get("FLEET_OPERATOR_TOKEN", "").strip()
    )
    if not configured and len(legacy) < 32:
        raise HTTPException(status_code=403, detail="Model Intake operator credential is not configured")
    presented_sha256 = hashlib.sha256(presented.encode()).hexdigest()
    configured_match = any(
        secrets.compare_digest(presented_sha256, item["token_sha256"])
        for item in configured
    )
    legacy_match = len(legacy) >= 32 and secrets.compare_digest(presented, legacy)
    if not configured_match and not legacy_match:
        raise HTTPException(status_code=403, detail="Model Intake operator authentication failed")


_MODEL_INTAKE_APPROVAL_ROLES = {
    "model_security_reviewer", "ml_platform_reviewer", "release_manager",
    "legal_reviewer", "privacy_reviewer", "data_owner", "risk_acceptance",
}


def _model_intake_configured_operator_credentials() -> list[dict[str, Any]]:
    """Load environment-owned hashed credentials with stable identities and roles."""
    raw = os.getenv("MODEL_INTAKE_OPERATOR_CREDENTIALS_JSON", "").strip()
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=503, detail="Model Intake operator credential map is invalid") from exc
    if not isinstance(decoded, list) or not decoded:
        raise HTTPException(status_code=503, detail="Model Intake operator credential map must be a non-empty list")
    records: list[dict[str, Any]] = []
    seen_tokens: set[str] = set()
    for value in decoded:
        if not isinstance(value, dict):
            raise HTTPException(status_code=503, detail="Model Intake operator credential record is invalid")
        token_sha256 = str(value.get("token_sha256") or "").lower()
        subject = str(value.get("subject") or "").strip()
        roles = value.get("roles")
        if (
            not re.fullmatch(r"[0-9a-f]{64}", token_sha256)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{1,199}", subject)
            or not isinstance(roles, list)
            or any(str(role) not in _MODEL_INTAKE_APPROVAL_ROLES for role in roles)
            or token_sha256 in seen_tokens
        ):
            raise HTTPException(status_code=503, detail="Model Intake operator credential record is invalid")
        seen_tokens.add(token_sha256)
        records.append({
            "token_sha256": token_sha256,
            "subject": subject,
            "roles": sorted({str(role) for role in roles}),
        })
    return records


def _model_intake_operator_credential(request: Request) -> dict[str, Any] | None:
    presented_sha256 = hashlib.sha256(_fleet_bearer_credential(request).encode()).hexdigest()
    for item in _model_intake_configured_operator_credentials():
        if secrets.compare_digest(presented_sha256, item["token_sha256"]):
            return item
    return None


def _model_intake_authenticated_subject(request: Request) -> str:
    """Return a server-derived identity; never accept approver identity in JSON."""
    scope = getattr(request, "scope", {})
    system_actor = scope.get("shakerscan.model_intake_system_actor") if isinstance(scope, Mapping) else None
    if system_actor == "system:model-intake-auto":
        return system_actor
    _require_model_intake_operator(request)
    credential = _fleet_bearer_credential(request, principal="Model Intake operator")
    if _model_intake_local_session_valid(request, credential):
        return "operator:standalone-local-ui"
    configured = _model_intake_operator_credential(request)
    if configured:
        return f"operator:{configured['subject']}"
    if not credential:
        raise HTTPException(status_code=403, detail="Model Intake authenticated identity is unavailable")
    return f"operator-token:{hashlib.sha256(credential.encode()).hexdigest()[:24]}"


def _model_intake_operator_roles(request: Request) -> set[str]:
    _model_intake_authenticated_subject(request)
    credential = _fleet_bearer_credential(request, principal="Model Intake operator")
    if _model_intake_local_session_valid(request, credential):
        return set()
    configured = _model_intake_operator_credential(request)
    if configured:
        return set(configured["roles"])
    configured = {
        item.strip()
        for item in os.getenv("MODEL_INTAKE_OPERATOR_ROLES", "").split(",")
        if item.strip()
    }
    return configured


def _model_intake_submission_subject(request: Request) -> str:
    """Bind submitter identity to the same authenticated principal used downstream.

    Submissions are part of the controlled admission workflow and already require a
    bearer credential.  Deriving a second, role-prefixed identity from that same
    credential would make one principal appear distinct at approval time and defeat
    submitter/approver separation.
    """
    return _model_intake_authenticated_subject(request)


def _model_intake_automatic_system_request() -> Request:
    """Create an internal principal without persisting or replaying a bearer token."""
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/internal/model-intake/automatic-review",
        "raw_path": b"/internal/model-intake/automatic-review",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 0),
        "server": ("127.0.0.1", 8080),
        "shakerscan.model_intake_system_actor": "system:model-intake-auto",
    }
    request = Request(scope)
    # Minimal FastAPI request doubles used by the complete suite intentionally
    # expose only headers/client/url. Preserve the server-only scope contract so
    # those requests fail closed while the internal controller remains testable.
    if not hasattr(request, "scope"):
        request.scope = scope
    return request


__all__ = [
    "_MODEL_INTAKE_APPROVAL_ROLES",
    "_MODEL_INTAKE_LOCAL_SESSION_MAX_SECONDS",
    "_MODEL_INTAKE_LOCAL_SESSION_VERSION",
    "_fleet_bearer_credential",
    "_mint_model_intake_local_session",
    "_model_intake_authenticated_subject",
    "_model_intake_automatic_system_request",
    "_model_intake_configured_operator_credentials",
    "_model_intake_local_session_allowed",
    "_model_intake_local_session_valid",
    "_model_intake_operator_credential",
    "_model_intake_operator_roles",
    "_model_intake_submission_subject",
    "_require_fleet_operator",
    "_require_model_intake_operator",
]
