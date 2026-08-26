"""Interactive testing session routes.

Extracted verbatim from the api.py monolith. Drives browser-backed manual
testing sessions: start/inspect/end a session, capture screenshots, run browser
actions and endpoint tests, and persist explicitly-created findings.

Collaborators (database pool, results directory, ASM defaults for a newly
registered target) are injected by the composition root, so this module imports
shared helpers and the session manager but nothing from ``api.api``.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from typing import Any, Callable, Optional
import uuid

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

try:
    from api_utils import _uuid_or_400
    from evidence_triage import redact_finding_evidence as _redact_finding_evidence
    from secret_store import decrypt_secret
    from serialization import row_to_dict
    from session_manager import InteractiveSession, InteractiveSessionManager
except ModuleNotFoundError:  # package import in host-side tests
    from ..api_utils import _uuid_or_400
    from ..evidence_triage import redact_finding_evidence as _redact_finding_evidence
    from ..secret_store import decrypt_secret
    from ..serialization import row_to_dict
    from ..session_manager import InteractiveSession, InteractiveSessionManager


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_results_dir_provider: Callable[[], Any] | None = None
_asm_enabled_default: Callable[..., Any] | None = None
_asm_config_default: Callable[..., Any] | None = None


def configure_interactive_router(
    pool_provider: Callable[[], Any],
    *,
    results_dir_provider: Callable[[], Any],
    asm_enabled_default: Callable[..., Any],
    asm_config_default: Callable[..., Any],
) -> None:
    """Bind the pool and collaborators this domain needs.

    The ASM defaults read runtime automation settings that still live in api.py,
    so they are injected and resolved lazily instead of imported.
    """
    global _pool_provider, _results_dir_provider
    global _asm_enabled_default, _asm_config_default
    _pool_provider = pool_provider
    _results_dir_provider = results_dir_provider
    _asm_enabled_default = asm_enabled_default
    _asm_config_default = asm_config_default


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool


def _default_asm_enabled_for_new_web_target(discovery_source: str = "manual") -> bool:
    return bool(_asm_enabled_default(discovery_source)) if _asm_enabled_default else False


def _default_asm_config_for_new_web_target(discovery_source: str = "manual") -> dict[str, Any]:
    return dict(_asm_config_default(discovery_source)) if _asm_config_default else {}

class SessionFindingCreate(BaseModel):
    """Create a finding from an AI security session (target auto-populated)."""
    title: str
    severity: str  # critical, high, medium, low, info
    description: Optional[str] = None
    category: Optional[str] = None
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    url: Optional[str] = None
    evidence: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    remediation: Optional[str] = None
    notes: Optional[str] = None


class SessionStartRequest(BaseModel):
    target: str


class SessionActionRequest(BaseModel):
    action: str  # navigate, click, fill, set_auth, use_credential_profile, register, login, submit, wait, extract
    user: Optional[str] = "default"
    data: Optional[dict] = None


class EndpointTestRequest(BaseModel):
    endpoint: str
    method: str = "GET"
    as_user: Optional[str] = None
    body: Optional[dict] = None
    allow_out_of_scope: bool = False  # Set True to allow cross-origin requests (SSRF risk)


@router.post("/session/start")
async def start_session(request: SessionStartRequest):
    """
    Start an interactive browser session for AI-assisted security testing.

    This creates a headless browser session that can be used for:
    - Taking screenshots to analyze UI
    - Navigating and interacting with the application
    - Registering and logging in test users
    - Testing endpoints with different user contexts (BOLA testing)

    Returns a session_id to use in subsequent requests.

    Unlike scan endpoints which strip paths, sessions preserve the full URL
    so you can start at specific pages (e.g., /login).
    """
    # Validate and normalize URL (but preserve path for sessions)
    from urllib.parse import urlparse, urlunparse
    raw_target = (request.target or "").strip()
    if not raw_target:
        raise HTTPException(status_code=400, detail="Target URL required")

    # Add scheme if missing
    has_scheme = "://" in raw_target
    url_to_parse = raw_target if has_scheme else f"https://{raw_target}"

    try:
        parsed = urlparse(url_to_parse)
        # Validate scheme
        if parsed.scheme not in ("http", "https"):
            raise HTTPException(status_code=400, detail=f"Invalid scheme '{parsed.scheme}': only http/https allowed")
        # Validate host
        if not parsed.hostname:
            raise HTTPException(status_code=400, detail="Invalid target URL: no hostname")
        # Reject URLs with credentials (prevents credential leakage in logs/artifacts)
        if parsed.username or parsed.password:
            raise HTTPException(status_code=400, detail="URLs with embedded credentials (user:pass@host) are not allowed")
        # Access port early to catch malformed URLs
        _ = parsed.port
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {e}")

    # Reconstruct URL preserving path (but normalizing host to lowercase)
    normalized_target = urlunparse((
        parsed.scheme,
        parsed.netloc.lower(),
        parsed.path or "/",
        parsed.params,
        parsed.query,
        ""  # Strip fragment
    ))

    try:
        manager = await InteractiveSessionManager.get_instance()
        session = await manager.create_session(normalized_target, _results_dir_provider())
        result = await session.start()

        if not result.get("success"):
            await manager.close_session(session.session_id)
            raise HTTPException(status_code=500, detail=result.get("error", "Failed to start session"))

        return result

    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start session: {str(e)}")


@router.get("/session/{session_id}")
async def get_session_state(session_id: str):
    """Get current state of an interactive session."""
    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    return await session.get_state()


@router.post("/session/{session_id}/screenshot")
async def session_screenshot(
    session_id: str,
    full_page: bool = False,
    user: str = "default"
):
    """
    Capture a screenshot of the current page.

    Args:
        session_id: The session ID
        full_page: Capture full scrollable page (default: viewport only)
        user: Which user's browser context to screenshot (default: "default")

    Returns base64-encoded PNG image.
    """
    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    result = await session.screenshot(full_page=full_page, user=user)

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Screenshot failed"))

    return result


@router.get("/session/{session_id}/screenshot.png")
async def session_screenshot_raw(
    session_id: str,
    full_page: bool = False,
    user: str = "default"
):
    """
    Capture a screenshot and return raw PNG bytes.

    This endpoint returns the image directly (not JSON), making it easy to
    save to a file with curl:
        curl -s "http://localhost:8080/session/{id}/screenshot.png" -o screenshot.png

    Args:
        session_id: The session ID
        full_page: Capture full scrollable page (default: viewport only)
        user: Which user's browser context to screenshot (default: "default")
    """
    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    screenshot_bytes = await session.screenshot_raw(full_page=full_page, user=user)

    if screenshot_bytes is None:
        raise HTTPException(status_code=500, detail=f"Screenshot failed for user '{user}'")

    return Response(content=screenshot_bytes, media_type="image/png")


@router.post("/session/{session_id}/action")
async def session_action(session_id: str, request: SessionActionRequest):
    """
    Execute a browser action in the session.

    Supported actions:
    - navigate: Go to URL (data: {"url": "/path"})
    - click: Click element (data: {"selector": "button#submit"})
    - fill: Fill input (data: {"selector": "input#email", "value": "test@example.com"})
    - set_auth: Set auth context (data: {"token":"..."} or {"auth_header":"Bearer ..."} or {"cookies":{"session":"..."}})
    - use_credential_profile: Apply the target principal slot's managed profile (data: {"credential_profile_id":"..."})
    - register: Register user (data: {"email": "...", "password": "..."})
    - login: Login user (data: {"email": "...", "password": "..."})
    - submit: Submit form (data: {"selector": "form"})
    - wait: Wait for selector/timeout (data: {"selector": "...", "timeout": 5000})
    - extract: Extract data (data: {"selector": "...", "attribute": "href"})

    The 'user' parameter creates separate browser contexts for multi-user testing.
    """
    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    action_name = str(request.action or "").strip()
    user_name = str(request.user or "default").strip() or "default"
    action_data = dict(request.data or {})
    # These bindings are server assertions. A caller cannot add them to raw
    # set_auth/login actions and thereby qualify for an authz replay.
    action_data.pop("_credential_profile_id", None)
    action_data.pop("_principal_auth_state", None)
    action_data.pop("_replace_auth_state", None)
    managed_profile_applied = False
    if action_name == "use_credential_profile":
        if user_name not in {"user1", "user2"}:
            raise HTTPException(status_code=400, detail="managed credential profiles require user1 or user2")
        profile_uuid = _uuid_or_400(action_data.get("credential_profile_id"), "credential profile id")
        async with _pool().acquire() as conn:
            profile_row = await conn.fetchrow(
                """
                SELECT cp.id, cp.auth_kind, cp.secret_value, p.auth_state, t.url AS target_url
                FROM target_credential_profiles cp
                JOIN targets t ON t.id = cp.target_id
                JOIN target_principals p
                  ON p.target_id = cp.target_id
                 AND lower(p.credential_profile) = lower(cp.name)
                 AND p.is_active = true
                WHERE cp.id = $1
                  AND cp.is_active = true
                  AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
                  AND p.auth_state = $2
                """,
                profile_uuid,
                user_name,
            )
        if not profile_row:
            raise HTTPException(
                status_code=404,
                detail="Active credential profile is not bound to this target principal slot",
            )
        profile = row_to_dict(profile_row)
        if not session._is_in_scope(str(profile.get("target_url") or "")):
            raise HTTPException(status_code=409, detail="Credential profile target does not match the session origin")
        secret_value = str(decrypt_secret(profile.get("secret_value")) or "").strip()
        if not secret_value:
            raise HTTPException(status_code=409, detail="Credential profile has no usable secret")
        auth_kind = str(profile.get("auth_kind") or "").strip()
        if auth_kind == "authorization_header":
            action_data = {"auth_header": secret_value}
        elif auth_kind == "cookie":
            action_data = {"cookie_string": secret_value}
        else:
            raise HTTPException(status_code=409, detail="Credential profile auth kind is not executable")
        action_data["_credential_profile_id"] = str(profile_uuid)
        action_data["_principal_auth_state"] = user_name
        action_data["_replace_auth_state"] = True
        action_name = "set_auth"
        managed_profile_applied = True

    result = await session.action({
        "action": action_name,
        "user": user_name,
        "data": action_data,
    })

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Action failed"))

    if managed_profile_applied:
        result["managed_profile_applied"] = True
    return result


@router.post("/session/{session_id}/test-endpoint")
async def session_test_endpoint(session_id: str, request: EndpointTestRequest):
    """
    Test a specific API endpoint with optional user authentication.

    This is the core BOLA testing endpoint. It makes a request to the
    specified endpoint using the authentication context of 'as_user'.

    By default, only same-origin requests are allowed to prevent SSRF.
    Set allow_out_of_scope=True to test cross-origin endpoints.

    Example BOLA test:
    1. Login as user1, discover resource at /api/items/42
    2. Login as user2
    3. Call this endpoint with endpoint="/api/items/42" and as_user="user2"
    4. Treat a 200 or response difference as a lead; confirm principal distinctness,
       object ownership, sensitive data/state impact, and a denied control before
       recording a BOLA vulnerability

    Args:
        endpoint: API endpoint path (e.g., "/api/items/42")
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        as_user: Test as this user's session (uses their cookies/token)
        body: Request body for POST/PUT/PATCH
        allow_out_of_scope: Allow cross-origin requests (default: False for SSRF protection)
    """
    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    result = await session.test_endpoint(
        endpoint=request.endpoint,
        method=request.method,
        as_user=request.as_user,
        body=request.body,
        allow_out_of_scope=request.allow_out_of_scope
    )

    # Don't raise exception on request failure - return the result
    # so Claude can analyze the access control behavior
    return result


@router.delete("/session/{session_id}")
async def end_session(session_id: str):
    """
    End an interactive session and cleanup resources.

    This closes the browser and frees memory. Sessions also auto-expire
    after 30 minutes of inactivity.
    """
    manager = await InteractiveSessionManager.get_instance()
    closed = await manager.close_session(session_id)

    if not closed:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "status": "closed",
        "session_id": session_id,
        "message": "Session ended successfully"
    }


@router.get("/sessions")
async def list_sessions():
    """List all active interactive sessions."""
    manager = await InteractiveSessionManager.get_instance()

    sessions = []
    for session_id, session in manager.sessions.items():
        sessions.append({
            "session_id": session_id,
            "target_url": session.state.target_url,
            "created_at": session.state.created_at.isoformat(),
            "last_activity": session.state.last_activity.isoformat(),
            "is_expired": session.is_expired()
        })

    return {
        "sessions": sessions,
        "count": len(sessions)
    }


@router.post("/session/{session_id}/findings")
async def create_session_finding(session_id: str, request: SessionFindingCreate):
    """
    Create a finding from an AI security session.

    The target is automatically populated from the session.
    Use this during interactive testing to record discovered vulnerabilities.

    Example:
        curl -X POST "http://localhost:8080/session/{id}/findings" \\
          -H "Content-Type: application/json" \\
          -d '{
            "title": "BOLA on Basket API",
            "severity": "critical",
            "description": "User2 can access User1 basket via /rest/basket/{id}",
            "category": "BOLA",
            "cwe": "CWE-639",
            "evidence": "GET /rest/basket/9 with User2 token returns User1 data"
          }'
    """
    # Get session to extract target
    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    target_url = session.target_url

    # Validate severity
    valid_severities = ['critical', 'high', 'medium', 'low', 'info']
    if request.severity.lower() not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
        )

    # Normalize target URL to origin
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    normalized_target = f"{parsed.scheme}://{parsed.netloc}"

    # Generate fingerprint for deduplication
    fingerprint_source = f"{normalized_target}:{request.title}:{request.severity}"
    if request.url:
        fingerprint_source += f":{request.url}"
    fingerprint = hashlib.sha256(fingerprint_source.encode()).hexdigest()[:32]

    async with _pool().acquire() as conn:
        # Get or create target
        target = await conn.fetchrow(
            "SELECT id FROM targets WHERE url = $1",
            normalized_target
        )

        if target:
            target_id = target['id']
        else:
            # Create new target
            target_id = await conn.fetchval("""
                INSERT INTO targets (url, name, root_domain, discovery_source, asm_enabled, asm_config)
                VALUES ($1, $2, $3, 'ai_session', $4, $5)
                ON CONFLICT (canonical_key) DO UPDATE SET url = targets.url
                RETURNING id
            """, normalized_target, parsed.hostname, parsed.hostname,
                 _default_asm_enabled_for_new_web_target("ai_session"),
                 json.dumps(_default_asm_config_for_new_web_target("ai_session")))

        # Check for existing finding with same fingerprint
        existing = await conn.fetchrow(
            "SELECT id, status FROM findings WHERE fingerprint = $1 AND target_id = $2",
            fingerprint, target_id
        )

        if existing:
            # Update last_seen and potentially resurface
            if existing['status'] == 'resolved':
                await conn.execute("""
                    UPDATE findings
                    SET status = 'active', last_seen_at = NOW(),
                        resurfaced_count = resurfaced_count + 1,
                        session_id = $2, updated_at = NOW()
                    WHERE id = $1
                """, existing['id'], session_id)
                return {
                    'id': str(existing['id']),
                    'fingerprint': fingerprint,
                    'status': 'resurfaced',
                    'message': 'Existing finding resurfaced'
                }
            else:
                await conn.execute(
                    "UPDATE findings SET last_seen_at = NOW(), session_id = $2 WHERE id = $1",
                    existing['id'], session_id
                )
                return {
                    'id': str(existing['id']),
                    'fingerprint': fingerprint,
                    'status': 'duplicate',
                    'message': 'Finding already exists'
                }

        # Build evidence JSON if provided. Redact live auth material (bearer
        # tokens, JWTs, auth headers/cookies) the same way scanner findings are
        # sanitised in save_findings_from_partial — manual/session evidence
        # captured during interactive testing routinely carries live credentials
        # we must never persist (they leak via the API/UI and outlive the
        # engagement).
        evidence_json = None
        if request.evidence or request.remediation:
            evidence_json = {}
            if request.evidence:
                evidence_json['proof'] = request.evidence
            if request.remediation:
                evidence_json['remediation'] = request.remediation
            evidence_json = _redact_finding_evidence(evidence_json)
        redacted_request = _redact_finding_evidence(request.request)
        redacted_response = _redact_finding_evidence(request.response)

        # Create new finding
        finding_id = await conn.fetchval("""
            INSERT INTO findings (
                target_id, fingerprint, title, description, severity,
                cvss_score, tool, cwe, url, evidence, request, response,
                notes, source, session_id, status
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                'ai_session', $14, 'active'
            )
            RETURNING id
        """,
            target_id,
            fingerprint,
            request.title,
            request.description,
            request.severity.lower(),
            request.cvss_score,
            request.category or 'ai_session',
            request.cwe,
            request.url or normalized_target,
            json.dumps(evidence_json) if evidence_json else None,
            redacted_request,
            redacted_response,
            request.notes,
            session_id
        )

        # Update target finding count
        await conn.execute("""
            UPDATE targets SET
                active_findings_count = (
                    SELECT COUNT(*) FROM findings
                    WHERE target_id = $1 AND status = 'active'
                ),
                updated_at = NOW()
            WHERE id = $1
        """, target_id)

    return {
        'id': str(finding_id),
        'fingerprint': fingerprint,
        'target_id': str(target_id),
        'target': normalized_target,
        'session_id': session_id,
        'status': 'created',
        'message': 'Finding created successfully'
    }
