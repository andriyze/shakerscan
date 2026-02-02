"""
OAuth 2.0 and OpenID Connect Authentication for DAST Scanning.

This module provides OAuth/OIDC authentication for security scanning of protected APIs.
It supports multiple OAuth flows and automatic token management.

Phase 2.1c of the Authenticated DAST Foundation.

Features:
- OAuth 2.0 Client Credentials flow (for service-to-service)
- OAuth 2.0 Resource Owner Password Credentials flow
- OpenID Connect discovery document parsing
- JWT token parsing and validation
- Automatic token refresh handling
- Bearer token injection for authenticated requests

Usage:
    # Client Credentials flow
    auth = await oauth_client_credentials(
        token_url="https://auth.example.com/oauth/token",
        client_id="my-client-id",
        client_secret="my-client-secret",
        scope="read write"
    )

    # Password Grant flow
    auth = await oauth_password_grant(
        token_url="https://auth.example.com/oauth/token",
        client_id="my-client-id",
        username="user@example.com",
        password="password123"
    )

    # OIDC Discovery
    config = await oidc_discover("https://auth.example.com")
"""

import asyncio
import base64
import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode, urlparse

# Import auth session for making requests
from .auth_session import AuthSession

# Well-known OIDC discovery paths
OIDC_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

# Common token endpoint patterns (for auto-discovery)
TOKEN_ENDPOINT_PATTERNS = [
    "/oauth/token",
    "/oauth2/token",
    "/token",
    "/auth/token",
    "/api/oauth/token",
    "/connect/token",
    "/as/token.oauth2",
]

# Common authorization endpoint patterns
AUTH_ENDPOINT_PATTERNS = [
    "/oauth/authorize",
    "/oauth2/authorize",
    "/authorize",
    "/auth/authorize",
    "/connect/authorize",
    "/as/authorization.oauth2",
]


@dataclass
class OAuthToken:
    """Represents an OAuth access token."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int | None = None
    refresh_token: str | None = None
    scope: str | None = None
    id_token: str | None = None
    issued_at: float = field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired (with 60 second buffer)."""
        if not self.expires_in:
            return False
        return time.time() > (self.issued_at + self.expires_in - 60)

    @property
    def expires_at(self) -> datetime | None:
        """Get token expiration time."""
        if not self.expires_in:
            return None
        return datetime.fromtimestamp(self.issued_at + self.expires_in, tz=UTC)

    def to_header(self) -> dict[str, str]:
        """Get Authorization header for this token."""
        return {"Authorization": f"{self.token_type} {self.access_token}"}


@dataclass
class OIDCConfig:
    """OpenID Connect configuration from discovery document."""
    issuer: str
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    jwks_uri: str | None = None
    registration_endpoint: str | None = None
    scopes_supported: list[str] = field(default_factory=list)
    response_types_supported: list[str] = field(default_factory=list)
    grant_types_supported: list[str] = field(default_factory=list)
    token_endpoint_auth_methods_supported: list[str] = field(default_factory=list)
    claims_supported: list[str] = field(default_factory=list)
    code_challenge_methods_supported: list[str] = field(default_factory=list)
    id_token_signing_alg_values_supported: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OIDCConfig":
        """Create from discovery document JSON."""
        return cls(
            issuer=data.get("issuer", ""),
            authorization_endpoint=data.get("authorization_endpoint"),
            token_endpoint=data.get("token_endpoint"),
            userinfo_endpoint=data.get("userinfo_endpoint"),
            jwks_uri=data.get("jwks_uri"),
            registration_endpoint=data.get("registration_endpoint"),
            scopes_supported=data.get("scopes_supported", []),
            response_types_supported=data.get("response_types_supported", []),
            grant_types_supported=data.get("grant_types_supported", []),
            token_endpoint_auth_methods_supported=data.get("token_endpoint_auth_methods_supported", []),
            claims_supported=data.get("claims_supported", []),
            code_challenge_methods_supported=data.get("code_challenge_methods_supported", []),
            id_token_signing_alg_values_supported=data.get("id_token_signing_alg_values_supported", []),
        )


@dataclass
class OAuthResult:
    """Result of an OAuth authentication attempt."""
    success: bool
    token: OAuthToken | None = None
    session: AuthSession | None = None
    error: str | None = None
    error_description: str | None = None
    oidc_config: OIDCConfig | None = None
    jwt_claims: dict[str, Any] | None = None


async def _http_request(
    method: str,
    url: str,
    data: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30
) -> dict[str, Any]:
    """Make HTTP request using curl subprocess."""
    cmd = ["curl", "-s", "-X", method, "-w", "\n%{http_code}"]

    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    if data:
        cmd.extend(["-d", urlencode(data)])
        if "Content-Type" not in (headers or {}):
            cmd.extend(["-H", "Content-Type: application/x-www-form-urlencoded"])

    cmd.append(url)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            # Kill the subprocess on timeout to prevent orphans
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return {"status": 0, "body": "", "error": "timeout"}
        except asyncio.CancelledError:
            if proc:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            raise
        output = stdout.decode("utf-8", errors="replace")

        # Split response body and status code
        lines = output.rsplit("\n", 2)
        if len(lines) >= 2:
            body = lines[0]
            status = int(lines[-1]) if lines[-1].isdigit() else 0
        else:
            body = output
            status = 0

        return {
            "status": status,
            "body": body,
            "headers": {}
        }
    except TimeoutError:
        return {"status": 0, "body": "", "error": "timeout"}
    except asyncio.CancelledError:
        if proc:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        raise
    except Exception as e:
        return {"status": 0, "body": "", "error": str(e)}


def parse_jwt_claims(token: str) -> dict[str, Any] | None:
    """
    Parse JWT token claims without verification.

    This extracts the payload for inspection only - does NOT verify signature.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        # Decode payload (middle part)
        payload = parts[1]
        # Add padding if needed
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding

        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None


def parse_jwt_header(token: str) -> dict[str, Any] | None:
    """Parse JWT header without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header = parts[0]
        padding = 4 - len(header) % 4
        if padding != 4:
            header += "=" * padding

        decoded = base64.urlsafe_b64decode(header)
        return json.loads(decoded)
    except Exception:
        return None


async def oidc_discover(issuer_url: str, timeout: int = 30) -> OIDCConfig | None:
    """
    Discover OIDC configuration from issuer URL.

    Args:
        issuer_url: The OIDC issuer URL (e.g., https://auth.example.com)
        timeout: Request timeout in seconds

    Returns:
        OIDCConfig if discovery successful, None otherwise
    """
    # Normalize issuer URL
    issuer_url = issuer_url.rstrip("/")

    for path in OIDC_DISCOVERY_PATHS:
        discovery_url = f"{issuer_url}{path}"

        response = await _http_request("GET", discovery_url, timeout=timeout)

        if response.get("status") == 200:
            try:
                data = json.loads(response.get("body", ""))
                if isinstance(data, dict) and data.get("issuer"):
                    return OIDCConfig.from_dict(data)
            except json.JSONDecodeError:
                continue

    return None


async def find_token_endpoint(base_url: str, timeout: int = 30) -> str | None:
    """
    Try to find OAuth token endpoint by checking common paths.

    Returns the first working token endpoint URL found.
    """
    base_url = base_url.rstrip("/")

    # First try OIDC discovery
    oidc_config = await oidc_discover(base_url, timeout)
    if oidc_config and oidc_config.token_endpoint:
        return oidc_config.token_endpoint

    # Try common token endpoint patterns
    for pattern in TOKEN_ENDPOINT_PATTERNS:
        url = f"{base_url}{pattern}"
        response = await _http_request("POST", url, timeout=timeout)

        # Token endpoints typically return 400/401 without credentials, not 404
        if response.get("status") in [400, 401, 405]:
            return url

    return None


async def oauth_client_credentials(
    token_url: str,
    client_id: str,
    client_secret: str,
    scope: str | None = None,
    extra_params: dict[str, str] | None = None,
    timeout: int = 30
) -> OAuthResult:
    """
    Perform OAuth 2.0 Client Credentials flow.

    This flow is used for service-to-service authentication where
    the client is acting on its own behalf (not on behalf of a user).

    Args:
        token_url: OAuth token endpoint URL
        client_id: Client ID
        client_secret: Client secret
        scope: Space-separated list of scopes (optional)
        extra_params: Additional parameters to include in token request
        timeout: Request timeout in seconds

    Returns:
        OAuthResult with token if successful
    """
    result = OAuthResult(success=False)

    # Build token request
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }

    if scope:
        data["scope"] = scope

    if extra_params:
        data.update(extra_params)

    # Request token
    response = await _http_request(
        "POST",
        token_url,
        data=data,
        headers={"Accept": "application/json"},
        timeout=timeout
    )

    if response.get("status") == 200:
        try:
            token_data = json.loads(response.get("body", ""))

            if "access_token" in token_data:
                token = OAuthToken(
                    access_token=token_data["access_token"],
                    token_type=token_data.get("token_type", "Bearer"),
                    expires_in=token_data.get("expires_in"),
                    refresh_token=token_data.get("refresh_token"),
                    scope=token_data.get("scope"),
                    id_token=token_data.get("id_token"),
                )

                # Create authenticated session
                session = AuthSession(
                    headers=token.to_header(),
                    base_url=urlparse(token_url).scheme + "://" + urlparse(token_url).netloc
                )

                result.success = True
                result.token = token
                result.session = session

                # Parse JWT claims if present
                if token.id_token:
                    result.jwt_claims = parse_jwt_claims(token.id_token)
                elif token.access_token and "." in token.access_token:
                    # Access token might also be a JWT
                    result.jwt_claims = parse_jwt_claims(token.access_token)

                return result

            # Check for error response
            if "error" in token_data:
                result.error = token_data.get("error")
                result.error_description = token_data.get("error_description")
                return result

        except json.JSONDecodeError:
            result.error = "invalid_response"
            result.error_description = "Token endpoint returned non-JSON response"
            return result

    result.error = "token_request_failed"
    result.error_description = f"Token request failed with status {response.get('status')}"
    return result


async def oauth_password_grant(
    token_url: str,
    client_id: str,
    username: str,
    password: str,
    client_secret: str | None = None,
    scope: str | None = None,
    extra_params: dict[str, str] | None = None,
    timeout: int = 30
) -> OAuthResult:
    """
    Perform OAuth 2.0 Resource Owner Password Credentials flow.

    This flow exchanges user credentials for an access token.
    Note: This flow is discouraged for third-party apps but still
    used in some internal/legacy systems.

    Args:
        token_url: OAuth token endpoint URL
        client_id: Client ID
        username: Resource owner username
        password: Resource owner password
        client_secret: Client secret (optional, depends on client type)
        scope: Space-separated list of scopes (optional)
        extra_params: Additional parameters to include in token request
        timeout: Request timeout in seconds

    Returns:
        OAuthResult with token if successful
    """
    result = OAuthResult(success=False)

    # Build token request
    data = {
        "grant_type": "password",
        "client_id": client_id,
        "username": username,
        "password": password,
    }

    if client_secret:
        data["client_secret"] = client_secret

    if scope:
        data["scope"] = scope

    if extra_params:
        data.update(extra_params)

    # Request token
    response = await _http_request(
        "POST",
        token_url,
        data=data,
        headers={"Accept": "application/json"},
        timeout=timeout
    )

    if response.get("status") == 200:
        try:
            token_data = json.loads(response.get("body", ""))

            if "access_token" in token_data:
                token = OAuthToken(
                    access_token=token_data["access_token"],
                    token_type=token_data.get("token_type", "Bearer"),
                    expires_in=token_data.get("expires_in"),
                    refresh_token=token_data.get("refresh_token"),
                    scope=token_data.get("scope"),
                    id_token=token_data.get("id_token"),
                )

                # Create authenticated session
                session = AuthSession(
                    headers=token.to_header(),
                    base_url=urlparse(token_url).scheme + "://" + urlparse(token_url).netloc
                )

                result.success = True
                result.token = token
                result.session = session

                # Parse JWT claims if present
                if token.id_token:
                    result.jwt_claims = parse_jwt_claims(token.id_token)
                elif token.access_token and "." in token.access_token:
                    result.jwt_claims = parse_jwt_claims(token.access_token)

                return result

            if "error" in token_data:
                result.error = token_data.get("error")
                result.error_description = token_data.get("error_description")
                return result

        except json.JSONDecodeError:
            result.error = "invalid_response"
            result.error_description = "Token endpoint returned non-JSON response"
            return result

    result.error = "token_request_failed"
    result.error_description = f"Token request failed with status {response.get('status')}"
    return result


async def oauth_refresh_token(
    token_url: str,
    refresh_token: str,
    client_id: str,
    client_secret: str | None = None,
    scope: str | None = None,
    timeout: int = 30
) -> OAuthResult:
    """
    Refresh an OAuth access token using a refresh token.

    Args:
        token_url: OAuth token endpoint URL
        refresh_token: The refresh token
        client_id: Client ID
        client_secret: Client secret (optional)
        scope: Space-separated list of scopes (optional, may be reduced)
        timeout: Request timeout in seconds

    Returns:
        OAuthResult with new token if successful
    """
    result = OAuthResult(success=False)

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }

    if client_secret:
        data["client_secret"] = client_secret

    if scope:
        data["scope"] = scope

    response = await _http_request(
        "POST",
        token_url,
        data=data,
        headers={"Accept": "application/json"},
        timeout=timeout
    )

    if response.get("status") == 200:
        try:
            token_data = json.loads(response.get("body", ""))

            if "access_token" in token_data:
                token = OAuthToken(
                    access_token=token_data["access_token"],
                    token_type=token_data.get("token_type", "Bearer"),
                    expires_in=token_data.get("expires_in"),
                    refresh_token=token_data.get("refresh_token", refresh_token),
                    scope=token_data.get("scope"),
                    id_token=token_data.get("id_token"),
                )

                session = AuthSession(
                    headers=token.to_header(),
                    base_url=urlparse(token_url).scheme + "://" + urlparse(token_url).netloc
                )

                result.success = True
                result.token = token
                result.session = session
                return result

            if "error" in token_data:
                result.error = token_data.get("error")
                result.error_description = token_data.get("error_description")
                return result

        except json.JSONDecodeError:
            result.error = "invalid_response"
            return result

    result.error = "refresh_failed"
    result.error_description = f"Token refresh failed with status {response.get('status')}"
    return result


class OAuthSession:
    """
    Managed OAuth session with automatic token refresh.

    This class wraps an AuthSession and handles token lifecycle management,
    automatically refreshing tokens when they expire.
    """

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str | None = None,
        initial_token: OAuthToken | None = None,
        auto_refresh: bool = True
    ):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = initial_token
        self.auto_refresh = auto_refresh
        self._session: AuthSession | None = None
        self._refresh_lock = asyncio.Lock()

    @property
    def is_authenticated(self) -> bool:
        """Check if session has a valid token."""
        return self.token is not None and not self.token.is_expired

    async def ensure_authenticated(self) -> bool:
        """Ensure we have a valid token, refreshing if needed."""
        if not self.token:
            return False

        if self.token.is_expired and self.auto_refresh and self.token.refresh_token:
            async with self._refresh_lock:
                # Double-check after acquiring lock
                if self.token.is_expired:
                    result = await oauth_refresh_token(
                        token_url=self.token_url,
                        refresh_token=self.token.refresh_token,
                        client_id=self.client_id,
                        client_secret=self.client_secret
                    )
                    if result.success and result.token:
                        self.token = result.token
                        self._session = result.session
                    else:
                        return False

        return not self.token.is_expired

    def get_session(self) -> AuthSession | None:
        """Get the underlying AuthSession with current token."""
        if not self.token:
            return None

        if not self._session:
            self._session = AuthSession(
                headers=self.token.to_header(),
                base_url=urlparse(self.token_url).scheme + "://" + urlparse(self.token_url).netloc
            )
        else:
            # Update session headers with current token
            self._session.headers.update(self.token.to_header())

        return self._session

    async def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> dict[str, Any]:
        """Make authenticated request, refreshing token if needed."""
        if not await self.ensure_authenticated():
            return {"error": "not_authenticated", "status": 0}

        session = self.get_session()
        if not session:
            return {"error": "no_session", "status": 0}

        return await session.request(method, url, **kwargs)

    async def get(self, url: str, **kwargs) -> dict[str, Any]:
        """Make authenticated GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> dict[str, Any]:
        """Make authenticated POST request."""
        return await self.request("POST", url, **kwargs)

    def get_stats(self) -> dict[str, Any]:
        """Get session statistics."""
        stats = {
            "authenticated": self.is_authenticated,
            "auto_refresh": self.auto_refresh,
            "has_refresh_token": bool(self.token and self.token.refresh_token),
        }

        if self.token:
            stats["token_type"] = self.token.token_type
            stats["expires_at"] = self.token.expires_at.isoformat() if self.token.expires_at else None
            stats["is_expired"] = self.token.is_expired
            stats["scope"] = self.token.scope

        return stats

    async def close(self):
        """Close the session."""
        if self._session:
            await self._session.close()


async def oauth_authenticate(
    base_url: str,
    client_id: str,
    client_secret: str | None = None,
    username: str | None = None,
    password: str | None = None,
    token_url: str | None = None,
    scope: str | None = None,
    grant_type: str | None = None,
    timeout: int = 30
) -> OAuthResult:
    """
    Unified OAuth authentication function.

    Automatically determines the appropriate OAuth flow based on provided credentials:
    - If username/password provided: Uses Resource Owner Password Credentials flow
    - If only client_id/client_secret: Uses Client Credentials flow

    Args:
        base_url: Base URL of the OAuth provider (used for OIDC discovery)
        client_id: OAuth client ID
        client_secret: OAuth client secret (optional for some flows)
        username: Resource owner username (triggers password grant)
        password: Resource owner password
        token_url: Explicit token endpoint URL (auto-discovered if not provided)
        scope: Space-separated list of scopes
        grant_type: Force specific grant type ("client_credentials" or "password")
        timeout: Request timeout in seconds

    Returns:
        OAuthResult with token and session if successful
    """
    result = OAuthResult(success=False)

    # Try OIDC discovery
    oidc_config = await oidc_discover(base_url, timeout)
    if oidc_config:
        result.oidc_config = oidc_config
        if not token_url:
            token_url = oidc_config.token_endpoint

    # Find token endpoint if not provided
    if not token_url:
        token_url = await find_token_endpoint(base_url, timeout)

    if not token_url:
        result.error = "no_token_endpoint"
        result.error_description = "Could not find OAuth token endpoint"
        return result

    # Determine grant type
    if grant_type:
        use_grant_type = grant_type
    elif username and password:
        use_grant_type = "password"
    elif client_id and client_secret:
        use_grant_type = "client_credentials"
    else:
        result.error = "insufficient_credentials"
        result.error_description = "Need client_secret for client_credentials or username/password for password grant"
        return result

    # Execute appropriate flow
    if use_grant_type == "password":
        if not username or not password:
            result.error = "missing_credentials"
            result.error_description = "Username and password required for password grant"
            return result

        return await oauth_password_grant(
            token_url=token_url,
            client_id=client_id,
            username=username,
            password=password,
            client_secret=client_secret,
            scope=scope,
            timeout=timeout
        )

    elif use_grant_type == "client_credentials":
        if not client_secret:
            result.error = "missing_client_secret"
            result.error_description = "Client secret required for client credentials grant"
            return result

        return await oauth_client_credentials(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            timeout=timeout
        )

    result.error = "unsupported_grant_type"
    result.error_description = f"Unsupported grant type: {use_grant_type}"
    return result


async def test_oauth_auth(
    base_url: str,
    client_id: str,
    client_secret: str | None = None,
    username: str | None = None,
    password: str | None = None,
    scope: str | None = None
) -> dict[str, Any]:
    """
    Test OAuth authentication and return detailed results.

    Useful for validating OAuth configuration before scanning.
    """
    results = {
        "base_url": base_url,
        "client_id": client_id,
        "has_client_secret": bool(client_secret),
        "has_credentials": bool(username and password),
        "scope": scope,
        "oidc_discovery": None,
        "token_endpoint": None,
        "authentication": None,
        "token_info": None,
        "jwt_claims": None,
        "error": None
    }

    # Try OIDC discovery
    oidc_config = await oidc_discover(base_url)
    if oidc_config:
        results["oidc_discovery"] = {
            "issuer": oidc_config.issuer,
            "token_endpoint": oidc_config.token_endpoint,
            "authorization_endpoint": oidc_config.authorization_endpoint,
            "grant_types_supported": oidc_config.grant_types_supported,
            "scopes_supported": oidc_config.scopes_supported[:10] if oidc_config.scopes_supported else [],
        }
        results["token_endpoint"] = oidc_config.token_endpoint

    # Find token endpoint if not from discovery
    if not results["token_endpoint"]:
        results["token_endpoint"] = await find_token_endpoint(base_url)

    # Attempt authentication
    auth_result = await oauth_authenticate(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        username=username,
        password=password,
        scope=scope
    )

    results["authentication"] = {
        "success": auth_result.success,
        "error": auth_result.error,
        "error_description": auth_result.error_description
    }

    if auth_result.success and auth_result.token:
        results["token_info"] = {
            "token_type": auth_result.token.token_type,
            "expires_in": auth_result.token.expires_in,
            "has_refresh_token": bool(auth_result.token.refresh_token),
            "has_id_token": bool(auth_result.token.id_token),
            "scope": auth_result.token.scope,
            "expires_at": auth_result.token.expires_at.isoformat() if auth_result.token.expires_at else None
        }

        if auth_result.jwt_claims:
            # Mask sensitive fields
            safe_claims = {}
            for key, value in auth_result.jwt_claims.items():
                if key in ["sub", "aud", "iss", "exp", "iat", "scope", "azp"]:
                    safe_claims[key] = value
                else:
                    safe_claims[key] = "***"
            results["jwt_claims"] = safe_claims

        # Clean up session
        if auth_result.session:
            await auth_result.session.close()

    return results


# Export main functions
__all__ = [
    "OAuthResult",
    "OAuthSession",
    "OAuthToken",
    "OIDCConfig",
    "find_token_endpoint",
    "oauth_authenticate",
    "oauth_client_credentials",
    "oauth_password_grant",
    "oauth_refresh_token",
    "oidc_discover",
    "parse_jwt_claims",
    "parse_jwt_header",
    "test_oauth_auth",
]
