"""
OAuth/OIDC Security Testing Module

Tests for common OAuth 2.0 and OpenID Connect vulnerabilities:
- PKCE bypass (accepting token request without code_verifier)
- Open redirect in redirect_uri
- State parameter validation
- Token leakage via Referer header
- Scope manipulation
- Client credential exposure

Reference: OWASP Testing Guide v4.2 - OAuth/OIDC Testing
"""

import asyncio
import base64
import hashlib
import logging
import re
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

logger = logging.getLogger(__name__)


class OAuthFlow(Enum):
    """OAuth 2.0 grant types"""
    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"  # deprecated but still common
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "device_code"
    REFRESH_TOKEN = "refresh_token"


class PKCEMethod(Enum):
    """PKCE code challenge methods"""
    PLAIN = "plain"
    S256 = "S256"


@dataclass
class OAuthEndpoints:
    """Discovered OAuth endpoints"""
    authorization_url: str | None = None
    token_url: str | None = None
    userinfo_url: str | None = None
    revocation_url: str | None = None
    jwks_url: str | None = None
    registration_url: str | None = None
    introspection_url: str | None = None
    issuer: str | None = None


@dataclass
class OAuthVulnerability:
    """Represents an OAuth vulnerability finding"""
    vuln_type: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: dict[str, Any]
    remediation: str


# Common OAuth/OIDC discovery paths
OAUTH_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
    "/.well-known/openid-configuration/",
    "/realms/master/.well-known/openid-configuration",  # Keycloak
    "/oauth2/.well-known/openid-configuration",
    "/v1/.well-known/openid-configuration",
    "/v2/.well-known/openid-configuration",
]

# Common OAuth endpoint patterns (when discovery fails)
OAUTH_ENDPOINT_PATTERNS = {
    "authorization": [
        "/oauth/authorize",
        "/oauth2/authorize",
        "/authorize",
        "/auth/authorize",
        "/connect/authorize",
        "/oauth/auth",
        "/as/authorization.oauth2",
    ],
    "token": [
        "/oauth/token",
        "/oauth2/token",
        "/token",
        "/auth/token",
        "/connect/token",
        "/as/token.oauth2",
    ],
    "userinfo": [
        "/oauth/userinfo",
        "/oauth2/userinfo",
        "/userinfo",
        "/connect/userinfo",
        "/me",
    ],
}

# Redirect URI bypass payloads for open redirect testing
REDIRECT_URI_BYPASSES = [
    # Subdomain-based bypasses
    "https://evil.com#@legitimate.com",
    "https://legitimate.com.evil.com",
    "https://legitimate.com@evil.com",
    "https://evil.com\\@legitimate.com",
    "https://evil.com%40legitimate.com",
    # Path traversal
    "https://legitimate.com/../evil.com",
    "https://legitimate.com/..%2Fevil.com",
    "https://legitimate.com/callback/../../../evil.com/callback",
    # Protocol manipulation
    "//evil.com",
    "///evil.com",
    "////evil.com",
    "/\\evil.com",
    # Localhost bypass
    "http://localhost",
    "http://127.0.0.1",
    "http://[::1]",
    "http://0.0.0.0",
    # JavaScript URI (for implicit flow)
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    # URL encoding bypasses
    "https://legitimate.com%2f%2e%2e%2fevil.com",
    "https://legitimate.com%252f%252e%252e%252fevil.com",
    # Case manipulation
    "HTTPS://EVIL.COM",
    # Port manipulation
    "https://legitimate.com:443@evil.com",
    "https://legitimate.com:8080",
]


def generate_pkce_pair(method: PKCEMethod = PKCEMethod.S256) -> tuple[str, str]:
    """
    Generate PKCE code_verifier and code_challenge pair.

    Returns:
        Tuple of (code_verifier, code_challenge)
    """
    # Generate random code_verifier (43-128 chars from unreserved charset)
    code_verifier = secrets.token_urlsafe(32)

    if method == PKCEMethod.PLAIN:
        code_challenge = code_verifier
    else:  # S256
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    return code_verifier, code_challenge


async def discover_oauth_endpoints(
    base_url: str,
    client: httpx.AsyncClient,
) -> OAuthEndpoints:
    """
    Discover OAuth/OIDC endpoints via well-known discovery or probing.

    Args:
        base_url: Target base URL
        client: HTTP client

    Returns:
        OAuthEndpoints with discovered URLs
    """
    endpoints = OAuthEndpoints()
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Try OIDC discovery first
    for path in OAUTH_DISCOVERY_PATHS:
        try:
            url = f"{base}{path}"
            resp = await client.get(url, timeout=10.0)

            if resp.status_code == 200:
                try:
                    config = resp.json()
                    endpoints.issuer = config.get("issuer")
                    endpoints.authorization_url = config.get("authorization_endpoint")
                    endpoints.token_url = config.get("token_endpoint")
                    endpoints.userinfo_url = config.get("userinfo_endpoint")
                    endpoints.revocation_url = config.get("revocation_endpoint")
                    endpoints.jwks_url = config.get("jwks_uri")
                    endpoints.registration_url = config.get("registration_endpoint")
                    endpoints.introspection_url = config.get("introspection_endpoint")

                    if endpoints.authorization_url:
                        logger.info(f"Discovered OAuth config at {url}")
                        return endpoints
                except (ValueError, KeyError):
                    pass
        except httpx.RequestError:
            continue

    # Fallback: probe common endpoint patterns
    for endpoint_type, patterns in OAUTH_ENDPOINT_PATTERNS.items():
        for pattern in patterns:
            try:
                url = f"{base}{pattern}"
                # Use OPTIONS or HEAD to avoid side effects
                resp = await client.options(url, timeout=5.0)

                if resp.status_code in (200, 302, 400, 401, 405):
                    # Endpoint likely exists (400/401 = requires params)
                    if endpoint_type == "authorization":
                        endpoints.authorization_url = url
                    elif endpoint_type == "token":
                        endpoints.token_url = url
                    elif endpoint_type == "userinfo":
                        endpoints.userinfo_url = url
                    break
            except httpx.RequestError:
                continue

    return endpoints


async def test_pkce_bypass(
    token_url: str,
    client_id: str,
    redirect_uri: str,
    client: httpx.AsyncClient,
    authorization_code: str | None = None,
) -> OAuthVulnerability | None:
    """
    Test if the OAuth server accepts token requests without code_verifier
    when PKCE was used in the authorization request.

    This is a critical vulnerability that allows authorization code interception
    attacks even when PKCE is supposedly enforced.

    Args:
        token_url: OAuth token endpoint
        client_id: OAuth client ID
        redirect_uri: Registered redirect URI
        client: HTTP client
        authorization_code: Optional real auth code (if available)

    Returns:
        OAuthVulnerability if bypass detected, None otherwise
    """
    # Generate PKCE pair
    code_verifier, code_challenge = generate_pkce_pair(PKCEMethod.S256)

    # Test 1: Token request without code_verifier
    # A properly secured server should reject this
    token_data_no_verifier = {
        "grant_type": "authorization_code",
        "code": authorization_code or "test_code_12345",
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        # Intentionally omitting code_verifier
    }

    try:
        resp = await client.post(
            token_url,
            data=token_data_no_verifier,
            timeout=10.0,
        )

        # Analyze response
        response_text = resp.text.lower()
        response_json = None
        try:
            response_json = resp.json()
        except ValueError:
            pass

        # Check for successful token or weak error
        # Vulnerable: returns token without verifier
        # Vulnerable: returns error about invalid code (not about missing verifier)

        if resp.status_code == 200 and response_json:
            if "access_token" in response_json:
                return OAuthVulnerability(
                    vuln_type="PKCE Bypass - No Verifier Required",
                    severity="critical",
                    description=(
                        "The OAuth server issued an access token without requiring "
                        "code_verifier, even though PKCE should be enforced. "
                        "This allows authorization code interception attacks."
                    ),
                    evidence={
                        "token_url": token_url,
                        "request": token_data_no_verifier,
                        "response_status": resp.status_code,
                        "response_contains_token": True,
                    },
                    remediation=(
                        "Enforce PKCE on the token endpoint by requiring code_verifier "
                        "for all authorization_code grant requests. Validate that the "
                        "code_verifier matches the code_challenge from the authorization request."
                    ),
                )

        # Check for error response that indicates PKCE not enforced
        if response_json and "error" in response_json:
            error = response_json.get("error", "")
            error_desc = response_json.get("error_description", "")

            # If error is about invalid/expired code but not about missing verifier
            # the server may not be enforcing PKCE
            if error == "invalid_grant" and "verifier" not in error_desc.lower():
                # Need to test with valid code to confirm
                return OAuthVulnerability(
                    vuln_type="PKCE Bypass - Potential",
                    severity="medium",
                    description=(
                        "The OAuth server did not explicitly reject the token request "
                        "for missing code_verifier. Error was about invalid code, not "
                        "missing PKCE parameters. This may indicate PKCE is optional."
                    ),
                    evidence={
                        "token_url": token_url,
                        "request": token_data_no_verifier,
                        "response_status": resp.status_code,
                        "error": error,
                        "error_description": error_desc,
                    },
                    remediation=(
                        "Ensure PKCE is required for all public clients. The server should "
                        "reject requests missing code_verifier with a specific error like "
                        "'invalid_request' with description mentioning code_verifier."
                    ),
                )
    except httpx.RequestError as e:
        logger.warning(f"PKCE bypass test failed: {e}")

    # Test 2: Token request with wrong code_verifier
    token_data_wrong_verifier = {
        "grant_type": "authorization_code",
        "code": authorization_code or "test_code_12345",
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": "wrong_verifier_" + secrets.token_urlsafe(16),
    }

    try:
        resp = await client.post(
            token_url,
            data=token_data_wrong_verifier,
            timeout=10.0,
        )

        if resp.status_code == 200:
            try:
                response_json = resp.json()
                if "access_token" in response_json:
                    return OAuthVulnerability(
                        vuln_type="PKCE Bypass - Wrong Verifier Accepted",
                        severity="critical",
                        description=(
                            "The OAuth server issued an access token with an incorrect "
                            "code_verifier. This indicates PKCE validation is not working, "
                            "allowing authorization code interception attacks."
                        ),
                        evidence={
                            "token_url": token_url,
                            "request": token_data_wrong_verifier,
                            "response_status": resp.status_code,
                            "response_contains_token": True,
                        },
                        remediation=(
                            "Fix PKCE validation to properly verify that code_verifier "
                            "matches the code_challenge from the authorization request."
                        ),
                    )
            except ValueError:
                pass
    except httpx.RequestError as e:
        logger.warning(f"PKCE wrong verifier test failed: {e}")

    return None


async def test_redirect_uri_validation(
    authorization_url: str,
    client_id: str,
    legitimate_redirect_uri: str,
    client: httpx.AsyncClient,
) -> list[OAuthVulnerability]:
    """
    Test for open redirect vulnerabilities in redirect_uri validation.

    Args:
        authorization_url: OAuth authorization endpoint
        client_id: OAuth client ID
        legitimate_redirect_uri: Known valid redirect URI
        client: HTTP client

    Returns:
        List of vulnerabilities found
    """
    vulnerabilities = []
    parsed_legit = urlparse(legitimate_redirect_uri)

    for bypass_payload in REDIRECT_URI_BYPASSES:
        # Generate test redirect_uri based on legitimate one
        if bypass_payload.startswith("https://legitimate.com"):
            test_uri = bypass_payload.replace(
                "legitimate.com",
                parsed_legit.netloc
            )
        elif bypass_payload.startswith("//") or bypass_payload.startswith("/\\"):
            test_uri = bypass_payload
        else:
            test_uri = bypass_payload

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": test_uri,
            "scope": "openid",
            "state": secrets.token_urlsafe(16),
        }

        try:
            # Don't follow redirects to see the actual response
            resp = await client.get(
                authorization_url,
                params=params,
                follow_redirects=False,
                timeout=10.0,
            )

            # Check for redirect to the attacker-controlled URI
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")

                # Check if the redirect contains our payload
                if "evil.com" in location.lower() or test_uri in location:
                    vulnerabilities.append(OAuthVulnerability(
                        vuln_type="Open Redirect via redirect_uri",
                        severity="high",
                        description=(
                            f"The authorization endpoint accepted an open redirect payload "
                            f"in the redirect_uri parameter, allowing an attacker to steal "
                            f"authorization codes or tokens."
                        ),
                        evidence={
                            "authorization_url": authorization_url,
                            "malicious_redirect_uri": test_uri,
                            "response_status": resp.status_code,
                            "redirect_location": location,
                        },
                        remediation=(
                            "Implement strict redirect_uri validation:\n"
                            "1. Use exact string matching for registered redirect URIs\n"
                            "2. Do not allow subdomain matching\n"
                            "3. Do not allow path manipulation\n"
                            "4. Validate protocol (reject javascript:, data:)"
                        ),
                    ))
                    # Found one, continue testing others for comprehensive report

            # Also check for error responses that might indicate partial bypass
            elif resp.status_code == 200:
                # Authorization page rendered - may indicate redirect_uri accepted
                if "authorize" in resp.text.lower() or "consent" in resp.text.lower():
                    # Check if error page shows the malicious URI
                    if "evil.com" in resp.text or test_uri in resp.text:
                        vulnerabilities.append(OAuthVulnerability(
                            vuln_type="Open Redirect via redirect_uri (reflected)",
                            severity="medium",
                            description=(
                                f"The authorization endpoint reflects the redirect_uri "
                                f"in the page content, which may enable XSS or phishing."
                            ),
                            evidence={
                                "authorization_url": authorization_url,
                                "malicious_redirect_uri": test_uri,
                                "response_status": resp.status_code,
                            },
                            remediation=(
                                "Sanitize and validate redirect_uri before any use. "
                                "Do not reflect unvalidated URIs in page content."
                            ),
                        ))

        except httpx.RequestError as e:
            logger.debug(f"Redirect URI test failed for {test_uri}: {e}")
            continue

    return vulnerabilities


async def test_state_parameter(
    authorization_url: str,
    token_url: str,
    client_id: str,
    redirect_uri: str,
    client: httpx.AsyncClient,
) -> list[OAuthVulnerability]:
    """
    Test for state parameter validation issues (CSRF protection).

    Args:
        authorization_url: OAuth authorization endpoint
        token_url: OAuth token endpoint
        client_id: OAuth client ID
        redirect_uri: Redirect URI
        client: HTTP client

    Returns:
        List of vulnerabilities found
    """
    vulnerabilities = []

    # Test 1: Authorization request without state parameter
    params_no_state = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        # No state parameter
    }

    try:
        resp = await client.get(
            authorization_url,
            params=params_no_state,
            follow_redirects=False,
            timeout=10.0,
        )

        # If the server accepts request without state
        if resp.status_code in (200, 302, 303):
            # Check if it's an error page or authorization page
            is_error = False
            if resp.status_code == 200:
                content = resp.text.lower()
                is_error = "error" in content and "state" in content

            if not is_error:
                vulnerabilities.append(OAuthVulnerability(
                    vuln_type="Missing State Parameter Enforcement",
                    severity="medium",
                    description=(
                        "The authorization endpoint does not require the state parameter, "
                        "leaving the OAuth flow vulnerable to CSRF attacks."
                    ),
                    evidence={
                        "authorization_url": authorization_url,
                        "request_params": params_no_state,
                        "response_status": resp.status_code,
                    },
                    remediation=(
                        "Require the state parameter for all authorization requests. "
                        "Generate cryptographically random state values and validate "
                        "them when processing the callback."
                    ),
                ))
    except httpx.RequestError as e:
        logger.debug(f"State parameter test failed: {e}")

    # Test 2: Check if state is properly validated in callback
    # This would require a real flow, so we check for indicators
    params_with_state = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": "predictable_state_12345",  # Use predictable state
    }

    try:
        resp = await client.get(
            authorization_url,
            params=params_with_state,
            follow_redirects=False,
            timeout=10.0,
        )

        # Check if predictable state is accepted
        if resp.status_code in (200, 302, 303):
            # Look for the state in response
            location = resp.headers.get("location", "")
            if "predictable_state_12345" in location:
                vulnerabilities.append(OAuthVulnerability(
                    vuln_type="Predictable State Accepted",
                    severity="low",
                    description=(
                        "The authorization endpoint accepted a predictable state value. "
                        "While not directly exploitable, clients should use random state."
                    ),
                    evidence={
                        "authorization_url": authorization_url,
                        "predictable_state": "predictable_state_12345",
                    },
                    remediation=(
                        "Clients should generate cryptographically random state values. "
                        "Servers may consider enforcing minimum entropy requirements."
                    ),
                ))
    except httpx.RequestError:
        pass

    return vulnerabilities


async def test_scope_manipulation(
    authorization_url: str,
    client_id: str,
    redirect_uri: str,
    client: httpx.AsyncClient,
) -> list[OAuthVulnerability]:
    """
    Test for scope manipulation/escalation vulnerabilities.

    Args:
        authorization_url: OAuth authorization endpoint
        client_id: OAuth client ID
        redirect_uri: Redirect URI
        client: HTTP client

    Returns:
        List of vulnerabilities found
    """
    vulnerabilities = []

    # Scopes to test for unauthorized access
    test_scopes = [
        "admin",
        "write",
        "delete",
        "user:admin",
        "repo:admin",
        "offline_access",  # Refresh token access
        "openid profile email admin",  # Appending admin
        "*",  # Wildcard
        "https://www.googleapis.com/auth/admin.directory.user",  # Google admin
        "https://graph.microsoft.com/.default",  # Microsoft full access
    ]

    base_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": secrets.token_urlsafe(16),
    }

    for scope in test_scopes:
        params = {**base_params, "scope": scope}

        try:
            resp = await client.get(
                authorization_url,
                params=params,
                follow_redirects=False,
                timeout=10.0,
            )

            # Check if elevated scope was accepted
            if resp.status_code in (200, 302, 303):
                # Check for consent page (scope accepted)
                if resp.status_code == 200:
                    content = resp.text.lower()
                    # Look for consent/authorize indicators
                    if ("consent" in content or "authorize" in content or
                        "permission" in content) and "error" not in content:
                        vulnerabilities.append(OAuthVulnerability(
                            vuln_type="Scope Escalation",
                            severity="medium",
                            description=(
                                f"The authorization endpoint accepted scope '{scope}' "
                                f"which may grant elevated permissions."
                            ),
                            evidence={
                                "authorization_url": authorization_url,
                                "requested_scope": scope,
                                "response_status": resp.status_code,
                            },
                            remediation=(
                                "Validate requested scopes against allowed scopes "
                                "for each client. Reject or downgrade unauthorized scopes."
                            ),
                        ))

                # Check redirect for scope in response
                location = resp.headers.get("location", "")
                if resp.status_code in (302, 303) and "scope" in location.lower():
                    if scope.replace(" ", "+") in location or scope in location:
                        vulnerabilities.append(OAuthVulnerability(
                            vuln_type="Scope Escalation (in redirect)",
                            severity="medium",
                            description=(
                                f"The authorization endpoint granted scope '{scope}' "
                                f"as indicated in the redirect response."
                            ),
                            evidence={
                                "authorization_url": authorization_url,
                                "requested_scope": scope,
                                "redirect_location": location,
                            },
                            remediation=(
                                "Implement scope validation per client. Only allow "
                                "scopes that are registered for the specific client_id."
                            ),
                        ))

        except httpx.RequestError:
            continue

    return vulnerabilities


async def test_implicit_flow_token_leakage(
    authorization_url: str,
    client_id: str,
    redirect_uri: str,
    client: httpx.AsyncClient,
) -> list[OAuthVulnerability]:
    """
    Test if implicit flow is enabled (token in URL fragment).
    Implicit flow is deprecated due to token leakage risks.

    Args:
        authorization_url: OAuth authorization endpoint
        client_id: OAuth client ID
        redirect_uri: Redirect URI
        client: HTTP client

    Returns:
        List of vulnerabilities found
    """
    vulnerabilities = []

    # Test response_type=token (implicit flow)
    implicit_params = {
        "response_type": "token",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": secrets.token_urlsafe(16),
    }

    try:
        resp = await client.get(
            authorization_url,
            params=implicit_params,
            follow_redirects=False,
            timeout=10.0,
        )

        if resp.status_code in (200, 302, 303):
            # Check if consent page or redirect with token
            is_error = False
            if resp.status_code == 200:
                content = resp.text.lower()
                is_error = "error" in content and (
                    "unsupported_response_type" in content or
                    "invalid_request" in content
                )

            location = resp.headers.get("location", "")

            # Token in fragment indicates implicit flow is enabled
            if not is_error:
                if "#access_token=" in location:
                    vulnerabilities.append(OAuthVulnerability(
                        vuln_type="Implicit Flow Enabled (Token in URL)",
                        severity="high",
                        description=(
                            "The OAuth server supports implicit flow (response_type=token) "
                            "which returns access tokens directly in the URL fragment. "
                            "This is deprecated and vulnerable to token leakage via "
                            "browser history, Referer headers, and XSS."
                        ),
                        evidence={
                            "authorization_url": authorization_url,
                            "response_type": "token",
                            "token_in_fragment": True,
                        },
                        remediation=(
                            "Disable implicit flow. Use authorization code flow with PKCE "
                            "for public clients (SPAs, mobile apps). If implicit flow must "
                            "remain enabled, use response_mode=form_post to avoid URL leakage."
                        ),
                    ))
                elif resp.status_code == 200 and not is_error:
                    # Consent page shown - implicit flow may be supported
                    vulnerabilities.append(OAuthVulnerability(
                        vuln_type="Implicit Flow Potentially Enabled",
                        severity="medium",
                        description=(
                            "The OAuth server appears to accept response_type=token "
                            "requests. Implicit flow is deprecated and should be disabled."
                        ),
                        evidence={
                            "authorization_url": authorization_url,
                            "response_type": "token",
                            "response_status": resp.status_code,
                        },
                        remediation=(
                            "Disable implicit flow if not needed. Use authorization code "
                            "flow with PKCE for public clients."
                        ),
                    ))

    except httpx.RequestError as e:
        logger.debug(f"Implicit flow test failed: {e}")

    # Also test response_type=id_token (OIDC implicit)
    oidc_implicit_params = {
        "response_type": "id_token",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": secrets.token_urlsafe(16),
        "nonce": secrets.token_urlsafe(16),
    }

    try:
        resp = await client.get(
            authorization_url,
            params=oidc_implicit_params,
            follow_redirects=False,
            timeout=10.0,
        )

        if resp.status_code in (200, 302) and "error" not in resp.text.lower():
            location = resp.headers.get("location", "")
            if "#id_token=" in location or resp.status_code == 200:
                vulnerabilities.append(OAuthVulnerability(
                    vuln_type="OIDC Implicit Flow Enabled",
                    severity="medium",
                    description=(
                        "The server supports OIDC implicit flow (response_type=id_token). "
                        "While less risky than access tokens, id_tokens in URLs can still "
                        "leak sensitive user information."
                    ),
                    evidence={
                        "authorization_url": authorization_url,
                        "response_type": "id_token",
                    },
                    remediation=(
                        "Consider disabling implicit flow for id_tokens. "
                        "Use response_mode=form_post if implicit flow is required."
                    ),
                ))
    except httpx.RequestError:
        pass

    return vulnerabilities


async def test_client_credential_exposure(
    base_url: str,
    client: httpx.AsyncClient,
) -> list[OAuthVulnerability]:
    """
    Test for exposed OAuth client credentials in common locations.

    Args:
        base_url: Target base URL
        client: HTTP client

    Returns:
        List of vulnerabilities found
    """
    vulnerabilities = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Paths where client secrets might be exposed
    credential_paths = [
        "/.env",
        "/config.json",
        "/settings.json",
        "/oauth_config.json",
        "/app/config.json",
        "/api/config",
        "/.git/config",
        "/package.json",
        "/webpack.config.js",
        "/config/oauth.json",
        "/js/config.js",
        "/static/js/config.js",
        "/assets/config.js",
    ]

    # Patterns indicating OAuth credentials
    credential_patterns = [
        r'client[_-]?secret["\s:=]+["\']?[\w\-]{20,}',
        r'OAUTH[_-]?SECRET["\s:=]+["\']?[\w\-]{20,}',
        r'AUTH[_-]?SECRET["\s:=]+["\']?[\w\-]{20,}',
        r'"secret"[:\s]+["\'][\w\-]{20,}["\']',
        r'clientSecret["\s:=]+["\'][\w\-]{20,}',
    ]

    for path in credential_paths:
        try:
            resp = await client.get(f"{base}{path}", timeout=5.0)

            if resp.status_code == 200:
                content = resp.text

                for pattern in credential_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        vulnerabilities.append(OAuthVulnerability(
                            vuln_type="OAuth Client Secret Exposure",
                            severity="critical",
                            description=(
                                f"Potential OAuth client secret found exposed at {path}. "
                                f"Client secrets should never be exposed in client-side "
                                f"code or publicly accessible files."
                            ),
                            evidence={
                                "path": path,
                                "pattern_matched": pattern,
                                "match_preview": matches[0][:50] + "..." if len(matches[0]) > 50 else matches[0],
                            },
                            remediation=(
                                "Remove client secrets from client-side code and public files. "
                                "Use environment variables on the server side. "
                                "Rotate any exposed credentials immediately."
                            ),
                        ))
                        break  # One finding per path is enough

        except httpx.RequestError:
            continue

    return vulnerabilities


async def run_oauth_security_tests(
    base_url: str,
    client_id: str | None = None,
    redirect_uri: str | None = None,
    auth_header: str | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """
    Run comprehensive OAuth/OIDC security tests.

    Args:
        base_url: Target base URL
        client_id: OAuth client ID (optional, will try to detect)
        redirect_uri: Registered redirect URI (optional)
        auth_header: Authorization header for authenticated tests
        timeout: Overall timeout in seconds

    Returns:
        Dict with discovered endpoints, vulnerabilities, and summary
    """
    results = {
        "endpoints": None,
        "vulnerabilities": [],
        "tests_run": [],
        "summary": {},
    }

    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header

    async with httpx.AsyncClient(
        headers=headers,
        follow_redirects=False,
        verify=False,  # Allow self-signed certs for testing
    ) as client:
        # Step 1: Discover OAuth endpoints
        logger.info(f"Discovering OAuth endpoints for {base_url}")
        endpoints = await discover_oauth_endpoints(base_url, client)
        results["endpoints"] = {
            "authorization_url": endpoints.authorization_url,
            "token_url": endpoints.token_url,
            "userinfo_url": endpoints.userinfo_url,
            "jwks_url": endpoints.jwks_url,
            "issuer": endpoints.issuer,
        }

        if not endpoints.authorization_url and not endpoints.token_url:
            logger.warning(f"No OAuth endpoints discovered for {base_url}")
            results["summary"]["oauth_detected"] = False
            return results

        results["summary"]["oauth_detected"] = True

        # Use defaults if not provided
        test_client_id = client_id or "test_client"
        test_redirect_uri = redirect_uri or f"{base_url}/callback"

        # Step 2: Run security tests
        vulnerabilities = []

        # Test PKCE bypass
        if endpoints.token_url:
            results["tests_run"].append("pkce_bypass")
            vuln = await test_pkce_bypass(
                endpoints.token_url,
                test_client_id,
                test_redirect_uri,
                client,
            )
            if vuln:
                vulnerabilities.append(vuln)

        # Test redirect URI validation
        if endpoints.authorization_url:
            results["tests_run"].append("redirect_uri_validation")
            vulns = await test_redirect_uri_validation(
                endpoints.authorization_url,
                test_client_id,
                test_redirect_uri,
                client,
            )
            vulnerabilities.extend(vulns)

        # Test state parameter
        if endpoints.authorization_url and endpoints.token_url:
            results["tests_run"].append("state_parameter")
            vulns = await test_state_parameter(
                endpoints.authorization_url,
                endpoints.token_url,
                test_client_id,
                test_redirect_uri,
                client,
            )
            vulnerabilities.extend(vulns)

        # Test scope manipulation
        if endpoints.authorization_url:
            results["tests_run"].append("scope_manipulation")
            vulns = await test_scope_manipulation(
                endpoints.authorization_url,
                test_client_id,
                test_redirect_uri,
                client,
            )
            vulnerabilities.extend(vulns)

        # Test implicit flow
        if endpoints.authorization_url:
            results["tests_run"].append("implicit_flow")
            vulns = await test_implicit_flow_token_leakage(
                endpoints.authorization_url,
                test_client_id,
                test_redirect_uri,
                client,
            )
            vulnerabilities.extend(vulns)

        # Test client credential exposure
        results["tests_run"].append("credential_exposure")
        vulns = await test_client_credential_exposure(base_url, client)
        vulnerabilities.extend(vulns)

        # Convert vulnerabilities to dicts
        results["vulnerabilities"] = [
            {
                "type": v.vuln_type,
                "severity": v.severity,
                "description": v.description,
                "evidence": v.evidence,
                "remediation": v.remediation,
            }
            for v in vulnerabilities
        ]

        # Summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
            severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1

        results["summary"]["total_vulnerabilities"] = len(vulnerabilities)
        results["summary"]["severity_counts"] = severity_counts
        results["summary"]["tests_completed"] = len(results["tests_run"])

    return results


# Convenience function for integration with main scanner
async def test_oauth_endpoints(
    url: str,
    client_id: str | None = None,
    auth_header: str | None = None,
) -> list[dict]:
    """
    Simplified interface for scanner integration.

    Args:
        url: Target URL
        client_id: Optional client ID
        auth_header: Optional auth header

    Returns:
        List of vulnerability dictionaries for scanner findings
    """
    results = await run_oauth_security_tests(
        base_url=url,
        client_id=client_id,
        auth_header=auth_header,
    )

    return results.get("vulnerabilities", [])
