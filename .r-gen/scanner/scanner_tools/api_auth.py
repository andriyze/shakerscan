import json
import os
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import httpx

from .auth_session import AuthSession


LOGIN_PATH_HINTS = [
    "/api/login",
    "/api/auth/login",
    "/api/v1/login",
    "/api/v2/login",
    "/auth/login",
    "/login",
    "/users/login",
    "/user/login",
    "/session",
    "/sessions",
    "/token",
    "/oauth/token",
    "/oauth2/token",
]

LOGIN_TERMS = ("login", "signin", "auth", "token", "session", "oauth")

TOKEN_KEYS = {
    "access_token",
    "token",
    "auth_token",
    "jwt",
    "id_token",
    "api_key",
    "apikey",
}


@dataclass
class ApiLoginResult:
    success: bool
    session: AuthSession | None = None
    login_url: str | None = None
    method: str | None = None
    token: str | None = None
    token_type: str | None = None
    token_key: str | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    attempts: int = 0
    error: str | None = None


def _read_wordlist(path: str, limit: int | None = None) -> list[str]:
    if not path or not os.path.exists(path):
        return []
    entries: list[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(line)
            if limit is not None and len(entries) >= limit:
                break
    return entries


def _unique_preserve_order(items: list[str]) -> list[str]:
    seen = set()
    ordered: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def _build_login_candidates(base_url: str, login_url: str | None = None, max_candidates: int = 30) -> list[str]:
    candidates: list[str] = []
    if login_url:
        candidates.append(login_url)

    wordlist_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "wordlists"))
    prefixes_path = os.path.join(wordlist_dir, "api-prefixes.txt")
    resources_path = os.path.join(wordlist_dir, "api-resources.txt")

    prefixes = _read_wordlist(prefixes_path, limit=40)
    resources = _read_wordlist(resources_path, limit=120)

    login_resources = [r for r in resources if any(term in r.lower() for term in LOGIN_TERMS)]

    for prefix in prefixes:
        candidates.append(prefix)
        for resource in login_resources:
            candidates.append(f"{prefix.rstrip('/')}/{resource.lstrip('/')}")

    candidates.extend(LOGIN_PATH_HINTS)
    normalized: list[str] = []
    for entry in candidates:
        if not entry:
            continue
        if entry.startswith("http://") or entry.startswith("https://"):
            normalized.append(entry)
        else:
            normalized.append(urllib.parse.urljoin(base_url, entry))

    normalized = _unique_preserve_order(normalized)
    if max_candidates and len(normalized) > max_candidates:
        normalized = normalized[:max_candidates]
    return normalized


def _build_payloads(username: str, password: str, extra_fields: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    payloads = [
        {"username": username, "password": password},
        {"email": username, "password": password},
        {"user": username, "password": password},
        {"login": username, "password": password},
        {"identifier": username, "password": password},
        {"username": username, "pass": password},
        {"email": username, "pass": password},
    ]
    if extra_fields and isinstance(extra_fields, dict):
        merged = []
        for payload in payloads:
            merged_payload = dict(payload)
            merged_payload.update(extra_fields)
            merged.append(merged_payload)
        payloads = merged
    return payloads


def _looks_like_login_failure(body: str) -> bool:
    if not body:
        return False
    sample = body.lower()[:2000]
    keywords = [
        "invalid", "incorrect", "unauthorized", "forbidden",
        "login failed", "authentication failed", "wrong password",
    ]
    return any(k in sample for k in keywords)


def _extract_token(obj: Any) -> tuple[str | None, str | None, str | None]:
    if isinstance(obj, dict):
        token_type = obj.get("token_type") or obj.get("type")
        for key, value in obj.items():
            key_lower = str(key).lower()
            if key_lower in TOKEN_KEYS and isinstance(value, str):
                return key_lower, value, token_type
        for value in obj.values():
            found = _extract_token(value)
            if found[1]:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _extract_token(item)
            if found[1]:
                return found
    return None, None, None


def _headers_for_token(token_key: str | None, token: str, token_type: str | None = None) -> dict[str, str]:
    if not token:
        return {}
    if token_key in ("api_key", "apikey", "x-api-key"):
        return {"X-API-Key": token}
    scheme = token_type or "Bearer"
    if isinstance(scheme, str):
        scheme = scheme.strip()
    if not scheme:
        scheme = "Bearer"
    if scheme.lower() == "bearer":
        scheme = "Bearer"
    return {"Authorization": f"{scheme} {token}"}


async def api_login(
    base_url: str,
    username: str,
    password: str,
    login_url: str | None = None,
    extra_fields: dict[str, Any] | None = None,
    timeout: float = 10.0,
    max_candidates: int = 30,
    max_attempts: int = 18,
) -> ApiLoginResult:
    if not username or not password:
        return ApiLoginResult(success=False, error="missing credentials")

    candidates = _build_login_candidates(base_url, login_url, max_candidates=max_candidates)
    payloads = _build_payloads(username, password, extra_fields)

    attempts = 0
    last_error = None

    # follow_redirects=False is deliberate (SCAN-03a): these POSTs carry the
    # operator's credentials, and a target-controlled 307/308 would otherwise
    # re-send the credential body to an off-origin Location. Success detection
    # reads token/cookies from the first response, so following is unnecessary.
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=False) as client:
        for candidate in candidates:
            # Isolate the cookie jar per candidate endpoint. Otherwise a cookie
            # set by one candidate (e.g. an anonymous session/CSRF cookie from
            # /wp-login.php) leaks into requests to every later candidate, which
            # can produce a false "logged in via cookie" success attributed to
            # the wrong endpoint. Credentials against the same endpoint (the
            # JSON→form fallback below) still legitimately share its cookies.
            client.cookies.clear()
            for payload in payloads:
                if max_attempts and attempts >= max_attempts:
                    break
                attempts += 1
                try:
                    resp = await client.post(candidate, json=payload)
                except Exception as e:
                    last_error = str(e)
                    continue

                token_key, token_value, token_type = None, None, None
                cookies = dict(resp.cookies)
                if resp.headers.get("authorization"):
                    auth_header = resp.headers.get("authorization")
                    token_value = auth_header
                    token_key = "authorization"
                else:
                    if resp.text:
                        try:
                            data = resp.json()
                        except Exception:
                            try:
                                data = json.loads(resp.text)
                            except Exception:
                                data = None
                        if data is not None:
                            token_key, token_value, token_type = _extract_token(data)

                if token_value and token_key == "authorization":
                    headers = {"Authorization": token_value}
                    session = AuthSession(headers=headers, base_url=base_url)
                    return ApiLoginResult(
                        success=True,
                        session=session,
                        login_url=candidate,
                        method="json",
                        token=token_value,
                        token_key=token_key,
                        attempts=attempts,
                        headers=headers,
                    )

                if token_value:
                    headers = _headers_for_token(token_key, token_value, token_type)
                    session = AuthSession(headers=headers, cookies=cookies, base_url=base_url)
                    return ApiLoginResult(
                        success=True,
                        session=session,
                        login_url=candidate,
                        method="json",
                        token=token_value,
                        token_type=token_type,
                        token_key=token_key,
                        cookies=cookies,
                        headers=headers,
                        attempts=attempts,
                    )

                if cookies:
                    session = AuthSession(cookies=cookies, base_url=base_url)
                    return ApiLoginResult(
                        success=True,
                        session=session,
                        login_url=candidate,
                        method="json",
                        cookies=cookies,
                        attempts=attempts,
                    )

                if resp.status_code == 415 or "unsupported media type" in (resp.text or "").lower():
                    try:
                        resp_form = await client.post(candidate, data=payload)
                    except Exception as e:
                        last_error = str(e)
                        continue
                    cookies = dict(resp_form.cookies)
                    token_key, token_value, token_type = None, None, None
                    if resp_form.text:
                        try:
                            data = resp_form.json()
                        except Exception:
                            try:
                                data = json.loads(resp_form.text)
                            except Exception:
                                data = None
                        if data is not None:
                            token_key, token_value, token_type = _extract_token(data)
                    if token_value:
                        headers = _headers_for_token(token_key, token_value, token_type)
                        session = AuthSession(headers=headers, cookies=cookies, base_url=base_url)
                        return ApiLoginResult(
                            success=True,
                            session=session,
                            login_url=candidate,
                            method="form",
                            token=token_value,
                            token_type=token_type,
                            token_key=token_key,
                            cookies=cookies,
                            headers=headers,
                            attempts=attempts,
                        )
                    if cookies:
                        session = AuthSession(cookies=cookies, base_url=base_url)
                        return ApiLoginResult(
                            success=True,
                            session=session,
                            login_url=candidate,
                            method="form",
                            cookies=cookies,
                            attempts=attempts,
                        )

                if resp.status_code >= 400 and _looks_like_login_failure(resp.text or ""):
                    last_error = f"{resp.status_code} login failed"

            if max_attempts and attempts >= max_attempts:
                break

    if not last_error:
        last_error = "no login endpoints responded successfully"
    return ApiLoginResult(success=False, attempts=attempts, error=last_error)
