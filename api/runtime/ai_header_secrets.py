"""Secret values in an AI target's header template: encrypted at rest, never returned.

A header such as ``Authorization`` or ``X-Api-Key`` placed in the template used to be stored and
served in plaintext. Its value is now encrypted with the credential key when it is saved, shown as
``***`` in every response, and decrypted only when the request to the AI target is built. Sending
``***`` back on an update keeps the stored value.
"""
from __future__ import annotations

import json
from typing import Any

try:
    from secret_store import SecretStoreUnavailable, encrypt_secret, encryption_enabled
except ModuleNotFoundError:  # package-style imports in tests
    from api.secret_store import SecretStoreUnavailable, encrypt_secret, encryption_enabled

MASK = '***'
# Same markers the AI Gate report redaction uses, plus the other usual credential header names.
SECRET_MARKERS = ('authorization', 'auth', 'cookie', 'token', 'secret', 'password', 'key',
                  'session', 'credential', 'signature')
MIGRATION = 'v2_ai_header_template_secrets_v1'


def is_secret_header(name: str) -> bool:
    lowered = str(name).lower()
    return any(marker in lowered for marker in SECRET_MARKERS)


def protect(headers: dict[str, str], existing: dict[str, Any] | None = None) -> dict[str, str]:
    """Encrypt secret header values; ``***`` keeps the value already stored under that name."""
    stored = {str(name).lower(): value for name, value in (existing or {}).items()}
    protected: dict[str, str] = {}
    for name, value in headers.items():
        if not is_secret_header(name):
            protected[name] = value
            continue
        if value == MASK:
            if not isinstance(stored.get(name.lower()), str) or not stored[name.lower()]:
                raise ValueError(f'Header {name} has no stored value to keep; send its value')
            value = stored[name.lower()]
        protected[name] = encrypt_secret(value)
    return protected


def masked(headers: Any) -> Any:
    if not isinstance(headers, dict):
        return headers
    return {name: (MASK if is_secret_header(name) and value not in (None, '') else value)
            for name, value in headers.items()}


async def encrypt_stored_secrets(conn: Any) -> int:
    """Encrypt secret header values saved before they were protected. Runs once per database."""
    if await conn.fetchval('SELECT 1 FROM app_schema_migrations WHERE name=$1', MIGRATION):
        return 0
    if not encryption_enabled():
        return 0  # retried on the next start, once the key is available
    updated = 0
    for row in await conn.fetch("SELECT id, headers_template FROM ai_targets WHERE headers_template <> '{}'::jsonb"):
        headers = row['headers_template']
        headers = json.loads(headers) if isinstance(headers, str) else dict(headers or {})
        clean = {str(k): v for k, v in headers.items() if isinstance(v, str)}
        protected = {**headers, **protect(clean)}
        if protected != headers:
            await conn.execute('UPDATE ai_targets SET headers_template=$2::jsonb WHERE id=$1',
                               row['id'], json.dumps(protected))
            updated += 1
    await conn.execute('INSERT INTO app_schema_migrations(name) VALUES($1) ON CONFLICT DO NOTHING', MIGRATION)
    return updated


def protect_or_http_error(headers: dict[str, str], existing: Any = None) -> dict[str, str]:
    from fastapi import HTTPException
    if isinstance(existing, str):
        existing = json.loads(existing or '{}')
    try:
        return protect(headers, existing if isinstance(existing, dict) else None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except SecretStoreUnavailable:
        raise HTTPException(status_code=503, detail='Credential encryption is unavailable; secret headers cannot be saved') from None
