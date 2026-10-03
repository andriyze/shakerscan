"""Encrypt complete AI request templates; retain masked secrets on editor updates."""
from __future__ import annotations
import json
from typing import Any
from .ai_header_secrets import MASK
try:
    from secret_store import encrypt_secret, decrypt_secret, encryption_enabled, SecretStoreUnavailable
except ModuleNotFoundError:
    from api.secret_store import encrypt_secret, decrypt_secret, encryption_enabled, SecretStoreUnavailable

SCHEMA = "ai-request-template/encrypted-v1"
MIGRATION = "v2_ai_request_template_secrets_v1"
_SECRET_FIELDS = frozenset({
    "password", "passwd", "secret", "secrets", "clientsecret", "apikey", "xapikey",
    "accesstoken", "refreshtoken", "idtoken", "token", "authtoken", "bearertoken",
    "authorization", "auth", "cookie", "cookies", "privatekey", "credentials",
    "credential", "sessiontoken", "sessionkey",
})


def reveal(value: Any) -> dict:
    value = json.loads(value) if isinstance(value, str) else dict(value or {})
    if value.get("schema_version") == SCHEMA:
        value = json.loads(decrypt_secret(value["ciphertext"]))
    if not isinstance(value, dict):
        raise ValueError("request template must be an object")
    return value


def _restore(value: Any, existing: Any) -> Any:
    if value == MASK:
        if existing is None:
            raise ValueError("Masked template value has no stored value to keep")
        return existing
    if isinstance(value, dict):
        return {k: _restore(v, existing.get(k) if isinstance(existing, dict) else None) for k, v in value.items()}
    if isinstance(value, list):
        return [_restore(v, existing[i] if isinstance(existing, list) and i < len(existing) else None) for i, v in enumerate(value)]
    return value


def protect(value: dict, existing: Any = None) -> dict:
    if value.get("schema_version") == SCHEMA:
        raise ValueError("Client cannot submit a storage envelope")
    plain = _restore(value, reveal(existing))
    return _encrypt(plain)


def _encrypt(value: dict) -> dict:
    """Encrypt stored data literally; editor masks are interpreted only by protect."""
    return {"schema_version": SCHEMA, "ciphertext": encrypt_secret(json.dumps(value, ensure_ascii=False))} if value else {}


def public(value: Any) -> dict:
    def mask(node: Any, sensitive: bool = False) -> Any:
        if isinstance(node, dict):
            return {k: mask(v, sensitive or "".join(c for c in str(k).casefold() if c.isalnum()) in _SECRET_FIELDS) for k, v in node.items()}
        if isinstance(node, list):
            return [mask(v, sensitive) for v in node]
        return MASK if sensitive and node not in (None, "") else node
    return mask(reveal(value))


def protect_or_http_error(value: dict, existing: Any = None) -> dict:
    from fastapi import HTTPException
    try:
        return protect(value, existing)
    except SecretStoreUnavailable:
        raise HTTPException(503, "Credential encryption is unavailable; request template cannot be saved") from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


async def encrypt_stored_templates(conn: Any) -> int:
    if await conn.fetchval("SELECT 1 FROM app_schema_migrations WHERE name=$1", MIGRATION) or not encryption_enabled():
        return 0
    count = 0
    for row in await conn.fetch("SELECT id, request_template FROM ai_targets WHERE request_template <> '{}'::jsonb FOR UPDATE"):
        stored = json.loads(row["request_template"]) if isinstance(row["request_template"], str) else dict(row["request_template"] or {})
        if stored.get("schema_version") == SCHEMA:
            continue
        await conn.execute("UPDATE ai_targets SET request_template=$2::jsonb WHERE id=$1", row["id"], json.dumps(_encrypt(stored)))
        count += 1
    await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1) ON CONFLICT DO NOTHING", MIGRATION)
    return count
