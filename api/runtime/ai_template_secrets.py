"""Encrypt complete AI request templates; retain masked secrets on editor updates."""
from __future__ import annotations
import json
import re
from typing import Any
from .ai_header_secrets import MASK, is_secret_header
try:
    from secret_store import encrypt_secret, decrypt_secret, encryption_enabled, SecretStoreUnavailable
except ModuleNotFoundError:
    from api.secret_store import encrypt_secret, decrypt_secret, encryption_enabled, SecretStoreUnavailable

SCHEMA = "ai-request-template/encrypted-v1"
MIGRATION = "v2_ai_request_template_secrets_v1"
# A field is secret when one of its words is a secret word (api_token, secretKey, X-Api-Key) or its
# run-together name ends in one (accesstoken, apisecret). Plurals and other words stay visible:
# max_tokens, keywords, session_id and author are template settings, not credentials.
_SECRET_WORDS = frozenset({
    "password", "passwd", "pwd", "passphrase", "secret", "secrets", "token", "apikey", "key",
    "credential", "credentials", "cookie", "cookies", "authorization", "auth", "bearer",
    "privatekey", "signature", "jwt", "otp", "assertion",
})
# Header and parameter lists are often written as name/value objects
# ({"name": "Authorization", "value": "Bearer ..."}). There the secret is the sibling value, so a
# secret-looking name (judged like a header name) makes these value fields secret too.
_PAIR_NAME_KEYS = ("name", "key", "header", "field", "param")
_PAIR_VALUE_KEYS = frozenset({"value", "val", "content"})
_SECRET_SUFFIXES = ("password", "passwd", "passphrase", "secret", "token", "apikey", "privatekey",
                    "secretkey", "accesskey", "clientkey", "sessionkey", "credential", "credentials")


def is_secret_field(name: Any) -> bool:
    words = [w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", str(name))]
    joined = "".join(words)
    return bool(words) and (any(w in _SECRET_WORDS for w in words) or joined.endswith(_SECRET_SUFFIXES))


def _secret_pair_values(*nodes: Any) -> frozenset[str]:
    for node in nodes:
        if not isinstance(node, dict):
            continue
        for name_key in _PAIR_NAME_KEYS:
            name = node.get(name_key)
            if isinstance(name, str) and name != MASK and (is_secret_field(name) or is_secret_header(name)):
                return _PAIR_VALUE_KEYS
    return frozenset()


def reveal(value: Any) -> dict:
    value = json.loads(value) if isinstance(value, str) else dict(value or {})
    if value.get("schema_version") == SCHEMA:
        value = json.loads(decrypt_secret(value["ciphertext"]))
    if not isinstance(value, dict):
        raise ValueError("request template must be an object")
    return value


def _restore(value: Any, existing: Any, sensitive: bool = False) -> Any:
    """``***`` keeps the stored value only where the response masked it: in a secret field.
    Anywhere else it is ordinary text and is saved as written."""
    if sensitive and value == MASK:
        if existing is None:
            raise ValueError("Masked template value has no stored value to keep")
        return existing
    if isinstance(value, dict):
        pair_values = _secret_pair_values(value, existing)
        return {k: _restore(v, existing.get(k) if isinstance(existing, dict) else None,
                            sensitive or is_secret_field(k) or k in pair_values) for k, v in value.items()}
    if isinstance(value, list):
        return [_restore(v, existing[i] if isinstance(existing, list) and i < len(existing) else None, sensitive)
                for i, v in enumerate(value)]
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
            pair_values = _secret_pair_values(node)
            return {k: mask(v, sensitive or is_secret_field(k) or k in pair_values) for k, v in node.items()}
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
