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


def _pair_identity(node: Any) -> tuple[tuple[str, str], ...]:
    """Structural labels identify a name/value entry; positions do not."""
    if not isinstance(node, dict) or not any(k in node for k in _PAIR_VALUE_KEYS):
        return ()
    return tuple((k, node[k]) for k in _PAIR_NAME_KEYS
                 if isinstance(node.get(k), str) and node[k] != MASK)


def _field_sensitive(node: dict, key: str, inherited: bool) -> bool:
    # A field called `key` may contain credential material, not a parameter name.
    # Entry matching must never lower the existing masking classification.
    return inherited or is_secret_field(key) or key in _secret_pair_values(node)


def _matching_pair_identity(value: dict, existing: dict, sensitive: bool, old_sensitive: bool) -> tuple:
    labels = dict(value)
    for key in _PAIR_NAME_KEYS:
        if (value.get(key) == MASK and isinstance(existing.get(key), str)
                and _field_sensitive(value, key, sensitive)
                and _field_sensitive(existing, key, old_sensitive)):
            labels[key] = existing[key]
    return _pair_identity(labels)


def _mask_node(node: Any, sensitive: bool = False) -> Any:
    if isinstance(node, dict):
        return {k: _mask_node(v, _field_sensitive(node, k, sensitive)) for k, v in node.items()}
    if isinstance(node, list):
        return [_mask_node(v, sensitive) for v in node]
    return MASK if sensitive and node not in (None, "") else node


def _same_json_node(left: Any, right: Any) -> bool:
    """Compare JSON structure without Python's bool/int/float equivalence."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _same_json_node(value, right[key]) for key, value in left.items()
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same_json_node(value, old) for value, old in zip(left, right)
        )
    return left == right


def _restore(value: Any, existing: Any, sensitive: bool = False, old_sensitive: bool = False) -> Any:
    """Only a previously masked field of the same entry may retain a secret."""
    if sensitive and value == MASK:
        if existing is None or not old_sensitive:
            raise ValueError("Masked template value has no stored value to keep")
        return existing
    if isinstance(value, dict):
        old = existing if isinstance(existing, dict) else {}
        if _matching_pair_identity(value, old, sensitive, old_sensitive) != _pair_identity(old):
            if any(value.get(k) == MASK for k in _secret_pair_values(old)):
                raise ValueError("Masked template entry was renamed; provide its value")
            old = {}
        return {k: _restore(v, old.get(k), _field_sensitive(value, k, sensitive) or k in _secret_pair_values(old),
                            _field_sensitive(old, k, old_sensitive)) for k, v in value.items()}
    if isinstance(value, list):
        previous = existing if isinstance(existing, list) else []
        # An unchanged masked view is a no-op, including repeated
        # secret masks and duplicate named entries. Preserve each original slot;
        # never infer a reorder from indistinguishable masks. Any list edit must
        # take the identity-matching path below instead.
        if isinstance(existing, list) and _same_json_node(value, _mask_node(previous, old_sensitive)):
            return [_restore(item, old, sensitive, old_sensitive)
                    for item, old in zip(value, previous)]
        restored = []
        for item in value:
            identity = _pair_identity(item)
            candidates = [old for old in previous if isinstance(old, dict) and
                _matching_pair_identity(item, old, sensitive, old_sensitive) == _pair_identity(old)] if identity else [
                old for old in previous if _mask_node(old, old_sensitive) == item]
            # No positional fallback for edits: duplicate names or indistinguishable masks
            # cannot establish which prior secret the operator intended to keep.
            old = candidates[0] if len(candidates) == 1 else None
            restored.append(_restore(item, old, sensitive, old_sensitive))
        return restored
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
    return _mask_node(reveal(value))


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
