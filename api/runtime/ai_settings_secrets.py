"""Encrypted runtime provider keys, with a compare-and-set legacy backfill."""
from __future__ import annotations
import logging
from redis.exceptions import RedisError
try:
    from secret_store import encrypt_secret, decrypt_secret, SecretStoreUnavailable
except ModuleNotFoundError:
    from api.secret_store import encrypt_secret, decrypt_secret, SecretStoreUnavailable

_CAS = """if redis.call('HGET',KEYS[1],ARGV[1]) == ARGV[2] then
    return redis.call('HSET',KEYS[1],ARGV[1],ARGV[3]) end return 0"""
_LOG = logging.getLogger(__name__)


def protect_settings(values: dict) -> dict:
    return {key: encrypt_secret(value) if key == "ai_api_key" else value for key, value in values.items()}


def load_settings(redis, name: str) -> dict[str, str]:
    raw = redis.hgetall(name) or {}
    values = {(k.decode() if isinstance(k, bytes) else str(k)):
              (v.decode() if isinstance(v, bytes) else str(v)) for k, v in raw.items()}
    value = values.get("ai_api_key")
    if value:
        if not value.startswith("enc:fernet:"):
            try:
                encrypted = encrypt_secret(value)
                redis.eval(_CAS, 1, name, "ai_api_key", value, encrypted)
            except (SecretStoreUnavailable, RedisError):
                pass  # legacy reads survive; new writes always require encryption
        try:
            values["ai_api_key"] = decrypt_secret(value)
        except SecretStoreUnavailable:
            values.pop("ai_api_key", None)
            _LOG.warning("Stored AI provider key is unavailable; keeping other AI settings")
    return values
