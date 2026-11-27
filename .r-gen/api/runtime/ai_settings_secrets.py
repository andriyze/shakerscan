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


def compact_history(redis) -> None:
    """Rewrite Redis persistence after the provider key changed.

    Redis keeps every earlier write in its append-only file until it is rewritten, so a replaced,
    cleared or once-plaintext key would otherwise stay on disk. Best effort: a rewrite already in
    progress or a restricted command is logged, never raised.
    """
    try:
        persistence = redis.info("persistence") or {}
        if int(persistence.get("aof_enabled") or 0):
            redis.bgrewriteaof()
        else:
            redis.bgsave()
    except Exception as exc:  # noqa: BLE001 - persistence compaction must not fail the request
        _LOG.warning("Could not compact Redis persistence after a provider key change: %s", type(exc).__name__)


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
                if redis.eval(_CAS, 1, name, "ai_api_key", value, encrypted):
                    compact_history(redis)
            except (SecretStoreUnavailable, RedisError):
                pass  # legacy reads survive; new writes always require encryption
        try:
            values["ai_api_key"] = decrypt_secret(value)
        except SecretStoreUnavailable:
            values.pop("ai_api_key", None)
            _LOG.warning("Stored AI provider key is unavailable; keeping other AI settings")
    return values
