"""Template migration and editor masking preserve their different semantics."""
import asyncio
import json
import pytest
import secret_store
from runtime import ai_template_secrets, ai_settings_secrets


@pytest.fixture
def key(monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_loaded", False)
    monkeypatch.setattr(secret_store, "_fernet", None)


def test_body_masking_keeps_normal_configuration_visible(key):
    template = {"input": "{{prompt}}", "max_tokens": 100, "author": "operator",
                "keywords": ["test"], "session_id": "conversation-1",
                "nested": {"apiKey": "secret-canary", "client_secret": "client-canary"}}
    stored = ai_template_secrets.protect(template)
    shown = ai_template_secrets.public(stored)
    assert {k: shown[k] for k in ("input", "max_tokens", "author", "keywords", "session_id")} == {
        k: template[k] for k in ("input", "max_tokens", "author", "keywords", "session_id")}
    assert shown["nested"] == {"apiKey": "***", "client_secret": "***"}
    shown["max_tokens"] = 200
    restored = ai_template_secrets.reveal(ai_template_secrets.protect(shown, stored))
    assert restored["nested"] == template["nested"] and restored["max_tokens"] == 200


def test_template_backfill_encrypts_literal_masks_and_is_idempotent(key):
    class Connection:
        marked = False
        stored = {"input": "{{prompt}}", "api_key": "***", "nested": ["***"]}
        async def fetchval(self, query, *args): return self.marked
        async def fetch(self, query): return [{"id": "fixture", "request_template": json.dumps(self.stored)}]
        async def execute(self, query, *args):
            if query.startswith("UPDATE"): self.stored = json.loads(args[1])
            else: self.marked = True
    conn = Connection()
    assert asyncio.run(ai_template_secrets.encrypt_stored_templates(conn)) == 1
    assert conn.stored["ciphertext"].startswith("enc:fernet:")
    assert ai_template_secrets.reveal(conn.stored) == {"input": "{{prompt}}", "api_key": "***", "nested": ["***"]}
    assert asyncio.run(ai_template_secrets.encrypt_stored_templates(conn)) == 0


def test_unreadable_provider_key_keeps_other_settings(monkeypatch, caplog):
    class Redis:
        def hgetall(self, name): return {"ai_api_key": "enc:fernet:unreadable", "ai_api_url": "http://fixture", "ai_model": "fixture-model"}
    def unavailable(value): raise secret_store.SecretStoreUnavailable("key unavailable")
    monkeypatch.setattr(ai_settings_secrets, "decrypt_secret", unavailable)
    assert ai_settings_secrets.load_settings(Redis(), "settings:ai") == {
        "ai_api_url": "http://fixture", "ai_model": "fixture-model"}
    assert "keeping other AI settings" in caplog.text
    assert "enc:fernet:unreadable" not in caplog.text


def test_legacy_provider_read_survives_a_backfill_redis_error(key):
    from redis.exceptions import RedisError
    class Redis:
        def hgetall(self, name): return {"ai_api_key": "legacy-canary", "ai_model": "fixture-model"}
        def eval(self, *args): raise RedisError("CAS not available")
    assert ai_settings_secrets.load_settings(Redis(), "settings:ai")["ai_api_key"] == "legacy-canary"


def test_report_contains_a_readable_redacted_template(key):
    from ai_gate_scan import _target_snapshot_for_manifest
    stored = ai_template_secrets.protect({"input": "{{prompt}}", "max_tokens": 64, "api_key": "report-canary"})
    report = _target_snapshot_for_manifest({"request_template": stored})
    assert report["request_template"] == {"input": "{{prompt}}", "max_tokens": 64, "api_key": "***"}
    assert "ciphertext" not in json.dumps(report) and "report-canary" not in json.dumps(report)


class _PersistingRedis:
    """Records persistence compaction; ``aof`` mirrors Redis's aof_enabled."""
    def __init__(self, values, *, aof=True, swap=1):
        self.values, self.aof, self.swap, self.compacted = values, aof, swap, []
    def hgetall(self, name): return dict(self.values)
    def eval(self, *args): return self.swap
    def info(self, section): return {"aof_enabled": 1 if self.aof else 0}
    def bgrewriteaof(self): self.compacted.append("aof")
    def bgsave(self): self.compacted.append("rdb")


def test_encrypting_a_legacy_provider_key_compacts_persisted_history(key):
    redis = _PersistingRedis({"ai_api_key": "legacy-canary"})
    assert ai_settings_secrets.load_settings(redis, "settings:ai")["ai_api_key"] == "legacy-canary"
    assert redis.compacted == ["aof"]
    # Another reader already swapped it: nothing to compact again.
    lost_race = _PersistingRedis({"ai_api_key": "legacy-canary"}, swap=0)
    ai_settings_secrets.load_settings(lost_race, "settings:ai")
    assert lost_race.compacted == []
    snapshot_only = _PersistingRedis({}, aof=False)
    ai_settings_secrets.compact_history(snapshot_only)
    assert snapshot_only.compacted == ["rdb"]


def test_compaction_failure_never_fails_the_caller(caplog):
    class Restricted(_PersistingRedis):
        def bgrewriteaof(self):
            from redis.exceptions import ResponseError
            raise ResponseError("Background append only file rewriting already in progress")
    ai_settings_secrets.compact_history(Restricted({}))
    assert "Could not compact Redis persistence" in caplog.text
