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
