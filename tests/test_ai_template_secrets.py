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

def test_secret_fields_are_masked_by_word_and_settings_stay_visible(key):
    stored = ai_template_secrets.protect({
        "input": "{{prompt}}", "api_token": "t-canary", "api_secret": "s-canary", "secret_key": "k-canary",
        "auth": {"bearerToken": "b-canary"}, "max_tokens": 64, "keywords": ["a"], "session_id": "s-1"})
    shown = ai_template_secrets.public(stored)
    assert shown == {"input": "{{prompt}}", "api_token": "***", "api_secret": "***", "secret_key": "***",
                     "auth": {"bearerToken": "***"}, "max_tokens": 64, "keywords": ["a"], "session_id": "s-1"}
    assert "canary" not in json.dumps(shown)


def test_literal_mask_text_is_kept_outside_secret_fields(key):
    created = ai_template_secrets.protect({"input": "{{prompt}}", "stop": "***", "api_token": "t-canary"})
    assert ai_template_secrets.reveal(created)["stop"] == "***"
    # An edit sends back what it was shown: the secret keeps its value, ordinary text its new value.
    updated = ai_template_secrets.protect({"input": "{{prompt}} v2", "stop": "***", "api_token": "***"}, created)
    assert ai_template_secrets.reveal(updated) == {"input": "{{prompt}} v2", "stop": "***", "api_token": "t-canary"}
    with pytest.raises(ValueError):
        ai_template_secrets.protect({"input": "{{prompt}}", "api_token": "***"})


def test_name_value_header_lists_mask_the_secret_value_and_keep_it_on_save(key):
    """{"name": "Authorization", "value": "Bearer ..."} was returned in clear: neither key is a
    secret word. The secret is the sibling value, judged by the header name."""
    template = {
        "headers": [
            {"name": "Authorization", "value": "Bearer live-canary"},
            {"name": "X-Session-Token", "value": "session-canary"},
            {"name": "Content-Type", "value": "application/json"},
        ],
        "params": [{"key": "client_assertion", "val": "assertion-canary"}, {"key": "page", "val": "2"}],
        "auth_jwt": "jwt-canary",
        "otp": "123456",
    }
    stored = ai_template_secrets.protect(template)
    shown = ai_template_secrets.public(stored)
    text = json.dumps(shown)
    for canary in ("live-canary", "session-canary", "assertion-canary", "jwt-canary", "123456"):
        assert canary not in text
    assert shown["headers"][2] == {"name": "Content-Type", "value": "application/json"}
    assert shown["params"][1]["val"] == "2"
    # Saving the masked editor view keeps the stored secrets.
    shown["headers"][2]["value"] = "text/plain"
    restored = ai_template_secrets.reveal(ai_template_secrets.protect(shown, stored))
    assert restored["headers"][0]["value"] == "Bearer live-canary"
    assert restored["headers"][1]["value"] == "session-canary"
    assert restored["params"][0]["val"] == "assertion-canary"
    assert restored["headers"][2]["value"] == "text/plain"


@pytest.mark.parametrize("change", ["reverse", "delete_first"])
def test_masked_named_entries_keep_their_own_values_after_reorder_or_removal(key, change):
    template = {"headers": [{"name": "Authorization", "value": "Bearer first-canary"},
                            {"name": "X-Session-Token", "value": "second-canary"}]}
    stored = ai_template_secrets.protect(template)
    shown = ai_template_secrets.public(stored)
    shown["headers"] = list(reversed(shown["headers"])) if change == "reverse" else shown["headers"][1:]
    restored = ai_template_secrets.reveal(ai_template_secrets.protect(shown, stored))
    values = {item["name"]: item["value"] for item in restored["headers"]}
    assert values["X-Session-Token"] == "second-canary"
    if change == "reverse":
        assert values["Authorization"] == "Bearer first-canary"


@pytest.mark.parametrize("name", ["X-Debug", "X-Other-Token"])
def test_renaming_a_masked_entry_never_inherits_the_previous_secret(key, name):
    stored = ai_template_secrets.protect({"header": {"name": "Authorization", "value": "Bearer rename-canary"}})
    shown = ai_template_secrets.public(stored)
    shown["header"]["name"] = name
    with pytest.raises(ValueError, match="Masked"):
        ai_template_secrets.protect(shown, stored)
    shown["header"]["value"] = "explicit-replacement"
    restored = ai_template_secrets.reveal(ai_template_secrets.protect(shown, stored))
    assert restored["header"]["value"] == "explicit-replacement"
    assert "rename-canary" not in json.dumps(ai_template_secrets.public(stored))


def test_duplicate_named_masks_are_ambiguous_but_explicit_values_are_editable(key):
    template = {"headers": [{"name": "Authorization", "value": value} for value in ("first-canary", "second-canary")]}
    stored = ai_template_secrets.protect(template)
    with pytest.raises(ValueError, match="Masked"):
        ai_template_secrets.protect(ai_template_secrets.public(stored), stored)
    assert ai_template_secrets.reveal(ai_template_secrets.protect(template, stored)) == template


def test_parameter_labels_remain_visible_and_survive_reordering(key):
    template = {"params": [{"key": "client_assertion", "val": "assertion-canary"},
                           {"key": "api_key", "val": "api-canary"}]}
    stored = ai_template_secrets.protect(template)
    shown = ai_template_secrets.public(stored)
    assert shown["params"][0]["key"] == "client_assertion"
    shown["params"].reverse()
    restored = ai_template_secrets.reveal(ai_template_secrets.protect(shown, stored))
    assert restored["params"] == list(reversed(template["params"]))
