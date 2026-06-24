"""R2b: encryption-at-rest for AI target credential secrets.

Opt-in via AI_CREDENTIAL_ENC_KEY; backward compatible (plaintext passthrough when
disabled, prefix-tagged so legacy rows and encrypted rows coexist).
"""

import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))


def _reload_secret_store():
    import secret_store
    return importlib.reload(secret_store)


def test_disabled_by_default_is_plaintext(monkeypatch):
    monkeypatch.delenv("AI_CREDENTIAL_ENC_KEY", raising=False)
    ss = _reload_secret_store()
    assert ss.encryption_enabled() is False
    assert ss.encrypt_secret("hunter2") == "hunter2"   # no-op when disabled
    assert ss.decrypt_secret("hunter2") == "hunter2"
    assert ss.encrypt_secret(None) is None
    assert ss.encrypt_secret("") == ""


def test_roundtrip_and_passthrough_when_key_set(monkeypatch):
    pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet

    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    ss = _reload_secret_store()
    assert ss.encryption_enabled() is True

    enc = ss.encrypt_secret("hunter2")
    assert enc.startswith("enc:fernet:")
    assert "hunter2" not in enc                       # ciphertext, not plaintext
    assert ss.decrypt_secret(enc) == "hunter2"        # round-trips
    assert ss.encrypt_secret(enc) == enc              # never double-encrypts
    assert ss.decrypt_secret("legacy-plaintext") == "legacy-plaintext"  # legacy rows pass through


def test_bad_key_disables_rather_than_crashes(monkeypatch):
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", "not-a-valid-fernet-key")
    ss = _reload_secret_store()
    assert ss.encryption_enabled() is False
    assert ss.encrypt_secret("hunter2") == "hunter2"


def teardown_module(module):
    os.environ.pop("AI_CREDENTIAL_ENC_KEY", None)
    _reload_secret_store()
