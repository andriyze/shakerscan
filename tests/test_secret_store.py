"""Encryption-at-rest for target credential secrets."""

import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))


def _reload_secret_store():
    import secret_store
    return importlib.reload(secret_store)


def test_unavailable_key_store_fails_closed(monkeypatch, tmp_path):
    monkeypatch.delenv("AI_CREDENTIAL_ENC_KEY", raising=False)
    blocked_parent = tmp_path / "not-a-directory"
    blocked_parent.write_text("file")
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY_FILE", str(blocked_parent / "credential.key"))
    ss = _reload_secret_store()
    assert ss.encryption_enabled() is False
    with pytest.raises(ss.SecretStoreUnavailable):
        ss.encrypt_secret("hunter2")
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
    with pytest.raises(ss.SecretStoreUnavailable):
        ss.encrypt_secret("hunter2")


def test_auto_generated_key_is_stable_and_file_is_private(monkeypatch, tmp_path):
    pytest.importorskip("cryptography")
    monkeypatch.delenv("AI_CREDENTIAL_ENC_KEY", raising=False)
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY_FILE", str(tmp_path / "credential.key"))
    first = _reload_secret_store()
    ciphertext = first.encrypt_secret("hunter2")
    key_contents = (tmp_path / "credential.key").read_text()
    assert (tmp_path / "credential.key").stat().st_mode & 0o777 == 0o600
    second = _reload_secret_store()
    assert (tmp_path / "credential.key").read_text() == key_contents
    assert second.decrypt_secret(ciphertext) == "hunter2"


def teardown_module(module):
    os.environ.pop("AI_CREDENTIAL_ENC_KEY", None)
    os.environ.pop("AI_CREDENTIAL_ENC_KEY_FILE", None)
    _reload_secret_store()
