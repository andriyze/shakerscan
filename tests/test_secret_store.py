"""Encryption-at-rest for target credential secrets."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))


def _reload_secret_store():
    import secret_store
    secret_store._loaded = False
    secret_store._fernet = None
    return secret_store


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


def test_initializer_creates_private_api_owned_key_before_worker_start(monkeypatch, tmp_path):
    monkeypatch.delenv("AI_CREDENTIAL_ENC_KEY", raising=False)
    path = tmp_path / "credential.key"
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY_FILE", str(path))
    ss = _reload_secret_store()
    ss.initialize_storage_owner(os.getuid(), os.getgid())
    for file in (path, tmp_path / "credential.key.lock"):
        assert file.stat().st_mode & 0o777 == 0o600
        assert file.stat().st_uid == os.getuid()
    ciphertext = ss.encrypt_secret("fixture-canary")
    ss.initialize_storage_owner(os.getuid(), os.getgid())
    assert _reload_secret_store().decrypt_secret(ciphertext) == "fixture-canary"



def test_initializer_failure_names_the_key_file_and_never_replaces_it(monkeypatch, tmp_path):
    monkeypatch.delenv("AI_CREDENTIAL_ENC_KEY", raising=False)
    path = tmp_path / "credential.key"
    path.write_text("")  # damaged: an empty key must never be silently regenerated
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY_FILE", str(path))
    ss = _reload_secret_store()
    with pytest.raises(ss.SecretStoreUnavailable) as failure:
        ss.initialize_storage_owner(os.getuid(), os.getgid())
    assert str(path) in str(failure.value) and "Restore it" in str(failure.value)
    assert path.read_text() == ""


@pytest.fixture(autouse=True)
def reset_key_cache(monkeypatch):
    import secret_store
    monkeypatch.setattr(secret_store, "_loaded", False)
    monkeypatch.setattr(secret_store, "_fernet", None)


def test_a_new_key_file_is_owner_only_from_creation(monkeypatch, tmp_path):
    """Not just after a later chmod: the temporary file never has the umask's wider mode."""
    monkeypatch.delenv("AI_CREDENTIAL_ENC_KEY", raising=False)
    path = tmp_path / "credential.key"
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY_FILE", str(path))
    ss = _reload_secret_store()
    monkeypatch.setattr(ss.os, "chmod", lambda *args, **kwargs: None)
    previous = os.umask(0o022)
    try:
        assert ss.encryption_enabled()
    finally:
        os.umask(previous)
    assert path.stat().st_mode & 0o777 == 0o600
