"""Raw HTTP archive payloads are sealed before the evidence store sees them."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "api"), str(ROOT)]


@pytest.fixture
def key(monkeypatch):
    from cryptography.fernet import Fernet
    import secret_store
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", False)
    return secret_store


def test_the_store_only_receives_the_sealed_payload_and_keeps_the_plaintext_digest(key):
    from evidence_storage import serialize_evidence_content
    from runtime.archive_blob_secrets import encrypting_store, reveal
    received = []
    def store(content):
        received.append(content)
        raw, sha, size = serialize_evidence_content(content)
        return {"content_sha256": sha, "size_bytes": size, "storage_uri": "inline:", "content": raw}
    payload = {"authorization": "Bearer archive-canary"}
    stored = encrypting_store(store)(payload)
    assert "archive-canary" not in json.dumps(received) and "archive-canary" not in json.dumps(stored)
    # Deduplication still keys on the payload, not on the random ciphertext.
    assert (stored["content_sha256"], stored["size_bytes"]) == serialize_evidence_content(payload)[1:]
    assert json.loads(reveal(stored["content"])) == payload


def test_plain_rows_read_unchanged_and_an_unreadable_seal_reads_as_absent(key, monkeypatch):
    from runtime import archive_blob_secrets as blobs
    assert blobs.reveal('{"a": "b"}') == '{"a": "b"}' and blobs.reveal(None) is None
    sealed = json.dumps(blobs.envelope('{"a":"b"}'))
    def unavailable(value):
        raise key.SecretStoreUnavailable("key unavailable")
    monkeypatch.setattr(blobs, "decrypt_secret", unavailable)
    assert blobs.reveal(sealed) is None


def test_without_a_key_the_payload_is_not_archived_at_all(monkeypatch):
    import secret_store
    from runtime.archive_blob_secrets import encrypting_store
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", True)
    called = []
    stored = encrypting_store(lambda content: called.append(content) or {})({"cookie": "sid=1"})
    assert stored["content_sha256"] is None and called == []


def test_a_payload_that_fit_inline_in_plaintext_stays_inline_when_sealed(key):
    """Encryption grows a payload by about a third; it must not push it into external storage,
    which the archive reader does not load."""
    from evidence_storage import INLINE_STORAGE_URI, evidence_inline_max_bytes
    from runtime.archive_blob_secrets import encrypting_store, reveal
    body = "x" * (evidence_inline_max_bytes() - 1024)  # e.g. a 31 KiB body under a 32 KiB limit
    externalized = []
    stored = encrypting_store(lambda content: externalized.append(content) or {})(body)
    assert externalized == [] and stored["storage_uri"] == INLINE_STORAGE_URI
    assert json.loads(reveal(stored["content"])) == body


def test_a_payload_too_large_inline_in_plaintext_is_still_externalized_sealed(key):
    from evidence_storage import evidence_inline_max_bytes
    from runtime.archive_blob_secrets import encrypting_store, is_envelope
    externalized = []
    encrypting_store(lambda content: externalized.append(content) or {"storage_uri": "local:x"})(
        "y" * (evidence_inline_max_bytes() + 1))
    assert len(externalized) == 1 and is_envelope(externalized[0])
