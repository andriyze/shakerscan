"""Secret header values in an AI target's template are encrypted at rest and never returned."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'api'), str(ROOT)]


@pytest.fixture
def key(monkeypatch):
    from cryptography.fernet import Fernet
    import secret_store
    monkeypatch.setenv('AI_CREDENTIAL_ENC_KEY', Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, '_fernet', None)
    monkeypatch.setattr(secret_store, '_loaded', False)
    return secret_store


def test_secret_headers_are_encrypted_and_content_headers_are_not(key):
    from runtime.ai_header_secrets import protect
    stored = protect({'Content-Type': 'application/json', 'X-Api-Key': 'sk-live-123', 'Authorization': 'Bearer abc'})
    assert stored['Content-Type'] == 'application/json'
    for name in ('X-Api-Key', 'Authorization'):
        assert stored[name].startswith('enc:fernet:') and 'sk-live' not in stored[name]
    assert key.decrypt_secret(stored['X-Api-Key']) == 'sk-live-123'


def test_the_mask_keeps_the_stored_value_and_never_becomes_the_value(key):
    from runtime.ai_header_secrets import MASK, masked, protect
    first = protect({'X-Api-Key': 'sk-live-123'})
    shown = masked({**first, 'Accept': 'application/json'})
    assert shown == {'X-Api-Key': MASK, 'Accept': 'application/json'}
    # A client that sends back what it was shown keeps the secret; a legacy plaintext one is encrypted.
    kept = protect({'x-api-key': MASK}, existing=first)
    assert key.decrypt_secret(kept['x-api-key']) == 'sk-live-123'
    assert key.decrypt_secret(protect({'Cookie': MASK}, existing={'Cookie': 'sid=1'})['Cookie']) == 'sid=1'
    with pytest.raises(ValueError):
        protect({'X-Api-Key': MASK}, existing={})


def test_the_request_to_the_ai_target_carries_the_decrypted_value(key):
    from ai_gate.targets.rest_json import build_headers
    from runtime.ai_header_secrets import protect
    headers = build_headers({'headers_template': protect({'X-Api-Key': 'sk-live-123', 'Accept': 'text/plain'}),
                             'credential': {'auth_kind': 'none'}})
    assert headers['X-Api-Key'] == 'sk-live-123' and headers['Accept'] == 'text/plain'


def test_saving_fails_closed_without_a_key(monkeypatch):
    import secret_store
    from fastapi import HTTPException
    from runtime.ai_header_secrets import protect_or_http_error
    monkeypatch.setattr(secret_store, '_fernet', None)
    monkeypatch.setattr(secret_store, '_loaded', True)
    with pytest.raises(HTTPException) as error:
        protect_or_http_error({'Authorization': 'Bearer abc'})
    assert error.value.status_code == 503
    # Content headers never need the key.
    assert protect_or_http_error({'Accept': 'application/json'}) == {'Accept': 'application/json'}


class _Connection:
    def __init__(self, rows):
        self.rows, self.markers, self.updates = rows, set(), {}

    async def fetchval(self, query, name):
        return 1 if name in self.markers else None

    async def fetch(self, query):
        return [{'id': row_id, 'headers_template': json.dumps(headers)} for row_id, headers in self.rows.items()]

    async def execute(self, query, *args):
        if query.startswith('UPDATE'):
            self.updates[args[0]] = json.loads(args[1])
        else:
            self.markers.add(args[0])


def test_stored_plaintext_secrets_are_encrypted_once(key):
    from runtime.ai_header_secrets import encrypt_stored_secrets
    conn = _Connection({'a': {'X-Api-Key': 'sk-live-123', 'Accept': 'application/json'}, 'b': {'Accept': 'text/plain'}})
    assert asyncio.run(encrypt_stored_secrets(conn)) == 1
    assert set(conn.updates) == {'a'}
    assert key.decrypt_secret(conn.updates['a']['X-Api-Key']) == 'sk-live-123'
    assert conn.updates['a']['Accept'] == 'application/json'
    assert asyncio.run(encrypt_stored_secrets(conn)) == 0  # the marker stops a second pass


def test_without_a_key_the_backfill_waits_for_the_next_start(monkeypatch):
    import secret_store
    from runtime.ai_header_secrets import encrypt_stored_secrets
    monkeypatch.setattr(secret_store, '_fernet', None)
    monkeypatch.setattr(secret_store, '_loaded', True)
    conn = _Connection({'a': {'X-Api-Key': 'sk-live-123'}})
    assert asyncio.run(encrypt_stored_secrets(conn)) == 0
    assert not conn.markers and not conn.updates


def test_header_backfill_encrypts_a_literal_editor_mask(key):
    from runtime.ai_header_secrets import encrypt_stored_secrets
    conn = _Connection({'fixture': {'X-Api-Key': '***'}})
    assert asyncio.run(encrypt_stored_secrets(conn)) == 1
    assert key.decrypt_secret(conn.updates['fixture']['X-Api-Key']) == '***'
