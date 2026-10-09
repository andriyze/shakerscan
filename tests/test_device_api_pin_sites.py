"""The two API-process device connect sites pin and check their address before any traffic.

Device Hunt ``device_http_request`` and the control-authorization replay connect from the API
process to a ``connect_address`` stored by an earlier posture scan. Both call
``_pin_device_origin`` first; the review of #358 deleted both calls and every test still passed,
because the only test exercised ``pin_device_connect_address`` directly. These drive the two
call sites themselves with a stored metadata address and require the refusal, and that no
request is attempted.

The pool, the stored posture origins, the request collection and the HTTP sender are labelled
test doubles (unit fixtures); nothing touches a database or the network.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import uuid
from contextlib import asynccontextmanager

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from devices import router as device_router

METADATA_ADDRESSES = ("169.254.169.254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "fd00:ec2::254")
PUBLIC_ADDRESS = "203.0.113.10"


class _FakeConnection:
    """Unit fixture: the rows the two paths read."""

    def __init__(self, rows=()):
        self.rows = list(rows)

    async def fetchval(self, query, *_args):
        assert "environment" in query
        return "production"

    async def fetch(self, *_args):
        return self.rows

    async def fetchrow(self, *_args):
        return None


class _FakePool:
    def __init__(self, rows=()):
        self.connection = _FakeConnection(rows)

    @asynccontextmanager
    async def acquire(self):
        yield self.connection


def _origin(connect_address):
    return {
        "origin": "http://tv.test:80", "scheme": "http", "hostname": "tv.test", "port": 80,
        "connect_address": connect_address, "host_header": "",
    }


@pytest.fixture
def sent(monkeypatch):
    """Every request the paths attempt (labelled double for the pinned HTTP sender)."""
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
    attempts: list[dict] = []

    async def record(**kwargs):
        attempts.append(kwargs)
        return {"status": 200, "headers": {}, "body": b"{}"}

    monkeypatch.setattr(device_router, "_device_request_pinned_http", record)
    monkeypatch.setattr(device_router, "_device_request_pinned_control_http", record)
    return attempts


def _device_http_request(monkeypatch, connect_address):
    async def origins(_device_target_id):
        return [_origin(connect_address)]

    monkeypatch.setattr(device_router, "_pool_provider", lambda: _FakePool())
    monkeypatch.setattr(device_router, "_device_confirmed_web_origins", origins)
    return asyncio.run(device_router._execute_device_capability_operation(
        run_id=uuid.uuid4(), device_target_id=uuid.uuid4(), safety_profile="authenticated_active",
        approval_receipt_id=None, state={}, name="device_http_request",
        args={"method": "GET", "path": "/", "origin_port": 80},
    ))


@pytest.mark.parametrize("address", METADATA_ADDRESSES)
def test_device_http_request_refuses_a_stored_metadata_address(monkeypatch, sent, address):
    with pytest.raises(HTTPException) as caught:
        _device_http_request(monkeypatch, address)
    assert caught.value.status_code == 422
    assert sent == []


def test_device_http_request_connects_to_the_pinned_public_address(monkeypatch, sent):
    result = _device_http_request(monkeypatch, PUBLIC_ADDRESS)
    assert result["ok"] is True
    assert [item["connect_address"] for item in sent] == [PUBLIC_ADDRESS]


def _replay(monkeypatch, connect_address):
    collection_id = str(uuid.uuid4())
    payload = {"requests": ["unit fixture"]}
    digest = hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    imported = {"id": "change", "method": "POST", "url": "http://tv.test/api/setting", "headers": {}}
    reverse = {"id": "undo", "method": "POST", "url": "http://tv.test/api/setting", "headers": {}}
    blocked: list[list[str]] = []

    async def origins(_device_target_id):
        return [_origin(connect_address)]

    async def record_blocked(**kwargs):
        blocked.append(list(kwargs["gaps"]))
        return {"ok": False, "gaps": kwargs["gaps"]}

    rows = [{"id": collection_id, "name": "c", "document_sha256": digest, "encrypted_payload": "x"}]
    monkeypatch.setattr(device_router, "_pool_provider", lambda: _FakePool(rows))
    monkeypatch.setattr(device_router, "_device_confirmed_web_origins", origins)
    monkeypatch.setattr(device_router, "_device_control_authorization_blocked", record_blocked)
    monkeypatch.setattr(device_router.device_agent, "control_authorization_precondition_gaps", lambda *_a: [])
    monkeypatch.setattr(device_router, "decrypt_secret", lambda _value: json.dumps(payload))
    monkeypatch.setattr(device_router, "_resolve_imported_device_requests", lambda _p: [imported, reverse])
    monkeypatch.setattr(device_router, "_device_paired_reverse_request", lambda _items, _id: reverse)
    result = asyncio.run(device_router._verify_device_control_authorization_candidate(
        run_id=uuid.uuid4(), device_target_id=uuid.uuid4(), candidate_id=uuid.uuid4(),
        state={"device_request_collections": [{"collection_id": collection_id}]},
        locus={"collection_id": collection_id, "request_id": "change", "cleanup_request_id": "undo",
               "state_path": "/api/setting"},
    ))
    return result, blocked


@pytest.mark.parametrize("address", METADATA_ADDRESSES)
def test_the_control_replay_refuses_a_stored_metadata_address(monkeypatch, sent, address):
    _result, blocked = _replay(monkeypatch, address)
    assert blocked == [["request_origin_destination_refused"]]
    assert sent == []


def test_the_control_replay_connects_to_the_pinned_public_address(monkeypatch, sent):
    async def record_then_stop(**kwargs):
        sent.append(kwargs)
        raise ConnectionResetError  # stop after the first request; the rest of the proof is not under test

    monkeypatch.setattr(device_router, "_device_request_pinned_http", record_then_stop)
    with pytest.raises(HTTPException) as caught:
        _replay(monkeypatch, PUBLIC_ADDRESS)
    assert caught.value.status_code == 502
    assert [item["connect_address"] for item in sent] == [PUBLIC_ADDRESS]
