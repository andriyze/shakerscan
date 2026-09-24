"""DELETE /request-collections/{id} retires a collection and everything hanging off it.

Before this route a web request collection could be uploaded but never removed: the UI had no
delete control and the API had no route, so a mistaken or stale upload stayed selectable forever.
"""
from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

import request_collection_api  # noqa: E402


class _Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Connection:
    def __init__(self, collection_row):
        self.collection_row = collection_row
        self.statements: list[str] = []

    def transaction(self):
        return _Transaction()

    async def fetchrow(self, sql, *params):
        self.statements.append(" ".join(sql.split()))
        assert "is_active=false" in sql and "RETURNING *" in sql
        return self.collection_row

    async def execute(self, sql, *params):
        self.statements.append(" ".join(sql.split()))
        return "UPDATE 2" if "request_collection_selections" in sql else "UPDATE 1"


class _Acquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return _Acquire(self.conn)


@pytest.fixture
def bind_pool(monkeypatch):
    def _bind(conn):
        request_collection_api.configure_request_collection_router(lambda: _Pool(conn))
        return conn
    yield _bind
    request_collection_api.configure_request_collection_router(lambda: None)


def test_deactivate_hides_collection_and_revokes_dependents(bind_pool):
    collection_id = uuid.uuid4()
    conn = bind_pool(_Connection({
        "id": collection_id, "target_id": uuid.uuid4(), "device_target_id": None,
        "name": "stale", "format": "postman_collection", "encrypted_payload": "cipher",
        "payload_sha256": "a" * 64, "request_count": 3, "safe_request_count": 3,
        "potentially_mutating_request_count": 0, "metadata_json": "{}", "is_active": False,
    }))
    result = asyncio.run(request_collection_api.deactivate_request_collection(str(collection_id)))
    assert result["status"] == "deactivated"
    assert result["collection"]["id"] == str(collection_id)
    assert result["collection"]["is_active"] is False
    assert "encrypted_payload" not in result["collection"]
    assert result["revoked_selections"] == 2
    touched = [s for s in conn.statements if s.startswith("UPDATE")]
    tables = [s.split()[1] for s in touched]
    assert tables == [
        "request_collections", "request_collection_selections",
        "request_collection_bindings", "request_collection_environments",
    ]
    selections = next(s for s in touched if "request_collection_selections" in s)
    assert "revoked_at=COALESCE(revoked_at, NOW())" in selections
    for statement in touched[1:]:
        assert "collection_id=$1 AND is_active=true" in statement


def test_unknown_or_already_retired_collection_is_404_and_touches_nothing_else(bind_pool):
    conn = bind_pool(_Connection(None))
    with pytest.raises(HTTPException) as exc:
        asyncio.run(request_collection_api.deactivate_request_collection(str(uuid.uuid4())))
    assert exc.value.status_code == 404
    assert len(conn.statements) == 1


def test_malformed_id_is_rejected_before_the_database(bind_pool):
    conn = bind_pool(_Connection(None))
    with pytest.raises(HTTPException) as exc:
        asyncio.run(request_collection_api.deactivate_request_collection("not-a-uuid"))
    assert exc.value.status_code == 400
    assert conn.statements == []
