import hashlib
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.public_retry_receipts import router

SCAN_ID = "d2fbfe98-b5d7-41f9-83f1-5f1e4b8ba657"


class Pool:
    def __init__(self, row):
        self.row = row
        self.calls = 0

    def acquire(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def fetchrow(self, sql, key):
        self.calls += 1
        assert "method='POST' AND path='/scans'" in sql
        assert key == hashlib.sha256(b"receipt-fixture-key").hexdigest()
        return self.row


@pytest.mark.parametrize("mode,status", [
    ("recorded", 200), ("completed", 200), ("missing", 404), ("mismatch", 409),
    ("processing", 202), ("malformed", 202), ("wrong_kind", 202), ("conflict", 202),
])
def test_lookup_exposes_only_bound_recorded_identity(mode, status):
    value = {"schema": "public-dispatch-acceptance/v1", "kind": "scan",
             "status": "recorded", "id": SCAN_ID, "extra": "must-not-leak"}
    row = {"request_sha256": "a" * 64, "state": "processing", "response_status": None}
    if mode in {"completed", "conflict"}:
        row.update(state="completed", response_status=200)
        value = {"scan_id": SCAN_ID, "extra": "must-not-leak"}
        if mode == "conflict":
            value["id"] = "other"
    elif mode == "wrong_kind":
        value["kind"] = "retest"
    elif mode == "mismatch":
        row["request_sha256"] = "b" * 64
    row["response_body"] = (b"bad-json" if mode == "malformed" else
                            None if mode == "processing" else json.dumps(value).encode())
    app = FastAPI()
    app.include_router(router)
    app.state.db_pool = Pool(None if mode == "missing" else row)
    with TestClient(app) as client:
        response = client.get("/scans/dispatch-receipts/lookup", headers={
            "Idempotency-Key": "receipt-fixture-key", "X-ShakerScan-Request-SHA256": "a" * 64,
        })
    assert response.status_code == status
    assert response.headers["cache-control"] == "no-store"
    assert "must-not-leak" not in response.text
    assert "scan_id" in response.json() if status == 200 else "scan_id" not in response.json()


def test_lookup_requires_exact_single_headers_before_reading_database():
    app = FastAPI()
    app.include_router(router)
    app.state.db_pool = Pool(None)
    with TestClient(app) as client:
        path = "/scans/dispatch-receipts/lookup"
        assert client.get(path).status_code == 400
        headers = [("Idempotency-Key", "receipt-fixture-key"),
                   ("X-ShakerScan-Request-SHA256", "a" * 64)]
        assert client.get(path, headers=headers + [headers[0]]).status_code == 400
        assert client.get(path + "?key=forbidden", headers=headers).status_code == 400
    assert app.state.db_pool.calls == 0
