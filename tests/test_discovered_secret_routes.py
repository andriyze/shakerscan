"""Operator routes for discovered secrets: planner ingress refused, unknown ids are 404, and a
listing carries metadata only (the store tests cover the SQL in real PostgreSQL)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "api"), str(ROOT / "scanner")]

from targets import discovered_secret_routes as routes  # noqa: E402

TARGET = str(uuid.uuid4())
SECRET = str(uuid.uuid4())
NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)


class Conn:
    def __init__(self):
        self.calls = []

    async def fetchval(self, query, *args):
        self.calls.append(query)
        if query.startswith("SELECT 1 FROM targets"):
            return 1 if str(args[0]) == TARGET else None
        return uuid.UUID(SECRET) if str(args[0]) == SECRET else None

    async def fetch(self, query, *args):
        self.calls.append(query)
        return [{
            "id": uuid.UUID(SECRET), "kind": "password", "label": "DB_PASSWORD", "length": 22,
            "source": {"kind": "hunt_action", "id": "a", "hunt_id": "h"}, "first_seen_at": NOW,
            "last_seen_at": NOW, "seen_count": 1, "state": "active", "expires_at": NOW,
            "uses": 0, "last_used_at": None, "value_ciphertext": "enc:fernet:never-returned",
        }]


class Pool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        conn = self.conn

        class Ctx:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *exc):
                return False
        return Ctx()


@pytest.fixture
def client(monkeypatch):
    conn = Conn()
    monkeypatch.setattr(routes, "pool", lambda: Pool(conn))
    app = FastAPI()
    app.include_router(routes.router)
    return TestClient(app), app


def test_a_listing_carries_metadata_and_never_a_value(client):
    http, _ = client
    listed = http.get(f"/targets/{TARGET}/discovered-secrets").json()
    assert listed["count"] == 1 and listed["values_visible"] is False
    item = listed["secrets"][0]
    assert item["ref"] == f"secret://{SECRET}" and "value" not in str(item).lower().replace("values", "")
    assert "enc:fernet" not in str(listed)
    assert http.get(f"/targets/{uuid.uuid4()}/discovered-secrets").status_code == 404
    assert http.get("/targets/not-a-uuid/discovered-secrets").status_code == 404


def test_state_and_expiry_changes_answer_404_for_another_targets_secret(client):
    http, _ = client
    ok = http.post(f"/targets/{TARGET}/discovered-secrets/{SECRET}/state", json={"state": "revoked_by_operator"})
    assert ok.status_code == 200
    missing = http.post(f"/targets/{TARGET}/discovered-secrets/{uuid.uuid4()}/state", json={"state": "active"})
    assert missing.status_code == 404
    assert http.post(f"/targets/{TARGET}/discovered-secrets/{SECRET}/state",
                     json={"state": "superseded"}).status_code == 422
    assert http.post(f"/targets/{TARGET}/discovered-secrets/{SECRET}/expiry", json={"days": 0}).status_code == 422
    assert http.post(f"/targets/{TARGET}/discovered-secrets/{SECRET}/expiry", json={"days": 7}).status_code == 200


def test_the_planner_ingress_is_refused(client):
    http, app = client

    @app.middleware("http")
    async def planner(request, call_next):
        request.scope["shakerscan.planner_hunt_id"] = "hunt-1"
        return await call_next(request)

    refused = TestClient(app).get(f"/targets/{TARGET}/discovered-secrets")
    assert refused.status_code == 403 and refused.json()["detail"]["reason_code"] == "operator_only"
