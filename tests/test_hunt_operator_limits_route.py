"""Exercise the public request boundary, not only its downstream normalizer."""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "api")]

import httpx
import pytest
from fastapi import FastAPI

from api.hunt import run_router
from api.hunt.start_contract import MAX_DIRECT_ORIGIN_ADDRESSES, MAX_SKILLS
from api.hunt.target_binding import web_hunt_target

TARGET = "11111111-1111-4111-8111-111111111111"
RECEIPT = "22222222-2222-4222-8222-222222222222"


@pytest.mark.parametrize("field,limit", [
    ("skill_ids", MAX_SKILLS),
    ("direct_origin_addresses", MAX_DIRECT_ORIGIN_ADDRESSES),
])
@pytest.mark.parametrize("over_limit", [False, True])
def test_post_hunts_enforces_the_advertised_limit(monkeypatch, field, limit, over_limit):
    admitted = []

    async def resolve(_target_id):
        return {"approval_receipt_id": RECEIPT, "scope_receipt_id": "scope"}

    async def start(contract):
        admitted.append(contract)
        return {"hunt_id": "fixture", "policy": contract.policy.public_dict()}

    monkeypatch.setattr(run_router, "_standing_authorization_resolver", resolve)
    monkeypatch.setattr(run_router, "_start_handler", start)
    app = FastAPI()
    app.include_router(run_router.router)
    count = limit + int(over_limit)
    values = ([f"203.0.113.{i + 1}" for i in range(count)]
              if field == "direct_origin_addresses"
              else [f"skill.web-{i:02d}" for i in range(count)])
    payload = {
        "target_id": TARGET, "target_kind": "network", "goal": "Inspect fixture",
        "policy": {"allow_direct_origin": True} if field == "direct_origin_addresses" else {},
        field: values,
    }

    async def execute():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://fixture",
        ) as client:
            return await client.post("/hunts", json=payload)

    response = asyncio.run(execute())
    assert response.status_code == (422 if over_limit else 200), response.text
    if over_limit:
        assert admitted == []
    else:
        assert len(getattr(admitted[0], field)) == limit


@pytest.mark.parametrize("kind", ["web", "api", "network"])
def test_worker_binding_accepts_all_labels_of_a_web_asset(kind):
    target, url = web_hunt_target(
        {"target_kind": kind, "target_id": TARGET},
        {"target": {"url": "http://fixture.test:8123", "origins": ["http://fixture.test:8123"]},
         "authorized_target_addresses": ["127.0.0.1"]},
        {"scope_receipt_id": "scope"},
    )
    assert url == "http://fixture.test:8123"
    assert target.target_kind == kind
    assert target.target_id == TARGET
    assert target.allowed_addresses == ("127.0.0.1",)


def test_device_uuid_does_not_become_a_web_asset_by_accident():
    with pytest.raises(ValueError):
        web_hunt_target({"target_kind": "device", "target_id": TARGET}, {}, {})
