from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from hunt.legacy import LegacyHuntIsolationMiddleware, legacy_hunt_write_blocked


def test_duplicate_hunt_engines_are_quarantined_but_can_be_cancelled():
    assert legacy_hunt_write_blocked("/agent/hunt/target/session", "POST")
    assert legacy_hunt_write_blocked("/device-agent/session/run/reply", "POST")
    assert legacy_hunt_write_blocked("/devices/device/agent/session", "POST")
    assert not legacy_hunt_write_blocked("/agent/hunt/session/run", "GET")
    assert not legacy_hunt_write_blocked("/agent/hunt/session/run/cancel", "POST")
    assert not legacy_hunt_write_blocked("/hunts", "POST")


def test_quarantine_returns_gone_with_a_canonical_migration_pointer(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_LEGACY_HUNT_WRITES_ENABLED", "true")
    downstream_called = False
    messages: list[dict] = []

    async def downstream(scope, receive, send):
        nonlocal downstream_called
        downstream_called = True

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    middleware = LegacyHuntIsolationMiddleware(downstream)
    asyncio.run(middleware(
        {"type": "http", "method": "POST", "path": "/agent/hunt/target/session"},
        receive, send,
    ))

    assert downstream_called is False
    assert messages[0]["status"] == 410
    headers = dict(messages[0]["headers"])
    assert headers[b"deprecation"] == b"true"
    assert headers[b"link"] == b'</hunts>; rel="successor-version"'
    payload = json.loads(messages[1]["body"])
    assert payload["canonical_endpoint"] == "/hunts"
    assert "temporary_override_env" not in payload


def test_quarantine_preserves_cancel_with_deprecation_headers():
    downstream_called = False
    messages: list[dict] = []

    async def downstream(_scope, _receive, send):
        nonlocal downstream_called
        downstream_called = True
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    middleware = LegacyHuntIsolationMiddleware(downstream)
    asyncio.run(middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/agent/hunt/session/run/cancel",
        },
        receive,
        send,
    ))

    assert downstream_called is True
    assert messages[0]["status"] == 204
    headers = dict(messages[0]["headers"])
    assert headers[b"deprecation"] == b"true"
    assert headers[b"link"] == b'</hunts>; rel="successor-version"'


def test_legacy_hunt_routes_are_isolated_and_research_remains_specialized():
    root = Path(__file__).resolve().parents[1]
    api = (root / "api" / "api.py").read_text()
    product = (root / "docs" / "product-model.md").read_text()

    assert "app.add_middleware(LegacyHuntIsolationMiddleware)" in api
    assert '@app.post("/agent/hunt/{target_id}")' in api
    assert '@app.post("/devices/{device_id}/agent/session")' in api
    assert '@app.post("/research/launch")' in api
    assert "It is not a Hunt launcher" in product
    assert "A Hunt request creates one `/hunts` run" in product
