from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)


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
    # The Agent Hunt write handlers are DELETED, not merely isolated, so this no
    # longer requires them to exist -- see the deletion proofs below. The
    # middleware remains for the surfaces still pending removal in later phases.
    # Agent Hunt and device-agent writes are DELETED, not merely isolated. The
    # middleware remains for the surfaces still pending removal (Research).
    assert not route_is_declared("POST", "/agent/hunt/{target_id}")
    assert not route_is_declared("POST", "/devices/{device_id}/agent/session")
    assert route_is_declared("POST", "/research/launch")
    assert "It is not a Hunt launcher" in product
    assert "A Hunt request creates one `/hunts` run" in product


def test_no_non_cancel_write_exists_under_the_legacy_agent_hunt_surface():
    """The legacy write handlers are deleted, not merely blocked.

    Keeping full handler bodies behind a 410 middleware preserves dead attack
    surface, imports, request models, database writes, and maintenance cost.
    The middleware stays as the migration response, but there must be nothing
    left for it to guard.
    """
    from tests.api_sources import declared_routes

    offenders = [
        f"{method} {path}"
        for method, path in declared_routes("/agent/hunt")
        if method not in {"GET", "HEAD", "OPTIONS"}
        and not path.rstrip("/").endswith("/cancel")
    ]
    assert not offenders, (
        f"legacy Agent Hunt still declares non-cancel writes: {offenders}"
    )


def test_deleted_legacy_agent_hunt_symbols_are_gone_from_the_api_tree():
    """The handlers and everything reachable only from them are removed."""
    from tests.api_sources import api_tree_source

    source = api_tree_source()
    for symbol in (
        "async def run_agent_hunt_endpoint", "async def start_agent_hunt_session",
        "async def submit_agent_hunt_reply", "async def _run_agent_hunt(",
        "class AgentHuntRequest", "class AgentHuntSessionStartRequest",
        "class AgentHuntReplyRequest",
    ):
        assert symbol not in source, f"{symbol} survived the legacy Hunt deletion"


def test_legacy_agent_finding_verification_write_is_deleted():
    """Candidate reads remain, but verification uses canonical Hunt/finding flows."""
    root = Path(__file__).resolve().parents[1]
    source = (root / "api" / "agent_routes" / "router.py").read_text()
    ui_client = (root / "ui" / "src" / "lib" / "api.ts").read_text()

    assert not route_is_declared("POST", "/agent/findings/{finding_id}/verify")
    assert route_is_declared("GET", "/agent/findings/{target_id}")
    assert route_is_declared("POST", "/findings/{finding_id:path}/retest")
    assert "verify_suspected_agent_finding" not in source
    assert "verifySuspectedAgentFinding" not in ui_client


def test_legacy_agent_hunt_writes_return_410_without_invoking_the_old_engine():
    """The migration response must not reach any former handler."""
    from hunt.legacy import LegacyHuntIsolationMiddleware, legacy_hunt_write_blocked

    for method, path in (
        ("POST", "/agent/hunt/target-1"),
        ("POST", "/agent/hunt/target-1/session"),
        ("POST", "/agent/hunt/session/run-1/reply"),
    ):
        assert legacy_hunt_write_blocked(path, method), f"{method} {path} is not blocked"

    # History and cancellation stay reachable for the migration window.
    for method, path in (
        ("GET", "/agent/hunt/runs"),
        ("GET", "/agent/hunt/session/run-1"),
        ("POST", "/agent/hunt/session/run-1/cancel"),
    ):
        assert not legacy_hunt_write_blocked(path, method), (
            f"{method} {path} must remain available during the migration window"
        )

    sent: list[dict] = []

    async def _never_called(scope, receive, send):  # pragma: no cover - must not run
        raise AssertionError("the legacy Hunt engine was invoked")

    async def _send(message):
        sent.append(message)

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    import asyncio

    middleware = LegacyHuntIsolationMiddleware(_never_called)
    asyncio.run(middleware(
        {"type": "http", "method": "POST", "path": "/agent/hunt/target-1", "headers": []},
        _receive,
        _send,
    ))
    assert sent and sent[0]["status"] == 410
    headers = dict(sent[0]["headers"])
    assert headers.get(b"deprecation") == b"true"
    assert b"/hunts" in headers.get(b"link", b"")


def test_no_new_legacy_agent_hunt_rows_are_written():
    """The quarantined table must not gain rows once its engine is deleted."""
    from tests.api_sources import api_tree_source

    source = api_tree_source()
    assert "INSERT INTO agent_hunt_runs" not in source, (
        "a legacy agent_hunt_runs insert survives; the surface is read-only"
    )


def test_no_non_cancel_write_exists_under_the_legacy_device_agent_surface():
    """The device-agent write handlers are deleted, like Agent Hunt's."""
    from tests.api_sources import declared_routes, route_is_declared

    offenders = [
        f"{method} {path}"
        for method, path in declared_routes("/device-agent")
        if method not in {"GET", "HEAD", "OPTIONS"}
        and not path.rstrip("/").endswith("/cancel")
    ]
    assert not offenders, f"legacy device-agent still declares writes: {offenders}"
    assert not route_is_declared("POST", "/devices/{device_id}/agent/session")
    # History and cancellation remain for the migration window.
    assert route_is_declared("GET", "/device-agent/runs")
    assert route_is_declared("POST", "/device-agent/session/{run_id}/cancel")


def test_no_new_legacy_device_agent_rows_are_written():
    from tests.api_sources import api_tree_source

    source = api_tree_source()
    for statement in ("INSERT INTO device_agent_runs", "INSERT INTO device_agent_actions"):
        assert statement not in source, f"{statement} survives; the surface is read-only"
