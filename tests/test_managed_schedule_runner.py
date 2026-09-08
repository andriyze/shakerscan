"""Managed scheduler orchestration with controlled persistence/transport fixtures."""

import asyncio
import types
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from schedules import managed_runner as runner
from schedules.managed_dispatch import DispatchOutcome

from tests.api_sources import definition_source


def test_unconfigured_mode_is_standalone_and_partial_configuration_fails(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_SCHEDULE_DISPATCH_ORIGIN", raising=False)
    monkeypatch.delenv("SHAKERSCAN_SCHEDULE_DISPATCH_TOKEN", raising=False)
    assert asyncio.run(runner.run_due(None)) is False
    monkeypatch.setenv("SHAKERSCAN_SCHEDULE_DISPATCH_ORIGIN", "https://gateway.test")
    with pytest.raises(ValueError, match="incomplete"):
        asyncio.run(runner.run_due(None))


@pytest.mark.parametrize("state", ["retry", "accepted", "denied"])
def test_managed_dispatch_uses_persisted_payload_and_receipt(monkeypatch, state):
    now = datetime.now(timezone.utc)
    schedule_id, occurrence_id, lease_id = uuid4(), uuid4(), uuid4()
    schedule = {
        "id": schedule_id,
        "target_url": "https://example.test",
        "scan_options": {},
        "schedule_kind": "normal_scan",
    }
    persisted = {"target": "https://example.test", "budget_profile": "fast"}
    init = AsyncMock()
    claim = AsyncMock(
        return_value={"id": occurrence_id, "lease_id": lease_id, "payload": persisted}
    )
    settle = AsyncMock(return_value=True)
    monkeypatch.setattr(runner.occurrences, "initialize", init)
    monkeypatch.setattr(runner.occurrences, "claim", claim)
    monkeypatch.setattr(runner.occurrences, "settle", settle)
    monkeypatch.setattr(
        runner.schedule_ops, "fetch_due_schedules", AsyncMock(return_value=[schedule])
    )
    monkeypatch.setattr(runner.schedule_ops, "schedule_next_run_at", lambda _: now)
    dispatcher = type("Dispatcher", (), {"origin": "https://gateway.test"})()
    dispatcher.dispatch = AsyncMock(
        return_value=DispatchOutcome(
            state, "fixture", str(uuid4()) if state == "accepted" else None
        )
    )
    assert asyncio.run(runner.run_due(object(), dispatcher=dispatcher, now=now)) is True
    dispatcher.dispatch.assert_awaited_once_with(
        str(schedule_id), str(occurrence_id), persisted
    )
    assert settle.await_args.kwargs["state"] == state
    assert settle.await_args.kwargs["next_run_at"] == (
        None if state == "retry" else now
    )


@pytest.mark.parametrize(
    "options",
    [
        {"auth_header": "synthetic-secret"},
        {"credential_profile_ids": [str(uuid4())]},
        {"policy": {"active_testing": True}},
        {"custom_endpoints": ["GET /private"]},
    ],
)
def test_payload_does_not_silently_drop_unsupported_authority(options):
    with pytest.raises(ValueError):
        runner.scan_payload(
            {
                "target_url": "https://example.test",
                "scan_options": options,
                "schedule_kind": "normal_scan",
            }
        )


def test_unsupported_managed_kind_never_falls_back(monkeypatch):
    monkeypatch.setattr(runner.occurrences, "initialize", AsyncMock())
    claim = AsyncMock()
    monkeypatch.setattr(runner.occurrences, "claim", claim)
    monkeypatch.setattr(
        runner.schedule_ops,
        "fetch_due_schedules",
        AsyncMock(
            return_value=[
                {
                    "id": uuid4(),
                    "target_url": "https://example.test",
                    "scan_options": {},
                    "schedule_kind": "asm_improve",
                }
            ]
        ),
    )
    dispatcher = type(
        "Dispatcher", (), {"origin": "https://gateway.test", "dispatch": AsyncMock()}
    )()
    assert asyncio.run(runner.run_due(None, dispatcher=dispatcher)) is True
    claim.assert_not_awaited()
    dispatcher.dispatch.assert_not_awaited()


@pytest.mark.parametrize("managed", [False, True])
def test_real_scheduler_entrypoint_routes_before_local_queue(monkeypatch, managed):
    callback = AsyncMock(return_value=managed)
    monkeypatch.setattr(runner, "run_due", callback)

    class LocalPathReached(Exception):
        pass

    def local_queue():
        raise LocalPathReached()

    namespace = {
        "asyncpg": types.SimpleNamespace(Pool=object),
        "get_redis": local_queue,
    }
    exec(  # noqa: S102 -- execute the trusted repository function, not external input
        compile(
            definition_source("run_due_schedules"), "<scheduler entrypoint>", "exec"
        ),
        namespace,
    )
    if managed:
        asyncio.run(namespace["run_due_schedules"](None))
    else:
        with pytest.raises(LocalPathReached):
            asyncio.run(namespace["run_due_schedules"](None))
    callback.assert_awaited_once_with(None)
