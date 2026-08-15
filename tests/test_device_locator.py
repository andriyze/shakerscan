"""Behavior tests for mutable network locators on durable device identities."""

import asyncio
import os
import sys
import uuid

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import api as api_module  # noqa: E402


class FakeLocatorConnection:
    def __init__(self, *, active_scan: bool = False, active_agent: bool = False):
        self.device = {
            "id": uuid.uuid4(),
            "primary_locator": "192.168.1.10",
            "metadata_json": {},
        }
        self.active_scan = active_scan
        self.active_agent = active_agent
        self.executed: list[tuple[str, tuple[object, ...]]] = []

    async def fetchrow(self, query, *args):
        if "FOR UPDATE" in query:
            return dict(self.device)
        if "INSERT INTO device_locator_history" in query:
            return {
                "id": uuid.uuid4(),
                "device_target_id": args[0],
                "previous_locator": args[1],
                "locator": args[2],
                "locator_type": args[3],
                "change_reason": args[4],
                "change_source": args[5],
            }
        if "SELECT * FROM device_targets" in query:
            return dict(self.device)
        raise AssertionError(query)

    async def fetchval(self, query, *_args):
        if "FROM scans" in query:
            return 1 if self.active_scan else None
        if "FROM device_agent_runs" in query:
            return 1 if self.active_agent else None
        raise AssertionError(query)

    async def execute(self, query, *args):
        self.executed.append((query, args))
        if "UPDATE device_targets SET primary_locator" in query:
            self.device["primary_locator"] = args[0]
        return "OK"


def test_locator_change_updates_address_without_creating_a_new_device():
    conn = FakeLocatorConnection()
    original_id = conn.device["id"]

    device, history = asyncio.run(api_module._change_device_primary_locator(
        conn,
        original_id,
        "192.168.1.45",
        reason="DHCP reassignment",
        source="operator",
    ))

    assert device["id"] == original_id
    assert device["primary_locator"] == "192.168.1.45"
    assert history["previous_locator"] == "192.168.1.10"
    assert history["locator"] == "192.168.1.45"
    assert any("INSERT INTO device_interfaces" in query for query, _ in conn.executed)
    assert not any("INSERT INTO device_targets" in query for query, _ in conn.executed)


@pytest.mark.parametrize("active_scan,active_agent", [(True, False), (False, True)])
def test_locator_change_is_blocked_while_device_work_is_active(active_scan, active_agent):
    conn = FakeLocatorConnection(active_scan=active_scan, active_agent=active_agent)

    with pytest.raises(HTTPException) as error:
        asyncio.run(api_module._change_device_primary_locator(
            conn,
            conn.device["id"],
            "192.168.1.45",
            reason=None,
            source="operator",
        ))

    assert error.value.status_code == 409
    assert conn.executed == []


def test_reselecting_current_locator_is_idempotent():
    conn = FakeLocatorConnection()

    device, history = asyncio.run(api_module._change_device_primary_locator(
        conn,
        conn.device["id"],
        conn.device["primary_locator"],
        reason=None,
        source="operator",
    ))

    assert device["primary_locator"] == "192.168.1.10"
    assert history is None
    assert conn.executed == []
