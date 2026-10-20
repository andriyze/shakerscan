"""list/v1 Service Intelligence pages keep each page row with its own inventory.

A connected device is also an active ``targets`` row with the same id (its ``host://`` asset), so
the filtered inventory holds a ``device`` row and a ``web`` row that share a UUID. When both land
on one page, each must keep its own evidence: the device its services, the host target its own.
"""
from __future__ import annotations

from datetime import datetime, timezone
import sys
import uuid

import pytest

from api.exposure import service_store

DEVICE = uuid.UUID("44444444-4444-4444-8444-444444444444")
WEB = uuid.UUID("55555555-5555-4555-8555-555555555555")
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)
ARGS = dict(target_kind="all", target_id=None, root_domain=None, search="", snapshot={}, matcher=None, registry=None)


def _row(kind, target_id, locator):
    """A page row: the columns ``page_targets_sql`` selects plus the list/v1 keyset aliases."""
    return {"id": target_id, "kind": kind, "label": f"{kind} {locator}", "locator": locator,
            "root_domain": None, "locator_generation": 1 if kind == "device" else None,
            "locator_changed_at": NOW if kind == "device" else None,
            "__list_sort": kind, "__list_id": target_id}


DEVICE_ROW = _row("device", DEVICE, "10.66.0.5")
HOST_ROW = _row("web", DEVICE, "host://10.66.0.5")
WEB_ROW = _row("web", WEB, "https://app.example.test")


class Conn:
    """Answers the page query with ``rows`` (already in page order, as PostgreSQL returns them)."""

    def __init__(self, rows):
        self.rows = rows
        self.page_params = []

    async def fetch(self, sql, *args):
        self.page_params.append(args)
        return list(self.rows)

    async def fetchval(self, sql, *args):
        return NOW if "clock_timestamp" in sql else len(self.rows)


@pytest.fixture(autouse=True)
def _cursor_key():
    contract = sys.modules[service_store.Page.__module__]
    contract.configure_cursor_key(b"k" * 32)
    yield
    contract.configure_cursor_key(None)


@pytest.fixture
def built(monkeypatch):
    """Replace the per-target evidence read with one that reports which row it was built for."""
    calls = []

    async def inventory(conn, target, snapshot, matcher, registry):
        calls.append((target["kind"], target["id"]))
        services = [{"transport": "tcp", "port": 22}, {"transport": "udp", "port": 161}]
        if target["kind"] != "device":
            services = []
        return {"id": str(target["id"]), "kind": target["kind"], "locator": target["locator"],
                "services": services, "source_count": len(services)}

    monkeypatch.setattr(service_store, "target_inventory", inventory)
    return calls


def _shape(items):
    return [(item["id"], item["kind"], item["locator"], len(item["services"])) for item in items]


# What each row's own inventory looks like: the device carries its two services.
DEVICE_ITEM = (str(DEVICE), "device", "10.66.0.5", 2)
HOST_ITEM = (str(DEVICE), "web", "host://10.66.0.5", 0)
WEB_ITEM = (str(WEB), "web", "https://app.example.test", 0)


@pytest.mark.asyncio
async def test_a_device_and_its_host_target_on_one_page_keep_their_own_inventories(built):
    rows = [DEVICE_ROW, HOST_ROW, WEB_ROW]
    body = await service_store.service_page_v1(
        Conn(rows), service_store.Page(limit=10, count="exact"), **ARGS)
    assert _shape(body["items"]) == [DEVICE_ITEM, HOST_ITEM, WEB_ITEM]
    assert body["total"] == 3 and body["has_more"] is False and body["next_cursor"] is None
    # The legacy offset page over the same rows is the reference: list/v1 returns the same targets.
    legacy = await service_store.service_page(Conn(rows), limit=10, offset=0, **ARGS)
    assert body["items"] == legacy["targets"]


@pytest.mark.asyncio
async def test_target_id_of_a_device_returns_the_device_and_its_host_target(built):
    conn = Conn([DEVICE_ROW, HOST_ROW])
    body = await service_store.service_page_v1(
        conn, service_store.Page(limit=10), **dict(ARGS, target_id=DEVICE))
    assert conn.page_params[0][1] == DEVICE  # the filter's $2
    assert _shape(body["items"]) == [DEVICE_ITEM, HOST_ITEM]


@pytest.mark.asyncio
async def test_descending_page_keeps_each_row_with_its_own_inventory(built):
    rows = [WEB_ROW, HOST_ROW, DEVICE_ROW]  # kind DESC, then id DESC
    body = await service_store.service_page_v1(
        Conn(rows), service_store.Page(limit=10, sort="-kind"), **ARGS)
    assert _shape(body["items"]) == [WEB_ITEM, HOST_ITEM, DEVICE_ITEM]


@pytest.mark.asyncio
async def test_a_full_page_builds_only_its_own_rows_and_continues_after_the_last(built):
    # limit + 1 rows: the extra row only proves has_more and gets no inventory.
    body = await service_store.service_page_v1(
        Conn([DEVICE_ROW, HOST_ROW, WEB_ROW]), service_store.Page(limit=2), **ARGS)
    assert _shape(body["items"]) == [DEVICE_ITEM, HOST_ITEM]
    assert built == [("device", DEVICE), ("web", DEVICE)]
    assert body["has_more"] is True and body["next_cursor"]
    # The cursor resumes after the page's last row, the host target (web, D), not the device.
    plan = service_store.SERVICES_V1.plan(
        service_store.Page(limit=2, cursor=body["next_cursor"]),
        filters={"target_kind": "all", "target_id": None, "root_domain": None, "search": ""})
    assert plan.position == ("web", DEVICE)
