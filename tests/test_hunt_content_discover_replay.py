"""web.content_discover hits reach the caller and the endpoint inventory.

Regression for soak defect 4 (2026-10-07, Hunts d89ed01f and 4b5a313c): content discovery runs
about a minute, longer than the client's HTTP wait, so the client settles the outcome by replaying
the same idempotency key. The replay read observations only from ``hunt_actions.result_summary``,
where worker-placed actions keep just a count, and hard-coded ``execution_started=False``: every
call returned ``replayed`` with no observations while ``observation_count`` was 4-8. Hits were
also never written to the target's endpoint inventory (only crawls were).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from api.hunt import endpoint_knowledge
from api.hunt import interaction_router as router

HUNT = str(uuid.uuid4())
KEY = "mcp-" + "a" * 32
INPUT = {"wordlist": "common"}
RECEIPT = str(uuid.uuid4())
HITS = [
    {"kind": "content_discovery", "url": "https://app.test/.git/config", "status": 200, "length": 92},
    {"kind": "content_discovery", "url": "https://app.test/admin", "status": 403, "length": 10},
]
# Content-safe summary exactly as process_canonical_scanner_capability_job persists it.
SUMMARY = {
    "status": "success", "ok": True, "partial": False, "timed_out": False,
    "observation_count": len(HITS), "record_count": len(HITS), "error": None,
    "budget_consumed": {"agent_actions": 1, "http_requests": 220, "tool_wall_seconds": 55},
    "receipt_id": RECEIPT,
}


class ReplayStore:
    def __init__(self, receipt):
        self.receipt = receipt
        self.queries = []

    @asynccontextmanager
    async def acquire(self):
        yield self

    @asynccontextmanager
    async def transaction(self, **_kwargs):
        yield self

    async def fetchrow(self, sql, *args):
        self.queries.append(sql)
        if "FROM hunt_actions" in sql:
            return {
                "capability_name": "web.content_discover", "status": "completed",
                "input_summary": json.dumps({
                    "input_digest": hashlib.sha256(json.dumps(
                        INPUT, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                    ).encode()).hexdigest(),
                    "idempotency_key_sha256": hashlib.sha256(KEY.encode()).hexdigest(),
                }),
                "result_summary": json.dumps(SUMMARY),
                "receipt_id": uuid.UUID(RECEIPT),
            }
        if "FROM budget_reservations" in sql:
            assert args[0] == HUNT
            return {"receipt_json": json.dumps(self.receipt)} if self.receipt is not None else None
        raise AssertionError(sql)


def _replay(monkeypatch, receipt):
    store = ReplayStore(receipt)

    async def lookup(_conn, hunt_id, for_update=False):
        return {"id": uuid.UUID(HUNT), "status": "completed", "target_kind": "web"}

    monkeypatch.setattr(router, "_pool", lambda: store)
    monkeypatch.setattr(router, "_hunt_run_or_404", lookup)
    request = router.HuntCapabilityRequest(idempotency_key=KEY, input=INPUT)
    return asyncio.run(router.execute_hunt_capability(HUNT, "web.content_discover", request))


def test_replay_returns_the_settled_receipts_observations(monkeypatch):
    result = _replay(monkeypatch, {"receipt_id": RECEIPT, "observations": HITS})
    assert result["idempotent_replay"] is True
    action = result["action_result"]
    assert action["status"] == "success"
    assert [item["url"] for item in action["observations"]] == [item["url"] for item in HITS]
    assert action["execution_started"] is True


def test_replay_never_returns_another_receipts_observations(monkeypatch):
    result = _replay(monkeypatch, {"receipt_id": str(uuid.uuid4()), "observations": HITS})
    assert result["action_result"]["observations"] == []


# Negative controls exactly as the worker's bounded wordlist emits them: paths that cannot exist.
CONTROLS = [
    {"kind": "content_discovery", "url": f"https://app.test/.shakerscan-absent-{index:016x}",
     "status": 404, "length": 19, "negative_control": True}
    for index in range(3)
]


def _catch_all(status, length, words):
    return [
        {"kind": "content_discovery", "url": f"https://app.test/{word}", "status": status,
         "length": length}
        for word in words
    ]


def test_content_discovery_hits_become_endpoints_but_controls_do_not():
    records = [
        *CONTROLS,
        *HITS,
        {"kind": "content_discovery", "url": "https://app.test/missing", "status": 404, "length": 19},
        {"kind": "content_discovery", "url": "https://other.test/admin", "status": 200, "length": 5},
    ]
    assert endpoint_knowledge.content_discovery_worklist(records, origin="https://app.test/") == [
        "GET /.git/config", "GET /admin",
    ]


def test_spa_catch_all_hits_never_enter_the_inventory():
    # An SPA answers every unknown path with its index shell: the controls measure that response,
    # so wordlist hits of the same status and size are not endpoints. A response that differs
    # (a real file, or a forbidden route on a host whose unknown paths answer 200) still is.
    controls = [{**item, "status": 200, "length": 75_210} for item in CONTROLS]
    records = [
        *controls,
        *_catch_all(200, 75_210, ["admin", "backup", "wp-login.php", "server-status"]),
        *_catch_all(200, 75_300, ["phpmyadmin"]),  # within the learned size tolerance
        {"kind": "content_discovery", "url": "https://app.test/.git/config", "status": 200,
         "length": 92},
        {"kind": "content_discovery", "url": "https://app.test/ftp", "status": 403, "length": 75_210},
    ]
    assert endpoint_knowledge.content_discovery_worklist(records, origin="https://app.test/") == [
        "GET /.git/config", "GET /ftp",
    ]


def test_blanket_forbidden_hits_never_enter_the_inventory():
    controls = [{**item, "status": 403, "length": 199} for item in CONTROLS]
    records = [*controls, *_catch_all(403, 199, [".env", ".htpasswd", "admin"])]
    assert endpoint_knowledge.content_discovery_worklist(records, origin="https://app.test/") == []


def test_uncalibrated_content_discovery_records_nothing():
    # Without a measured absent path a status-only hit cannot be told from a catch-all.
    assert endpoint_knowledge.content_discovery_worklist(HITS, origin="https://app.test/") == []


def test_content_discovery_is_recorded_in_the_endpoint_inventory(monkeypatch):
    calls = []

    async def upsert(conn, target_id, worklist, **kwargs):
        calls.append((target_id, worklist, kwargs))
        return len(worklist)

    monkeypatch.setattr(endpoint_knowledge.asm_inventory, "upsert_endpoints", upsert)
    count = asyncio.run(endpoint_knowledge.enrich_crawl_endpoints(
        None, target=SimpleNamespace(target_kind="web", target_id="owned"),
        origin="https://app.test/", capability="web.content_discover", input={},
        records=[*CONTROLS, *HITS],
    ))
    assert count == 2
    assert calls[0][1] == ["GET /.git/config", "GET /admin"]


class SavepointConnection:
    def __init__(self):
        self.savepoints = []

    @asynccontextmanager
    async def transaction(self, **_kwargs):
        self.savepoints.append("open")
        try:
            yield self
        except BaseException:
            self.savepoints.append("rolled_back")
            raise
        self.savepoints.append("released")


def test_inventory_failure_rolls_back_only_its_savepoint(monkeypatch):
    async def failing_upsert(conn, target_id, worklist, **kwargs):
        raise RuntimeError("inventory unavailable")

    monkeypatch.setattr(endpoint_knowledge.asm_inventory, "upsert_endpoints", failing_upsert)
    conn = SavepointConnection()
    count = asyncio.run(endpoint_knowledge.record_discovered_endpoints(
        conn, target=SimpleNamespace(target_kind="web", target_id="owned"),
        origin="https://app.test/", capability="web.crawl", input={},
        records=[{"kind": "discovered_route", "url": "https://app.test/a", "method": "GET"}],
    ))
    assert count == 0
    assert conn.savepoints == ["open", "rolled_back"]


DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")


@pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")
def test_postgres_inventory_failure_leaves_the_settlement_transaction_usable():
    import asyncpg

    async def scenario():
        assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
        schema = "hunt_inventory_savepoint_" + uuid.uuid4().hex
        conn = await asyncpg.connect(DSN)
        try:
            await conn.execute(f'CREATE SCHEMA "{schema}"')
            await conn.execute(f'SET search_path TO "{schema}"')
            await conn.execute("CREATE TABLE settled (id int)")
            async with conn.transaction():
                await conn.execute("INSERT INTO settled VALUES (1)")
                # target_endpoints does not exist here: the upsert fails inside its savepoint.
                count = await endpoint_knowledge.record_discovered_endpoints(
                    conn, target=SimpleNamespace(target_kind="web", target_id=str(uuid.uuid4())),
                    origin="https://app.test/", capability="web.content_discover", input={},
                    records=[*CONTROLS, *HITS],
                )
                assert count == 0
                await conn.execute("INSERT INTO settled VALUES (2)")
            assert await conn.fetchval("SELECT count(*) FROM settled") == 2
        finally:
            await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            await conn.close()

    asyncio.run(scenario())


def test_worker_settlement_records_endpoints_through_the_savepoint_helper():
    source = (Path(__file__).resolve().parents[1] / "api" / "worker.py").read_text(encoding="utf-8")
    assert "await record_discovered_endpoints(conn, target=target, origin=execution_target," in source
    assert "await enrich_crawl_endpoints(" not in source


@pytest.mark.parametrize("budget,started", [
    ({"agent_actions": 1, "http_requests": 0}, False),
    ({"agent_actions": 1, "tool_wall_seconds": 3}, True),
    ({}, False),
])
def test_execution_started_follows_settled_traffic(budget, started):
    from api.hunt.action_replay import execution_started_from_budget
    assert execution_started_from_budget(budget) is started
