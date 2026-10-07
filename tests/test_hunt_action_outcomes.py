"""Hunt action records explain refusals, name their candidates, and report state before schema.

Regressions for soak defects 16, 17 and 21 (2026-10-07):
* an action refused at admission was listed as ``failed`` with no reason, a null receipt and a
  ``legacy_unknown`` settlement (Hunt 1e38154e, web.crawl reserving 150 of 100 HTTP requests);
* ``outcome_summary.candidate_ids`` was ``[]`` on every Hunt although candidates existed;
* a capability call with bad input on a completed Hunt answered 422 instead of 409.
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import pytest

from api.hunt import interaction_router as router
from api.hunt.run_service import (
    HUNT_CANDIDATES_QUERY,
    HuntRunService,
    public_hunt_action,
)
from tests.test_hunt_run_router import _Pool, _row

SHORTAGE = {
    "error": "budget_insufficient_for_action:http_requests",
    "retryable_with_smaller_action": True,
    "shortages": {"http_requests": 50},
    "remaining": {"http_requests": 86},
    "budget_reservation_id": "9b7e8f1a-0000-4000-8000-000000000001",
    "budget_reservation_state": "released",
}


def _refused_action(summary=SHORTAGE):
    return {
        "id": uuid.uuid4(), "capability_name": "web.crawl", "status": "failed",
        "input_summary": {}, "result_summary": json.dumps(summary), "receipt_id": None,
    }


def test_admission_refusal_is_reported_with_its_reason_and_no_charge():
    result = public_hunt_action(_refused_action())["result"]
    assert result["ok"] is False
    assert result["error"] == "budget_insufficient_for_action:http_requests"
    assert result["refusal"] == {
        "stage": "admission",
        "reason": "budget_insufficient_for_action:http_requests",
        "retryable_with_smaller_action": True,
        "shortages": {"http_requests": 50},
        "remaining": {"http_requests": 86},
    }
    accounting = result["budget_accounting"]
    assert accounting["basis"] == "refused_at_admission"
    assert accounting["charge_basis"] == "not_charged"
    assert accounting["settlement_status"] == "released"
    assert accounting["reservation_id"] == SHORTAGE["budget_reservation_id"]


def test_an_exhausting_refusal_without_a_durable_reservation_is_also_explained():
    summary = {"error": "budget_exhausted:hosts_attempted", "retryable_with_smaller_action": False,
               "shortages": {"hosts_attempted": 1}, "remaining": {"hosts_attempted": 0}}
    result = public_hunt_action(_refused_action(summary))["result"]
    assert result["refusal"]["reason"] == "budget_exhausted:hosts_attempted"
    assert result["budget_accounting"]["settlement_status"] == "not_reserved"


def test_a_failed_executed_action_keeps_its_error_but_is_not_called_a_refusal():
    row = {**_refused_action({"ok": False, "error": "capability_fault:TimeoutError"}),
           "receipt_id": uuid.uuid4()}
    result = public_hunt_action(row)["result"]
    assert result["error"] == "capability_fault:TimeoutError"
    assert "refusal" not in result
    assert result["budget_accounting"]["basis"] != "refused_at_admission"


def test_outcome_summary_names_the_candidates_this_hunt_recorded():
    hunt_id = str(uuid.uuid4())
    candidate_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    queries = []

    class Connection:
        async def fetchrow(self, query, *args):
            return _row(id=uuid.UUID(hunt_id))

        async def fetch(self, query, *args):
            queries.append((query, args))
            if "FROM investigation_candidates" in query:
                return [{"id": uuid.UUID(value), "total_count": 2} for value in candidate_ids]
            return []

    summary = asyncio.run(HuntRunService(lambda: _Pool(Connection())).get(hunt_id))["outcome_summary"]
    assert summary["candidate_ids"] == sorted(candidate_ids)
    assert summary["candidate_count"] == 2 and summary["candidate_ids_truncated"] is False
    (query, args), = [item for item in queries if "FROM investigation_candidates" in item[0]]
    assert args == (uuid.UUID(hunt_id),)
    assert "o.hunt_run_id=$1" in query and "status <> 'expired'" in query


def _store(status, recorded=False):
    class Store:
        @asynccontextmanager
        async def acquire(self):
            yield self

        async def fetchrow(self, sql, *args):
            assert "FROM hunt_actions" in sql
            return {"id": args[0]} if recorded else None

    async def lookup(_conn, hunt_id, for_update=False):
        return {"id": uuid.UUID(hunt_id), "status": status}

    return Store(), lookup


@pytest.mark.parametrize("status", ["completed", "cancelled", "failed", "budget_exhausted"])
def test_capability_call_on_a_finished_hunt_reports_state_before_schema(monkeypatch, status):
    store, lookup = _store(status)
    monkeypatch.setattr(router, "_pool", lambda: store)
    monkeypatch.setattr(router, "_hunt_run_or_404", lookup)
    request = router.HuntCapabilityRequest(
        idempotency_key="mcp-" + "b" * 32, input={"wordlist": "not-a-wordlist", "bogus": 1},
    )
    with pytest.raises(router.HTTPException) as exc:
        asyncio.run(router.execute_hunt_capability(str(uuid.uuid4()), "web.content_discover", request))
    assert exc.value.status_code == 409
    assert exc.value.detail == f"Hunt is {status}"


def test_active_hunt_still_reports_schema_errors(monkeypatch):
    store, lookup = _store("active")
    monkeypatch.setattr(router, "_pool", lambda: store)
    monkeypatch.setattr(router, "_hunt_run_or_404", lookup)
    request = router.HuntCapabilityRequest(idempotency_key="mcp-" + "c" * 32, input={"bogus": 1})
    with pytest.raises(router.HTTPException) as exc:
        asyncio.run(router.execute_hunt_capability(str(uuid.uuid4()), "web.content_discover", request))
    assert exc.value.status_code == 422


DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")


@pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")
def test_postgres_candidate_query_selects_live_candidates_observed_by_the_hunt():
    async def scenario():
        import asyncpg
        assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1"}
        schema = "hunt_outcomes_" + uuid.uuid4().hex
        conn = await asyncpg.connect(DSN)
        try:
            await conn.execute(f'CREATE SCHEMA "{schema}"')
            await conn.execute(f'SET search_path TO "{schema}"')
            await conn.execute("""
                CREATE TABLE investigation_candidates(id uuid PRIMARY KEY, status text);
                CREATE TABLE investigation_candidate_observations(candidate_id uuid, hunt_run_id uuid);
            """)
            hunt, other = uuid.uuid4(), uuid.uuid4()
            live, expired, foreign = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
            for cid, status, owner in ((live, "new", hunt), (expired, "expired", hunt), (foreign, "new", other)):
                await conn.execute("INSERT INTO investigation_candidates VALUES($1,$2)", cid, status)
                await conn.execute("INSERT INTO investigation_candidate_observations VALUES($1,$2)", cid, owner)
            await conn.execute("INSERT INTO investigation_candidate_observations VALUES($1,$2)", live, hunt)
            rows = await conn.fetch(HUNT_CANDIDATES_QUERY, hunt)
            assert [(row["id"], row["total_count"]) for row in rows] == [(live, 1)]
        finally:
            await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            await conn.close()
    asyncio.run(scenario())
