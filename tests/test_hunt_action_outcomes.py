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


def test_an_admission_refusal_is_attempted_but_never_executed():
    """Live: a budget_exhausted:agent_actions refusal (no receipt, nothing sent) was counted in
    executed_calls. attempted = executed + rejected + other must hold."""
    from api.hunt.run_service import hunt_action_outcome_summary

    refused = public_hunt_action(_refused_action({
        "error": "budget_exhausted:agent_actions", "retryable_with_smaller_action": False,
        "shortages": {"agent_actions": 1}, "remaining": {"agent_actions": 0},
    }))
    executed_failure = public_hunt_action({
        **_refused_action({"ok": False, "error": "capability_fault:TimeoutError"}),
        "receipt_id": uuid.uuid4(),
    })
    completed = public_hunt_action({
        "id": uuid.uuid4(), "capability_name": "http.request", "status": "completed",
        "input_summary": {}, "result_summary": json.dumps({"ok": True}), "receipt_id": uuid.uuid4(),
    })
    running = {"status": "running", "result": {}}
    assert refused["result"]["execution_started"] is False
    assert executed_failure["result"]["execution_started"] is None
    summary = hunt_action_outcome_summary([refused, executed_failure, completed, running])
    assert summary["attempted_calls"] == 4
    assert summary["executed_calls"] == 2
    assert summary["rejected_calls"] == 1
    assert summary["other_calls"] == 1
    assert summary["unsuccessful_calls"] == 1 and summary["successful_calls"] == 1
    assert summary["attempted_calls"] == (
        summary["executed_calls"] + summary["rejected_calls"] + summary["other_calls"]
    )
    assert summary["executed_calls"] == (
        summary["successful_calls"] + summary["unsuccessful_calls"]
        + summary["indeterminate_calls"] + summary["partial_calls"]
    )


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
    assert exc.value.detail["message"] == f"Hunt is {status}"
    assert exc.value.detail["reason_code"] == "hunt_not_runnable"


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
    from api.investigation_candidates import CANDIDATE_SCHEMA_STATEMENTS
    from tests.hunt_candidate_pg_schema import candidate_schema_sql

    async def scenario():
        import asyncpg
        assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1"}
        schema = "hunt_outcomes_" + uuid.uuid4().hex
        conn = await asyncpg.connect(DSN)
        try:
            await conn.execute(f'CREATE SCHEMA "{schema}"')
            await conn.execute(f'SET search_path TO "{schema}"')
            # The real baseline DDL, then unified startup twice (a converted, restarted install).
            await conn.execute(candidate_schema_sql())
            for _ in range(2):
                for statement in CANDIDATE_SCHEMA_STATEMENTS:
                    await conn.execute(statement)
            target = uuid.uuid4()
            hunt, other = uuid.uuid4(), uuid.uuid4()
            live, expired, foreign = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
            for cid, status, owner in ((live, "new", hunt), (expired, "expired", hunt), (foreign, "new", other)):
                await conn.execute(
                    """INSERT INTO investigation_candidates
                       (id, plane, target_id, family, title, claim, fingerprint, status)
                       VALUES ($1,'web',$2,'x','t','c',$3,$4)""",
                    cid, target, cid.hex, status,
                )
                await conn.execute(
                    """INSERT INTO investigation_candidate_observations
                       (candidate_id, hunt_run_id, title, claim) VALUES ($1,$2,'t','c')""",
                    cid, owner,
                )
            await conn.execute(
                """INSERT INTO investigation_candidate_observations
                   (candidate_id, hunt_run_id, title, claim) VALUES ($1,$2,'t','c')""",
                live, hunt,
            )
            rows = await conn.fetch(HUNT_CANDIDATES_QUERY, hunt)
            assert [(row["id"], row["total_count"]) for row in rows] == [(live, 1)]
            # The per-Hunt lookup is served by the hunt_run_id index, not a table scan.
            await conn.execute("SET enable_seqscan = off")
            plan = "\n".join(
                row[0] for row in await conn.fetch("EXPLAIN " + HUNT_CANDIDATES_QUERY, hunt)
            )
            assert "idx_investigation_candidate_observations_hunt_run" in plan
        finally:
            await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            await conn.close()
    asyncio.run(scenario())


def test_unified_startup_installs_the_candidate_schema_on_converted_instances(monkeypatch):
    import importlib

    from api.targets import asset_migration

    executed: list[str] = []

    class Conn:
        async def execute(self, statement, *args):
            executed.append(" ".join(str(statement).split()))
            return "OK"

        def transaction(self):
            @asynccontextmanager
            async def scope():
                yield self
            return scope()

    class Pool:
        @asynccontextmanager
        async def acquire(self):
            yield Conn()

    async def noop(*_args, **_kwargs):
        return None

    async def converted(_conn):
        return True

    async def baseline(_pool):
        raise AssertionError("a converted instance never reruns the frozen baseline")

    monkeypatch.setattr(asset_migration, "migration_applied", converted)
    monkeypatch.setattr(asset_migration, "reconcile_active_finding_counts", noop)
    monkeypatch.setattr(
        importlib.import_module("api.targets.asset_inputs_migration"), "migrate_asset_inputs", noop,
    )
    for module, name in (
        ("runtime.ai_header_secrets", "encrypt_stored_secrets"),
        ("runtime.ai_template_secrets", "encrypt_stored_templates"),
        ("runtime.archive_blob_secrets", "encrypt_stored_blobs"),
        ("runtime.credential_migration", "migrate_legacy_web_credentials"),
        ("hunt.grant_repair", "repair_grant_authority"),
    ):
        monkeypatch.setattr(importlib.import_module(module), name, noop)
    asyncio.run(asset_migration.run_unified_startup(Pool(), baseline))
    assert any(
        "CREATE INDEX IF NOT EXISTS idx_investigation_candidate_observations_hunt_run" in statement
        for statement in executed
    )
