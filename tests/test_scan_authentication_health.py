"""Real Scan receipt path with synthetic loopback identity and disposable PostgreSQL."""
import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from uuid import UUID, uuid4

import pytest

from tests.test_authenticated_assurance_postgres import DSN, exercise, write
from tests.test_authenticated_validation_worker import Fixture, SECRET, prepare, process_validation_job, result
from tests.test_scan_action_adapter import _action, _lease, Backend
from authenticated_assurance.jobs import target_binding
from authenticated_assurance.scan_health import build_scan_health_adapter
from authenticated_assurance.snapshots import ScanProfileSelection, pin_scan_profiles, attach_scan_snapshots
from runtime.models import ScanPolicy
from runtime.scan_credential_guard import build_scan_credential_check
from scan.action_adapter import DatabaseNeutralScanActionDispatcher
from scan.action_plan import ScanActionPlan
from scan.worker_action_executor import ReceiptScanActionExecutor
import secret_store

pytestmark = pytest.mark.skipif(not DSN, reason="requires disposable assurance PostgreSQL database")


async def scan_inputs(pool, store, config, fixture, monkeypatch):
    config = config.model_copy(update={"lifecycle_state": "ready"})
    server, payload, config, approval_id = await prepare(pool, store, config, fixture, monkeypatch)
    await process_validation_job(payload, pool=pool, worker_id="setup-fixture")
    validation = (await result(pool, payload))["validation"]
    assert validation["state"] == "valid"
    refs = [{"profile_id": str(config.credential_reference), "profile_version": 1,
        "credential_record_version": 1, "auth_kind": "bearer_token", "principal_slot": "primary",
        "allowed_capabilities": ["http.request"]}]
    async with pool.acquire() as conn, conn.transaction():
        binding = json.loads(await conn.fetchval(
            "SELECT target_binding_json FROM authentication_validation_requests WHERE id=$1", UUID(payload["job_id"])))
        snapshots = await pin_scan_profiles(conn, [ScanProfileSelection(
            profile_id=config.credential_reference, revision=1, reviewed=True)], refs,
            target_id=config.target_id, target_url=config.credential_destinations[0],
            now=datetime.now(timezone.utc), generation=UUID(validation["process_generation"]))
        await conn.execute("UPDATE approval_receipts SET action_name='scan.submit' WHERE id=$1", approval_id)
    options = {"approval_receipt_id": str(approval_id), "scope_receipt_id": binding["scope_receipt_id"],
        "credential_action_name": "scan.submit", "credential_profile_refs": attach_scan_snapshots(refs, snapshots),
        "authentication_allow_insecure_transport": True, "auth_header": "Bearer " + SECRET,
        "resolved_credential_profiles": [{**refs[0], "scan_lane": "primary"}]}
    target = target_binding(binding)
    action = replace(_action("authentication.health_primary", "http.request", 0, capability_args={
        "authentication_profile_ref": {"profile_id": str(config.credential_reference), "revision": 1,
                                       "configuration_digest": config.digest(1, 1)}}),
        target_binding_digest=target.digest, action_digest=None)
    plan = ScanActionPlan(scan_id=str(uuid4()), execution_plan_digest="a" * 64,
        target_binding_digest=target.digest, actions=(action,))

    async def forbidden(*args, **kwargs):
        raise AssertionError("No subprocess belongs to this fixture")

    dispatcher = DatabaseNeutralScanActionDispatcher(target_url=config.credential_destinations[0], target=target,
        options=options, policy=ScanPolicy(approval_receipt_id=str(approval_id)), scan_id=plan.scan_id,
        job_id="fixture", worker_id="broker:worker-1", plan=plan, backend=Backend(),
        process_runner=forbidden, cancelled=lambda: False,
        authentication_health_adapter_factory=lambda **kwargs: build_scan_health_adapter(pool, **kwargs))
    executor = ReceiptScanActionExecutor(scan_id=plan.scan_id, target_id=target.target_id,
        worker_id="broker:worker-1", dispatcher=dispatcher,
        credential_check=build_scan_credential_check(pool, options=options, target=target, scan_id=plan.scan_id,
            session_check=dispatcher.authentication_health_status))
    return server, executor, dispatcher, plan, action, config, approval_id


@pytest.mark.parametrize("status,body,location,state", [
    (200, json.dumps({"id": "test-user", "private": SECRET}).encode(), None, "valid"),
    (200, b'{"page":"login"}', None, "invalid"),
    (403, b'{}', None, "unknown"),
    (401, b'{}', None, "invalid"),
    (302, b'{}', "http://127.0.0.1:9999/leak", "unknown"),
])
def test_scan_health_receipt_spends_one_request_without_raw_response(monkeypatch, status, body, location, state):
    async def scenario(pool, store, config):
        fixture = Fixture()
        server, executor, dispatcher, plan, action, _, _ = await scan_inputs(pool, store, config, fixture, monkeypatch)
        async with server:
            fixture.status, fixture.body, fixture.location = status, body, location
            receipt = await executor.execute(action, _lease(plan, action), lambda: asyncio.sleep(0))
        assert fixture.count == 2 and fixture.authenticated
        assert receipt.budget_consumed["http_requests"] == 1
        health = next(item for item in receipt.observations if item["kind"] == "authentication_health")
        assert health["record"]["state"] == state
        assert receipt.status == ("success" if state == "valid" else "failed")
        assert SECRET not in json.dumps(receipt.canonical_dict())
        assert receipt.redacted_execution["response_content_retained"] is False
        if state == "valid":
            from authenticated_assurance.models import ValidationRecord
            from authenticated_assurance.scan_health import PROCESS_GENERATION
            checked = ValidationRecord.model_validate(dispatcher._authentication_health_records[health["record"]["profile_id"]])
            assert checked.process_generation == PROCESS_GENERATION
        work = replace(action, capability_args={"method": "GET"}, action_digest=None)
        assert dispatcher.authentication_health_status(work) == (None if state == "valid" else "authentication_uncertain")
        assert await dispatcher.restore_terminal_state(action, None) is False
        if state == "valid":
            stored = dispatcher._authentication_health_records[health["record"]["profile_id"]]
            stored["process_generation"] = str(uuid4())
            assert dispatcher.authentication_health_status(work) == "authentication_uncertain"
            stored.update(health["record"])
            stored["checked_at"] = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
            stored["valid_until"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            assert dispatcher.authentication_health_status(work) == "authentication_uncertain"
    exercise(scenario)


def test_timed_out_health_is_partial_and_unknown(monkeypatch):
    async def scenario(pool, store, config):
        fixture = Fixture()
        server, executor, _, plan, action, _, _ = await scan_inputs(pool, store, config, fixture, monkeypatch)
        async with server:
            fixture.hold = True
            try:
                receipt = await executor.execute(action, _lease(plan, action), lambda: asyncio.sleep(0))
            finally:
                fixture.release.set()
        assert fixture.count == 2
        assert receipt.timed_out and receipt.partial
        record = next(item["record"] for item in receipt.observations if item["kind"] == "authentication_health")
        assert (record["state"], record["reason_code"]) == ("unknown", "validation_timeout")
        assert receipt.budget_consumed["http_requests"] == 1
    exercise(scenario)


@pytest.mark.parametrize("change", ["profile", "approval"])
def test_revocation_during_health_cannot_publish_a_valid_observation(monkeypatch, change):
    async def scenario(pool, store, config):
        fixture = Fixture()
        server, executor, _, plan, action, config, approval_id = await scan_inputs(pool, store, config, fixture, monkeypatch)
        async with server:
            fixture.entered.clear()
            fixture.hold = True
            task = asyncio.create_task(executor.execute(action, _lease(plan, action), lambda: asyncio.sleep(0)))
            try:
                await asyncio.wait_for(fixture.entered.wait(), 2)
                if change == "profile":
                    await write(pool, store, config.model_copy(update={"lifecycle_state": "disabled"}), expected=1)
                else:
                    async with pool.acquire() as conn:
                        await conn.execute("UPDATE approval_receipts SET status='revoked', revoked_at=NOW() WHERE id=$1", approval_id)
                fixture.release.set()
                receipt = await asyncio.wait_for(task, 3)
            finally:
                fixture.release.set()
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        assert receipt.status != "success" and fixture.count == 2
        assert all(item.get("record", {}).get("state") != "valid" for item in receipt.observations)
        assert SECRET not in json.dumps(receipt.canonical_dict())
    exercise(scenario)


def test_health_expiration_interrupts_inflight_scan_work(monkeypatch):
    async def scenario(pool, store, config):
        fixture = Fixture()
        server, executor, dispatcher, plan, action, config, _ = await scan_inputs(pool, store, config, fixture, monkeypatch)
        async with server:
            health = await executor.execute(action, _lease(plan, action), lambda: asyncio.sleep(0))
            assert health.status == "success"
            work = replace(action, action_id="baseline.http", capability_args={"method": "GET"}, action_digest=None)
            work_plan = replace(plan, actions=(work,), plan_digest=None)
            dispatcher.plan = work_plan
            fixture.entered.clear()
            fixture.hold = True
            task = asyncio.create_task(executor.execute(work, _lease(work_plan, work), lambda: asyncio.sleep(0)))
            try:
                await asyncio.wait_for(fixture.entered.wait(), 2)
                cached = dispatcher._authentication_health_records[str(config.credential_reference)]
                cached["checked_at"] = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
                cached["valid_until"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
                receipt = await asyncio.wait_for(task, 3)
            finally:
                fixture.release.set()
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        assert fixture.count == 3
        assert receipt.status == "partial" and receipt.partial
        assert "authentication_uncertain" in receipt.errors
        assert receipt.budget_consumed["http_requests"] == 1
        assert receipt.redacted_execution["identity_interruption"]["continuous_identity_proven"] is False
    exercise(scenario)


@pytest.mark.parametrize("change", ["key", "consent", "budget", "approval"])
def test_scan_health_preflight_loss_never_sends_anonymous_request(monkeypatch, change):
    async def scenario(pool, store, config):
        fixture = Fixture()
        server, executor, dispatcher, plan, action, _, approval_id = await scan_inputs(pool, store, config, fixture, monkeypatch)
        async with server:
            if change == "key":
                monkeypatch.setattr(secret_store, "_fernet", None)
            elif change == "consent":
                dispatcher.options["authentication_allow_insecure_transport"] = False
            elif change == "budget":
                action = replace(action, requested_budget={"http_requests": 0, "tool_wall_seconds": 1}, action_digest=None)
                plan = replace(plan, actions=(action,), plan_digest=None)
            else:
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE approval_receipts SET status='revoked', revoked_at=NOW() WHERE id=$1", approval_id)
            receipt = await executor.execute(action, _lease(plan, action), lambda: asyncio.sleep(0))
        assert fixture.count == 1
        assert receipt.status != "success" and receipt.budget_consumed.get("http_requests", 0) == 0
        assert SECRET not in json.dumps(receipt.canonical_dict())
    exercise(scenario)
