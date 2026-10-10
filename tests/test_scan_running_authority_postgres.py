"""Device and AI scans re-check the target's authorization while they run (PostgreSQL).

These runs are one piece of work, not a canonical action graph. They are composed here as
``process_scan_job`` composes them: ``running_scan_authority`` around the worker's own
product handlers (``worker._NON_DAST_WORKER_HANDLER``, so the worker's stop wiring is the one
under test), with the real ``ScanAuthorityGuard`` over the installed schema. Only the scanner
functions are fixtures (``fixture_scanner``): they run a fixture ``sleep`` process and stop it
when the run's stop check says so, as the device and AI scanners do; one ignores its stop
check, as the AI target scan has none. No target is contacted.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
import sys
import time
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from tests.test_scan_local_revocation_postgres import StallingPool, scan_database  # noqa: E402

# ``template_database`` (one installed schema, cloned per test) comes from the local revocation
# suite, registered here as a plugin.
pytest_plugins = ["tests.test_scan_local_revocation_postgres"]
import target_authorization  # noqa: E402
import worker  # noqa: E402
from scan.running_scan_authority import ScanAuthorityStopped, running_scan_authority  # noqa: E402


@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    """Progress and user-cancel reads go to Redis in production; the fixtures need neither."""
    async def no_progress(*_args, **_kwargs):
        return None
    monkeypatch.setattr(worker, "update_scan_progress", no_progress)
    monkeypatch.setattr(worker, "_scan_cancel_requested", lambda *_a, **_k: False)
    monkeypatch.setattr(worker, "_append_device_activity", lambda *_a, **_k: None)


class FixtureScanner:
    """Fixture scanner: a ``sleep`` process stopped when the run's stop check fires.

    ``raises_on_stop`` ends the stop with an error, as the device scanners do
    ("connected-device scan cancelled before <stage>").
    """

    def __init__(self, *, honours_stop=True, seconds=30, raises_on_stop=False):
        self.honours_stop, self.seconds, self.raises_on_stop = honours_stop, seconds, raises_on_stop
        self.calls = 0
        self.stopped_at: float | None = None
        self.returncode: int | None = None

    async def run(self, stop_check):
        self.calls += 1
        process = await asyncio.create_subprocess_exec("sleep", str(self.seconds))
        try:
            while process.returncode is None:
                if self.honours_stop and await stop_check():
                    process.terminate()
                    await process.wait()
                    self.stopped_at = time.monotonic()
                    if self.raises_on_stop:
                        raise ValueError("connected-device scan cancelled before fixture_stage")
                    return {"findings": [{"title": "observed before the stop"}], "cancelled": True,
                            "result": {"score": None, "grade": None}}
                try:
                    await asyncio.wait_for(process.wait(), timeout=0.05)
                except asyncio.TimeoutError:
                    pass
            return {"findings": [], "result": {"score": 100, "grade": "A"}}
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
                self.stopped_at = time.monotonic()
            self.returncode = process.returncode


def _await_stop(check):
    async def stop():
        value = check()
        return await value if inspect.isawaitable(value) else bool(value)
    return stop


async def _device(pool, *, standing=True):
    async with pool.acquire() as conn:
        device_id = await conn.fetchval(
            """INSERT INTO device_targets(name, primary_locator, environment)
               VALUES('fixture device', 'device.fixture.test', 'lab') RETURNING id""")
        receipt = None
        if standing:
            receipt = str((await target_authorization.authorize_target(
                conn, device_id, approved_by="fixture-owner"))["approval_receipt_id"])
    return device_id, receipt


async def _ai_target(pool, *, expires="1 hour"):
    async with pool.acquire() as conn:
        ai_id = await conn.fetchval(
            "INSERT INTO ai_targets(name, endpoint_url) VALUES($1, $2) "
            "RETURNING id", "fixture model", f"http://model.fixture.test/v1/chat/{uuid.uuid4().hex}")
        scope_id = "scope-" + uuid.uuid4().hex
        await conn.execute(
            """INSERT INTO scope_receipts(id, target_id, verdict, allowed_hosts)
               VALUES($1, $2, 'allowed', '["model.fixture.test"]')""", scope_id, ai_id)
        approval = await conn.fetchval(
            f"""INSERT INTO approval_receipts(scope_receipt_id, risk_tier, confirmations, action_name,
                    approved_by, expires_at)
                VALUES($1, 'active', '["confirm_authorized"]', 'ai.target.scan', 'fixture-owner',
                       NOW() + INTERVAL '{expires}') RETURNING id""", scope_id)
    return ai_id, str(approval), scope_id


async def _run_device(pool, scanner, monkeypatch, *, device_id, receipt, during=None, guard_pool=None,
                      options=None, **timing):
    from scanner_tools import device_posture

    async def fixture_posture(_target, options):
        return await scanner.run(options["_cancel_check"])
    monkeypatch.setattr(device_posture, "run_device_posture_scan", fixture_posture)
    options = options or {"run_kind": "device_posture", "asset_authorization_receipt_id": receipt}
    scan_id = str(uuid.uuid4())
    events: list[str] = []
    authority = await running_scan_authority(pool, options=options, device_target_id=str(device_id),
                                             record_event=events.append, **timing)
    if guard_pool is not None and authority.guard is not None:
        for guard in authority.guard.guards:
            guard.pool = guard_pool
    hook = asyncio.create_task(during()) if during else None
    try:
        async with authority:
            result = await worker._NON_DAST_WORKER_HANDLER.device.run_posture(
                "device.fixture.test", options, scan_id=scan_id, job_id=str(uuid.uuid4()))
        result = await authority.annotate(result, scan_id=scan_id)
    finally:
        if hook is not None:
            await hook
    return result, authority, events


def test_revoking_a_device_authorization_stops_a_running_posture_scan(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            device_id, receipt = await _device(pool)
            scanner = FixtureScanner()
            marks = {}

            async def revoke_soon():
                await asyncio.sleep(0.5)
                marks["revoked_at"] = time.monotonic()
                async with pool.acquire() as conn:
                    assert await target_authorization.revoke_target_authorization(
                        conn, device_id, revoked_by="fixture-owner", reason="fixture revoke mid-scan") == 1

            result, authority, events = await _run_device(
                pool, scanner, monkeypatch, device_id=device_id, receipt=receipt, during=revoke_soon)
            # Production 2 s poll: stopped within one poll of the revoke, through the scanner's
            # own stop check, and what it found before the stop is kept.
            assert scanner.returncode is not None and scanner.returncode < 0
            assert scanner.stopped_at - marks["revoked_at"] < 3.0
            assert result["findings"] == [{"title": "observed before the stop"}]
            assert authority.reason == "authorization_revoked" and "approval_revocation" in events
            assert result["coverage"]["status"] == "partial"
            stop = result["scan_metadata"]["authority_stop"]
            assert result["scan_metadata"]["stop_reason"] == "authorization_withdrawn"
            assert stop["reason_code"] == "authorization_revoked"
            assert stop["interrupted_actions"] == ["scan.run"]
    asyncio.run(run())


def test_a_device_scanner_that_ends_its_stop_with_an_error_fails_naming_the_authorization(
        template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            device_id, receipt = await _device(pool)
            scanner = FixtureScanner(raises_on_stop=True)

            async def revoke_soon():
                await asyncio.sleep(0.3)
                async with pool.acquire() as conn:
                    await target_authorization.revoke_target_authorization(
                        conn, device_id, revoked_by="fixture-owner", reason="fixture revoke mid-scan")

            with pytest.raises(ScanAuthorityStopped) as stopped:
                await _run_device(pool, scanner, monkeypatch, device_id=device_id, receipt=receipt,
                                  during=revoke_soon, poll_seconds=0.2)
            assert not stopped.value.before_start and stopped.value.reason == "authorization_revoked"
            assert "authorization_revoked" in str(stopped.value) and scanner.returncode < 0
    asyncio.run(run())


def test_a_device_scan_is_refused_before_it_starts_when_its_authorization_was_revoked(template_database,
                                                                                      monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            device_id, receipt = await _device(pool)
            async with pool.acquire() as conn:
                await target_authorization.revoke_target_authorization(
                    conn, device_id, revoked_by="fixture-owner", reason="fixture revoke before start")
            scanner = FixtureScanner()
            with pytest.raises(ScanAuthorityStopped) as stopped:
                await _run_device(pool, scanner, monkeypatch, device_id=device_id, receipt=receipt)
            assert stopped.value.before_start and stopped.value.reason == "authorization_revoked"
            assert scanner.calls == 0
    asyncio.run(run())


def test_a_deactivated_device_stops_its_scan_as_out_of_scope(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            device_id, receipt = await _device(pool)
            scanner = FixtureScanner()

            async def deactivate():
                await asyncio.sleep(0.3)
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE device_targets SET is_active=false WHERE id=$1", device_id)

            result, authority, _events = await _run_device(
                pool, scanner, monkeypatch, device_id=device_id, receipt=receipt, during=deactivate,
                poll_seconds=0.2)
            assert authority.reason == "scope_invalid" and scanner.returncode < 0
            assert result["scan_metadata"]["authority_stop"]["reason_code"] == "scope_invalid"
    asyncio.run(run())


def test_an_unanswering_database_stops_a_device_scan_as_unverified_not_revoked(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            device_id, receipt = await _device(pool)
            scanner = FixtureScanner()
            stalling = StallingPool(pool)
            marks = {}

            async def stall():
                await asyncio.sleep(0.3)
                stalling.stalled = True
                marks["stalled_at"] = time.monotonic()

            result, authority, events = await _run_device(
                pool, scanner, monkeypatch, device_id=device_id, receipt=receipt, during=stall,
                guard_pool=stalling, poll_seconds=0.3, unverified_after_seconds=1.5)
            assert scanner.stopped_at - marks["stalled_at"] < 1.5 + 0.5
            assert authority.reason == "authorization_unverified" and not authority.guard.withdrawn
            assert not events
            assert result["scan_metadata"]["stop_reason"] == "authorization_unverified"
            assert result["coverage"] == {"status": "partial", "reasons": ["authorization_unverified"]}
            assert stalling.pending == 0
            stalling.stalled = False
    asyncio.run(run())


def test_a_short_database_blip_does_not_stop_a_device_scan(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            device_id, receipt = await _device(pool)
            scanner = FixtureScanner(seconds=2)
            stalling = StallingPool(pool)

            async def blip():
                await asyncio.sleep(0.3)
                stalling.stalled = True
                await asyncio.sleep(0.6)
                stalling.stalled = False

            result, authority, events = await _run_device(
                pool, scanner, monkeypatch, device_id=device_id, receipt=receipt, during=blip,
                guard_pool=stalling, poll_seconds=0.3, unverified_after_seconds=1.5)
            assert scanner.returncode == 0 and authority.reason is None and not events
            assert "scan_metadata" not in result
    asyncio.run(run())


def test_a_device_scan_admitted_without_a_receipt_is_not_watched(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            device_id, _receipt = await _device(pool, standing=False)
            scanner = FixtureScanner(seconds=1)
            result, authority, _events = await _run_device(
                pool, scanner, monkeypatch, device_id=device_id, receipt=None)
            assert authority.guard is None and scanner.returncode == 0
            assert result["result"]["grade"] == "A"
    asyncio.run(run())


async def _run_ai(pool, scanner, monkeypatch, *, ai_id, approval, scope_id, during=None, boundary=False,
                  grace=None, options=None, **timing):
    if boundary:
        from ai_gate.boundary import runner

        async def fixture_boundary(_target, _options, *, cancelled):
            return await scanner.run(_await_stop(cancelled))
        monkeypatch.setattr(runner, "run_boundary_scan", fixture_boundary)
    else:
        import ai_gate_scan

        async def fixture_ai_scan(_target, _options):  # no stop check, as the real one has none
            return await scanner.run(_await_stop(lambda: False))
        monkeypatch.setattr(ai_gate_scan, "run_ai_target_scan", fixture_ai_scan)
    options = {**(options or {"run_kind": "ai_api", "approval_receipt_id": approval, "scope_receipt_id": scope_id}),
               **({"ai_probe_pack": "shaker-ai-boundary"} if boundary else {})}
    scan_id = str(uuid.uuid4())
    authority = await running_scan_authority(pool, options=options, ai_target_id=str(ai_id), **timing)
    if grace is not None:
        authority.grace_seconds = grace
    hook = asyncio.create_task(during()) if during else None
    try:
        async with authority:
            result = await worker._NON_DAST_WORKER_HANDLER.ai_gate.run(
                "http://model.fixture.test/v1/chat", options, scan_id=scan_id, job_id=str(uuid.uuid4()))
        result = await authority.annotate(result, scan_id=scan_id)
    finally:
        if hook is not None:
            await hook
    return result, authority


async def _revoke_approval(pool, approval):
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE approval_receipts SET status='revoked', revoked_at=NOW(), revoked_by='fixture-owner',
                      revocation_reason='fixture revoke mid-scan' WHERE id=$1""", uuid.UUID(approval))


def test_revoking_an_ai_scan_approval_stops_a_running_boundary_scan(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            ai_id, approval, scope_id = await _ai_target(pool)
            scanner = FixtureScanner()

            async def revoke_soon():
                await asyncio.sleep(0.3)
                await _revoke_approval(pool, approval)

            result, authority = await _run_ai(pool, scanner, monkeypatch, ai_id=ai_id, approval=approval,
                                              scope_id=scope_id, during=revoke_soon, boundary=True,
                                              poll_seconds=0.2)
            assert authority.reason == "authorization_revoked" and scanner.returncode < 0
            assert result["findings"] == [{"title": "observed before the stop"}]
            assert result["scan_metadata"]["authority_stop"]["reason_code"] == "authorization_revoked"
    asyncio.run(run())


def test_an_ai_scan_without_a_stop_check_is_cancelled_after_the_grace(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            ai_id, approval, scope_id = await _ai_target(pool)
            scanner = FixtureScanner(honours_stop=False)
            marks = {}

            async def revoke_soon():
                await asyncio.sleep(0.3)
                await _revoke_approval(pool, approval)
                marks["revoked_at"] = time.monotonic()

            with pytest.raises(ScanAuthorityStopped) as stopped:
                await _run_ai(pool, scanner, monkeypatch, ai_id=ai_id, approval=approval, scope_id=scope_id,
                              during=revoke_soon, grace=0.5, poll_seconds=0.2)
            assert not stopped.value.before_start and stopped.value.reason == "authorization_revoked"
            # What the Scan records names the authorization stop, not a validation error.
            report = stopped.value.report
            assert "target authorization" in report["error"] and "authorization_revoked" in report["error"]
            assert report["coverage"]["status"] == "partial"
            assert report["scan_metadata"]["stop_reason"] == "authorization_withdrawn"
            assert report["scan_metadata"]["authority_stop"]["reason_code"] == "authorization_revoked"
            # One poll to see the revoke, then the grace, then the cancelled scan's process is gone.
            assert scanner.stopped_at - marks["revoked_at"] < 0.2 + 0.5 + 0.5
            assert scanner.returncode is not None and scanner.returncode < 0
    asyncio.run(run())


def test_an_ai_scan_stops_when_its_target_is_deactivated_or_its_approval_expires(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            ai_id, approval, scope_id = await _ai_target(pool)

            async def deactivate():
                await asyncio.sleep(0.3)
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE ai_targets SET is_active=false WHERE id=$1", ai_id)

            _result, authority = await _run_ai(pool, FixtureScanner(), monkeypatch, ai_id=ai_id,
                                               approval=approval, scope_id=scope_id, during=deactivate,
                                               boundary=True, poll_seconds=0.2)
            assert authority.reason == "scope_invalid"

            ai_id, approval, scope_id = await _ai_target(pool, expires="1500 milliseconds")
            _result, authority = await _run_ai(pool, FixtureScanner(), monkeypatch, ai_id=ai_id,
                                               approval=approval, scope_id=scope_id, boundary=True,
                                               poll_seconds=0.3)
            assert authority.reason == "authorization_expired"
    asyncio.run(run())


def test_an_ai_scan_admitted_without_a_receipt_is_not_watched(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            ai_id, _approval, _scope = await _ai_target(pool)
            scanner = FixtureScanner(seconds=1)
            result, authority = await _run_ai(pool, scanner, monkeypatch, ai_id=ai_id, approval=None,
                                              scope_id=None, boundary=True)
            assert authority.guard is None and scanner.returncode == 0 and result["result"]["grade"] == "A"
    asyncio.run(run())


# --- Fleet: a running broker action asks the control plane, which answers from the guard ---

def _broker_control_plane(monkeypatch, pool, scan):
    """The real control-plane route over ``pool``; node authentication and the job-lease lookup
    are fixtures that bind the call to ``scan`` (their own checks are covered elsewhere)."""
    from types import SimpleNamespace
    import fleet_routes.router as fleet

    async def authenticated(_node_id, _request):
        return None

    from scan.broker_authority import RunningBrokerAuthority

    async def action_context(_conn, **kwargs):
        action = next(item for item in scan.plan.actions if item.action_id == kwargs["action_id"])
        job = SimpleNamespace(target=scan.binding, execution_plan=SimpleNamespace(policy=scan.policy))
        return {"scan_id": scan.scan_id}, scan.plan, job, action, backend

    backend = FixtureBrokerBackend()
    monkeypatch.setattr(fleet, "_broker_authenticated_node", authenticated)
    monkeypatch.setattr(fleet, "_broker_action_context", action_context)
    monkeypatch.setattr(fleet, "_broker_submitted_action_lease", lambda raw, **_kwargs: dict(raw))
    monkeypatch.setattr(fleet, "_pool", lambda: pool)
    monkeypatch.setattr(fleet, "_BROKER_RUNNING_AUTHORITY", RunningBrokerAuthority())

    async def request(method, path, payload):
        assert method == "POST" and path.endswith("/authority")
        _, _, _, _, node_id, _, lease_id, _, action_id, _ = path.split("/")
        return await fleet.broker_scan_action_authority(
            node_id, lease_id, action_id, fleet.BrokerActionAuthorityRequest(**payload), None)
    request.backend = backend
    return request


class FixtureBrokerBackend:
    """Fixture control-plane backend: records heartbeats and the receipts it is asked to settle."""

    def __init__(self):
        self.heartbeats, self.settled = 0, []

    async def heartbeat(self, _lease):
        self.heartbeats += 1

    async def settle(self, _lease, receipt):
        from types import SimpleNamespace
        self.settled.append(receipt)
        return SimpleNamespace(canonical_dict=lambda: {"status": receipt.status})


def _broker_authority(scan, request, **timing):
    from scan.broker_backend import BrokerActionAuthority, BrokerScanExecutionBackend
    backend = BrokerScanExecutionBackend(plan=scan.plan, worker_id="broker:node-1", job_lease_token="t" * 40,
                                         base_path="/fleet/broker/nodes/node-1/leases/lease-1", request=request)
    return BrokerActionAuthority(lambda: backend, request, **timing)


def test_the_control_plane_route_answers_with_the_guard_decision(template_database, monkeypatch):
    from tests.test_scan_local_revocation_postgres import _scan

    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            request = _broker_control_plane(monkeypatch, pool, scan)
            authority = _broker_authority(scan, request)
            active = scan.plan.actions[1]
            assert await authority.check(active) is None
            await scan.revoke()
            assert await authority.poll(active) == "authorization_revoked"
            # Sticky for the rest of the Scan, as the local guard is.
            assert await authority.check(scan.plan.actions[2]) == "authorization_revoked"
    asyncio.run(run())


def test_revoking_authorization_stops_an_action_running_on_a_fleet_node(template_database, monkeypatch):
    """The fleet node's executor, with the control plane's real decision over PostgreSQL."""
    from tests.test_scan_local_revocation_postgres import FixtureToolDispatcher, _scan

    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            request = _broker_control_plane(monkeypatch, pool, scan)
            revoked_at = {}

            async def revoke_soon():
                await asyncio.sleep(0.5)
                revoked_at["t"] = time.monotonic()
                assert await scan.revoke() == 1

            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               long_actions=frozenset({"templates.active"}),
                                               during={"templates.active": revoke_soon})
            authority = _broker_authority(scan, request)  # production 2 s poll, 10 s tolerance
            await scan.run(dispatcher, authority)
            returncode, exited_at = dispatcher.process_exits["templates.active"]
            assert returncode is not None and returncode < 0
            assert exited_at - revoked_at["t"] < 3.0
            actions = await scan.actions()
            assert actions["templates.active"] == ("partial", "authorization_revoked")
            assert actions["templates.followup"] == ("blocked", "authorization_revoked")
            assert dispatcher.dispatched == ["baseline.http", "templates.active", "finalize.report"]
            assert await scan.held_reservations() == 0
    asyncio.run(run())


# --- Receipts created and admitted as the API creates and admits them ---
#
# Scope and approval receipts come from the real routes (``POST /arsenal/scope/preview``,
# ``POST /arsenal/approvals``, ``POST /arsenal/approvals/{id}/revoke``), a standing
# authorization from ``target_authorization.authorize_target`` (``POST /targets/{id}/authorization``),
# and the Scan options are composed as the device and AI scan routes compose them, from the
# real admission check (``api._validate_approval_receipt_for_action``). The run must start
# exactly when admission accepted it, and stop only for what changed afterwards.

class _Api:
    def __init__(self, pool, monkeypatch):
        import api as api_module
        if not hasattr(api_module, "_validate_approval_receipt_for_action"):  # the package, not api.py
            from api import api as api_module
        import arsenal_routes.router as arsenal
        monkeypatch.setattr(arsenal, "_pool", lambda: pool)
        self.api, self.arsenal, self.pool = api_module, arsenal, pool

    async def approval(self, url, *, action_name, expires_at=None):
        """A scope receipt for ``url`` and an approval of it, as the UI requests them."""
        scope = (await self.arsenal.arsenal_scope_preview(self.arsenal.ScopePreviewRequest(
            url=url, environment="lab")))["scope_receipt"]
        approval = (await self.arsenal.arsenal_create_approval(self.arsenal.ApprovalReceiptRequest(
            scope_receipt_id=scope["receipt_id"], risk_tier="active",
            # The UI asks for the scope review when the preview needs it.
            confirmations=["confirm_authorized",
                           *(["confirm_scope_reviewed"] if scope["verdict"] == "needs_approval" else [])],
            action_name=action_name, approved_by="fixture-owner", expires_at=expires_at)))["approval_receipt"]
        return str(approval["id"])

    async def revoke(self, approval_id):
        await self.arsenal.arsenal_revoke_approval(approval_id, self.arsenal.ApprovalReceiptRevocationRequest(
            revoked_by="fixture-owner", reason="fixture revoke mid-scan"))

    async def device_options(self, device_id, *, approval_id=None, confirm_authorized=False):
        """``POST /devices/{id}/scan`` options: standing snapshot unless confirmed inline."""
        from devices.network_authorization import network_authorization_snapshot
        async with self.pool.acquire() as conn:
            device = await conn.fetchrow("SELECT primary_locator FROM device_targets WHERE id=$1", device_id)
            standing = None if confirm_authorized else await network_authorization_snapshot(conn, device_id)
            assert confirm_authorized or standing, "admission requires a standing authorization"
            context = await self.api._validate_approval_receipt_for_action(
                conn, approval_id, target_url=str(device["primary_locator"]), action_name="device.scan",
                risk_tier="active", created_by="device_scan_endpoint")
        options = {"run_kind": "device_posture", "confirm_authorized": True,
                   "asset_authorization_receipt_id": standing["approval_receipt_id"] if standing else None,
                   "approval_receipt_id": approval_id}
        options.update(context or {})
        return options

    async def ai_options(self, ai_id, *, approval_id):
        """``POST /ai/targets/{id}/scan`` options without credentials (expiry not required)."""
        async with self.pool.acquire() as conn:
            endpoint = await conn.fetchval("SELECT endpoint_url FROM ai_targets WHERE id=$1", ai_id)
            context = await self.api._validate_approval_receipt_for_action(
                conn, approval_id, target_url=endpoint, target_id=None, action_name="ai_gate.scan",
                risk_tier="active", always_require_receipt=False, require_target_binding=False,
                require_expiry=False)
        return {"run_kind": "ai_api", "approval_receipt_id": approval_id, **(context or {})}


def _revoke_after(seconds, revoke, marks):
    async def hook():
        await asyncio.sleep(seconds)
        marks["revoked_at"] = time.monotonic()
        await revoke()
    return hook


def test_an_ai_scan_admitted_with_a_non_expiring_approval_runs_and_stops_on_its_revoke(template_database,
                                                                                         monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            api = _Api(pool, monkeypatch)
            async with pool.acquire() as conn:
                ai_id = await conn.fetchval(
                    "INSERT INTO ai_targets(name, endpoint_url) VALUES('model', 'https://model.fixture.test/v1/chat') "
                    "RETURNING id")
            approval = await api.approval("https://model.fixture.test/v1/chat", action_name="ai_gate.scan")
            options = await api.ai_options(ai_id, approval_id=approval)
            # Admitted without an expiry: it runs to completion while nothing changes.
            scanner = FixtureScanner(seconds=1)
            result, authority = await _run_ai(pool, scanner, monkeypatch, ai_id=ai_id, approval=None,
                                              scope_id=None, options=options, boundary=True, poll_seconds=0.2)
            assert authority.reason is None and scanner.returncode == 0 and result["result"]["grade"] == "A"
            # The same receipt revoked through the route stops the next run while it runs.
            marks = {}
            scanner = FixtureScanner()
            result, authority = await _run_ai(pool, scanner, monkeypatch, ai_id=ai_id, approval=None, scope_id=None,
                                              options=options, boundary=True, poll_seconds=0.2,
                                              during=_revoke_after(0.3, lambda: api.revoke(approval), marks))
            assert authority.reason == "authorization_revoked" and scanner.returncode < 0
            assert scanner.stopped_at - marks["revoked_at"] < 1.0
            assert result["scan_metadata"]["authority_stop"]["reason_code"] == "authorization_revoked"
    asyncio.run(run())


def test_a_device_scan_admitted_with_a_non_expiring_per_scan_approval_runs_and_stops_on_its_revoke(
        template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            api = _Api(pool, monkeypatch)
            device_id, _ = await _device(pool, standing=False)
            approval = await api.approval("http://device.fixture.test", action_name="device.scan")
            options = await api.device_options(device_id, approval_id=approval, confirm_authorized=True)
            assert options["asset_authorization_receipt_id"] is None
            scanner = FixtureScanner(seconds=1)
            result, authority, _events = await _run_device(pool, scanner, monkeypatch, device_id=device_id,
                                                           receipt=None, options=options, poll_seconds=0.2)
            assert authority.reason is None and scanner.returncode == 0
            marks = {}
            scanner = FixtureScanner()
            result, authority, events = await _run_device(
                pool, scanner, monkeypatch, device_id=device_id, receipt=None, options=options, poll_seconds=0.2,
                during=_revoke_after(0.3, lambda: api.revoke(approval), marks))
            assert authority.reason == "authorization_revoked" and "approval_revocation" in events
            assert scanner.stopped_at - marks["revoked_at"] < 1.0
    asyncio.run(run())


def test_a_device_scan_with_standing_authorization_and_a_per_scan_approval_watches_both(template_database,
                                                                                          monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            api = _Api(pool, monkeypatch)
            device_id, standing = await _device(pool)
            approval = await api.approval("http://device.fixture.test", action_name="device.scan")
            options = await api.device_options(device_id, approval_id=approval)
            # The options' scope is the per-scan approval's; the standing receipt has its own.
            assert options["asset_authorization_receipt_id"] == standing
            assert options["approval_receipt_id"] == approval
            scanner = FixtureScanner(seconds=1)
            _result, authority, _events = await _run_device(pool, scanner, monkeypatch, device_id=device_id,
                                                            receipt=None, options=options, poll_seconds=0.2)
            assert authority.reason is None and scanner.returncode == 0

            async def revoke_standing():
                async with pool.acquire() as conn:
                    await target_authorization.revoke_target_authorization(
                        conn, device_id, revoked_by="fixture-owner", reason="fixture revoke mid-scan")
            for revoke in (revoke_standing, lambda: api.revoke(approval)):
                if revoke is not revoke_standing:  # a fresh standing authorization; the approval is revoked
                    async with pool.acquire() as conn:
                        standing = str((await target_authorization.authorize_target(
                            conn, device_id, approved_by="fixture-owner"))["approval_receipt_id"])
                    options = {**options, "asset_authorization_receipt_id": standing}
                scanner = FixtureScanner()
                _result, authority, _events = await _run_device(
                    pool, scanner, monkeypatch, device_id=device_id, receipt=None, options=options,
                    poll_seconds=0.2, during=_revoke_after(0.3, revoke, {}))
                assert authority.reason == "authorization_revoked" and scanner.returncode < 0
    asyncio.run(run())


def test_a_device_moved_outside_its_approved_scope_stops_as_out_of_scope_not_revoked(template_database,
                                                                                      monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            api = _Api(pool, monkeypatch)
            device_id, _ = await _device(pool, standing=False)
            approval = await api.approval("http://device.fixture.test", action_name="device.scan")
            options = await api.device_options(device_id, approval_id=approval, confirm_authorized=True)

            async def move():
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE device_targets SET primary_locator='elsewhere.fixture.test' "
                                       "WHERE id=$1", device_id)
            scanner = FixtureScanner()
            result, authority, events = await _run_device(
                pool, scanner, monkeypatch, device_id=device_id, receipt=None, options=options,
                poll_seconds=0.2, during=_revoke_after(0.3, move, {}))
            assert authority.reason == "scope_invalid" and "approval_revocation" not in events
            assert result["scan_metadata"]["authority_stop"]["reason_code"] == "scope_invalid"
    asyncio.run(run())


def test_an_approval_with_an_expiry_that_passes_stops_the_run_as_expired(template_database, monkeypatch):
    from datetime import datetime, timedelta, timezone

    async def run():
        async with scan_database(template_database) as pool:
            api = _Api(pool, monkeypatch)
            device_id, _ = await _device(pool, standing=False)
            approval = await api.approval("http://device.fixture.test", action_name="device.scan",
                                          expires_at=datetime.now(timezone.utc) + timedelta(milliseconds=1500))
            options = await api.device_options(device_id, approval_id=approval, confirm_authorized=True)
            _result, authority, _events = await _run_device(pool, FixtureScanner(), monkeypatch,
                                                             device_id=device_id, receipt=None, options=options,
                                                             poll_seconds=0.3)
            assert authority.reason == "authorization_expired"
    asyncio.run(run())


def _broker_body(scan, action, **extra):
    return {"job_lease_token": "t" * 40, "worker_id": "broker:node-1", "plan_digest": scan.plan.plan_digest,
            "action_id": action.action_id, "action_digest": action.action_digest, **extra}


def _broker_receipt(scan, action, **changes):
    from datetime import datetime, timezone
    from runtime.receipts import CapabilityReceipt
    now = datetime.now(timezone.utc).isoformat()
    values = dict(
        capability_name=action.capability_name, adapter_name="fixture", adapter_version="1",
        target_id=str(scan.target_id), scan_id=str(scan.scan_id), worker_id="broker:node-1",
        scope_receipt_id=scan.binding.scope_receipt_id, approval_receipt_id=scan.policy.approval_receipt_id,
        status="success", input_digest=action.action_digest, parser_version="fixture/v1", started_at=now,
        finished_at=now, budget_reserved=action.requested_budget,
        budget_consumed={"http_requests": 1, "tool_wall_seconds": 1},
        observations=({"kind": "http_response", "status_code": 200},))
    values.update(changes)
    return CapabilityReceipt(**values)


def test_a_heartbeat_for_a_withdrawn_action_loses_its_lease_on_the_control_plane(template_database, monkeypatch):
    """A node that never asks (older or misbehaving) cannot keep a withdrawn action alive."""
    from fastapi import HTTPException
    import fleet_routes.router as fleet
    from tests.test_scan_local_revocation_postgres import _scan

    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            request = _broker_control_plane(monkeypatch, pool, scan)
            active = scan.plan.actions[1]
            body = fleet.BrokerActionLeaseRequest(**_broker_body(scan, active, action_lease={}))
            heartbeat = fleet.heartbeat_broker_scan_action
            assert await heartbeat("node-1", "lease-1", active.action_id, body, None) == {"status": "running"}
            await scan.revoke()
            with pytest.raises(HTTPException) as lost:
                await heartbeat("node-1", "lease-1", active.action_id, body, None)
            assert lost.value.status_code == 409 and "authorization_revoked" in lost.value.detail
            assert request.backend.heartbeats == 1  # the withdrawn heartbeat did not extend the lease
    asyncio.run(run())


def test_a_result_settled_after_a_revoke_is_recorded_partial_not_succeeded(template_database, monkeypatch):
    import fleet_routes.router as fleet
    from tests.test_scan_local_revocation_postgres import _scan

    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            request = _broker_control_plane(monkeypatch, pool, scan)
            settle = fleet.settle_broker_scan_action
            first, active, later = scan.plan.actions[0], scan.plan.actions[1], scan.plan.actions[2]
            # Before the revoke a success is settled as the node reported it.
            body = fleet.BrokerActionResultRequest(**_broker_body(
                scan, first, action_lease={}, receipt=_broker_receipt(scan, first).public_dict()))
            await settle("node-1", "lease-1", first.action_id, body, None)
            assert request.backend.settled[-1].status == "success"
            await scan.revoke()
            # A node that kept running reports success with what it found: the control plane
            # keeps the observations and records the receipt partial with the reason.
            body = fleet.BrokerActionResultRequest(**_broker_body(
                scan, active, action_lease={}, receipt=_broker_receipt(scan, active).public_dict()))
            await settle("node-1", "lease-1", active.action_id, body, None)
            settled = request.backend.settled[-1]
            assert settled.status == "partial" and settled.partial
            assert settled.errors[0] == "authorization_revoked"
            assert settled.redacted_execution["target_authority_interruption"]["reason_code"] == "authorization_revoked"
            assert {"kind": "http_response", "status_code": 200} in settled.observations
            # A node that stopped on its own already says so; its receipt is kept as it is.
            honest = _broker_receipt(scan, later, status="partial", partial=True, errors=("authorization_revoked",),
                                     redacted_execution={"target_authority_interruption": {
                                         "reason_code": "authorization_revoked", "observed_at": None}})
            body = fleet.BrokerActionResultRequest(**_broker_body(
                scan, later, action_lease={}, receipt=honest.public_dict()))
            await settle("node-1", "lease-1", later.action_id, body, None)
            assert request.backend.settled[-1].receipt_hash == honest.receipt_hash
    asyncio.run(run())


def test_the_authority_route_polls_cheaply_after_its_first_check(template_database, monkeypatch):
    from tests.test_scan_local_revocation_postgres import CountingPool, _scan

    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            counted = CountingPool(pool)
            request = _broker_control_plane(monkeypatch, counted, scan)
            authority = _broker_authority(scan, request)
            active = scan.plan.actions[1]
            assert await authority.check(active) is None
            after_first = dict(counted.statements_by_kind)
            for _ in range(5):
                assert await authority.poll(active) is None
            # Each later poll is one statement: the guard's fingerprint, no full re-check.
            assert counted.statements_by_kind["fingerprint"] - after_first["fingerprint"] == 5
            assert counted.statements_by_kind["other"] == after_first["other"]
            await scan.revoke()
            assert await authority.poll(active) == "authorization_revoked"
    asyncio.run(run())
