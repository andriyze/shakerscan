"""A credentialed Scan admitted on the target's standing authorization records a credential-tier
receipt, as New Scan does (PostgreSQL).

A credentialed scan from the terminal was bound to the target's standing active-tier receipt,
while New Scan in the UI creates a bounded credential-tier receipt. The submission now
derives a credential-tier receipt from the standing authorization (``derive_credential_scan_receipt``)
and binds the scan to it. Who may start the scan is unchanged (it still needs the standing
authorization); the derived receipt ends with the authorization it came from and authorizes no
other work. The running-scan guard is the real one over the installed schema; only the dispatcher
is a fixture (``FixtureToolDispatcher``). No target is contacted.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from tests.test_scan_local_revocation_postgres import (  # noqa: E402
    FixtureToolDispatcher, _scan, scan_database,
)

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]
import target_authorization  # noqa: E402
from runtime.models import ScanPolicy, TargetBinding  # noqa: E402


async def _row(pool, receipt_id):
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM approval_receipts WHERE id=$1", uuid.UUID(str(receipt_id)))
    return dict(row) if row else None


def test_the_derived_receipt_is_credential_tier_bounded_and_names_its_source(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            standing = scan.policy.approval_receipt_id
            async with pool.acquire() as conn:
                derived = await target_authorization.derive_credential_scan_receipt(
                    conn, target_id=scan.target_id, standing_receipt_id=standing, scan_id=scan.scan_id)
            row, source = await _row(pool, derived), await _row(pool, standing)
            assert derived and derived != standing
            assert row["risk_tier"] == "credential"
            assert row["action_name"] == "scan.submit"
            assert row["scope_receipt_id"] == source["scope_receipt_id"]
            assert row["approved_by"] == source["approved_by"] == "fixture-owner"
            assert row["status"] == "active"
            assert row["expires_at"] is not None
            assert row["expires_at"] <= datetime.now(timezone.utc) + timedelta(days=7, minutes=1)
            context = row["action_context"]
            context = json.loads(context) if isinstance(context, str) else context
            assert context["derived_from_approval_receipt_id"] == str(standing)
            assert context["derived_for"] == "credential_scan"
            assert context["target_id"] == str(scan.target_id)
            # The Scan it was recorded for, and the tier of the authorization it came from.
            assert context["scan_id"] == str(scan.scan_id)
            assert context["source_risk_tier"] == source["risk_tier"] == "active"
    asyncio.run(run())


def test_no_receipt_is_derived_from_a_revoked_or_missing_authorization(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            standing = scan.policy.approval_receipt_id
            await scan.revoke()
            async with pool.acquire() as conn:
                revoked = await target_authorization.derive_credential_scan_receipt(
                    conn, target_id=scan.target_id, standing_receipt_id=standing)
                missing = await target_authorization.derive_credential_scan_receipt(
                    conn, target_id=scan.target_id, standing_receipt_id=uuid.uuid4())
                count = await conn.fetchval("SELECT count(*) FROM approval_receipts WHERE risk_tier='credential'")
            assert revoked is None and missing is None and count == 0
    asyncio.run(run())


def test_an_authorization_inherited_from_another_target_derives_nothing(template_database):
    """Only a target's own standing authorization is copied; an inherited one stays as it is."""
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool, url="http://owner.test")
            async with pool.acquire() as conn:
                other = await conn.fetchval("INSERT INTO targets(url) VALUES('http://other.test') RETURNING id")
                derived = await target_authorization.derive_credential_scan_receipt(
                    conn, target_id=other, standing_receipt_id=scan.policy.approval_receipt_id)
            assert derived is None
    asyncio.run(run())


def test_revoking_the_target_authorization_revokes_the_derived_receipt_and_stops_the_scan(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            async with pool.acquire() as conn:
                derived = await target_authorization.derive_credential_scan_receipt(
                    conn, target_id=scan.target_id, standing_receipt_id=scan.policy.approval_receipt_id)
            scan.policy = ScanPolicy(active_testing=True, approval_receipt_id=str(derived),
                                     scope_receipt_id=scan.binding.scope_receipt_id)
            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               after={"baseline.http": scan.revoke})
            guard = scan.guard()
            await scan.run(dispatcher, guard)
            assert dispatcher.dispatched == ["baseline.http", "finalize.report"]
            assert (await scan.actions())["templates.active"] == ("blocked", "authorization_revoked")
            assert (await _row(pool, derived))["status"] == "revoked"
    asyncio.run(run())


def test_a_derived_receipt_stops_with_its_source_even_without_the_cascade(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            source = scan.policy.approval_receipt_id
            async with pool.acquire() as conn:
                derived = await target_authorization.derive_credential_scan_receipt(
                    conn, target_id=scan.target_id, standing_receipt_id=source)
            scan.policy = ScanPolicy(active_testing=True, approval_receipt_id=str(derived),
                                     scope_receipt_id=scan.binding.scope_receipt_id)

            async def revoke_source_only():
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE approval_receipts SET status='revoked', revoked_at=NOW(), "
                                       "revoked_by='fixture' WHERE id=$1", uuid.UUID(str(source)))

            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               after={"baseline.http": revoke_source_only})
            await scan.run(dispatcher, scan.guard())
            assert dispatcher.dispatched == ["baseline.http", "finalize.report"]
            assert (await scan.actions())["templates.active"] == ("blocked", "authorization_revoked")
    asyncio.run(run())


def test_a_derived_receipt_authorizes_no_other_submission(template_database, monkeypatch):
    """Supplied again (another scan, a Hunt, a credential use), it is refused with its reason."""
    from fastapi import HTTPException

    from api import api as api_module

    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            async with pool.acquire() as conn:
                derived = await target_authorization.derive_credential_scan_receipt(
                    conn, target_id=scan.target_id, standing_receipt_id=scan.policy.approval_receipt_id)
                admitted = await api_module._validate_approval_receipt_for_action(
                    conn, derived, target_url="http://revocation.test", target_id=scan.target_id,
                    action_name="scan.submit", risk_tier="credential", always_require_receipt=True,
                    require_target_binding=True, require_expiry=True,
                    admit_derived_credential_receipt=True,
                )
                assert admitted["risk_tier"] == "credential"
                with pytest.raises(HTTPException) as refused:
                    await api_module._validate_approval_receipt_for_action(
                        conn, derived, target_url="http://revocation.test", target_id=scan.target_id,
                        action_name="scan.submit", risk_tier="credential", always_require_receipt=True,
                        require_target_binding=True, require_expiry=True,
                    )
                blocked = await conn.fetchval(
                    "SELECT blocked_by::text FROM command_results WHERE status='blocked' "
                    "ORDER BY created_at DESC LIMIT 1")
            return refused.value, blocked

    refused, blocked = asyncio.run(run())
    assert refused.status_code == 400
    assert "one scan" in str(refused.detail) and "without a receipt" in str(refused.detail)
    assert "approval_receipt_derived_for_one_scan" in blocked


class _AdmittedToFamilies(Exception):
    """Raised where admission has bound the scan's receipts, before the scan is queued."""


def _submit(monkeypatch, template_database, *, supplied=False, credentialed=True):
    """Drive the real submission through receipt binding; the credential admission is a labelled
    double (an exact-target profile ref) so no encrypted profile is needed, and the run stops at
    the family prerequisite check, which reads the bound options."""
    from api import api as api_module
    from tests.test_target_asset_inputs_postgres import encryption

    encryption(monkeypatch)
    url = "http://credentialed.test"

    async def dns_alias(_pool, target, *, supplied_receipt_id=None, **_kwargs):
        return target, None, None, supplied_receipt_id

    async def no_op(*_args, **_kwargs):
        return None

    async def fixture_credential_refs(_conn, **_kwargs):  # labelled double
        return [{"credential_profile_id": str(uuid.uuid4()), "auth_kind": "authorization_header",
                 "scan_lane": "primary", "allowed_capabilities": ["web.crawl"]}] if credentialed else []

    async def no_browser_logins(*_args, **_kwargs):
        return []

    seen = {}

    def stop(_families, options_payload, *_args, **_kwargs):
        seen["options"] = json.loads(json.dumps(options_payload, default=str))
        raise _AdmittedToFamilies

    monkeypatch.setattr(api_module, "get_redis", lambda: object())
    monkeypatch.setattr(api_module.target_dns_alias, "prepare_scan_dns_alias", dns_alias)
    monkeypatch.setattr(api_module, "_worker_freshness_snapshot", lambda: {"available": False})
    monkeypatch.setattr(api_module, "_require_approval_receipt_if_policy_enabled", no_op)
    monkeypatch.setattr(api_module, "_require_reachable_fleet_placement", no_op)
    monkeypatch.setattr(api_module, "_admit_generic_scan_credential_profiles", fixture_credential_refs)
    monkeypatch.setattr(api_module, "admit_scan_browser_login_profiles", no_browser_logins)
    monkeypatch.setattr(api_module.check_registry, "scan_family_precondition_errors", stop)
    derive = api_module.target_authorization.derive_credential_scan_receipt
    seen["receipts"] = {}

    async def observed_derive(conn, **kwargs):
        # The real derivation; the row is read on admission's connection, inside the transaction
        # the stop rolls back.
        derived = await derive(conn, **kwargs)
        if derived:
            seen["receipts"][derived] = dict(await conn.fetchrow(
                "SELECT * FROM approval_receipts WHERE id=$1", uuid.UUID(derived)))
        return derived

    monkeypatch.setattr(api_module.target_authorization, "derive_credential_scan_receipt", observed_derive)

    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                target_id = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", url)
                standing = await target_authorization.authorize_target(conn, target_id, approved_by="fixture-owner")
            receipt = None
            if supplied == "standing":
                receipt = str(standing["approval_receipt_id"])
            elif supplied:
                async with pool.acquire() as conn:
                    receipt = str(await conn.fetchval(
                        """INSERT INTO approval_receipts(scope_receipt_id,risk_tier,confirmations,approved_by,expires_at)
                           VALUES($1,'credential','["confirm_authorized"]','interactive-ui',NOW()+interval '2 hours')
                           RETURNING id""", standing["scope_receipt_id"]))
            monkeypatch.setattr(api_module, "db_pool", pool)
            with pytest.raises(_AdmittedToFamilies):
                await api_module._submit_scan(api_module.ScanRequest(
                    target=url, policy={"active_testing": True},
                    credential_profile_ids=[str(uuid.uuid4())] if credentialed else [],
                    approval_receipt_id=receipt))
            bound = seen["options"]["approval_receipt_id"]
            row = seen["receipts"].get(bound)
            if row is None:
                async with pool.acquire() as conn:
                    row = dict(await conn.fetchrow("SELECT * FROM approval_receipts WHERE id=$1", uuid.UUID(bound)))
            return standing, receipt, seen["options"], row

    return asyncio.run(run())


def test_a_terminal_credentialed_scan_is_bound_to_a_credential_tier_receipt(template_database, monkeypatch):
    standing, _supplied, options, row = _submit(monkeypatch, template_database)
    assert options["approval_receipt_id"] != standing["approval_receipt_id"]
    assert row["risk_tier"] == "credential" and row["action_name"] == "scan.submit"
    assert options["risk_tier"] == "credential"
    assert options["scope_receipt_id"] == standing["scope_receipt_id"]
    # The plan the scan runs under names the same receipt as its options.
    assert options["scan_policy"]["approval_receipt_id"] == options["approval_receipt_id"]
    assert options["scan_execution_plan"]["policy"]["approval_receipt_id"] == options["approval_receipt_id"]


def test_an_uncredentialed_active_scan_keeps_the_standing_receipt(template_database, monkeypatch):
    standing, _supplied, options, row = _submit(monkeypatch, template_database, credentialed=False)
    assert options["approval_receipt_id"] == standing["approval_receipt_id"]
    assert row["risk_tier"] == "active"


def test_a_receipt_the_caller_named_is_kept(template_database, monkeypatch):
    _standing, supplied, options, row = _submit(monkeypatch, template_database, supplied=True)
    assert options["approval_receipt_id"] == supplied
    assert row["action_context"] is None or "derived_for" not in str(row["action_context"])


def test_naming_the_standing_authorization_records_the_same_credential_tier_receipt(
        template_database, monkeypatch):
    """The tier on record does not depend on whether the client spelled the standing receipt."""
    standing, supplied, options, row = _submit(monkeypatch, template_database, supplied="standing")
    assert supplied == str(standing["approval_receipt_id"])
    assert options["approval_receipt_id"] != supplied
    assert row["risk_tier"] == "credential" and row["action_name"] == "scan.submit"
    context = row["action_context"]
    context = json.loads(context) if isinstance(context, str) else context
    assert context["derived_from_approval_receipt_id"] == supplied
    assert str(uuid.UUID(context["scan_id"])) == context["scan_id"]
    assert options["scan_policy"]["approval_receipt_id"] == options["approval_receipt_id"]


def test_a_derived_receipt_covers_credentials_and_its_source_tier_only():
    """Stored as tier ``credential`` (ranked above intrusive), it never reads as broader than the
    standing authorization it came from."""
    from runtime.approval_policy import approval_covers_risk

    def derived(source_tier):
        return {"risk_tier": "credential", "action_name": "scan.submit", "action_context": json.dumps({
            "derived_for": "credential_scan", "derived_from_approval_receipt_id": str(uuid.uuid4()),
            **({"source_risk_tier": source_tier} if source_tier else {})})}

    standing = {"risk_tier": "active", "action_name": "target.authorization"}
    for tier in ("read_only", "passive", "active", "intrusive", "credential", "dangerous"):
        assert approval_covers_risk(derived("active"), tier) is (
            tier == "credential" or approval_covers_risk(standing, tier)), tier
    assert approval_covers_risk(derived("intrusive"), "intrusive") is True
    assert approval_covers_risk(derived("intrusive"), "dangerous") is False
    # A record without its source's tier covers what it was recorded for, nothing else.
    assert approval_covers_risk(derived(None), "credential") is True
    assert approval_covers_risk(derived(None), "active") is False
    # An ordinary credential-tier receipt is unchanged.
    assert approval_covers_risk({"risk_tier": "credential", "action_name": "scan.submit"}, "intrusive") is True


# --- The derived receipt ends with its source, wherever it is filed and whichever gate reads it ---

async def _alias_service(pool):
    """An owner target authorized (S), and an application service on its www twin whose standing
    authorization is an alias receipt A2 filed under the service and derived from S."""
    async with pool.acquire() as conn:
        owner = await conn.fetchval("INSERT INTO targets(url) VALUES('http://alias.test') RETURNING id")
        source = await target_authorization.authorize_target(conn, owner, approved_by="fixture-owner")
        service = await conn.fetchval("INSERT INTO targets(url) VALUES('http://www.alias.test') RETURNING id")
        receipt = (await target_authorization.evaluate_target_scope(conn, service))["receipt"]
        await target_authorization.persist_scope_receipt(conn, receipt, service)
        alias = await conn.fetchval(
            """INSERT INTO approval_receipts
                   (scope_receipt_id, risk_tier, confirmations, action_name, action_context, approved_by)
               VALUES ($1,'active','["confirm_authorized"]','target.authorization',$2::jsonb,'fixture-owner')
               RETURNING id""",
            receipt["receipt_id"], json.dumps({
                "target_id": str(service), "host": "www.alias.test", "dns_alias_from": "alias.test",
                "derived_from_approval_receipt_id": str(source["approval_receipt_id"]),
            }),
        )
    host_binding = TargetBinding(target_id=str(service), target_kind="web", canonical_host="www.alias.test",
                                 allowed_origins=("http://www.alias.test",), environment="lab",
                                 scope_receipt_id=receipt["receipt_id"])
    return owner, service, str(source["approval_receipt_id"]), str(alias), host_binding


async def _credential_gate(pool, binding, receipt_id):
    """The worker's last gate before decryption, as a credentialed Scan's credential check calls it."""
    from runtime.credential_resolver import CredentialResolutionError, validate_worker_credential_authority
    async with pool.acquire() as conn:
        try:
            await validate_worker_credential_authority(
                conn, owner_kind="scan", owner_id=str(uuid.uuid4()), target=binding,
                approval_receipt_id=receipt_id, scope_receipt_id=binding.scope_receipt_id,
                action_name="scan.submit")
        except CredentialResolutionError as exc:
            return str(exc)
    return "allowed"


def test_revoking_the_owner_revokes_a_receipt_derived_under_an_alias_service(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            owner, service, source, alias, binding = await _alias_service(pool)
            async with pool.acquire() as conn:
                derived = await target_authorization.derive_credential_scan_receipt(
                    conn, target_id=service, standing_receipt_id=alias)
            assert derived
            assert await _credential_gate(pool, binding, derived) == "allowed"
            async with pool.acquire() as conn:
                await target_authorization.revoke_target_authorization(
                    conn, owner, revoked_by="fixture-owner", reason="owner offboarded")
            statuses = {name: (await _row(pool, value))["status"]
                        for name, value in (("source", source), ("alias", alias), ("derived", derived))}
            assert statuses == {"source": "revoked", "alias": "revoked", "derived": "revoked"}
            assert await _credential_gate(pool, binding, derived) != "allowed"
    asyncio.run(run())


def test_the_credential_gate_refuses_a_derived_receipt_whose_source_ended(template_database):
    """A passive credentialed Scan has no approval on its plan: the credential gate is its only stop."""
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            source = scan.policy.approval_receipt_id
            async with pool.acquire() as conn:
                derived = await target_authorization.derive_credential_scan_receipt(
                    conn, target_id=scan.target_id, standing_receipt_id=source)
            assert await _credential_gate(pool, scan.binding, derived) == "allowed"
            async with pool.acquire() as conn:
                # A revoke of the source alone, with no cascade to the receipts derived from it.
                await conn.execute("UPDATE approval_receipts SET status='revoked', revoked_at=NOW(), "
                                   "revoked_by='fixture' WHERE id=$1", uuid.UUID(str(source)))
            assert (await _row(pool, derived))["status"] == "active"
            refused = await _credential_gate(pool, scan.binding, derived)
            assert refused != "allowed" and "source" in refused
            assert await _credential_gate(pool, scan.binding, source) != "allowed"
    asyncio.run(run())


def test_the_credential_gate_refuses_a_derived_receipt_whose_source_no_longer_stands(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            async with pool.acquire() as conn:
                derived = await target_authorization.derive_credential_scan_receipt(
                    conn, target_id=scan.target_id, standing_receipt_id=scan.policy.approval_receipt_id)
                # The target's host changed: its standing authorization no longer covers it.
                await conn.execute("UPDATE targets SET url='http://moved.test' WHERE id=$1", scan.target_id)
            assert await _credential_gate(pool, scan.binding, derived) != "allowed"
    asyncio.run(run())


def test_the_generic_approval_revoke_route_ends_the_derived_receipt(template_database, monkeypatch):
    import arsenal_routes.router as arsenal

    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(arsenal, "_pool", lambda: pool)
            scan = await _scan(pool)
            source = scan.policy.approval_receipt_id
            async with pool.acquire() as conn:
                derived = await target_authorization.derive_credential_scan_receipt(
                    conn, target_id=scan.target_id, standing_receipt_id=source)
            await arsenal.arsenal_revoke_approval(str(source), arsenal.ApprovalReceiptRevocationRequest(
                revoked_by="fixture-owner", reason="fixture revoke"))
            assert (await _row(pool, source))["status"] == "revoked"
            assert (await _row(pool, derived))["status"] == "revoked"
    asyncio.run(run())


def test_the_running_scan_check_reads_the_target_from_the_derived_receipt(template_database):
    """A binding without a target id does not skip the source check: it fails closed."""
    from scan.authorization import ActionAuthorityDecision, revalidate_scan_action_authority

    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            source = scan.policy.approval_receipt_id
            async with pool.acquire() as conn:
                derived = await target_authorization.derive_credential_scan_receipt(
                    conn, target_id=scan.target_id, standing_receipt_id=source)
                action = next(item for item in scan.plan.actions if item.action_id == "templates.active")
                unbound = TargetBinding(target_id="", target_kind="web", canonical_host="revocation.test",
                                        allowed_origins=("http://revocation.test",), environment="lab",
                                        scope_receipt_id=scan.binding.scope_receipt_id)
                before = await revalidate_scan_action_authority(
                    conn, action=action, target_binding=unbound,
                    scope_receipt_id=scan.binding.scope_receipt_id, approval_receipt_id=derived)
                await conn.execute("UPDATE approval_receipts SET status='revoked', revoked_at=NOW(), "
                                   "revoked_by='fixture' WHERE id=$1", uuid.UUID(str(source)))
                after = await revalidate_scan_action_authority(
                    conn, action=action, target_binding=unbound,
                    scope_receipt_id=scan.binding.scope_receipt_id, approval_receipt_id=derived)
            assert before is ActionAuthorityDecision.ALLOWED
            assert after is ActionAuthorityDecision.REJECTED_REVOKED
    asyncio.run(run())


async def _wait_for_lock(pool, pid, *, seconds=10.0):
    """Until the backend ``pid`` waits on a lock (a concurrent transaction holds the row)."""
    deadline = asyncio.get_running_loop().time() + seconds
    async with pool.acquire() as conn:
        while asyncio.get_running_loop().time() < deadline:
            if await conn.fetchval(
                "SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid=$1", pid):
                return True
            await asyncio.sleep(0.05)
    return False


def test_a_revocation_waits_for_a_derivation_in_progress_and_then_ends_it(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            source = scan.policy.approval_receipt_id
            deriving, revoking = await pool.acquire(), await pool.acquire()
            try:
                derive_tx = deriving.transaction()
                await derive_tx.start()
                derived = await target_authorization.derive_credential_scan_receipt(
                    deriving, target_id=scan.target_id, standing_receipt_id=source)
                assert derived

                async def revoke():
                    async with revoking.transaction():
                        await target_authorization.revoke_target_authorization(
                            revoking, scan.target_id, revoked_by="fixture-owner", reason="fixture race")

                task = asyncio.create_task(revoke())
                # The revocation cannot pass the derivation's lock on the source.
                assert await _wait_for_lock(pool, revoking.get_server_pid())
                assert not task.done()
                await derive_tx.commit()
                await asyncio.wait_for(task, timeout=10)
            finally:
                await pool.release(deriving)
                await pool.release(revoking)
            assert (await _row(pool, source))["status"] == "revoked"
            assert (await _row(pool, derived))["status"] == "revoked"
    asyncio.run(run())


def test_a_derivation_waits_for_a_revocation_in_progress_and_then_derives_nothing(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            source = scan.policy.approval_receipt_id
            deriving, revoking = await pool.acquire(), await pool.acquire()
            try:
                revoke_tx = revoking.transaction()
                await revoke_tx.start()
                await target_authorization.revoke_target_authorization(
                    revoking, scan.target_id, revoked_by="fixture-owner", reason="fixture race")

                async def derive():
                    async with deriving.transaction():
                        return await target_authorization.derive_credential_scan_receipt(
                            deriving, target_id=scan.target_id, standing_receipt_id=source)

                task = asyncio.create_task(derive())
                assert await _wait_for_lock(pool, deriving.get_server_pid())
                assert not task.done()
                await revoke_tx.commit()
                derived = await asyncio.wait_for(task, timeout=10)
            finally:
                await pool.release(deriving)
                await pool.release(revoking)
            async with pool.acquire() as conn:
                active = await conn.fetchval(
                    "SELECT count(*) FROM approval_receipts WHERE status='active' "
                    "AND action_context->>'derived_for'='credential_scan'")
            assert derived is None and active == 0
    asyncio.run(run())
