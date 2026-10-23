"""A credentialed Scan admitted on the target's standing authorization records a credential-tier
receipt, as New Scan does (PostgreSQL).

E1 O2: a credentialed scan from the terminal was bound to the target's standing active-tier
receipt, while New Scan in the UI creates a bounded credential-tier receipt. The submission now
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
from runtime.models import ScanPolicy  # noqa: E402


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
                    conn, target_id=scan.target_id, standing_receipt_id=standing)
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
            if supplied:
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
    _standing, supplied, options, _row = _submit(monkeypatch, template_database, supplied=True)
    assert options["approval_receipt_id"] == supplied
