"""``GET /targets/{id}`` and ``GET /targets`` agree on whether a target is authorized (PostgreSQL).

The single-target answer did not carry ``authorized_for_active_testing`` at all, while the list
did: a client reading one target (an agent's ``target.get``) saw no authorization state and had to
know to read the nested ``authorization`` object instead. The list computed the field with its own
predicate, which only looked for a receipt recorded on the row itself, so a web app covered by its
host's standing authorization (the canonical reader says authorized, ``inherited``) was listed as
not authorized, and an archived target that still held a receipt was listed as authorized although
every reader resolves an archived target to no authorization.

Both answers now come from the canonical reader's rules; each case is checked against
``current_target_authorization()``. Lab-range addresses only; nothing is contacted. Requires
``TARGET_ASSET_TEST_DATABASE_URL``.
"""
from __future__ import annotations

import asyncio
import json
import uuid

from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402
from tests.test_target_host_web_consistency_postgres import _host_of, _router, _target  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]


async def _receipt(conn, target_id, host):
    scope = "scope-" + uuid.uuid4().hex
    await conn.execute(
        """INSERT INTO scope_receipts(id, target_id, input_scope, normalized_scope, verdict, blocked_by,
                                      warnings, checks, environment, allowed_hosts, allowed_root_domains,
                                      redirect_destinations)
           VALUES($1, $2, '{}', $3, 'allowed', '[]', '[]', '[]', 'lab', $4, '[]', '[]')""",
        scope, target_id, json.dumps({"host": host}), json.dumps([host]))
    await conn.execute(
        """INSERT INTO approval_receipts(scope_receipt_id, risk_tier, confirmations, action_name,
                                         action_context, approved_by, status)
           VALUES($1, 'active', '["confirm_authorized"]', 'target.authorization', '{}', 'fixture', 'active')""",
        scope)


def test_target_detail_and_list_report_the_canonical_authorization_state(template_database, monkeypatch):
    async def run():
        import target_authorization
        from targets.archive import archive

        async with scan_database(template_database) as pool:
            router, _asset_router = _router(monkeypatch, pool)
            own = await router.create_target(_target("http://10.10.10.180:8081"))
            via_host = await router.create_target(_target("http://10.10.10.181:8081"))
            none = await router.create_target(_target("http://10.10.10.182:8081"))
            archived = await router.create_target(_target("http://10.10.10.183:8081"))
            async with pool.acquire() as conn:
                await _receipt(conn, uuid.UUID(own["id"]), "10.10.10.180")
                await _receipt(conn, (await _host_of(pool, via_host["id"]))["id"], "10.10.10.181")
                await _receipt(conn, uuid.UUID(archived["id"]), "10.10.10.183")
            await archive(pool, uuid.UUID(archived["id"]))

            expected = {own["id"]: True, via_host["id"]: True, none["id"]: False, archived["id"]: False}
            listed = await router.list_targets(include_inactive=True, limit=100, offset=0)
            by_id = {row["id"]: row for row in listed["targets"]}
            for target_id, authorized in expected.items():
                async with pool.acquire() as conn:
                    canonical = await target_authorization.current_target_authorization(conn, target_id)
                assert (canonical is not None) is authorized, target_id
                detail = await router.get_target(target_id)
                assert detail["authorized_for_active_testing"] is authorized, (
                    f"GET /targets/{target_id} does not say whether the target is authorized")
                assert (detail["authorization"] is not None) is authorized
                assert by_id[target_id]["authorized_for_active_testing"] is authorized, (
                    f"GET /targets disagrees with the canonical reader for {target_id}")
            assert (await router.get_target(via_host["id"]))["authorization"]["inherited"] is True
    asyncio.run(run())
