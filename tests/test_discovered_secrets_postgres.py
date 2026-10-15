"""Discovered secrets in real PostgreSQL (2.10): store, deduplicate, resolve by reference, refuse.

DISCOVERED_SECRETS_TEST_DATABASE_URL must address localhost/shakerscan_discovered_secrets_test;
the schema is rebuilt from db/init.sql and the startup migrations. Values are synthetic.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
from uuid import uuid4

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("DISCOVERED_SECRETS_TEST_DATABASE_URL")
REQUIRED = os.environ.get("DISCOVERED_SECRETS_POSTGRES_REQUIRED") == "1"
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable discovered-secrets database")
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "api"), str(ROOT / "scanner")]

from hunt import discovered_secrets as store  # noqa: E402

SYNTHETIC = "synthetic-db-password-7f3a9c"
SYNTHETIC_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c2lnbmF0dXJl"


@pytest.fixture(scope="module", autouse=True)
def schema():
    require_disposable_database(DSN or "", "shakerscan_discovered_secrets_test")

    async def initialize():
        from retest_contract import run_schema_migrations
        async with asyncpg.create_pool(DSN, min_size=1, max_size=3) as pool:
            async with pool.acquire() as conn:
                await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
                await conn.execute((ROOT / "db/init.sql").read_text())
            await run_schema_migrations(pool)
    asyncio.run(initialize())


@pytest.fixture(autouse=True)
def credential_key(monkeypatch):
    from cryptography.fernet import Fernet
    import secret_store
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", False)  # the schema migration loaded it keyless


def run(scenario):
    async def work():
        async with asyncpg.create_pool(DSN, min_size=1, max_size=4) as pool:
            async with pool.acquire() as conn:
                await scenario(conn)
    asyncio.run(work())


async def _target(conn):
    target = uuid4()
    await conn.execute("INSERT INTO targets(id,url) VALUES($1,$2)", target, f"https://{target}.example.invalid")
    return target


async def _hunt(conn, target):
    hunt = await conn.fetchval(
        "INSERT INTO hunt_runs(target_kind,target_id,status) VALUES('web',$1,'active') RETURNING id", target)
    action = await conn.fetchval(
        "INSERT INTO hunt_actions(hunt_run_id,capability_name,status) VALUES($1,'http.request','completed') RETURNING id",
        hunt)
    return hunt, action


def test_a_value_is_stored_once_per_target_encrypted_and_listed_without_it():
    async def scenario(conn):
        target = await _target(conn)
        source = {"kind": "hunt_action", "id": str(uuid4()), "hunt_id": str(uuid4())}
        first = await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC, "DB_PASSWORD"), (SYNTHETIC_JWT, "")], source=source)
        assert first == {"stored": 2, "refreshed": 0}
        again = await store.record_discovered(conn, target_id=target, values=[(SYNTHETIC, "")], source=source)
        assert again == {"stored": 0, "refreshed": 1}
        rows = await conn.fetch("SELECT * FROM discovered_secrets WHERE target_id=$1", target)
        assert len(rows) == 2
        for row in rows:
            assert row["value_ciphertext"].startswith("enc:fernet:")
            assert SYNTHETIC not in str(dict(row)) and SYNTHETIC_JWT not in str(dict(row))
        listed = await store.list_for_target(conn, target)
        assert {item["kind"] for item in listed} == {"password", "jwt"}
        password = next(item for item in listed if item["kind"] == "password")
        assert password["seen_count"] == 2 and password["label"] == "DB_PASSWORD"
        assert password["length"] == len(SYNTHETIC) and password["ref"].startswith("secret://")
        assert SYNTHETIC not in str(listed) and SYNTHETIC_JWT not in str(listed)
        # The same value on another target is a separate row.
        other = await _target(conn)
        assert (await store.record_discovered(
            conn, target_id=other, values=[(SYNTHETIC, "")], source=source))["stored"] == 1
    run(scenario)


def test_a_reference_resolves_only_for_its_target_while_active_and_records_the_use():
    async def scenario(conn):
        target, other = await _target(conn), await _target(conn)
        await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC, "password")],
            source={"kind": "hunt_action", "id": str(uuid4())})
        ref = (await store.list_for_target(conn, target))[0]["ref"]
        hunt, action = await _hunt(conn, target)
        value = await store.resolve_for_hunt(
            conn, reference=ref, target_id=target, hunt_run_id=hunt, action_id=action,
            destination_host="app.example.invalid")
        assert value == SYNTHETIC
        listed = (await store.list_for_target(conn, target))[0]
        assert listed["uses"] == 1 and listed["last_used_at"]
        other_hunt, other_action = await _hunt(conn, other)
        with pytest.raises(store.DiscoveredSecretError) as refused:
            await store.resolve_for_hunt(
                conn, reference=ref, target_id=other, hunt_run_id=other_hunt, action_id=other_action)
        assert refused.value.reason == store.SECRET_TARGET_MISMATCH and SYNTHETIC not in str(refused.value)
        secret_id = ref.removeprefix("secret://")
        assert await store.set_state(
            conn, target_id=target, secret_id=secret_id, state="revoked_by_operator", actor="operator:test")
        with pytest.raises(store.DiscoveredSecretError) as revoked:
            await store.resolve_for_hunt(conn, reference=ref, target_id=target, hunt_run_id=hunt, action_id=action)
        assert revoked.value.reason == store.SECRET_NOT_ACTIVE
        # A new sighting does not undo an operator's revocation.
        await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC, "")], source={"kind": "retest", "id": "r1"})
        assert (await store.list_for_target(conn, target))[0]["state"] == "revoked_by_operator"
        assert await store.set_state(
            conn, target_id=target, secret_id=secret_id, state="active", actor="operator:test")
        await conn.execute(
            "UPDATE discovered_secrets SET expires_at=$2 WHERE id=$1::uuid", secret_id,
            datetime.now(timezone.utc) - timedelta(seconds=1))
        with pytest.raises(store.DiscoveredSecretError) as expired:
            await store.resolve_for_hunt(conn, reference=ref, target_id=target, hunt_run_id=hunt, action_id=action)
        assert expired.value.reason == store.SECRET_EXPIRED
        assert (await store.expire_due(conn))["expired"] == 1
        assert await store.list_for_target(conn, target, usable_only=True) == []
        # An operator decided about this row (revoked, then reactivated): a later sighting does not
        # revive it after expiry; the operator can.
        await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC, "")], source={"kind": "retest", "id": "r2"})
        assert await store.list_for_target(conn, target, usable_only=True) == []
        assert await store.set_state(conn, target_id=target, secret_id=secret_id, state="active",
                                     actor="operator:test")
        assert await store.set_expiry(conn, target_id=target, secret_id=secret_id, days=7, actor="operator:test")
        assert (await store.list_for_target(conn, target, usable_only=True))[0]["ref"] == ref
    run(scenario)


def test_malformed_unknown_and_hostile_references_are_refused_without_a_value():
    async def scenario(conn):
        target = await _target(conn)
        hunt, action = await _hunt(conn, target)
        for reference in ("secret://not-a-uuid", "withheld://hunt/x/1", "", "secret://" + str(uuid4()).upper()):
            with pytest.raises(store.DiscoveredSecretError) as refused:
                await store.resolve_for_hunt(
                    conn, reference=reference, target_id=target, hunt_run_id=hunt, action_id=action)
            assert refused.value.reason == store.SECRET_REFERENCE_INVALID
        with pytest.raises(store.DiscoveredSecretError) as unknown:
            await store.resolve_for_hunt(
                conn, reference=f"secret://{uuid4()}", target_id=target, hunt_run_id=hunt, action_id=action)
        assert unknown.value.reason == store.SECRET_UNAVAILABLE
        # Values the store does not keep: empty and over the limit; a device id with no targets row.
        assert await store.record_discovered(
            conn, target_id=target, values=[("", ""), ("x" * (store.MAX_VALUE_CHARS + 1), "")],
            source={"kind": "hunt_action"}) == {"stored": 0, "refreshed": 0}
        assert await store.record_discovered(
            conn, target_id=uuid4(), values=[(SYNTHETIC, "")], source={"kind": "hunt_action"}) == {
                "stored": 0, "refreshed": 0}
        # A multi-byte value with separators round-trips exactly.
        hostile = "pä$$;\nwörd\t\"'`secret://" + str(uuid4())
        await store.record_discovered(conn, target_id=target, values=[(hostile, "")], source={"kind": "hunt_action"})
        ref = (await store.list_for_target(conn, target))[0]["ref"]
        assert await store.resolve_for_hunt(
            conn, reference=ref, target_id=target, hunt_run_id=hunt, action_id=action) == hostile
    run(scenario)


def test_a_failure_inside_the_store_never_undoes_the_callers_transaction():
    async def scenario(conn):
        target = await _target(conn)
        async with conn.transaction():
            await conn.execute("UPDATE targets SET url=url WHERE id=$1", target)
            result = await store.record_discovered(
                conn, target_id=target, values=[(SYNTHETIC, "")],
                source={"kind": "not-a-source-kind"})
            assert result == {"stored": 0, "refreshed": 0}
            # The caller's transaction is still usable.
            assert await conn.fetchval("SELECT 1 FROM targets WHERE id=$1", target) == 1
    run(scenario)


def test_without_a_stable_key_nothing_is_stored(monkeypatch):
    import secret_store
    monkeypatch.setattr(secret_store, "derived_installation_key", lambda purpose: None)

    async def scenario(conn):
        target = await _target(conn)
        assert await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC, "")], source={"kind": "hunt_action"}) == {
                "stored": 0, "refreshed": 0}
        assert await conn.fetchval("SELECT count(*) FROM discovered_secrets WHERE target_id=$1", target) == 0
    run(scenario)


def test_sealing_a_hunt_actions_withheld_values_keeps_them_for_the_target():
    from runtime.hunt_http_exchange import persist_withheld_values
    from runtime.models import TargetBinding

    async def scenario(conn):
        target = await _target(conn)
        hunt, action = await _hunt(conn, target)
        binding = TargetBinding(target_id=str(target), target_kind="web",
                                canonical_host="app.example.invalid")
        run_row = {"id": str(hunt), "status": "active", "completed_at": None}
        async with conn.transaction():
            result = await persist_withheld_values(
                conn, run=run_row, action_id=action, target=binding,
                values={1: SYNTHETIC, 2: SYNTHETIC_JWT}, status="success")
        assert result["status"] == "sealed" and result["discovered_secrets"] == {"stored": 2, "refreshed": 0}
        listed = await store.list_for_target(conn, target)
        assert len(listed) == 2 and {item["source"]["id"] for item in listed} == {str(action)}
        assert all(item["source"]["hunt_id"] == str(hunt) for item in listed)
    run(scenario)


def test_a_value_sent_by_reference_is_withheld_from_the_hunts_later_echoes():
    from runtime.hunt_http_exchange import sealed_hunt_knowledge
    from runtime.models import TargetBinding

    async def scenario(conn):
        target = await _target(conn)
        await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC, "")], source={"kind": "hunt_action"})
        ref = (await store.list_for_target(conn, target))[0]["ref"]
        hunt, action = await _hunt(conn, target)
        binding = TargetBinding(target_id=str(target), target_kind="web", canonical_host="app.example.invalid")
        before = await sealed_hunt_knowledge(conn, run_id=hunt, target=binding)
        assert SYNTHETIC not in before["values"]
        await store.resolve_for_hunt(conn, reference=ref, target_id=target, hunt_run_id=hunt, action_id=action)
        after = await sealed_hunt_knowledge(conn, run_id=hunt, target=binding)
        assert after["values"][0] == SYNTHETIC  # seeded first: every later echo is withheld
        other_hunt, _ = await _hunt(conn, target)
        assert SYNTHETIC not in (await sealed_hunt_knowledge(conn, run_id=other_hunt, target=binding))["values"]
    run(scenario)


def test_an_operators_expiry_is_not_extended_by_sightings_and_expired_rows_are_swept():
    async def scenario(conn):
        target = await _target(conn)
        await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC, "")], source={"kind": "hunt_action"})
        ref = (await store.list_for_target(conn, target))[0]["ref"]
        secret_id = ref.removeprefix("secret://")
        assert await store.set_expiry(conn, target_id=target, secret_id=secret_id, days=1, actor="operator:test")
        before = (await store.list_for_target(conn, target))[0]["expires_at"]
        await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC, "")], source={"kind": "retest"})
        assert (await store.list_for_target(conn, target))[0]["expires_at"] == before
        await conn.execute(
            "UPDATE discovered_secrets SET expires_at=NOW() - interval '1 second' WHERE id=$1::uuid", secret_id)
        assert (await store.expire_due(conn))["expired"] >= 1
        await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC, "")], source={"kind": "retest"})
        assert (await store.list_for_target(conn, target))[0]["state"] == "expired"  # operator's call stands
        await conn.execute(
            """UPDATE discovered_secrets SET expires_at=NOW() - make_interval(days => $2),
                state_changed_at=NOW() - make_interval(days => $2) WHERE id=$1::uuid""",
            secret_id, store.RETAIN_AFTER_EXPIRY_DAYS + 1)
        assert (await store.expire_due(conn))["deleted"] >= 1
        assert await store.list_for_target(conn, target) == []
    run(scenario)


def test_deleting_a_hunt_erases_what_it_found_and_keeps_other_hunts_use_records():
    from data_lifecycle import records

    async def scenario(conn):
        target = await _target(conn)
        finder, finder_action = await _hunt(conn, target)
        user, user_action = await _hunt(conn, target)
        await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC, "")],
            source={"kind": "hunt_action", "id": str(finder_action), "hunt_id": str(finder)})
        await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC_JWT, "")], source={"kind": "scan_finding", "id": "s"})
        jwt_ref = next(i["ref"] for i in await store.list_for_target(conn, target) if i["kind"] == "jwt")
        await store.resolve_for_hunt(conn, reference=jwt_ref, target_id=target, hunt_run_id=user, action_id=user_action)
        columns = {"discovered_secrets": {"source"}}
        predicate = records.owned("hunt", columns)["discovered_secrets"]
        await conn.execute(f"DELETE FROM discovered_secrets r WHERE {predicate}", [finder])
        kinds = {i["kind"] for i in await store.list_for_target(conn, target)}
        assert kinds == {"jwt"}  # the finder's secret is gone, the other stays
        await conn.execute("DELETE FROM hunt_runs WHERE id=$1", user)
        uses = await conn.fetch(
            "SELECT hunt_run_id FROM discovered_secret_uses WHERE secret_id=$1::uuid",
            jwt_ref.removeprefix("secret://"))
        assert uses and all(row["hunt_run_id"] is None for row in uses)  # the use record survives
    run(scenario)


def test_a_target_keeps_at_most_its_cap(monkeypatch):
    monkeypatch.setattr(store, "MAX_PER_TARGET", 3)

    async def scenario(conn):
        target = await _target(conn)
        await store.record_discovered(
            conn, target_id=target, values=[(f"synthetic-value-{i:03d}", "") for i in range(5)],
            source={"kind": "hunt_action"})
        assert await conn.fetchval("SELECT count(*) FROM discovered_secrets WHERE target_id=$1", target) == 3
    run(scenario)


def test_a_scan_findings_secret_is_kept_and_replaced_by_its_reference():
    from scan.finding_secrets import scrub_findings
    aws = "AKIA" + "Q7XK2M4N9P3R8T5W"

    async def scenario(conn):
        target = await _target(conn)
        findings = [{"title": "Exposed config", "evidence": {"match_snippet": f"key {aws} here"}}]
        counts = await scrub_findings(conn, target_id=target, scan_id=uuid4(), findings=findings)
        assert counts == {"found": 1, "kept": 1}
        listed = await store.list_for_target(conn, target)
        assert listed[0]["source"]["kind"] == "scan_finding"
        assert findings[0]["evidence"]["match_snippet"] == f"key [{listed[0]['ref']}] here"
    run(scenario)


def test_a_grant_lets_another_targets_hunt_use_a_secret_and_revoking_stops_it():
    async def scenario(conn):
        owner, other, third = await _target(conn), await _target(conn), await _target(conn)
        await store.record_discovered(conn, target_id=owner, values=[(SYNTHETIC, "password")],
                                      source={"kind": "hunt_action"})
        ref = (await store.list_for_target(conn, owner))[0]["ref"]
        secret_id = ref.removeprefix("secret://")
        hunt, action = await _hunt(conn, other)
        with pytest.raises(store.DiscoveredSecretError):
            await store.resolve_for_hunt(conn, reference=ref, target_id=other, hunt_run_id=hunt, action_id=action)
        assert await store.grant(conn, target_id=owner, secret_id=secret_id, to_target_id=other,
                                 actor="operator:test")
        assert await store.resolve_for_hunt(
            conn, reference=ref, target_id=other, hunt_run_id=hunt, action_id=action) == SYNTHETIC
        listed = await store.list_for_target(conn, other, usable_only=True)
        assert [item["ref"] for item in listed] == [ref] and listed[0]["found_on"] == str(owner)
        assert (await store.briefing_counts(conn, other))["usable"] == 1
        # Only the owning target grants; a third target stays refused.
        assert not await store.grant(conn, target_id=other, secret_id=secret_id, to_target_id=third,
                                     actor="operator:test")
        third_hunt, third_action = await _hunt(conn, third)
        with pytest.raises(store.DiscoveredSecretError):
            await store.resolve_for_hunt(conn, reference=ref, target_id=third, hunt_run_id=third_hunt,
                                         action_id=third_action)
        with pytest.raises(ValueError):
            await store.grant(conn, target_id=owner, secret_id=secret_id, to_target_id=owner, actor="o")
        assert await store.revoke_grant(conn, target_id=owner, secret_id=secret_id, to_target_id=other)
        with pytest.raises(store.DiscoveredSecretError):
            await store.resolve_for_hunt(conn, reference=ref, target_id=other, hunt_run_id=hunt, action_id=action)
        assert (await store.briefing_counts(conn, other))["usable"] == 0
    run(scenario)


def test_the_briefing_counts_usable_and_never_used_secrets_by_kind():
    async def scenario(conn):
        target = await _target(conn)
        await store.record_discovered(conn, target_id=target, values=[(SYNTHETIC, "password"),
                                      (SYNTHETIC_JWT, "")], source={"kind": "hunt_action"})
        hunt, action = await _hunt(conn, target)
        jwt = next(i["ref"] for i in await store.list_for_target(conn, target) if i["kind"] == "jwt")
        await store.resolve_for_hunt(conn, reference=jwt, target_id=target, hunt_run_id=hunt, action_id=action)
        counts = await store.briefing_counts(conn, target)
        assert counts["usable"] == 2 and counts["never_used"] == 1
        assert counts["by_kind"] == {"jwt": 1, "password": 1} and SYNTHETIC not in str(counts)
    run(scenario)


def test_promote_moves_the_value_into_a_profile_and_reveal_is_recorded(monkeypatch):
    import httpx
    from fastapi import FastAPI
    from targets import discovered_secret_routes as routes

    async def scenario(conn):
        target = await _target(conn)
        await store.record_discovered(conn, target_id=target, values=[(SYNTHETIC, "API_TOKEN")],
                                      source={"kind": "hunt_action"})
        ref = (await store.list_for_target(conn, target))[0]["ref"]
        secret_id = ref.removeprefix("secret://")
        async with asyncpg.create_pool(DSN, min_size=1, max_size=2) as pool:
            monkeypatch.setattr(routes, "pool", lambda: pool)
            app = FastAPI()
            app.include_router(routes.router)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as http:
                shown = await http.post(f"/targets/{target}/discovered-secrets/{secret_id}/reveal")
                assert shown.status_code == 200 and shown.json() == {"value": SYNTHETIC}
                assert shown.headers["cache-control"] == "no-store"
                bad = await http.post(f"/targets/{target}/discovered-secrets/{secret_id}/promote",
                                      json={"name": "x", "auth_kind": "not_a_kind"})
                assert bad.status_code in {400, 422} and SYNTHETIC not in bad.text
                assert (await store.list_for_target(conn, target))[0]["state"] == "active"
                promoted = await http.post(
                    f"/targets/{target}/discovered-secrets/{secret_id}/promote",
                    json={"name": "Found API token", "auth_kind": "bearer_token"})
                assert promoted.status_code == 201, promoted.text
                assert SYNTHETIC not in promoted.text
                profile = promoted.json()["profile"]
        listed = (await store.list_for_target(conn, target))[0]
        assert listed["state"] == "superseded" and listed["promoted_profile_id"] == str(profile["id"])
        assert listed["reveals"] >= 2 and listed["uses"] == 0  # reveal and promote, no Hunt use
        stored = await conn.fetchval("SELECT encrypted_secret FROM credential_profile_versions WHERE profile_id=$1::uuid",
                                     str(profile["id"]))
        assert stored and SYNTHETIC not in str(stored)
        hunt, action = await _hunt(conn, target)
        with pytest.raises(store.DiscoveredSecretError):  # superseded: use the profile now
            await store.resolve_for_hunt(conn, reference=ref, target_id=target, hunt_run_id=hunt, action_id=action)
    run(scenario)


def test_review_fixes_planner_view_promote_once_and_grant_to_an_active_target(monkeypatch):
    import httpx
    from fastapi import FastAPI
    from targets import discovered_secret_routes as routes

    async def scenario(conn):
        owner, other, archived = await _target(conn), await _target(conn), await _target(conn)
        await conn.execute("UPDATE targets SET is_active=false WHERE id=$1", archived)
        await store.record_discovered(conn, target_id=owner, values=[(SYNTHETIC, "API_TOKEN")],
                                      source={"kind": "hunt_action", "hunt_id": str(uuid4())})
        ref = (await store.list_for_target(conn, owner))[0]["ref"]
        secret_id = ref.removeprefix("secret://")
        with pytest.raises(LookupError):
            await store.grant(conn, target_id=owner, secret_id=secret_id, to_target_id=archived, actor="o")
        assert await store.grant(conn, target_id=owner, secret_id=secret_id, to_target_id=other, actor="o")
        # A Hunt of the granted target sees how to use it, nothing about other targets or Hunts.
        row = (await store.list_for_target(conn, other))[0]
        view = store.planner_view(row, other)
        assert view["granted"] is True and view["ref"] == ref
        assert not {"granted_to", "found_on", "source", "promoted_profile_id", "reveals"} & set(view)
        async with asyncpg.create_pool(DSN, min_size=1, max_size=2) as pool:
            monkeypatch.setattr(routes, "pool", lambda: pool)
            app = FastAPI()
            app.include_router(routes.router)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as http:
                body = {"name": "Found token", "auth_kind": "bearer_token"}
                first = await http.post(f"/targets/{owner}/discovered-secrets/{secret_id}/promote", json=body)
                assert first.status_code == 201, first.text
                again = await http.post(f"/targets/{owner}/discovered-secrets/{secret_id}/promote",
                                        json={**body, "name": "Again"})
                assert again.status_code == 409 and SYNTHETIC not in again.text
                regrant = await http.post(f"/targets/{owner}/discovered-secrets/{secret_id}/grants",
                                          json={"target_id": str(archived)})
                assert regrant.status_code in {400, 404}
        profiles = await conn.fetchval("SELECT count(*) FROM credential_profiles WHERE target_id=$1", owner)
        assert profiles == 1
    run(scenario)


def test_a_hunts_record_lists_each_reference_it_sent_and_never_a_reveal_or_value():
    async def scenario(conn):
        target = await _target(conn)
        await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC, "DB_PASSWORD")],
            source={"kind": "scan_finding", "id": str(uuid4())})
        ref = (await store.list_for_target(conn, target))[0]["ref"]
        hunt, action = await _hunt(conn, target)
        other_hunt, other_action = await _hunt(conn, target)
        await store.resolve_for_hunt(conn, reference=ref, target_id=target, hunt_run_id=hunt,
                                     action_id=action, destination_host="app.example.invalid")
        await store.resolve_for_hunt(conn, reference=ref, target_id=target, hunt_run_id=other_hunt,
                                     action_id=other_action, destination_host="other.example.invalid")
        await store.value_for_operator(conn, target_id=target, secret_id=ref.removeprefix("secret://"),
                                       actor="operator:test", purpose="reveal")
        uses = await store.read_hunt_uses(conn, hunt)
        assert [(use["ref"], use["kind"], use["label"], use["action_id"], use["destination_host"])
                for use in uses] == [(ref, "password", "DB_PASSWORD", str(action), "app.example.invalid")]
        assert uses[0]["found_on"] == str(target) and uses[0]["secret_values_visible"] is False
        assert SYNTHETIC not in str(uses)
    run(scenario)
