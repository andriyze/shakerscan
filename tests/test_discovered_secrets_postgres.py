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
        assert await store.expire_due(conn) == 1
        assert await store.list_for_target(conn, target, usable_only=True) == []
        # Seen again after expiry: active again, with a fresh expiry.
        await store.record_discovered(
            conn, target_id=target, values=[(SYNTHETIC, "")], source={"kind": "retest", "id": "r2"})
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
