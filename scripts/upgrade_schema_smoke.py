#!/usr/bin/env python3
"""Run current migrations and assert clean/dirty published-schema invariants."""

from __future__ import annotations

import argparse
import asyncio
import json
import os



TARGET_ID = "11111111-1111-4111-8111-111111111111"
TARGET_CANONICAL_KEY = "web:upgrade.example.test"
COMPLETED_SCAN_ID = "33333333-3333-4333-8333-333333333333"
PENDING_SCAN_ID = "55555555-5555-4555-8555-555555555555"
FINDING_ID = "44444444-4444-4444-8444-444444444444"
AI_TARGET_ID = "66666666-6666-4666-8666-666666666666"
MODEL_INTAKE_ID = "77777777-7777-4777-8777-777777777777"
EVIDENCE_ID = "88888888-8888-4888-8888-888888888888"
FLEET_NODE_ID = "99999999-9999-4999-8999-999999999999"
FLEET_CREDENTIAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
LEGACY_CREDENTIAL_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
LEGACY_HUNT_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


async def _table_exists(conn, table: str) -> bool:
    return bool(await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", f"public.{table}"))


async def _assert_common(conn) -> None:
    index_name = await conn.fetchval("SELECT to_regclass('public.idx_targets_canonical_key')::text")
    if index_name != "idx_targets_canonical_key":
        raise RuntimeError("idx_targets_canonical_key is missing after migration")
    trigger_count = await conn.fetchval(
        """
        SELECT COUNT(*) FROM pg_trigger
        WHERE tgname = 'trg_targets_canonical_key' AND NOT tgisinternal
        """
    )
    if trigger_count != 1:
        raise RuntimeError("canonical target trigger is missing or duplicated")
    for table in (
        "app_schema_migrations",
        "budget_reservations",
        "credential_profiles",
        "request_collections",
        "hunt_runs",
        "model_intake_submission_events",
    ):
        if not await _table_exists(conn, table):
            raise RuntimeError(f"{table} is missing after migration")
    if not await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM app_schema_migrations "
        "WHERE name='v2_budget_reservations_v2')"
    ):
        raise RuntimeError("V2 budget reservation migration marker is missing")

    submission_state_constraint = await conn.fetchval(
        """
        SELECT pg_get_constraintdef(oid) FROM pg_constraint
        WHERE conname = 'model_intake_submission_state_check'
          AND conrelid = 'model_intake_submissions'::regclass
        """
    )
    if not submission_state_constraint or "policy_decided" not in submission_state_constraint:
        raise RuntimeError("model intake submission state constraint is missing or incomplete")

    deployment_binding_fk = await conn.fetchval(
        """
        SELECT pg_get_constraintdef(oid) FROM pg_constraint
        WHERE conname = 'model_intake_deployment_bindings_admission_id_fkey'
          AND conrelid = 'model_intake_deployment_bindings'::regclass
        """
    )
    if not deployment_binding_fk or "ON DELETE SET NULL" not in deployment_binding_fk:
        raise RuntimeError("model intake deployment binding admission FK is missing or inconsistent")

    join_token_columns = {
        row["column_name"]
        for row in await conn.fetch(
            """
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'node_join_tokens'
            """
        )
    }
    required_join_token_columns = {
        "token_id", "transport", "max_uses", "use_count", "last_used_at", "revoked_at",
    }
    missing = sorted(required_join_token_columns - join_token_columns)
    if missing:
        raise RuntimeError(f"reusable fleet join-token migration is incomplete: {missing}")

    desired_state_changed_at = await conn.fetchval(
        """
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'nodes'
              AND column_name = 'desired_state_changed_at' AND is_nullable = 'NO'
        )
        """
    )
    if not desired_state_changed_at:
        raise RuntimeError("fleet desired-state timestamp migration is missing")


async def _assert_stable_fixture(conn, *, upgraded: bool) -> None:
    target = await conn.fetchrow(
        "SELECT id::text, url, total_scans, active_findings_count, canonical_key "
        "FROM targets WHERE id=$1::uuid",
        TARGET_ID,
    )
    if not target or dict(target) != {
        "id": TARGET_ID,
        "url": "https://upgrade.example.test",
        "total_scans": 3,
        # Candidate startup repairs this denormalized badge from the one
        # authoritative active finding in the fixture. A restored pre-upgrade
        # database must retain the exact legacy value until candidate migrations
        # are run again.
        "active_findings_count": 1 if upgraded else 3,
        "canonical_key": TARGET_CANONICAL_KEY,
    }:
        raise RuntimeError(f"previous-stable target was not preserved: {target!r}")

    scans = await conn.fetch(
        "SELECT id::text, target_id::text, status, scan_type FROM scans "
        "WHERE id=ANY($1::uuid[]) ORDER BY id",
        [COMPLETED_SCAN_ID, PENDING_SCAN_ID],
    )
    if [dict(row) for row in scans] != [
        {
            "id": COMPLETED_SCAN_ID,
            "target_id": TARGET_ID,
            "status": "completed",
            "scan_type": "quick",
        },
        {
            "id": PENDING_SCAN_ID,
            "target_id": TARGET_ID,
            "status": "pending",
            "scan_type": "smart",
        },
    ]:
        raise RuntimeError(f"completed or pending Scan state was not preserved: {scans!r}")

    finding = await conn.fetchrow(
        "SELECT id::text, scan_id::text, target_id::text, fingerprint, severity "
        "FROM findings WHERE id=$1::uuid",
        FINDING_ID,
    )
    if not finding or dict(finding) != {
        "id": FINDING_ID,
        "scan_id": COMPLETED_SCAN_ID,
        "target_id": TARGET_ID,
        "fingerprint": "upgrade-smoke-finding",
        "severity": "medium",
    }:
        raise RuntimeError(f"previous-stable finding was not preserved: {finding!r}")

    evidence = await conn.fetchrow(
        "SELECT id::text, scan_id::text, finding_id::text, content_sha256, retention_class "
        "FROM evidence_objects WHERE id=$1::uuid",
        EVIDENCE_ID,
    )
    if not evidence or dict(evidence) != {
        "id": EVIDENCE_ID,
        "scan_id": COMPLETED_SCAN_ID,
        "finding_id": FINDING_ID,
        "content_sha256": "e" * 64,
        "retention_class": "audit",
    }:
        raise RuntimeError(f"previous-stable evidence was not preserved: {evidence!r}")

    ai_target = await conn.fetchrow(
        "SELECT id::text, name, endpoint_url, is_active FROM ai_targets WHERE id=$1::uuid",
        AI_TARGET_ID,
    )
    if not ai_target or dict(ai_target) != {
        "id": AI_TARGET_ID,
        "name": "Previous stable AI target",
        "endpoint_url": "https://upgrade-ai.example.test/query",
        "is_active": True,
    }:
        raise RuntimeError(f"previous-stable AI Gate target was not preserved: {ai_target!r}")

    submission = await conn.fetchrow(
        "SELECT id::text, scan_id::text, state, source_kind, source_reference_hash "
        "FROM model_intake_submissions WHERE id=$1::uuid",
        MODEL_INTAKE_ID,
    )
    if not submission or dict(submission) != {
        "id": MODEL_INTAKE_ID,
        "scan_id": COMPLETED_SCAN_ID,
        "state": "submitted",
        "source_kind": "https",
        "source_reference_hash": "a" * 64,
    }:
        raise RuntimeError(f"previous-stable Model Intake submission was not preserved: {submission!r}")

    legacy_credential = await conn.fetchrow(
        "SELECT id::text, target_id::text, name, auth_kind, secret_value, is_active "
        "FROM target_credential_profiles WHERE id=$1::uuid",
        LEGACY_CREDENTIAL_ID,
    )
    if (
        not legacy_credential
        or legacy_credential["target_id"] != TARGET_ID
        or legacy_credential["name"] != "previous-stable-primary"
        or legacy_credential["auth_kind"] != "authorization_header"
        or not str(legacy_credential["secret_value"] or "").startswith("enc:fernet:")
        or not legacy_credential["is_active"]
    ):
        raise RuntimeError(f"previous-stable credential was not preserved: {legacy_credential!r}")

    hunt = await conn.fetchrow(
        "SELECT id::text, target_id::text, objective, status, execution_mode "
        "FROM research_episodes WHERE id=$1::uuid",
        LEGACY_HUNT_ID,
    )
    if not hunt or dict(hunt) != {
        "id": LEGACY_HUNT_ID,
        "target_id": TARGET_ID,
        "objective": "Previous stable legacy Hunt awaiting its planner",
        "status": "awaiting_planner",
        "execution_mode": "gated",
    }:
        raise RuntimeError(f"previous-stable Hunt was not preserved: {hunt!r}")

    node = await conn.fetchrow(
        "SELECT id::text, name, status, desired_worker_count FROM nodes WHERE id=$1::uuid",
        FLEET_NODE_ID,
    )
    if not node or dict(node) != {
        "id": FLEET_NODE_ID,
        "name": "previous-stable-worker",
        "status": "draining",
        "desired_worker_count": 1,
    }:
        raise RuntimeError(f"previous-stable fleet node was not preserved: {node!r}")
    node_credential = await conn.fetchrow(
        "SELECT id::text, node_id::text, credential_hash, credential_version, revoked_at "
        "FROM node_credentials WHERE id=$1::uuid",
        FLEET_CREDENTIAL_ID,
    )
    if (
        not node_credential
        or node_credential["node_id"] != FLEET_NODE_ID
        or node_credential["credential_hash"] != "c" * 64
        or node_credential["credential_version"] != 1
        or node_credential["revoked_at"] is not None
    ):
        raise RuntimeError(f"previous-stable fleet credential was not preserved: {node_credential!r}")

    token = await conn.fetchrow(
        """
        SELECT token_id::text, transport, max_uses, use_count,
               consumed_at IS NOT NULL AS consumed, revoked_at
        FROM node_join_tokens WHERE token_hash='upgrade-consumed-token'
        """
    )
    if (
        not token
        or not token["token_id"]
        or token["transport"] != "broker"
        or token["max_uses"] != 1
        or token["use_count"] != 1
        or not token["consumed"]
        or token["revoked_at"] is not None
    ):
        raise RuntimeError(f"consumed fleet join token was not preserved: {token!r}")

    if upgraded:
        generic = await conn.fetchrow(
            "SELECT id::text, target_kind, target_id::text, name, auth_kind, "
            "principal_slot, is_active FROM credential_profiles WHERE id=$1::uuid",
            LEGACY_CREDENTIAL_ID,
        )
        if (
            not generic
            or generic["target_kind"] != "web"
            or generic["target_id"] != TARGET_ID
            or generic["name"] != "previous-stable-primary"
            or generic["auth_kind"] != "authorization_header"
            or generic["principal_slot"] != "primary"
            or not generic["is_active"]
        ):
            raise RuntimeError(f"legacy credential was not mirrored into V2: {generic!r}")


def rollback_expectations(baseline: dict, upgraded: dict) -> dict:
    """What a restored pre-upgrade backup must and must not carry, per schema object kind.

    The previous-stable inventory is whatever the baseline runtime actually created, so the
    candidate-only set is derived for each release instead of being hardcoded against one
    historical baseline: the pre-V2 list (budget_reservations, credential_profiles, ...) was
    right against 0.8.18 and wrong against every V2 baseline, which already owns those objects.
    """
    expectations: dict = {}
    for kind in ("tables", "migrations"):
        base = set(baseline.get(kind, []))
        upg = set(upgraded.get(kind, []))
        expectations[kind] = {
            "absent": sorted(upg - base),
            "present": sorted(base),
            "dropped_by_candidate": sorted(base - upg),
        }
    return expectations


async def schema_inventory(conn) -> dict:
    tables = [
        row["tablename"]
        for row in await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
        )
    ]
    migrations: list[str] = []
    if await _table_exists(conn, "app_schema_migrations"):
        migrations = [
            row["name"]
            for row in await conn.fetch("SELECT name FROM app_schema_migrations ORDER BY name")
        ]
    return {"tables": tables, "migrations": migrations}


async def _migration_applied(conn, name: str) -> bool:
    if not await _table_exists(conn, "app_schema_migrations"):
        return False
    return bool(
        await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM app_schema_migrations WHERE name=$1)", name
        )
    )


async def _assert_rollback(conn, expectations: dict) -> None:
    probes = {"tables": _table_exists, "migrations": _migration_applied}
    for kind, exists in probes.items():
        label = kind[:-1]
        for name in expectations[kind]["absent"]:
            if await exists(conn, name):
                raise RuntimeError(f"rollback retained candidate-only {label} {name}")
        for name in expectations[kind]["present"]:
            if not await exists(conn, name):
                raise RuntimeError(f"rollback lost previous-stable {label} {name}")
    await _assert_stable_fixture(conn, upgraded=False)


def _load_inventory(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        inventory = json.load(handle)
    if not isinstance(inventory, dict) or not isinstance(inventory.get("tables"), list):
        raise RuntimeError(f"{path} is not a schema inventory")
    return inventory


async def _write_inventory(conn, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(await schema_inventory(conn), handle, indent=2, sort_keys=True)


async def _run(
    database_url: str,
    scenario: str,
    *,
    inventory_out: str | None = None,
    baseline_inventory: str | None = None,
    upgraded_inventory: str | None = None,
) -> None:
    import asyncpg

    from retest_contract import run_schema_migrations

    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=2)
    try:
        if scenario == "inventory":
            # Read-only: the pre-upgrade baseline schema, taken before any candidate migration.
            async with pool.acquire() as conn:
                await _write_inventory(conn, inventory_out)
            return
        if scenario == "rollback":
            expectations = rollback_expectations(
                _load_inventory(baseline_inventory), _load_inventory(upgraded_inventory)
            )
            print(
                json.dumps(
                    {
                        "scenario": "rollback",
                        "candidate_only": {
                            kind: expectations[kind]["absent"] for kind in expectations
                        },
                        "dropped_by_candidate": {
                            kind: expectations[kind]["dropped_by_candidate"]
                            for kind in expectations
                        },
                    },
                    sort_keys=True,
                )
            )
            async with pool.acquire() as conn:
                await _assert_rollback(conn, expectations)
            return
        if scenario != "verify_dirty":
            await run_schema_migrations(pool)
            # Both API and workers run migrations. A second pass must be harmless.
            await run_schema_migrations(pool)
        async with pool.acquire() as conn:
            await _assert_common(conn)
            if scenario in {"dirty", "verify_dirty"}:
                await _assert_stable_fixture(conn, upgraded=True)
            if inventory_out:
                await _write_inventory(conn, inventory_out)
    finally:
        await pool.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))
    parser.add_argument(
        "--scenario",
        choices=("clean", "dirty", "verify_dirty", "inventory", "rollback"),
        required=True,
    )
    parser.add_argument("--inventory-out", help="write the schema inventory JSON here")
    parser.add_argument("--baseline-inventory", help="pre-upgrade inventory (rollback)")
    parser.add_argument("--upgraded-inventory", help="post-candidate inventory (rollback)")
    args = parser.parse_args()
    if not args.database_url:
        parser.error("--database-url or DATABASE_URL is required")
    if args.scenario == "inventory" and not args.inventory_out:
        parser.error("--scenario inventory requires --inventory-out")
    if args.scenario == "rollback" and not (args.baseline_inventory and args.upgraded_inventory):
        parser.error("--scenario rollback requires --baseline-inventory and --upgraded-inventory")

    asyncio.run(
        _run(
            args.database_url,
            args.scenario,
            inventory_out=args.inventory_out,
            baseline_inventory=args.baseline_inventory,
            upgraded_inventory=args.upgraded_inventory,
        )
    )
    print(json.dumps({"status": "passed", "scenario": args.scenario}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
