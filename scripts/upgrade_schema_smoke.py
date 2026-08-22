#!/usr/bin/env python3
"""Run current migrations and assert clean/dirty published-schema invariants."""

from __future__ import annotations

import argparse
import asyncio
import json
import os

import asyncpg

from retest_contract import run_schema_migrations


SURVIVOR_ID = "11111111-1111-4111-8111-111111111111"
SURVIVOR_CANONICAL_KEY = "web:upgrade.example.test"
SCAN_ID = "33333333-3333-4333-8333-333333333333"
FINDING_ID = "44444444-4444-4444-8444-444444444444"


async def _assert_common(conn) -> None:
    index_name = await conn.fetchval("SELECT to_regclass('public.idx_targets_canonical_key')::text")
    if index_name != "idx_targets_canonical_key":
        raise RuntimeError("idx_targets_canonical_key is missing after migration")
    trigger_count = await conn.fetchval(
        """
        SELECT COUNT(*)
        FROM pg_trigger
        WHERE tgname = 'trg_targets_canonical_key' AND NOT tgisinternal
        """
    )
    if trigger_count != 1:
        raise RuntimeError("canonical target trigger is missing or duplicated")
    if not await conn.fetchval("SELECT to_regclass('public.app_schema_migrations') IS NOT NULL"):
        raise RuntimeError("app_schema_migrations is missing after migration")
    if not await conn.fetchval("SELECT to_regclass('public.budget_reservations') IS NOT NULL"):
        raise RuntimeError("budget_reservations is missing after migration")
    if not await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM app_schema_migrations "
        "WHERE name='v2_budget_reservations_v2')"
    ):
        raise RuntimeError("V2 budget reservation migration marker is missing")
    if not await conn.fetchval("SELECT to_regclass('public.model_intake_submission_events') IS NOT NULL"):
        raise RuntimeError("model_intake_submission_events is missing after migration")

    submission_state_constraint = await conn.fetchval(
        """
        SELECT pg_get_constraintdef(oid)
        FROM pg_constraint
        WHERE conname = 'model_intake_submission_state_check'
          AND conrelid = 'model_intake_submissions'::regclass
        """
    )
    if not submission_state_constraint or "policy_decided" not in submission_state_constraint:
        raise RuntimeError("model intake submission state constraint is missing or incomplete")

    deployment_binding_fk = await conn.fetchval(
        """
        SELECT pg_get_constraintdef(oid)
        FROM pg_constraint
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
            SELECT column_name
            FROM information_schema.columns
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
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'nodes'
              AND column_name = 'desired_state_changed_at'
              AND is_nullable = 'NO'
        )
        """
    )
    if not desired_state_changed_at:
        raise RuntimeError("fleet desired-state timestamp migration is missing")


async def _assert_dirty_merge(conn) -> None:
    rows = await conn.fetch(
        "SELECT id::text, canonical_key FROM targets WHERE canonical_key = $1",
        SURVIVOR_CANONICAL_KEY,
    )
    if [dict(row) for row in rows] != [
        {"id": SURVIVOR_ID, "canonical_key": SURVIVOR_CANONICAL_KEY}
    ]:
        raise RuntimeError(f"canonical duplicate merge produced unexpected targets: {rows!r}")

    scan_target = await conn.fetchval("SELECT target_id::text FROM scans WHERE id = $1::uuid", SCAN_ID)
    finding_target = await conn.fetchval(
        "SELECT target_id::text FROM findings WHERE id = $1::uuid", FINDING_ID
    )
    if scan_target != SURVIVOR_ID or finding_target != SURVIVOR_ID:
        raise RuntimeError(
            "duplicate merge did not preserve scan/finding ownership: "
            f"scan={scan_target}, finding={finding_target}"
        )

    legacy_token = await conn.fetchrow(
        """
        SELECT token_id::text, transport, max_uses, use_count, consumed_at IS NOT NULL AS consumed
        FROM node_join_tokens
        WHERE token_hash = 'upgrade-consumed-token'
        """
    )
    if not legacy_token or not legacy_token["token_id"] or legacy_token["transport"] is not None:
        raise RuntimeError(f"legacy fleet join token was not upgraded safely: {legacy_token!r}")
    if legacy_token["max_uses"] != 1 or legacy_token["use_count"] != 1 or not legacy_token["consumed"]:
        raise RuntimeError(f"consumed legacy fleet token was reactivated: {legacy_token!r}")


async def _run(database_url: str, scenario: str) -> None:
    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=2)
    try:
        await run_schema_migrations(pool)
        # Both API and workers run migrations. A second pass must be harmless.
        await run_schema_migrations(pool)
        async with pool.acquire() as conn:
            await _assert_common(conn)
            if scenario == "dirty":
                await _assert_dirty_merge(conn)
    finally:
        await pool.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))
    parser.add_argument("--scenario", choices=("clean", "dirty"), required=True)
    args = parser.parse_args()
    if not args.database_url:
        parser.error("--database-url or DATABASE_URL is required")

    asyncio.run(_run(args.database_url, args.scenario))
    print(json.dumps({"status": "passed", "scenario": args.scenario}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
