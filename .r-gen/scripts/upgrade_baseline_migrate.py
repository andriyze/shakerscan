#!/usr/bin/env python3
"""Run the installed previous-release schema migrator against one test database."""

from __future__ import annotations

import argparse
import asyncio

import asyncpg

from retest_contract import run_schema_migrations


async def _run(database_url: str) -> None:
    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=2)
    try:
        await run_schema_migrations(pool)
        await run_schema_migrations(pool)
    finally:
        await pool.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    args = parser.parse_args()
    asyncio.run(_run(args.database_url))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
