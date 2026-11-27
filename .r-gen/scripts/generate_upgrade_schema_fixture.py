#!/usr/bin/env python3
"""Record the database a released engine leaves behind, for the schema-equivalence upgrade test.

For a git revision (a release tag, or a merge commit for an untagged release), this:

1. checks the revision out in a temporary git worktree;
2. creates an empty database, applies that revision's ``db/init.sql`` and runs that revision's own
   startup migrations (``retest_contract.run_schema_migrations``), which converts it to the
   unified target model, as an install of that release is;
3. dumps the result (schema and the few seeded rows) with ``pg_dump`` into
   ``tests/fixtures/upgrade_schemas/<name>.sql.gz``, without psql meta-commands, owners or grants.

``tests/test_schema_upgrade_equivalence_postgres.py`` restores each dump, runs the current
startup and requires the catalog to equal a fresh install's.

Usage (the DSN names a disposable local server; ``--pg-dump`` may be a command such as
``docker exec CONTAINER pg_dump`` so the dump matches the server's version)::

    scripts/generate_upgrade_schema_fixture.py --revision v2.8.1 --name v2.8.1 \\
        --dsn postgresql://postgres:secret@127.0.0.1:55490/postgres \\
        --pg-dump "docker exec ss-pg pg_dump -U postgres"
"""
from __future__ import annotations

import argparse
import gzip
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "tests" / "fixtures" / "upgrade_schemas"
STARTUP = """
import asyncio, sys
import asyncpg
async def main(dsn):
    conn = await asyncpg.connect(dsn)
    try:
        from targets.asset_migration import BoundConnectionPool
        import retest_contract
        await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
    finally:
        await conn.close()
asyncio.run(main(sys.argv[1]))
"""


def _database(dsn: str, name: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, "/" + name, parts.query, parts.fragment))


def strip_meta_commands(text: str) -> str:
    """Plain pg_dump output for a driver: no ``\\restrict``-style psql meta-commands."""
    return "".join(line for line in text.splitlines(keepends=True) if not line.startswith("\\"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--revision", required=True, help="release tag or commit to record")
    parser.add_argument("--name", required=True, help="fixture name, e.g. v2.8.1")
    parser.add_argument("--dsn", required=True, help="a disposable local PostgreSQL server (any database)")
    parser.add_argument("--pg-dump", default="pg_dump", help="pg_dump command, matching the server version")
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args(argv)
    if urlsplit(args.dsn).hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit("use a disposable local PostgreSQL server")
    name = "upgrade_fixture_" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory() as scratch:
        tree = Path(scratch) / "tree"
        subprocess.run(["git", "worktree", "add", "--detach", str(tree), args.revision], cwd=ROOT, check=True)
        try:
            import asyncio

            import asyncpg

            async def create() -> None:
                conn = await asyncpg.connect(args.dsn)
                try:
                    await conn.execute(f'CREATE DATABASE "{name}"')
                finally:
                    await conn.close()
                conn = await asyncpg.connect(_database(args.dsn, name))
                try:
                    await conn.execute((tree / "db" / "init.sql").read_text(encoding="utf-8"))
                finally:
                    await conn.close()

            async def drop() -> None:
                conn = await asyncpg.connect(args.dsn)
                try:
                    await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
                finally:
                    await conn.close()

            asyncio.run(create())
            try:
                env_path = f"{tree}:{tree / 'api'}:{tree / 'scanner'}"
                subprocess.run([args.python, "-c", STARTUP, _database(args.dsn, name)], check=True, cwd=tree,
                      env={"PYTHONPATH": env_path, "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"})
                dump = subprocess.run([*shlex.split(args.pg_dump), "--no-owner", "--no-privileges",
                                       "--inserts", "-d", name], check=True, capture_output=True, text=True).stdout
            finally:
                asyncio.run(drop())
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(tree)], cwd=ROOT, check=True)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    header = f"-- {args.name}: revision {args.revision}, its init.sql and its own startup (converted)\n"
    target = OUTPUT / f"{args.name}.sql.gz"
    with gzip.GzipFile(target, "wb", mtime=0) as handle:
        handle.write((header + strip_meta_commands(dump)).encode("utf-8"))
    print(f"wrote {target.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
