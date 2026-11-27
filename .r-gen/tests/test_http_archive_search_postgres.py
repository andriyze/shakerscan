"""An archive search finds a call by its path, read back from PostgreSQL, and never by a value the
masked archive withholds.

Rows are fixture calls (identified as such: no target is contacted) persisted with the real
production writer ``archive_http_transactions`` into the installed schema, then counted and read
with the real reader. A row archived before ``search_url`` existed (inserted without it) still
matches on its capability.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
import json
import uuid

from runtime import http_archive
from runtime.http_archive import HttpTransaction, _default_store, archive_http_transactions
from runtime.http_archive_reader import count_transactions, read_transactions

from tests.test_scan_local_revocation_postgres import (  # noqa: F401  (template_database is a fixture)
    scan_database,
    template_database,
)


async def _scan_id(conn, url: str) -> str:
    target_id = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", url)
    scan_id = uuid.uuid4()
    await conn.execute(
        """INSERT INTO scans (id,target_id,target_url,status,scan_generation,budget_json,budget_used_json)
           VALUES ($1,$2,$3,'running','canonical',$4::jsonb,'{}'::jsonb)""",
        scan_id, target_id, url, json.dumps({}),
    )
    return str(scan_id)


def test_archive_search_matches_paths_and_not_withheld_values(template_database, tmp_path):  # noqa: F811
    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                scan_id = await _scan_id(conn, "http://search.test")
                calls = [
                    ("http://search.test/hub/login?next=%2F", "web.crawl"),
                    ("http://search.test/api/items?api_key=s3cretvalue", "http.request"),
                    ("http://admin:pa55word@search.test/HUB/settings", "http.request"),
                    ("http://search.test/100%_done", "http.request"),
                ]
                assert await archive_http_transactions(conn, [
                    HttpTransaction(plane="scan", method="GET", url=url, sequence=index,
                                    scan_id=scan_id, capability_name=capability)
                    for index, (url, capability) in enumerate(calls)
                ], store=_default_store(tmp_path), scan_id=scan_id) == len(calls)
                # A call archived before the column existed.
                await conn.execute(
                    """INSERT INTO http_transactions(plane,sequence,scan_id,capability_name,method,url)
                       VALUES ('scan',9,$1,'templates.scan','GET','http://search.test/hub/legacy')""",
                    uuid.UUID(scan_id),
                )

                async def urls(search):
                    total = await count_transactions(conn, scan_id=scan_id, hunt_run_id=None, search=search)
                    rows = await read_transactions(conn, scan_id=scan_id, hunt_run_id=None,
                                                   search=search, payloads=False)
                    assert total == len(rows)
                    return [row["url"] for row in rows]

                # Path matches are case-insensitive substrings.
                assert await urls("/hub/") == [calls[0][0], calls[2][0]]
                assert await urls("/hub/login") == [calls[0][0]]
                # Query values, userinfo passwords and usernames are not searchable.
                assert await urls("s3cret") == []
                assert await urls("api_key") == []
                assert await urls("pa55word") == []
                assert await urls("admin:") == []
                # LIKE wildcards in the search text are literal.
                assert await urls("100%_") == [calls[3][0]]
                assert await urls("1_0") == []
                # The pre-column row is still found by its capability, not by its path.
                assert await urls("templates.scan") == ["http://search.test/hub/legacy"]
                assert await urls("legacy") == []

    asyncio.run(run())


def test_a_worker_ahead_of_the_api_migration_still_archives(template_database, tmp_path, monkeypatch):  # noqa: F811
    """Workers wait only for PostgreSQL and Redis: on an upgrade one can archive before the API's
    startup step has added search_url. Its calls are stored (searchable by capability), not lost."""
    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                await conn.execute("ALTER TABLE http_transactions DROP COLUMN search_url")
                monkeypatch.setattr(http_archive, "_search_url_column_present", False)
                scan_id = await _scan_id(conn, "http://early.test")
                assert await archive_http_transactions(conn, [
                    HttpTransaction(plane="scan", method="GET", url="http://early.test/hub/login",
                                    sequence=1, scan_id=scan_id, capability_name="web.crawl"),
                ], store=_default_store(tmp_path), scan_id=scan_id) == 1
                assert http_archive._search_url_column_present is False
                # The API's startup step adds the column; the next batch names it.
                from runtime.http_archive_search import SEARCH_URL_SCHEMA_SQL
                await conn.execute(SEARCH_URL_SCHEMA_SQL)
                assert await archive_http_transactions(conn, [
                    HttpTransaction(plane="scan", method="GET", url="http://early.test/hub/next",
                                    sequence=2, scan_id=scan_id, capability_name="web.crawl"),
                ], store=_default_store(tmp_path), scan_id=scan_id) == 1
                rows = await conn.fetch(
                    "SELECT url, search_url FROM http_transactions WHERE scan_id=$1 ORDER BY sequence",
                    uuid.UUID(scan_id),
                )
                assert [(r["url"], r["search_url"]) for r in rows] == [
                    ("http://early.test/hub/login", None),
                    ("http://early.test/hub/next", "http://early.test/hub/next"),
                ]

    asyncio.run(run())
