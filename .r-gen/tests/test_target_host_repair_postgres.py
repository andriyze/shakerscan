"""R3 follow-up: targets whose stored host the one canonicalizer now refuses get a supported repair."""
import asyncio
import json

import pytest

from targets.asset_inputs_migration import migrate_asset_inputs
from targets.asset_migration import migrate_target_assets
from targets.host_canonical_repair import REPAIR_KEY, REVIEW_KEY, repair_target_host_spellings, unambiguous_ipv4
from tests.test_target_asset_inputs_postgres import encryption, prepare
from tests.test_target_asset_migration_postgres import database


@pytest.mark.parametrize("text, address", [
    ("127.1", "127.0.0.1"), ("2852039166", "169.254.169.254"), ("0x7f.0.0.1", "127.0.0.1"),
    ("01.02.03.04", "1.2.3.4"),  # octal and decimal readings agree
    ("010.000.000.001", None),   # octal 8.0.0.1 to a resolver, 10.0.0.1 to inet: ambiguous
    ("08.0.0.1", None), ("256.1.1.1", None), ("example.123", None),
])
def test_only_a_numeric_spelling_with_one_reading_is_repaired(text, address):
    assert unambiguous_ipv4(text) == address


def test_stored_hosts_the_canonicalizer_refuses_are_repaired_or_flagged_once(monkeypatch):
    encryption(monkeypatch)

    async def run():
        async with database() as conn:
            await prepare(conn)
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            ids = {}
            for url in ("https://127.1:8443/app", "https://2852039166/", "https://010.000.000.001/",
                        "https://xn--i-7iq.ws/", "https://app.example.com/"):
                ids[url] = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", url)
            async with conn.transaction():
                done = await repair_target_host_spellings(conn)
            rows = {row["id"]: row for row in await conn.fetch("SELECT id, url, metadata_json FROM targets")}

            def meta(url):
                value = rows[ids[url]]["metadata_json"] or {}
                return json.loads(value) if isinstance(value, str) else value

            assert rows[ids["https://127.1:8443/app"]]["url"].startswith("https://127.0.0.1:8443")
            assert meta("https://127.1:8443/app")[REPAIR_KEY]["from"] == "127.1"
            assert rows[ids["https://2852039166/"]]["url"].startswith("https://169.254.169.254")
            for flagged in ("https://010.000.000.001/", "https://xn--i-7iq.ws/"):
                assert rows[ids[flagged]]["url"].startswith(flagged.rstrip("/")), "left as stored"
                review = meta(flagged)[REVIEW_KEY]
                assert review["stored_host"] in flagged and "Create the target again" in review["action"]
            assert REVIEW_KEY not in meta("https://app.example.com/") and REPAIR_KEY not in meta("https://app.example.com/")
            # Each web address and its host asset: repaired together, or flagged together.
            hosts = {row["url"]: str(row["id"]) for row in rows.values() if row["url"].startswith("host://")}
            assert set(done["repaired"]) == {str(ids["https://127.1:8443/app"]), str(ids["https://2852039166/"]),
                                             hosts["host://127.0.0.1"], hosts["host://169.254.169.254"]}
            # The octal web address's asset was already stored by inet as host://10.0.0.1; only the
            # web address, whose text a resolver reads as 8.0.0.1, is flagged.
            assert set(done["flagged"]) == {str(ids["https://010.000.000.001/"]), str(ids["https://xn--i-7iq.ws/"]),
                                            hosts["host://xn--i-7iq.ws"]}
            owners = {row["id"]: row["asset_owner_id"] for row in await conn.fetch("SELECT id, asset_owner_id FROM targets")}
            assert str(owners[ids["https://127.1:8443/app"]]) == hosts["host://127.0.0.1"], "one asset, kept"
            async with conn.transaction():
                assert await repair_target_host_spellings(conn) == {"repaired": [], "flagged": []}, "runs once"
    asyncio.run(run())
