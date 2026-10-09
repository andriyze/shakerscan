"""Public Suffix List boundaries on real PostgreSQL: legacy roots, Targets list grouping and
domain deletion never span registrants (run by the target-assets job)."""
import asyncio

from scope.roots import recompute_spanning_target_roots
from targets.asset_migration import migrate_target_assets
from targets.asset_inputs_migration import migrate_asset_inputs
from targets.asset_store import list_assets
from tests.test_target_asset_migration_postgres import database
from tests.test_target_asset_inputs_postgres import prepare, encryption

async def _converted(conn):
    await prepare(conn)
    async with conn.transaction():
        await migrate_target_assets(conn)
        await migrate_asset_inputs(conn)


def test_legacy_public_suffix_roots_are_recomputed_once(monkeypatch):
    encryption(monkeypatch)

    async def run():
        async with database() as conn:
            await conn.execute("""INSERT INTO targets(url, name, root_domain, is_root) VALUES
                ('https://shop.example.co.uk', 'shop', 'co.uk', false),
                ('https://example.co.uk', 'apex', 'co.uk', false),
                ('https://victim.github.io', 'pages', 'github.io', false),
                ('https://bucket.s3.amazonaws.com', 'bucket', 'amazonaws.com', false),
                ('https://api.example.com', 'api', 'example.com', false)""")
            changed = await recompute_spanning_target_roots(conn)
            rows = {row["url"]: (row["root_domain"], row["is_root"]) for row in await conn.fetch(
                "SELECT url, root_domain, is_root FROM targets WHERE url LIKE 'https://%'")}
            return changed, rows, await recompute_spanning_target_roots(conn)

    changed, rows, again = asyncio.run(run())
    assert changed == 4 and again == 0
    assert rows == {
        "https://shop.example.co.uk": ("example.co.uk", False),
        "https://example.co.uk": ("example.co.uk", True),
        "https://victim.github.io": ("victim.github.io", True),
        "https://bucket.s3.amazonaws.com": ("bucket.s3.amazonaws.com", True),
        "https://api.example.com": ("example.com", False),
    }


def test_targets_list_groups_and_domain_deletion_never_span_registrants(monkeypatch):
    encryption(monkeypatch)
    from data_lifecycle.inventory import domain_roots

    async def run():
        async with database() as conn:
            await _converted(conn)
            ids = {}
            for host in ("victim.github.io", "api.victim.github.io", "attacker.github.io",
                         "shop.example.co.uk", "other.co.uk", "192.0.2.7", "github.io"):
                ids[host] = await conn.fetchval(
                    "INSERT INTO targets(url, name, root_domain) VALUES ($1, $2, $3) RETURNING id",
                    f"https://{host}", host, "github.io" if host.endswith("github.io") else "co.uk")
            listing = await list_assets(conn, group_by="domain", limit=50)
            groups = {group["root_domain"]: group for group in listing["groups"]}
            victim = set(await domain_roots(conn, "victim.github.io"))
            suffix = set(await domain_roots(conn, "github.io"))
            return ids, groups, listing, victim, suffix

    ids, groups, listing, victim, suffix = asyncio.run(run())
    assert set(groups) == {"victim.github.io", "attacker.github.io", "example.co.uk", "other.co.uk",
                           "192.0.2.7", "github.io"}
    assert listing["total_groups"] == 6
    assert {asset["locator"] for asset in groups["victim.github.io"]["targets"]} == {
        "victim.github.io", "api.victim.github.io"}
    assert {name: group["discoverable"] for name, group in groups.items()} == {
        "victim.github.io": True, "attacker.github.io": True, "example.co.uk": True,
        "other.co.uk": True, "192.0.2.7": False, "github.io": False}
    # The legacy stored root (github.io, co.uk) never pulls other registrants into a deletion.
    assert ids["attacker.github.io"] not in victim and ids["victim.github.io"] in victim
    assert ids["api.victim.github.io"] in victim
    assert ids["github.io"] in suffix
    assert not {ids["victim.github.io"], ids["attacker.github.io"]} & suffix
