"""Public Suffix List boundaries on real PostgreSQL: discovery admission, legacy roots, Targets
list grouping and domain deletion never span registrants (run by the target-assets job)."""
import asyncio

from operations import discovery
from scope.roots import recompute_spanning_target_roots
from targets.asset_migration import migrate_target_assets
from targets.asset_inputs_migration import migrate_asset_inputs
from targets.asset_store import list_assets
from tests.test_target_asset_migration_postgres import database
from tests.test_target_asset_inputs_postgres import prepare, encryption

RECEIPT_SQL = """INSERT INTO scope_receipts (id, target_id, input_scope, normalized_scope, verdict,
    blocked_by, warnings, checks, environment, allowed_hosts, allowed_root_domains, redirect_destinations)
    VALUES ($1, $2, '{}', '{}', 'allowed', '[]', '[]', '[]', 'production', '[]', $3::jsonb, '[]')"""


async def _converted(conn):
    await prepare(conn)
    async with conn.transaction():
        await migrate_target_assets(conn)
        await migrate_asset_inputs(conn)


def test_discovery_counts_only_targets_a_person_added(monkeypatch):
    encryption(monkeypatch)
    monkeypatch.setenv(discovery.MAX_ACTIVE_ENV, "20")

    async def run():
        async with database() as conn:
            await _converted(conn)
            mine = await conn.fetchval(
                "INSERT INTO targets(url, name) VALUES ('https://app.mine.test', 'mine') RETURNING id")
            await conn.execute("INSERT INTO targets(url, name) VALUES ('https://app.example.co.uk', 'app')")
            await conn.execute(
                "INSERT INTO targets(url, name, discovery_source) VALUES ('https://x.other.test', 'x', 'subfinder')")
            await conn.execute(
                "INSERT INTO targets(url, name, discovery_source) VALUES ('https://chat.ai.test', 'c', 'ai_session')")
            # A scan submission's own target (2.8.2 marks it) is not a declaration.
            await conn.execute(
                "INSERT INTO targets(url, name, discovery_source) VALUES ('https://shop.scanned.test', 's', 'scan')")
            # An archived discovered row: the host row the asset model made for it stays active,
            # but it is not a person's declaration.
            await conn.execute("""INSERT INTO targets(url, name, discovery_source, is_active)
                VALUES ('https://old.archived.test', 'o', 'subfinder', false)""")
            # A host a person added on its own counts; one a Hunt agent created does not.
            await conn.execute("""INSERT INTO targets(url, name, discovery_source)
                VALUES ('host://db.hostonly.test', 'db', 'host')""")
            await conn.execute("""INSERT INTO targets(url, name, discovery_source, metadata_json)
                VALUES ('host://db.agent.test', 'db', 'host', '{"created_via": "hunt"}')""")
            # A receipt bound to a declared target cannot name an unrelated root.
            await conn.execute(RECEIPT_SQL, "unrelated", mine, '["victim.com"]')
            await conn.execute(RECEIPT_SQL, "unbound", None, '["scoped.test"]')
            first = await discovery.admit_discovery(conn, "example.co.uk", requested_by=discovery.requester())
            outcomes = {}
            for name in ("dev.example.co.uk", "other.test", "unknown.test", "ai.test", "scanned.test",
                         "archived.test", "hostonly.test", "agent.test", "victim.com", "scoped.test",
                         "mine.test"):
                try:
                    await discovery.admit_discovery(conn, name, requested_by=discovery.requester())
                    outcomes[name] = 200
                except discovery.DiscoveryRefused as exc:
                    outcomes[name] = exc.status_code
            run_row = dict(await conn.fetchrow("SELECT * FROM discovery_runs WHERE id=$1", first))
            # A run older than ACTIVE_WINDOW no longer holds its apex.
            await conn.execute(
                "UPDATE discovery_runs SET created_at = NOW() - interval '3 hours' WHERE id = $1", first)
            again = await discovery.admit_discovery(conn, "example.co.uk", requested_by=discovery.requester())
            return outcomes, run_row, first, again

    outcomes, run_row, first, again = asyncio.run(run())
    assert outcomes == {
        "dev.example.co.uk": 409, "other.test": 403, "unknown.test": 403, "ai.test": 403,
        "scanned.test": 403, "archived.test": 403, "hostonly.test": 200, "agent.test": 403,
        "victim.com": 403, "scoped.test": 403, "mine.test": 200,
    }
    assert run_row["requested_by"] == "local-operator" and run_row["root_domain"] == "example.co.uk"
    assert again != first


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
