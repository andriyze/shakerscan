"""Public Suffix List boundaries on real PostgreSQL: discovery admission, legacy roots, Targets
list grouping and domain deletion never span registrants (run by the target-assets job)."""
import asyncio
import json
import types
import uuid

import pytest

from operations import discovery
from scope.roots import recompute_spanning_target_roots
from targets.asset_migration import BoundConnectionPool, migrate_target_assets
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


async def _admission(conn, name):
    """The status POST /discovery would answer for ``name``; an admitted run is completed so the
    next probe of the same apex is not refused as already running."""
    try:
        run_id = await discovery.admit_discovery(conn, name, requested_by=discovery.requester())
    except discovery.DiscoveryRefused as exc:
        return exc.status_code
    await conn.execute("UPDATE discovery_runs SET status='completed' WHERE id=$1", run_id)
    return 200


def _resolve_everything(monkeypatch):
    """Every name resolves to one global address (a fixture; no network)."""
    import target_resolution

    async def lookup(_hostname):
        return ["93.184.215.14"]

    monkeypatch.setattr(target_resolution, "system_lookup", lookup)


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
            # A scan submission's own target is not a declaration.
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


def test_a_host_a_person_added_keeps_declaring_its_domain_after_a_scan(monkeypatch):
    """Adding a host, then scanning its URL, attaches the scan's row under the host. The host is
    still the person's declaration, so discovery for its domain stays admitted."""
    from targets.asset_router import HostTargetCreate, persist_host_target
    encryption(monkeypatch)
    monkeypatch.setenv(discovery.MAX_ACTIVE_ENV, "20")

    async def run():
        async with database() as conn:
            await _converted(conn)
            host = await persist_host_target(conn, HostTargetCreate(locator="db.example.net"))
            before = await _admission(conn, "example.net")
            await conn.execute("""INSERT INTO targets(url, name, discovery_source)
                VALUES ('https://db.example.net', 'db', 'scan')""")
            owner = await conn.fetchval(
                "SELECT asset_owner_id FROM targets WHERE url = 'https://db.example.net'")
            after = await _admission(conn, "example.net")
            # A host stored before the marker existed counts as it did: not once a scan's row is
            # under it. Adding it again on the Targets page marks it.
            await conn.execute("""INSERT INTO targets(url, name, discovery_source)
                VALUES ('host://db.legacy.test', 'db', 'host')""")
            await conn.execute("""INSERT INTO targets(url, name, discovery_source)
                VALUES ('https://db.legacy.test', 'db', 'scan')""")
            legacy = await _admission(conn, "legacy.test")
            await persist_host_target(conn, HostTargetCreate(locator="db.legacy.test"))
            legacy_added = await _admission(conn, "legacy.test")
            # The host the asset model creates for a scan's row is not a declaration either way.
            await conn.execute("""INSERT INTO targets(url, name, discovery_source)
                VALUES ('https://db.scanned.test', 'db', 'scan')""")
            owned = await conn.fetchrow(
                "SELECT discovery_source, metadata_json FROM targets WHERE url = 'host://db.scanned.test'")
            scanned = await _admission(conn, "scanned.test")
            return host, before, owner, after, legacy, legacy_added, owned, scanned

    host, before, owner, after, legacy, legacy_added, owned, scanned = asyncio.run(run())
    assert host["status"] == "created" and str(owner) == host["id"]
    assert (before, after) == (200, 200)
    assert (legacy, legacy_added) == (403, 200)
    assert owned["discovery_source"] == "host" and "declared" not in (owned["metadata_json"] or "")
    assert scanned == 403


def test_adding_a_target_a_scan_or_hunt_created_makes_it_the_persons(monkeypatch):
    """POST /targets and POST /targets/hosts on a row a scan or a Hunt agent created first turn it
    into the person's own target; rows from other automated sources keep their source."""
    from api import api as api_module
    from targets.asset_router import HostTargetCreate, persist_host_target
    encryption(monkeypatch)
    _resolve_everything(monkeypatch)
    monkeypatch.setenv(discovery.MAX_ACTIVE_ENV, "20")

    async def run():
        async with database() as conn:
            await _converted(conn)
            monkeypatch.setattr(api_module, "db_pool", BoundConnectionPool(conn))
            await conn.execute("""INSERT INTO targets(url, name, discovery_source) VALUES
                ('https://app.scanned.test', 'a', 'scan'),
                ('https://found.discovered.test', 'f', 'subfinder')""")
            await conn.execute("""INSERT INTO targets(url, name, metadata_json) VALUES
                ('https://app.agentweb.test', 'w', '{"created_via": "hunt", "cohort": "lab"}')""")
            await persist_host_target(conn, HostTargetCreate(locator="db.agent.test"), created_via="hunt")
            before = {name: await _admission(conn, name)
                      for name in ("scanned.test", "agentweb.test", "agent.test", "discovered.test")}
            responses = []
            for url in ("https://app.scanned.test", "https://app.agentweb.test",
                        "https://found.discovered.test"):
                responses.append(await api_module.create_target(
                    types.SimpleNamespace(url=url, name=None, scan_options={})))
            host = await persist_host_target(conn, HostTargetCreate(locator="db.agent.test"))
            after = {name: await _admission(conn, name)
                     for name in ("scanned.test", "agentweb.test", "agent.test", "discovered.test")}
            rows = {row["url"]: (row["discovery_source"], row["metadata_json"]) for row in await conn.fetch(
                """SELECT url, discovery_source, metadata_json::text AS metadata_json FROM targets
                   WHERE url IN ('https://app.scanned.test', 'https://app.agentweb.test',
                                 'https://found.discovered.test', 'host://db.agent.test')""")}
            return before, responses, host, after, rows

    before, responses, host, after, rows = asyncio.run(run())
    assert before == {"scanned.test": 403, "agentweb.test": 403, "agent.test": 403, "discovered.test": 403}
    assert [response["status"] for response in responses] == ["already_exists"] * 3
    assert host["status"] == "already_exists"
    assert after == {"scanned.test": 200, "agentweb.test": 200, "agent.test": 200, "discovered.test": 403}
    assert rows["https://app.scanned.test"][0] == "manual"
    assert rows["https://app.agentweb.test"][0] == "manual"
    assert "created_via" not in rows["https://app.agentweb.test"][1]
    assert '"cohort": "lab"' in rows["https://app.agentweb.test"][1]
    assert rows["https://found.discovered.test"][0] == "subfinder"
    assert rows["host://db.agent.test"][0] == "host"
    assert "created_via" not in rows["host://db.agent.test"][1]
    assert '"declared": true' in rows["host://db.agent.test"][1]


class _StopAfterTargetRow(Exception):
    pass


def test_a_scan_submission_records_its_target_as_scan_created(monkeypatch):
    """Drive the real submission path to the row it creates: it is marked 'scan' and does not
    declare its domain."""
    from api import api as api_module
    encryption(monkeypatch)
    monkeypatch.setenv(discovery.MAX_ACTIVE_ENV, "20")

    async def dns_alias(_pool, target, **_kwargs):
        return target, None, None, None

    async def no_op(*_args, **_kwargs):
        return None

    async def stop(*_args, **_kwargs):
        raise _StopAfterTargetRow

    monkeypatch.setattr(api_module, "get_redis", lambda: object())
    monkeypatch.setattr(api_module.target_dns_alias, "prepare_scan_dns_alias", dns_alias)
    monkeypatch.setattr(api_module, "_worker_freshness_snapshot", lambda: {"available": False})
    monkeypatch.setattr(api_module, "_require_approval_receipt_if_policy_enabled", no_op)
    monkeypatch.setattr(api_module, "_require_reachable_fleet_placement", no_op)
    monkeypatch.setattr(api_module, "_generic_collection_refs", stop)

    async def run():
        async with database() as conn:
            await _converted(conn)
            monkeypatch.setattr(api_module, "db_pool", BoundConnectionPool(conn))
            with pytest.raises(_StopAfterTargetRow):
                await api_module._submit_scan(api_module.ScanRequest(
                    target="https://shop.submitted.test", policy={"active_testing": False}))
            row = await conn.fetchrow(
                "SELECT discovery_source, asset_owner_id FROM targets WHERE url = 'https://shop.submitted.test'")
            return row, await _admission(conn, "submitted.test")

    row, status = asyncio.run(run())
    assert row["discovery_source"] == "scan" and row["asset_owner_id"] is not None
    assert status == 403


def test_a_hunt_agents_target_create_records_created_via_hunt(monkeypatch):
    """Drive the Hunt ``targets.create`` action: the host it creates records created_via='hunt'
    and does not declare its domain; a host the person already had is left theirs."""
    from hunt.asset_actions import execute_asset_action
    from targets.asset_router import HostTargetCreate, persist_host_target
    encryption(monkeypatch)
    monkeypatch.setenv(discovery.MAX_ACTIVE_ENV, "20")

    async def run():
        async with database() as conn:
            await _converted(conn)
            pool = BoundConnectionPool(conn)
            subject = await persist_host_target(conn, HostTargetCreate(locator="subject.mine.test"))
            hunt = {"id": uuid.uuid4(), "target_id": uuid.UUID(subject["id"]), "target_kind": "network",
                    "policy_json": {}}
            created = await execute_asset_action(pool, hunt, "targets.create", {"locator": "db.agent.test"})
            existing = await execute_asset_action(pool, hunt, "targets.create", {"locator": "subject.mine.test"})
            metadata = {row["url"]: json.loads(row["metadata_json"]) for row in await conn.fetch(
                """SELECT url, metadata_json::text AS metadata_json FROM targets
                   WHERE url IN ('host://db.agent.test', 'host://subject.mine.test')""")}
            return (created, existing, metadata,
                    await _admission(conn, "agent.test"), await _admission(conn, "mine.test"))

    created, existing, metadata, agent, mine = asyncio.run(run())
    assert created["status"] == "created" and existing["status"] == "already_exists"
    assert metadata["host://db.agent.test"]["created_via"] == "hunt"
    assert "created_via" not in metadata["host://subject.mine.test"]
    assert (agent, mine) == (403, 200)
