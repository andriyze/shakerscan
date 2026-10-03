"""Atomic conversion of the 2.6 inventory into stable host targets and service members.

Run under the startup migration lock after the frozen 2.6 baseline. Old device UUIDs
are retained. Compatibility names are views, not another asset inventory. Downgrade
requires restoring the pre-upgrade database backup; read-only aliases are not dual writes.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
import ipaddress
import json
import re
from typing import Any
import urllib.parse

from .asset_schema import ASSET_MIGRATION, ASSET_SCHEMA_SQL, ASSET_VIEW_SQL
from .asset_invariants import _install_host_key


def locator_from_url(value: str) -> str | None:
    """Normalize a literal host, without resolving DNS or equating aliases."""
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https", "host"} or parsed.username or parsed.password:
            return None
        host = str(parsed.hostname or "").lower().rstrip(".")
        if not host:
            return None
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return host.encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        return None


def host_url(locator: str) -> str:
    return f"host://[{locator}]" if ":" in locator else f"host://{locator}"

def canonical_origin_url(value: str) -> str:
    """Use the same literal host spelling for SQL membership and Python binding."""
    locator = locator_from_url(value)
    if locator is None:
        raise ValueError('invalid application origin')
    parsed = urllib.parse.urlsplit(value)
    authority = f'[{locator}]' if ':' in locator else locator
    if parsed.port is not None:
        authority += f':{parsed.port}'
    return parsed._replace(netloc=authority).geturl()


class BoundConnectionPool:
    """Let the frozen baseline run inside the caller's connection and transaction."""
    def __init__(self, conn: Any) -> None:
        self.conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


async def migration_applied(conn: Any) -> bool:
    if not await conn.fetchval("SELECT to_regclass('app_schema_migrations')"):
        return False
    return bool(await conn.fetchval(
        "SELECT 1 FROM app_schema_migrations WHERE name=$1", ASSET_MIGRATION,
    ))




async def _canonical_device_references(conn: Any) -> None:
    # These were exclusive references to two inventories. Both now identify the same
    # target; the compatibility device column remains available for one release.
    await conn.execute("""
        ALTER TABLE request_collections DROP CONSTRAINT IF EXISTS request_collections_target_check;
        ALTER TABLE hunt_runs DROP CONSTRAINT IF EXISTS hunt_runs_target_check;
        ALTER TABLE IF EXISTS investigation_candidates DROP CONSTRAINT IF EXISTS investigation_candidates_target_check;
    """)
    tables = await conn.fetch("""
        SELECT table_name FROM information_schema.columns
        WHERE table_schema=current_schema() AND column_name='device_target_id'
          AND table_name IN (SELECT tablename FROM pg_tables WHERE schemaname=current_schema())
        ORDER BY table_name
    """)
    for row in tables:
        table = str(row["table_name"])
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", table):
            raise RuntimeError("unexpected device-owned relation name")
        await conn.execute(f'ALTER TABLE "{table}" ADD COLUMN IF NOT EXISTS target_id UUID REFERENCES targets(id) ON DELETE CASCADE')
        await conn.execute(f'UPDATE "{table}" SET target_id=device_target_id WHERE device_target_id IS NOT NULL AND target_id IS NULL')
        await conn.execute(f'CREATE INDEX IF NOT EXISTS "idx_{table}_unified_target" ON "{table}"(target_id)')
        await conn.execute(f'''CREATE TRIGGER unified_target_reference BEFORE INSERT OR UPDATE OF target_id,device_target_id
            ON "{table}" FOR EACH ROW EXECUTE FUNCTION enforce_device_target_alias()''')
    await conn.execute("""
        ALTER TABLE request_collections ADD CONSTRAINT request_collections_target_check
            CHECK (target_id IS NOT NULL AND (device_target_id IS NULL OR device_target_id=target_id));
        ALTER TABLE hunt_runs ADD CONSTRAINT hunt_runs_target_check CHECK (
            (target_kind IN ('web','api','network') AND target_id IS NOT NULL AND device_target_id IS NULL) OR
            (target_kind='device' AND target_id IS NOT NULL AND device_target_id=target_id)
        );
    """)


async def migrate_target_assets(conn: Any) -> None:
    """Apply once inside an existing transaction; failure leaves the old database intact."""
    if await migration_applied(conn):
        return
    await conn.execute(ASSET_SCHEMA_SQL)
    await _install_host_key(conn)
    devices = await conn.fetch("SELECT * FROM device_targets ORDER BY created_at,id")
    for device in devices:
        locator = locator_from_url(host_url(str(device["primary_locator"])))
        if locator is None:
            raise RuntimeError(f"stored device locator is invalid for target {device['id']}; migration rolled back")
        metadata = device["metadata_json"] or {}
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        metadata = {**metadata, "environment": device["environment"],
                    "cohort": metadata.get("cohort") or device["environment"]}
        await conn.execute("""
            INSERT INTO targets(id,url,name,discovery_source,metadata_json,is_active,created_at,updated_at)
            VALUES($1,$2,$3,'host',$4,$5,$6,$7)
        """, device["id"], host_url(locator), device["name"], json.dumps(metadata),
            device["is_active"], device["created_at"], device["updated_at"])
    await conn.execute("""
        INSERT INTO target_device_profiles (
            target_id,device_class,manufacturer,model,firmware_version,stable_identity,
            identity_confidence,environment,policy_id,sensor_affinity,last_scanned_at,last_scan_id,
            last_score,last_grade,active_findings_count,locator_generation,created_at,updated_at
        ) SELECT id,device_class,manufacturer,model,firmware_version,stable_identity,
            identity_confidence,environment,policy_id,sensor_affinity,last_scanned_at,last_scan_id,
            last_score,last_grade,active_findings_count,locator_generation,created_at,updated_at
        FROM device_targets;
    """)
    from .asset_fk import retarget_foreign_keys
    await retarget_foreign_keys(conn, "device_targets", "targets")
    await conn.execute("DROP TABLE device_targets")
    await conn.execute(ASSET_VIEW_SQL)
    origins = await conn.fetch("""
        SELECT id,url,root_domain,metadata_json FROM targets
        WHERE url ~* '^https?://' AND discovery_source IS DISTINCT FROM 'model-intake'
        ORDER BY created_at,id
    """)
    for origin in origins:
        locator = locator_from_url(str(origin["url"]))
        if not locator:
            raise RuntimeError(f"stored web origin is invalid for target {origin['id']}; migration rolled back")
        try:
            normalized = canonical_origin_url(str(origin['url']))
            if normalized != origin['url']:
                await conn.execute('UPDATE targets SET url=$2 WHERE id=$1',origin['id'],normalized)
        except (ValueError, UnicodeError) as exc:
            raise RuntimeError(f"stored web origin is invalid for target {origin['id']}; migration rolled back") from exc
        owner = await conn.fetchval("""
            INSERT INTO targets(url,name,discovery_source,root_domain,metadata_json)
            VALUES($1,$2,'host',$3,$4)
            ON CONFLICT(canonical_key) DO UPDATE SET url=targets.url RETURNING id
        """, host_url(locator), locator, origin["root_domain"], origin["metadata_json"])
        await conn.execute("UPDATE targets SET asset_owner_id=$2 WHERE id=$1", origin["id"], owner)
    await _canonical_device_references(conn)
    from .asset_compatibility import repair_candidate_target_constraint
    await repair_candidate_target_constraint(conn)
    await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1)", ASSET_MIGRATION)


async def run_unified_startup(pool: Any, baseline: Any) -> None:
    """Serialize baseline and conversion atomically, including concurrent worker startup."""
    async with pool.acquire() as conn:
        await conn.execute("SELECT pg_advisory_lock(8675309)")
        try:
            async with conn.transaction():
                if not await migration_applied(conn):
                    # The baseline takes the same reentrant session lock on this connection.
                    await baseline(BoundConnectionPool(conn))
                    await migrate_target_assets(conn)
                import importlib
                migrate_asset_inputs = importlib.import_module(
                    f"{__package__}.asset_inputs_migration"
                ).migrate_asset_inputs
                await migrate_asset_inputs(conn)
                # Data migrations added after the conversion must run here: the baseline above
                # never runs again on a converted database. Each is marker-gated.
                try:
                    from runtime.ai_header_secrets import encrypt_stored_secrets
                except ModuleNotFoundError:
                    from api.runtime.ai_header_secrets import encrypt_stored_secrets
                await encrypt_stored_secrets(conn)
        finally:
            await conn.execute("SELECT pg_advisory_unlock(8675309)")
