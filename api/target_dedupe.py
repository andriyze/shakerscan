"""Canonical target de-duplication — the canonical key, the per-group row merge, and a
full-DB merge. Shared by the POST /targets/dedupe endpoint (api.py) and the schema
migration (retest_contract.py) so dirty installs heal with the same tested logic
instead of leaving target creation broken when the UNIQUE index can't be built.

This module imports nothing from api/retest_contract, so it is safe to import from both.
"""
import ipaddress
import re
import urllib.parse
import uuid
from typing import Any


RETENTION_PREVIEW_FK_CONSTRAINT = "evidence_objects_retention_delete_preview_fk"


class TargetMergeBlockedError(RuntimeError):
    """A target merge would invalidate an in-flight retention deletion intent."""

    def __init__(self, target_ids: list[Any], preview_ids: list[Any] | None = None):
        self.target_ids = sorted({str(item) for item in target_ids if item})
        self.preview_ids = sorted({str(item) for item in (preview_ids or []) if item})
        super().__init__(
            "Target merge is blocked while an evidence retention deletion is executing"
        )

    def api_detail(self) -> dict[str, Any]:
        return {
            "error": "target_merge_blocked_by_evidence_retention",
            "message": (
                "Cannot merge these targets while an evidence retention deletion is executing. "
                "Resume or finish the unfinished Evidence cleanup, then retry the merge."
            ),
            "target_ids": self.target_ids,
            "preview_ids": self.preview_ids,
        }


async def ensure_no_executing_retention_previews(conn, target_ids: list[Any]) -> None:
    """Fail closed before a merge can rewrite/delete an executing preview's target."""
    normalized = sorted({uuid.UUID(str(item)) for item in target_ids if item})
    if not normalized:
        return
    rows = await conn.fetch(
        """
        SELECT id, target_id
        FROM evidence_retention_previews
        WHERE target_id = ANY($1::uuid[])
          AND status = 'executing'
        ORDER BY target_id, id
        FOR SHARE
        """,
        normalized,
    )
    if rows:
        raise TargetMergeBlockedError(
            [row["target_id"] for row in rows],
            [row["id"] for row in rows],
        )


def canonical_web_host(url: Any) -> str:
    """Return the host identity shared by every HTTP(S) origin on that host.

    Scheme, credentials, port, path, query, and fragment are deliberately not part of
    a web target's identity. They remain part of the concrete scan/hunt origin. This is
    what lets ``http://app:8080`` and ``https://app:9090`` contribute evidence to one
    target without accidentally sending a request to the wrong origin.
    """
    raw = str(url or "").strip()
    if not raw:
        return ""
    candidate = raw if "://" in raw else f"//{raw}"
    try:
        parsed = urllib.parse.urlsplit(candidate)
        host = str(parsed.hostname or "").strip().strip("[]").rstrip(".").lower()
    except ValueError:
        return ""
    if not host:
        return ""
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        return host


def canonical_target_key(url: Any, discovery_source: Any = None) -> str:
    """Return the durable target identity key.

    Web targets are host assets, not origins: all HTTP(S) schemes and ports share one
    ``web:`` key. Model Intake rows are artifact subjects and therefore retain their
    complete scheme-insensitive path/query identity under ``artifact:``. Callers that
    create artifact subjects must therefore provide the ``model-intake`` discovery
    source; ordinary DAST and Deep Hunt URLs remain web targets even when they include
    a path.

    This MUST stay equivalent to ``targets_set_canonical_key`` in ``db/init.sql`` and
    ``retest_contract.py`` for normalized stored URLs.
    """
    raw = str(url or "").strip().lower()
    source = str(discovery_source or "").strip().lower()
    if source == "model-intake":
        subject = re.sub(r"^https?://", "", raw).rstrip("/")
        return f"artifact:{subject}"
    host = canonical_web_host(raw)
    return f"web:{host}" if host else "web:"


# target_id-bearing tables with a UNIQUE(target_id, ...) constraint: reassigning a
# duplicate's rows can collide, so colliding rows are dropped first (survivor- or
# lower-id-sibling-wins; NULL keys never collide).
MERGE_UNIQUE_TABLES: list[tuple[str, list[str]]] = [
    ("application_graph_nodes", ["node_type", "node_key"]),
    ("application_graph_edges", ["src_key", "dst_key", "edge_type"]),
    ("target_principal_provisioning_attempts", ["auth_state"]),
]
# target_id-bearing tables without a target_id unique constraint — plain reassignment.
MERGE_PLAIN_TABLES: list[str] = [
    "agent_context_packs", "agent_hunt_runs", "campaign_actions", "campaigns",
    "evidence_instances", "evidence_retention_previews", "export_events",
    "finding_exceptions", "finding_verifications", "model_intake_admissions",
    "refuter_reviews", "research_episodes", "scan_campaigns", "scans", "schedules",
    "target_invariant_contracts",
]


async def _table_exists(conn, table: str) -> bool:
    """Migration-safe existence check for tables added after the original schema."""
    fetchval = getattr(conn, "fetchval", None)
    if not callable(fetchval):
        # Lightweight unit-test connections model the current schema and only record
        # mutations. Production asyncpg connections always take the catalog path.
        return True
    return bool(await fetchval("SELECT to_regclass($1) IS NOT NULL", f"public.{table}"))


async def _merge_named_credentials(conn, survivor_id, dupe_ids: list) -> None:
    if not await _table_exists(conn, "target_credential_profiles"):
        return
    # Keep the most recently rotated credential for each case-insensitive name. The
    # secret stays encrypted; only ownership moves to the surviving target.
    await conn.execute(
        """
        DELETE FROM target_credential_profiles d
        USING target_credential_profiles keep
        WHERE d.target_id = ANY($1::uuid[])
          AND keep.target_id = ANY($2::uuid[])
          AND lower(keep.name) = lower(d.name)
          AND (keep.rotated_at, keep.updated_at, keep.id) > (d.rotated_at, d.updated_at, d.id)
        """,
        dupe_ids,
        [survivor_id, *dupe_ids],
    )
    # If the newest row belonged to a duplicate, remove an older survivor row first.
    await conn.execute(
        """
        DELETE FROM target_credential_profiles old
        USING target_credential_profiles newest
        WHERE old.target_id = $1
          AND newest.target_id = ANY($2::uuid[])
          AND lower(old.name) = lower(newest.name)
          AND (newest.rotated_at, newest.updated_at, newest.id) >
              (old.rotated_at, old.updated_at, old.id)
        """,
        survivor_id,
        dupe_ids,
    )
    await conn.execute(
        "UPDATE target_credential_profiles SET target_id=$2 WHERE target_id=ANY($1::uuid[])",
        dupe_ids,
        survivor_id,
    )


async def _merge_findings(conn, survivor_id, dupe_ids: list) -> None:
    """Merge fingerprint collisions without cascading away proof history."""
    if not await _table_exists(conn, "findings"):
        return
    all_ids = [survivor_id, *dupe_ids]
    if await _table_exists(conn, "evidence_objects"):
        # A finding owns at most one durable evidence object of each type. Two
        # canonical-target variants can nevertheless have produced the same finding
        # independently, so moving both objects directly to the surviving finding
        # violates evidence_objects_finding_type_unique and blocks startup. Collapse
        # only those exact (surviving finding, object type) collisions before the
        # generic child re-parenting below. Prefer evidence already attached to the
        # finding we keep, then the newest object. The surrounding target-merge
        # transaction and retention-preview guard make this atomic and fail closed.
        await conn.execute(
            """
            WITH ranked_findings AS (
                SELECT id,
                       FIRST_VALUE(id) OVER (
                           PARTITION BY fingerprint
                           ORDER BY (target_id=$2) DESC, updated_at DESC, id DESC
                       ) AS keep_id
                FROM findings WHERE target_id=ANY($1::uuid[])
            ), ranked_objects AS (
                SELECT evidence.id,
                       ROW_NUMBER() OVER (
                           PARTITION BY ranked.keep_id, evidence.object_type
                           ORDER BY (evidence.finding_id=ranked.keep_id) DESC,
                                    evidence.created_at DESC,
                                    evidence.id DESC
                       ) AS rn
                FROM evidence_objects evidence
                JOIN ranked_findings ranked ON ranked.id=evidence.finding_id
            )
            DELETE FROM evidence_objects evidence
            USING ranked_objects ranked
            WHERE evidence.id=ranked.id AND ranked.rn>1
            """,
            all_ids,
            survivor_id,
        )
    child_tables = (
        "evidence_instances",
        "evidence_objects",
        "export_events",
        "finding_verifications",
        "refuter_reviews",
    )
    for table in child_tables:
        if not await _table_exists(conn, table):
            continue
        await conn.execute(
            f"""
            WITH ranked AS (
                SELECT id,
                       FIRST_VALUE(id) OVER (
                           PARTITION BY fingerprint
                           ORDER BY (target_id=$2) DESC, updated_at DESC, id DESC
                       ) AS keep_id
                FROM findings WHERE target_id=ANY($1::uuid[])
            )
            UPDATE {table} child SET finding_id=r.keep_id
            FROM ranked r WHERE child.finding_id=r.id AND r.id<>r.keep_id
            """,
            all_ids,
            survivor_id,
        )
    await conn.execute(
        """
        WITH ranked AS (
            SELECT id, ROW_NUMBER() OVER (
                PARTITION BY fingerprint
                ORDER BY (target_id=$2) DESC, updated_at DESC, id DESC
            ) AS rn
            FROM findings WHERE target_id=ANY($1::uuid[])
        )
        DELETE FROM findings f USING ranked r WHERE f.id=r.id AND r.rn>1
        """,
        all_ids,
        survivor_id,
    )
    await conn.execute(
        "UPDATE findings SET target_id=$2 WHERE target_id=ANY($1::uuid[])",
        dupe_ids,
        survivor_id,
    )


async def _merge_target_endpoints(conn, survivor_id, dupe_ids: list) -> None:
    """Merge endpoint fingerprints while retaining attempts and expectations."""
    if not await _table_exists(conn, "target_endpoints"):
        return
    all_ids = [survivor_id, *dupe_ids]
    for table in ("asm_endpoint_attempts", "target_endpoint_expectations"):
        if not await _table_exists(conn, table):
            continue
        await conn.execute(
            f"""
            WITH ranked AS (
                SELECT id,
                       FIRST_VALUE(id) OVER (
                           PARTITION BY fingerprint
                           ORDER BY (target_id=$2) DESC, updated_at DESC, id DESC
                       ) AS keep_id
                FROM target_endpoints WHERE target_id=ANY($1::uuid[])
            )
            UPDATE {table} child SET endpoint_id=r.keep_id
            FROM ranked r WHERE child.endpoint_id=r.id AND r.id<>r.keep_id
            """,
            all_ids,
            survivor_id,
        )
    await conn.execute(
        """
        WITH ranked AS (
            SELECT id, ROW_NUMBER() OVER (
                PARTITION BY fingerprint
                ORDER BY (target_id=$2) DESC, updated_at DESC, id DESC
            ) AS rn
            FROM target_endpoints WHERE target_id=ANY($1::uuid[])
        )
        DELETE FROM target_endpoints e USING ranked r WHERE e.id=r.id AND r.rn>1
        """,
        all_ids,
        survivor_id,
    )
    await conn.execute(
        "UPDATE target_endpoints SET target_id=$2 WHERE target_id=ANY($1::uuid[])",
        dupe_ids,
        survivor_id,
    )


async def _merge_hypotheses(conn, survivor_id, dupe_ids: list) -> None:
    """Merge hypothesis keys and preserve links from reviews and decisions."""
    if not await _table_exists(conn, "hypotheses"):
        return
    all_ids = [survivor_id, *dupe_ids]
    for table in ("refuter_reviews", "research_decisions"):
        if not await _table_exists(conn, table):
            continue
        await conn.execute(
            f"""
            WITH ranked AS (
                SELECT id,
                       FIRST_VALUE(id) OVER (
                           PARTITION BY family, dedupe_key
                           ORDER BY (target_id=$2) DESC, updated_at DESC, id DESC
                       ) AS keep_id
                FROM hypotheses WHERE target_id=ANY($1::uuid[])
            )
            UPDATE {table} child SET hypothesis_id=r.keep_id
            FROM ranked r WHERE child.hypothesis_id=r.id AND r.id<>r.keep_id
            """,
            all_ids,
            survivor_id,
        )
    await conn.execute(
        """
        WITH ranked AS (
            SELECT id, ROW_NUMBER() OVER (
                PARTITION BY family, dedupe_key
                ORDER BY (target_id=$2) DESC, updated_at DESC, id DESC
            ) AS rn
            FROM hypotheses WHERE target_id=ANY($1::uuid[])
        )
        DELETE FROM hypotheses h USING ranked r WHERE h.id=r.id AND r.rn>1
        """,
        all_ids,
        survivor_id,
    )
    await conn.execute(
        "UPDATE hypotheses SET target_id=$2 WHERE target_id=ANY($1::uuid[])",
        dupe_ids,
        survivor_id,
    )


async def _merge_target_principals(conn, survivor_id, dupe_ids: list) -> None:
    if not await _table_exists(conn, "target_principals"):
        return
    all_ids = [survivor_id, *dupe_ids]
    # Repoint expectation references before removing exact duplicate identities.
    # Rank across the complete group, not just survivor-vs-duplicate: two duplicate
    # targets may carry the same identity even when the chosen survivor has none.
    if await _table_exists(conn, "target_endpoint_expectations"):
        # Mapping two equivalent principals can make two expectations identical on
        # their current target. Remove only that exact collision before changing the
        # principal FK, preserving the newest authored expectation.
        await conn.execute(
            """
            WITH principal_map AS (
                SELECT id,
                       FIRST_VALUE(id) OVER (
                           PARTITION BY lower(label), COALESCE(tenant_id, ''), COALESCE(auth_state, '')
                           ORDER BY (target_id=$2) DESC, updated_at DESC, id DESC
                       ) AS keep_id
                FROM target_principals WHERE target_id=ANY($1::uuid[])
            ), ranked AS (
                SELECT e.id, ROW_NUMBER() OVER (
                    PARTITION BY e.target_id, e.method, e.path, e.param_shape, e.param_location,
                                 COALESCE(pm.keep_id, e.principal_id,
                                     '00000000-0000-0000-0000-000000000000'::uuid),
                                 COALESCE(e.principal_role, ''), COALESCE(e.tenant_id, '')
                    ORDER BY e.updated_at DESC, e.id DESC
                ) AS rn
                FROM target_endpoint_expectations e
                LEFT JOIN principal_map pm ON pm.id=e.principal_id
                WHERE e.target_id=ANY($1::uuid[])
            )
            DELETE FROM target_endpoint_expectations e
            USING ranked r WHERE e.id=r.id AND r.rn>1
            """,
            all_ids,
            survivor_id,
        )
        await conn.execute(
            """
            WITH ranked AS (
                SELECT id,
                       FIRST_VALUE(id) OVER (
                           PARTITION BY lower(label), COALESCE(tenant_id, ''), COALESCE(auth_state, '')
                           ORDER BY (target_id=$2) DESC, updated_at DESC, id DESC
                       ) AS keep_id
                FROM target_principals WHERE target_id=ANY($1::uuid[])
            )
            UPDATE target_endpoint_expectations e SET principal_id=r.keep_id
            FROM ranked r WHERE e.principal_id=r.id AND r.id<>r.keep_id
            """,
            all_ids,
            survivor_id,
        )
    await conn.execute(
        """
        WITH ranked AS (
            SELECT id, ROW_NUMBER() OVER (
                PARTITION BY lower(label), COALESCE(tenant_id, ''), COALESCE(auth_state, '')
                ORDER BY (target_id=$2) DESC, updated_at DESC, id DESC
            ) AS rn
            FROM target_principals WHERE target_id=ANY($1::uuid[])
        )
        DELETE FROM target_principals p USING ranked r WHERE p.id=r.id AND r.rn>1
        """,
        all_ids,
        survivor_id,
    )
    # Two previously separate rows may both own the active user1/user2 slot. Keep
    # every identity, but only the newest one active before consolidating ownership.
    await conn.execute(
        """
        WITH ranked AS (
            SELECT id, ROW_NUMBER() OVER (
                PARTITION BY auth_state ORDER BY updated_at DESC, id DESC
            ) AS rn
            FROM target_principals
            WHERE target_id = ANY($1::uuid[])
              AND is_active = true AND auth_state IN ('user1','user2')
        )
        UPDATE target_principals p SET is_active=false, updated_at=NOW()
        FROM ranked r WHERE p.id=r.id AND r.rn>1
        """,
        all_ids,
    )
    await conn.execute(
        "UPDATE target_principals SET target_id=$2 WHERE target_id=ANY($1::uuid[])",
        dupe_ids,
        survivor_id,
    )


async def _merge_endpoint_expectations(conn, survivor_id, dupe_ids: list) -> None:
    if not await _table_exists(conn, "target_endpoint_expectations"):
        return
    await conn.execute(
        """
        DELETE FROM target_endpoint_expectations d
        WHERE d.target_id = ANY($1::uuid[])
          AND EXISTS (
              SELECT 1 FROM target_endpoint_expectations keep
              WHERE keep.target_id = ANY($2::uuid[])
                AND keep.method=d.method AND keep.path=d.path
                AND keep.param_shape=d.param_shape AND keep.param_location=d.param_location
                AND COALESCE(keep.principal_id, '00000000-0000-0000-0000-000000000000'::uuid) =
                    COALESCE(d.principal_id, '00000000-0000-0000-0000-000000000000'::uuid)
                AND COALESCE(keep.principal_role, '') = COALESCE(d.principal_role, '')
                AND COALESCE(keep.tenant_id, '') = COALESCE(d.tenant_id, '')
                AND (keep.target_id=$3 OR keep.id<d.id)
          )
        """,
        dupe_ids,
        [survivor_id, *dupe_ids],
        survivor_id,
    )
    await conn.execute(
        "UPDATE target_endpoint_expectations SET target_id=$2 WHERE target_id=ANY($1::uuid[])",
        dupe_ids,
        survivor_id,
    )


async def merge_target_group(conn, survivor_id, dupe_ids: list) -> None:
    """Reassign every child row of the duplicate targets to the survivor, then delete
    the duplicates and recompute the survivor's counts. Runs in the caller's txn."""
    group_target_ids = [survivor_id, *dupe_ids]
    await ensure_no_executing_retention_previews(conn, group_target_ids)
    await _merge_named_credentials(conn, survivor_id, dupe_ids)
    await _merge_target_principals(conn, survivor_id, dupe_ids)
    await _merge_findings(conn, survivor_id, dupe_ids)
    await _merge_target_endpoints(conn, survivor_id, dupe_ids)
    await _merge_hypotheses(conn, survivor_id, dupe_ids)
    for table, key_cols in MERGE_UNIQUE_TABLES:
        if not await _table_exists(conn, table):
            continue
        key_match = " AND ".join(f"o.{c} = d.{c}" for c in key_cols)
        await conn.execute(f"""
            DELETE FROM {table} d
            WHERE d.target_id = ANY($1::uuid[])
              AND EXISTS (
                SELECT 1 FROM {table} o
                WHERE {key_match}
                  AND (o.target_id = $2 OR (o.target_id = ANY($1::uuid[]) AND o.id < d.id))
              )
        """, dupe_ids, survivor_id)
        await conn.execute(
            f"UPDATE {table} SET target_id = $2 WHERE target_id = ANY($1::uuid[])",
            dupe_ids, survivor_id)
    await _merge_endpoint_expectations(conn, survivor_id, dupe_ids)
    for table in MERGE_PLAIN_TABLES:
        if not await _table_exists(conn, table):
            continue
        await conn.execute(
            f"UPDATE {table} SET target_id = $2 WHERE target_id = ANY($1::uuid[])",
            dupe_ids, survivor_id)
    await conn.execute(
        "UPDATE targets SET parent_target_id = $2 WHERE parent_target_id = ANY($1::uuid[])",
        dupe_ids, survivor_id)
    try:
        await conn.execute("DELETE FROM targets WHERE id = ANY($1::uuid[])", dupe_ids)
    except Exception as exc:
        # The restrictive FK is the race-proof backstop if a preview transitions
        # to executing after the explicit check above. Translate only that named
        # constraint; unrelated integrity failures must retain their original error.
        if getattr(exc, "constraint_name", None) == RETENTION_PREVIEW_FK_CONSTRAINT:
            raise TargetMergeBlockedError(group_target_ids) from exc
        raise
    await conn.execute("""
        UPDATE targets SET
            active_findings_count = (SELECT count(*) FROM findings WHERE target_id = $1 AND status = 'active'),
            total_scans = (SELECT count(*) FROM scans WHERE target_id = $1)
        WHERE id = $1
    """, survivor_id)


async def plan_canonical_merges(conn) -> list[dict]:
    """Group targets by canonical key and, for each group with >1 member, pick a
    survivor (active > most findings > most scans > https) and list the merges."""
    rows = await conn.fetch(
        "SELECT id, url, discovery_source, is_active, total_scans, active_findings_count FROM targets")
    groups: dict[str, list] = {}
    for r in rows:
        groups.setdefault(canonical_target_key(r["url"], r.get("discovery_source")), []).append(r)

    plan: list[dict] = []
    for key, members in groups.items():
        if len(members) < 2:
            continue
        ranked = sorted(members, key=lambda r: (
            1 if r["is_active"] else 0,
            int(r["active_findings_count"] or 0),
            int(r["total_scans"] or 0),
            1 if str(r["url"] or "").lower().startswith("https://") else 0,
        ), reverse=True)
        survivor, dupes = ranked[0], ranked[1:]
        plan.append({
            "canonical": key,
            "survivor": {"id": str(survivor["id"]), "url": survivor["url"],
                         "active_findings_count": survivor["active_findings_count"],
                         "total_scans": survivor["total_scans"]},
            "merged": [{"id": str(d["id"]), "url": d["url"],
                        "active_findings_count": d["active_findings_count"],
                        "total_scans": d["total_scans"]} for d in dupes],
        })
    return plan


async def merge_all_canonical_duplicates(conn) -> int:
    """Merge every canonical-duplicate group and return the rows removed.

    The schema migration wraps this operation in one outer transaction; the per-group
    transactions below are savepoints, so one late collision rolls back the entire
    host-identity migration rather than committing a partial repair.
    """
    removed = 0
    plan = await plan_canonical_merges(conn)
    all_target_ids = [
        uuid.UUID(target["id"])
        for item in plan
        for target in (item["survivor"], *item["merged"])
    ]
    await ensure_no_executing_retention_previews(conn, all_target_ids)
    for item in plan:
        survivor_id = uuid.UUID(item["survivor"]["id"])
        dupe_ids = [uuid.UUID(m["id"]) for m in item["merged"]]
        async with conn.transaction():
            await merge_target_group(conn, survivor_id, dupe_ids)
        removed += len(dupe_ids)
    return removed
