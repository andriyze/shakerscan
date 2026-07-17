"""Canonical target de-duplication — the canonical key, the per-group row merge, and a
full-DB merge. Shared by the POST /targets/dedupe endpoint (api.py) and the schema
migration (retest_contract.py) so dirty installs heal with the same tested logic
instead of leaving target creation broken when the UNIQUE index can't be built.

This module imports nothing from api/retest_contract, so it is safe to import from both.
"""
import re
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


def canonical_target_key(url: Any) -> str:
    """Scheme-and-trailing-slash-insensitive canonical origin. MUST stay equivalent to
    the SQL form in the targets_set_canonical_key trigger (db/init.sql / migration)."""
    raw = str(url or "").strip().lower()
    raw = re.sub(r"^https?://", "", raw).rstrip("/")
    return raw


# target_id-bearing tables with a UNIQUE(target_id, ...) constraint: reassigning a
# duplicate's rows can collide, so colliding rows are dropped first (survivor- or
# lower-id-sibling-wins; NULL keys never collide).
MERGE_UNIQUE_TABLES: list[tuple[str, list[str]]] = [
    ("findings", ["fingerprint"]),
    ("target_endpoints", ["fingerprint"]),
    ("application_graph_nodes", ["node_type", "node_key"]),
    ("application_graph_edges", ["src_key", "dst_key", "edge_type"]),
]
# target_id-bearing tables without a target_id unique constraint — plain reassignment.
MERGE_PLAIN_TABLES: list[str] = [
    "scans", "scan_campaigns", "schedules", "finding_exceptions", "finding_verifications",
]


async def merge_target_group(conn, survivor_id, dupe_ids: list) -> None:
    """Reassign every child row of the duplicate targets to the survivor, then delete
    the duplicates and recompute the survivor's counts. Runs in the caller's txn."""
    group_target_ids = [survivor_id, *dupe_ids]
    await ensure_no_executing_retention_previews(conn, group_target_ids)
    for table, key_cols in MERGE_UNIQUE_TABLES:
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
    for table in MERGE_PLAIN_TABLES:
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
        "SELECT id, url, is_active, total_scans, active_findings_count FROM targets")
    groups: dict[str, list] = {}
    for r in rows:
        groups.setdefault(canonical_target_key(r["url"]), []).append(r)

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
    """Merge every canonical-duplicate group (per-group transactional). Returns the
    number of duplicate rows removed. Used by the migration's index-build fail-safe."""
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
