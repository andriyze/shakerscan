"""GET /exposure/assets ranked in SQL: a page is bounded work.

The asset list used to read every asset with its counts and rank them in Python (URL parsing,
cohort rules, action reasons, priority) before slicing a page. Now:

* What depends only on an asset's own row (exposure class, cohort, whether it has an owner, an AI
  surface's blast-radius score before findings) is computed by the one Python implementation
  (``asset_cohorts``, ``ai_assurance``) and kept in ``exposure_target_facts`` /
  ``exposure_ai_target_facts``. A trigger marks a row stale when one of its inputs is edited; a
  read recomputes only missing or stale rows (new, edited, or classified by an older engine), so
  the rules stay in one place and a steady-state read does no Python work per asset. A read
  recomputes at most ``FACTS_READ_BUDGET`` rows; a larger backlog (a bulk import, an upgrade, a
  ``FACTS_VERSION`` bump) is finished by a background task the read starts and by the summary
  compactor's tick, and until then the read ranks those assets with provisional facts and says so
  (``classification_pending``). A read never classifies the whole inventory in Python.
* Finding counts come from the trigger-maintained summary (``targets/scale_summary.py``) and two
  small partial indexes (rows a retest settled; rows that could be proven), never from a pass over
  every finding.
* Action reasons, priority, score, coverage posture, the headline metrics and the cohort counts are
  SQL over those per-asset values; Python builds only the returned page's rows.

The legacy limit/offset response is unchanged (tests/exposure_assets_reference.py is the previous
implementation, kept as the oracle). ``count``/``cursor``/``fields`` select list/v1.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
import logging
from typing import Any, Mapping

try:
    from ai_assurance import build_agent_blast_radius
    from api_utils import _parse_graph_json
    from asset_cohorts import target_cohort, target_exposure_class
    from list_contract import ListSpec, SortKey, SqlParams
    from targets.scale_summary import TICK_HOOKS as summary_tick_hooks
except ModuleNotFoundError:  # package import in host-side tests
    from ..ai_assurance import build_agent_blast_radius
    from ..api_utils import _parse_graph_json
    from ..asset_cohorts import target_cohort, target_exposure_class
    from ..list_contract import ListSpec, SortKey, SqlParams
    from ..targets.scale_summary import TICK_HOOKS as summary_tick_hooks

from .proof_rollup import INVESTIGATOR_TOOLS, NEEDS_VERIFICATION_SQL, asset_finding_counts_sql, proof_counts_sql
from .scale_indexes import EXPOSURE_SCALE_INDEXES

#: Bump when the Python classification changes: every stored fact is then recomputed once.
FACTS_VERSION = "exposure-facts/1"
# Cold or invalidated inventories are classified in small transactions, never one Python list.
FACTS_BATCH = 100
# The most facts one read recomputes before it ranks (about 0.1 ms each); the background finishes
# a larger backlog (``complete_facts_in_background``).
FACTS_READ_BUDGET = 1000
# Facts an asset is ranked with before its first classification (it then shows as pending).
PROVISIONAL_EXPOSURE_CLASS = "unknown"
PROVISIONAL_COHORT = "unclassified"
logger = logging.getLogger("shakerscan.api.exposure.asset_rank")
PRIORITY_WEIGHT = {"P1": 300, "P2": 200, "P3": 100}
STALE_DAYS = 30
NEW_DAYS = 7

# Metadata keys the asset row reads (cohort, ownership, AI blast radius): the rest of the JSON
# stays in the database.
TARGET_METADATA_KEYS = ("cohort", "environment", "owner", "asset_owner", "risk_tier", "data_classification")
AI_METADATA_KEYS = (
    "cohort", "environment", "owner", "asset_owner", "risk_tier", "data_classification",
    "tool_inventory", "tools", "mcp_tools", "per_tool_scopes", "tool_scopes", "mcp_scopes",
    "oauth_scopes", "delegated_identity", "service_accounts", "agent_identities", "memory_stores",
    "memory", "state_stores", "write_action_approval", "dry_run_mode", "transaction_limits",
    "sandboxing", "audit_logs", "kill_switch",
)

COHORT_GROUPS = {
    "operational": ("production", "staging", "unclassified"),
    "non_operational": ("lab", "demo", "calibration", "internal"),
}


def metadata_subset_sql(column: str, keys: tuple[str, ...]) -> str:
    """Only ``keys`` of a JSON object (absent keys stay absent); a non-object passes unchanged."""
    names = ", ".join("'" + key + "'" for key in keys)
    return (
        f"(CASE WHEN jsonb_typeof({column}) = 'object' THEN COALESCE((SELECT jsonb_object_agg(e.key, e.value)"
        f" FROM jsonb_each({column}) e WHERE e.key IN ({names})), '{{}}'::jsonb) ELSE {column} END)"
    )


def exposure_class(value: str | None, *, kind: str = "web") -> str:
    if kind == "model":
        return "supply_chain"
    return target_exposure_class(value)


def jsonb_truthy_sql(expr: str) -> str:
    """Python truthiness of a decoded JSON value (``bool(json.loads(...))``); NULL is false."""
    return (
        f"(CASE jsonb_typeof({expr}) WHEN 'boolean' THEN ({expr})::boolean"
        f" WHEN 'number' THEN ({expr})::numeric <> 0"
        f" WHEN 'string' THEN ({expr}) #>> '{{}}' <> ''"
        f" WHEN 'array' THEN jsonb_array_length({expr}) > 0"
        f" WHEN 'object' THEN ({expr}) <> '{{}}'::jsonb ELSE false END)"
    )


# --- The stored per-asset facts ------------------------------------------------------------------
#
# ``state`` is FRESH_STATE when the row holds facts computed by this engine from the asset's current
# columns. A trigger marks a row stale ('stale:<transaction id>') in the transaction that edits one
# of those columns, so a read finds the rows to recompute with an anti-join instead of hashing every
# asset. A reader writes recomputed facts only over the exact state it read (UPDATE ... WHERE state
# = expected; INSERT ... ON CONFLICT DO NOTHING for a missing row): an edit that commits while the
# reader computes leaves its own stale mark, and the next read recomputes that asset again.

FRESH_STATE = f"fresh:{FACTS_VERSION}"
_TRIGGER_VERSION = "v1"

FACTS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS exposure_target_facts (
    target_id UUID PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
    state TEXT NOT NULL,
    exposure_class TEXT NOT NULL,
    cohort TEXT NOT NULL,
    owner_present BOOLEAN NOT NULL
);
CREATE TABLE IF NOT EXISTS exposure_ai_target_facts (
    ai_target_id UUID PRIMARY KEY REFERENCES ai_targets(id) ON DELETE CASCADE,
    state TEXT NOT NULL,
    exposure_class TEXT NOT NULL,
    cohort TEXT NOT NULL,
    owner_present BOOLEAN NOT NULL,
    environment_production BOOLEAN NOT NULL,
    blast_static_score INTEGER NOT NULL
);
"""

FACTS_FUNCTIONS_SQL = f"""
CREATE OR REPLACE FUNCTION exposure_target_facts_stale_{_TRIGGER_VERSION}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO exposure_target_facts (target_id, state, exposure_class, cohort, owner_present)
    VALUES (NEW.id, 'stale:' || txid_current(), '', '', false)
    ON CONFLICT (target_id) DO UPDATE SET state = EXCLUDED.state;
    RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION exposure_ai_target_facts_stale_{_TRIGGER_VERSION}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO exposure_ai_target_facts (ai_target_id, state, exposure_class, cohort, owner_present,
                                          environment_production, blast_static_score)
    VALUES (NEW.id, 'stale:' || txid_current(), '', '', false, false, 0)
    ON CONFLICT (ai_target_id) DO UPDATE SET state = EXCLUDED.state;
    RETURN NULL;
END $$;
"""

_FACTS_TRIGGERS = (
    ("targets", f"exposure_target_facts_stale_{_TRIGGER_VERSION}", f"""
        CREATE TRIGGER exposure_target_facts_stale_{_TRIGGER_VERSION}
        AFTER UPDATE OF url, name, discovery_source, metadata_json ON targets
        FOR EACH ROW WHEN (OLD.url IS DISTINCT FROM NEW.url OR OLD.name IS DISTINCT FROM NEW.name
            OR OLD.discovery_source IS DISTINCT FROM NEW.discovery_source
            OR OLD.metadata_json IS DISTINCT FROM NEW.metadata_json)
        EXECUTE FUNCTION exposure_target_facts_stale_{_TRIGGER_VERSION}()"""),
    ("ai_targets", f"exposure_ai_target_facts_stale_{_TRIGGER_VERSION}", f"""
        CREATE TRIGGER exposure_ai_target_facts_stale_{_TRIGGER_VERSION}
        AFTER UPDATE OF endpoint_url, name, target_type, production_mode, metadata_json ON ai_targets
        FOR EACH ROW WHEN (OLD.endpoint_url IS DISTINCT FROM NEW.endpoint_url OR OLD.name IS DISTINCT FROM NEW.name
            OR OLD.target_type IS DISTINCT FROM NEW.target_type
            OR OLD.production_mode IS DISTINCT FROM NEW.production_mode
            OR OLD.metadata_json IS DISTINCT FROM NEW.metadata_json)
        EXECUTE FUNCTION exposure_ai_target_facts_stale_{_TRIGGER_VERSION}()"""),
)


async def install_exposure_facts(conn: Any) -> None:
    """Create the fact tables, functions and triggers when missing. Runs under the startup lock;
    on a database that has them it only reads the catalog (no table lock, no catalog write)."""
    tables = await conn.fetchval(
        "SELECT to_regclass('exposure_target_facts') IS NOT NULL AND to_regclass('exposure_ai_target_facts') IS NOT NULL"
    )
    if not tables:
        await conn.execute(FACTS_SCHEMA_SQL)
    functions = await conn.fetchval(
        "SELECT count(*) FROM pg_proc WHERE proname = ANY($1::text[])",
        [name for _table, name, _ddl in _FACTS_TRIGGERS],
    )
    if functions != len(_FACTS_TRIGGERS):
        await conn.execute(FACTS_FUNCTIONS_SQL)
    existing = {
        row["tgname"] for row in await conn.fetch(
            "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal"
            " AND tgrelid IN ('targets'::regclass, 'ai_targets'::regclass)"
        )
    }
    for _table, name, ddl in _FACTS_TRIGGERS:
        if name not in existing:
            await conn.execute(ddl)


def target_facts(row: Mapping[str, Any]) -> tuple[str, str, bool]:
    """``(exposure_class, cohort, owner_present)`` of a web target or model artifact row."""
    kind = "model" if row.get("discovery_source") == "model-intake" else "web"
    klass = exposure_class(row.get("url"), kind=kind)
    meta = _parse_graph_json(row.get("metadata_json"))
    cohort = target_cohort(url=row.get("url"), name=row.get("name"), discovery_source=row.get("discovery_source"),
                           metadata=meta, exposure_class=klass)
    owner = str(meta.get("owner") or meta.get("asset_owner") or "").strip() or None
    return klass, cohort, owner is not None


def ai_target_facts(row: Mapping[str, Any]) -> tuple[str, str, bool, bool, int]:
    """``(exposure_class, cohort, owner_present, environment_production, blast_static_score)``."""
    klass = exposure_class(row.get("endpoint_url"), kind="ai")
    meta = _parse_graph_json(row.get("metadata_json"))
    cohort = target_cohort(url=row.get("endpoint_url"), name=row.get("name"), discovery_source="ai_gate",
                           metadata=meta, exposure_class=klass)
    owner = str(meta.get("asset_owner") or meta.get("owner") or "").strip() or None
    environment_production = str(meta.get("environment") or "").strip().lower() == "production"
    # The score before the active-findings term, which the ranking adds in SQL (it saturates at 20).
    static = int(build_agent_blast_radius(dict(row), [])["score"])
    return klass, cohort, owner is not None, environment_production, static


_FACT_SOURCES = {
    "target": {
        "select": f"""SELECT t.id, t.url, t.name, t.discovery_source,
                   {metadata_subset_sql('t.metadata_json', TARGET_METADATA_KEYS)} AS metadata_json, x.state
            FROM targets t LEFT JOIN exposure_target_facts x ON x.target_id = t.id
            WHERE t.is_active = true AND x.state IS DISTINCT FROM $1 ORDER BY t.id""",
        "table": "exposure_target_facts", "key": "target_id", "owner": "targets",
        "columns": (("exposure_class", "text"), ("cohort", "text"), ("owner_present", "boolean")),
        "compute": target_facts,
    },
    "ai": {
        "select": f"""SELECT a.id, a.endpoint_url, a.name, a.target_type, a.production_mode,
                   {metadata_subset_sql('a.metadata_json', AI_METADATA_KEYS)} AS metadata_json, x.state
            FROM ai_targets a LEFT JOIN exposure_ai_target_facts x ON x.ai_target_id = a.id
            WHERE a.is_active = true AND x.state IS DISTINCT FROM $1 ORDER BY a.id""",
        "table": "exposure_ai_target_facts", "key": "ai_target_id", "owner": "ai_targets",
        "columns": (("exposure_class", "text"), ("cohort", "text"), ("owner_present", "boolean"),
                    ("environment_production", "boolean"), ("blast_static_score", "integer")),
        "compute": ai_target_facts,
    },
}


async def _refresh_kind(conn: Any, kind: str) -> tuple[int, int]:
    """Recompute one bounded batch of changed facts; ``(written, raced)``."""
    source = _FACT_SOURCES[kind]
    rows = await conn.fetch(source["select"] + " LIMIT $2", FRESH_STATE, FACTS_BATCH)
    if not rows:
        return 0, 0
    columns = source["columns"]
    computed = [source["compute"](dict(row)) for row in rows]
    names = [name for name, _type in columns]
    unnest_args = ", ".join(f"${index + 3}::{sql_type}[]" for index, (_name, sql_type) in enumerate(columns))
    alias = ", ".join(["id", "expected", *names])
    values = [[fact[index] for fact in computed] for index in range(len(columns))]
    table, key = source["table"], source["key"]
    updated = await conn.fetch(f"""
        UPDATE {table} x SET state = '{FRESH_STATE}', {', '.join(f'{name} = u.{name}' for name in names)}
        FROM unnest($1::uuid[], $2::text[], {unnest_args}) AS u({alias})
        WHERE x.{key} = u.id AND x.state = u.expected
        RETURNING x.{key}""",
        [row["id"] for row in rows], [row["state"] for row in rows], *values)
    inserted = await conn.fetch(f"""
        INSERT INTO {table} ({key}, state, {', '.join(names)})
        SELECT u.id, '{FRESH_STATE}', {', '.join(f'u.{name}' for name in names)}
        FROM unnest($1::uuid[], $2::text[], {unnest_args}) AS u({alias})
        WHERE u.expected IS NULL AND EXISTS (SELECT 1 FROM {source['owner']} o WHERE o.id = u.id)
        ON CONFLICT ({key}) DO NOTHING
        RETURNING {key}""",
        [row["id"] for row in rows], [row["state"] for row in rows], *values)
    written = len(updated) + len(inserted)
    return written, len(rows) - written


async def refresh_facts(conn: Any, *, include_web: bool = True, include_ai: bool = True,
                        attempts: int = 3, max_rows: int | None = None) -> int:
    """Recompute the facts whose inputs changed (or that an older engine computed); returns how
    many rows were written. Rows an edit raced are recomputed again, a bounded number of times.
    ``max_rows`` stops after about that many rows (a read's budget); ``facts_pending`` then says
    whether any are left."""
    written = 0
    examined = 0
    kinds = [kind for kind, wanted in (("target", include_web), ("ai", include_ai)) if wanted]
    for attempt in range(attempts):
        raced = 0
        try:
            for kind in kinds:
                while max_rows is None or examined < max_rows:
                    async with conn.transaction():
                        done, lost = await _refresh_kind(conn, kind)
                    written += done
                    raced += lost
                    examined += done + lost
                    # A full successful batch leaves more possible work. Commit it before
                    # loading the next batch; edits that raced this one use the outer retry.
                    if lost or done < FACTS_BATCH:
                        break
        except Exception as exc:
            # Two readers refreshing the same rows can deadlock; the loser retries.
            if exc.__class__.__name__ != "DeadlockDetectedError" or attempt == attempts - 1:
                raise
            raced = 1
        if not raced or (max_rows is not None and examined >= max_rows):
            break
    return written


async def facts_pending(conn: Any, *, include_web: bool = True, include_ai: bool = True) -> bool:
    """Whether an active asset still lacks facts computed by this engine from its current columns."""
    for kind, wanted in (("target", include_web), ("ai", include_ai)):
        if wanted and await conn.fetchval(
                f"SELECT EXISTS ({_FACT_SOURCES[kind]['select']} LIMIT 1)", FRESH_STATE):
            return True
    return False


_BACKGROUND: dict[str, Any] = {"task": None}


def complete_facts_in_background(pool: Any) -> bool:
    """Start (once per process) a task that recomputes every pending fact; False when one runs.

    A read that left a backlog calls this, so the next read finds the facts ready."""
    task = _BACKGROUND["task"]
    if task is not None and not task.done():
        return False

    async def complete() -> None:
        try:
            async with pool.acquire() as conn:
                await refresh_facts(conn)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # a later read or compactor tick retries
            logger.warning("exposure facts refresh skipped: %s", type(exc).__name__)

    _BACKGROUND["task"] = asyncio.get_running_loop().create_task(complete())
    return True


async def refresh_facts_tick(pool: Any) -> int:
    """The summary compactor's share: keep the facts warm whether or not anyone reads the list
    (a database upgraded to this engine, or rows bulk-loaded without the API, start cold)."""
    async with pool.acquire() as conn:
        return await refresh_facts(conn)


if refresh_facts_tick not in summary_tick_hooks:
    summary_tick_hooks.append(refresh_facts_tick)


# --- The ranking ----------------------------------------------------------------------------------

def _latest_scan_sql(owner_filter: str) -> str:
    return f"""LEFT JOIN LATERAL (
            SELECT s.id, s.status, s.scan_type, s.completed_at,
                   s.result -> 'scan_completion_status' AS completion_status,
                   s.result ->> 'coverage_status' AS top_coverage_status
            FROM scans s WHERE {owner_filter}
            ORDER BY s.created_at DESC LIMIT 1
        ) ls ON true"""


def _ranked_sql(params: SqlParams, *, root_domain: str | None, kind: str | None, now: datetime,
                adjustments: Mapping[tuple[str, str], Mapping[str, int]]) -> str:
    """CTEs ``scored`` (every asset the kind/root filters keep) with ranking columns."""
    include_web = kind in (None, "web", "model")
    include_ai = kind in (None, "ai")
    p_root = params.add(root_domain)
    p_web_kind = params.add(kind if kind in ("web", "model") else None)
    p_web = params.add(include_web)
    p_ai = params.add(include_ai)
    p_now = params.add(now)
    keys = sorted(adjustments)
    p_adj = ", ".join(params.add(values) for values in (
        [key[0] for key in keys], [key[1] for key in keys],
        [int(adjustments[key].get("verified", 0)) for key in keys],
        [int(adjustments[key].get("needs_verification", 0)) for key in keys],
        [int(adjustments[key].get("investigator_verified", 0)) for key in keys],
    ))
    p_adj_kinds, p_adj_ids, p_dv, p_dn, p_di = p_adj.split(", ")
    # _scan_completion_flags: an object's "limited" or "budget_exhausted", by Python truthiness.
    limited_flag = jsonb_truthy_sql("(ls.completion_status -> 'limited')")
    budget_flag = jsonb_truthy_sql("(ls.completion_status -> 'budget_exhausted')")
    limited = f"(jsonb_typeof(ls.completion_status) = 'object' AND ({limited_flag} OR {budget_flag}))"
    return f"""
    adj AS (
        SELECT * FROM unnest({p_adj_kinds}::text[], {p_adj_ids}::uuid[], {p_dv}::int[], {p_dn}::int[], {p_di}::int[])
            AS a(asset_kind, asset_id, dv, dn, di)
    ),
    web_counts AS (
        SELECT target_id AS asset_id, sum(n)::bigint AS total,
               COALESCE(sum(n) FILTER (WHERE severity = 'critical'), 0)::bigint AS crit,
               COALESCE(sum(n) FILTER (WHERE severity = 'high'), 0)::bigint AS high
        FROM (SELECT target_id, severity, n FROM finding_summary_counts WHERE status = 'active'
              UNION ALL
              SELECT target_id, severity, n FROM finding_summary_deltas WHERE status = 'active') parts
        WHERE {p_web}
        GROUP BY target_id
    ),
    web_settled AS (
        SELECT f.target_id AS asset_id, count(*) AS n FROM findings f
        WHERE {p_web} AND f.status = 'active' AND f.target_id IS NOT NULL
          AND NOT COALESCE({NEEDS_VERIFICATION_SQL}, false)
        GROUP BY f.target_id
    ),
    web_proof AS ({proof_counts_sql("target_id", proof_scope=f"TRUE AND {p_web}")}),
    web_suspected AS (
        SELECT target_id AS asset_id, COUNT(*) AS n FROM investigation_candidates
        WHERE {p_web} AND plane = 'web'
          AND status IN ('new','verification_queued','verifying','inconclusive','blocked')
        GROUP BY target_id
    ),
    web AS (
        SELECT 'target'::text AS asset_kind, t.id,
               CASE WHEN t.discovery_source IS NOT DISTINCT FROM 'model-intake' THEN 'model' ELSE 'web' END AS kind,
               COALESCE(x.exposure_class, '{PROVISIONAL_EXPOSURE_CLASS}') AS exposure_class,
               COALESCE(x.cohort, '{PROVISIONAL_COHORT}') AS cohort, COALESCE(x.owner_present, false) AS owner_present,
               false AS ai_production, NULL::integer AS blast_static,
               t.created_at, COALESCE(t.total_scans, 0) AS total_scans,
               COALESCE(ls.completed_at, t.last_scanned_at) AS last_scanned_at,
               ls.id AS latest_scan_id, ls.status AS latest_scan_status, ls.scan_type AS latest_scan_type,
               ls.completion_status, ls.top_coverage_status, {limited} AS scan_limited,
               COALESCE(c.total, 0) AS total, COALESCE(c.crit, 0) AS crit, COALESCE(c.high, 0) AS high,
               (COALESCE(pr.verified, 0) + COALESCE(adj.dv, 0))::bigint AS verified,
               (COALESCE(pr.investigator_verified, 0) + COALESCE(adj.di, 0))::bigint AS investigator_verified,
               (COALESCE(c.total, 0) - COALESCE(st.n, 0) - COALESCE(pr.verified_needs, 0)
                + COALESCE(adj.dn, 0))::bigint AS proof_needs,
               COALESCE(sus.n, 0)::bigint AS suspected
        FROM targets t
        LEFT JOIN exposure_target_facts x ON x.target_id = t.id
        {_latest_scan_sql("s.target_id = t.id AND (s.scan_role IS NULL OR s.scan_role <> 'shard')")}
        LEFT JOIN web_counts c ON c.asset_id = t.id
        LEFT JOIN web_settled st ON st.asset_id = t.id
        LEFT JOIN web_proof pr ON pr.asset_id = t.id
        LEFT JOIN web_suspected sus ON sus.asset_id = t.id
        LEFT JOIN adj ON adj.asset_kind = 'target' AND adj.asset_id = t.id
        WHERE {p_web} AND t.is_active = true
          AND ({p_root}::text IS NULL OR t.root_domain = {p_root}::text)
          AND ({p_web_kind}::text IS NULL
               OR ({p_web_kind}::text = 'model') = (t.discovery_source IS NOT DISTINCT FROM 'model-intake'))
    ),
    ai_counts AS ({asset_finding_counts_sql("ai_target_id", proof_scope="f.target_id IS NULL")}),
    ai AS (
        SELECT 'ai'::text AS asset_kind, a.id, 'ai'::text AS kind,
               COALESCE(x.exposure_class, '{PROVISIONAL_EXPOSURE_CLASS}') AS exposure_class,
               COALESCE(x.cohort, '{PROVISIONAL_COHORT}') AS cohort, COALESCE(x.owner_present, false) AS owner_present,
               (COALESCE(a.production_mode, false) OR COALESCE(x.environment_production, false)) AS ai_production,
               COALESCE(x.blast_static_score, 0) AS blast_static,
               a.created_at, COALESCE(sc.n, 0) AS total_scans,
               COALESCE(ls.completed_at, a.last_scanned_at) AS last_scanned_at,
               ls.id AS latest_scan_id, ls.status AS latest_scan_status, ls.scan_type AS latest_scan_type,
               ls.completion_status, ls.top_coverage_status, {limited} AS scan_limited,
               COALESCE(c.active_total, 0) AS total, COALESCE(c.active_critical, 0) AS crit,
               COALESCE(c.active_high, 0) AS high,
               (COALESCE(c.proof_verified, 0) + COALESCE(adj.dv, 0))::bigint AS verified,
               0::bigint AS investigator_verified,
               (COALESCE(c.proof_needs_verification, 0) + COALESCE(adj.dn, 0))::bigint AS proof_needs,
               0::bigint AS suspected
        FROM ai_targets a
        LEFT JOIN exposure_ai_target_facts x ON x.ai_target_id = a.id
        {_latest_scan_sql("s.ai_target_id = a.id")}
        LEFT JOIN LATERAL (SELECT COUNT(*) AS n FROM scans s WHERE s.ai_target_id = a.id) sc ON true
        LEFT JOIN ai_counts c ON c.asset_id = a.id
        LEFT JOIN adj ON adj.asset_kind = 'ai' AND adj.asset_id = a.id
        WHERE {p_ai} AND a.is_active = true
          AND ({p_root}::text IS NULL OR LOWER(a.endpoint_url) LIKE '%' || LOWER({p_root}::text) || '%')
    ),
    assets AS (
        SELECT *,
               total_scans <= 0 OR last_scanned_at IS NULL AS never_scanned,
               last_scanned_at IS NOT NULL AND last_scanned_at <= {p_now}::timestamptz - interval '{STALE_DAYS} days' AS aged,
               COALESCE(latest_scan_status = 'failed', false) AS failed,
               COALESCE(scan_limited, false) AS limited,
               CASE WHEN kind = 'ai' THEN
                   CASE WHEN LEAST(100, blast_static + CASE WHEN total > 0 THEN LEAST(20, total * 5) ELSE 0 END) >= 75
                        THEN 'critical'
                        WHEN LEAST(100, blast_static + CASE WHEN total > 0 THEN LEAST(20, total * 5) ELSE 0 END) >= 55
                        THEN 'high' ELSE 'other' END
               END AS blast_tier
        FROM (SELECT * FROM web UNION ALL SELECT * FROM ai) unioned
    ),
    reasoned AS (
        SELECT *, array_remove(ARRAY[
                   CASE WHEN never_scanned THEN 'never_scanned' WHEN aged THEN 'stale_scan' END,
                   CASE WHEN failed THEN 'failed_scan' END,
                   CASE WHEN limited THEN 'incomplete_scan' END,
                   CASE WHEN crit > 0 THEN 'critical_findings' WHEN high > 0 THEN 'high_findings' END,
                   CASE WHEN exposure_class = 'public' AND (crit > 0 OR high > 0) THEN 'public_high_risk' END,
                   CASE WHEN kind = 'ai' AND ai_production AND (crit > 0 OR high > 0) THEN 'production_ai_risk' END,
                   CASE WHEN kind = 'ai' AND blast_tier IN ('high', 'critical') THEN 'high_blast_radius' END
               ]::text[], NULL) AS action_reasons
        FROM assets
    ),
    prioritized AS (
        SELECT *,
               CASE WHEN cardinality(action_reasons) = 0 THEN NULL
                    WHEN crit > 0 OR 'production_ai_risk' = ANY(action_reasons) THEN 'P1'
                    WHEN 'public_high_risk' = ANY(action_reasons) OR 'high_blast_radius' = ANY(action_reasons)
                         OR high > 0 THEN 'P2'
                    ELSE 'P3' END AS action_priority
        FROM reasoned
    ),
    scored AS (
        SELECT *,
               (CASE action_priority WHEN 'P1' THEN {PRIORITY_WEIGHT['P1']} WHEN 'P2' THEN {PRIORITY_WEIGHT['P2']}
                    WHEN 'P3' THEN {PRIORITY_WEIGHT['P3']} END
                + crit * 10 + high + CASE WHEN exposure_class = 'public' THEN 25 ELSE 0 END)
               AS priority_score,
               crit * 1000 + high * 50 + total AS risk_score,
               (created_at IS NOT NULL AND created_at > {p_now}::timestamptz - interval '{NEW_DAYS} days') AS is_new,
               CASE WHEN never_scanned THEN 'unscanned' WHEN failed THEN 'failed' WHEN limited THEN 'limited'
                    WHEN aged THEN 'stale' ELSE 'fresh' END AS coverage_posture,
               proof_needs + suspected AS needs_verification
        FROM prioritized
    ),
    ranked AS (
        SELECT *, COALESCE(priority_score, 0)::bigint AS action_score, is_new::int AS is_new_rank FROM scored
    )"""


def _cohort_filter(params: SqlParams, cohort: str | None) -> str:
    selected = str(cohort or "all")
    if selected == "all":
        return "TRUE"
    allowed = list(COHORT_GROUPS.get(selected, (selected,)))
    return f"r.cohort = ANY({params.add(allowed)}::text[])"


METRICS_SQL = """
    count(*)::bigint AS asset_count,
    COALESCE(sum(crit), 0)::bigint AS active_critical,
    COALESCE(sum(high), 0)::bigint AS active_high,
    COALESCE(sum(verified), 0)::bigint AS active_verified,
    COALESCE(sum(needs_verification), 0)::bigint AS active_needs_verification,
    count(*) FILTER (WHERE kind = 'ai')::bigint AS ai_surfaces,
    count(*) FILTER (WHERE kind = 'web')::bigint AS web_targets,
    count(*) FILTER (WHERE kind = 'model')::bigint AS model_artifacts,
    count(*) FILTER (WHERE exposure_class = 'public')::bigint AS public_assets,
    count(*) FILTER (WHERE exposure_class = 'internal')::bigint AS internal_assets,
    count(*) FILTER (WHERE 'never_scanned' = ANY(action_reasons))::bigint AS unscanned_assets,
    count(*) FILTER (WHERE 'stale_scan' = ANY(action_reasons))::bigint AS stale_assets,
    count(*) FILTER (WHERE 'incomplete_scan' = ANY(action_reasons))::bigint AS incomplete_scans,
    count(*) FILTER (WHERE 'failed_scan' = ANY(action_reasons))::bigint AS failed_scans,
    count(*) FILTER (WHERE coverage_posture = 'fresh')::bigint AS fresh_scans,
    count(*) FILTER (WHERE verified > 0)::bigint AS verified_assets,
    count(*) FILTER (WHERE investigator_verified > 0)::bigint AS investigator_verified_assets,
    count(*) FILTER (WHERE suspected > 0)::bigint AS investigator_suspected_assets,
    count(*) FILTER (WHERE needs_verification > 0 AND crit + high > 0)::bigint AS unverified_high_assets,
    count(*) FILTER (WHERE NOT owner_present)::bigint AS unowned_assets,
    count(*) FILTER (WHERE cardinality(action_reasons) > 0)::bigint AS needs_action,
    count(*) FILTER (WHERE action_priority = 'P1')::bigint AS p1_count,
    count(*) FILTER (WHERE action_priority = 'P2')::bigint AS p2_count,
    count(*) FILTER (WHERE action_priority = 'P3')::bigint AS p3_count,
    count(*) FILTER (WHERE kind = 'ai' AND ai_production)::bigint AS prod_ai_surfaces,
    count(*) FILTER (WHERE kind = 'ai' AND blast_tier IN ('high', 'critical'))::bigint AS high_blast_ai_surfaces,
    count(*) FILTER (WHERE is_new)::bigint AS new_count"""
METRIC_NAMES = tuple(
    line.strip().rsplit(" AS ", 1)[1].rstrip(",") for line in METRICS_SQL.strip().splitlines()
)

# The page columns: ranking values plus what the response builds each row from. Page rows only
# read their target's (or AI target's) own columns.
_PAGE_COLUMNS = """
    r.asset_kind, r.id, r.kind, r.exposure_class, r.cohort, r.created_at, r.total_scans, r.last_scanned_at,
    r.latest_scan_id, r.latest_scan_status, r.latest_scan_type, r.completion_status, r.top_coverage_status,
    r.total, r.crit, r.high, r.verified, r.investigator_verified, r.suspected, r.needs_verification,
    r.action_reasons, r.action_priority, r.action_score, r.risk_score, r.is_new, r.coverage_posture"""
_DETAIL_JOINS = """
    LEFT JOIN targets t ON page.asset_kind = 'target' AND t.id = page.id
    LEFT JOIN ai_targets a ON page.asset_kind = 'ai' AND a.id = page.id"""
_DETAIL_COLUMNS = f"""
    t.url, t.name, t.root_domain, t.discovery_source, t.last_grade, t.last_score,
    a.name AS ai_name, a.endpoint_url, a.target_type, a.production_mode,
    CASE WHEN page.asset_kind = 'target' THEN {metadata_subset_sql('t.metadata_json', TARGET_METADATA_KEYS)}
         ELSE {metadata_subset_sql('a.metadata_json', AI_METADATA_KEYS)} END AS metadata_json"""

ORDER_SQL = "action_score DESC, risk_score DESC, is_new_rank DESC, id DESC"


def offset_page_sql(params: SqlParams, *, root_domain: str | None, kind: str | None, cohort: str | None,
                    now: datetime, adjustments: Mapping[tuple[str, str], Mapping[str, int]],
                    limit: int, offset: int) -> str:
    """One statement: the metrics and cohort counts (on every row; one row when the page is empty)
    and the requested limit/offset page in rank order."""
    ranked = _ranked_sql(params, root_domain=root_domain, kind=kind, now=now, adjustments=adjustments)
    where = _cohort_filter(params, cohort)
    p_limit, p_offset = params.add(limit), params.add(offset)
    return f"""WITH {ranked},
    selected AS (SELECT * FROM ranked r WHERE {where}),
    metrics AS (SELECT {METRICS_SQL} FROM selected),
    cohorts AS (SELECT COALESCE(jsonb_object_agg(cohort, n), '{{}}'::jsonb) AS cohort_counts
                FROM (SELECT cohort, count(*) AS n FROM ranked GROUP BY cohort) c),
    page AS (SELECT {_PAGE_COLUMNS}, row_number() OVER (ORDER BY {ORDER_SQL}) AS position
             FROM selected r ORDER BY {ORDER_SQL} LIMIT {p_limit} OFFSET {p_offset})
    SELECT m.*, cohorts.cohort_counts, page.*, {_DETAIL_COLUMNS}
    FROM metrics m CROSS JOIN cohorts
    LEFT JOIN page ON true
    {_DETAIL_JOINS}
    ORDER BY page.position"""


# list/v1: sort keys over the ranked columns (``s`` is the selected set).
ASSETS_LIST = ListSpec(
    scope="exposure_assets",
    sorts={
        "priority": SortKey("s.action_score", "int", then=(("s.risk_score", "int"), ("s.is_new_rank", "int"))),
        "risk": SortKey("s.risk_score", "int"),
        "first_seen": SortKey("COALESCE(s.created_at, 'epoch'::timestamptz)", "datetime"),
    },
    default_sort="-priority",
    # Every field is built in Python from the page row; the map only declares the names.
    fields={name: "NULL" for name in (
        "id", "node_id", "kind", "label", "url", "root_domain", "origin", "target_type", "production_mode",
        "exposure_class", "cohort", "owner", "environment", "risk_tier", "data_classification",
        "blast_radius_score", "blast_radius_tier", "blast_radius_factors", "missing_runtime_controls",
        "grade", "score", "active_total", "active_critical", "active_high", "active_verified",
        "active_needs_verification", "investigator_verified_count", "investigator_suspected_count",
        "total_scans", "last_scanned_at", "latest_scan_id", "latest_scan_status", "latest_scan_type",
        "latest_scan_href", "scan_complete", "scan_limited", "coverage_status", "coverage_posture",
        "skipped_modules_count", "capped_lists_count", "scan_age_days", "action_reasons", "needs_action",
        "action_priority", "action_score", "recommended_actions", "first_seen_at", "is_new", "risk_score",
        "findings_href",
    )},
    id_expr="s.id",
)


def keyset_page_sql(params: SqlParams, plan: Any, *, root_domain: str | None, kind: str | None,
                    cohort: str | None, now: datetime,
                    adjustments: Mapping[tuple[str, str], Mapping[str, int]]) -> str:
    """The list/v1 statement: metrics and cohort counts, then ``plan.fetch_limit`` rows after the
    cursor in the plan's order (keyset over the ranked set)."""
    ranked = _ranked_sql(params, root_domain=root_domain, kind=kind, now=now, adjustments=adjustments)
    where = _cohort_filter(params, cohort)
    keyset = plan.keyset_clauses(params)
    page_where = " AND ".join(keyset) if keyset else "TRUE"
    return f"""WITH {ranked},
    selected AS (SELECT * FROM ranked r WHERE {where}),
    metrics AS (SELECT {METRICS_SQL} FROM selected),
    cohorts AS (SELECT COALESCE(jsonb_object_agg(cohort, n), '{{}}'::jsonb) AS cohort_counts
                FROM (SELECT cohort, count(*) AS n FROM ranked GROUP BY cohort) c),
    page AS (SELECT {_PAGE_COLUMNS.replace('r.', 's.')}, {plan.keyset_select},
                    row_number() OVER (ORDER BY {plan.order_by}) AS position
             FROM selected s WHERE {page_where} ORDER BY {plan.order_by} LIMIT {plan.fetch_limit})
    SELECT m.*, cohorts.cohort_counts, page.*, {_DETAIL_COLUMNS}
    FROM metrics m CROSS JOIN cohorts
    LEFT JOIN page ON true
    {_DETAIL_JOINS}
    ORDER BY page.position"""


def metrics_from(row: Mapping[str, Any]) -> tuple[dict[str, int], int]:
    metrics = {name: int(row[name]) for name in METRIC_NAMES if name != "new_count"}
    return metrics, int(row["new_count"])


def adjustment_rows_sql() -> str:
    """Every active row whose proof only Python decides (the partial index finds the few)."""
    try:
        from finding_routes.list_query import INDEXED_UNDETERMINED_SQL
        from finding_routes.proof_sql import latest_retest_mode_sql
    except ModuleNotFoundError:  # package import in host-side tests
        from ..finding_routes.list_query import INDEXED_UNDETERMINED_SQL
        from ..finding_routes.proof_sql import latest_retest_mode_sql
    return f"""
        SELECT f.target_id, f.ai_target_id, f.status, f.severity, f.tool, f.evidence,
               f.last_verification_verdict, f.analyst_verdict,
               {latest_retest_mode_sql(finding_id="f.id", verdict="f.last_verification_verdict")}
                   AS latest_retest_mode
        FROM findings f
        WHERE f.status = 'active' AND {INDEXED_UNDETERMINED_SQL}
          AND (f.target_id IS NOT NULL OR f.ai_target_id IS NOT NULL)"""


def stringify_keys(adjustments: Mapping[tuple[str, str], Any]) -> dict[tuple[str, str], Any]:
    return {(kind, str(asset_id)): value for (kind, asset_id), value in adjustments.items()}


__all__ = [
    "AI_METADATA_KEYS", "ASSETS_LIST", "COHORT_GROUPS", "EXPOSURE_SCALE_INDEXES", "FACTS_VERSION", "FRESH_STATE",
    "INVESTIGATOR_TOOLS", "METRIC_NAMES", "PRIORITY_WEIGHT", "TARGET_METADATA_KEYS", "adjustment_rows_sql",
    "ai_target_facts", "complete_facts_in_background", "exposure_class", "facts_pending", "install_exposure_facts",
    "keyset_page_sql", "metadata_subset_sql", "metrics_from", "offset_page_sql", "refresh_facts",
    "refresh_facts_tick", "stringify_keys", "target_facts",
]

