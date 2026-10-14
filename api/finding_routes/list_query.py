"""GET /findings query building: filters over ``findings`` alone, a bounded page, then its rows.

Both response shapes share this module:

* the deprecated ``limit``/``offset`` shape (``{findings, total, limit, offset, ...}``), kept for the
  2.11 line for the UI, the client, MCP ``shakerscan_findings`` and the gateway;
* the list contract (``list/v1``: ``limit``/``cursor``/``sort``/``fields``/``count``/``since``,
  ``{items, next_cursor, has_more, total?, total_kind, generated_at}``), chosen by sending any
  of its own parameters.

Every filter is a predicate on ``findings f`` (a filter on the joined target, AI target or device
becomes ``f.<fk> = ANY(ARRAY(SELECT id ...))``), so the page query reads only findings and an
index can produce its order. The page is chosen first (ids only, ``ORDER BY ... LIMIT``) and the
row columns, the target labels, the latest retest (one LATERAL probe per page row) and the proof
projection are computed for that page alone. Nothing per row runs over the whole match set, and
the total is a separate COUNT over the same filters (the legacy shape) or ``count_total`` (the
list contract: none, a planner estimate, or exact up to 10,000).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Iterable, Mapping, Optional
import uuid

from fastapi import HTTPException

try:
    from list_contract import EXACT_COUNT_CAP, ListPlan, ListSpec, Page, SortKey, SqlParams, count_total
except ModuleNotFoundError:  # package import in host-side tests
    from ..list_contract import EXACT_COUNT_CAP, ListPlan, ListSpec, Page, SortKey, SqlParams, count_total

from .hunt_scope import finding_hunt_predicate
from .list_filters import host_in_domain_sql
from .list_schema import FIRST_SEEN_SORT_SQL, LAST_SEEN_SORT_SQL
from .proof_sql import (
    latest_retest_mode_sql, proof_state_sql, triage_string_sql, undetermined_proof_sql,
    verified_candidate_sql, verified_sql,
)

#: Findings columns a list row carries (every column but the detail bodies and severity_rank).
FINDING_SUMMARY_COLUMNS: tuple[str, ...] = (
    "id", "scan_id", "first_seen_scan_id", "last_seen_scan_id", "target_id", "ai_target_id",
    "device_target_id", "hunt_run_id", "fingerprint", "title", "severity", "cvss_score", "tool",
    "cwe", "cwe_name", "owasp", "url", "status", "first_seen_at", "last_seen_at", "resolved_at",
    "resurfaced_count", "ai_verdict", "ai_confidence", "last_verification_status",
    "last_verification_verdict", "last_verification_confidence", "last_verified_at",
    "verification_count", "source", "session_id", "created_at", "updated_at",
    "ai_classification_source", "analyst_verdict", "analyst_verdict_at",
)
#: Served by GET /findings/{id}; the legacy list returns them only with include_details=true.
FINDING_DETAIL_COLUMNS: tuple[str, ...] = (
    "description", "evidence", "request", "response", "ai_rationale", "ai_recommendations",
    "notes", "analyst_verdict_notes",
)

ROW_JOINS_SQL = """
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            LEFT JOIN device_targets dt ON f.device_target_id = dt.id
            LEFT JOIN LATERAL (
                SELECT status, result_status, verdict, confidence, completed_at, verification_mode
                FROM finding_verifications
                WHERE finding_id=f.id
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            ) latest_retest ON TRUE"""

# The latest retest's mode as the proof projection reads it, from the row's LATERAL.
LATEST_RETEST_MODE_SQL = "CASE WHEN latest_retest.verdict IS NOT NULL THEN latest_retest.verification_mode END"

#: Columns a row adds beyond findings: its target and its latest retest.
ROW_EXTRA_COLUMNS: dict[str, str] = {
    "target_url": "COALESCE(t.url, ait.endpoint_url, dt.primary_locator)",
    "target_name": "COALESCE(t.name, ait.name, dt.name)",
    "root_domain": "t.root_domain",
    "ai_target_url": "ait.endpoint_url",
    "ai_target_name": "ait.name",
    "latest_retest_status": "latest_retest.status",
    "latest_retest_result_status": "latest_retest.result_status",
    "latest_retest_verdict": "COALESCE(latest_retest.verdict, f.last_verification_verdict)",
    "latest_retest_confidence": "COALESCE(latest_retest.confidence, f.last_verification_confidence)",
    "latest_retest_completed_at": "COALESCE(latest_retest.completed_at, f.last_verified_at)",
    "latest_retest_mode": LATEST_RETEST_MODE_SQL,
}

# The proof projection for a fetched row (latest retest from the LATERAL) ...
PROOF_STATE_ROW_SQL = proof_state_sql(
    evidence="f.evidence", severity="f.severity",
    verdict="f.last_verification_verdict", retest_mode=LATEST_RETEST_MODE_SQL,
)
# ... and as a filter over findings alone (the retest is looked up only where it can matter).
PROOF_STATE_FILTER_SQL = proof_state_sql(
    evidence="f.evidence", severity="f.severity", verdict="f.last_verification_verdict",
    retest_mode=latest_retest_mode_sql(finding_id="f.id", verdict="f.last_verification_verdict"),
)
# proof_state = 'verified' alone, through the partial index idx_findings_proof_candidates.
VERIFIED_CANDIDATE_SQL = verified_candidate_sql(evidence="f.evidence", verdict="f.last_verification_verdict")
VERIFIED_FILTER_SQL = (
    f"({VERIFIED_CANDIDATE_SQL} AND "
    + verified_sql(evidence="f.evidence", verdict="f.last_verification_verdict",
                   retest_mode=latest_retest_mode_sql(finding_id="f.id", verdict="f.last_verification_verdict"))
    + ")"
)
UNDETERMINED_SQL = undetermined_proof_sql("f.evidence")
# Undetermined rows through their partial index (idx_findings_triage_string).
INDEXED_UNDETERMINED_SQL = f"({triage_string_sql('f.evidence')} AND {UNDETERMINED_SQL})"

# Inputs the Python proof projection needs for an undetermined row, fetched for those rows only.
_PROOF_INPUT_COLUMNS = (
    f"{UNDETERMINED_SQL} AS _proof_undetermined, "
    f"CASE WHEN {UNDETERMINED_SQL} THEN f.evidence END AS _proof_evidence"
)
_PROOF_INPUT_KEYS = ("_proof_undetermined", "_proof_evidence")


@asynccontextmanager
async def without_jit(conn: Any) -> AsyncIterator[Any]:
    """A transaction with JIT off. The proof projection is one ~28 kB expression: LLVM compiles it
    whenever the planner's cost passes jit_above_cost, and that compile (about 2 s) costs more
    than the bounded query it would speed up."""
    async with conn.transaction():
        await conn.execute("SET LOCAL jit = off")
        yield conn


def _bad_request(message: str) -> HTTPException:
    return HTTPException(status_code=400, detail=message)


def _uuid(value: str, name: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except ValueError:
        raise _bad_request(f"{name} must be a UUID") from None


def _source_type_clause(source_type: Optional[str]) -> Optional[str]:
    """The ``source_type`` taxonomy (dast / device / ai / ai_gate / ai_session / deep_hunt /
    autonomous / model_intake / asm / manual), the same product taxonomy the UI exposes."""
    clauses = {
        "ai": "(f.source IN ('ai_gate', 'ai_session', 'autonomous') OR f.ai_target_id IS NOT NULL)",
        "ai_gate": "f.source = 'ai_gate'",
        "ai_session": "f.source = 'ai_session'",
        "deep_hunt": (
            "(f.source IN ('autonomous', 'deep_hunt')"
            " OR f.tool = 'autonomous_workflow'"
            " OR f.evidence->'research'->>'driven_by' = 'autonomous_research')"
        ),
        "autonomous": "(f.source = 'autonomous' OR f.tool = 'autonomous_workflow')",
        "model_intake": "(f.source = 'model_intake' OR f.tool = 'model_intake')",
        "asm": "f.source = 'asm'",
        "manual": "f.source = 'manual'",
        "device": "f.source = 'device'",
        "dast": (
            "(COALESCE(f.source, 'scan') NOT IN "
            "('ai_gate', 'ai_session', 'autonomous', 'deep_hunt', 'model_intake', 'asm', 'manual', 'device')"
            " AND f.ai_target_id IS NULL"
            " AND COALESCE(f.tool, '') NOT IN ('model_intake', 'autonomous_workflow')"
            " AND COALESCE(f.evidence->'research'->>'driven_by', '') <> 'autonomous_research')"
        ),
    }
    return clauses.get(source_type) if source_type else None


@dataclass(frozen=True)
class FindingFilters:
    """Every GET /findings filter except proof, already parsed."""

    severities: Optional[list[str]] = None
    status: Optional[str] = None
    source_type: Optional[str] = None
    target_id: Optional[str] = None
    ai_target_id: Optional[str] = None
    device_target_id: Optional[str] = None
    scan_id: Optional[str] = None
    hunt_id: Optional[str] = None
    root_domain: Optional[str] = None
    verification_verdict: Optional[str] = None
    verification_mode: Optional[str] = None
    verified_only: bool = False
    driven_by: Optional[str] = None
    research_campaign_id: Optional[str] = None
    search: Optional[str] = None
    seen_within_days: Optional[int] = None
    not_seen_within_days: Optional[int] = None
    first_seen_within_days: Optional[int] = None
    resolved_within_days: Optional[int] = None

    def fingerprint(self) -> dict[str, Any]:
        """The values a list/v1 cursor is bound to."""
        return {name: value for name, value in self.__dict__.items() if value not in (None, False)}

    def clauses(self, params: SqlParams) -> list[str]:
        """WHERE predicates over ``findings f`` only."""
        where: list[str] = []
        if self.severities:
            where.append(f"f.severity = ANY({params.add(self.severities)}::text[])")
        if self.status:
            where.append(f"f.status = {params.add(self.status)}")
        source = _source_type_clause(self.source_type)
        if source:
            where.append(source)
        if self.target_id:
            where.append(f"f.target_id = {params.add(_uuid(self.target_id, 'target_id'))}")
        if self.ai_target_id:
            where.append(f"f.ai_target_id = {params.add(_uuid(self.ai_target_id, 'ai_target_id'))}")
        if self.device_target_id:
            where.append(
                f"f.device_target_id = {params.add(_uuid(self.device_target_id, 'device_target_id'))}")
        if self.scan_id:
            where.append(f"f.scan_id = {params.add(_uuid(self.scan_id, 'scan_id'))}")
        if self.hunt_id:
            # A family-proof promotion may have no direct hunt_run_id. Its actual producing
            # verification is durable; another run's observation is not proof.
            params.add(_uuid(self.hunt_id, "hunt_id"))
            where.append(finding_hunt_predicate(len(params.values)))
        if self.root_domain:
            domain = params.add(self.root_domain)
            where.append(f"""(
                f.target_id = ANY(ARRAY(SELECT id FROM targets WHERE root_domain = {domain}))
                OR f.ai_target_id = ANY(ARRAY(SELECT id FROM ai_targets
                                             WHERE {host_in_domain_sql("endpoint_url", domain)}))
                OR f.device_target_id = ANY(ARRAY(SELECT id FROM device_targets
                                                 WHERE {host_in_domain_sql("primary_locator", domain)}))
            )""")
        if self.verification_verdict:
            where.append(f"f.last_verification_verdict = {params.add(self.verification_verdict)}")
        if self.verified_only:
            where.append("f.last_verification_verdict = 'exploited'")
        if self.driven_by == "autonomous_research":
            # Findings produced by research-driven work (a deep-hunt decision queued the scan that
            # found them), stamped by backfill_campaign_scan_finding_links. Distinct from
            # source_type='autonomous' (agent-native claims) and organic DAST (no marker).
            where.append("f.evidence->'research'->>'driven_by' = 'autonomous_research'")
        if self.research_campaign_id:
            campaign = _uuid(self.research_campaign_id, "research_campaign_id")
            where.append(f"f.evidence->'research'->>'campaign_id' = {params.add(str(campaign))}")
        if self.verification_mode:
            where.append(f"""EXISTS (
                SELECT 1 FROM finding_verifications fv2
                WHERE fv2.finding_id = f.id AND fv2.verification_mode = {params.add(self.verification_mode)}
            )""")
        if self.search:
            pattern = params.add(f"%{self.search}%")
            where.append(f"""(
                f.title ILIKE {pattern}
                OR f.url ILIKE {pattern}
                OR f.target_id = ANY(ARRAY(SELECT id FROM targets
                                          WHERE url ILIKE {pattern} OR name ILIKE {pattern}))
                OR f.ai_target_id = ANY(ARRAY(SELECT id FROM ai_targets
                                             WHERE endpoint_url ILIKE {pattern} OR name ILIKE {pattern}))
                OR f.device_target_id = ANY(ARRAY(SELECT id FROM device_targets
                                                 WHERE name ILIKE {pattern} OR primary_locator ILIKE {pattern}))
            )""")
        if self.seen_within_days:
            where.append(f"f.last_seen_at >= NOW() - INTERVAL '1 day' * {params.add(self.seen_within_days)}")
        if self.not_seen_within_days:
            where.append(f"f.last_seen_at < NOW() - INTERVAL '1 day' * {params.add(self.not_seen_within_days)}")
        if self.first_seen_within_days:
            where.append(
                f"f.first_seen_at >= NOW() - INTERVAL '1 day' * {params.add(self.first_seen_within_days)}")
        if self.resolved_within_days:
            where.append(
                f"f.resolved_at >= NOW() - INTERVAL '1 day' * {params.add(self.resolved_within_days)}")
        return where


def proof_filter_sql(proof_states: list[str], params: SqlParams) -> str:
    """WHERE clause for ``proof_state=...`` (decided rows; see ``has_undetermined``)."""
    if proof_states == ["verified"]:
        return VERIFIED_FILTER_SQL
    return f"{PROOF_STATE_FILTER_SQL} = ANY({params.add(proof_states)}::text[])"


def where_sql(clauses: Iterable[str]) -> str:
    clauses = list(clauses)
    return " AND ".join(clauses) if clauses else "TRUE"


async def has_undetermined(conn: Any, where: list[str], values: list[Any]) -> bool:
    """Whether any row the filters leave needs the Python proof projection (an index probe)."""
    return bool(await conn.fetchval(
        f"SELECT EXISTS (SELECT 1 FROM findings f WHERE {where_sql([*where, INDEXED_UNDETERMINED_SQL])})",
        *values,
    ))


def row_select_sql(*, details: bool) -> str:
    """The columns of one list row: findings summary (plus details), target and latest retest."""
    columns = [f"f.{name}" for name in FINDING_SUMMARY_COLUMNS]
    if details:
        columns += [f"f.{name}" for name in FINDING_DETAIL_COLUMNS]
    columns += [f"{expr} AS {name}" for name, expr in ROW_EXTRA_COLUMNS.items()]
    return ", ".join(columns)


def apply_proof(row: Mapping[str, Any], project: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    """A fetched row with ``proof_state``/``is_verified``/``is_suspected`` and no helper columns.

    The SQL projection (``_proof_state``) answers for every row except an undetermined one, which
    ``project`` (finding_proof_fields) answers from its evidence, fetched for that row only.
    """
    item = dict(row)
    state = item.pop("_proof_state", None)
    undetermined = item.pop("_proof_undetermined", False)
    evidence = item.pop("_proof_evidence", None)
    if undetermined:
        fields = project({
            "evidence": evidence, "severity": item.get("severity"),
            "last_verification_verdict": item.get("last_verification_verdict"),
            "latest_retest_mode": item.get("latest_retest_mode"),
        })
    else:
        fields = {"is_verified": state == "verified", "is_suspected": state == "suspected",
                  "proof_state": state}
    item.update(fields)
    return item


# --- legacy limit/offset shape -----------------------------------------------------------------


def legacy_order(sort_by: Optional[str], sort_order: str) -> list[tuple[str, str]]:
    """``[(expression, direction)]`` with an id tiebreak, as the legacy list has always sorted.

    Descending severity and seen-time orders use the keyset index expressions (a NULL time sorts
    last either way); an ascending seen time keeps NULLS LAST, which the COALESCE form cannot.
    """
    direction = "DESC" if sort_order == "desc" else "ASC"
    if sort_by in ("first_seen", "last_seen"):
        column = "f.first_seen_at" if sort_by == "first_seen" else "f.last_seen_at"
        indexed = FIRST_SEEN_SORT_SQL if sort_by == "first_seen" else LAST_SEEN_SORT_SQL
        if direction == "DESC":
            return [(indexed, "DESC"), ("f.id", "DESC")]
        return [(column, "ASC NULLS LAST"), ("f.id", "ASC")]
    if sort_by == "cvss":
        return [("f.cvss_score", f"{direction} NULLS LAST"), ("f.id", direction)]
    # Severity (most severe first for desc); the newest sighting first within a severity always.
    return [("f.severity_rank", direction), (LAST_SEEN_SORT_SQL, "DESC"), ("f.id", "DESC")]


def order_sql(order: list[tuple[str, str]]) -> str:
    return ", ".join(f"{expr} {direction}" for expr, direction in order)


async def legacy_page(
    conn: Any, *, where: list[str], values: list[Any], order: list[tuple[str, str]],
    limit: int, offset: int, details: bool, project: Callable[[dict[str, Any]], dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """``(rows, total)``: ids by ``ORDER BY ... LIMIT/OFFSET``, then those rows' columns."""
    params = SqlParams(values)
    page_ids = await conn.fetch(
        f"SELECT f.id FROM findings f WHERE {where_sql(where)} ORDER BY {order_sql(order)}"
        f" LIMIT {params.add(limit)} OFFSET {params.add(offset)}",
        *params.values,
    )
    ids = [row["id"] for row in page_ids]
    if len(ids) < limit and (ids or offset == 0):
        total = offset + len(ids)
    else:
        total = int(await conn.fetchval(
            f"SELECT count(*) FROM findings f WHERE {where_sql(where)}", *values,
        ) or 0)
    if not ids:
        return [], total
    rows = await conn.fetch(
        f"""SELECT {row_select_sql(details=details)},
                   {PROOF_STATE_ROW_SQL} AS _proof_state, {_PROOF_INPUT_COLUMNS}
            FROM unnest($1::uuid[]) WITH ORDINALITY AS page(id, ord)
            JOIN findings f ON f.id = page.id
            {ROW_JOINS_SQL}
            ORDER BY page.ord""",
        ids,
    )
    return [apply_proof(row, project) for row in rows], total


def legacy_stream_sql(where: list[str], order: list[tuple[str, str]]) -> str:
    """Every matching row with the columns the Python projection reads (the undetermined path)."""
    return (
        f"SELECT {row_select_sql(details=True)} FROM findings f {ROW_JOINS_SQL}"
        f" WHERE {where_sql(where)} ORDER BY {order_sql(order)}"
    )


# --- list/v1 ----------------------------------------------------------------------------------

LIST_V1_PARAMETERS = frozenset({"cursor", "sort", "fields", "count", "since"})
LEGACY_ONLY_PARAMETERS = frozenset({"offset", "sort_by", "sort_order", "include_details", "include_candidates"})

_V1_FIELDS: dict[str, str] = {
    **{name: f"f.{name}" for name in FINDING_SUMMARY_COLUMNS},
    **ROW_EXTRA_COLUMNS,
    "proof_state": PROOF_STATE_ROW_SQL,
    "is_verified": f"({PROOF_STATE_ROW_SQL}) = 'verified'",
    "is_suspected": f"({PROOF_STATE_ROW_SQL}) = 'suspected'",
}

FINDINGS_LIST = ListSpec(
    scope="findings",
    sorts={
        # Most severe first, then most recently seen: one descending keyset over
        # idx_findings_severity_keyset.
        "severity": SortKey("f.severity_rank", "int", then=((LAST_SEEN_SORT_SQL, "datetime"),)),
        "last_seen": SortKey(LAST_SEEN_SORT_SQL, "datetime"),
        "first_seen": SortKey(FIRST_SEEN_SORT_SQL, "datetime"),
        "cvss": SortKey("COALESCE(f.cvss_score, -1)", "numeric"),
    },
    default_sort="-severity",
    fields=_V1_FIELDS,
    id_expr="f.id",
    since_expr="f.updated_at",
    table="findings",
)


async def v1_page(
    conn: Any, page: Page, *, filters: FindingFilters, proof_states: Optional[list[str]],
    project: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """One list/v1 page of findings (summary projection only, never evidence or bodies)."""
    plan = FINDINGS_LIST.plan(page, filters={**filters.fingerprint(), "proof_state": proof_states})
    params = SqlParams()
    where = filters.clauses(params)
    where += plan.filter_clauses(params)
    undetermined = False
    if proof_states:
        undetermined = await has_undetermined(conn, where, params.snapshot())
        proof_clause = proof_filter_sql(proof_states, params)
        # An undetermined row's proof is decided in Python below, so the SQL keeps it for that.
        where.append(f"({proof_clause} OR {INDEXED_UNDETERMINED_SQL})" if undetermined else proof_clause)
    count_values = params.snapshot()

    kept: list[dict[str, Any]] = []
    current: ListPlan = plan
    while True:
        page_params = SqlParams(count_values)
        page_where = where + current.keyset_clauses(page_params)
        rows = await conn.fetch(
            f"""SELECT {current.select_list}, {_PROOF_INPUT_COLUMNS},
                       f.severity AS _proof_severity, f.last_verification_verdict AS _proof_verdict,
                       {LATEST_RETEST_MODE_SQL} AS _proof_mode
                FROM (SELECT f.id FROM findings f WHERE {where_sql(page_where)}
                      ORDER BY {current.order_by} LIMIT {current.fetch_limit}) page
                JOIN findings f ON f.id = page.id
                {ROW_JOINS_SQL}
                ORDER BY {current.order_by}""",
            *page_params.values,
        )
        for row in rows:
            item = dict(row)
            severity = item.pop("_proof_severity")
            verdict = item.pop("_proof_verdict")
            mode = item.pop("_proof_mode")
            if item.pop("_proof_undetermined"):
                fields = project({"evidence": item.pop("_proof_evidence"), "severity": severity,
                                  "last_verification_verdict": verdict, "latest_retest_mode": mode})
                if proof_states and fields["proof_state"] not in proof_states:
                    continue
                for name in ("proof_state", "is_verified", "is_suspected"):
                    if name in item:
                        item[name] = fields[name]
            else:
                item.pop("_proof_evidence")
            kept.append(item)
        # Only a dropped undetermined row can leave the page short while rows remain.
        if len(kept) > page.limit or len(rows) < current.fetch_limit:
            break
        current = current.after(rows[-1])

    total, kind = await _v1_total(conn, page, where=where, values=count_values,
                                  undetermined=undetermined, proof_states=proof_states, project=project)
    return plan.envelope(kept, total=total, total_kind=kind)


async def _v1_total(
    conn: Any, page: Page, *, where: list[str], values: list[Any], undetermined: bool,
    proof_states: Optional[list[str]], project: Callable[[dict[str, Any]], dict[str, Any]],
) -> tuple[Optional[int], str]:
    if page.count != "exact" or not undetermined:
        return await count_total(conn, page.count, from_sql="findings f", where=where,
                                 values=values, table="findings")
    # Exact with undetermined rows: SQL counts the decided rows, Python the undetermined ones.
    decided, kind = await count_total(conn, "exact", from_sql="findings f",
                                      where=[*where, f"NOT {UNDETERMINED_SQL}"], values=values)
    if kind == "at_least":
        return decided, kind
    rows = await conn.fetch(
        f"""SELECT f.evidence, f.severity, f.last_verification_verdict,
                   {latest_retest_mode_sql(finding_id='f.id', verdict='f.last_verification_verdict')}
                       AS latest_retest_mode
            FROM findings f WHERE {where_sql([*where, INDEXED_UNDETERMINED_SQL])}
            LIMIT {EXACT_COUNT_CAP + 1}""",
        *values,
    )
    extra = sum(1 for row in rows if project(dict(row))["proof_state"] in (proof_states or ()))
    found = decided + extra
    if found > EXACT_COUNT_CAP:
        return EXACT_COUNT_CAP, "at_least"
    return found, "exact"


__all__ = [
    "FINDINGS_LIST",
    "FINDING_DETAIL_COLUMNS",
    "FINDING_SUMMARY_COLUMNS",
    "FindingFilters",
    "LEGACY_ONLY_PARAMETERS",
    "LIST_V1_PARAMETERS",
    "PROOF_STATE_FILTER_SQL",
    "PROOF_STATE_ROW_SQL",
    "ROW_JOINS_SQL",
    "UNDETERMINED_SQL",
    "VERIFIED_CANDIDATE_SQL",
    "apply_proof",
    "has_undetermined",
    "legacy_order",
    "legacy_page",
    "legacy_stream_sql",
    "proof_filter_sql",
    "v1_page",
    "without_jit",
]
