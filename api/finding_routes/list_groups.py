"""GET /findings?group_by=issue: the findings list as groups of repeats, grouped in SQL.

A group is the findings that are the same issue on the same subject in the same proof and triage
state: the same trimmed, lower-cased title, severity, subject (the target, AI target or device
target id, else the host of the finding's URL), proof_state and status. This is the key the
Findings page used to compute in the browser over one loaded page (``findingGroupKey`` in
ui/src/lib/findingGroups.ts); here it covers every finding the filters match, so a group's count
is the whole group and the group count is every group.

The request is the list/v1 request of GET /findings (the same filters, ``sort``, ``limit``,
``cursor``, ``count``, ``since``) plus ``group_by=issue``; ``fields`` is refused. The answer is the
list/v1 envelope whose items are groups::

    {"title_key", "severity", "subject", "proof_state", "status",   # the group key
     "count",                                                       # members under the filters
     "first_seen_at", "last_seen_at",                               # min / max over members
     "lead": {...},              # the first member in the requested sort, as a list/v1 row
     "member_ids": [...],        # the first GROUP_MEMBER_LIMIT members, lead first, in that order
     "member_ids_truncated": bool,
     "members": [{"id", "url", "last_seen_at", "latest_retest_verdict"}, ...]}  # same order

plus ``findings_total`` (members over every group) beside ``total`` when a count is requested.
Groups are ordered by their lead's position in the requested sort, which is the order the browser
gave them: walking the findings in that sort, a group appears where its first member does. The
cursor is bound to the filters, the sort and ``group_by`` (list_contract), and continues after the
previous page's last lead.

Cost. A group's count and lead depend on every member, so each page groups the whole match set:
one pass over the filtered findings computing the key (the proof projection included) and one
aggregate. That is linear in the matches (about 1.4 s for 430k matching findings, most of it the
key and proof expressions), so the route is an admission-controlled heavy read (request_guards)
under the heavy statement timeout. Only the page's
groups then read their lead rows and member locations. The group count comes from the same
aggregate, so a requested count is always exact.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from fastapi import HTTPException

try:
    from list_contract import ListSpec, Page, SortKey, SqlParams, snapshot_time
except ModuleNotFoundError:  # package import in host-side tests
    from ..list_contract import ListSpec, Page, SortKey, SqlParams, snapshot_time

from .list_query import (
    FINDINGS_LIST,
    FINDINGS_LIST_UNRANKED,
    PROOF_STATE_FILTER_SQL,
    ROW_JOINS_SQL,
    V1_PROOF_INPUT_COLUMNS,
    V1_ROW_SELECT_SQL,
    FindingFilters,
    finish_v1_row,
    resolved_proof_filter,
    undetermined_proof_states,
    where_sql,
)

GROUP_BY_VALUES = ("issue",)
#: Members listed per group (the lead first); ``member_ids_truncated`` says when there are more.
GROUP_MEMBER_LIMIT = 50

# String.prototype.trim() removes ECMAScript WhiteSpace and LineTerminator characters.
_JS_WHITESPACE = (
    "U&'\\0009\\000A\\000B\\000C\\000D\\0020\\00A0\\1680\\2000\\2001\\2002\\2003\\2004\\2005"
    "\\2006\\2007\\2008\\2009\\200A\\2028\\2029\\202F\\205F\\3000\\FEFF'"
)
TITLE_KEY_SQL = f"lower(btrim(COALESCE(f.title, ''), {_JS_WHITESPACE}))"

# The host the browser's URL parser gives for an absolute URL with an authority: no userinfo, the
# special schemes' host lower-cased and their default port dropped. Anything else has no host.
_SCHEME_SQL = r"lower(substring(f.url from '^([A-Za-z][A-Za-z0-9+.\-]*)://'))"
_AUTHORITY_HOST_SQL = r"substring(f.url from '^[A-Za-z][A-Za-z0-9+.\-]*://(?:[^/?#\\]*@)?([^/?#\\]*)')"
URL_HOST_SQL = f"""(CASE
    WHEN {_SCHEME_SQL} IN ('http', 'https', 'ws', 'wss', 'ftp') THEN regexp_replace(
        lower({_AUTHORITY_HOST_SQL}),
        CASE {_SCHEME_SQL} WHEN 'http' THEN ':(80)?$' WHEN 'ws' THEN ':(80)?$'
                           WHEN 'https' THEN ':(443)?$' WHEN 'wss' THEN ':(443)?$'
                           ELSE ':(21)?$' END,
        '')
    WHEN {_SCHEME_SQL} IS NOT NULL THEN {_AUTHORITY_HOST_SQL}
    END)"""
# The joined target URL only exists when one of the ids does, and an id comes first.
SUBJECT_KEY_SQL = (
    "COALESCE(f.target_id::text, f.ai_target_id::text, f.device_target_id::text, "
    f"NULLIF({URL_HOST_SQL}, ''), '')"
)

_KEY_COLUMNS = ("k_title", "k_severity", "k_subject", "k_proof", "k_status")
_SORT_COLUMNS = ("lead_s0", "lead_s1", "lead_s2")


def _group_sorts() -> dict[str, SortKey]:
    """The findings list's sort names over the groups' lead values (same kinds, same cursor shape)."""
    sorts: dict[str, SortKey] = {}
    for name, key in FINDINGS_LIST.sorts.items():
        kinds = [kind for _expr, kind in key.columns]
        sorts[name] = SortKey(
            f"g.{_SORT_COLUMNS[0]}", kinds[0],
            then=tuple((f"g.{_SORT_COLUMNS[index]}", kind) for index, kind in enumerate(kinds[1:], 1)),
        )
    return sorts


#: The grouped list: its own cursor scope, the findings list's sort names, the lead id tiebreaker.
FINDING_GROUPS_LIST = ListSpec(
    scope="findings_groups",
    sorts=_group_sorts(),
    default_sort=FINDINGS_LIST.default_sort,
    fields={
        "title_key": "g.k_title", "severity": "g.k_severity", "subject": "g.k_subject",
        "proof_state": "g.k_proof", "status": "g.k_status", "count": "g.member_count",
        "first_seen_at": "g.first_seen_at", "last_seen_at": "g.last_seen_at", "lead": "g.lead_id",
        "member_ids": "g.member_ids", "member_ids_truncated": "g.member_count",
        "members": "g.member_ids",
    },
    id_expr="g.lead_id",
    since_expr="f.updated_at",
)


def _bad_request(error: str, message: str) -> HTTPException:
    return HTTPException(status_code=400, detail={"error": error, "message": message})


def parse_group_by(value: Optional[str]) -> Optional[str]:
    """``issue``, or None when absent; anything else is a 400."""
    if value is None:
        return None
    chosen = str(value).strip().lower()
    if chosen not in GROUP_BY_VALUES:
        raise _bad_request("invalid_group_by", f"group_by must be one of {', '.join(GROUP_BY_VALUES)}")
    return chosen


async def groups_page(
    conn: Any, page: Page, *, filters: FindingFilters, proof_states: Optional[list[str]],
    project: Callable[[dict[str, Any]], dict[str, Any]], ranked: bool = True, group_by: str = "issue",
) -> dict[str, Any]:
    """One list/v1 page of finding groups (summary rows only, never evidence or bodies)."""
    if page.fields is not None:
        raise _bad_request("invalid_fields", "fields cannot be combined with group_by")
    plan = FINDING_GROUPS_LIST.plan(page, filters={
        **filters.fingerprint(), "proof_state": proof_states, "group_by": group_by,
    })
    member_sorts = (FINDINGS_LIST if ranked else FINDINGS_LIST_UNRANKED).sorts[plan.sort_name].columns
    direction = "DESC" if plan.descending else "ASC"

    params = SqlParams()
    where = filters.clauses(params)
    where += plan.filter_clauses(params)
    if proof_states:
        where.append(await resolved_proof_filter(conn, where, params, proof_states, project))
    # The rows whose proof only Python can decide take their projected state into the key.
    overrides = await undetermined_proof_states(
        conn, where, params.values, project,
        too_broad="add a target_id, scan_id, severity or seen_within_days filter",
    )
    proof_sql = PROOF_STATE_FILTER_SQL
    from_sql = "findings f"
    if overrides:
        ids = params.add(list(overrides))
        states = params.add(list(overrides.values()))
        from_sql += (f" LEFT JOIN unnest({ids}::uuid[], {states}::text[]) AS proof_override(id, state)"
                     " ON proof_override.id = f.id")
        proof_sql = f"COALESCE(proof_override.state, {proof_sql})"

    member_order = ", ".join(
        [f"{expr} {direction}" for expr, _kind in member_sorts] + [f"f.id {direction}"])
    lead_values = ", ".join(
        f"(array_agg({expr} ORDER BY {member_order}))[1] AS {_SORT_COLUMNS[index]}"
        for index, (expr, _kind) in enumerate(member_sorts)
    )
    generated_at = await snapshot_time(conn)
    keyset = plan.keyset_clauses(params)
    rows = await conn.fetch(
        f"""WITH g AS (
                SELECT {TITLE_KEY_SQL} AS k_title, COALESCE(f.severity, '') AS k_severity,
                       {SUBJECT_KEY_SQL} AS k_subject, COALESCE({proof_sql}, '') AS k_proof,
                       COALESCE(f.status, '') AS k_status,
                       count(*) AS member_count,
                       max(f.last_seen_at) AS last_seen_at, min(f.first_seen_at) AS first_seen_at,
                       (array_agg(f.id ORDER BY {member_order}))[1:{GROUP_MEMBER_LIMIT}] AS member_ids,
                       (array_agg(f.id ORDER BY {member_order}))[1] AS lead_id,
                       {lead_values}
                FROM {from_sql}
                WHERE {where_sql(where)}
                GROUP BY 1, 2, 3, 4, 5
            ),
            totals AS (SELECT count(*) AS groups_total, COALESCE(sum(member_count), 0) AS findings_total FROM g)
            SELECT g.*, {plan.keyset_select}, totals.groups_total, totals.findings_total
            FROM totals LEFT JOIN g ON {where_sql(keyset)}
            ORDER BY {plan.order_by}
            LIMIT {plan.fetch_limit}""",
        *params.values,
    )
    groups_total = int(rows[0]["groups_total"]) if rows else 0
    findings_total = int(rows[0]["findings_total"]) if rows else 0
    groups = [row for row in rows if row["lead_id"] is not None]

    page_groups = groups[: page.limit]
    member_ids = [member for row in page_groups for member in row["member_ids"]]
    leads: dict[Any, dict[str, Any]] = {}
    members: dict[Any, dict[str, Any]] = {}
    if page_groups:
        lead_rows = await conn.fetch(
            f"""SELECT {V1_ROW_SELECT_SQL}, {V1_PROOF_INPUT_COLUMNS}
                FROM unnest($1::uuid[]) AS page(id) JOIN findings f ON f.id = page.id
                {ROW_JOINS_SQL}""",
            [row["lead_id"] for row in page_groups],
        )
        leads = {row["id"]: finish_v1_row(row, project) for row in lead_rows}
        member_rows = await conn.fetch(
            """SELECT f.id, f.url, f.last_seen_at,
                      COALESCE(latest_retest.verdict, f.last_verification_verdict) AS latest_retest_verdict
               FROM unnest($1::uuid[]) AS page(id) JOIN findings f ON f.id = page.id
               LEFT JOIN LATERAL (
                   SELECT verdict FROM finding_verifications WHERE finding_id = f.id
                   ORDER BY created_at DESC, id DESC LIMIT 1
               ) latest_retest ON TRUE""",
            member_ids,
        )
        members = {row["id"]: dict(row) for row in member_rows}

    items: list[dict[str, Any]] = []
    for row in groups:
        item = dict(row)
        ids = list(row["member_ids"])
        item.update({
            "title_key": row["k_title"], "severity": row["k_severity"], "subject": row["k_subject"],
            "proof_state": row["k_proof"], "status": row["k_status"], "count": int(row["member_count"]),
            "lead": leads.get(row["lead_id"]),
            "member_ids": ids, "member_ids_truncated": int(row["member_count"]) > len(ids),
            "members": [members[member] for member in ids if member in members],
        })
        items.append(item)
    body = plan.envelope(items, total=groups_total if page.count != "none" else None,
                         total_kind="exact" if page.count != "none" else "none",
                         generated_at=generated_at)
    if page.count != "none":
        body["findings_total"] = findings_total
    return body


__all__ = [
    "FINDING_GROUPS_LIST",
    "GROUP_BY_VALUES",
    "GROUP_MEMBER_LIMIT",
    "SUBJECT_KEY_SQL",
    "TITLE_KEY_SQL",
    "URL_HOST_SQL",
    "groups_page",
    "parse_group_by",
]
