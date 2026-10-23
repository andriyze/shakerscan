"""The 2.10 read paths that 2.11 replaced, kept verbatim as the oracle for equality tests.

tests/test_targets_dashboard_scale_postgres.py runs these against the same fixture as the new
code and asserts equal results. They are the queries that did full-table counts, correlated
per-target subqueries and DISTINCT ON over every row; nothing in the product calls them.
"""
from __future__ import annotations

import json
from typing import Any

# --- /dashboard (api/operations/router.py at v2.10.0) -------------------------------------------

DASHBOARD_RECENT_SCANS = """
    SELECT id, target_id, ai_target_id, target_url, status, score, grade,
           scan_type, run_kind, findings_count, created_at, completed_at
    FROM (
        SELECT DISTINCT ON (
            COALESCE('target:' || target_id::text, 'ai:' || ai_target_id::text, 'url:' || target_url)
        )
            id, target_id, ai_target_id, target_url, status, score, grade,
            scan_type, run_kind, findings_count, created_at, completed_at
        FROM scans
        WHERE (scan_role IS NULL OR scan_role <> 'shard')
          AND status = 'completed'
          AND COALESCE(run_kind, '') <> 'model_intake'
          AND COALESCE(scan_type, '') <> 'model_intake'
          AND device_target_id IS NULL
          AND COALESCE(scan_role, '') <> 'device_web_origin'
          AND COALESCE(run_kind, '') NOT IN ('device_posture','device_probe','device_web_dast')
        ORDER BY
            COALESCE('target:' || target_id::text, 'ai:' || ai_target_id::text, 'url:' || target_url),
            created_at DESC
    ) latest_per_target
    ORDER BY created_at DESC
    LIMIT 10
"""

DASHBOARD_RECENT_FINDINGS = """
    SELECT id, title, severity, status, tool, first_seen_at
    FROM findings
    WHERE status = 'active' AND severity IN ('critical', 'high')
      AND COALESCE(source, '') <> 'device'
    ORDER BY
        CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                      WHEN 'low' THEN 4 ELSE 5 END,
        first_seen_at DESC
    LIMIT 10
"""

DASHBOARD_DAST_FINDINGS = """
    SELECT
        COUNT(*) FILTER (
            WHERE status = 'active' AND severity IN ('critical', 'high')
              AND COALESCE(source, 'scan') NOT IN ('ai_gate', 'ai_session', 'model_intake', 'asm', 'manual')
              AND ai_target_id IS NULL AND COALESCE(tool, '') <> 'model_intake'
        ) AS blockers,
        COUNT(*) FILTER (
            WHERE status = 'active'
              AND COALESCE(source, 'scan') NOT IN ('ai_gate', 'ai_session', 'model_intake', 'asm', 'manual')
              AND ai_target_id IS NULL AND COALESCE(tool, '') <> 'model_intake'
        ) AS active_findings
    FROM findings
"""

DASHBOARD_DAST_SCANS = """
    SELECT
        COUNT(*) FILTER (WHERE status IN ('pending', 'queued', 'running')) AS active_scans,
        COUNT(*) FILTER (WHERE status = 'failed' AND created_at >= NOW() - INTERVAL '7 days') AS recent_failed
    FROM scans
    WHERE (scan_role IS NULL OR scan_role <> 'shard')
      AND COALESCE(run_kind, 'dast') NOT IN ('ai_api', 'ai_widget', 'ai_rag', 'ai_trace', 'ai_mcp', 'model_intake')
"""

DASHBOARD_AI_GATE = """SELECT COUNT(*) FROM findings
    WHERE status = 'active' AND (source = 'ai_gate' OR ai_target_id IS NOT NULL)"""
DASHBOARD_MODEL_INTAKE = """SELECT COUNT(*) FROM findings
    WHERE status = 'active' AND (source = 'model_intake' OR tool = 'model_intake')"""
DASHBOARD_DEPLOYMENT = """SELECT
        COUNT(*) FILTER (WHERE status = 'active' AND severity = 'critical') AS critical,
        COUNT(*) FILTER (WHERE status = 'active' AND severity = 'high') AS high
    FROM findings"""
DASHBOARD_BLOCKERS = """SELECT
        COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
        COUNT(*) FILTER (WHERE severity = 'high') AS high
    FROM findings
    WHERE status = 'active' AND severity IN ('critical', 'high') AND COALESCE(source, '') <> 'device'"""


# --- /targets/grouped enrichment (api/targets/router.py at v2.10.0) -----------------------------

GROUPED_INVESTIGATOR = """
    SELECT ids.target_id,
           COALESCE(f.investigator_verified_count, 0) AS investigator_verified_count,
           COALESCE(c.investigator_suspected_count, 0) AS investigator_suspected_count
    FROM unnest($1::uuid[]) AS ids(target_id)
    LEFT JOIN LATERAL (
        SELECT COUNT(*) AS investigator_verified_count FROM findings
        WHERE target_id=ids.target_id AND status='active' AND last_verification_verdict='exploited'
          AND tool IN ('autonomous_workflow','bola')
    ) f ON true
    LEFT JOIN LATERAL (
        SELECT COUNT(*) AS investigator_suspected_count FROM investigation_candidates
        WHERE target_id=ids.target_id AND plane='web'
          AND status IN ('new','verification_queued','verifying','inconclusive','blocked')
    ) c ON true
"""

GROUPED_ASM = """
    WITH inventory AS (
        SELECT target_id, COUNT(*) AS total,
               COUNT(*) FILTER (WHERE test_status <> 'gone') AS testable,
               COUNT(*) FILTER (WHERE test_status = 'tested') AS status_tested
        FROM target_endpoints WHERE target_id = ANY($1::uuid[]) GROUP BY target_id
    ),
    latest_attempt AS (
        SELECT DISTINCT ON (te.id) te.target_id, te.id AS endpoint_id,
            CASE WHEN aea.status = 'completed'
                  AND lower(COALESCE(aea.scanner_telemetry_json->>'per_endpoint_telemetry', 'false')) <> 'true'
                 THEN 'partial' ELSE aea.status END AS status
        FROM target_endpoints te
        JOIN asm_endpoint_attempts aea ON aea.endpoint_id = te.id
        WHERE te.target_id = ANY($1::uuid[]) AND te.test_status <> 'gone'
        ORDER BY te.id, COALESCE(aea.completed_at, aea.started_at) DESC, aea.started_at DESC
    ),
    attempts AS (
        SELECT target_id, COUNT(*) AS attempted, COUNT(*) FILTER (WHERE status = 'completed') AS completed
        FROM latest_attempt GROUP BY target_id
    )
    SELECT i.target_id, i.total, i.testable, i.status_tested,
           COALESCE(a.attempted, 0) AS attempted, COALESCE(a.completed, 0) AS attempt_completed
    FROM inventory i LEFT JOIN attempts a ON a.target_id = i.target_id
"""


# --- /targets/inventory (api/targets/asset_inventory.py at v2.10.0) -----------------------------

def old_inventory_fragments(ai: Any) -> dict[str, str]:
    """The correlated per-asset fragments the summary replaced, over the module's own MEMBERS."""
    active = f"findings f WHERE f.status='active' AND f.target_id IN {ai.MEMBERS}"
    return {
        "active": active,
        "risk": f"""(SELECT COALESCE(sum(CASE f.severity WHEN 'critical' THEN 1000 WHEN 'high' THEN 100
    WHEN 'medium' THEN 10 WHEN 'low' THEN 1 ELSE 0 END),0) FROM {active})""",
        "any": f"EXISTS(SELECT 1 FROM {active})",
        "critical_high": f"EXISTS(SELECT 1 FROM {active} AND f.severity IN ('critical','high'))",
    }


def old_authorized_sql(ai: Any, alias: str) -> str:
    target_key = ai._host_key(ai._raw_host("authority.url"), "target_asset_locator(authority.url)")
    scope_raw = "lower(rtrim(trim(both '[]' FROM scope_host), '.'))"
    scope_key = ai._host_key(scope_raw, "target_asset_locator(target_asset_url(lower(trim(both '[]' FROM scope_host))))")
    return f"""EXISTS(SELECT 1 FROM targets authority
    JOIN scope_receipts s ON s.target_id=authority.id
    JOIN approval_receipts a ON a.scope_receipt_id=s.id
    WHERE authority.id=target_effective_authorization_target({alias}.id)
      AND a.approved_by IS NOT NULL AND a.status='active'
      AND a.risk_tier IN ('active','intrusive') AND a.action_name='target.authorization'
      AND (a.expires_at IS NULL OR a.expires_at > NOW())
      AND COALESCE(s.verdict,'') <> 'blocked'
      AND {target_key} IN (
          SELECT {scope_key}
          FROM (SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(s.allowed_hosts)='array' THEN s.allowed_hosts ELSE '[]'::jsonb END)
                UNION ALL SELECT s.normalized_scope->>'host') hosts(scope_host)
          WHERE COALESCE(scope_host,'') <> ''))"""


async def old_inventory_facets(conn: Any, ai: Any, where: str, parameters: list) -> dict[str, Any]:
    old = old_inventory_fragments(ai)
    authorized = (f"({old_authorized_sql(ai, 't')} OR (SELECT count(*) FROM targets member "
                  f"WHERE member.asset_owner_id=t.id AND member.is_active AND {old_authorized_sql(ai, 'member')}) > 0)")
    row = await conn.fetchrow(f"""WITH scope AS (
        SELECT {ai.ENVIRONMENT} AS environment,{authorized} AS authorized,
            {old['any']} AS has_findings, {old['critical_high']} AS critical_high,
            {ai.LAST_SCANNED} IS NOT NULL AS scanned,{ai.SCANNING} AS scanning,
            {ai.WEB_VIEW} AS web,{ai.NETWORK_VIEW} AS network
        FROM {ai.ROOT_FROM} WHERE {where}
    )
    SELECT count(*) AS total,
        count(*) FILTER (WHERE authorized) AS authorized,
        count(*) FILTER (WHERE NOT authorized) AS unauthorized,
        count(*) FILTER (WHERE has_findings) AS findings_any,
        count(*) FILTER (WHERE critical_high) AS findings_critical_high,
        count(*) FILTER (WHERE NOT has_findings) AS findings_none,
        count(*) FILTER (WHERE scanned) AS activity_scanned,
        count(*) FILTER (WHERE NOT scanned AND NOT scanning) AS activity_never,
        count(*) FILTER (WHERE scanning) AS activity_scanning,
        count(*) FILTER (WHERE web) AS asset_type_web,
        count(*) FILTER (WHERE network) AS asset_type_network,
        (SELECT COALESCE(jsonb_object_agg(environment,total),'{{}}'::jsonb) FROM (
            SELECT environment,count(*) AS total FROM scope GROUP BY environment) environments) AS environments
    FROM scope""", *parameters)
    environments = row['environments']
    if isinstance(environments, str):
        environments = json.loads(environments)
    count = lambda key: int(row[key])  # noqa: E731
    return {
        'total': count('total'),
        'environment': {key: int(value) for key, value in environments.items()},
        'authorization': {'authorized': count('authorized'), 'unauthorized': count('unauthorized')},
        'findings': {'any': count('findings_any'), 'critical_high': count('findings_critical_high'),
                     'none': count('findings_none')},
        'activity': {'scanned': count('activity_scanned'), 'never': count('activity_never'),
                     'scanning': count('activity_scanning')},
        'asset_type': {'web': count('asset_type_web'), 'network': count('asset_type_network')},
    }


# --- ASM coverage (api/asm_inventory.py at v2.10.0) ---------------------------------------------

ASM_LATEST_ATTEMPTS = """
    WITH latest_attempt AS (
        SELECT DISTINCT ON (te.id) te.id AS endpoint_id, aea.status, aea.scanner_telemetry_json
        FROM target_endpoints te
        JOIN asm_endpoint_attempts aea ON aea.endpoint_id = te.id
        WHERE te.target_id = $1 AND te.test_status <> 'gone'
        ORDER BY te.id, COALESCE(aea.completed_at, aea.started_at) DESC, aea.started_at DESC
    )
    SELECT status, scanner_telemetry_json FROM latest_attempt
"""


# --- Campaign impact and the refuter window (api/arsenal_routes/router.py at v2.10.0) ------------

async def old_campaign_impact(conn: Any, campaign_ids: list, impact: Any) -> dict:
    rows = await conn.fetch(
        """
        SELECT ca.mission_campaign_id, linked.finding_id, f.id, f.severity, f.status
        FROM campaign_actions ca
        CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(ca.finding_ids, '[]'::jsonb)) AS linked(finding_id)
        LEFT JOIN findings f ON f.id::text = linked.finding_id
        WHERE ca.mission_campaign_id = ANY($1::uuid[])
        """,
        campaign_ids,
    )
    grouped = {campaign_id: [] for campaign_id in campaign_ids}
    unresolved, seen = set(), {campaign_id: set() for campaign_id in campaign_ids}
    for row in rows:
        campaign_id = row["mission_campaign_id"]
        data = dict(row)
        finding_id = str(data.get("finding_id") or "")
        if not data.get("id"):
            unresolved.add(campaign_id)
            continue
        if finding_id in seen[campaign_id]:
            continue
        seen[campaign_id].add(finding_id)
        grouped[campaign_id].append(data)
    return {cid: impact(grouped[cid], partial=cid in unresolved) for cid in campaign_ids}


REFUTER_FINDINGS = """
    SELECT * FROM findings
    WHERE status = 'active'
      AND (severity IN ('critical', 'high') OR source IN ('ai_gate', 'model_intake')
           OR ai_target_id IS NOT NULL OR tool = 'model_intake')
    ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                           WHEN 'low' THEN 4 ELSE 5 END,
             last_seen_at DESC NULLS LAST, first_seen_at DESC NULLS LAST
    LIMIT $1
"""

REFUTER_SCANS = """
    SELECT target_id, target_url, scan_id, findings_count
    FROM (
        SELECT target_id, target_url, id AS scan_id, findings_count,
               ROW_NUMBER() OVER (PARTITION BY target_id ORDER BY created_at DESC) AS rn
        FROM scans
        WHERE status = 'completed' AND run_kind = 'web_dast' AND target_id IS NOT NULL
          AND (scan_role IS NULL OR scan_role <> 'shard')
    ) ranked
    WHERE rn <= $1
    ORDER BY target_id, rn
"""


# --- The 2.11 candidate's unbounded legacy shapes (api/targets at ad5ce4fd) ----------------------
#
# Before the legacy responses were bounded they held every group with every member. Kept here as
# the oracle: the bounded legacy response and the list/v1 walks must equal these groups.

async def old_grouped(conn: Any, router: Any, *, include_inactive: bool = False, search: str | None = None,
                      discovery_source: str | None = None, grade: str | None = None,
                      has_findings: bool | None = None, sort_by: str = "root_domain",
                      sort_order: str = "asc") -> dict[str, Any]:
    """GET /targets/grouped without list/v1: every group, every target, sorted in Python."""
    from targets import grouped_list

    target_columns = f"{router._GROUPED_TARGET_COLUMNS},\n                {router._authorized_for_active_testing_sql()}"
    query = f"SELECT {target_columns} FROM targets t WHERE 1=1"
    params: list[Any] = []
    if not include_inactive:
        query += " AND t.is_active = true"
    if discovery_source != "model-intake":
        query += " AND COALESCE(t.discovery_source, 'manual') NOT IN ('model-intake','host')"
    if search:
        params.append(search)
        n = len(params)
        query += (f" AND (t.url ILIKE '%' || ${n} || '%' OR t.name ILIKE '%' || ${n} || '%'"
                  f" OR t.root_domain ILIKE '%' || ${n} || '%')")
    if discovery_source:
        params.append(discovery_source)
        query += f" AND t.discovery_source = ${len(params)}"
    if grade:
        params.append(grade)
        query += f" AND UPPER(t.last_grade) = UPPER(${len(params)})"
    if has_findings is not None:
        query += " AND t.active_findings_count > 0" if has_findings else " AND t.active_findings_count = 0"
    query += " ORDER BY t.root_domain, t.is_root DESC, t.url"
    rows = router._dedupe_canonical_target_rows(await conn.fetch(query, *params))
    target_ids = [row["id"] for row in rows]
    investigator = await grouped_list.investigator_counts(conn, target_ids)
    asm = await grouped_list.asm_coverage_by_target(conn, target_ids)

    def attach(data: dict) -> dict:
        data["asm_coverage"] = asm.get(str(data["id"]))
        data.update(investigator.get(str(data["id"]), {
            "investigator_verified_count": 0, "investigator_suspected_count": 0}))
        return data

    grouped: dict[str, dict] = {}
    for row in rows:
        rd = row["root_domain"] or "unknown"
        group = grouped.setdefault(rd, {"root_domain": rd, "root_target": None, "subdomains": []})
        data = attach(router._public_target_row(row))
        if row["is_root"]:
            # The last root in URL order is the group's root; another root of the same domain
            # (an app of the same host on another port) is a member (E1-N2).
            if group["root_target"] is not None:
                group["subdomains"].append(group["root_target"])
            group["root_target"] = data
        else:
            group["subdomains"].append(data)
    result = []
    for data in grouped.values():
        data["subdomains"].sort(key=lambda item: item["url"])
        root = data["root_target"]
        data["subdomain_count"] = len(data["subdomains"])
        data["total_count"] = data["subdomain_count"] + (1 if root else 0)
        data["total_findings"] = (root["active_findings_count"] if root else 0) + sum(
            s["active_findings_count"] for s in data["subdomains"])
        data["best_score"] = root["last_score"] if root and root["last_score"] is not None else None
        data["latest_scan"] = root["last_scanned_at"] if root else None
        data["earliest_created"] = root["created_at"] if root else min(
            (s["created_at"] for s in data["subdomains"]), default=None)
        members = ([root] if root else []) + data["subdomains"]
        data["asm_coverage"] = grouped_list.group_asm_rollup([t.get("asm_coverage") for t in members])
        result.append(data)
    reverse = sort_order == "desc"

    def key(item: dict) -> Any:
        if sort_by == "last_scanned_at":
            return item["latest_scan"] or ""
        if sort_by == "active_findings_count":
            return item["total_findings"]
        if sort_by == "last_score":
            return (-1 if reverse else 101) if item["best_score"] is None else item["best_score"]
        if sort_by == "created_at":
            return item["earliest_created"] or ""
        return item["root_domain"].lower()

    result.sort(key=key, reverse=reverse)
    return {"domains": result, "total_root_domains": len(result),
            "total_targets": sum(d["total_count"] for d in result)}


async def old_inventory_domain_groups(conn: Any, ai: Any, query: Any, *, from_sql: str, sort: str,
                                      limit: int, offset: int) -> dict[str, Any]:
    """GET /targets/inventory?group_by=domain without list/v1: every member of each group, the
    groups formed and ordered in Python over every matching asset."""
    order, aggregate, direction = ai.SORTS[sort]
    matching = await conn.fetch(f"""SELECT t.id,target_asset_locator(t.url) AS locator,{order} AS sort_key
        FROM {from_sql} WHERE {query.where}""", *query.parameters)
    members: dict[str, list[Any]] = {}
    for row in matching:
        members.setdefault(ai.group_domain(row["locator"] or ""), []).append(row)
    descending = direction == "DESC"

    def present(value: Any) -> tuple[int, Any]:
        return (1, 0) if value is None else (0, value)

    def group_key(item: tuple[str, list[Any]]) -> Any:
        domain, rows = item
        if sort == "name":
            return domain
        values = [row["sort_key"] for row in rows if row["sort_key"] is not None]
        return present((max if aggregate == "max" else min)(values) if values else None)

    ordered = sorted(members.items(), key=lambda item: item[0])
    ordered.sort(key=group_key, reverse=descending)
    page = ordered[offset:offset + limit]
    ids = [row["id"] for _domain, rows in page for row in rows]
    detail = {row["id"]: row for row in await conn.fetch(f"""SELECT {ai.ROOT_COLUMNS},{ai.DETAIL_COLUMNS}
        FROM {ai.ROOT_FROM} WHERE t.id = ANY($2::uuid[])""", query.parameters[0], ids)} if ids else {}
    groups = []
    for domain, rows in page:
        rows = sorted(rows, key=lambda row: (str(row["locator"] or ""), str(row["id"])))
        rows.sort(key=lambda row: present(row["sort_key"]), reverse=descending)
        rows.sort(key=lambda row: str(row["locator"] or "") != domain)
        group = {"root_domain": domain, "discoverable": ai.discoverable(domain), "targets": []}
        for row in rows:
            asset = ai.public_asset(detail[row["id"]])
            asset["root_domain"] = domain
            group["targets"].append(asset)
        groups.append(group)
    return {"groups": groups, "total": len(matching), "total_groups": len(members)}
