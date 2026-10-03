"""The target inventory: one row per asset, grouped by domain, filtered and counted in SQL.

Every filter applies before counting and pagination, so pages, totals and facet counts agree.
Domain grouping pages complete groups and never creates asset membership.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException

try:
    from scanner_tools.vendor_risk import MULTI_PART_TLDS
except ModuleNotFoundError:
    from scanner.scanner_tools.vendor_risk import MULTI_PART_TLDS


ROOT_COLUMNS = """t.id,t.name,t.url,t.is_active,t.created_at,t.updated_at,t.asset_owner_id,
    target_asset_locator(t.url) AS locator,t.metadata_json,
    (p.target_id IS NOT NULL) AS connected_device,
    p.device_class,p.manufacturer,p.model,p.firmware_version,
    p.last_scanned_at AS network_last_scanned_at,p.last_scan_id AS network_last_scan_id,
    p.last_score AS network_score,p.last_grade AS network_grade"""
ROOT_FROM = "targets t LEFT JOIN target_device_profiles p ON p.target_id=t.id"
ROOT_WHERE = "t.asset_owner_id IS NULL AND COALESCE(t.discovery_source,'manual') <> 'model-intake'"
HOST_NETWORK = """(target_asset_locator(t.url) LIKE '%:%'
    OR target_asset_locator(t.url) ~ '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'
    OR target_asset_locator(t.url) NOT LIKE '%.%'
    OR target_asset_locator(t.url) ~ '\\.(local|internal|localhost)$')"""
NETWORK_VIEW = f"""({HOST_NETWORK} OR p.target_id IS NOT NULL
    OR EXISTS(SELECT 1 FROM device_services service WHERE service.target_id=t.id AND service.state='open'))"""
WEB_VIEW = f"""(NOT {HOST_NETWORK} OR t.url ~ '^https?://'
    OR EXISTS(SELECT 1 FROM targets member WHERE member.asset_owner_id=t.id AND member.is_active
              AND member.url ~ '^https?://'))"""

MEMBERS = "(SELECT member.id FROM targets member WHERE member.id=t.id OR member.asset_owner_id=t.id)"
ENVIRONMENT = """COALESCE(NULLIF(t.metadata_json->>'environment',''),
    NULLIF(t.metadata_json->>'cohort',''),'production')"""
ACTIVE_FINDINGS = f"findings f WHERE f.status='active' AND f.target_id IN {MEMBERS}"
RISK_WEIGHT = f"""(SELECT COALESCE(sum(CASE f.severity WHEN 'critical' THEN 1000 WHEN 'high' THEN 100
    WHEN 'medium' THEN 10 WHEN 'low' THEN 1 ELSE 0 END),0) FROM {ACTIVE_FINDINGS})"""
LAST_SCANNED = """GREATEST(t.last_scanned_at,p.last_scanned_at,(SELECT max(member.last_scanned_at)
    FROM targets member WHERE member.asset_owner_id=t.id))"""
SCANNING = f"""EXISTS(SELECT 1 FROM scans sc WHERE sc.status IN ('pending','queued','running')
    AND sc.target_id IN {MEMBERS})"""
# The same standing-authorization rule the submission gate applies (target_authorization.py):
# an active, approved, unexpired standing receipt whose scope names the authority target's host,
# resolved through current same-host membership.
AUTHORIZED = """EXISTS(SELECT 1 FROM targets authority
    JOIN scope_receipts s ON s.target_id=authority.id
    JOIN approval_receipts a ON a.scope_receipt_id=s.id
    WHERE authority.id=target_effective_authorization_target(t.id)
      AND a.approved_by IS NOT NULL AND a.status='active'
      AND a.risk_tier IN ('active','intrusive') AND a.action_name='target.authorization'
      AND (a.expires_at IS NULL OR a.expires_at > NOW())
      AND COALESCE(s.verdict,'') <> 'blocked'
      AND (COALESCE(s.allowed_hosts,'[]'::jsonb) ? target_asset_locator(authority.url)
           OR lower(s.normalized_scope->>'host')=target_asset_locator(authority.url)))"""

DETAIL_COLUMNS = f"""
    (SELECT count(*) FROM targets member WHERE member.asset_owner_id=t.id AND member.is_active) AS origin_count,
    (SELECT count(*) FROM device_services service WHERE service.target_id=t.id AND service.state='open') AS service_count,
    (SELECT count(*) FROM {ACTIVE_FINDINGS}) AS active_findings_count,
    (SELECT COALESCE(jsonb_object_agg(severity,total),'{{}}'::jsonb) FROM (
        SELECT f.severity,count(*) AS total FROM {ACTIVE_FINDINGS} GROUP BY f.severity) counts) AS severity_counts,
    (SELECT COALESCE(jsonb_agg(jsonb_build_object('id',member.id,'url',member.url,'name',member.name,
        'is_active',member.is_active,'last_scanned_at',member.last_scanned_at,'last_grade',member.last_grade,
        'last_score',member.last_score,'active_findings_count',member.active_findings_count)
        ORDER BY member.url),'[]'::jsonb) FROM (
        SELECT * FROM targets member WHERE member.asset_owner_id=t.id AND (member.is_active OR $1::boolean)
        ORDER BY member.url,member.id LIMIT 24) member) AS origins,
    {LAST_SCANNED} AS last_scanned_at,
    {SCANNING} AS scanning,
    {AUTHORIZED} AS authorized"""

FILTERS = {
    'authorization': {'authorized': AUTHORIZED, 'unauthorized': f'NOT {AUTHORIZED}'},
    'findings': {
        'any': f'EXISTS(SELECT 1 FROM {ACTIVE_FINDINGS})',
        'critical_high': f"EXISTS(SELECT 1 FROM {ACTIVE_FINDINGS} AND f.severity IN ('critical','high'))",
        'none': f'NOT EXISTS(SELECT 1 FROM {ACTIVE_FINDINGS})',
    },
    'activity': {
        'never': f'{LAST_SCANNED} IS NULL AND NOT {SCANNING}',
        'scanned': f'{LAST_SCANNED} IS NOT NULL',
        'scanning': SCANNING,
    },
    'asset_type': {'web': WEB_VIEW, 'network': NETWORK_VIEW},
}
SORTS = {
    # (asset order key, group aggregate, direction)
    'name': ('lower(COALESCE(NULLIF(t.name,\'\'),target_asset_locator(t.url),t.url))', 'min', 'ASC'),
    'risk': (RISK_WEIGHT, 'max', 'DESC'),
    'recent': (f"COALESCE(extract(epoch FROM {LAST_SCANNED}),0)", 'max', 'DESC'),
    'created': ('extract(epoch FROM t.created_at)', 'max', 'DESC'),
}
GROUP_DOMAIN = r"""CASE
    WHEN locator LIKE '%:%' OR locator ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
         OR locator='localhost' OR locator ~ '\.(local|internal|localhost)$'
         OR locator NOT LIKE '%.%' THEN locator
    WHEN substring(locator from '[^.]+\.[^.]+$')=ANY({tlds}::text[])
        THEN COALESCE(substring(locator from '[^.]+\.[^.]+\.[^.]+$'),locator)
    ELSE COALESCE(substring(locator from '[^.]+\.[^.]+$'),locator)
END"""


def public_asset(row: Any) -> dict[str, Any]:
    result = dict(row)
    metadata = result.pop('metadata_json', None) or {}
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    result['environment'] = str(metadata.get('environment') or metadata.get('cohort') or 'production')
    saved_skill = metadata.get('target_skill')
    result['has_target_skill'] = bool(isinstance(saved_skill, dict) and (saved_skill.get('methodology')
        or isinstance(saved_skill.get('operator_snapshot'), dict) and saved_skill['operator_snapshot'].get('methodology')))
    hints = metadata.get('port_hints')
    result['port_hints'] = [port for port in (hints if isinstance(hints,list) else [])
                            if type(port) is int and 1 <= port <= 65535][:128]
    result['asset_id'] = result.get('asset_owner_id') or result['id']
    result['inventory_kind'] = 'service' if result.get('asset_owner_id') else 'asset'
    for key in ('severity_counts', 'origins'):
        if isinstance(result.get(key), str):
            result[key] = json.loads(result[key])
    return result


class _Query:
    """WHERE clause and positional parameters built together, so placeholders never drift."""

    def __init__(self, where: str, parameters: list):
        self.where, self.parameters = where, list(parameters)

    def bind(self, value: Any) -> str:
        self.parameters.append(value)
        return f'${len(self.parameters)}'


async def list_assets(conn: Any, *, search: str = '', connected_only: bool = False,
                      include_inactive: bool = False, include_services: bool = False,
                      limit: int = 100, offset: int = 0, group_by: str | None = None,
                      asset_type: str | None = None, environment: str | None = None,
                      authorization: str | None = None, findings: str | None = None,
                      activity: str | None = None, sort: str = 'name',
                      include_facets: bool = False) -> dict[str, Any]:
    if sort not in SORTS:
        raise HTTPException(400, 'Unknown sort order')
    chosen = {'asset_type': asset_type, 'authorization': authorization, 'findings': findings, 'activity': activity}
    for name, value in chosen.items():
        if value is not None and value not in FILTERS[name]:
            raise HTTPException(400, f'Unknown {name.replace("_", " ")} filter')
    base = "COALESCE(t.discovery_source,'manual') <> 'model-intake'" if include_services else ROOT_WHERE
    # $1-$3 are fixed: DETAIL_COLUMNS reads $1 to decide whether retired services are listed.
    query = _Query(base + """
        AND ($1::boolean OR t.is_active)
        AND (NOT $2::boolean OR p.target_id IS NOT NULL)
        AND ($3::text='' OR t.name ILIKE '%' || $3 || '%' OR t.url ILIKE '%' || $3 || '%'
             OR EXISTS (SELECT 1 FROM targets member WHERE member.asset_owner_id=t.id
                        AND (member.name ILIKE '%' || $3 || '%' OR member.url ILIKE '%' || $3 || '%')))
    """, [include_inactive, connected_only, search.strip()])
    facet_query = _Query(query.where, query.parameters)
    for name, value in chosen.items():
        if value is not None:
            query.where += ' AND ' + FILTERS[name][value]
    if environment:
        query.where += f' AND {ENVIRONMENT}={query.bind(environment.strip().lower())}'
    facets = await inventory_facets(conn, facet_query) if include_facets else None
    if group_by == 'domain':
        if include_services:
            raise HTTPException(400, 'Domain hierarchy groups assets; service records remain within their asset')
        result = await _list_domain_groups(conn, query, sort=sort, limit=limit, offset=offset)
    else:
        total = await conn.fetchval(f'SELECT count(*) FROM {ROOT_FROM} WHERE {query.where}', *query.parameters)
        order, _, direction = SORTS[sort]
        rows = await conn.fetch(f"""SELECT {ROOT_COLUMNS},{DETAIL_COLUMNS}
            FROM {ROOT_FROM} WHERE {query.where}
            ORDER BY {order} {direction},lower(COALESCE(t.name,t.url)),t.id
            LIMIT {query.bind(limit)} OFFSET {query.bind(offset)}""", *query.parameters)
        result = {'targets': [public_asset(row) for row in rows], 'total': int(total),
                  'limit': limit, 'offset': offset, 'inventory_kind': 'assets'}
    if facets is not None:
        result['facets'] = facets
    return result


async def _list_domain_groups(conn: Any, query: _Query, *, sort: str, limit: int, offset: int) -> dict[str, Any]:
    order, aggregate, direction = SORTS[sort]
    tlds = query.bind(sorted(MULTI_PART_TLDS))
    # Page complete groups, rather than cutting a root and its subdomains across asset pages.
    grouped = f"""WITH matching AS (
        SELECT t.id,target_asset_locator(t.url) AS locator,{order} AS sort_key
        FROM {ROOT_FROM} WHERE {query.where}
    ), grouped AS (SELECT id,sort_key,{GROUP_DOMAIN.format(tlds=tlds)} AS group_domain FROM matching)"""
    counts = await conn.fetchrow(f"""{grouped}
        SELECT count(*) AS total,count(DISTINCT group_domain) AS total_groups FROM grouped""", *query.parameters)
    page_limit, page_offset = query.bind(limit), query.bind(offset)
    # Alphabetical inventories order groups by the domain itself, not by member display names.
    group_key = 'min(group_domain)' if sort == 'name' else f'{aggregate}(sort_key)'
    rows = await conn.fetch(f"""{grouped}, page AS (
        SELECT group_domain,{group_key} AS group_key FROM grouped GROUP BY group_domain
        ORDER BY group_key {direction},group_domain LIMIT {page_limit} OFFSET {page_offset}
    )
    SELECT {ROOT_COLUMNS},{DETAIL_COLUMNS},grouped.group_domain
    FROM {ROOT_FROM} JOIN grouped ON grouped.id=t.id JOIN page USING(group_domain)
    ORDER BY page.group_key {direction},group_domain,(target_asset_locator(t.url)=group_domain) DESC,
        grouped.sort_key {direction},target_asset_locator(t.url),t.id
    """, *query.parameters)
    groups: dict[str, dict[str, Any]] = {}
    targets = []
    for row in rows:
        asset = public_asset(row)
        domain = asset.pop('group_domain')
        asset['root_domain'] = domain
        targets.append(asset)
        groups.setdefault(domain, {'root_domain': domain, 'targets': []})['targets'].append(asset)
    return {'targets': targets, 'groups': list(groups.values()), 'total': int(counts['total']),
            'total_groups': int(counts['total_groups']), 'limit': limit, 'offset': offset,
            'inventory_kind': 'assets', 'group_by': 'domain'}


async def inventory_facets(conn: Any, query: _Query) -> dict[str, Any]:
    """Counts for each filter value over the search scope, before the other filters apply."""
    row = await conn.fetchrow(f"""WITH scope AS (
        SELECT {ENVIRONMENT} AS environment,{AUTHORIZED} AS authorized,
            EXISTS(SELECT 1 FROM {ACTIVE_FINDINGS}) AS has_findings,
            EXISTS(SELECT 1 FROM {ACTIVE_FINDINGS} AND f.severity IN ('critical','high')) AS critical_high,
            {LAST_SCANNED} IS NOT NULL AS scanned,{SCANNING} AS scanning,
            {WEB_VIEW} AS web,{NETWORK_VIEW} AS network
        FROM {ROOT_FROM} WHERE {query.where}
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
    FROM scope""", *query.parameters)
    environments = row['environments']
    if isinstance(environments, str):
        environments = json.loads(environments)
    count = lambda key: int(row[key])
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
