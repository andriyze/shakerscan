"""The target inventory: one row per asset, grouped by domain, filtered and counted in SQL.

Every filter applies before counting and pagination, so pages, totals and facet counts agree.
Domain grouping pages complete groups and never creates asset membership.
"""
from __future__ import annotations

import json
import re
from typing import Any

from fastapi import HTTPException

try:
    from scope.psl import PublicSuffixError, parse_domain, registrable_domain
except ModuleNotFoundError:
    from ..scope.psl import PublicSuffixError, parse_domain, registrable_domain


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
# resolved through current same-host membership. ``alias`` names the targets row it is asked for.
# Both the target and each scope host go through target_asset_locator, so an IP literal is
# compared in one canonical spelling (2001:DB8::0001 is 2001:db8::1), as the Python reader does.
# A host the Python canonicalizer (host_names.canonical_host) refuses compares as NULL, so it
# matches nothing: a numeric-looking spelling that is not canonical dotted-quad IPv4. PostgreSQL
# inet reads 010.000.000.001 as 10.0.0.1 while resolvers may read it as octal, and the Python
# reader refuses it; without this the list could call a target "Authorized" that the scan path
# does not authorize.
_IPV4_OCTET = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
_NUMERIC_LOOKING = r"(^|\.)([0-9]+|0x[0-9a-f]*)$"
_CANONICAL_IPV4 = f"^{_IPV4_OCTET}(\\.{_IPV4_OCTET}){{3}}$"


def _raw_host(url: str) -> str:
    """The host text of a stored URL before any inet canonicalization (IPv6 is not numeric-looking)."""
    return (f"lower(rtrim(split_part(split_part(split_part(split_part(regexp_replace({url}, '^[A-Za-z]+://', ''), "
            f"'/', 1), '?', 1), '#', 1), ':', 1), '.'))")


def _host_key(raw: str, locator: str) -> str:
    # Only a host without ':' can be an IPv4 spelling: an IPv6 literal that embeds IPv4
    # (::ffff:10.0.0.1, 64:ff9b::192.0.2.1) ends in a dotted quad and is canonicalised by inet.
    return (f"(CASE WHEN position(':' in ({raw})) = 0 AND ({raw}) ~ '{_NUMERIC_LOOKING}' "
            f"AND ({raw}) !~ '{_CANONICAL_IPV4}' THEN NULL ELSE ({locator}) END)")


def authorized_sql(alias: str) -> str:
    target_key = _host_key(_raw_host("authority.url"), "target_asset_locator(authority.url)")
    scope_raw = "lower(rtrim(trim(both '[]' FROM scope_host), '.'))"
    scope_key = _host_key(scope_raw, "target_asset_locator(target_asset_url(lower(trim(both '[]' FROM scope_host))))")
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


# The asset (host) itself: its authority covers every linked web app that inherits it.
AUTHORIZED = authorized_sql('t')
# A linked web app the scan path treats as authorized: through the host, or through its own
# standing receipt (recorded on the web address by the scan flow or POST /targets/{id}/authorization),
# which also overrides a host authorization it does not want.
AUTHORIZED_MEMBERS = f"""(SELECT count(*) FROM targets member
    WHERE member.asset_owner_id=t.id AND member.is_active AND {authorized_sql('member')})"""
# Anything on the asset that a scan may actively test. The list filters on this, so an asset
# whose web address is authorized is never filed under "Not authorized".
ANY_AUTHORIZED = f"({AUTHORIZED} OR {AUTHORIZED_MEMBERS} > 0)"

DETAIL_COLUMNS = f"""
    (SELECT count(*) FROM targets member WHERE member.asset_owner_id=t.id AND member.is_active) AS origin_count,
    (SELECT count(*) FROM device_services service WHERE service.target_id=t.id AND service.state='open') AS service_count,
    (SELECT count(*) FROM {ACTIVE_FINDINGS}) AS active_findings_count,
    (SELECT COALESCE(jsonb_object_agg(severity,total),'{{}}'::jsonb) FROM (
        SELECT f.severity,count(*) AS total FROM {ACTIVE_FINDINGS} GROUP BY f.severity) counts) AS severity_counts,
    (SELECT COALESCE(jsonb_agg(jsonb_build_object('id',member.id,'url',member.url,'name',member.name,
        'is_active',member.is_active,'last_scanned_at',member.last_scanned_at,'last_grade',member.last_grade,
        'last_score',member.last_score,'active_findings_count',member.active_findings_count,
        'authorized',{authorized_sql('member')})
        ORDER BY member.url),'[]'::jsonb) FROM (
        SELECT * FROM targets member WHERE member.asset_owner_id=t.id AND (member.is_active OR $1::boolean)
        ORDER BY member.url,member.id LIMIT 24) member) AS origins,
    {LAST_SCANNED} AS last_scanned_at,
    {SCANNING} AS scanning,
    {AUTHORIZED} AS authorized,
    {AUTHORIZED_MEMBERS} AS authorized_origin_count"""

FILTERS = {
    'authorization': {'authorized': ANY_AUTHORIZED, 'unauthorized': f'NOT {ANY_AUTHORIZED}'},
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
_NETWORK_LOCATOR = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")


def group_domain(locator: str) -> str:
    """The Targets list's domain group for an asset locator: its registrable domain under the
    bundled Public Suffix List (PRIVATE section included), so ``victim.github.io`` and
    ``attacker.github.io`` are two groups and ``shop.example.co.uk`` belongs to
    ``example.co.uk``. Addresses, single labels and .local/.internal/.localhost names, and a host
    that is itself a public suffix, are their own group. A group never spans registrants."""
    locator = str(locator or "").split("#", 1)[0].strip().lower().rstrip(".")
    if (":" in locator or _NETWORK_LOCATOR.fullmatch(locator) or "." not in locator
            or locator == "localhost" or locator.endswith((".local", ".internal", ".localhost"))):
        return locator
    return registrable_domain(locator) or locator


def discoverable(group: str) -> bool:
    """Whether subdomain discovery can run for a domain group (POST /discovery would accept it)."""
    try:
        parse_domain(group)
    except PublicSuffixError:
        return False
    return True


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
    """Page complete domain groups, rather than cutting a root and its subdomains across pages.

    Grouping uses the Public Suffix List (``group_domain``), which SQL cannot apply, so the
    matching assets' ids, locators and sort keys are read first, grouped and paged here, and only
    the page's assets are read in full.
    """
    order, aggregate, direction = SORTS[sort]
    matching = await conn.fetch(f"""SELECT t.id,target_asset_locator(t.url) AS locator,{order} AS sort_key
        FROM {ROOT_FROM} WHERE {query.where}""", *query.parameters)
    members: dict[str, list[Any]] = {}
    for row in matching:
        members.setdefault(group_domain(row['locator'] or ''), []).append(row)
    descending = direction == 'DESC'

    def present(value: Any) -> tuple[int, Any]:
        # PostgreSQL puts NULL last ascending and first descending.
        return (1, 0) if value is None else (0, value)

    def group_key(item: tuple[str, list[Any]]) -> Any:
        domain, rows = item
        if sort == 'name':
            return domain
        values = [row['sort_key'] for row in rows if row['sort_key'] is not None]
        return present((max if aggregate == 'max' else min)(values) if values else None)

    ordered = sorted(members.items(), key=lambda item: item[0])
    ordered.sort(key=group_key, reverse=descending)
    page = ordered[offset:offset + limit]
    ids = [row['id'] for _domain, rows in page for row in rows]
    detail = {row['id']: row for row in await conn.fetch(f"""SELECT {ROOT_COLUMNS},{DETAIL_COLUMNS}
        FROM {ROOT_FROM} WHERE t.id = ANY($2::uuid[])""", query.parameters[0], ids)} if ids else {}
    groups: list[dict[str, Any]] = []
    targets = []
    for domain, rows in page:
        rows = sorted(rows, key=lambda row: (str(row['locator'] or ''), str(row['id'])))
        rows.sort(key=lambda row: present(row['sort_key']), reverse=descending)
        rows.sort(key=lambda row: str(row['locator'] or '') != domain)
        group = {'root_domain': domain, 'discoverable': discoverable(domain), 'targets': []}
        for row in rows:
            if row['id'] not in detail:
                continue  # removed between the two reads
            asset = public_asset(detail[row['id']])
            asset['root_domain'] = domain
            targets.append(asset)
            group['targets'].append(asset)
        groups.append(group)
    return {'targets': targets, 'groups': groups, 'total': len(matching),
            'total_groups': len(members), 'limit': limit, 'offset': offset,
            'inventory_kind': 'assets', 'group_by': 'domain'}


async def inventory_facets(conn: Any, query: _Query) -> dict[str, Any]:
    """Counts for each filter value over the search scope, before the other filters apply."""
    row = await conn.fetchrow(f"""WITH scope AS (
        SELECT {ENVIRONMENT} AS environment,{FILTERS['authorization']['authorized']} AS authorized,
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
