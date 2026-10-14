"""The target inventory: one row per asset, grouped by domain, filtered and counted in SQL.

Every filter applies before counting and pagination, so pages, totals and facet counts agree.
Domain grouping pages complete groups and never creates asset membership.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from fastapi import HTTPException

try:
    from scope.psl import PSL_PIN_PATH, PublicSuffixError, parse_domain, registrable_domain
except ModuleNotFoundError:
    from ..scope.psl import PSL_PIN_PATH, PublicSuffixError, parse_domain, registrable_domain
from .scale_summary import ACTIVE_FINDINGS_BY_TARGET_SQL
try:
    from list_contract import ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time
except ModuleNotFoundError:
    from ..list_contract import ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time


ROOT_COLUMNS = """t.id,t.name,t.url,t.is_active,t.created_at,t.updated_at,t.asset_owner_id,
    target_asset_locator(t.url) AS locator,t.metadata_json,
    (p.target_id IS NOT NULL) AS connected_device,
    p.device_class,p.manufacturer,p.model,p.firmware_version,
    p.last_scanned_at AS network_last_scanned_at,p.last_scan_id AS network_last_scan_id,
    p.last_score AS network_score,p.last_grade AS network_grade"""
ROOT_FROM = "targets t LEFT JOIN target_device_profiles p ON p.target_id=t.id"
# Active findings per asset (the asset row and its services), from the trigger-maintained finding
# summary: one hash join instead of a correlated count over ``findings`` per asset. Equal to
# ACTIVE_FINDINGS below: a finding counts for its target and for that target's owning asset.
ASSET_FINDINGS = f"""(SELECT owner.asset_id, sum(s.active)::bigint AS active,
        COALESCE(sum(s.critical_high), 0)::bigint AS critical_high, sum(s.risk)::bigint AS risk
    FROM {ACTIVE_FINDINGS_BY_TARGET_SQL} s
    JOIN targets m ON m.id = s.target_id
    CROSS JOIN LATERAL (SELECT m.id UNION SELECT m.asset_owner_id WHERE m.asset_owner_id IS NOT NULL) owner(asset_id)
    GROUP BY owner.asset_id)"""
SUMMARY_FROM = f"{ROOT_FROM} LEFT JOIN {ASSET_FINDINGS} fsum ON fsum.asset_id=t.id"
ROOT_WHERE = "t.asset_owner_id IS NULL AND COALESCE(t.discovery_source,'manual') <> 'model-intake'"
def _host_network(locator: str) -> str:
    return f"""({locator} LIKE '%:%'
    OR {locator} ~ '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'
    OR {locator} NOT LIKE '%.%'
    OR {locator} ~ '\\.(local|internal|localhost)$')"""


def _network_view(locator: str) -> str:
    return f"""({_host_network(locator)} OR p.target_id IS NOT NULL
    OR EXISTS(SELECT 1 FROM device_services service WHERE service.target_id=t.id AND service.state='open'))"""


def _web_view(locator: str) -> str:
    return f"""(NOT {_host_network(locator)} OR t.url ~ '^https?://'
    OR EXISTS(SELECT 1 FROM targets member WHERE member.asset_owner_id=t.id AND member.is_active
              AND member.url ~ '^https?://'))"""


HOST_NETWORK = _host_network('target_asset_locator(t.url)')
NETWORK_VIEW = _network_view('target_asset_locator(t.url)')
WEB_VIEW = _web_view('target_asset_locator(t.url)')
# The facet scan computes each asset's locator once (target_asset_locator is PL/pgSQL with an
# exception block; the views above call it eight times per row between them).
_FACET_LOCATOR_FROM = "CROSS JOIN LATERAL (SELECT target_asset_locator(t.url) AS locator OFFSET 0) tal"

MEMBERS = "(SELECT member.id FROM targets member WHERE member.id=t.id OR member.asset_owner_id=t.id)"
ENVIRONMENT = """COALESCE(NULLIF(t.metadata_json->>'environment',''),
    NULLIF(t.metadata_json->>'cohort',''),'production')"""
ACTIVE_FINDINGS = f"findings f WHERE f.status='active' AND f.target_id IN {MEMBERS}"
# The risk weight (critical 1000, high 100, medium 10, low 1) of an asset's active findings.
RISK_WEIGHT = "COALESCE(fsum.risk,0)"
HAS_FINDINGS = "COALESCE(fsum.active,0) > 0"
HAS_CRITICAL_HIGH = "COALESCE(fsum.critical_high,0) > 0"
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


# Targets holding a live standing authorization receipt. Uncorrelated, so PostgreSQL computes it
# once per query; it is usually a handful of ids.
_RECEIPT_HOLDERS = """ARRAY(SELECT s.target_id FROM approval_receipts a
    JOIN scope_receipts s ON s.id=a.scope_receipt_id
    WHERE a.approved_by IS NOT NULL AND a.status='active'
      AND a.risk_tier IN ('active','intrusive') AND a.action_name='target.authorization'
      AND (a.expires_at IS NULL OR a.expires_at > NOW())
      AND COALESCE(s.verdict,'') <> 'blocked' AND s.target_id IS NOT NULL)"""


def authorized_sql(alias: str) -> str:
    """Whether ``alias`` (a targets row) is covered by a standing authorization.

    The authority is the target itself or its owning asset (target_effective_authorization_target),
    so a target whose id and owner both hold no live receipt is decided without evaluating the
    per-row authority lookup: the guard is a necessary condition, never a new way to pass.
    """
    target_key = _host_key(_raw_host("authority.url"), "target_asset_locator(authority.url)")
    scope_raw = "lower(rtrim(trim(both '[]' FROM scope_host), '.'))"
    scope_key = _host_key(scope_raw, "target_asset_locator(target_asset_url(lower(trim(both '[]' FROM scope_host))))")
    return f"""(({alias}.id = ANY({_RECEIPT_HOLDERS}) OR {alias}.asset_owner_id = ANY({_RECEIPT_HOLDERS}))
    AND EXISTS(SELECT 1 FROM targets authority
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
          WHERE COALESCE(scope_host,'') <> '')))"""


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
        'any': HAS_FINDINGS,
        'critical_high': HAS_CRITICAL_HIGH,
        'none': f'NOT {HAS_FINDINGS}',
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
    # Operator-set ownership (Targets "Edit details"): who owns the asset and its reporting cohort.
    result['owner'] = str(metadata.get('owner') or '')[:200] or None
    result['cohort'] = str(metadata.get('cohort') or '')[:40] or None
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


def _validate(sort: str, chosen: dict[str, Any]) -> None:
    if sort not in SORTS:
        raise HTTPException(400, 'Unknown sort order')
    for name, value in chosen.items():
        if value is not None and value not in FILTERS[name]:
            raise HTTPException(400, f'Unknown {name.replace("_", " ")} filter')


def _scope_query(*, search: str, connected_only: bool, include_inactive: bool,
                 include_services: bool) -> _Query:
    base = "COALESCE(t.discovery_source,'manual') <> 'model-intake'" if include_services else ROOT_WHERE
    # $1-$3 are fixed: DETAIL_COLUMNS reads $1 to decide whether retired services are listed.
    return _Query(base + """
        AND ($1::boolean OR t.is_active)
        AND (NOT $2::boolean OR p.target_id IS NOT NULL)
        AND ($3::text='' OR t.name ILIKE '%' || $3 || '%' OR t.url ILIKE '%' || $3 || '%'
             OR EXISTS (SELECT 1 FROM targets member WHERE member.asset_owner_id=t.id
                        AND (member.name ILIKE '%' || $3 || '%' OR member.url ILIKE '%' || $3 || '%')))
    """, [include_inactive, connected_only, search.strip()])


def _apply_filters(query: _Query, chosen: dict[str, Any], environment: str | None) -> None:
    for name, value in chosen.items():
        if value is not None:
            query.where += ' AND ' + FILTERS[name][value]
    if environment:
        query.where += f' AND {ENVIRONMENT}={query.bind(environment.strip().lower())}'


def _needs_summary(sort: str, chosen: dict[str, Any]) -> bool:
    return sort == 'risk' or chosen.get('findings') is not None


async def list_assets(conn: Any, *, search: str = '', connected_only: bool = False,
                      include_inactive: bool = False, include_services: bool = False,
                      limit: int = 100, offset: int = 0, group_by: str | None = None,
                      asset_type: str | None = None, environment: str | None = None,
                      authorization: str | None = None, findings: str | None = None,
                      activity: str | None = None, sort: str = 'name',
                      include_facets: bool = False) -> dict[str, Any]:
    """The legacy (limit/offset) inventory response, deprecated for the 2.11.x line."""
    chosen = {'asset_type': asset_type, 'authorization': authorization, 'findings': findings, 'activity': activity}
    _validate(sort, chosen)
    query = _scope_query(search=search, connected_only=connected_only, include_inactive=include_inactive,
                         include_services=include_services)
    facet_query = _Query(query.where, query.parameters)
    _apply_filters(query, chosen, environment)
    from_sql = SUMMARY_FROM if _needs_summary(sort, chosen) else ROOT_FROM
    facets = await inventory_facets(conn, facet_query) if include_facets else None
    if group_by == 'domain':
        if include_services:
            raise HTTPException(400, 'Domain hierarchy groups assets; service records remain within their asset')
        result = await _list_domain_groups(conn, query, from_sql=from_sql, sort=sort, limit=limit, offset=offset)
    else:
        total = await conn.fetchval(f'SELECT count(*) FROM {from_sql} WHERE {query.where}', *query.parameters)
        order, _, direction = SORTS[sort]
        rows = await conn.fetch(f"""SELECT {ROOT_COLUMNS},{DETAIL_COLUMNS}
            FROM {from_sql} WHERE {query.where}
            ORDER BY {order} {direction},lower(COALESCE(t.name,t.url)),t.id
            LIMIT {query.bind(limit)} OFFSET {query.bind(offset)}""", *query.parameters)
        result = {'targets': [public_asset(row) for row in rows], 'total': int(total),
                  'limit': limit, 'offset': offset, 'inventory_kind': 'assets'}
    if facets is not None:
        result['facets'] = facets
    return result


async def _list_domain_groups(conn: Any, query: _Query, *, from_sql: str = ROOT_FROM, sort: str, limit: int,
                              offset: int) -> dict[str, Any]:
    """Page complete domain groups, rather than cutting a root and its subdomains across pages.

    Grouping uses the Public Suffix List (``group_domain``), which SQL cannot apply, so the
    matching assets' ids, locators and sort keys are read first, grouped and paged here, and only
    the page's assets are read in full.
    """
    order, aggregate, direction = SORTS[sort]
    matching = await conn.fetch(f"""SELECT t.id,target_asset_locator(t.url) AS locator,{order} AS sort_key
        FROM {from_sql} WHERE {query.where}""", *query.parameters)
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
    """Counts for each filter value over the search scope, before the other filters apply.

    Finding facets come from the finding summary joined once (``SUMMARY_FROM``), not from two
    correlated counts over ``findings`` per asset."""
    row = await conn.fetchrow(f"""WITH scope AS (
        SELECT {ENVIRONMENT} AS environment,{FILTERS['authorization']['authorized']} AS authorized,
            {HAS_FINDINGS} AS has_findings,
            {HAS_CRITICAL_HIGH} AS critical_high,
            {LAST_SCANNED} IS NOT NULL AS scanned,{SCANNING} AS scanning,
            {_web_view('tal.locator')} AS web,{_network_view('tal.locator')} AS network
        FROM {SUMMARY_FROM} {_FACET_LOCATOR_FROM} WHERE {query.where}
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


# --- list/v1 -----------------------------------------------------------------------------------
#
# Keyset pages over assets, or over domain groups with at most ``member_limit`` assets each. The
# sort keys are the legacy ones (NOT NULL), compared in SQL; ``-`` descends. Domain groups use the
# Public Suffix List grouping (``group_domain``) through ``target_inventory_groups``, a cache of
# that pure function keyed by locator and list version, filled for unseen locators on read.

DEFAULT_MEMBER_LIMIT = 20
MAX_MEMBER_LIMIT = 200
_LOCATOR = "COALESCE(target_asset_locator(t.url),'')"
_SORT_KEYS = {
    'name': (SORTS['name'][0], 'text'),
    'risk': (RISK_WEIGHT, 'int'),
    'recent': (SORTS['recent'][0], 'numeric'),
    'created': (f"COALESCE({SORTS['created'][0]},0)", 'numeric'),
}
ASSETS_V1 = ListSpec(
    scope='targets.inventory',
    sorts={name: SortKey(expr, kind) for name, (expr, kind) in _SORT_KEYS.items()},
    default_sort='name',
    fields={'id': 't.id'},
    id_expr='t.id',
)
# Groups: name sorts by the domain itself (as legacy); the others by the group's highest key.
GROUPS_V1 = ListSpec(
    scope='targets.inventory.domains',
    sorts={
        'name': SortKey('g.group_domain COLLATE "C"', 'text'),
        'risk': SortKey('g.group_sort', 'int'),
        'recent': SortKey('g.group_sort', 'numeric'),
        'created': SortKey('g.group_sort', 'numeric'),
    },
    default_sort='name',
    fields={'root_domain': 'g.group_domain', 'member_count': 'g.member_count'},
    id_expr='g.group_domain COLLATE "C"',
    id_kind='text',
)


def psl_version() -> str:
    global _PSL_VERSION
    if _PSL_VERSION is None:
        _PSL_VERSION = 'group-domain/v1:' + hashlib.sha256(PSL_PIN_PATH.read_bytes()).hexdigest()[:32]
    return _PSL_VERSION


_PSL_VERSION: str | None = None


async def fill_group_cache(conn: Any, from_sql: str, query: _Query) -> int:
    """Compute ``group_domain`` for matching locators the cache has not seen under this list."""
    version_ref = f'${len(query.parameters) + 1}'
    missing = await conn.fetch(f"""SELECT DISTINCT {_LOCATOR} AS locator FROM {from_sql}
        WHERE {query.where} AND NOT EXISTS (
            SELECT 1 FROM target_inventory_groups cache
            WHERE cache.locator={_LOCATOR} AND cache.psl_version={version_ref})""",
                               *query.parameters, psl_version())
    if not missing:
        return 0
    rows = [(row['locator'], group_domain(row['locator']), psl_version()) for row in missing]
    await conn.executemany("""INSERT INTO target_inventory_groups(locator, group_domain, psl_version)
        VALUES ($1, $2, $3)
        ON CONFLICT (locator) DO UPDATE SET group_domain=EXCLUDED.group_domain, psl_version=EXCLUDED.psl_version""",
                           rows)
    return len(rows)


async def list_assets_v1(conn: Any, page: Page, *, search: str = '', connected_only: bool = False,
                         include_inactive: bool = False, include_services: bool = False,
                         group_by: str | None = None, asset_type: str | None = None,
                         environment: str | None = None, authorization: str | None = None,
                         findings: str | None = None, activity: str | None = None,
                         member_limit: int = DEFAULT_MEMBER_LIMIT,
                         include_facets: bool = False) -> dict[str, Any]:
    if page.fields is not None:
        raise HTTPException(400, {'error': 'fields_unsupported', 'message': 'the inventory does not support fields='})
    chosen = {'asset_type': asset_type, 'authorization': authorization, 'findings': findings, 'activity': activity}
    sort_name = (page.sort or 'name').lstrip('-')
    _validate(sort_name, chosen)
    filters = {**chosen, 'search': search.strip(), 'connected_only': connected_only,
               'include_inactive': include_inactive, 'include_services': include_services,
               'environment': (environment or '').strip().lower() or None, 'group_by': group_by,
               'member_limit': member_limit}
    query = _scope_query(search=search, connected_only=connected_only, include_inactive=include_inactive,
                         include_services=include_services)
    facet_query = _Query(query.where, query.parameters)
    _apply_filters(query, chosen, environment)
    from_sql = SUMMARY_FROM if _needs_summary(sort_name, chosen) else ROOT_FROM
    if group_by == 'domain':
        if include_services:
            raise HTTPException(400, 'Domain hierarchy groups assets; service records remain within their asset')
        body = await _domain_groups_v1(conn, page, query, from_sql=from_sql, sort_name=sort_name,
                                       filters=filters, member_limit=member_limit)
    else:
        plan = ASSETS_V1.plan(page, filters=filters)
        params = SqlParams(query.parameters)
        page_where = [query.where] + plan.keyset_clauses(params)
        generated_at = await snapshot_time(conn)  # before the page query
        rows = await conn.fetch(f"""SELECT {ROOT_COLUMNS},{DETAIL_COLUMNS},{plan.select_list}
            FROM {from_sql} WHERE {' AND '.join(page_where)}
            ORDER BY {plan.order_by} LIMIT {plan.fetch_limit}""", *params.values)
        total, kind = await count_total(conn, page.count, from_sql=from_sql, where=[query.where],
                                        values=query.parameters)
        detail = {row['id']: row for row in rows}
        body = plan.envelope(rows, total=total, total_kind=kind, generated_at=generated_at,
                             transform=lambda item: _public_v1_asset(detail[item['id']]))
        body['inventory_kind'] = 'assets'
    if include_facets:
        body['facets'] = await inventory_facets(conn, facet_query)
    return body


_KEYSET_COLUMNS = ('__list_sort', '__list_id')


def _public_v1_asset(row: Any) -> dict[str, Any]:
    return public_asset({key: row[key] for key in row.keys() if key not in _KEYSET_COLUMNS})


async def _domain_groups_v1(conn: Any, page: Page, query: _Query, *, from_sql: str, sort_name: str,
                            filters: dict[str, Any], member_limit: int) -> dict[str, Any]:
    plan = GROUPS_V1.plan(page, filters=filters)
    await fill_group_cache(conn, from_sql, query)
    order, aggregate, _direction = SORTS[sort_name]
    params = SqlParams(query.parameters)
    version = params.add(psl_version())
    group_sort = '0' if sort_name == 'name' else f"COALESCE({'max' if aggregate == 'max' else 'min'}(a.sort_key),0)"
    groups_from = f"""(SELECT a.group_domain, count(*) AS member_count, {group_sort} AS group_sort
        FROM (SELECT cache.group_domain, {order} AS sort_key
              FROM {from_sql}
              JOIN target_inventory_groups cache ON cache.locator={_LOCATOR} AND cache.psl_version={version}
              WHERE {query.where}) a
        GROUP BY a.group_domain) g"""
    count_values = params.snapshot()
    keyset = plan.keyset_clauses(params)
    generated_at = await snapshot_time(conn)  # before the page query
    rows = await conn.fetch(f"""SELECT {plan.select_list} FROM {groups_from}
        {'WHERE ' + ' AND '.join(keyset) if keyset else ''}
        ORDER BY {plan.order_by} LIMIT {plan.fetch_limit}""", *params.values)
    total, kind = await count_total(conn, page.count, from_sql=groups_from, values=count_values)
    domains = [row['root_domain'] for row in rows[: page.limit]]
    members: dict[str, list[Any]] = {domain: [] for domain in domains}
    if domains:
        descending = (page.sort or '').startswith('-')
        member_params = SqlParams(query.parameters)
        member_version = member_params.add(psl_version())
        domains_ref = member_params.add(domains)
        limit_ref = member_params.add(member_limit)
        # The legacy member order: the domain's own asset first, then the sort key in the page's
        # direction (NULL as PostgreSQL places it), then locator and id.
        direction = 'DESC NULLS FIRST' if descending else 'ASC NULLS LAST'
        # Text keys compare by code point, as the legacy (Python) grouping did.
        member_order = f'({order}) COLLATE "C"' if sort_name == 'name' else order
        member_rows = await conn.fetch(f"""SELECT * FROM (
                SELECT {ROOT_COLUMNS},{DETAIL_COLUMNS}, cache.group_domain AS __group,
                       row_number() OVER (PARTITION BY cache.group_domain
                           ORDER BY ({_LOCATOR} IS DISTINCT FROM cache.group_domain), {member_order} {direction},
                                    {_LOCATOR} COLLATE "C", t.id) AS __rank
                FROM {from_sql}
                JOIN target_inventory_groups cache ON cache.locator={_LOCATOR} AND cache.psl_version={member_version}
                WHERE {query.where} AND cache.group_domain = ANY({domains_ref}::text[])) ranked
            WHERE __rank <= {limit_ref}
            ORDER BY __group, __rank""", *member_params.values)
        for row in member_rows:
            members[row['__group']].append(row)

    def group_item(item: dict[str, Any]) -> dict[str, Any]:
        domain = item['root_domain']
        targets = []
        for row in members.get(domain, []):
            asset = public_asset({key: row[key] for key in row.keys() if key not in ('__group', '__rank')})
            asset['root_domain'] = domain
            targets.append(asset)
        return {'root_domain': domain, 'discoverable': discoverable(domain), 'targets': targets,
                'member_count': int(item['member_count']),
                'members_truncated': int(item['member_count']) > len(targets)}

    body = plan.envelope(rows, total=total, total_kind=kind, transform=group_item, generated_at=generated_at)
    body.update({'inventory_kind': 'assets', 'group_by': 'domain'})
    return body
