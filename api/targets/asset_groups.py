"""Domain hierarchy over canonical assets. Grouping never creates asset membership."""
from typing import Any

try:
    from scanner_tools.vendor_risk import MULTI_PART_TLDS
except ModuleNotFoundError:
    from scanner.scanner_tools.vendor_risk import MULTI_PART_TLDS


GROUP_DOMAIN = r"""CASE
    WHEN locator LIKE '%:%' OR locator ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
         OR locator='localhost' OR locator ~ '\.(local|internal|localhost)$'
         OR locator NOT LIKE '%.%' THEN locator
    WHEN substring(locator from '[^.]+\.[^.]+$')=ANY($4::text[])
        THEN COALESCE(substring(locator from '[^.]+\.[^.]+\.[^.]+$'),locator)
    ELSE COALESCE(substring(locator from '[^.]+\.[^.]+$'),locator)
END"""


async def list_domain_assets(conn: Any, *, where: str, parameters: list, limit: int, offset: int):
    from .asset_store import ROOT_COLUMNS, ROOT_FROM, public_asset
    # Page complete groups, rather than cutting a root and its subdomains across asset pages.
    filtered = f"""WITH matching AS (
        SELECT t.id,target_asset_locator(t.url) AS locator FROM {ROOT_FROM} WHERE {where}
    ), grouped AS (SELECT id,{GROUP_DOMAIN} AS group_domain FROM matching)"""
    args = [*parameters, sorted(MULTI_PART_TLDS)]
    counts = await conn.fetchrow(f"""{filtered}
        SELECT count(*) AS total,count(DISTINCT group_domain) AS total_groups FROM grouped""", *args)
    rows = await conn.fetch(f"""{filtered}, page AS (
        SELECT DISTINCT group_domain FROM grouped ORDER BY group_domain LIMIT $5 OFFSET $6
    )
    SELECT {ROOT_COLUMNS}, grouped.group_domain,
        (SELECT count(*) FROM targets member WHERE member.asset_owner_id=t.id AND member.is_active) AS origin_count,
        (SELECT count(*) FROM device_services service WHERE service.target_id=t.id AND service.state='open') AS service_count,
        (SELECT count(*) FROM findings f WHERE f.status='active'
            AND f.target_id IN (SELECT id FROM targets member WHERE member.id=t.id OR member.asset_owner_id=t.id)) AS active_findings_count
    FROM {ROOT_FROM} JOIN grouped ON grouped.id=t.id JOIN page USING(group_domain)
    ORDER BY group_domain,(target_asset_locator(t.url)=group_domain) DESC,target_asset_locator(t.url),t.id
    """, *args, limit, offset)
    groups = {}
    targets = []
    for row in rows:
        asset = public_asset(row)
        domain = asset.pop('group_domain')
        asset['root_domain'] = domain
        targets.append(asset)
        groups.setdefault(domain, {'root_domain':domain, 'targets':[]})['targets'].append(asset)
    return {'targets':targets, 'groups':list(groups.values()), 'total':int(counts['total']),
            'total_groups':int(counts['total_groups']), 'limit':limit, 'offset':offset,
            'inventory_kind':'assets', 'group_by':'domain'}
