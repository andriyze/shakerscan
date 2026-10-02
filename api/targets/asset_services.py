"""Bounded shared service evidence from existing Scan, device and Hunt stores."""
from typing import Any
from .asset_migration import locator_from_url
try:
    from exposure.service_store import target_inventory
    from exposure.service_actions import canonical_registry
except ModuleNotFoundError:
    from ..exposure.service_store import target_inventory
    from ..exposure.service_actions import canonical_registry

MAX_ORIGINS = 8
MAX_SERVICES = 500


async def asset_service_knowledge(conn: Any, target_id: Any, *, snapshot=None, matcher=None, registry=None) -> dict[str, Any]:
    root = await conn.fetchrow("""SELECT t.id,t.url,t.name,t.root_domain,p.locator_generation,
        COALESCE((SELECT max(changed_at) FROM device_locator_history h WHERE h.device_target_id=t.id),t.created_at) AS locator_changed_at
        FROM targets t LEFT JOIN target_device_profiles p ON p.target_id=t.id WHERE t.id=$1""",target_id)
    if root is None:
        return {'services':[], 'warnings':['Target no longer exists.'], 'sources_truncated':False}
    if not await conn.fetchval("SELECT to_regclass('hunt_actions') IS NOT NULL AND to_regclass('budget_reservations') IS NOT NULL"):
        return {'services':[], 'warnings':['Service receipt storage is unavailable.'], 'sources_truncated':True}
    members = await conn.fetch("""SELECT id,url,name,root_domain FROM targets
        WHERE asset_owner_id=$1 AND target_asset_access_owner(id)=$1
        ORDER BY url,id LIMIT $2""",target_id,MAX_ORIGINS+1)
    views = [{'id':root['id'],'kind':'web','label':root['name'] or root['url'],
              'locator':root['url'],'root_domain':root['root_domain']}]
    if root['locator_generation'] is not None:
        views.append({**views[0], 'kind':'device','locator':locator_from_url(root['url']),
                      'locator_generation':root['locator_generation'],
                      'locator_changed_at':root['locator_changed_at']})
    views.extend({'id':item['id'],'kind':'web','label':item['name'] or item['url'],
                  'locator':item['url'],'root_domain':item['root_domain']} for item in members[:MAX_ORIGINS])
    services, warnings = [], []
    truncated = len(members) > MAX_ORIGINS
    for view in views:
        result = await target_inventory(conn,view,snapshot or {'status':'unavailable'},matcher,registry or canonical_registry())
        room = MAX_SERVICES - len(services)
        services.extend(result['services'][:room])
        warnings.extend(result['warnings'])
        truncated = truncated or result['sources_truncated']
        if len(result['services']) > room:
            truncated = True
            warnings.append('Shared service evidence is limited to 500 records; inspect individual origins for additional history.')
    if len(members) > MAX_ORIGINS:
        warnings.append('Application-service evidence is limited to eight current origins; inspect an origin directly for additional history.')
    return {'services':services,'warnings':list(dict.fromkeys(warnings)), 'sources_truncated':truncated}
