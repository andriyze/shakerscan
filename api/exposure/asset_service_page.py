"""Shared asset projection composed above the existing service evidence reader."""
try:
    from targets.asset_services import asset_service_knowledge
    from targets.asset_store import resolve_asset_id
except ModuleNotFoundError:
    from ..targets.asset_services import asset_service_knowledge
    from ..targets.asset_store import resolve_asset_id
from .service_intel import snapshot_summary


async def service_page(conn, *, target_id, snapshot, matcher, registry, **_):
    owner = await resolve_asset_id(conn,target_id)
    knowledge = await asset_service_knowledge(conn,owner,snapshot=snapshot,matcher=matcher,registry=registry)
    return {'targets':[{'id':str(owner),**knowledge}], 'intelligence':snapshot_summary(snapshot),
            'limitations':['Existing evidence only; no traffic is executed.',
                           'Shared service history is bounded to eight application origins and 500 records.']}
