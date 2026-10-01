"""One host approval; exact service overrides and revocations stay effective."""
import asyncio
import json
import uuid

from api import target_authorization
from api.targets.asset_authority import standing_authorization_matches_target
from api.targets.asset_migration import migrate_target_assets
from api.targets.asset_inputs_migration import migrate_asset_inputs
from tests.test_target_asset_migration_postgres import database
from tests.test_target_asset_inputs_postgres import prepare


async def receipt(conn, target, host, *, status='active'):
    scope='scope-'+uuid.uuid4().hex
    await conn.execute("""INSERT INTO scope_receipts(id,target_id,input_scope,normalized_scope,verdict,blocked_by,warnings,checks,environment,allowed_hosts,allowed_root_domains,redirect_destinations)
        VALUES($1,$2,'{}',$3,'allowed','[]','[]','[]','lab',$4,'[]','[]')""",scope,target,json.dumps({'host':host}),json.dumps([host]))
    return await conn.fetchval("""INSERT INTO approval_receipts(scope_receipt_id,risk_tier,confirmations,action_name,action_context,approved_by,status)
        VALUES($1,'active','["confirm_authorized"]','target.authorization','{}','fixture',$2) RETURNING id""",scope,status)


def test_host_authority_is_reused_and_service_revocation_is_not_bypassed():
    async def run():
        async with database() as conn:
            await prepare(conn)
            device=await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Shared','authority.test') RETURNING id")
            origin=await conn.fetchval("INSERT INTO targets(url) VALUES('https://authority.test:8443') RETURNING id")
            other=await conn.fetchval("INSERT INTO targets(url) VALUES('https://other-authority.test') RETURNING id")
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            approval=await receipt(conn,device,'authority.test')
            inherited=await target_authorization.current_target_authorization(conn,origin)
            assert inherited['inherited'] and inherited['approval_receipt_id']==str(approval)
            assert await conn.fetchval('SELECT count(*) FROM approval_receipts')==1
            assert await standing_authorization_matches_target(conn,target_id=origin,scope_target_id=device,approval_receipt_id=approval)
            assert not await standing_authorization_matches_target(conn,target_id=other,scope_target_id=device,approval_receipt_id=approval)
            await target_authorization.revoke_target_authorization(conn,origin,revoked_by='fixture',reason='service excluded')
            assert await target_authorization.current_target_authorization(conn,origin) is None
            assert not await standing_authorization_matches_target(conn,target_id=origin,scope_target_id=device,approval_receipt_id=approval)
            own=await receipt(conn,origin,'authority.test')
            current=await target_authorization.current_target_authorization(conn,origin)
            assert not current['inherited'] and current['approval_receipt_id']==str(own)
            await target_authorization.revoke_target_authorization(conn,device,revoked_by='fixture',reason='host withdrawn')
            assert (await target_authorization.current_target_authorization(conn,origin))['approval_receipt_id']==str(own)
    asyncio.run(run())


def test_locator_change_and_expired_explicit_authority_do_not_fall_back_to_host():
    async def run():
        async with database() as conn:
            await prepare(conn)
            device=await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Shared','old-locator.test') RETURNING id")
            origin=await conn.fetchval("INSERT INTO targets(url) VALUES('https://old-locator.test:8443') RETURNING id")
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            host_approval=await receipt(conn,device,'old-locator.test')
            own=await receipt(conn,origin,'old-locator.test')
            await conn.execute("UPDATE approval_receipts SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1",own)
            assert await target_authorization.current_target_authorization(conn,origin) is None
            assert not await standing_authorization_matches_target(conn,target_id=origin,scope_target_id=device,approval_receipt_id=host_approval)
            await conn.execute("UPDATE device_targets SET primary_locator='new-locator.test',locator_generation=locator_generation+1 WHERE id=$1",device)
            assert await target_authorization.current_target_authorization(conn,device) is None
    asyncio.run(run())
