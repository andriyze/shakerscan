"""Optional real-SQL acceptance, using connection-local temporary tables only."""
from datetime import datetime, timezone
import json
import os
import uuid

import pytest

from api.exposure.service_actions import canonical_registry
from api.exposure.service_intel import load_service_intelligence
from api.exposure.service_store import service_page

DATABASE_URL = os.environ.get("SERVICE_INTELLIGENCE_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="isolated Service Intelligence PostgreSQL test database not configured")


@pytest.mark.asyncio
async def test_target_pagination_and_historical_device_locator_in_real_postgres():
    import asyncpg
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute("""
          CREATE TEMP TABLE targets (id uuid,name text,url text,root_domain text,discovery_source text,is_active boolean);
          CREATE TEMP TABLE device_targets (id uuid,name text,primary_locator text,locator_generation integer,is_active boolean,created_at timestamptz);
          CREATE TEMP TABLE device_locator_history (device_target_id uuid,changed_at timestamptz);
          CREATE TEMP TABLE scans (id uuid,target_id uuid,device_target_id uuid,target_url text,created_at timestamptz,status text);
          CREATE TEMP TABLE device_services (id uuid,device_target_id uuid,scan_id uuid,transport text,port integer,state text,service_name text,
            product text,version text,cpe text,encrypted boolean,web_origin text,first_seen_at timestamptz,last_seen_at timestamptz,metadata_json jsonb);
          CREATE TEMP TABLE scan_capability_actions (scan_id uuid,action_id text,capability_name text,action_digest text,result_digest text,
            result_json jsonb,status text,worker_id text,finished_at timestamptz);
          CREATE TEMP TABLE findings (id uuid,target_id uuid,device_target_id uuid,url text,title text,severity text,status text,
            last_verification_verdict text,last_seen_at timestamptz,evidence jsonb);
        """)
        device = uuid.UUID('11111111-1111-4111-8111-111111111111')
        web = uuid.UUID('22222222-2222-4222-8222-222222222222')
        scan = uuid.UUID('33333333-3333-4333-8333-333333333333')
        stamp = datetime(2026, 9, 16, tzinfo=timezone.utc)
        await conn.execute("INSERT INTO targets VALUES ($1,'Web','https://app.example.test','example.test',NULL,true)", web)
        await conn.execute("INSERT INTO device_targets VALUES ($1,'Device','device.example.test',2,true,$2)", device, stamp)
        await conn.execute("INSERT INTO device_locator_history VALUES ($1,$2)", device, stamp)
        await conn.execute("INSERT INTO scans VALUES ($1,NULL,$2,'old.example.test',$3,'completed')", scan, device, stamp)
        await conn.execute("""INSERT INTO device_services VALUES ($1,$2,$3,'tcp',8443,'open','https','GoAhead','3.0.0',
                           'cpe:2.3:a:embedthis:goahead:3.0.0:*:*:*:*:*:*:*',true,'https://old.example.test:8443',$4,$4,'{}')""",
                           uuid.uuid4(), device, scan, stamp)
        snapshot, matcher = load_service_intelligence()
        kwargs = dict(root_domain='example.test', search='', snapshot=snapshot, matcher=matcher, registry=canonical_registry())
        async with conn.transaction(isolation='repeatable_read', readonly=True):
            first = await service_page(conn, target_kind='all', target_id=None, limit=1, offset=0, **kwargs)
            second = await service_page(conn, target_kind='all', target_id=None, limit=1, offset=1, **kwargs)
            assert first['total_targets'] == second['total_targets'] == 2
            assert first['has_more'] and not second['has_more']
            assert first['targets'][0]['id'] != second['targets'][0]['id']
            service = first['targets'][0]['services'][0]
            assert service['binding_status'] == 'historical_locator' and service['hunt_href'] is None
            assert service['cve_candidates'][0]['applicability'] == 'candidate'
            scoped = await service_page(conn, target_kind='web', target_id=device, limit=10, offset=0, **kwargs)
            assert scoped['total_targets'] == 0
            literal = await service_page(conn, target_kind='all', target_id=None, limit=10, offset=0, **{**kwargs, 'search': '%'})
            assert literal['total_targets'] == 0
    finally:
        await conn.close()
