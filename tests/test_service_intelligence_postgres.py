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
          CREATE TEMP TABLE hunt_runs (id uuid,target_id uuid,device_target_id uuid,target_kind text,created_at timestamptz,context_pack jsonb);
          CREATE TEMP TABLE hunt_actions (id uuid,hunt_run_id uuid,capability_name text,status text,receipt_id uuid);
          CREATE TEMP TABLE budget_reservations (id text,owner_kind text,owner_id text,action_id text,action_digest text,
            capability_name text,status text,state_json jsonb,state_digest text,receipt_json jsonb,finished_at timestamptz);
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


@pytest.mark.asyncio
async def test_verify_scan_outcomes_read_from_real_scan_action_and_finding_rows():
    import asyncpg
    from api.exposure.service_rows import attach_verification, verification_records

    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute("""
          CREATE TEMP TABLE scans (id uuid,target_id uuid,status text,created_at timestamptz,completed_at timestamptz,options jsonb);
          CREATE TEMP TABLE scan_capability_actions (scan_id uuid,action_id text,status text,reason_code text,receipt_json jsonb);
          CREATE TEMP TABLE findings (id uuid,target_id uuid,scan_id uuid,first_seen_scan_id uuid,last_seen_scan_id uuid,
            status text,severity text,last_seen_at timestamptz,evidence jsonb,proof_state text);
        """)
        web, other = uuid.uuid4(), uuid.uuid4()
        matched, clean, gap, unrelated = (uuid.uuid4() for _ in range(4))
        stamp = datetime(2026, 10, 16, tzinfo=timezone.utc)
        rows = [
            (matched, web, 'completed', stamp, ['cve-2021-41773']),
            (clean, web, 'completed', stamp.replace(day=15), ['cve-2023-0001']),
            (gap, web, 'completed', stamp.replace(day=14), ['cve-2024-0002']),
            (unrelated, other, 'completed', stamp, ['cve-2024-0002']),
        ]
        for scan_id, target, status, created, ids in rows:
            await conn.execute("INSERT INTO scans VALUES ($1,$2,$3,$4,$4,$5::jsonb)", scan_id, target, status, created,
                               json.dumps({"verify_templates": ids}))
        await conn.execute("INSERT INTO scans VALUES ($1,$2,'completed',$3,$3,'{}'::jsonb)", uuid.uuid4(), web, stamp)
        def receipt(ran, excluded=None):
            return json.dumps({"redacted_execution": {"verify_selection": {
                "requested": sorted(set(ran) | set(excluded or {})), "ran": ran,
                "excluded": excluded or {}, "negative_unreliable": {}}}})
        insert = "INSERT INTO scan_capability_actions VALUES ($1,$2,$3,$4,$5::jsonb)"
        await conn.execute(insert, matched, 'active.templates', 'success', None, receipt(['cve-2021-41773']))
        await conn.execute(insert, clean, 'active.templates.002', 'success', None, receipt(['cve-2023-0001']))
        await conn.execute(insert, gap, 'active.templates', 'skipped', 'verify_checks_excluded',
                           receipt([], {'cve-2024-0002': 'needs_oob_interaction'}))
        await conn.execute(insert, unrelated, 'active.templates', 'success', None, receipt(['cve-2024-0002']))
        finding = uuid.uuid4()
        await conn.execute("""INSERT INTO findings VALUES ($1,$2,$3,$3,$3,'active','critical',$4,
                           '{"template_id":"CVE-2021-41773"}'::jsonb,'candidate')""", finding, web, matched, stamp)
        target = {'id': str(web), 'kind': 'web', 'locator': 'https://app.example.test'}
        services = [{
            'id': 'svc', 'application_origin': 'https://app.example.test', 'presence': 'observed_open',
            'binding_status': 'observation_only',
            'cve_candidates': [
                {'id': cve, 'checks': [{'kind': 'nuclei_template', 'id': check}]}
                for cve, check in (('CVE-2021-41773', 'CVE-2021-41773'), ('CVE-2023-0001', 'cve-2023-0001'),
                                   ('CVE-2024-0002', 'cve-2024-0002'), ('CVE-2024-0003', 'cve-2024-0003'))
            ],
        }]
        async with conn.transaction(isolation='repeatable_read', readonly=True):
            records = await verification_records(conn, target, services)
        attach_verification(target, services, records)
        states = {item['id']: item['verification'] for item in services[0]['cve_candidates']}
        assert states['CVE-2021-41773']['status'] == 'check_matched'
        assert states['CVE-2021-41773']['finding_id'] == str(finding)
        assert states['CVE-2021-41773']['proof_state'] == 'candidate'
        assert states['CVE-2023-0001']['status'] == 'check_not_matched'
        assert states['CVE-2024-0002']['status'] == 'inconclusive'
        assert 'needs_oob_interaction' in states['CVE-2024-0002']['reason']
        assert states['CVE-2024-0002']['scan_id'] == str(gap)  # never the other target's Scan
        assert states['CVE-2024-0003']['status'] == 'available'
        assert states['CVE-2024-0003']['request']['verify_templates'] == ['cve-2024-0003']
    finally:
        await conn.close()



@pytest.mark.asyncio
async def test_intel_bundle_high_water_mark_only_rises_and_repairs_the_mark_file(tmp_path):
    import asyncpg
    from scanner.scanner_tools import intel_bundle

    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute("DROP TABLE IF EXISTS intel_bundle_high_water")
        await conn.execute(intel_bundle.HIGH_WATER_SCHEMA_SQL)
        await conn.execute(intel_bundle.HIGH_WATER_SCHEMA_SQL)  # idempotent on restart
        assert await intel_bundle.database_high_water(conn) == 0
        assert await intel_bundle.record_database_high_water(conn, 7, "aaaaaaaaaaaaaaaa") == 7
        assert await intel_bundle.record_database_high_water(conn, 3, "bbbbbbbbbbbbbbbb") == 7
        directory = str(tmp_path / "intel")
        assert intel_bundle.read_high_water(directory) == 0
        assert await intel_bundle.sync_high_water_from_database(conn, directory) == 7
        assert intel_bundle.read_high_water(directory) == 7
    finally:
        await conn.execute("DROP TABLE IF EXISTS intel_bundle_high_water")
        await conn.close()
