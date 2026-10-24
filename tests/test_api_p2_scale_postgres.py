"""The 2.11 bounded reads of milestone 2 on real PostgreSQL, against the SQL they replaced.

Real PostgreSQL only: API_P2_TEST_DATABASE_URL on localhost naming ``shakerscan_api_p2_test``.
The module resets that database's public schema, installs db/init.sql plus the startup
migrations and seeds ``.invalid``/private hosts only.

What it proves (tests/api_p2_reference.py holds the replaced SQL verbatim):

* the Scan assessment columns: a steady-state restart takes no lock on ``scans``; the trigger
  projects every write; rows written before them read the same through the NULL-tolerant read;
  the background projection leaves ``updated_at`` alone and then reads the same from columns;
* ``/metrics/v2`` counters, grade reasons and reconciliation equal the previous SQL, with rows
  projected and not projected;
* ``/devices``, ``/investigation/candidates``, ``/evidence/instances``, ``/credential-profiles``
  and ``/exposure/services``: the legacy pages equal the previous queries, and list/v1 walks reach
  every row, in the legacy order, with a cursor bound to its filters;
* ``/ai/inventory`` equals the inventory built from the previous scan query;
* ``/scans/{id}``: the projected parallel children give the same contributions; findings bounded;
* the research autopilot claims past a batch of blocked episodes without examining them all.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import uuid

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("API_P2_TEST_DATABASE_URL")
REQUIRED = os.environ.get("API_P2_POSTGRES_REQUIRED") == "1"
DATABASE = "shakerscan_api_p2_test"
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable api-p2 PostgreSQL database"
)

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fastapi import HTTPException  # noqa: E402

import list_contract as lc  # noqa: E402
from tests import api_p2_reference as ref  # noqa: E402

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


async def _connect():
    return await asyncpg.connect(require_disposable_database(DSN, DATABASE))


def _run(fn):
    async def wrapper():
        conn = await _connect()
        try:
            return await fn(conn)
        finally:
            await conn.close()
    return asyncio.run(wrapper())


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        conn = self.conn

        class Ctx:
            async def __aenter__(self_inner):
                return conn

            async def __aexit__(self_inner, *exc):
                return False
        return Ctx()


def _request(conn):
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(db_pool=_Pool(conn))))


def _api_module():
    import importlib
    module = importlib.import_module("api")
    return importlib.import_module("api.api") if hasattr(module, "__path__") else module


@pytest.fixture(autouse=True)
def _cursor_key():
    lc.configure_cursor_key(b"q" * 32)
    yield
    lc.configure_cursor_key(None)


RESULTS = [
    None,
    {},
    {"result": {"risk_assessment_state": "observed", "application_observed": True},
     "coverage": {"grade_reliability": {"reliable": True, "reasons": []}}},
    {"result": {"risk_assessment_state": "not_examined", "application_observed": False},
     "coverage": {"grade_reliability": {"reliable": False, "reasons": ["application_not_observed", "x"]}}},
    {"result": {"application_observed": None},
     "coverage": {"grade_reliability": {"reliable": "false", "reasons": "not-an-array"}}},
    {"result": {"risk_assessment_state": "partial"},
     "coverage": {"grade_reliability": {"reasons": ["family_incomplete", 3, None, {"k": 1}]}}},
    {"coverage": {"grade_reliability": {"reliable": "true"}}},
    {"result": "text", "coverage": []},
]

SEED_SQL = """
-- Connected devices (unified targets + profiles through the compatibility view).
INSERT INTO device_targets(name, primary_locator, device_class, environment, metadata_json, is_active)
SELECT 'device '||g, '10.66.0.'||g, (ARRAY['camera','router','printer'])[1+g%3], 'production',
       jsonb_build_object('n', g), g % 7 <> 0
FROM generate_series(1, 45) g;
UPDATE targets t SET updated_at = TIMESTAMPTZ '2026-09-01' + p.rn * INTERVAL '1 minute'
FROM (SELECT target_id, row_number() OVER (ORDER BY md5(target_id::text)) rn FROM target_device_profiles) p
WHERE p.target_id = t.id;
UPDATE target_device_profiles SET updated_at = TIMESTAMPTZ '2026-08-01';
INSERT INTO scans(device_target_id, target_url, status, scan_type, run_kind, created_at, completed_at,
                  execution_context, coverage_json, result)
SELECT p.target_id, 'device-'||p.target_id, 'completed', 'device_posture', 'device_posture', now(), now(), '{}', '{}',
       CASE WHEN abs(hashtext(p.target_id::text)) % 4 = 0 THEN NULL ELSE jsonb_build_object('device_posture', jsonb_build_object(
           'completeness', jsonb_build_object('complete', abs(hashtext(p.target_id::text)) % 2 = 0),
           'decision', jsonb_build_object('decision', 'pass'),
           'reachability', jsonb_build_object('status', 'reachable', 'attempts', '[1,2]'::jsonb,
                                              'nmap_host_discovery', 'x'))) END
FROM target_device_profiles p;
UPDATE target_device_profiles p SET last_scan_id = s.id FROM scans s
WHERE s.device_target_id = p.target_id AND abs(hashtext(p.target_id::text)) % 5 <> 0;
INSERT INTO device_services(device_target_id, transport, port, state, service_name)
SELECT p.target_id, 'tcp', port, CASE WHEN port = 23 THEN 'not_observed' ELSE 'open' END, 'svc'
FROM target_device_profiles p, unnest(ARRAY[22, 23, 80]) port;
-- Investigation candidates with observations; equal last_seen_at pairs exercise the id tiebreak.
INSERT INTO investigation_candidates(plane, target_id, family, title, claim, claimed_severity, evidence_refs,
    verification_context, fingerprint, status, last_seen_at, created_at, updated_at)
SELECT 'web', t.id, 'xss', 'Candidate '||g, 'claim', (ARRAY['critical','high','info'])[1+g%3],
       jsonb_build_array('ref-'||g, 'ref2'), jsonb_build_object('c', g), 'p2-cand-'||g,
       (ARRAY['new','verified','refuted'])[1+g%3], TIMESTAMPTZ '2026-09-10' + (g/2) * INTERVAL '1 minute',
       TIMESTAMPTZ '2026-09-10', TIMESTAMPTZ '2026-09-10' + g * INTERVAL '1 second'
FROM generate_series(1, 130) g
JOIN (SELECT id, row_number() OVER (ORDER BY url) rn FROM targets WHERE url LIKE 'https://web%') t ON t.rn = 1 + g % 6;
INSERT INTO investigation_candidate_observations(candidate_id, source_kind, title, claim, observed_at)
SELECT c.id, 'hunt', c.title, 'obs', now() FROM investigation_candidates c, generate_series(1, 3) k
WHERE k <= 1 + abs(hashtext(c.id::text)) % 3;
-- Evidence instances (more than one list/v1 page); every tenth on one finding.
INSERT INTO findings(id, fingerprint, title, severity, tool, url, evidence, status, source)
VALUES ('aaaaaaaa-0000-4000-8000-000000000001', 'p2-evidence-finding', 'E',
        'high', 'nuclei', 'https://web1.example.invalid/e', '{}', 'active', 'scan');
INSERT INTO evidence_instances(target_id, concrete_url, hash, proof_state, evidence_strength,
    request_response_refs, principal_pair, proof_observation, metadata_json, created_at, finding_id)
SELECT t.id, 'https://web1.example.invalid/e/'||g, md5(g::text), 'unverified', 'signal',
       jsonb_build_array('r'), jsonb_build_object('a', 'b'),
       jsonb_build_object('objective', 'obj '||g, 'verdict', 'inconclusive', 'body', repeat('p', 50),
                          'comparisons', jsonb_build_array(1, 2, g % 3),
                          'family_proof', jsonb_build_object('family', 'sqli', 'verdict', 'x', 'extra', 'y'),
                          'token', 'secret-value-'||g),
       jsonb_build_object('m', g), TIMESTAMPTZ '2026-09-20' + g * INTERVAL '1 second',
       CASE WHEN g % 10 = 0 THEN 'aaaaaaaa-0000-4000-8000-000000000001'::uuid END
FROM generate_series(1, 230) g, (SELECT id FROM targets WHERE url LIKE 'https://web%' ORDER BY url LIMIT 1) t;
-- Credential profiles, shared with two other targets each.
INSERT INTO credential_profiles(id, target_kind, target_id, name, auth_kind, principal_slot, configuration_json,
    rotated_at, created_at, updated_at, is_active, principal_label)
SELECT gen_random_uuid(), 'web', t.id, 'Profile '||chr(65 + g % 26)||g, 'bearer_token', 'primary',
       '{"auth_kind": "bearer_token", "secret_values_visible": false, "header_name": "Authorization"}'::jsonb,
       now(), now(), now(), g % 5 <> 0, CASE WHEN g % 4 = 0 THEN 'svc-'||g END
FROM generate_series(1, 64) g
JOIN (SELECT id, row_number() OVER (ORDER BY url) rn FROM targets WHERE url LIKE 'https://web%') t ON t.rn = 1 + g % 6;
INSERT INTO credential_profile_bindings(id, profile_id, binding_kind, binding_id, allowed_capabilities, is_active, created_at, updated_at)
SELECT gen_random_uuid(), p.id, 'target', p.target_id::text, '["http.request"]', true, now(), now() FROM credential_profiles p;
INSERT INTO credential_profile_bindings(id, profile_id, binding_kind, binding_id, allowed_capabilities, is_active,
    created_at, updated_at, revoked_at)
SELECT gen_random_uuid(), p.id, 'target', t.id::text, '["http.request"]', true, now(), now(),
       CASE WHEN abs(hashtext(p.id::text)) % 3 = 0 THEN now() END
FROM credential_profiles p CROSS JOIN LATERAL (
    SELECT id FROM targets WHERE id <> p.target_id AND url LIKE 'https://web%' ORDER BY md5(id::text || p.id::text) LIMIT 2) t;
"""


@pytest.fixture(scope="module", autouse=True)
def _database():
    async def setup():
        conn = await _connect()
        try:
            await conn.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
            await conn.execute((ROOT / "db" / "init.sql").read_text())
            import retest_contract
            from targets.asset_migration import BoundConnectionPool
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            await conn.executemany(
                "INSERT INTO targets(url, name, root_domain, metadata_json) VALUES ($1, $2, $3, '{}')",
                [(f"https://web{n}.example.invalid", f"web {n}", "example.invalid") for n in range(1, 13)],
            )
            await conn.execute(SEED_SQL)
            await conn.execute("ANALYZE")
        finally:
            await conn.close()
    asyncio.run(setup())


# --- Scan assessment columns ------------------------------------------------------------------


async def _insert_scans(conn, *, projected: bool) -> list[uuid.UUID]:
    if not projected:
        await conn.execute("ALTER TABLE scans DISABLE TRIGGER scans_project_assessment")
    try:
        ids = []
        for index, result in enumerate(RESULTS * 3):
            ids.append(await conn.fetchval(
                "INSERT INTO scans(target_url, status, run_kind, execution_context, coverage_json, result, "
                "created_at) VALUES ($1, 'completed', 'web_dast', '{}', '{}', $2::jsonb, $3) RETURNING id",
                f"https://assess{index}.example.invalid", None if result is None else json.dumps(result),
                T0 + timedelta(minutes=index)))
        return ids
    finally:
        if not projected:
            await conn.execute("ALTER TABLE scans ENABLE TRIGGER scans_project_assessment")


async def _old_and_new_assessment(conn, ids):
    from scan.assessment import project_scan_assessment_row
    from scan.assessment_columns import SCAN_LIST_ASSESSMENT_COLUMNS
    old = await conn.fetch(f"SELECT s.id, s.run_kind, {ref.SCAN_LIST_ASSESSMENT_COLUMNS} FROM scans s "
                           "WHERE s.id = ANY($1::uuid[]) ORDER BY s.id", ids)
    new = await conn.fetch(f"SELECT s.id, s.run_kind, {SCAN_LIST_ASSESSMENT_COLUMNS} FROM scans s "
                           "WHERE s.id = ANY($1::uuid[]) ORDER BY s.id", ids)
    return ([project_scan_assessment_row(dict(row)) for row in old],
            [project_scan_assessment_row(dict(row)) for row in new])


def test_assessment_columns_restart_takes_no_lock_and_reads_are_the_same_before_and_after_projection():
    from scan import assessment_columns as ac

    async def body(conn):
        async with conn.transaction():
            await ac.install_scan_assessment_columns(conn)
            locks = await conn.fetch(
                "SELECT mode FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'relation' "
                "AND relation = 'scans'::regclass")
            assert all(row["mode"] == "AccessShareLock" for row in locks), locks
        written = await _insert_scans(conn, projected=True)
        legacy = await _insert_scans(conn, projected=False)
        assert await conn.fetchval("SELECT count(*) FROM scans WHERE id = ANY($1::uuid[]) "
                                   "AND assessment_projected IS NULL", legacy) == len(legacy)
        assert await conn.fetchval("SELECT bool_and(assessment_projected) FROM scans WHERE id = ANY($1::uuid[])",
                                   written)
        old, new = await _old_and_new_assessment(conn, written + legacy)
        assert new == old
        before = {row["id"]: row["updated_at"] for row in await conn.fetch(
            "SELECT id, updated_at FROM scans WHERE id = ANY($1::uuid[])", legacy)}
        projected = await ac.backfill_scan_assessment(conn, batch=7)
        assert projected >= len(legacy)
        after = {row["id"]: row["updated_at"] for row in await conn.fetch(
            "SELECT id, updated_at FROM scans WHERE id = ANY($1::uuid[])", legacy)}
        assert after == before  # the projection is not a change in /scans?since=
        # The backfill's batch query is the partial index's predicate, so it reads the index.
        from runtime.loop_scale_indexes import LOOP_SCALE_INDEXES
        (definition,) = [spec[2] for spec in LOOP_SCALE_INDEXES if spec[0] == "idx_scans_assessment_unprojected"]
        await conn.execute(f"CREATE INDEX IF NOT EXISTS idx_scans_assessment_unprojected ON {definition}")
        async with conn.transaction():
            await conn.execute("SET LOCAL enable_seqscan = off")
            plan = "\n".join(row[0] for row in await conn.fetch("EXPLAIN " + ac.UNPROJECTED_IDS_SQL, None, 7))
        assert "idx_scans_assessment_unprojected" in plan, plan
        assert not await conn.fetchval("SELECT count(*) FROM scans WHERE assessment_projected IS NULL")
        old, new = await _old_and_new_assessment(conn, written + legacy)
        assert new == old
        # Every column equals its projection of the stored report, for every shape.
        for name in ("risk_assessment_state", "application_observed", "grade_reliable", "grade_reliability_reasons"):
            mismatched = await conn.fetchval(
                f"SELECT count(*) FROM scans s WHERE s.{name} IS DISTINCT FROM {ac.projection(name, 's.result')}")
            assert mismatched == 0, name
        # A later write of the report re-projects it.
        await conn.execute("UPDATE scans SET result = $2::jsonb WHERE id = $1", written[0], json.dumps(RESULTS[3]))
        row = await conn.fetchrow("SELECT risk_assessment_state, grade_reliable FROM scans WHERE id = $1", written[0])
        assert (row["risk_assessment_state"], row["grade_reliable"]) == ("not_examined", False)
    _run(body)


# --- /metrics/v2 -----------------------------------------------------------------------------


METRICS_SEED = """
INSERT INTO scans(id, target_url, status, run_kind, scan_generation, scan_action_plan_digest, scan_job_digest,
                  scan_job_payload, execution_context, coverage_json, created_at, policy_json)
VALUES ('bbbbbbbb-0000-4000-8000-000000000001', 'https://m1.example.invalid', 'completed', 'web_dast', 'v2',
        repeat('a', 64), 'd', '{}', '{}', '{}', now(), '{"active_testing": true}'),
       ('bbbbbbbb-0000-4000-8000-000000000002', 'https://m2.example.invalid', 'completed', 'web_dast', 'v2',
        repeat('b', 64), 'd', jsonb_build_object('big', repeat('z', 5000)), '{}', '{}', now(), '{}'),
       ('bbbbbbbb-0000-4000-8000-000000000003', 'https://m3.example.invalid', 'completed', 'web_dast', 'v1',
        NULL, NULL, '{}', '{}', '{}', now(), '{}');
INSERT INTO scan_capability_actions(scan_id, action_id, stage, ordinal, capability_name, adapter_name, adapter_version,
  output_schema, action_digest, execution_plan_digest, target_binding_digest, input_binding_digest, requested_budget,
  placement_json, required, supporting, status, reason_code, result_json, receipt_json, lease_expires_at, updated_at)
SELECT s.id, 'a'||k, 'stage', k, 'http.request', 'seed', '1', 'seed/v1', md5(s.id::text||k)||md5(k::text),
  repeat('e', 64), repeat('f', 64), repeat('a', 64), '{}', '{}', k % 2 = 0, false,
  (ARRAY['success','failed','leased','planned','timed_out','blocked','running'])[1 + k % 7],
  (ARRAY[NULL,'manifest_unavailable','scope_invalid','authorization_revoked'])[1 + k % 4],
  CASE WHEN k % 3 = 0 THEN NULL ELSE '{}'::jsonb END,
  CASE WHEN k % 5 = 0 THEN jsonb_build_object('budget_reservation_id', 'r'||k) ELSE '{}'::jsonb END,
  CASE WHEN k % 7 IN (2, 6) THEN now() - interval '1 minute' END, now()
FROM scans s, generate_series(0, 13) k WHERE s.id::text LIKE 'bbbbbbbb-%';
INSERT INTO budget_reservations(id, owner_kind, owner_id, action_id, action_digest, capability_name, status,
  requested_json, version, state_digest, state_json, created_at, updated_at, finished_at, hold_applied,
  execution_receipt_hash)
SELECT 'res-'||a.id, 'scan', a.scan_id::text, a.action_id, a.action_digest, a.capability_name,
       (ARRAY['released','committed','failed'])[1 + a.ordinal % 3], '{}', 1, repeat('d', 64), '{}',
       now() - interval '1 hour', now() - interval '1 hour', now() - interval '1 hour', false,
       CASE WHEN a.ordinal % 3 = 1 THEN repeat('9', 64) END
FROM scan_capability_actions a WHERE a.scan_id::text LIKE 'bbbbbbbb-%' AND a.ordinal % 2 = 0;
UPDATE scan_capability_actions a SET reservation_id = 'res-'||a.id
WHERE a.scan_id::text LIKE 'bbbbbbbb-%' AND a.ordinal % 4 = 0;
INSERT INTO scan_work_manifests(id, scan_id, kind, schema_version, content_schema, target_binding_digest,
  source_action_ids, status, entry_count, manifest_digest, content_json)
SELECT gen_random_uuid(), s.id, 'endpoint', 'v1', 'c', repeat('c', 64), '[]', 'complete', 4, md5(s.id::text)||md5('m'), '{}'
FROM scans s WHERE s.id::text LIKE 'bbbbbbbb-%';
"""


def test_metrics_sql_equals_the_previous_sql_with_projected_and_unprojected_rows():
    from scan import action_budget_reconciliation as abr
    from scan import operational_metrics as om

    async def body(conn):
        await conn.execute(METRICS_SEED)
        legacy = await _insert_scans(conn, projected=False)  # half the assessment rows unprojected
        assert legacy
        for old_sql, new_sql in ((ref._CORE_SQL, om._CORE_SQL), (ref._RECONCILIATION_SQL, abr._RECONCILIATION_SQL)):
            assert dict(await conn.fetchrow(new_sql)) == dict(await conn.fetchrow(old_sql))
        old_reasons = [tuple(row) for row in await conn.fetch(ref._GRADE_REASONS_SQL)]
        assert old_reasons and [tuple(row) for row in await conn.fetch(om._GRADE_REASONS_SQL)] == old_reasons
        core = dict(await conn.fetchrow(om._CORE_SQL))
        assert core["unexpected_legacy_execution"] >= 1 and core["unreliable_grade_count"] >= 1
        assert core["manifest_failures"] and core["required_action_failures"] and core["stale_action_leases"]
        reconciliation = dict(await conn.fetchrow(abr._RECONCILIATION_SQL))
        assert reconciliation["stale_terminal_reservation_without_action"] and reconciliation["linked_action_count"]
        assert reconciliation["receipt_link_missing"] and reconciliation["linked_authority_mismatch"]
    _run(body)


# --- /devices --------------------------------------------------------------------------------


async def _old_devices(conn, *, include_inactive=False, device_class=None, search=None, limit=100, offset=0):
    conditions = ["($1::boolean = true OR d.is_active = true)"]
    params = [include_inactive]
    if device_class:
        params.append(device_class.strip().lower())
        conditions.append(f"d.device_class=${len(params)}")
    if search:
        params.append(f"%{search.strip()}%")
        conditions.append(f"(d.name ILIKE ${len(params)} OR d.primary_locator ILIKE ${len(params)} "
                          f"OR COALESCE(d.manufacturer,'') ILIKE ${len(params)})")
    sql = (ref.DEVICES_SQL.replace("{where}", " AND ".join(conditions))
           .replace("${len(params)+1}", f"${len(params) + 1}").replace("${len(params)+2}", f"${len(params) + 2}"))
    rows = await conn.fetch(sql, *params, limit, offset)
    total = await conn.fetchval(f"SELECT COUNT(*) FROM device_targets d WHERE {' AND '.join(conditions)}", *params)
    return [dict(row) for row in rows], total


def test_devices_legacy_pages_equal_the_previous_query_and_list_v1_walks_every_device(monkeypatch):
    api = _api_module()
    from devices import router as devices_router

    async def body(conn):
        monkeypatch.setattr(api, "db_pool", _Pool(conn))
        cases = [{}, {"include_inactive": True}, {"device_class": "camera"}, {"search": "device 1"},
                 {"limit": 7, "offset": 14}, {"include_inactive": True, "limit": 5, "offset": 40}]
        for case in cases:
            args = {"include_inactive": False, "device_class": None, "search": None, "limit": 100, "offset": 0, **case}
            old_rows, old_total = await _old_devices(conn, **args)
            new = await devices_router.list_devices(None, cursor=None, count=None, fields=None, since=None, **args)
            assert new["total"] == old_total and old_rows, case
            assert new["devices"] == [devices_router._decode_device_row(row) for row in old_rows], case
        legacy = await devices_router.list_devices(None, include_inactive=True, device_class=None, search=None,
                                                   limit=500, offset=0, cursor=None, count=None, fields=None, since=None)
        walked, cursor, first = [], None, None
        while True:
            page = await devices_router.list_devices(None, include_inactive=True, device_class=None, search=None,
                                                     limit=8, offset=0, cursor=cursor,
                                                     count="exact" if cursor is None else None, fields=None, since=None)
            first = first or page
            walked.extend(page["items"])
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break
        assert (first["total"], first["total_kind"]) == (legacy["total"], "exact")
        assert walked == legacy["devices"]  # ties on updated_at are broken by id, as the order already was
        with pytest.raises(HTTPException) as caught:
            await devices_router.list_devices(None, include_inactive=False, device_class=None, search=None,
                                              limit=8, offset=0, cursor=first["next_cursor"], count=None,
                                              fields=None, since=None)
        assert caught.value.detail["error"] == "cursor_mismatch"
        # A device without a change time sorts last in both the legacy page and the list/v1 walk.
        unchanged = legacy["devices"][0]["id"]
        await conn.execute("ALTER TABLE target_device_profiles ALTER COLUMN updated_at DROP NOT NULL")
        await conn.execute("UPDATE targets SET updated_at = NULL WHERE id = $1", unchanged)
        await conn.execute("UPDATE target_device_profiles SET updated_at = NULL WHERE target_id = $1", unchanged)
        legacy = await devices_router.list_devices(None, include_inactive=True, device_class=None, search=None,
                                                   limit=500, offset=0, cursor=None, count=None, fields=None, since=None)
        walked, cursor = [], None
        while True:
            page = await devices_router.list_devices(None, include_inactive=True, device_class=None, search=None,
                                                     limit=8, offset=0, cursor=cursor,
                                                     count="none" if cursor is None else None, fields=None, since=None)
            walked.extend(page["items"])
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break
        assert legacy["devices"][-1]["id"] == unchanged and walked == legacy["devices"]
        await conn.execute("UPDATE targets SET updated_at = now() WHERE id = $1", unchanged)
        await conn.execute("UPDATE target_device_profiles SET updated_at = now() WHERE target_id = $1", unchanged)
    _run(body)


# --- /investigation/candidates ---------------------------------------------------------------


def test_candidates_legacy_pages_equal_the_previous_query_and_list_v1_reaches_every_row(monkeypatch):
    api = _api_module()
    from investigation_routes import router as inv

    async def body(conn):
        monkeypatch.setattr(api, "db_pool", _Pool(conn))
        target = await conn.fetchval("SELECT target_id FROM investigation_candidates LIMIT 1")
        for case in ({}, {"status": "verified"}, {"target_id": str(target)}, {"plane": "web", "offset": 50},
                     {"limit": 9, "offset": 100}):
            args = {"plane": None, "target_id": None, "device_target_id": None, "status": None, "limit": 100,
                    "offset": 0, **case}
            old = await conn.fetch(ref.CANDIDATES_SQL, args["plane"], uuid.UUID(args["target_id"]) if args["target_id"] else None,
                                   None, args["status"], args["limit"], args["offset"])
            expected = []
            for row in old:
                item = inv._public_investigation_candidate(row)
                item.pop("total_count", None)
                expected.append(item)
            new = await inv.list_investigation_candidates(None, cursor=None, count=None, fields=None, since=None, **args)
            assert new["candidates"] == expected and expected, case
            assert new["total"] == (int(old[0]["total_count"]) if old else 0)
        walked, cursor = [], None
        while True:
            page = await inv.list_investigation_candidates(
                None, plane=None, target_id=None, device_target_id=None, status=None, limit=40, offset=0,
                cursor=cursor, count="exact", fields=None, since=None)
            walked.extend(page["items"])
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break
        everything = await inv.list_investigation_candidates(
            None, plane=None, target_id=None, device_target_id=None, status=None, limit=500, offset=0,
            cursor=None, count=None, fields=None, since=None)
        assert [item["id"] for item in walked] == [item["id"] for item in everything["candidates"]]
        assert "evidence_refs" not in walked[0] and walked[0]["evidence_ref_count"] == 2
        by_id = {item["id"]: item for item in everything["candidates"]}
        assert all(item["observation_count"] == by_id[item["id"]]["observation_count"] for item in walked)
    _run(body)


# --- /evidence/instances ---------------------------------------------------------------------


def test_evidence_legacy_list_equals_the_previous_query_and_list_v1_reaches_older_rows(monkeypatch):
    api = _api_module()
    from evidence_routes import router as ev

    async def body(conn):
        monkeypatch.setattr(api, "db_pool", _Pool(conn))
        finding = uuid.UUID("aaaaaaaa-0000-4000-8000-000000000001")
        for summary_only in (False, True):
            for limit, finding_id in ((50, None), (200, None), (10, finding)):
                old = await conn.fetch(ref.EVIDENCE_SQL, limit, finding_id, None)
                render = ev._public_evidence_instance_summary if summary_only else ev._public_evidence_instance_row
                new = await ev.list_evidence_instances(
                    None, finding_id=str(finding_id) if finding_id else None, tool_receipt_id=None,
                    limit=limit, summary_only=summary_only, cursor=None, count=None)
                assert new["evidence_instances"] == [render(row) for row in old]
                assert new["count"] == len(old) > 0
        total = await conn.fetchval("SELECT count(*) FROM evidence_instances")
        assert total > 200  # beyond the legacy list's reach
        walked, cursor = [], None
        while True:
            page = await ev.list_evidence_instances(None, finding_id=None, tool_receipt_id=None, limit=64,
                                                    summary_only=False, cursor=cursor, count="exact")
            assert page["total"] == total
            walked.extend(page["items"])
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break
        old_all = await conn.fetch("SELECT * FROM evidence_instances ORDER BY created_at DESC, id DESC")
        assert walked == [ev._public_evidence_instance_summary(row) for row in old_all]
        assert "secret-value" not in json.dumps(walked, default=str)
    _run(body)


# --- /credential-profiles --------------------------------------------------------------------


def test_credential_library_equals_the_previous_query_and_list_v1_walks_both_lists():
    import credential_api as ca
    from runtime.credential_store import CredentialProfileMetadata

    async def body(conn):
        request = _request(conn)
        for include_inactive, search, limit, offset in ((False, None, 100, 0), (True, None, 10, 20),
                                                        (True, "svc", 100, 0), (False, "profile a", 5, 1)):
            pattern = f"%{search.strip()}%" if search else None
            old = await conn.fetch(ref.LIBRARY_SQL, include_inactive, pattern, limit, offset)
            new = await ca.list_credential_profiles(request, None, target_kind=None, target_id=None,
                                                    include_inactive=include_inactive, search=search, limit=limit,
                                                    offset=offset, cursor=None, count=None)
            assert [item["id"] for item in new["profiles"]] == [str(row["id"]) for row in old]
            assert [item["shared_target_count"] for item in new["profiles"]] == [row["shared_target_count"] for row in old]
            assert new["total"] == (int(old[0]["total_count"]) if old else 0)
            assert [item["record_version"] for item in new["profiles"]] == [
                CredentialProfileMetadata.from_row(row).record_version for row in old]
        legacy = await ca.list_credential_profiles(request, None, target_kind=None, target_id=None,
                                                   include_inactive=True, search=None, limit=500, offset=0,
                                                   cursor=None, count=None)
        walked, cursor = [], None
        while True:
            page = await ca.list_credential_profiles(request, None, target_kind=None, target_id=None,
                                                     include_inactive=True, search=None, limit=9, offset=0,
                                                     cursor=cursor, count="exact")
            assert page["total"] == legacy["total"]
            walked.extend(page["items"])
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break
        assert walked == legacy["profiles"]
        target = uuid.UUID(await conn.fetchval(
            "SELECT binding_id FROM credential_profile_bindings b JOIN credential_profiles p ON p.id = b.profile_id "
            "WHERE b.binding_id <> p.target_id::text GROUP BY binding_id ORDER BY count(*) DESC LIMIT 1"))
        legacy_target = await ca.list_credential_profiles(request, None, target_kind="web", target_id=target,
                                                          include_inactive=True, search=None, limit=None, offset=0,
                                                          cursor=None, count=None)
        assert legacy_target["count"] > 4
        walked, cursor = [], None
        while True:
            page = await ca.list_credential_profiles(request, None, target_kind="web", target_id=target,
                                                     include_inactive=True, search=None, limit=3, offset=0,
                                                     cursor=cursor, count="exact")
            walked.extend(page["items"])
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break
        assert walked == legacy_target["profiles"]
    _run(body)


# --- /exposure/services ----------------------------------------------------------------------


def test_exposure_services_pages_are_the_previous_targets_and_list_v1_walks_them():
    from exposure import service_store as ss
    from exposure.service_actions import canonical_registry
    from exposure.service_intel import load_service_intelligence

    async def body(conn):
        snapshot, matcher = load_service_intelligence()
        registry = canonical_registry()
        args = dict(target_kind="all", target_id=None, root_domain=None, search="")

        async def v1_walk(sort=None, count="none", **filters):
            walked, bodies, cursor = [], [], None
            while True:
                body_ = await ss.service_page_v1(conn, lc.Page(limit=25, cursor=cursor, sort=sort, count=count),
                                                 snapshot=snapshot, matcher=matcher, registry=registry, **filters)
                walked.extend(body_["items"])
                bodies.append(body_)
                cursor = body_["next_cursor"]
                if not body_["has_more"]:
                    return walked, bodies

        legacy = []
        for offset in range(0, 10_000, 25):
            old = await conn.fetch(ref.TARGETS_SQL + " ORDER BY kind,id LIMIT $5 OFFSET $6", "all", None, None, "",
                                   25, offset)
            page = await ss.service_page(conn, limit=25, offset=offset, snapshot=snapshot, matcher=matcher,
                                         registry=registry, **args)
            assert [item["id"] for item in page["targets"]] == [str(row["id"]) for row in old]
            for item, row in zip(page["targets"], old):
                assert (item["kind"], item["locator"] if row["kind"] == "device" else None) == (
                    row["kind"], row["locator"] if row["kind"] == "device" else None)
            legacy.extend(page["targets"])
            if not page["has_more"]:
                break
        assert len(legacy) == page["total_targets"]
        # list/v1 walks reach every target in the legacy order, each with the same inventory.
        walked, bodies = await v1_walk(count="exact", **args)
        for body_ in bodies:
            assert body_["total"] == len(legacy) and body_["schema_version"] == page["schema_version"]
        assert walked == legacy
        # Descending: the same targets, each page in the reverse order (the outer query keeps it).
        walked, _ = await v1_walk(sort="-kind", **args)
        assert walked == legacy[::-1]
        # A connected device and its host:// target share an id. A read narrowed to one device, or
        # to a locator, puts both on one page; each keeps its own inventory, in either direction.
        device_id = await conn.fetchval("SELECT id FROM device_targets WHERE is_active AND primary_locator='10.66.0.4'")
        for narrowed in (dict(args, target_id=device_id), dict(args, search="10.66.0.4")):
            reference = await ss.service_page(conn, limit=25, offset=0, snapshot=snapshot, matcher=matcher,
                                              registry=registry, **narrowed)
            assert not reference["has_more"] and {"device", "web"} <= {t["kind"] for t in reference["targets"]}
            walked, _ = await v1_walk(**narrowed)
            assert walked == reference["targets"]
            walked, _ = await v1_walk(sort="-kind", **narrowed)
            assert walked == reference["targets"][::-1]
        pair, _ = await v1_walk(**dict(args, target_id=device_id))
        assert [(item["id"], item["kind"]) for item in pair] == [(str(device_id), "device"), (str(device_id), "web")]
        assert pair[0]["locator"] == "10.66.0.4" and pair[0]["source_count"] == 3
        assert {(s["transport"], s["port"]) for s in pair[0]["services"]} >= {("tcp", 22), ("tcp", 80)}
        assert pair[1]["services"] == []
        # The device locator-change time is still computed for the page's devices.
        device = await conn.fetchrow(ss.page_targets_sql(ss.FILTERED_TARGETS_SQL + " AND kind='device' LIMIT 1"),
                                     "all", None, None, "")
        assert device["locator_changed_at"] is not None
    _run(body)


# --- /ai/inventory ---------------------------------------------------------------------------


def test_ai_inventory_equals_the_inventory_of_the_previous_scan_query(monkeypatch):
    api = _api_module()
    from ai_assurance import build_ai_inventory
    from ai_targets import router as ai_router
    from serialization import row_to_dict

    async def body(conn):
        monkeypatch.setattr(api, "db_pool", _Pool(conn))
        await conn.execute("""
            INSERT INTO ai_targets(name, target_type, endpoint_url, metadata_json, is_active)
            VALUES ('ai one', 'api_chat', 'https://ai1.example.invalid/v1/chat', '{}', true);
            INSERT INTO scans(target_id, target_url, status, run_kind, execution_context, coverage_json, created_at,
                              options, result)
            SELECT t.id, t.url, 'completed', (ARRAY['web_dast','ai_api','web_dast'])[1 + g % 3], '{}', '{}',
                   now() - g * interval '1 minute',
                   CASE WHEN g % 4 = 0 THEN '{"safe_fixture": true, "x": 1}'::jsonb ELSE '{"profile": "standard"}'::jsonb END,
                   jsonb_build_object('discovery', jsonb_build_object('browser_api_endpoints', jsonb_build_array(
                       jsonb_build_object('url', 'https://web1.example.invalid/api/chat/' || g, 'method', 'POST'))),
                       'note', 'see https://web1.example.invalid/v1/completions and https://web2.example.invalid/llm')
            FROM generate_series(1, 30) g, (SELECT id, url FROM targets WHERE url LIKE 'https://web%' ORDER BY url LIMIT 1) t;
        """)
        new = await ai_router.get_ai_inventory(root_domain=None, include_inactive=False, include_resolved=False,
                                               limit_scans=150)
        inputs = {}
        captured = {}
        original = ai_router.build_ai_inventory

        def capture(**kwargs):
            captured.update(kwargs)
            return original(**kwargs)
        monkeypatch.setattr(ai_router, "build_ai_inventory", capture)
        await ai_router.get_ai_inventory(root_domain=None, include_inactive=False, include_resolved=False,
                                         limit_scans=150)
        inputs = dict(captured)
        inputs["scans"] = [row_to_dict(row) for row in await conn.fetch(ref.AI_SCANS_SQL, None, 150)]
        old = build_ai_inventory(**inputs)
        for body_ in (new, old):
            body_.pop("generated_at", None)
            body_.get("summary", {}).pop("inputs_truncated", None)
        assert new == old and (old["candidates"] or old.get("leads"))
    _run(body)


# --- /scans/{id} -----------------------------------------------------------------------------


def test_scan_detail_children_give_the_same_contributions_and_findings_are_bounded(monkeypatch):
    api = _api_module()
    from scan.detail_bounds import PARALLEL_CHILDREN_SQL

    async def body(conn):
        monkeypatch.setattr(api, "db_pool", _Pool(conn))
        parent = uuid.uuid4()
        await conn.execute(
            "INSERT INTO scans(id, target_url, status, run_kind, scan_role, execution_context, coverage_json, result) "
            "VALUES ($1, 'https://web1.example.invalid', 'running', 'web_dast', 'parent', '{}', '{}', '{}')", parent)
        children = [
            ({"active_checks": {"endpoint_attempts": [{"status": "ok", "url": "u"}, {"status": "Failed"}, "x", {}],
                                "check_family_scope": {"requested_family": "xss"}, "active_worklist_total": 4,
                                "per_endpoint_telemetry": False, "other": "dropped"}, "body": "b" * 3000},
             {"custom_endpoints": ["a", "b", "c"], "budget_profile": "balanced", "auth_header": "Bearer t",
              "custom_budget": {"active_max_seconds": 60, "active_max_endpoints": 5}}),
            ({"active_checks": "not-an-object"}, {"auth_state": "user2", "check_family": "sqli"}),
            (None, None),
            ({"active_checks": {"endpoint_attempts_total": 9, "active_endpoints_selected": 2}}, ["list-options"]),
        ]
        for index, (result, options) in enumerate(children):
            await conn.execute(
                "INSERT INTO scans(target_url, status, run_kind, scan_role, parent_scan_id, shard_index, progress, "
                "duration_seconds, execution_context, coverage_json, result, options) "
                "VALUES ('https://web1.example.invalid', 'completed', 'web_dast', 'shard', $1, $2, 50, 30, '{}', '{}', "
                "$3::jsonb, $4::jsonb)",
                parent, index, None if result is None else json.dumps(result), None if options is None else json.dumps(options))
        old = [api._public_parallel_shard(dict(row)) for row in await conn.fetch(ref.SHARD_ROWS_SQL, parent)]
        new = [api._public_parallel_shard(dict(row)) for row in await conn.fetch(PARALLEL_CHILDREN_SQL, parent)]
        assert new == old and any(item["contribution"] for item in old)
        await conn.execute("""
            INSERT INTO findings(scan_id, fingerprint, title, severity, tool, url, evidence, status, source,
                                 last_seen_at)
            SELECT $1, 'detail-'||g, 'F '||g, (ARRAY['low','critical','info'])[1+g%3],
                   'nuclei', 'https://web1.example.invalid/f/'||g, '{}', 'active', 'scan', now() - g * interval '1 second'
            FROM generate_series(1, 25) g""", parent)
        full = await api.get_scan(str(parent), verified_only=False, findings_limit=5000, include_result=True)
        assert (full["findings_total"], full["findings_truncated"], len(full["findings"])) == (25, False, 25)
        bounded = await api.get_scan(str(parent), verified_only=False, findings_limit=10, include_result=False)
        assert (bounded["findings_total"], bounded["findings_truncated"], bounded["result"]) == (25, True, None)
        assert [item["id"] for item in bounded["findings"]] == [item["id"] for item in full["findings"][:10]]
        assert bounded["shard_rollup"] == full["shard_rollup"] and bounded["shards"] == full["shards"]
        none = await api.get_scan(str(parent), verified_only=False, findings_limit=0, include_result=True)
        assert (none["findings"], none["findings_total"], none["findings_truncated"]) == ([], 25, True)
    _run(body)


def test_scan_detail_reads_only_what_it_answers(monkeypatch):
    """Default 500 rows; include_result=false selects the explanation's report parts only;
    verified_only filters in SQL before the limit and still admits rows this run proved."""
    api = _api_module()
    from scan import detail_bounds

    async def body(conn):
        monkeypatch.setattr(api, "db_pool", _Pool(conn))
        scan = uuid.uuid4()
        proven = {"title": "Proved now", "severity": "high", "tool": "nuclei",
                  "url": "https://web1.example.invalid/p", "template_id": "proved-now",
                  "proof_of_exploitation": True, "verified": True, "confidence": 0.9}
        report = {"findings": [proven], "coverage": {"reasons": ["r"]}, "body": "b" * 5000,
                  "parallel": {"canonical_action_execution": {"actions": []}, "shards": ["x"] * 10}}
        await conn.execute(
            "INSERT INTO scans(id, target_url, status, run_kind, execution_context, coverage_json, result) "
            "VALUES ($1, 'https://web1.example.invalid', 'completed', 'web_dast', '{}', '{}', $2::jsonb)",
            scan, json.dumps(report))
        await conn.execute("""
            INSERT INTO findings(scan_id, fingerprint, title, severity, tool, url, evidence, status, source,
                                 last_seen_at, last_verification_verdict)
            SELECT $1, 'many-'||g, 'F '||g, 'critical', 'nuclei', 'https://web1.example.invalid/f/'||g, '{}',
                   'active', 'scan', now() - g * interval '1 second',
                   CASE WHEN g IN (590, 595) THEN 'exploited' END
            FROM generate_series(1, 600) g""", scan)
        fingerprint = api.generate_finding_fingerprint(proven)
        await conn.execute(
            "INSERT INTO findings(scan_id, fingerprint, title, severity, tool, url, evidence, status,"
            " source, last_seen_at, last_verification_verdict) VALUES ($1, $2, 'Proved now', 'low', 'nuclei',"
            " 'https://web1.example.invalid/p', '{}', 'active', 'scan', now() - interval '1 day',"
            " 'false_positive')", scan, fingerprint)
        default = await api.get_scan(str(scan))
        assert (len(default["findings"]), default["findings_total"], default["findings_truncated"]) == (500, 601, True)
        assert default["result"]["body"] == report["body"]

        row = await detail_bounds.fetch_scan_detail_row(conn, scan, include_result=False, with_findings=False)
        assert json.loads(row["result"]) == {"coverage": report["coverage"],
                                             "parallel": {"canonical_action_execution": {"actions": []}}}
        assert set(dict(row)) == set(dict(await detail_bounds.fetch_scan_detail_row(
            conn, scan, include_result=True, with_findings=True)))
        lean = await api.get_scan(str(scan), findings_limit=0, include_result=False)
        assert lean["result"] is None and lean["execution_explanation"] == default["execution_explanation"]

        verified = await api.get_scan(str(scan), verified_only=True, findings_limit=2, include_result=False)
        assert sorted(item["title"] for item in verified["findings"]) == ["F 590", "F 595"]
        assert (verified["findings_total"], verified["findings_truncated"]) == (3, True)
        everything = await api.get_scan(str(scan), verified_only=True, findings_limit=10, include_result=False)
        assert sorted(item["title"] for item in everything["findings"]) == ["F 590", "F 595", "Proved now"]
        assert everything["findings_truncated"] is False
    _run(body)


# --- research autopilot claims ---------------------------------------------------------------


def test_autopilot_claims_past_blocked_episodes_in_bounded_batches():
    from research_routes import autopilot_loop as loop

    async def body(conn):
        target = await conn.fetchval("SELECT id FROM targets WHERE url LIKE 'https://web%' LIMIT 1")
        blocked_scan = await conn.fetchval(
            "INSERT INTO scans(target_url, status, run_kind, execution_context, coverage_json) "
            "VALUES ('https://web1.example.invalid', 'running', 'web_dast', '{}', '{}') RETURNING id")
        command = await conn.fetchval(
            "INSERT INTO command_results(command, status, risk_tier, scan_id, operator_message) "
            "VALUES ('asm.improve', 'running', 'passive', $1, 'm') RETURNING id", blocked_scan)
        episodes = []
        for index in range(13):
            episodes.append(await conn.fetchval(
                "INSERT INTO research_episodes(target_id, objective, episode_version, status, autopilot_enabled, "
                "updated_at) VALUES ($1, 'o', 'v1', 'awaiting_planner', true, $2) RETURNING id",
                target, T0 + timedelta(minutes=index)))
        for episode in episodes[:10]:  # the ten oldest wait on a running Scan
            observation = await conn.fetchval(
                "INSERT INTO research_observations(episode_id, sequence, observation_version, context_hash, "
                "episode_version, observation_pack) VALUES ($1, 1, 'v1', 'h', 1, '{}') RETURNING id", episode)
            await conn.execute(
                "INSERT INTO research_decisions(episode_id, observation_id, sequence, decision_version, decision_type, "
                "status, command_result_id, idempotency_key) VALUES ($1, $2, 1, 'v1', 'execute_action', 'dispatching', "
                "$3, $4)", episode, observation, command, f"k-{episode}")
        hub = SimpleNamespace(RESEARCH_AUTOPILOT_LEASE_SECONDS=30)
        cursor = loop.ClaimCursor()
        claimed = []
        for _ in range(4):
            row = await loop.claim_episode(conn, hub, "owner-test", cursor, batch=4)
            if row:
                claimed.append(row["id"])
        # Batches of four: [0-3] and [4-7] are blocked, [8-11] yields 10; the next poll yields 11.
        assert claimed == [episodes[10], episodes[11]]
        row = await conn.fetchrow("SELECT lease_owner, lease_expires_at FROM research_episodes WHERE id = $1", claimed[0])
        assert row["lease_owner"] == "owner-test" and row["lease_expires_at"] is not None
        # The cursor wraps after a short batch, so nothing eligible is starved.
        for _ in range(4):
            await loop.claim_episode(conn, hub, "owner-test", cursor, batch=4)
        assert await conn.fetchval("SELECT lease_owner FROM research_episodes WHERE id = $1", episodes[12]) == "owner-test"
        await conn.execute("DELETE FROM research_episodes WHERE id = ANY($1::uuid[])", episodes)
    _run(body)


def test_processes_claiming_at_once_never_lease_the_same_episode():
    """Every API process claims (2.11): concurrent claims split the episodes, none twice."""
    from research_routes import autopilot_loop as loop

    async def body(conn):
        target = await conn.fetchval("SELECT id FROM targets WHERE url LIKE 'https://web%' LIMIT 1")
        episodes = [await conn.fetchval(
            "INSERT INTO research_episodes(target_id, objective, episode_version, status, autopilot_enabled, "
            "updated_at) VALUES ($1, 'o', 'v1', 'awaiting_planner', true, $2) RETURNING id",
            target, T0 + timedelta(minutes=index)) for index in range(6)]
        hub = SimpleNamespace(RESEARCH_AUTOPILOT_LEASE_SECONDS=30)
        others = [await _connect() for _ in range(3)]
        try:
            async def process(index, other):
                cursor, claimed = loop.ClaimCursor(), []
                for _ in range(4):
                    row = await loop.claim_episode(other, hub, f"process-{index}", cursor)
                    if row:
                        claimed.append(row["id"])
                return claimed

            results = await asyncio.gather(*(process(i, other) for i, other in enumerate(others)))
        finally:
            for other in others:
                await other.close()
        claimed = [episode for result in results for episode in result]
        assert sorted(claimed) == sorted(episodes)  # each once, by whichever process got it
        owners = await conn.fetch("SELECT id, lease_owner FROM research_episodes WHERE id = ANY($1::uuid[])", episodes)
        by_owner = {row["id"]: row["lease_owner"] for row in owners}
        for index, result in enumerate(results):
            assert all(by_owner[episode] == f"process-{index}" for episode in result)
        await conn.execute("DELETE FROM research_episodes WHERE id = ANY($1::uuid[])", episodes)
    _run(body)
