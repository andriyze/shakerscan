"""Scan and Hunt identity uses absolute service provenance, with safe legacy adoption."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import os
import uuid

import pytest

from api.hunt.deterministic_findings import (
    _verified_xss_fingerprint,
    _xss_finding_records,
    materialize_verified_hunt_findings,
)
from api.hunt.finding_verifications import FINDING_HUNT_VERIFICATIONS_SCHEMA_SQL
from api.scan.finding_identity import canonical_finding_fingerprint, finding_identity_keys
from api.scan.finding_reconciliation import reconcile_legacy_finding_row
from scanner.finding_service_identity import service_origin
from scanner.findings import pre_service_templated_finding_identity, templated_finding_identity
from tests.disposable_postgres import require_disposable_database


def _finding(url, *, param="q"):
    return {"url": url, "cwe": "CWE-79", "tool": "dalfox", "title": "Verified cross-site scripting",
            "evidence": {"method": "GET", "param": param}}


@pytest.mark.parametrize("url,origin", [
    ("https://EXAMPLE.test./path", "https://example.test:443"),
    ("https://example.test:443/path", "https://example.test:443"),
    ("http://example.test/path", "http://example.test:80"),
    ("http://example.test:8080/path", "http://example.test:8080"),
    ("wss://EXAMPLE.test/socket", "wss://example.test:443"),
    ("ws://example.test:8080/socket", "ws://example.test:8080"),
    ("https://[2001:db8::1]:8443/path", "https://[2001:db8::1]:8443"),
])
def test_identity_always_names_the_normalized_absolute_service(url, origin):
    finding = _finding(url)
    assert service_origin(url) == origin
    assert templated_finding_identity(finding).endswith("|service=" + origin)
    previous = pre_service_templated_finding_identity(finding)
    assert "|service=" not in previous
    assert "t:" + hashlib.sha256(previous.encode()).hexdigest()[:16] in finding_identity_keys(finding)


def test_default_ports_collapse_but_other_ports_schemes_and_params_stay_distinct():
    implicit = canonical_finding_fingerprint(_finding("https://example.test/orders/1?q=payload"))
    explicit = canonical_finding_fingerprint(_finding("https://EXAMPLE.test.:443/orders/9?q=other"))
    assert implicit == explicit
    variants = [
        _finding("https://example.test:8443/orders/1?q=payload"),
        _finding("http://example.test/orders/1?q=payload"),
        _finding("https://other.test/orders/1?q=payload"),
        _finding("https://example.test/orders/1?name=payload", param="name"),
    ]
    assert len({implicit, *(canonical_finding_fingerprint(f) for f in variants)}) == 5


@pytest.mark.parametrize("baseline", [
    "https://example.test", "https://example.test:443", "https://example.test:8443",
    "http://example.test:8080",
])
@pytest.mark.parametrize("service", ["https://example.test", "https://example.test:8443"])
def test_reflected_xss_scan_and_hunt_agree_independently_of_hunt_baseline(baseline, service):
    proof = {"url": service + "/search?q=", "path": "/search", "param": "q"}
    assert _verified_xss_fingerprint(proof, method="GET", target_url=baseline) == \
        canonical_finding_fingerprint(_finding(proof["url"]))


def test_dom_xss_scan_and_hunt_share_route_identity_without_collapsing_other_client_routes():
    fingerprints = []
    for service, route in [
        ("https://example.test", "/search?q="),
        ("https://example.test:443", "/search?q=another-value"),
        ("https://example.test", "/profile?q="),
        ("https://example.test:8443", "/search?q="),
    ]:
        records = _xss_finding_records(
            uuid.uuid4(), uuid.uuid4(), "https://example.test:8080", "xss.verify", uuid.uuid4(),
            {}, [{"kind": "xss_alert", "proof_state": "verified", "param": "q",
                  "url": service + "/", "client_route": route, "payload_sha256": "a" * 64}],
            allowed_origins=(service,),
        )
        assert len(records) == 1
        record = records[0]
        assert record["fingerprint"] == canonical_finding_fingerprint(record)
        fingerprints.append(record["fingerprint"])
    assert fingerprints[0] == fingerprints[1]
    assert len(set(fingerprints)) == 3


DDL = """
CREATE TABLE targets(id uuid PRIMARY KEY, active_findings_count int DEFAULT 0, updated_at timestamptz);
CREATE TABLE device_targets(LIKE targets INCLUDING ALL);
CREATE TABLE hunt_runs(id uuid PRIMARY KEY);
CREATE TABLE hunt_actions(id uuid PRIMARY KEY, hunt_run_id uuid REFERENCES hunt_runs(id));
CREATE TABLE findings(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), target_id uuid REFERENCES targets(id),
 device_target_id uuid REFERENCES device_targets(id), hunt_run_id uuid REFERENCES hunt_runs(id),
 fingerprint text, title text, description text, severity text, cvss_score double precision,
 tool text, cwe text, url text, evidence jsonb, source text, status text,
 last_verification_status text, last_verification_verdict text, last_verification_confidence double precision,
 last_verified_at timestamptz, verification_count int DEFAULT 0, resolved_at timestamptz,
 resurfaced_count int DEFAULT 0, first_seen_at timestamptz DEFAULT now(),
 last_seen_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now());
CREATE UNIQUE INDEX web_finding_key ON findings(target_id,fingerprint) WHERE target_id IS NOT NULL;
CREATE UNIQUE INDEX device_finding_key ON findings(device_target_id,fingerprint) WHERE device_target_id IS NOT NULL;
CREATE TABLE finding_exceptions(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), finding_id text, fingerprint text, target_id uuid,
 updated_at timestamptz, edit_history jsonb DEFAULT '[]', status text, approver text, expires_at timestamptz);
CREATE TABLE finding_verifications(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), finding_id uuid REFERENCES findings(id),
 target_id uuid, device_target_id uuid, requested_by text, status text, result_status text,
 verdict text, verdict_reason text, finding_type text, target_url text, original_url text,
 proof jsonb, confidence double precision, verification_mode text, contract_id text,
 contract_version text, proof_basis text, started_at timestamptz, completed_at timestamptz, updated_at timestamptz);
"""


def _validated_postgres_dsn():
    dedicated = os.environ.get("FINDING_SERVICE_TEST_POSTGRES_DSN")
    dsn = dedicated or os.environ.get("HUNT_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("FINDING_SERVICE_TEST_POSTGRES_DSN or HUNT_TEST_POSTGRES_DSN is not configured")
    return require_disposable_database(
        dsn, "shakerscan_finding_service_test" if dedicated else "hunt_records",
    )


@pytest.mark.parametrize("dedicated,fallback,expected", [
    ("postgresql://localhost/shakerscan_finding_service_test",
     "postgresql://localhost/hunt_records", "postgresql://localhost/shakerscan_finding_service_test"),
    (None, "postgresql://127.0.0.1/hunt_records", "postgresql://127.0.0.1/hunt_records"),
])
def test_postgres_dsn_selection_prefers_dedicated_and_supports_ci_fallback(
    monkeypatch, dedicated, fallback, expected,
):
    monkeypatch.delenv("FINDING_SERVICE_TEST_POSTGRES_DSN", raising=False)
    if dedicated:
        monkeypatch.setenv("FINDING_SERVICE_TEST_POSTGRES_DSN", dedicated)
    monkeypatch.setenv("HUNT_TEST_POSTGRES_DSN", fallback)
    assert _validated_postgres_dsn() == expected


@pytest.mark.parametrize("dedicated,fallback", [
    ("postgresql://localhost/production", "postgresql://localhost/hunt_records"),
    (None, "postgresql://remote.example.test/hunt_records"),
])
def test_postgres_dsn_selection_rejects_unsafe_configuration(monkeypatch, dedicated, fallback):
    monkeypatch.delenv("FINDING_SERVICE_TEST_POSTGRES_DSN", raising=False)
    if dedicated:
        monkeypatch.setenv("FINDING_SERVICE_TEST_POSTGRES_DSN", dedicated)
    monkeypatch.setenv("HUNT_TEST_POSTGRES_DSN", fallback)
    with pytest.raises(ValueError, match="nonlocal, ambiguous, or non-test"):
        _validated_postgres_dsn()


def test_postgres_dsn_selection_skips_when_neither_test_database_is_configured(monkeypatch):
    monkeypatch.delenv("FINDING_SERVICE_TEST_POSTGRES_DSN", raising=False)
    monkeypatch.delenv("HUNT_TEST_POSTGRES_DSN", raising=False)
    with pytest.raises(pytest.skip.Exception):
        _validated_postgres_dsn()


@asynccontextmanager
async def _database():
    dsn = _validated_postgres_dsn()
    asyncpg = pytest.importorskip("asyncpg")
    conn = await asyncpg.connect(dsn)
    schema = "finding_service_" + uuid.uuid4().hex
    try:
        await conn.execute(f'CREATE SCHEMA "{schema}"')
        await conn.execute(f'SET search_path TO "{schema}"')
        await conn.execute(DDL)
        await conn.execute(FINDING_HUNT_VERIFICATIONS_SCHEMA_SQL)
        yield conn
    finally:
        await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await conn.close()


@pytest.mark.parametrize("kind", ["web", "device"])
def test_postgres_legacy_migration_keeps_id_history_and_separates_services(kind):
    async def run():
        async with _database() as conn:
            target, hunt, action, receipt = (uuid.uuid4() for _ in range(4))
            table = "device_targets" if kind == "device" else "targets"
            column = "device_target_id" if kind == "device" else "target_id"
            await conn.execute(f"INSERT INTO {table}(id) VALUES($1)", target)
            await conn.execute("INSERT INTO hunt_runs(id) VALUES($1)", hunt)
            await conn.execute("INSERT INTO hunt_actions(id,hunt_run_id) VALUES($1,$2)", action, hunt)
            baseline = "https://example.test"
            service = "https://example.test:8443"

            def observations(origin):
                return [{"kind": "xss_alert", "proof_state": "verified", "param": "q",
                         "url": origin + "/search?q=payload", "payload_sha256": "a" * 64}]

            record = _xss_finding_records(
                hunt, action, baseline, "xss.verify", receipt, {}, observations(service),
                allowed_origins=(service,),
            )[0]
            previous = pre_service_templated_finding_identity(record)
            old_key = "t:" + hashlib.sha256(previous.encode()).hexdigest()[:16]
            row_id = await conn.fetchval(
                f"""INSERT INTO findings({column},fingerprint,title,url,tool,cwe,evidence,status,
                      verification_count,resurfaced_count,first_seen_at)
                    VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,'accepted_risk',3,2,now()-interval '30 days')
                    RETURNING id""",
                target, old_key, record["title"], record["url"], record["tool"], record["cwe"],
                json.dumps(record["evidence"]),
            )
            await conn.execute("INSERT INTO finding_verifications(finding_id,verdict) VALUES($1,'exploited')", row_id)
            first_seen = await conn.fetchval("SELECT first_seen_at FROM findings WHERE id=$1", row_id)
            async with conn.transaction():
                migrated = await reconcile_legacy_finding_row(
                    conn, target_uuid=target, fingerprint=canonical_finding_fingerprint(record),
                    finding=record, target_kind=kind,
                )
            assert migrated["id"] == row_id and migrated["status"] == "accepted_risk"
            assert migrated["resurfaced_count"] == 2
            assert await conn.fetchval("SELECT verification_count FROM findings WHERE id=$1", row_id) == 3
            assert await conn.fetchval("SELECT count(*) FROM finding_verifications WHERE finding_id=$1", row_id) == 1
            # Put it back under the historical key to exercise Hunt's real lazy
            # reconciliation and upsert, rather than only the Scan-style helper.
            await conn.execute("UPDATE findings SET fingerprint=$1 WHERE id=$2", old_key, row_id)
            async with conn.transaction():
                ids = await materialize_verified_hunt_findings(
                    conn, hunt, action, target, baseline, "xss.verify", receipt, {}, observations(service),
                    target_kind=kind, allowed_origins=(service,),
                )
            assert ids == [str(row_id)]
            assert await conn.fetchval("SELECT first_seen_at FROM findings WHERE id=$1", row_id) == first_seen
            assert await conn.fetchval("SELECT count(*) FROM finding_verifications WHERE finding_id=$1", row_id) == 2
            await conn.execute("UPDATE findings SET status='false_positive' WHERE id=$1", row_id)
            async with conn.transaction():
                second = await materialize_verified_hunt_findings(
                    conn, hunt, action, target, baseline, "xss.verify", receipt, {}, observations(baseline),
                    target_kind=kind, allowed_origins=(baseline,),
                )
            assert second != ids
            assert await conn.fetchval("SELECT count(*) FROM findings") == 2
            assert await conn.fetchval("SELECT status FROM findings WHERE id=$1", row_id) == "false_positive"
            assert await conn.fetchval("SELECT status FROM findings WHERE id=$1", uuid.UUID(second[0])) == "active"
            assert await conn.fetchval("SELECT count(*) FROM finding_verifications WHERE finding_id=$1", row_id) == 2
    asyncio.run(run())


def test_postgres_concurrent_canonical_insert_does_not_abort_legacy_reconciliation():
    async def run():
        async with _database() as conn:
            import asyncpg

            target = uuid.uuid4()
            await conn.execute("INSERT INTO targets(id) VALUES($1)", target)
            finding = _finding("https://example.test/search?q=")
            canonical = canonical_finding_fingerprint(finding)
            previous = pre_service_templated_finding_identity(finding)
            old_key = "t:" + hashlib.sha256(previous.encode()).hexdigest()[:16]
            legacy_id = await conn.fetchval(
                """INSERT INTO findings(target_id,fingerprint,title,url,tool,cwe,evidence,status,
                     verification_count,resurfaced_count)
                   VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,'accepted_risk',3,2) RETURNING id""",
                target, old_key, finding["title"], finding["url"], finding["tool"], finding["cwe"],
                json.dumps(finding["evidence"]),
            )
            await conn.execute("INSERT INTO finding_verifications(finding_id,verdict) VALUES($1,'exploited')", legacy_id)
            concurrent_id = uuid.uuid4()
            second = await asyncpg.connect(_validated_postgres_dsn())
            schema = await conn.fetchval("SELECT current_schema()")
            await second.execute(f'SET search_path TO "{schema}"')

            class RacingConnection:
                inserted = False

                def transaction(self):
                    return conn.transaction()

                async def execute(self, query, *args):
                    return await conn.execute(query, *args)

                async def fetchrow(self, query, *args):
                    row = await conn.fetchrow(query, *args)
                    if "SELECT id FROM findings" in query and row is None and not self.inserted:
                        # Force the real race window: canonical absent at the
                        # guard, another committed writer wins before rekeying.
                        self.inserted = True
                        await second.execute(
                            """INSERT INTO findings(id,target_id,fingerprint,title,url,status)
                               VALUES($1,$2,$3,$4,$5,'false_positive')""",
                            concurrent_id, target, canonical, finding["title"], finding["url"],
                        )
                    return row

            proxy = RacingConnection()
            try:
                async with conn.transaction():
                    adopted = await reconcile_legacy_finding_row(
                        proxy, target_uuid=target, fingerprint=canonical, finding=finding,
                    )
                    # A unique-key race must not poison the caller's transaction.
                    assert await conn.fetchval("SELECT 1") == 1
                assert proxy.inserted
                assert adopted["id"] == concurrent_id
                legacy = await conn.fetchrow("SELECT * FROM findings WHERE id=$1", legacy_id)
                assert legacy["fingerprint"] == old_key and legacy["status"] == "accepted_risk"
                assert legacy["verification_count"] == 3 and legacy["resurfaced_count"] == 2
                assert await conn.fetchval("SELECT count(*) FROM finding_verifications WHERE finding_id=$1", legacy_id) == 1
                assert await conn.fetchval("SELECT count(*) FROM findings") == 2
            finally:
                await second.close()
    asyncio.run(run())


def test_stored_rows_with_text_evidence_and_path_only_urls_keep_their_service_identity():
    """Database rows carry evidence as JSON text, and pre-2.3.8 rows stored path-only URLs.
    Neither may stop a legacy row (and its triage history) being adopted."""
    from finding_service_identity import finding_provenance_key, finding_service_origin, same_finding_service

    as_dict = {"url": None, "evidence": {"url": "https://a.example.test/x"}}
    as_text = {"url": None, "evidence": '{"url": "https://a.example.test/x"}'}
    assert finding_service_origin(as_text) == "https://a.example.test:443"
    assert same_finding_service(as_text, as_dict)
    assert finding_provenance_key(as_text) == finding_provenance_key(as_dict)
    # Unknown on both sides: same finding when the client route matches.
    assert same_finding_service({"url": "/x"}, {"url": "/x"})
    # A known service never matches an unknown or different one.
    assert not same_finding_service({"url": "/x"}, as_dict)
    assert not same_finding_service(as_dict, {"url": "https://b.example.test/x"})
    # Malformed text evidence is treated as no evidence, not an error.
    assert finding_service_origin({"url": None, "evidence": "{not json"}) is None


def test_postgres_legacy_row_with_url_only_in_text_evidence_is_adopted():
    """The url column of older rows can be NULL with the URL only in evidence, which asyncpg
    returns as JSON text. Adoption must still recognise the service and keep the row's history."""
    async def run():
        async with _database() as conn:
            target = uuid.uuid4()
            await conn.execute("INSERT INTO targets(id) VALUES($1)", target)
            finding = _finding("https://example.test/search")
            finding["evidence"] = {**finding["evidence"], "url": "https://example.test/search"}
            previous = pre_service_templated_finding_identity(finding)
            old_key = "t:" + hashlib.sha256(previous.encode()).hexdigest()[:16]
            row_id = await conn.fetchval(
                """INSERT INTO findings(target_id,fingerprint,title,url,tool,cwe,evidence,status,
                      verification_count,resurfaced_count,first_seen_at)
                    VALUES($1,$2,$3,NULL,$4,$5,$6::jsonb,'false_positive',0,1,now())
                    RETURNING id""",
                target, old_key, finding["title"], finding["tool"], finding["cwe"], json.dumps(finding["evidence"]),
            )
            async with conn.transaction():
                migrated = await reconcile_legacy_finding_row(
                    conn, target_uuid=target, fingerprint=canonical_finding_fingerprint(finding),
                    finding=finding, target_kind="web",
                )
            assert migrated is not None and migrated["id"] == row_id
            assert migrated["status"] == "false_positive"
            assert await conn.fetchval("SELECT fingerprint FROM findings WHERE id=$1", row_id) == \
                canonical_finding_fingerprint(finding)
    asyncio.run(run())


def test_hunt_rows_written_with_unbracketed_ipv6_service_suffixes_are_reconcilable():
    """Hunt's own suffix wrote https://::1:443; the shared one writes https://[::1]:443."""
    from api.scan.finding_reconciliation import _legacy_identities, legacy_finding_fingerprint

    finding = _finding("https://[2001:db8::1]:8443/search")
    pre_service = pre_service_templated_finding_identity(finding)
    historical = "t:" + hashlib.sha256((pre_service + "|service=https://2001:db8::1:8443").encode()).hexdigest()[:16]
    candidates = {legacy_finding_fingerprint(identity, canonical_finding_fingerprint(finding))
                  for identity in _legacy_identities(finding)}
    assert historical in candidates


def test_identity_keys_survive_a_finding_the_pre_service_key_cannot_read(monkeypatch):
    """Every other legacy key is guarded; this one raised out of finding_identity_keys and broke
    the scan page's proof projection."""
    from api.scan import finding_identity

    def unreadable(_finding):
        raise ValueError("unreadable finding")

    monkeypatch.setattr(finding_identity, "pre_service_templated_finding_identity", unreadable)
    keys = finding_identity_keys(_finding("https://example.test/search"))
    assert keys and keys[0] == canonical_finding_fingerprint(_finding("https://example.test/search"))


def test_postgres_rekey_binds_only_the_original_rows_exception_atomically():
    async def run():
        async with _database() as conn:
            target, other_target = uuid.uuid4(), uuid.uuid4()
            await conn.execute("INSERT INTO targets(id) VALUES($1),($2)", target, other_target)
            finding = _finding("https://example.test/search?q=1")
            old_key = "t:" + hashlib.sha256(pre_service_templated_finding_identity(finding).encode()).hexdigest()[:16]
            canonical = canonical_finding_fingerprint(finding)
            row_id = await conn.fetchval("""INSERT INTO findings(target_id,fingerprint,title,url,tool,cwe,evidence,status)
                VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,'accepted_risk') RETURNING id""", target, old_key,
                finding["title"], finding["url"], finding["tool"], finding["cwe"], json.dumps(finding["evidence"]))
            exception_id = await conn.fetchval("""INSERT INTO finding_exceptions(target_id,fingerprint,status,approver,expires_at)
                VALUES($1,$2,'active','operator','2099-01-01') RETURNING id""", target, old_key)
            other_id = await conn.fetchval("""INSERT INTO finding_exceptions(target_id,fingerprint,status,approver,expires_at)
                VALUES($1,$2,'active','operator','2099-01-01') RETURNING id""", other_target, old_key)
            async with conn.transaction():
                adopted = await reconcile_legacy_finding_row(conn, target_uuid=target, fingerprint=canonical, finding=finding)
            assert adopted["id"] == row_id
            saved = await conn.fetchrow("SELECT * FROM finding_exceptions WHERE id=$1", exception_id)
            assert saved["finding_id"] == str(row_id) and saved["fingerprint"] == canonical
            assert saved["status"] == "active" and saved["approver"] == "operator" and saved["expires_at"].year == 2099
            assert json.loads(saved["edit_history"])[0]["fingerprint"] == old_key
            untouched = await conn.fetchrow("SELECT * FROM finding_exceptions WHERE id=$1", other_id)
            assert untouched["fingerprint"] == old_key and untouched["finding_id"] is None
    asyncio.run(run())


# The re-key moves the finding and its exceptions in one statement. Data-modifying CTEs share one
# snapshot and always run, so the exception move must not depend on which sub-statement the plan
# reads first: a row lock in `prior` skipped the row `moved` had already updated whenever the plan
# put `moved` first, re-keying the finding but leaving its exception on the old fingerprint.
@pytest.mark.parametrize("planner_off", [
    (),
    ("enable_nestloop",),
    ("enable_nestloop", "enable_hashjoin"),
    ("enable_nestloop", "enable_mergejoin"),
    ("enable_nestloop", "enable_hashjoin", "enable_material"),
    ("enable_nestloop", "enable_mergejoin", "enable_material"),
    ("enable_nestloop", "enable_indexscan", "enable_bitmapscan"),
])
def test_postgres_rekey_moves_the_exception_whatever_plan_order_postgres_picks(planner_off):
    async def run():
        async with _database() as conn:
            target = uuid.uuid4()
            await conn.execute("INSERT INTO targets(id) VALUES($1)", target)
            finding = _finding("https://example.test/search?q=1")
            old_key = "t:" + hashlib.sha256(pre_service_templated_finding_identity(finding).encode()).hexdigest()[:16]
            canonical = canonical_finding_fingerprint(finding)
            row_id = await conn.fetchval("""INSERT INTO findings(target_id,fingerprint,title,url,tool,cwe,evidence,status)
                VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,'accepted_risk') RETURNING id""", target, old_key,
                finding["title"], finding["url"], finding["tool"], finding["cwe"], json.dumps(finding["evidence"]))
            exception_id = await conn.fetchval("""INSERT INTO finding_exceptions(target_id,fingerprint,status,approver,expires_at)
                VALUES($1,$2,'active','operator','2099-01-01') RETURNING id""", target, old_key)
            async with conn.transaction():
                for setting in planner_off:
                    await conn.execute(f"SET LOCAL {setting} = off")
                adopted = await reconcile_legacy_finding_row(conn, target_uuid=target, fingerprint=canonical, finding=finding)
            assert adopted["id"] == row_id
            assert await conn.fetchval("SELECT fingerprint FROM findings WHERE id=$1", row_id) == canonical
            saved = await conn.fetchrow("SELECT fingerprint, finding_id FROM finding_exceptions WHERE id=$1", exception_id)
            assert (saved["fingerprint"], saved["finding_id"]) == (canonical, str(row_id))
    asyncio.run(run())
