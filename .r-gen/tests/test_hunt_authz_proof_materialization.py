"""Canonical loopback HTTP -> existing proof -> receipt -> Hunt finding acceptance.

PostgreSQL tests execute real materialization SQL in a disposable schema. They are
skipped only when its DSN is absent; configured database failures are failures.
These are assisted fixture tests, not autonomous discovery or Juice Shop recall.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
from urllib.parse import urlsplit
import uuid

import pytest

from api.hunt.authz_findings import authz_finding_records
from api.hunt.capability_reservations import terminalize_hunt_capability
from api.hunt.deterministic_findings import materialize_verified_hunt_findings
from api.hunt.finding_verifications import FINDING_HUNT_VERIFICATIONS_SCHEMA_SQL
from api.runtime.budget_reservations import DurableBudgetReservation
from api.runtime.models import TargetBinding
from api.scan.finalizer import canonical_authz_findings
from scanner.findings import pre_service_templated_finding_identity, templated_finding_identity
from tests.api_sources import definition_source
from tests.e2e.fixtures import fixtures_server

# The production HTTP adapter currently uses the installed-runtime import layout.
# Append, not prepend: do not turn api.py/scanner.py into package replacements.
sys.path.append(str(Path(__file__).resolve().parents[1] / "api"))
from capabilities.authz import verify_target_bound_object_authorization

HUNT, TARGET, ACTION, RECEIPT = (uuid.uuid4() for _ in range(4))
A = {"Authorization": "Bearer authz-token-a"}
B = {"Authorization": "Bearer authz-token-b"}
NOW = datetime.now(timezone.utc)


@pytest.fixture(scope="module")
def origin():
    server = fixtures_server.start(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


async def exercise(origin, routes, *, secondary=B):
    transactions = []
    result = await verify_target_bound_object_authorization(
        origin, routes, target=TargetBinding(
            target_id=str(TARGET), target_kind="web", canonical_host="127.0.0.1",
            allowed_origins=(origin,), allowed_addresses=("127.0.0.1",),
            scope_receipt_id="fixture-scope"),
        primary_headers=A, secondary_headers=secondary,
        transaction_recorder=transactions.append,
    )
    return result, make_receipt(result), transactions


def make_receipt(result, *, hunt_id=HUNT, target_id=TARGET, capability="authz.verify", target_kind="web"):
    running = DurableBudgetReservation.request(
        owner_kind="hunt", owner_id=str(hunt_id), capability_name=capability,
        amounts={"http_requests": 4, "tool_wall_seconds": 60},
        reservation_id=str(uuid.uuid4()), now=NOW,
    ).reserve(now=NOW, lease_seconds=90).start(worker_id="fixture-worker", now=NOW, lease_seconds=90)
    _, receipt = terminalize_hunt_capability(
        running, action_digest="a" * 64, capability_name=capability,
        adapter_name="bound_authz_verifier", adapter_version="1",
        target_id=str(target_id), target_kind=target_kind, capability_input={},
        action_status="completed", actual_budget=result["budget_consumed"], worker_id="fixture-worker",
        started_at=NOW.isoformat(), finished_at=(NOW + timedelta(seconds=1)).isoformat(),
        receipt_id=str(RECEIPT), result={"receipt_observations": [result["observation"]]},
    )
    return receipt


def records(receipt, origin):
    return authz_finding_records(receipt, hunt_id=HUNT, action_id=ACTION,
        target_id=TARGET, receipt_id=RECEIPT, allowed_origins=(origin,), target_url=origin)


def _service_proof(consumer_url, *, target_url="https://h.test",
                   allowed=("https://h.test", "https://h.test:8443")):
    """A verified cross-principal observation on one service of the Hunt's host."""
    producer_url = consumer_url.rsplit("/", 1)[0]
    observation = {
        "kind": "authz_differential", "proof_state": "verified",
        "proof_type": "cross_principal_replay", "principal_contexts_distinct": True,
        "object_absent_from_secondary_listing": True, "responses_equivalent": True,
        "consumer_url": consumer_url, "producer_url": producer_url,
        "resource_id_sha256": "0" * 64, "owner_status": 200, "attacker_status": 200,
        "accepted_principal_responses": {"primary": 200, "secondary": 200},
    }
    receipt = make_receipt({"observation": observation,
                            "budget_consumed": {"http_requests": 4, "tool_wall_seconds": 1}})
    projected = authz_finding_records(receipt, hunt_id=HUNT, action_id=ACTION,
        target_id=TARGET, receipt_id=RECEIPT, allowed_origins=allowed, target_url=target_url)
    assert len(projected) == 1
    return projected[0]


def test_the_same_route_on_another_service_port_is_a_distinct_finding():
    """Hunt reuses its authority on other ports of the host, and the templated identity
    keeps only path and parameter names: both proofs keyed one row, and the upsert
    overwrote one service's verified finding with the other's."""
    primary = _service_proof("https://h.test/api/orders/7")
    alternate = _service_proof("https://h.test:8443/api/orders/9")
    assert primary["fingerprint"] != alternate["fingerprint"]
    assert alternate["url"].startswith("https://h.test:8443/")
    # Another object id on the same alternate service is still the same endpoint.
    assert _service_proof("https://h.test:8443/api/orders/11")["fingerprint"] == alternate["fingerprint"]


def test_materializing_a_second_service_proof_does_not_overwrite_the_first():
    class DB:
        """The findings upsert, keyed like (target_id, fingerprint)."""
        def __init__(self): self.rows = {}
        async def fetchrow(self, query, target_id, fingerprint):
            return self.rows.get(fingerprint)
        async def fetchval(self, query, target_id, hunt_id, fingerprint, url, *args):
            assert "ON CONFLICT" in query
            self.rows.setdefault(fingerprint, {"id": uuid.uuid4()})["url"] = url
            return self.rows[fingerprint]["id"]
        async def execute(self, *args): pass

    db = DB()
    for url in ("https://h.test/api/orders/7", "https://h.test:8443/api/orders/9"):
        observation = {
            "kind": "authz_differential", "proof_state": "verified",
            "proof_type": "cross_principal_replay", "principal_contexts_distinct": True,
            "object_absent_from_secondary_listing": True, "responses_equivalent": True,
            "consumer_url": url, "producer_url": url.rsplit("/", 1)[0],
            "resource_id_sha256": "0" * 64, "owner_status": 200, "attacker_status": 200,
            "accepted_principal_responses": {"primary": 200, "secondary": 200},
        }
        receipt = make_receipt({"observation": observation,
                                "budget_consumed": {"http_requests": 4, "tool_wall_seconds": 1}})
        assert len(asyncio.run(materialize_verified_hunt_findings(
            db, HUNT, ACTION, TARGET, "https://h.test", "authz.verify", RECEIPT, {}, [],
            capability_receipt=receipt, allowed_origins=("https://h.test", "https://h.test:8443"),
        ))) == 1
    assert sorted(row["url"] for row in db.rows.values()) == [
        "https://h.test/api/orders/7", "https://h.test:8443/api/orders/9",
    ]


def test_default_port_spellings_of_one_service_share_a_fingerprint():
    implicit = _service_proof("https://h.test/api/orders/7")
    explicit = _service_proof("https://h.test:443/api/orders/9")
    assert implicit["fingerprint"] == explicit["fingerprint"]
    # Spelled with the port on the target side too.
    assert _service_proof("https://h.test/api/orders/7",
                          target_url="https://h.test:443/")["fingerprint"] == implicit["fingerprint"]


def test_a_target_service_finding_uses_scan_identity_and_retains_its_legacy_key():
    """Scan and Hunt agree even when the Hunt baseline uses another service."""
    record = _service_proof("https://h.test/api/orders/7")
    finding = {
        "url": record["url"], "cwe": record["cwe"], "tool": record["tool"],
        "title": record["title"], "evidence": record["evidence"],
    }
    identity = templated_finding_identity(finding)
    assert record["fingerprint"] == "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16]
    previous = pre_service_templated_finding_identity(finding)
    assert "t:" + hashlib.sha256(previous.encode()).hexdigest()[:16] == "t:33e0ffeed54c7ba2"
    assert _service_proof(
        "https://h.test/api/orders/7", target_url="https://h.test:8443",
    )["fingerprint"] == record["fingerprint"]


def test_real_bound_http_proof_projects_to_the_same_finding_as_scan(origin):
    result, receipt, traffic = asyncio.run(exercise(origin,
        [origin + "/authz/vuln/orders", origin + "/authz/vuln/orders/1001"]))
    projected = records(receipt, origin)
    assert len(projected) == 1
    assert result["observation"]["proof_state"] == "verified"
    assert result["budget_consumed"]["http_requests"] == len(traffic) == 4
    assert {t["principal_slot"] for t in traffic} == {"primary", "secondary"}
    assert all(t["method"] == "GET" for t in traffic)
    evidence = projected[0]["evidence"]
    scan = canonical_authz_findings(receipt.observations, receipt=evidence["capability_receipt"])[0]
    assert projected[0]["fingerprint"] == "t:" + hashlib.sha256(templated_finding_identity(scan).encode()).hexdigest()[:16]
    assert evidence["proof_contract_v2"] == scan["proof_contract_v2"]
    assert evidence["hunt_id"] == str(HUNT) and evidence["source_action_id"] == str(ACTION)
    assert evidence["capability_receipt"]["receipt_hash"] == receipt.receipt_hash
    from api.finding_routes.router import finding_proof_fields
    fields = finding_proof_fields({"evidence": evidence, "severity": "high",
                                   "last_verification_verdict": "exploited"})
    assert fields["is_verified"] is True and fields["proof_state"] == "verified"
    encoded = json.dumps(projected)
    assert "authz-token-a" not in encoded and "authz-token-b" not in encoded
    assert "owner@example" not in encoded


@pytest.mark.parametrize("routes,secondary", [
    (["/authz/safe/orders", "/authz/safe/orders/1001"], B),
    (["/authz/public/directory", "/authz/public/directory/7001"], B),
    (["/authz/public/notices", "/authz/public/notices/9001"], B),
    (["/authz/vuln/orders", "/authz/vuln/orders/1001"], A),
    (["/authz/vuln/orders", "/authz/vuln/orders/1001"], {"Authorization": "Bearer authz-token-expired"}),
    # A real crossing without a caller-scoped listing is still not a proof of entitlement.
    (["/authz/vuln/orders/1001", "/authz/vuln/orders/2001"], B),
])
def test_nonproof_controls_never_materialize(origin, routes, secondary):
    result, receipt, _ = asyncio.run(exercise(origin, [origin + p for p in routes], secondary=secondary))
    assert result["observation"]["proof_state"] != "verified"
    assert records(receipt, origin) == []


def test_receipt_ownership_and_hash_are_required_even_when_loose_flags_say_verified(origin):
    result, receipt, _ = asyncio.run(exercise(origin, [origin + "/authz/vuln/orders"]))
    assert records(make_receipt(result, hunt_id=uuid.uuid4()), origin) == []
    assert records(make_receipt(result, target_id=uuid.uuid4()), origin) == []
    assert records(make_receipt(result, capability="http.request"), origin) == []
    assert records(make_receipt(result, target_kind="device"), origin) == []
    assert records(None, origin) == []
    assert records(receipt, "https://unrelated.invalid") == []
    tampered = receipt.public_dict()
    tampered["observations"][0]["consumer_url"] += "/tampered"
    assert records(tampered, origin) == []


def test_all_original_scan_proof_requirements_still_apply(origin):
    result, _, _ = asyncio.run(exercise(origin, [origin + "/authz/vuln/orders"]))
    for key in ("proof_state", "proof_type", "principal_contexts_distinct",
                "object_absent_from_secondary_listing", "responses_equivalent"):
        changed = {**result, "observation": {**result["observation"], key: None}}
        assert records(make_receipt(changed), origin) == [], key


def test_http_worker_materializes_in_the_atomic_settlement_and_replays_saved_ids():
    source = definition_source("_worker_terminal_network_result")
    assert '"verified_finding_ids"' in source and "action_result" in source
    worker = (Path(__file__).resolve().parents[1] / "api/worker.py").read_text()
    begin = worker.index('        elif capability_name == "authz.verify":')
    end = worker.index("    except asyncio.CancelledError:", begin)
    settlement = worker[begin:end]
    assert settlement.index("terminalize_hunt_capability(") < settlement.index("materialize_verified_hunt_findings(")
    assert settlement.index("materialize_verified_hunt_findings(") < settlement.index("reservation_store.persist_terminal(")
    assert "capability_receipt=capability_receipt" in settlement
    assert "allowed_origins=target.allowed_origins" in settlement
    assert settlement.count('"verified_finding_ids": verified_finding_ids') == 2
    # The terminal branch returns before an adapter can run, using the already locked action.
    preceding = worker[worker.rfind("                if stored.record.terminal:", 0, begin):begin]
    assert 'action_result=_worker_json_object(action["result_summary"])' in preceding


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
 last_verified_at timestamptz, verification_count int, resolved_at timestamptz,
 resurfaced_count int DEFAULT 0,
 last_seen_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now());
CREATE UNIQUE INDEX web_finding_key ON findings(target_id,fingerprint) WHERE target_id IS NOT NULL;
CREATE UNIQUE INDEX device_finding_key ON findings(device_target_id,fingerprint) WHERE device_target_id IS NOT NULL;
CREATE TABLE finding_verifications(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), finding_id uuid REFERENCES findings(id),
 target_id uuid, device_target_id uuid, requested_by text, status text, result_status text,
 verdict text, verdict_reason text, finding_type text, target_url text, original_url text,
 proof jsonb, confidence double precision, verification_mode text, contract_id text,
 contract_version text, proof_basis text, started_at timestamptz, completed_at timestamptz, updated_at timestamptz);
"""


@pytest.mark.skipif(not os.getenv("HUNT_TEST_POSTGRES_DSN"), reason="disposable PostgreSQL DSN not configured")
@pytest.mark.parametrize("kind", ["web", "device"])
def test_real_postgres_proof_is_hunt_attributed_and_atomic(origin, kind):
    async def check():
        import asyncpg
        dsn = os.environ["HUNT_TEST_POSTGRES_DSN"]
        assert urlsplit(dsn).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
        conn = await asyncpg.connect(dsn)
        schema = "hunt_authz_proof_" + uuid.uuid4().hex
        try:
            await conn.execute(f'CREATE SCHEMA "{schema}"')
            await conn.execute(f'SET search_path TO "{schema}"')
            await conn.execute(DDL)
            await conn.execute(FINDING_HUNT_VERIFICATIONS_SCHEMA_SQL)
            table = "device_targets" if kind == "device" else "targets"
            column = "device_target_id" if kind == "device" else "target_id"
            await conn.execute(f"INSERT INTO {table}(id) VALUES($1)", TARGET)
            other_hunt, other_action = uuid.uuid4(), uuid.uuid4()
            for hunt, action in ((HUNT, ACTION), (other_hunt, other_action)):
                await conn.execute("INSERT INTO hunt_runs(id) VALUES($1)", hunt)
                await conn.execute("INSERT INTO hunt_actions(id,hunt_run_id) VALUES($1,$2)", action, hunt)
            result, _, _ = await exercise(origin, [origin + "/authz/vuln/orders"])
            receipt = make_receipt(result, target_kind=kind)
            async def persist(hunt=HUNT, action=ACTION):
                return await materialize_verified_hunt_findings(conn, hunt, action, TARGET, origin,
                    "authz.verify", RECEIPT, {}, [], target_kind=kind,
                    capability_receipt=receipt if hunt == HUNT else make_receipt(
                        result, hunt_id=hunt, target_kind=kind),
                    allowed_origins=(origin,))
            with pytest.raises(RuntimeError, match="rollback fixture"):
                async with conn.transaction():
                    await persist()
                    raise RuntimeError("rollback fixture")
            assert await conn.fetchval("SELECT count(*) FROM findings") == 0
            assert await conn.fetchval("SELECT count(*) FROM finding_verifications") == 0
            async with conn.transaction():
                ids = await persist()
            assert len(ids) == 1
            row = await conn.fetchrow(f"SELECT * FROM findings WHERE hunt_run_id=$1 AND {column}=$2", HUNT, TARGET)
            assert str(row["id"]) == ids[0] and row["last_verification_verdict"] == "exploited"
            assert row["cvss_score"] is None and row["cwe"] == "CWE-639"
            assert await conn.fetchval("SELECT count(*) FROM finding_verifications WHERE verdict='exploited'") == 1
            assert await conn.fetchval(f"SELECT active_findings_count FROM {table} WHERE id=$1", TARGET) == 1
            # A distinct deliberate verification upserts the same endpoint, retaining history.
            async with conn.transaction():
                assert await persist() == ids
            assert await conn.fetchval("SELECT count(*) FROM findings") == 1
            assert await conn.fetchval("SELECT count(*) FROM finding_verifications") == 2
            # D21: another Hunt proving the same finding again is recorded beside the first
            # verifier, which keeps the finding.
            async with conn.transaction():
                assert await persist(other_hunt, other_action) == ids
            assert await conn.fetchval("SELECT hunt_run_id FROM findings") == HUNT
            roles = await conn.fetch(
                "SELECT hunt_run_id, action_id, role FROM finding_hunt_verifications ORDER BY role DESC")
            assert [tuple(row) for row in roles] == [
                (HUNT, ACTION, "owner"), (other_hunt, other_action, "additional")]
            assert result["budget_consumed"]["http_requests"] == 4
        finally:
            await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            await conn.close()
    asyncio.run(check())
