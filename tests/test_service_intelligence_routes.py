"""Read-only API, result integrity and scoped Hunt-query tests."""
from contextlib import asynccontextmanager
import hashlib
import json
from types import SimpleNamespace
import uuid

from fastapi import FastAPI
import httpx
import pytest

from api.exposure import services_router, service_knowledge
from api.exposure.service_store import validated_scan_source, service_page
from api.runtime.observation_manifests import ObservationManifest
from api.scan.capability_result import CapabilityReceiptReference, CapabilityResultReference

OWNER = "11111111-1111-4111-8111-111111111111"
SCAN = "22222222-2222-4222-8222-222222222222"
SID = "33333333-3333-4333-8333-333333333333"


class Connection:
    def __init__(self):
        self.transaction_options = None
        self.loaded = 0

    @asynccontextmanager
    async def transaction(self, **options):
        self.transaction_options = options
        yield self


class Pool:
    def __init__(self):
        self.conn = Connection()

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


@pytest.mark.asyncio
async def test_api_is_read_only_paginated_and_uses_application_pool(monkeypatch):
    app = FastAPI()
    app.include_router(services_router.router)
    app.state.db_pool = Pool()
    captured = []
    monkeypatch.setattr(services_router, "load_service_intelligence", lambda: ({"status": "available"}, lambda *a, **k: []))
    monkeypatch.setattr(services_router, "canonical_registry", lambda: object())
    async def page(conn, **options):
        captured.append(options)
        return {"targets": [], "total_targets": 0}
    monkeypatch.setattr(services_router, "service_page", page)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/exposure/services?target_id={OWNER}&target_kind=device&limit=5&offset=10&search=Test")
        assert response.status_code == 200
        assert captured[0]["target_id"] == uuid.UUID(OWNER)
        assert captured[0]["limit"] == 5 and captured[0]["offset"] == 10
        assert app.state.db_pool.conn.transaction_options == {"isolation": "repeatable_read", "readonly": True}
        assert (await client.post('/exposure/services', json={"active_testing": True})).status_code == 405
        for query in ['limit=100000', 'offset=-1', 'target_kind=admin', 'target_id=other', 'root_domain=%25', 'search=' + 'x' * 201]:
            assert (await client.get('/exposure/services?' + query)).status_code == 422
        assert len(captured) == 1


@pytest.mark.asyncio
async def test_unready_database_is_explicit_503():
    app = FastAPI()
    app.include_router(services_router.router)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get('/exposure/services')).status_code == 503


def action_fixture():
    observations = [{"kind": "service", "address": "192.0.2.1", "transport": "tcp", "port": 8443, "state": "open", "service": "http"}]
    content = json.dumps(observations, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    manifest = ObservationManifest(owner_id=SCAN, action_id="discover.services", capability_name="service.fingerprint", output_schema="nmap-xml/v1",
                                   observation_count=1, content_sha256=hashlib.sha256(content).hexdigest(), size_bytes=len(content), object_key="scan-observations/test.json")
    result = CapabilityResultReference(action_id="discover.services", action_digest="a" * 64, capability_name="service.fingerprint", adapter_name="nmap", adapter_version="1",
                                       output_schema="nmap-xml/v1", status="success", partial=False, timed_out=False, reason_code=None,
                                       receipt_ref=CapabilityReceiptReference(receipt_id=SID, receipt_hash="b" * 64), observation_manifest_ref=manifest.reference(),
                                       budget_reserved={}, budget_consumed={})
    row = {"action_id": result.action_id, "action_digest": result.action_digest, "result_digest": result.result_digest,
           "capability_name": result.capability_name, "result_json": result.canonical_dict(), "scan_id": SCAN, "status": "success", "finished_at": "2026-09-16T00:00:00Z"}
    return row, manifest, observations


@pytest.mark.asyncio
async def test_scan_projection_verifies_manifest_hash_and_exact_owner():
    row, manifest, observations = action_fixture()
    class Conn:
        async def fetchrow(self, sql, *args):
            assert args[1:] == (uuid.UUID(SCAN), row["action_id"])
            return {"manifest_json": manifest.canonical_dict(), "observations_json": observations}
    projected = await validated_scan_source(Conn(), row)
    assert projected["observations"] == observations
    assert projected["sha256"] == manifest.content_sha256
    observations[0]["port"] = 22
    with pytest.raises(ValueError, match="service_source_invalid"):
        await validated_scan_source(Conn(), row)


@pytest.mark.asyncio
async def test_unbound_or_mismatched_action_result_is_rejected():
    row, _, _ = action_fixture()
    for change in ({"action_id": "another"}, {"action_digest": "f" * 64}, {"capability_name": "http.request"}, {"status": "partial"}):
        with pytest.raises(ValueError):
            await validated_scan_source(Connection(), {**row, **change})


@pytest.mark.asyncio
async def test_empty_out_of_range_page_keeps_total_and_filters():
    class Conn:
        async def fetchval(self, sql, *args):
            assert args == ("device", uuid.UUID(OWNER), "example.test", "literal_%")
            assert "strpos" in sql
            return 3
        async def fetch(self, sql, *args):
            assert args[-2:] == (10, 50)
            return []
    page = await service_page(Conn(), target_kind="device", target_id=uuid.UUID(OWNER), root_domain="EXAMPLE.TEST.", search="Literal_%", limit=10, offset=50,
                              snapshot={"status": "unavailable"}, matcher=None, registry=None)
    assert page["total_targets"] == 3 and page["targets"] == [] and not page["has_more"]


@pytest.mark.asyncio
async def test_hunt_query_reuses_target_scoped_evidence_and_binds_cursor(monkeypatch):
    records = [{"id": SID}, {"id": "44444444-4444-4444-8444-444444444444"}]
    monkeypatch.setattr(service_knowledge, "load_service_intelligence", lambda: ({}, None))
    monkeypatch.setattr(service_knowledge, "canonical_registry", lambda: None)
    async def page(conn, **args):
        assert args["target_id"] == uuid.UUID(OWNER)
        assert args["target_kind"] == "web" and args["limit"] == 1
        return {"targets": [{"services": records}], "intelligence": {}, "limitations": []}
    monkeypatch.setattr(service_knowledge, "service_page", page)
    first = await service_knowledge.query_service_knowledge(None, target_id=OWNER, device=False, limit=1)
    assert first["has_more"] and first["count"] == 1
    next_page = await service_knowledge.query_service_knowledge(None, target_id=OWNER, device=False, limit=1, cursor=first["next_cursor"])
    assert not next_page["has_more"] and next_page["rows"][0]["id"] != first["rows"][0]["id"]
    with pytest.raises(ValueError, match="target/query"):
        await service_knowledge.query_service_knowledge(None, target_id=SID, device=False, cursor=first["next_cursor"])
    records.append({"id": "55555555-5555-4555-8555-555555555555"})
    with pytest.raises(ValueError, match="changed"):
        await service_knowledge.query_service_knowledge(None, target_id=OWNER, device=False, cursor=first["next_cursor"])
    selected = await service_knowledge.query_service_knowledge(None, target_id=OWNER, device=False, filters={"id": SID})
    assert selected["rows"] == [{"id": SID}]
    with pytest.raises(ValueError):
        await service_knowledge.query_service_knowledge(None, target_id=OWNER, device=False, filters={"target_id": SID})
