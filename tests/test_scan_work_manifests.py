from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from api.scan.manifest_store import (
    MIGRATION_NAME,
    PostgresScanManifestStore,
    SCAN_WORK_MANIFEST_SCHEMA_SQL,
    ScanManifestStoreError,
)
from api.scan.work_manifests import (
    ScanWorkManifest,
    ScanWorkManifestError,
    ScanWorkManifestKind,
    ScanWorkManifestReference,
    build_candidate_manifest,
    build_endpoint_manifest,
    build_request_manifest,
    build_template_manifest,
    execution_url_for_endpoint,
    work_manifest_references_in,
)


SCAN_ID = "40000000-0000-4000-8000-000000000001"
TARGET_DIGEST = "a" * 64


def _surface(*, query_keys=("page", "owner")):
    return {
        "schema_version": "endpoint-manifest/v1",
        "status": "complete",
        "reason": None,
        "endpoint_count": 1,
        "endpoints": [{
            "method": "GET",
            "scheme": "https",
            "host": "app.example.test",
            "port": 443,
            "normalized_path": "/api/orders/{int}",
            "concrete_path": "/api/orders/1",
            "query_keys": list(query_keys),
            "content_fingerprint": None,
            "source": "web.crawl",
            "sensitive_path_redacted": False,
        }],
        "producers": {},
        "persistence_errors": [],
    }


def _endpoint_manifest(**kwargs):
    return build_endpoint_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        surface_manifest=_surface(**kwargs),
        source_action_ids=("discover.web_crawl",),
        auth_lane="primary",
        selected_shard=2,
    )


def test_endpoint_manifest_freezes_complete_value_free_route_contract():
    manifest = _endpoint_manifest()
    entry = manifest.entries[0]

    assert manifest.kind is ScanWorkManifestKind.ENDPOINT
    assert manifest.content_schema == "endpoint-manifest/v2"
    assert entry["canonical_path"] == "/api/orders/{int}"
    assert entry["query_parameter_names"] == ("owner", "page")
    assert entry["source_tool"] == "web.crawl"
    assert entry["discovery_depth"] == 1
    assert entry["auth_lane"] == "primary"
    assert entry["selected_shard"] == 2
    assert len(entry["route_id"]) == 64
    assert execution_url_for_endpoint(entry) == (
        "https://app.example.test/api/orders/1?owner=1&page=1"
    )

    encoded = json.dumps(manifest.canonical_dict(), sort_keys=True)
    assert "concrete_path" not in encoded
    assert "query_value" not in encoded
    assert ScanWorkManifest.from_dict(manifest.canonical_dict()) == manifest
    assert ScanWorkManifestReference.from_dict(
        manifest.reference().canonical_dict()
    ) == manifest.reference()


def test_manifest_reference_extraction_accepts_only_canonical_nested_references():
    reference = _endpoint_manifest().reference()

    extracted = work_manifest_references_in({
        "target_manifest_ref": reference.canonical_dict(),
        "duplicate": [reference.canonical_dict()],
        "lookalike": {**reference.canonical_dict(), "entry_count": 99},
        "invalid": {"manifest_id": reference.manifest_id},
    })

    assert extracted == (
        reference,
        ScanWorkManifestReference.from_dict({
            **reference.canonical_dict(), "entry_count": 99,
        }),
    )


def test_candidate_manifest_covers_every_parameter_and_marks_bounded_truncation():
    endpoint = _endpoint_manifest(query_keys=("a", "b", "c"))
    complete = build_candidate_manifest(
        endpoint,
        source_action_ids=("discover.candidates",),
        maximum=10,
    )
    partial = build_candidate_manifest(
        endpoint,
        source_action_ids=("discover.candidates",),
        maximum=2,
    )

    assert [item["parameter_name"] for item in complete.entries] == ["a", "b", "c"]
    assert len({item["candidate_id"] for item in complete.entries}) == 3
    assert partial.status == "partial"
    assert partial.reason_code == "candidate_limit_reached"
    assert len(partial.entries) == 2


def test_request_and_template_manifests_are_complete_bounded_and_deterministic():
    route = _endpoint_manifest().entries[0]["route_id"]
    request = build_request_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        source_action_ids=("inputs.collection_00",),
        requests=({
            "request_ref_id": "request-1",
            "route_id": route,
            "method": "GET",
            "auth_lane": "primary",
            "selected_shard": None,
            "safe_method": True,
            "body_schema_digest": None,
        },),
    )
    templates = build_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        source_action_ids=("active.templates",),
        templates=({
            "template_id": f"template-{index}",
            "template_digest": f"{index:064x}",
            "risk": "safe_active",
            "tags": ["cve"],
        } for index in range(5)),
        batch_size=2,
    )

    assert request.entries[0]["request_ref_id"] == "request-1"
    assert [item["batch_index"] for item in templates.entries] == [0, 0, 1, 1, 2]
    assert len(templates.entries) == 5


def test_manifests_reject_secret_fields_and_sensitive_concrete_paths():
    route = _endpoint_manifest().entries[0]["route_id"]
    with pytest.raises(ScanWorkManifestError, match="secret values"):
        build_request_manifest(
            scan_id=SCAN_ID,
            target_binding_digest=TARGET_DIGEST,
            source_action_ids=("inputs.collection_00",),
            requests=({
                "request_ref_id": "request-1",
                "route_id": route,
                "method": "GET",
                "auth_lane": "primary",
                "selected_shard": None,
                "safe_method": True,
                "body_schema_digest": None,
                "authorization": "Bearer should-never-persist",
            },),
        )

    surface = _surface()
    surface["endpoints"][0]["normalized_path"] = "/reset/secret_abcdefghijklmnopqrstuvwxyz"
    with pytest.raises(ScanWorkManifestError, match="sensitive path"):
        build_endpoint_manifest(
            scan_id=SCAN_ID,
            target_binding_digest=TARGET_DIGEST,
            surface_manifest=surface,
            source_action_ids=("discover.web_crawl",),
        )


class FakeConn:
    def __init__(self):
        self.rows = {}
        self.executed = []

    async def execute(self, query, *args):
        self.executed.append((query, args))

    async def fetchrow(self, query, *args):
        if query.lstrip().startswith("INSERT INTO scan_work_manifests"):
            manifest_id = args[0]
            content = args[11]
            existing = self.rows.get(manifest_id)
            if existing is not None and existing != content:
                return None
            self.rows[manifest_id] = content
            return {"content_json": content}
        if "FROM scan_work_manifests" in query:
            return (
                {"content_json": self.rows[args[0]]}
                if args[0] in self.rows else None
            )
        raise AssertionError(query)

    async def fetch(self, query, *args):
        assert "FROM scan_work_manifests" in query
        return [{"content_json": value} for value in self.rows.values()]


def test_postgres_manifest_store_round_trips_content_and_rejects_conflicts():
    manifest = _endpoint_manifest()
    conn = FakeConn()
    store = PostgresScanManifestStore()
    first = asyncio.run(store.persist(conn, manifest=manifest))
    second = asyncio.run(store.persist(conn, manifest=manifest))
    loaded = asyncio.run(store.load(
        conn,
        manifest_id=manifest.manifest_id,
        scan_id=SCAN_ID,
        expected_kind="endpoint",
        expected_digest=manifest.manifest_digest,
        expected_target_binding_digest=TARGET_DIGEST,
    ))

    assert first == second == manifest.reference()
    assert loaded == manifest
    assert asyncio.run(store.list_references(conn, scan_id=SCAN_ID)) == (
        manifest.reference(),
    )

    conn.rows[next(iter(conn.rows))] = json.dumps({"tampered": True})
    with pytest.raises(ScanManifestStoreError, match="invalid"):
        asyncio.run(store.load(
            conn, manifest_id=manifest.manifest_id, scan_id=SCAN_ID,
        ))


def test_work_manifest_schema_is_available_to_fresh_and_upgraded_databases():
    conn = FakeConn()
    asyncio.run(PostgresScanManifestStore().ensure_schema(conn))
    assert conn.executed == [(SCAN_WORK_MANIFEST_SCHEMA_SQL, ())]
    assert MIGRATION_NAME in SCAN_WORK_MANIFEST_SCHEMA_SQL
    for path in (
        Path("db/init.sql"),
        Path("db/repairs/2026-08-23_v2_scan_work_manifests.sql"),
    ):
        source = path.read_text(encoding="utf-8")
        assert "scan_work_manifests" in source
        assert "target_binding_digest" in source
        assert "manifest_digest" in source
        assert "content_json" in source
