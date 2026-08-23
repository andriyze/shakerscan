from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from api.runtime.observation_manifests import ObservationManifestReference
from api.runtime.observation_store import (
    MIGRATION_NAME,
    PostgresObservationManifestStore,
    SCAN_OBSERVATION_MANIFEST_SCHEMA_SQL,
    ObservationStoreError,
)


SCAN_ID = "50000000-0000-4000-8000-000000000001"


class FakeConn:
    def __init__(self):
        self.rows = {}
        self.executed = []

    async def execute(self, query, *args):
        self.executed.append((query, args))

    async def fetchrow(self, query, *args):
        if query.lstrip().startswith("INSERT INTO scan_observation_manifests"):
            key = args[0]
            incoming = {"manifest_json": args[10], "observations_json": args[11]}
            existing = self.rows.get(key)
            if existing is not None and existing != incoming:
                return None
            self.rows[key] = incoming
            return {"manifest_json": incoming["manifest_json"]}
        if "FROM scan_observation_manifests" in query:
            return self.rows.get(args[0])
        raise AssertionError(query)


def _persist(conn, observations):
    return asyncio.run(PostgresObservationManifestStore().persist(
        conn,
        scan_id=SCAN_ID,
        action_id="discover.web_crawl",
        capability_name="web.crawl",
        output_schema="katana-lines/v1",
        observations=observations,
    ))


def test_observation_store_round_trips_immutable_private_content():
    observations = ({
        "kind": "discovered_route",
        "method": "GET",
        "url": "https://app.example.test/api/orders?owner=%3Credacted%3E",
    },)
    conn = FakeConn()
    first = _persist(conn, observations)
    second = _persist(conn, observations)

    assert first == second
    assert isinstance(first, ObservationManifestReference)
    assert first.count == 1
    assert first.object_key.startswith("scan-observations/")
    assert "url" not in json.dumps(first.canonical_dict())
    loaded = asyncio.run(PostgresObservationManifestStore().load(
        conn,
        reference=first,
        scan_id=SCAN_ID,
        action_id="discover.web_crawl",
    ))
    assert loaded == observations


def test_observation_store_detects_tampered_content_and_non_json_values():
    conn = FakeConn()
    reference = _persist(conn, ({"kind": "route", "value": 1},))
    row = conn.rows[next(iter(conn.rows))]
    row["observations_json"] = json.dumps([{"kind": "route", "value": 2}])
    with pytest.raises(ObservationStoreError, match="differ"):
        asyncio.run(PostgresObservationManifestStore().load(
            conn, reference=reference, scan_id=SCAN_ID, action_id="discover.web_crawl",
        ))

    with pytest.raises(ObservationStoreError, match="canonical JSON"):
        _persist(FakeConn(), ({"not_finite": float("nan")},))


def test_observation_store_schema_is_in_fresh_and_upgrade_paths():
    conn = FakeConn()
    asyncio.run(PostgresObservationManifestStore().ensure_schema(conn))
    assert conn.executed == [(SCAN_OBSERVATION_MANIFEST_SCHEMA_SQL, ())]
    assert MIGRATION_NAME in SCAN_OBSERVATION_MANIFEST_SCHEMA_SQL
    for path in (
        Path("db/init.sql"),
        Path("db/repairs/2026-08-23_v2_scan_observation_manifests.sql"),
    ):
        source = path.read_text(encoding="utf-8")
        assert "scan_observation_manifests" in source
        assert "content_sha256" in source
        assert "observations_json" in source
