from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from api.runtime.request_collection_store import (
    PostgresRequestCollectionStore,
    RequestCollectionContractError,
    RequestCollectionSelection,
    canonical_collection_origin,
    canonical_collection_origins,
    request_collection_selection_digest,
)


PAYLOAD_DIGEST = "a" * 64
ENVIRONMENT_DIGEST = "b" * 64


def test_collection_origins_are_exact_and_content_free():
    assert canonical_collection_origin("HTTPS://API.Example.test:443") == (
        "https://api.example.test"
    )
    assert canonical_collection_origins([
        "https://api.example.test",
        "https://api.example.test/",
        "http://api.example.test:8080",
    ]) == (
        "http://api.example.test:8080",
        "https://api.example.test",
    )
    assert canonical_collection_origin("https://[2001:db8::1]:443") == (
        "https://[2001:db8::1]"
    )

    for value in (
        "https://user:secret@example.test",
        "https://example.test/path",
        "https://example.test?token=secret",
        "file:///tmp/collection",
    ):
        with pytest.raises(RequestCollectionContractError):
            canonical_collection_origin(value)


def test_named_selection_digest_is_deterministic_and_policy_bound():
    selector = RequestCollectionSelection.from_mapping({
        "folders": ["Admin", "Admin"],
        "methods": ["get", "post"],
        "tags": ["smoke"],
        "safe_methods_only": False,
        "max_requests": 25,
    })
    arguments = {
        "collection_id": "00000000-0000-4000-8000-000000000001",
        "payload_sha256": PAYLOAD_DIGEST,
        "binding_id": "00000000-0000-4000-8000-000000000002",
        "allowed_origins": ["https://api.example.test"],
        "selector": selector,
        "replay_policy": "confirmed_active",
        "environment_sha256": ENVIRONMENT_DIGEST,
    }

    first = request_collection_selection_digest(**arguments)
    second = request_collection_selection_digest(**arguments)

    assert first == second
    assert len(first) == 64
    assert selector.methods == ("GET", "POST")
    assert selector.folders == ("Admin",)
    assert "secret" not in selector.public_dict()

    with pytest.raises(RequestCollectionContractError, match="confirmed_active"):
        request_collection_selection_digest(
            **{**arguments, "replay_policy": "safe_reads"}
        )


def test_selection_contract_rejects_unbounded_or_unknown_inputs():
    with pytest.raises(RequestCollectionContractError, match="unsupported"):
        RequestCollectionSelection.from_mapping({"raw_document": {}})
    with pytest.raises(RequestCollectionContractError, match="between 1 and 2000"):
        RequestCollectionSelection(max_requests=2_001)
    with pytest.raises(RequestCollectionContractError, match="boolean"):
        RequestCollectionSelection.from_mapping({"safe_methods_only": "false"})
    with pytest.raises(RequestCollectionContractError, match="backtracking"):
        RequestCollectionSelection(path_regex="(a+)+$")
    with pytest.raises(RequestCollectionContractError, match="at most 32"):
        canonical_collection_origins([
            f"https://host-{index}.example.test" for index in range(33)
        ])


def test_safe_authentication_selection_requires_exact_disposable_posts():
    selector = RequestCollectionSelection(
        request_ids=("login-request",),
        methods=("POST",),
        safe_methods_only=False,
        max_requests=5,
        disposable_credentials=True,
    )
    arguments = {
        "collection_id": "00000000-0000-4000-8000-000000000001",
        "payload_sha256": PAYLOAD_DIGEST,
        "binding_id": "00000000-0000-4000-8000-000000000002",
        "allowed_origins": ["https://api.example.test"],
        "selector": selector,
        "replay_policy": "safe_authentication",
    }
    assert len(request_collection_selection_digest(**arguments)) == 64

    for replacement in (
        RequestCollectionSelection(methods=("POST",), safe_methods_only=False,
                                   max_requests=5, disposable_credentials=True),
        RequestCollectionSelection(request_ids=("login-request",), methods=("GET",),
                                   max_requests=5, disposable_credentials=True),
        RequestCollectionSelection(request_ids=("login-request",), methods=("POST",),
                                   safe_methods_only=False, max_requests=6,
                                   disposable_credentials=True),
        RequestCollectionSelection(request_ids=("login-request",), methods=("POST",),
                                   safe_methods_only=False, max_requests=5),
    ):
        with pytest.raises(RequestCollectionContractError, match="safe_authentication"):
            request_collection_selection_digest(**{**arguments, "selector": replacement})


def test_runtime_schema_is_installed_by_startup_and_new_database_init():
    root = Path(__file__).resolve().parents[1]
    init_sql = (root / "db" / "init.sql").read_text()
    migrations = (root / "api" / "retest_contract.py").read_text()
    for table in (
        "request_collection_environments",
        "request_collection_bindings",
        "request_collection_selections",
    ):
        assert f"CREATE TABLE {table}" in init_sql
    assert "PostgresRequestCollectionStore().ensure_schema(conn)" in migrations


def test_store_executes_one_idempotent_schema_bundle():
    class Connection:
        def __init__(self):
            self.queries = []

        async def execute(self, query):
            self.queries.append(query)

    conn = Connection()
    asyncio.run(PostgresRequestCollectionStore().ensure_schema(conn))

    assert len(conn.queries) == 1
    assert "CREATE TABLE IF NOT EXISTS request_collection_bindings" in conn.queries[0]
    assert "ON CONFLICT (collection_id, target_kind, target_id) DO NOTHING" in conn.queries[0]
    assert "DROP CONSTRAINT IF EXISTS request_collection_selections_name_unique" in conn.queries[0]
    assert "idx_request_collection_selections_current_name" in conn.queries[0]


def test_selection_replacement_keeps_revision_rows_instead_of_overwriting_digest():
    root = Path(__file__).resolve().parents[1]
    router = (root / "api" / "request_collection_api.py").read_text()
    worker = (root / "api" / "worker.py").read_text()

    assert "ON CONFLICT (binding_id, name) DO UPDATE" not in router
    assert "SET is_active=false, updated_at=NOW()" in router
    assert '"replaced_selection_id"' in router
    assert "AND s.binding_id=b.id AND s.is_active=true" not in worker
