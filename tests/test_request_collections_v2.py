from __future__ import annotations

from pathlib import Path

import pytest

from scanner.scanner_tools.request_collections import (
    REQUEST_COLLECTION_AGENT_PREVIEW_MAX,
    REQUEST_COLLECTION_IMPORT_DEFAULT,
    REQUEST_COLLECTION_IMPORT_HARD_MAX,
    REQUEST_COLLECTION_PAGE_MAX,
    REQUEST_COLLECTION_REPLAY_DEFAULT,
    REQUEST_COLLECTION_REPLAY_HARD_MAX,
    RequestImportError,
    RequestSelector,
    page_index,
    select_requests,
    validate_and_index,
)


def _postman(count: int) -> dict:
    return {
        "info": {"name": "Scale fixture", "schema": "v2.1"},
        "item": [
            {
                "name": f"request-{index}",
                "request": {
                    "method": "GET" if index % 2 == 0 else "POST",
                    "url": f"https://api.example.test/items/{index}?token=secret-{index}",
                    "header": [
                        {"key": "Authorization", "value": f"Bearer secret-{index}"},
                        {"key": "X-Label", "value": f"visible-{index}"},
                    ],
                    "body": {"mode": "raw", "raw": f'{{"password":"secret-{index}"}}'},
                },
            }
            for index in range(count)
        ],
    }


def test_v2_limits_are_separate_and_bounded():
    assert REQUEST_COLLECTION_IMPORT_DEFAULT == 5_000
    assert REQUEST_COLLECTION_IMPORT_HARD_MAX == 20_000
    assert REQUEST_COLLECTION_REPLAY_DEFAULT == 500
    assert REQUEST_COLLECTION_REPLAY_HARD_MAX == 2_000
    assert REQUEST_COLLECTION_AGENT_PREVIEW_MAX == 200
    assert REQUEST_COLLECTION_PAGE_MAX == 500


def test_postman_5000_import_builds_redacted_paginated_index():
    payload, summary, rows = validate_and_index(_postman(5_000))

    assert payload["collection"]["item"][0]["request"]["header"][0]["value"] == "Bearer secret-0"
    assert summary["schema_version"] == "request-collection/v2"
    assert summary["request_count"] == 5_000
    assert len(rows) == 5_000
    serialized_row = repr(rows[0]).lower()
    assert "authorization" not in serialized_row
    assert "bearer" not in serialized_row
    assert "password" not in serialized_row
    assert "secret-0" not in serialized_row

    first = page_index(rows, offset=0, limit=500)
    last = page_index(rows, offset=4_500, limit=500)
    assert first["count"] == 500 and first["next_offset"] == 500
    assert last["count"] == 500 and last["next_offset"] is None


def test_default_import_rejects_over_5000_but_explicit_hard_limit_accepts_boundary():
    fixture = _postman(5_001)
    with pytest.raises(RequestImportError, match="5000-request limit"):
        validate_and_index(fixture)

    _payload, summary, rows = validate_and_index(fixture, import_limit=20_000)
    assert summary["request_count"] == 5_001
    assert len(rows) == 5_001

    with pytest.raises(RequestImportError, match="import_limit"):
        validate_and_index(_postman(1), import_limit=20_001)


def test_selector_defaults_to_safe_reads_and_never_returns_more_than_replay_limit():
    payload, _summary, rows = validate_and_index(_postman(20))
    selected = select_requests(
        payload,
        RequestSelector(
            methods=("GET", "POST"), path_regex=r"/items/(?:1[0-9]|[0-9])", limit=20
        ),
    )
    assert len(selected) == 10
    assert {row["method"] for row in selected} == {"GET"}
    assert all("Authorization" in row["headers"] for row in selected)

    post_id = next(row["request_id"] for row in rows if row["method"] == "POST")
    writes = select_requests(
        payload, RequestSelector(request_ids=(post_id,), safe_methods_only=False, limit=1)
    )
    assert len(writes) == 1 and writes[0]["method"] == "POST"

    with pytest.raises(ValueError):
        RequestSelector(limit=REQUEST_COLLECTION_REPLAY_HARD_MAX + 1)


def test_page_and_regex_guards_fail_closed():
    with pytest.raises(ValueError):
        page_index([], limit=REQUEST_COLLECTION_PAGE_MAX + 1)
    with pytest.raises(ValueError):
        RequestSelector(path_regex="(")
    with pytest.raises(ValueError, match="backtracking"):
        RequestSelector(path_regex=r"(a+)+$")


def test_generic_storage_and_scan_hunt_api_contracts_are_wired():
    root = Path(__file__).resolve().parents[1]
    schema = (root / "db" / "init.sql").read_text()
    api = (root / "api" / "api.py").read_text()

    assert "CREATE TABLE request_collections" in schema
    assert "CREATE TABLE request_collection_requests" in schema
    assert 'app.post("/request-collections")' in api
    assert 'app.get("/request-collections/{collection_id}/requests")' in api
    assert 'app.post("/request-collections/{collection_id}/select")' in api
    assert "collection_refs, collection_endpoints = await _generic_collection_refs" in api
    assert "secret_values_visible" in api
