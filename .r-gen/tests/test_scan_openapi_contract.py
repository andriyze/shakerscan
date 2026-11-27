from __future__ import annotations

import pytest


pytest.importorskip("asyncpg")
pytest.importorskip("fastapi")

from api import api as api_module  # noqa: E402
from api.scan.contracts import public_scan_contract  # noqa: E402


def _enum_values(schema):
    values = set(schema.get("enum") or []) if isinstance(schema, dict) else set()
    if isinstance(schema, dict):
        for keyword in ("anyOf", "oneOf", "allOf"):
            for child in schema.get(keyword) or []:
                values.update(_enum_values(child))
    return values


def test_scan_openapi_budget_enums_match_public_contract_and_cli():
    expected = set(public_scan_contract()["budget_profiles"])
    openapi = api_module.app.openapi()

    for path in ("/scans", "/scans/batch"):
        schema = openapi["paths"][path]["post"]["requestBody"]["content"]["application/json"]["schema"]
        profile = schema["properties"]["budget_profile"]
        assert _enum_values(profile) == expected

    assert "ScanOptions" not in openapi["components"]["schemas"]
    assert "exhaustive" not in str(openapi)
