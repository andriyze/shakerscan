"""GET /findings filters accept only the values findings carry.

``status`` was a free string matched literally: ``status=open`` answered ``total: 0`` with no
error while an active, verified critical finding existed. It, ``source_type`` and
``verification_verdict`` are enums now, in the schema and at runtime (422 naming the parameter,
the value sent and the accepted values). PATCH /findings/{id} stored any status string; it takes
the same set.
"""
from __future__ import annotations

import uuid

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from api import api as api_module  # noqa: E402

STATUSES = {"active", "resolved", "false_positive", "accepted_risk"}


def _enum_values(schema):
    values = set(schema.get("enum") or []) if isinstance(schema, dict) else set()
    if isinstance(schema, dict):
        for keyword in ("anyOf", "oneOf", "allOf"):
            for child in schema.get(keyword) or []:
                values.update(_enum_values(child))
        if "$ref" in schema:
            name = schema["$ref"].rsplit("/", 1)[-1]
            values.update(_enum_values(api_module.app.openapi()["components"]["schemas"][name]))
    return values


def _query_param(name):
    params = api_module.app.openapi()["paths"]["/findings"]["get"]["parameters"]
    return next(p for p in params if p["name"] == name)["schema"]


def test_the_findings_filters_publish_their_values():
    assert _enum_values(_query_param("status")) == STATUSES
    assert {"dast", "deep_hunt", "model_intake", "manual"} <= _enum_values(_query_param("source_type"))
    assert {"exploited", "false_positive", "inconclusive"} <= _enum_values(_query_param("verification_verdict"))


@pytest.mark.parametrize("query", ["status=open", "status=bogusvalue", "source_type=web", "verification_verdict=confirmed"])
def test_an_unknown_filter_value_is_refused_not_matched(query):
    response = TestClient(api_module.app).get(f"/findings?{query}")
    assert response.status_code == 422
    name, value = query.split("=")
    error = response.json()["detail"][0]
    assert error["loc"] == ["query", name]
    assert error["input"] == value
    if name == "status":
        assert all(f"'{status}'" in error["msg"] for status in STATUSES)


def test_a_finding_status_update_takes_only_the_known_statuses():
    response = TestClient(api_module.app).patch(f"/findings/{uuid.uuid4()}", json={"status": "open"})
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"][-1] == "status"
