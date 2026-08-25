from __future__ import annotations

from pathlib import Path
import sys
import uuid

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

import request_collection_api  # noqa: E402


def test_request_collection_routes_are_owned_by_extracted_router():
    source = (ROOT / "api" / "request_collection_api.py").read_text(
        encoding="utf-8"
    )
    routes = {
        '@router.post("/request-collections")',
        '@router.get("/request-collections")',
        '@router.get("/request-collections/{collection_id}/requests")',
        '@router.post("/request-collections/{collection_id}/select")',
        '@router.get("/request-collections/{collection_id}")',
        '@router.post("/request-collections/{collection_id}/environments")',
        '@router.delete("/request-collections/{collection_id}/environments/{environment_id}")',
        '@router.post("/request-collections/{collection_id}/bindings")',
        '@router.post("/request-collections/{collection_id}/selections")',
        '@router.delete("/request-collections/{collection_id}/selections/{selection_id}")',
    }
    assert all(route in source for route in routes)


def test_request_collection_router_is_not_a_monolith_wrapper():
    source = (ROOT / "api" / "request_collection_api.py").read_text(
        encoding="utf-8"
    )
    primary = (ROOT / "api" / "api.py").read_text(encoding="utf-8")

    assert "import api" not in source
    assert "from api import" not in source
    assert "@app." not in source
    assert "@router.post(\"/request-collections\")" in source
    assert "app.include_router(request_collection_router)" in primary
    assert "@app.post(\"/request-collections\")" not in primary


def test_collection_models_reject_unknown_and_secret_shaped_fields():
    with pytest.raises(ValidationError):
        request_collection_api.RequestCollectionCreate.model_validate({
            "target_id": str(uuid.uuid4()),
            "document": {"item": []},
            "raw_secret": "must not enter a collection contract",
        })


def test_collection_binding_is_exact_target_bound():
    target_id = uuid.uuid4()
    collection = {
        "target_id": target_id,
        "device_target_id": None,
        "target_url": "https://api.example.test/root",
    }

    assert request_collection_api._request_collection_owner_binding(
        collection,
        target_kind="api",
        target_id=target_id,
        allowed_origins=["HTTPS://API.EXAMPLE.TEST:443"],
    ) == ("https://api.example.test",)
    with pytest.raises(request_collection_api.HTTPException) as error:
        request_collection_api._request_collection_owner_binding(
            collection,
            target_kind="api",
            target_id=target_id,
            allowed_origins=["https://outside.example.test"],
        )
    assert error.value.status_code == 422
