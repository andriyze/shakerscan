from __future__ import annotations

import asyncio
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Mapping

import pytest


pytest.importorskip("asyncpg")
pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi import Request  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from api import api as api_module  # noqa: E402
from api.public_api_contract import (  # noqa: E402
    PUBLIC_V2_SURFACE_PREFIXES,
    PUBLIC_V2_WRITE_BODY_LIMITS,
    PublicV2BodyLimitMiddleware,
    PublicV2IdempotencyMiddleware,
    public_v2_surface,
    public_v2_write_body_limit,
    public_v2_write_paths,
)
from api.runtime.credentials import CREDENTIAL_KINDS  # noqa: E402
from scripts.generate_public_api_contract import (  # noqa: E402
    MANIFEST_OUTPUT,
    TYPES_OUTPUT,
    build_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
WRITE_METHODS = {"post", "put", "patch", "delete"}
EXPECTED_SURFACES = {
    "scan", "hunt", "credentials", "collections", "evidence", "model_intake",
}


def _request_schema(
    openapi: Mapping[str, Any], method: str, path: str,
) -> Mapping[str, Any] | None:
    operation = openapi["paths"][path][method.lower()]
    schema = (
        operation.get("requestBody", {})
        .get("content", {})
        .get("application/json", {})
        .get("schema")
    )
    if not isinstance(schema, Mapping):
        return None
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
        return openapi["components"]["schemas"][ref.rsplit("/", 1)[-1]]
    return schema


def _property_schema(
    openapi: Mapping[str, Any], method: str, path: str, name: str,
) -> Mapping[str, Any]:
    schema = _request_schema(openapi, method, path) or {}
    return schema["properties"][name]


def _enum_values(schema: Any) -> set[str]:
    values: set[str] = set()
    if isinstance(schema, Mapping):
        values.update(str(value) for value in schema.get("enum") or [])
        for keyword in ("anyOf", "oneOf", "allOf"):
            for child in schema.get(keyword) or []:
                values.update(_enum_values(child))
    return values


def test_generated_public_contract_and_types_match_current_openapi():
    result = subprocess.run(
        [sys.executable, "scripts/generate_public_api_contract.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    openapi = api_module.app.openapi()
    expected = build_manifest(openapi)
    stored = json.loads(MANIFEST_OUTPUT.read_text(encoding="utf-8"))
    generated = TYPES_OUTPUT.read_text(encoding="utf-8")

    assert stored == expected
    assert stored["operation_count"] == len(stored["operations"])
    assert stored["component_schema_count"] == len(stored["component_schema_sha256"])
    assert set(stored["surfaces"]) == EXPECTED_SURFACES
    assert len({item["operation_id"] for item in stored["operations"].values()}) == len(
        stored["operations"]
    )
    assert stored["contract_sha256"] in generated
    assert "PublicApiRequestByOperation" in generated
    assert "PublicApiResponseByOperation" in generated


def test_public_contract_uses_current_scan_and_hunt_discovery_routes():
    manifest = json.loads(MANIFEST_OUTPUT.read_text(encoding="utf-8"))
    assert "GET /scan/contracts" in manifest["surfaces"]["scan"]
    assert "GET /hunts/contract" in manifest["surfaces"]["hunt"]
    assert "GET /scan/contract" not in manifest["operations"]
    assert "GET /hunt/contracts" not in manifest["operations"]
    docs = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in ("AGENTS.md", "docs/functionality-reference.md", "docs/mcp.md")
    )
    assert "GET /scan/contracts" in docs
    assert "GET /hunts/contract" in docs


def test_every_release_critical_json_write_rejects_unknown_fields():
    openapi = api_module.app.openapi()
    checked: list[str] = []
    for path, path_item in openapi["paths"].items():
        if public_v2_surface(path) is None:
            continue
        for method in WRITE_METHODS.intersection(path_item):
            schema = _request_schema(openapi, method, path)
            if schema is None:
                continue
            key = f"{method.upper()} {path}"
            checked.append(key)
            assert schema.get("additionalProperties") is False, key
    assert checked
    assert set(PUBLIC_V2_SURFACE_PREFIXES) == EXPECTED_SURFACES


def test_scan_public_schema_excludes_stale_and_secret_bearing_options():
    openapi = api_module.app.openapi()
    for path in ("/scans", "/scans/batch"):
        schema = _request_schema(openapi, "post", path) or {}
        options = schema["$defs"]["ScanPublicCompatibilityOptions"]
        fields = set(options["properties"])
        assert fields == {
            "custom_endpoints", "require_current_workers", "placement", "parallel",
            "shards", "shard_strategy", "auth_state_shards",
        }
        assert not fields.intersection({
            "scan_type", "quick", "thorough", "active", "xss", "sqli",
            "exhaustive", "smart_bola_max_endpoints", "auth_header", "auth_cookies",
            "login_password", "ai_api_key", "user2_header",
        })
    assert "ScanOptions" not in openapi.get("components", {}).get("schemas", {})


def test_supported_credential_and_collection_enums_are_generated_from_server_models():
    openapi = api_module.app.openapi()
    auth_kind = _property_schema(openapi, "post", "/credential-profiles", "auth_kind")
    collection_format = _property_schema(openapi, "post", "/request-collections", "format")
    assert _enum_values(auth_kind) == set(CREDENTIAL_KINDS)
    assert _enum_values(collection_format) == {
        "auto", "postman_collection", "har", "openapi",
    }
    assert "postman" not in _enum_values(collection_format)


def test_every_release_critical_write_has_a_body_limit():
    openapi = api_module.app.openapi()
    writes = public_v2_write_paths(openapi)
    assert writes
    for key in writes:
        method, path = key.split(" ", 1)
        limit = public_v2_write_body_limit(method, path)
        assert limit == PUBLIC_V2_WRITE_BODY_LIMITS[public_v2_surface(path)], key


def test_every_release_critical_write_publishes_durable_retry_header():
    openapi = api_module.app.openapi()
    for key in public_v2_write_paths(openapi):
        method, path = key.split(" ", 1)
        parameters = openapi["paths"][path][method.lower()].get("parameters") or []
        header = next((
            item for item in parameters
            if item.get("in") == "header" and item.get("name") == "Idempotency-Key"
        ), None)
        assert header is not None, key
        assert header["required"] is False
        assert header["schema"]["minLength"] == 8
        assert header["schema"]["maxLength"] == 200


async def _run_body_limit_request(
    *, method: str, path: str, chunks: list[bytes], content_length: int | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    called = False

    async def app(_scope, _receive, send):
        nonlocal called
        called = True
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    messages = [
        {
            "type": "http.request",
            "body": chunk,
            "more_body": index < len(chunks) - 1,
        }
        for index, chunk in enumerate(chunks)
    ] or [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive():
        return messages.pop(0)

    sent: list[dict[str, Any]] = []

    async def send(message):
        sent.append(message)

    headers = []
    if content_length is not None:
        headers.append((b"content-length", str(content_length).encode("ascii")))
    await PublicV2BodyLimitMiddleware(app)(
        {"type": "http", "method": method, "path": path, "headers": headers},
        receive,
        send,
    )
    return sent, called


@pytest.mark.parametrize("surface", sorted(EXPECTED_SURFACES))
def test_body_limit_rejects_oversized_content_length_without_calling_endpoint(surface):
    prefix = PUBLIC_V2_SURFACE_PREFIXES[surface][0]
    limit = PUBLIC_V2_WRITE_BODY_LIMITS[surface]
    sent, called = asyncio.run(_run_body_limit_request(
        method="POST", path=prefix, chunks=[], content_length=limit + 1,
    ))
    assert called is False
    assert sent[0]["status"] == 413
    payload = json.loads(sent[1]["body"])
    assert payload == {
        "detail": {
            "error": "request_body_too_large",
            "message": "Request body exceeds the public API limit.",
            "max_bytes": limit,
        }
    }


def test_body_limit_enforces_streamed_bytes_without_content_length():
    limit = PUBLIC_V2_WRITE_BODY_LIMITS["hunt"]
    sent, called = asyncio.run(_run_body_limit_request(
        method="POST",
        path="/hunts",
        chunks=[b"a" * (limit // 2), b"b" * (limit // 2 + 1)],
    ))
    assert called is False
    assert sent[0]["status"] == 413


class _IdempotencyConnection:
    def __init__(self):
        self.rows: dict[tuple[str, str, str], dict[str, Any]] = {}

    async def fetchrow(self, query, *args):
        key = tuple(args[:3])
        if "INSERT INTO public_api_idempotency" in query:
            if key in self.rows:
                return None
            self.rows[key] = {
                "method": args[0], "path": args[1], "key_sha256": args[2],
                "request_sha256": args[3], "state": "processing",
            }
            return {"method": args[0]}
        if "SELECT * FROM public_api_idempotency" in query:
            return self.rows.get(key)
        if "updated_at <" in query:
            return None
        raise AssertionError(query)

    async def execute(self, query, *args):
        key = tuple(args[:3])
        if "UPDATE public_api_idempotency" in query:
            row = self.rows[key]
            row.update({
                "state": "completed",
                "response_status": args[4],
                "response_headers": json.loads(args[5]),
                "response_body": args[6],
            })
            return "UPDATE 1"
        if "DELETE FROM public_api_idempotency" in query:
            self.rows.pop(key, None)
            return "DELETE 1"
        raise AssertionError(query)


class _Acquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *_args):
        return False


class _IdempotencyPool:
    def __init__(self):
        self.conn = _IdempotencyConnection()

    def acquire(self):
        return _Acquire(self.conn)


async def _idempotency_exchange(middleware, app, body):
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return messages.pop(0)

    sent = []

    async def send(message):
        sent.append(message)

    await middleware({
        "type": "http", "method": "POST", "path": "/scans",
        "headers": [(b"idempotency-key", b"retry-scan-0001")],
        "app": app,
    }, receive, send)
    return sent


def test_public_write_idempotency_replays_exact_response_and_rejects_key_reuse():
    calls = 0

    async def endpoint(_scope, _receive, send):
        nonlocal calls
        calls += 1
        body = b'{"scan_id":"scan-1","status":"queued"}'
        await send({
            "type": "http.response.start", "status": 200,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({"type": "http.response.body", "body": body})

    app = SimpleNamespace(state=SimpleNamespace(db_pool=_IdempotencyPool()))
    middleware = PublicV2IdempotencyMiddleware(endpoint)
    first = asyncio.run(_idempotency_exchange(middleware, app, b'{"target":"a"}'))
    replay = asyncio.run(_idempotency_exchange(middleware, app, b'{"target":"a"}'))
    conflict = asyncio.run(_idempotency_exchange(middleware, app, b'{"target":"b"}'))

    assert calls == 1
    assert first[0]["status"] == replay[0]["status"] == 200
    assert first[1]["body"] == replay[1]["body"]
    assert (b"idempotency-replayed", b"true") in replay[0]["headers"]
    assert conflict[0]["status"] == 409
    assert json.loads(conflict[1]["body"])["detail"]["error"] == "idempotency_key_reused"


def test_secret_named_public_fields_are_limited_to_encrypted_credential_writes():
    openapi = api_module.app.openapi()
    sensitive_names = {
        "secret", "secondary_secret", "custom_headers", "username", "client_id",
    }
    occurrences: dict[str, set[str]] = {}
    for path, path_item in openapi["paths"].items():
        if public_v2_surface(path) is None:
            continue
        for method in WRITE_METHODS.intersection(path_item):
            schema = _request_schema(openapi, method, path) or {}
            names = sensitive_names.intersection((schema.get("properties") or {}).keys())
            if names:
                occurrences[f"{method.upper()} {path}"] = names
    assert occurrences == {
        "POST /credential-profiles": {
            "secret", "secondary_secret", "custom_headers", "username", "client_id",
        },
        "POST /credential-profiles/{profile_id}/rotate": {
            "secret", "secondary_secret", "custom_headers", "username", "client_id",
        },
    }


@pytest.mark.parametrize(
    "path",
    [
        "/scans", "/hunts", "/credential-profiles", "/request-collections",
        "/evidence/instances", "/model-intake/scan",
    ],
)
def test_public_validation_error_shape_never_echoes_rejected_input(path):
    secret_canary = "never-echo-public-contract-canary"
    try:
        api_module.ModelIntakeAutomaticReviewRequest.model_validate({
            "source": "acme/model",
            "unexpected": secret_canary,
        })
    except ValidationError as exc:
        validation_error = RequestValidationError(exc.errors())
    else:  # pragma: no cover - strictness regression makes the assertion clearer
        raise AssertionError("strict test request unexpectedly validated")
    request = Request({
        "type": "http",
        "method": "POST",
        "path": path,
        "query_string": b"",
        "headers": [],
        "server": ("test", 80),
        "client": ("test", 1234),
        "scheme": "http",
    })
    response = asyncio.run(
        api_module._request_validation_error_handler(request, validation_error)
    )
    payload = json.loads(response.body)
    assert response.status_code == 422
    assert secret_canary not in response.body.decode("utf-8")
    assert set(payload) == {"detail"}
    assert set(payload["detail"][0]) == {"type", "loc", "msg"}


def test_real_asgi_boundaries_reject_unknown_fields_without_secret_echo():
    canary = "asgi-contract-secret-canary"
    cases = {
        "/scans": {"target": "https://example.test", "unexpected": canary},
        "/hunts": {
            "target_id": "11111111-1111-4111-8111-111111111111",
            "target_kind": "web",
            "policy": {},
            "unexpected": canary,
        },
        "/credential-profiles": {
            "target_kind": "web",
            "target_id": "11111111-1111-4111-8111-111111111111",
            "name": "primary",
            "auth_kind": "bearer_token",
            "unexpected": canary,
        },
        "/request-collections": {
            "target_id": "11111111-1111-4111-8111-111111111111",
            "document": {},
            "unexpected": canary,
        },
        "/evidence/instances": {"unexpected": canary},
        "/model-intake/automatic-reviews": {
            "source": "acme/model",
            "unexpected": canary,
        },
    }

    async def exercise():
        transport = httpx.ASGITransport(app=api_module.app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver",
        ) as client:
            return {
                path: await client.post(path, json=payload)
                for path, payload in cases.items()
            }

    responses = asyncio.run(exercise())
    for path, response in responses.items():
        assert response.status_code == 422, (path, response.text)
        assert canary not in response.text
        detail = response.json()["detail"]
        if isinstance(detail, list):
            assert all(set(item) == {"type", "loc", "msg"} for item in detail)
        else:
            assert isinstance(detail, dict)
            assert detail.get("error") == "invalid_request_shape" or detail.get("message")


def test_retry_safe_public_actions_publish_bounded_idempotency_keys():
    openapi = api_module.app.openapi()
    hunt = _request_schema(
        openapi, "post", "/hunts/{hunt_id}/capabilities/{capability_name}",
    ) or {}
    promotion = _request_schema(
        openapi, "post", "/model-intake/submissions/{submission_id}/promote",
    ) or {}
    for schema, minimum in ((hunt, 8), (promotion, 16)):
        assert "idempotency_key" in schema.get("required", [])
        field = schema["properties"]["idempotency_key"]
        assert field["minLength"] == minimum
        assert field["maxLength"] == 200


def test_scan_and_hunt_invalid_json_errors_have_stable_machine_shapes():
    class _BodyRequest:
        async def body(self):
            return b"{not-json"

    for product, model in (("Scan", api_module.ScanRequest), ("Scan batch", api_module.BatchRequest)):
        with pytest.raises(api_module.HTTPException) as caught:
            asyncio.run(api_module._parse_public_json_model(
                _BodyRequest(), model, product=product,
            ))
        assert caught.value.status_code == 400
        assert caught.value.detail["error"] == "invalid_json"
        assert set(caught.value.detail) == {"error", "message"}
