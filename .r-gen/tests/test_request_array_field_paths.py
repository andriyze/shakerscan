"""Imported array field names keep exact replay/proof on the intended JSON leaf."""
from __future__ import annotations

import asyncio
import json

import pytest

from api.capabilities.nosqli_verify import NoSQLiVerifyError, _json_body
from api.capabilities.request_mutation import (
    RequestMutationVerificationAdapter,
    RequestMutationVerificationError,
    mutate_private_request,
    replace_private_request_field,
)
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.request_shape import resolve_json_field_path
from scanner.scanner_tools.request_collections import _flatten_body_field_names
from tests.test_nosqli_verify_capability import _run as run_nosqli, _result
from tests.test_request_mutation_verifier import (
    ReflectingTransport, _candidate, _request, _target,
)
from tests.test_sqli_proof_capability import _run as run_sqli


DOCUMENT = {"items": [{"name": "seed", "id": 7}, {"name": "sibling", "id": 8}]}


@pytest.mark.parametrize(("field", "expected"), [
    ("items[].name", ("items", 0, "name")),
    ("items.0.name", ("items", 0, "name")),
    ("items.name", ("items", 0, "name")),
    ("items.1.name", ("items", 1, "name")),
])
def test_shared_resolver_maps_imported_and_exact_array_paths(field, expected):
    assert resolve_json_field_path(DOCUMENT, field) == expected
    assert resolve_json_field_path({"0": {"name": "value"}}, "0.name") == ("0", "name")


@pytest.mark.parametrize(("document", "field", "expected"), [
    ({"tags": ["seed", "sibling"]}, "tags[]", ("tags", 0)),
    ({"matrix": [[{"name": "seed"}]]}, "matrix[][].name", ("matrix", 0, 0, "name")),
    ([{"name": "seed"}], "[].name", (0, "name")),
])
def test_shared_resolver_handles_primitive_nested_and_root_arrays(document, field, expected):
    assert resolve_json_field_path(document, field) == expected


@pytest.mark.parametrize(("document", "field"), [
    ({"items": []}, "items[].name"),
    (DOCUMENT, "items.2.name"),
    (DOCUMENT, "items.-1.name"),
    (DOCUMENT, "items[].missing"),
    (DOCUMENT, "items..name"),
    ({"items": "scalar"}, "items[].name"),
])
def test_shared_resolver_rejects_nonexistent_paths_without_creating_nodes(document, field):
    before = json.dumps(document, sort_keys=True)
    with pytest.raises(ValueError):
        resolve_json_field_path(document, field)
    assert json.dumps(document, sort_keys=True) == before


@pytest.mark.parametrize("family", ["xss", "sqli"])
@pytest.mark.parametrize("field", ["items[].name", "items.0.name", "items.name"])
def test_request_mutation_and_proof_replacement_share_the_array_leaf(family, field):
    request = _request(body=json.dumps(DOCUMENT), content_type="application/json")
    changed, actual_field, marker, encoding = mutate_private_request(
        request, family=family, candidate_id="a" * 64, field_path=field,
    )
    expected = json.loads(request.body)
    expected["items"][0]["name"] = marker if family == "xss" else "seed'"
    assert json.loads(changed.body) == expected
    assert (actual_field, encoding) == (field, "json")

    proof_request, proof_encoding = replace_private_request_field(
        request, field_path=field, replacement="proof-payload",
    )
    expected["items"][0]["name"] = "proof-payload"
    assert json.loads(proof_request.body) == expected
    assert proof_encoding == "json"
    assert changed.headers == proof_request.headers == request.headers
    assert changed.url == proof_request.url == request.url
    assert json.loads(request.body) == DOCUMENT


def test_exact_index_changes_only_the_authorized_array_sibling():
    request = _request(body=json.dumps(DOCUMENT), content_type="application/json")
    changed, _encoding = replace_private_request_field(
        request, field_path="items.1.name", replacement="payload",
    )
    assert json.loads(changed.body) == {
        "items": [DOCUMENT["items"][0], {"name": "payload", "id": 8}],
    }


@pytest.mark.parametrize("field", ["items", "items[]", "items[].missing"])
def test_scalar_mutators_refuse_containers_and_missing_fields(field):
    request = _request(body=json.dumps(DOCUMENT), content_type="application/json")
    with pytest.raises(RequestMutationVerificationError):
        mutate_private_request(request, family="xss", candidate_id="a" * 64, field_path=field)
    with pytest.raises(RequestMutationVerificationError):
        replace_private_request_field(request, field_path=field, replacement="payload")


def test_nosqli_mutator_cannot_create_an_undeclared_missing_leaf():
    request = _request(body=json.dumps(DOCUMENT), content_type="application/json")
    with pytest.raises(NoSQLiVerifyError):
        _json_body(request, "items[].missing", {"$ne": "payload"})


def test_imported_array_field_executes_xss_request_verification():
    assert "items[].name" in _flatten_body_field_names(DOCUMENT)
    request = _request(body=json.dumps(DOCUMENT), content_type="application/json")
    transport = ReflectingTransport()
    spec = CAPABILITY_REGISTRY.require("xss.request_verify")
    adapter = RequestMutationVerificationAdapter(
        specification=spec, target=_target(), request=request,
        candidate={**_candidate(), "field_path": "items[].name"},
        transport=transport, requested_budget=dict(spec.budget_cost),
    )
    result = asyncio.run(adapter.execute(
        heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
    ))
    assert result.status == "success"
    assert result.observations[0]["proof_status"] == "reflected_candidate_only"
    assert result.actual_budget["http_requests"] == 2
    assert json.loads(transport.requests[1].body)["items"][1] == DOCUMENT["items"][1]


def test_imported_array_field_executes_repeated_sql_error_proof():
    class ErrorTransport:
        async def send(self, request, **_kwargs):
            value = json.loads(request.body)["items"][0]["name"]
            body = b"SQLITE_ERROR: near input: syntax error" if value.endswith("'") else b"ok"
            assert json.loads(request.body)["items"][1] == DOCUMENT["items"][1]
            return _result(500 if value.endswith("'") else 200, body)

    # The reference and exact wire request stay immutable across all four proofs.
    from tests.test_sqli_proof_capability import _request as sql_request
    request = sql_request(
        method="POST", url="https://app.example.test/search",
        body=json.dumps(DOCUMENT), content_type="application/json",
    )
    result = run_sqli(request, {
        "candidate_id": "a" * 64, "request_ref_id": "exact-request",
        "method": "POST", "field_path": "items[].name",
    }, ErrorTransport())
    assert result.observations[0]["proof_contract"] == "sqli_error_differential/v2"
    assert result.actual_budget["http_requests"] == 4
    assert json.loads(request.body) == DOCUMENT


def test_imported_array_field_executes_nosqli_semantic_proof():
    from tests.test_nosqli_verify_capability import _request as nosql_request

    class OperatorTransport:
        async def send(self, request, **_kwargs):
            document = json.loads(request.body)
            assert document["items"][1] == DOCUMENT["items"][1]
            value = document["items"][0]["name"]
            return _result(200, b'{"results":[1,2]}' if isinstance(value, dict) and "$ne" in value
                           else b'{"results":[]}')

    request = nosql_request(
        method="POST", url="https://app.example.test/search",
        body=json.dumps(DOCUMENT), content_type="application/json",
    )
    result = run_nosqli(request, {
        "candidate_id": "a" * 64, "request_ref_id": "exact-request",
        "method": "POST", "field_path": "items[].name", "request_class": "safe_read",
    }, OperatorTransport())
    assert result.status == "success"
    assert result.observations[0]["proof_state"] == "verified"
    assert result.actual_budget["http_requests"] == 4
    assert json.loads(request.body) == DOCUMENT
