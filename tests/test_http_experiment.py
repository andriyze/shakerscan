import asyncio
import json
import sys
from pathlib import Path

import httpx
import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import http_experiment as experiment  # noqa: E402


def _payload(**step_overrides):
    mutation = {"label": "mutation", "method": "GET", "path": "/api/items", "query": {"id": "2"}}
    mutation.update(step_overrides)
    return {
        "objective": "Compare object responses",
        "expected_signal": "Object shape changes",
        "falsifier": "Responses are equivalent",
        "steps": [
            {"label": "control", "method": "GET", "path": "/api/items", "query": {"id": "1"}},
            mutation,
        ],
    }


def test_normalize_experiment_accepts_bounded_same_origin_steps():
    normalized = experiment.normalize_experiment("https://example.test/base", _payload())

    assert normalized["steps"][0]["url"] == "https://example.test/api/items"
    assert normalized["timeout_seconds"] == 10


@pytest.mark.parametrize("path", ["https://other.test/x", "//other.test/x", "relative/path"])
def test_normalize_experiment_rejects_non_relative_paths(path):
    with pytest.raises(experiment.ExperimentContractError):
        experiment.normalize_experiment("https://example.test", _payload(path=path))


@pytest.mark.parametrize("header", ["Authorization", "Cookie", "Host", "X-API-Key"])
def test_normalize_experiment_rejects_model_supplied_credentials(header):
    with pytest.raises(experiment.ExperimentContractError, match="header_forbidden"):
        experiment.normalize_experiment("https://example.test", _payload(headers={header: "secret"}))


def test_normalize_experiment_rejects_header_control_characters():
    with pytest.raises(experiment.ExperimentContractError, match="control_character"):
        experiment.normalize_experiment("https://example.test", _payload(headers={"X-Test": "ok\r\nHost: other"}))


def test_compare_summaries_reports_structural_deltas():
    result = experiment.compare_summaries(
        {"status": 403, "content_length": 10, "body_sha256": "a", "body_sample": "denied", "json_keys": ["error"]},
        {"status": 200, "content_length": 20, "body_sha256": "b", "body_sample": "allowed", "json_keys": ["id"]},
    )

    assert result["status_changed"] is True
    assert result["length_delta"] == 10
    assert result["json_keys_added"] == ["id"]
    assert result["json_keys_removed"] == ["error"]


def test_response_summary_redacts_common_secret_fields():
    request = httpx.Request("GET", "https://example.test")
    response = httpx.Response(200, headers={"content-type": "application/json"}, request=request)
    summary = experiment.response_summary(response, b'{"token":"abc123","id":7}')

    assert "abc123" not in summary["body_sample"]
    assert summary["json_keys"] == ["id", "token"]


def test_normalize_experiment_supports_form_extract_and_selected_fields():
    payload = _payload(
        method="POST",
        form_body={"object_id": "${resource_id}"},
        extract=[{"name": "next_id", "source": "json", "path": "$.data.id"}],
        select_json=["$.data.owner"],
        select_headers=["etag"],
        role="verify",
        compare_to="control",
    )
    payload["steps"][0]["extract"] = [{"name": "resource_id", "source": "json", "path": "$.data.id"}]

    normalized = experiment.normalize_experiment("https://example.test", payload)

    assert normalized["steps"][1]["form_body"] == {"object_id": "${resource_id}"}
    assert normalized["steps"][1]["extract"][0]["name"] == "next_id"
    assert normalized["steps"][1]["role"] == "verify"


def test_normalize_experiment_rejects_sensitive_extraction():
    with pytest.raises(experiment.ExperimentContractError, match="sensitive_value_forbidden"):
        experiment.normalize_experiment(
            "https://example.test",
            _payload(extract=[{"name": "access_token", "source": "json", "path": "$.token"}]),
        )


def test_execute_experiment_chains_extracted_resource_and_compares_selected_values():
    seen = []

    def handler(request: httpx.Request):
        seen.append(str(request.url))
        if request.url.path == "/objects":
            return httpx.Response(200, json={"data": {"id": 7, "owner": "user1"}}, headers={"etag": "a"})
        return httpx.Response(200, json={"data": {"id": 7, "owner": "user2"}}, headers={"etag": "b"})

    payload = {
        "steps": [
            {
                "label": "control",
                "method": "GET",
                "path": "/objects",
                "extract": [{"name": "resource_id", "source": "json", "path": "$.data.id"}],
                "select_json": ["$.data.owner"],
                "select_headers": ["etag"],
            },
            {
                "label": "verify",
                "role": "verify",
                "method": "GET",
                "path": "/objects/${resource_id}",
                "select_json": ["$.data.owner"],
                "select_headers": ["etag"],
            },
        ]
    }

    result = asyncio.run(experiment.execute_experiment(
        "https://example.test", payload, transport=httpx.MockTransport(handler)
    ))

    assert seen[1].endswith("/objects/7")
    assert result["variable_names"] == ["resource_id"]
    assert result["comparisons"][0]["side_effect_check"] is True
    assert result["comparisons"][0]["selected_json_changed"] == {"$.data.owner": ["user1", "user2"]}
    assert result["comparisons"][0]["selected_headers_changed"] == {"etag": ["a", "b"]}
    assert isinstance(result["observations"][0]["response"]["elapsed_ms"], int)


def test_execute_experiment_fails_closed_on_missing_variable():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={})

    with pytest.raises(experiment.ExperimentContractError, match="variable_not_declared:missing"):
        asyncio.run(experiment.execute_experiment(
            "https://example.test",
            {
                "steps": [
                    {"label": "control", "method": "GET", "path": "/objects"},
                    {"label": "mutation", "method": "GET", "path": "/objects/${missing}"},
                ]
            },
            transport=httpx.MockTransport(handler),
        ))

    assert calls == []


def test_normalize_experiment_rejects_duplicate_extract_names_before_requests():
    payload = _payload()
    payload["steps"][0]["extract"] = [{"name": "resource_id", "source": "json", "path": "$.id"}]
    payload["steps"][1]["extract"] = [{"name": "resource_id", "source": "header", "header": "etag"}]

    with pytest.raises(experiment.ExperimentContractError, match="extract_name_ambiguous"):
        experiment.normalize_experiment("https://example.test", payload)


@pytest.mark.parametrize("field,value", [
    ("query", {"filter": {"nested": "no"}}),
    ("form_body", {"field": {"nested": "no"}}),
])
def test_normalize_experiment_rejects_non_scalar_query_and_form_values(field, value):
    overrides = {field: value}
    if field == "form_body":
        overrides["method"] = "POST"
    with pytest.raises(experiment.ExperimentContractError, match="value_must_be_scalar"):
        experiment.normalize_experiment("https://example.test", _payload(**overrides))


def test_execute_experiment_redacts_extracted_values_and_counts_wire_attempts():
    payload = {
        "steps": [
            {
                "label": "control",
                "method": "GET",
                "path": "/objects",
                "extract": [{"name": "resource_id", "source": "json", "path": "$.id"}],
            },
            {"label": "mutation", "method": "GET", "path": "/objects/${resource_id}"},
        ]
    }
    result = asyncio.run(experiment.execute_experiment(
        "https://example.test",
        payload,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"id": "private-object-7"})),
    ))

    extracted = result["observations"][0]["extracted"]["resource_id"]
    assert "private-object-7" not in str(extracted)
    assert extracted["length"] == len("private-object-7")
    assert result["request_count"] == 2


def test_compare_summaries_marks_failed_steps_non_comparable():
    result = experiment.compare_summaries({}, {"status": 200, "body_sha256": "ok"})

    assert result["comparable"] is False
    assert result["status_changed"] is None
    assert result["body_changed"] is None


def test_response_summary_marks_stream_prefix_digest_scope():
    request = httpx.Request("GET", "https://example.test")
    response = httpx.Response(200, headers={"content-length": str(experiment.MAX_BODY_BYTES + 100)}, request=request)
    body = b"a" * (experiment.MAX_BODY_BYTES + 1)

    summary = experiment.response_summary(response, body)

    assert summary["truncated"] is True
    assert summary["content_length"] == experiment.MAX_BODY_BYTES
    assert summary["bytes_observed"] == experiment.MAX_BODY_BYTES + 1
    assert summary["content_length_header"] == experiment.MAX_BODY_BYTES + 100
    assert summary["body_digest_scope"] == "prefix"


def test_execute_experiment_caps_response_while_streaming_and_closes_stream():
    class CountingStream(httpx.AsyncByteStream):
        def __init__(self):
            self.yielded = 0
            self.closed = False

        async def __aiter__(self):
            for _ in range(20):
                self.yielded += 1
                yield b"x" * 10_000

        async def aclose(self):
            self.closed = True

    streams = []

    def handler(request):
        stream = CountingStream()
        streams.append(stream)
        return httpx.Response(200, stream=stream)

    result = asyncio.run(experiment.execute_experiment(
        "https://example.test",
        _payload(),
        transport=httpx.MockTransport(handler),
    ))

    assert all(stream.yielded == 4 for stream in streams)
    assert all(stream.closed for stream in streams)
    assert all(item["response"]["truncated"] for item in result["observations"])
    assert all(item["response"]["bytes_observed"] == experiment.MAX_BODY_BYTES + 1 for item in result["observations"])


def test_execute_experiment_sends_json_and_chained_form_bodies():
    seen = []

    def handler(request):
        seen.append((request.headers.get("content-type"), request.content))
        return httpx.Response(200, json={"data": {"id": 9}})

    result = asyncio.run(experiment.execute_experiment(
        "https://example.test",
        {
            "steps": [
                {
                    "label": "control",
                    "method": "POST",
                    "path": "/objects",
                    "json_body": {"name": "control"},
                    "extract": [{"name": "resource_id", "source": "json", "path": "$.data.id"}],
                },
                {
                    "label": "mutation",
                    "method": "POST",
                    "path": "/objects/update",
                    "form_body": {"object_id": "${resource_id}", "state": "reviewed"},
                },
            ]
        },
        transport=httpx.MockTransport(handler),
    ))

    assert seen[0][0] == "application/json"
    assert json.loads(seen[0][1]) == {"name": "control"}
    assert seen[1][0] == "application/x-www-form-urlencoded"
    assert seen[1][1] in {b"object_id=9&state=reviewed", b"state=reviewed&object_id=9"}
    assert result["observations"][1]["request"]["body_kind"] == "form"


def test_failed_multi_extract_does_not_publish_partial_variables():
    result = asyncio.run(experiment.execute_experiment(
        "https://example.test",
        {
            "steps": [
                {
                    "label": "control",
                    "method": "GET",
                    "path": "/objects",
                    "extract": [
                        {"name": "resource_id", "source": "json", "path": "$.id"},
                        {"name": "revision", "source": "json", "path": "$.revision"},
                    ],
                },
                {"label": "mutation", "method": "GET", "path": "/objects/${resource_id}"},
            ]
        },
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"id": 7})),
    ))

    assert result["request_count"] == 1
    assert result["variable_names"] == []
    assert result["observations"][0]["response"]["status"] == 200
    assert result["observations"][0]["error"] == "extract_path_missing:$.revision"
    assert result["observations"][1]["error"] == "variable_not_available:resource_id"
    assert result["comparisons"][0]["comparable"] is False


def test_rendered_header_name_cannot_become_credential_header():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"field": "Authorization"})

    result = asyncio.run(experiment.execute_experiment(
        "https://example.test",
        {
            "steps": [
                {
                    "label": "control",
                    "method": "GET",
                    "path": "/field",
                    "extract": [{"name": "field_name", "source": "json", "path": "$.field"}],
                },
                {
                    "label": "mutation",
                    "method": "GET",
                    "path": "/objects",
                    "headers": {"${field_name}": "model-supplied-value"},
                },
            ]
        },
        transport=httpx.MockTransport(handler),
    ))

    assert len(calls) == 1
    assert result["observations"][1]["error"] == "rendered_header_forbidden:authorization"


@pytest.mark.parametrize("override,error", [
    ({"json_body": {"access_token": "value"}, "method": "POST"}, "json_body_sensitive_key_forbidden"),
    ({"form_body": {"password": "value"}, "method": "POST"}, "form_body_sensitive_key_forbidden"),
    ({"query": {"api_key": "value"}}, "query_sensitive_key_forbidden"),
    ({"select_json": ["$.data.password"]}, "selected_json_sensitive_value_forbidden"),
    ({"select_headers": ["x-auth-token"]}, "selected_header_forbidden"),
])
def test_normalize_experiment_rejects_sensitive_request_and_selected_fields(override, error):
    with pytest.raises(experiment.ExperimentContractError, match=error):
        experiment.normalize_experiment("https://example.test", _payload(**override))
