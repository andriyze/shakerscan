import asyncio
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
    result = asyncio.run(experiment.execute_experiment(
        "https://example.test",
        {
            "steps": [
                {"label": "control", "method": "GET", "path": "/objects"},
                {"label": "mutation", "method": "GET", "path": "/objects/${missing}"},
            ]
        },
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
    ))

    assert result["observations"][1]["error"] == "variable_not_available:missing"
