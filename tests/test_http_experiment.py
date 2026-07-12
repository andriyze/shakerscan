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
