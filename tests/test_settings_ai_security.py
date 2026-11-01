"""Security properties of the AI settings routes.

- The connection probe never sends the saved provider key to a URL the caller chose.
- Saving settings has no path that writes the provider key (or anything else) to the host
  environment file.
- The automatic false-positive close cannot be configured below the 0.7 verdict bar.
"""

from __future__ import annotations

import inspect
import os
import re
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import retest_contract  # noqa: E402
import settings_routes.router as router_module  # noqa: E402
from settings_routes.router import AISettingsProbeRequest, AISettingsUpdate  # noqa: E402

STORED_URL = "https://provider.example/v1/chat/completions"
STORED_KEY = "stored-provider-key"


@pytest.fixture
def probe_calls(monkeypatch):
    calls: list[dict] = []

    async def fake_probe(**kwargs):
        calls.append(kwargs)
        return {"ok": True, "error": None, "latency_ms": 1, "provider_meta": {}, "response": None}

    monkeypatch.setitem(router_module._deps, "load_effective_ai_settings", lambda: {
        "ai_url": STORED_URL,
        "ai_api_key": STORED_KEY,
        "ai_model": "stored-model",
        "ai_model_fallback": "",
    })
    monkeypatch.setattr(router_module, "_probe_ai_provider", fake_probe)
    return calls


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router_module.router)
    return TestClient(app)


@pytest.mark.parametrize("scope", ["scan", "verify"])
def test_probe_of_a_new_url_without_a_key_is_refused(client, probe_calls, scope):
    response = client.post("/settings/ai/test", json={
        "scope": scope, "ai_url": "https://attacker.example/collect",
    })

    assert response.status_code == 400
    assert "key is required" in response.json()["detail"]
    assert probe_calls == []


@pytest.mark.parametrize("scope", ["scan", "verify", "research"])
def test_probe_of_a_new_url_with_an_empty_key_is_refused(client, probe_calls, scope):
    response = client.post("/settings/ai/test", json={
        "scope": scope, "ai_url": "https://attacker.example/collect", "ai_api_key": "  ",
    })

    assert response.status_code == 400
    assert probe_calls == []


def test_probe_of_a_new_url_uses_only_the_key_in_the_request(client, probe_calls):
    response = client.post("/settings/ai/test", json={
        "ai_url": "https://other-provider.example/v1", "ai_api_key": "request-key",
    })

    assert response.status_code == 200
    assert [(c["ai_url"], c["ai_api_key"]) for c in probe_calls] == [
        ("https://other-provider.example/v1", "request-key"),
    ]


@pytest.mark.parametrize("body", [{}, {"ai_url": STORED_URL}, {"ai_url": f"  {STORED_URL} "}])
def test_probe_of_the_saved_url_may_use_the_saved_key(client, probe_calls, body):
    response = client.post("/settings/ai/test", json=body)

    assert response.status_code == 200
    assert [(c["ai_url"], c["ai_api_key"]) for c in probe_calls] == [(STORED_URL, STORED_KEY)]


def test_saving_settings_has_no_environment_file_write_path(client):
    response = client.put("/settings/ai", json={"persist_to_env": True})

    assert response.status_code == 422
    assert "persist_to_env" not in AISettingsUpdate.model_fields
    for name in ("_persist_env_updates", "LOCAL_ENV_FILE", "_normalize_env_value"):
        assert not hasattr(router_module, name)
    source = inspect.getsource(router_module)
    assert not re.search(r"\.env\b|AI_API_KEY|write_text|\bopen\(", source)


def test_auto_fp_confidence_below_the_floor_is_refused_with_422(client):
    response = client.put("/settings/ai", json={"auto_fp_min_confidence": 0.5})

    assert response.status_code == 422
    with pytest.raises(ValidationError):
        AISettingsUpdate(auto_fp_min_confidence=0.69)
    assert AISettingsUpdate(auto_fp_min_confidence=0.7).auto_fp_min_confidence == 0.7


@pytest.mark.parametrize("stored", ["0.0", "0.5", "-1"])
def test_a_low_confidence_stored_earlier_or_in_the_environment_is_raised_to_the_floor(monkeypatch, stored):
    policy = retest_contract.VerificationPolicy.from_env(overrides={"auto_fp_min_confidence": stored})
    assert policy.auto_fp_min_confidence == 0.7

    monkeypatch.setenv("AUTO_FP_MIN_CONFIDENCE", stored)
    assert retest_contract.VerificationPolicy.from_env().auto_fp_min_confidence == 0.7


def test_probe_request_model_is_unchanged_for_callers():
    assert set(AISettingsProbeRequest.model_fields) == {
        "scope", "ai_url", "ai_api_key", "ai_model", "ai_fallback_model",
    }
