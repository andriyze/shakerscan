"""
Unit tests for AI classifier resilience helpers (budget + circuit breaker).
"""

import asyncio
import json
import os
import sys
import time


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import ai_classifier  # noqa: E402


class _FakeAIResponse:
    def __init__(self, body, status=200):
        self.body = body
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def json(self, content_type=None):  # noqa: ARG002
        return self.body

    async def text(self):
        return json.dumps(self.body)


class _FakeAISession:
    def __init__(self, responses, **_kwargs):
        self.responses = responses

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def post(self, *_args, **_kwargs):
        response = self.responses.pop(0)
        if isinstance(response, tuple):
            status, body = response
            return _FakeAIResponse(body, status=status)
        return _FakeAIResponse(response)


def test_retryable_provider_error_detection():
    assert ai_classifier._is_retryable_provider_error(
        "Network error: ClientConnectionError: Connection closed"
    )
    assert ai_classifier._is_retryable_provider_error("AI provider timeout after 60s")
    assert ai_classifier._is_retryable_provider_error("HTTP 503: upstream unavailable")
    assert not ai_classifier._is_retryable_provider_error("Invalid JSON in response")


def test_provider_circuit_open_predicate():
    now = time.monotonic()
    assert ai_classifier._is_provider_circuit_open(now + 30, now)
    assert not ai_classifier._is_provider_circuit_open(now - 1, now)
    assert not ai_classifier._is_provider_circuit_open(None, now)


def test_provider_circuit_threshold_predicate():
    threshold = ai_classifier.AI_CLASSIFY_CIRCUIT_ERROR_THRESHOLD
    assert not ai_classifier._should_open_provider_circuit(max(0, threshold - 1))
    assert ai_classifier._should_open_provider_circuit(threshold)


def test_provider_circuit_opens_after_threshold_and_clears():
    ai_classifier._clear_provider_circuit_state()

    opened = False
    for _ in range(ai_classifier.AI_CLASSIFY_CIRCUIT_ERROR_THRESHOLD):
        opened, _count = ai_classifier._register_provider_circuit_failure(
            "Network error: ClientConnectionError: Connection closed"
        )

    state = ai_classifier._get_provider_circuit_state()
    assert opened
    assert state["is_open"] is True
    assert state["error_count"] >= ai_classifier.AI_CLASSIFY_CIRCUIT_ERROR_THRESHOLD

    ai_classifier._clear_provider_circuit_state()
    cleared = ai_classifier._get_provider_circuit_state()
    assert cleared["is_open"] is False
    assert cleared["error_count"] == 0


def test_provider_semantic_validator_retries_and_records_true_provenance(monkeypatch):
    responses = [
        {
            "choices": [{"message": {"content": json.dumps({"command": ""})}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
        },
        {
            "choices": [{"message": {"content": json.dumps({"command": "asm.gaps"})}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14},
        },
    ]

    class _Aiohttp:
        ClientTimeout = lambda **_kwargs: object()  # noqa: E731
        ClientError = OSError

        @staticmethod
        def ClientSession(**kwargs):
            return _FakeAISession(responses, **kwargs)

    async def no_sleep(_delay, _deadline):
        return True

    monkeypatch.setattr(ai_classifier, "aiohttp", _Aiohttp)
    monkeypatch.setattr(ai_classifier, "_sleep_with_budget", no_sleep)

    parsed, error, _latency = asyncio.run(ai_classifier.call_ai_provider(
        ai_url="https://provider.example/v1/chat/completions",
        ai_api_key="test-key",
        model="x-ai/grok-test",
        messages=[{"role": "user", "content": "return json"}],
        json_schema={"name": "probe", "schema": {"type": "object"}, "strict": True},
        response_validator=lambda value: None if value.get("command") else "command_required",
        use_circuit_breaker=False,
    ))

    assert error is None
    assert parsed["command"] == "asm.gaps"
    meta = parsed["_provider_meta"]
    assert meta["model_used"] == "x-ai/grok-test"
    assert meta["mode_used"] == "json_schema"
    assert meta["attempt_index"] == 1
    assert meta["schema_validated"] is True
    assert meta["usage"] == {"prompt_tokens": 21, "completion_tokens": 5, "total_tokens": 26}


def test_provider_failure_sink_records_cumulative_units_and_attempt_routes(monkeypatch):
    response = {
        "choices": [{"message": {"content": json.dumps({"command": ""})}}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
    }
    responses = [response.copy() for _ in range(6)]

    class _Aiohttp:
        ClientTimeout = lambda **_kwargs: object()  # noqa: E731
        ClientError = OSError

        @staticmethod
        def ClientSession(**kwargs):
            return _FakeAISession(responses, **kwargs)

    monkeypatch.setattr(ai_classifier, "aiohttp", _Aiohttp)
    monkeypatch.setattr(ai_classifier, "AI_RETRY_ATTEMPTS", 1)
    failure_meta = {"stale": True}

    parsed, error, _latency = asyncio.run(ai_classifier.call_ai_provider(
        ai_url="https://provider.example/v1/chat/completions",
        ai_api_key="test-key",
        model="primary-model",
        fallback_models=["fallback-model"],
        messages=[{"role": "user", "content": "return json"}],
        json_schema={"name": "probe", "schema": {"type": "object"}, "strict": True},
        response_validator=lambda _value: "command_required",
        use_circuit_breaker=False,
        failure_meta_sink=failure_meta,
    ))

    assert parsed is None
    assert "Semantic JSON contract rejected" in error
    assert "stale" not in failure_meta
    assert failure_meta["attempt_count"] == 6
    assert failure_meta["attempted_models"] == ["primary-model", "fallback-model"]
    assert failure_meta["attempted_modes"] == ["json_schema", "json_object", "none"]
    assert failure_meta["last_model_attempted"] == "fallback-model"
    assert failure_meta["last_mode_attempted"] == "none"
    assert failure_meta["planning_units_spent"] == 42
    assert failure_meta["usage"] == {
        "prompt_units": 30,
        "completion_units": 12,
        "total_units": 42,
    }
    assert len(failure_meta["errors"]) == 3

    def all_keys(value):
        if isinstance(value, dict):
            for key, nested in value.items():
                yield str(key)
                yield from all_keys(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from all_keys(nested)

    assert all("token" not in key.lower() for key in all_keys(failure_meta))


def test_provider_failure_sink_normalizes_anthropic_usage(monkeypatch):
    responses = [{
        "content": [{"type": "text", "text": json.dumps({"command": ""})}],
        "usage": {"input_tokens": 7, "output_tokens": 3},
    }]

    class _Aiohttp:
        ClientTimeout = lambda **_kwargs: object()  # noqa: E731
        ClientError = OSError

        @staticmethod
        def ClientSession(**kwargs):
            return _FakeAISession(responses, **kwargs)

    monkeypatch.setattr(ai_classifier, "aiohttp", _Aiohttp)
    monkeypatch.setattr(ai_classifier, "AI_RETRY_ATTEMPTS", 1)
    failure_meta = {}

    parsed, error, _latency = asyncio.run(ai_classifier.call_ai_provider(
        ai_url="https://api.anthropic.com/v1/messages",
        ai_api_key="test-key",
        model="claude-test",
        messages=[{"role": "user", "content": "return json"}],
        response_validator=lambda _value: "command_required",
        use_circuit_breaker=False,
        failure_meta_sink=failure_meta,
    ))

    assert parsed is None
    assert "Semantic JSON contract rejected" in error
    assert failure_meta["provider_kind"] == "anthropic_messages"
    assert failure_meta["attempted_modes"] == ["none"]
    assert failure_meta["planning_units_spent"] == 10
    assert failure_meta["usage"] == {
        "prompt_units": 7,
        "completion_units": 3,
        "total_units": 10,
    }


def test_provider_failure_sink_is_populated_on_early_configuration_error(monkeypatch):
    monkeypatch.setattr(ai_classifier, "aiohttp", object())
    failure_meta = {"stale": True}

    parsed, error, latency = asyncio.run(ai_classifier.call_ai_provider(
        ai_url="",
        ai_api_key="",
        model="configured-model",
        messages=[],
        failure_meta_sink=failure_meta,
    ))

    assert parsed is None
    assert error == "AI provider URL/API key not configured"
    assert latency is None
    assert failure_meta["model_requested"] == "configured-model"
    assert failure_meta["attempt_count"] == 0
    assert failure_meta["usage"]["total_units"] == 0
    assert failure_meta["planning_units_spent"] == 0
    assert failure_meta["errors"] == ["AI provider URL/API key not configured"]
    assert "stale" not in failure_meta


def test_provider_failure_sink_is_populated_on_definitive_auth_error(monkeypatch):
    responses = [(401, {"error": "invalid credential"})]

    class _Aiohttp:
        ClientTimeout = lambda **_kwargs: object()  # noqa: E731
        ClientError = OSError

        @staticmethod
        def ClientSession(**kwargs):
            return _FakeAISession(responses, **kwargs)

    monkeypatch.setattr(ai_classifier, "aiohttp", _Aiohttp)
    failure_meta = {}

    parsed, error, _latency = asyncio.run(ai_classifier.call_ai_provider(
        ai_url="https://provider.example/v1/chat/completions",
        ai_api_key="bad-key",
        model="primary-model",
        messages=[{"role": "user", "content": "return json"}],
        use_circuit_breaker=False,
        failure_meta_sink=failure_meta,
    ))

    assert parsed is None
    assert error.startswith("HTTP 401:")
    assert failure_meta["attempt_count"] == 1
    assert failure_meta["last_model_attempted"] == "primary-model"
    assert failure_meta["last_mode_attempted"] == "json_object"
    assert failure_meta["attempts"][0]["request_sent"] is True
    assert failure_meta["planning_units_spent"] == 0
    assert failure_meta["errors"] and failure_meta["errors"][0].startswith("HTTP 401:")
