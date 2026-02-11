"""
Unit tests for AI classifier resilience helpers (budget + circuit breaker).
"""

import os
import sys
import time


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import ai_classifier  # noqa: E402


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
