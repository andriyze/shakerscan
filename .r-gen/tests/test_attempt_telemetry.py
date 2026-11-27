from scanner.scanner_tools.attempt_telemetry import (
    ENDPOINT_ATTEMPT_SCHEMA_V1,
    JWT_PROBE_ATTEMPT_SCHEMA_V1,
    normalize_endpoint_attempt,
    normalize_registry_attempt_telemetry,
)


def test_endpoint_attempt_requires_declared_schema():
    attempt = {"custom_endpoint": "GET /api/items?id=1", "status": "completed"}

    assert normalize_endpoint_attempt(attempt, schema_version=None) is None
    assert normalize_endpoint_attempt(attempt, schema_version="future_v9") is None


def test_endpoint_attempt_normalizes_partial_and_proof_facts():
    normalized = normalize_endpoint_attempt(
        {
            "custom_endpoint": "POST /api/items json:{\"id\":1}",
            "method": "post",
            "family": "SQLI",
            "status": "completed",
            "attempted_params_count": 3,
            "completed_params_count": 2,
            "proof_type": "differential_response",
        },
        schema_version=ENDPOINT_ATTEMPT_SCHEMA_V1,
    )

    assert normalized is not None
    assert normalized["status"] == "partial"
    assert normalized["method"] == "POST"
    assert normalized["proof_observed"] is True
    assert normalized["schema_version"] == ENDPOINT_ATTEMPT_SCHEMA_V1


def test_registry_attempt_rejects_schema_mismatch():
    assert normalize_registry_attempt_telemetry(
        {"schema_version": "jwt_probe_result_v1", "status": "completed"},
        expected_schema=JWT_PROBE_ATTEMPT_SCHEMA_V1,
    ) is None


def test_registry_attempt_degrades_incomplete_completion():
    normalized = normalize_registry_attempt_telemetry(
        {
            "schema_version": JWT_PROBE_ATTEMPT_SCHEMA_V1,
            "status": "completed",
            "attempted_count": 4,
            "completed_count": 3,
        },
        expected_schema=JWT_PROBE_ATTEMPT_SCHEMA_V1,
    )

    assert normalized is not None
    assert normalized["status"] == "partial"
