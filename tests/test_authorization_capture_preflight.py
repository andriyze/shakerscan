"""Failed captures must not become expensive authorization experiments.

The service calls supported_capture for both object and baseline, during proposal
creation and again before admission. These tests exercise that shared preflight;
they make no claim about listing completeness, deployed workers or efficacy.
"""
from __future__ import annotations

import pytest

from api.hunt.authorization_evidence import AuthorizationWorkflowError, supported_capture

ORIGIN = "https://app.example.test"


def capture(path="/orders", **overrides):
    result = {"method": "GET", "url": ORIGIN + path, "request_body_bytes": 0,
              "status_code": 200, "error": None, "truncated": False}
    result.update(overrides)
    return result


@pytest.mark.parametrize("path", ["/orders", "/orders/1001"])
@pytest.mark.parametrize("status", [0, 199, 301, 302, 304, 400, 401, 403, 404, 429, 500, 503])
def test_failed_baseline_or_object_cannot_enter_the_listing_workflow(path, status):
    with pytest.raises(AuthorizationWorkflowError, match=f"HTTP {status}") as caught:
        supported_capture(capture(path, status_code=status), [ORIGIN])
    assert caught.value.status_code == 422
    assert "requires a successful baseline" in str(caught.value)


@pytest.mark.parametrize("status", [None, True, False, "200", 200.0])
def test_missing_or_malformed_status_is_not_success(status):
    with pytest.raises(AuthorizationWorkflowError, match="no valid HTTP status"):
        supported_capture(capture(status_code=status), [ORIGIN])


@pytest.mark.parametrize("status", [204, 205, 206])
def test_empty_or_partial_status_cannot_establish_a_baseline(status):
    with pytest.raises(AuthorizationWorkflowError, match="empty, partial"):
        supported_capture(capture(status_code=status), [ORIGIN])


@pytest.mark.parametrize("flag", [True, 1, None, "false"])
def test_truncated_or_unknown_completeness_is_not_evidence(flag):
    with pytest.raises(AuthorizationWorkflowError, match="completeness is unknown"):
        supported_capture(capture(truncated=flag), [ORIGIN])


def test_transport_error_is_rejected_without_echoing_sensitive_error_text():
    with pytest.raises(AuthorizationWorkflowError, match="transport error") as caught:
        supported_capture(capture(error="timeout at /reset?token=DO_NOT_ECHO"), [ORIGIN])
    assert "DO_NOT_ECHO" not in str(caught.value)
    assert "timeout at" not in str(caught.value)


@pytest.mark.parametrize("flag", [False, 0])
def test_successful_capture_keeps_its_exact_request_identity(flag):
    # bool is returned by PostgreSQL; the existing SQLite fixture returns int.
    assert supported_capture(capture("/orders/1001/", truncated=flag), [ORIGIN]) == "/orders/1001/"


def test_successful_status_does_not_claim_a_valid_listing_or_authorization():
    # Metadata preflight cannot distinguish a 200 SPA shell from a listing.
    # It returns the path, not real=true, listing_complete=true or verified=true.
    assert supported_capture(capture("/unknown-shape"), [ORIGIN]) == "/unknown-shape"


@pytest.mark.parametrize("overrides, expected", [
    ({"method": "DELETE"}, "body-free GET"),
    ({"request_body_bytes": 10}, "body-free GET"),
    ({"url": "https://other.example.test/orders"}, "frozen origins"),
    ({"url": ORIGIN + "/orders?token=secret"}, "Query, fragment"),
    ({"url": ORIGIN + "/orders#detail"}, "Query, fragment"),
])
def test_existing_request_and_scope_guards_remain(overrides, expected):
    with pytest.raises(AuthorizationWorkflowError, match=expected):
        supported_capture(capture(**overrides), [ORIGIN])
