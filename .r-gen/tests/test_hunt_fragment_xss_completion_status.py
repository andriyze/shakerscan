from hunt.capability_executor import CapabilityAdapterResult
from hunt.fragment_xss_proof import _normalize_hunt_browser_xss_result


def _result(*, proof_state="not_proven", reasons=()):
    observations = [
        {
            "kind": "xss_browser_proof",
            "proof_state": proof_state,
        }
    ]
    observations.extend(
        {
            "kind": "browser_request_blocked",
            "reason": reason,
            "method": "GET",
            "url": "https://app.example.test/",
        }
        for reason in reasons
    )
    return CapabilityAdapterResult(
        status="success",
        observations=tuple(observations),
        actual_budget={"browser_actions": 2, "http_requests": 3},
        execution_started=True,
        parser_version="xss-browser-proof/v1",
    )


def test_verified_browser_xss_proof_stays_success_when_requests_were_blocked():
    result = _normalize_hunt_browser_xss_result(
        _result(
            proof_state="verified",
            reasons=("cross_origin", "request_budget_exhausted"),
        )
    )

    assert result.status == "success"
    assert result.partial is False
    assert result.errors == ()


def test_not_proven_with_only_cross_origin_blocks_is_complete():
    result = _normalize_hunt_browser_xss_result(
        _result(reasons=("cross_origin",))
    )

    assert result.status == "success"
    assert result.partial is False
    assert result.errors == ()


def test_not_proven_with_request_budget_exhaustion_is_partial():
    result = _normalize_hunt_browser_xss_result(
        _result(reasons=("cross_origin", "request_budget_exhausted"))
    )

    assert result.status == "partial"
    assert result.partial is True
    assert "browser_request_blocked:request_budget_exhausted" in result.errors


def test_not_proven_with_state_changing_request_is_partial():
    result = _normalize_hunt_browser_xss_result(
        _result(reasons=("state_changing_method",))
    )

    assert result.status == "partial"
    assert result.partial is True
    assert "browser_request_blocked:state_changing_method" in result.errors


def test_not_proven_with_cancelled_request_is_cancelled():
    result = _normalize_hunt_browser_xss_result(
        _result(reasons=("cancelled",))
    )

    assert result.status == "cancelled"
    assert result.partial is False
    assert "browser_request_blocked:cancelled" in result.errors
