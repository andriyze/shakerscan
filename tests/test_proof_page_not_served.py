"""A proof whose page the service did not serve is no verdict (unit and integration fixtures).

The Scan's browser XSS proof recorded "not proven", a completed attempt, when the service
answered the proof's own navigation with HTTP 503: the payload never reached the page it tests,
the XSS family read complete with a reliable grade, and the reflection only the proof can promote
was dropped. The SQL injection proof did the same when its control and payloads met a service
that was down, rate-limiting or no longer serving the route. The retest of a proven finding
already read such answers as the service's (inconclusive, "the target was unavailable"); the
Scan's proofs now apply the same rule (``auth_refusal.unavailable_status``): one answer of 408,
429, 502, 503 or 504, or a missing page or server error on every answer, leaves the attempt
partial with ``target_unavailable:<status>``, its candidate unresolved and its family partial.
A page that loaded and did not run the payload is still "not proven".

Unit fixtures: a fake Playwright page (``tests.test_xss_proof_fidelity``) and a fake replay
transport stand in for the target, and the adapters are the real ones. Not a live Scan; the same
answers through the Scan's batches, result settlement and family coverage are in
``test_proof_page_not_served_scan.py``.
"""
from __future__ import annotations

import asyncio
import json
import sys
import urllib.parse

import pytest

from api.capabilities.browser import XSSBrowserProofAdapter
from api.capabilities.sqli_proof import SQLiProofAdapter
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.request_replay_executor import ReplayTransportResult
from api.scan.capability_result import CapabilityResultReason as Reason
from tests.test_sqli_proof_capability import _request, _target
from tests.test_xss_proof_fidelity import _install_fake_browser, _noop, _proof, _query_proof

# Answers that say the service decided (it timed the request out, asked for fewer requests, was
# down), and a missing page or a server error, which on a proof's only navigation is every answer.
NOT_SERVED = (404, 408, 410, 429, 500, 502, 503, 504)
NEVER_FIRES = "a-marker-that-never-fires"


@pytest.fixture(autouse=True)
def _no_settle(monkeypatch):
    """The proof's 1.5-second settle after the page loads, which these fixtures do not need."""
    monkeypatch.setattr("api.capabilities.browser.XSS_PROOF_SETTLE_SECONDS", 0)


def _browser_proof(monkeypatch, *, runs=False, marker=None, **page_kwargs):
    prepared = _query_proof()
    page, _seen = _install_fake_browser(monkeypatch, requires_auth=False, **page_kwargs)
    page.marker = marker if marker is not None else prepared.marker if runs else NEVER_FIRES
    return asyncio.run(XSSBrowserProofAdapter(prepared).execute(
        heartbeat=_noop, cancelled=lambda: False,
    ))


def _navigation(result):
    return next(item for item in result.observations if item.get("kind") == "browser_navigation")


# --- the browser XSS proof -----------------------------------------------------------------------


@pytest.mark.parametrize("status", NOT_SERVED)
def test_a_proof_page_the_service_did_not_serve_is_an_unresolved_attempt(monkeypatch, status):
    result = _browser_proof(monkeypatch, status=status)

    assert result.status == "partial" and result.partial is True
    assert result.errors == (f"target_unavailable:{status}",)
    assert _navigation(result)["status_code"] == status
    proof = _proof(result)
    assert proof["proof_state"] == "not_proven"
    assert proof["inconclusive_reason"] == "target_unavailable"


def test_a_navigation_answered_with_nothing_is_an_unresolved_attempt(monkeypatch):
    result = _browser_proof(monkeypatch, answer=False)

    assert result.status == "partial"
    assert result.errors == ("target_unavailable:0",)
    assert _navigation(result)["status_code"] is None
    assert _proof(result)["inconclusive_reason"] == "target_unavailable"


@pytest.mark.parametrize("status", [200, 201, 204, 299])
def test_a_page_that_loaded_and_did_not_run_the_payload_is_still_not_proven(monkeypatch, status):
    result = _browser_proof(monkeypatch, status=status)

    assert result.status == "success" and result.partial is False
    assert result.errors == ()
    proof = _proof(result)
    assert (proof["proof_state"], proof["finding_verdict"]) == ("not_proven", "not_proven")
    assert "inconclusive_reason" not in proof


@pytest.mark.parametrize("status", [400, 405, 422])
def test_the_applications_own_answer_to_the_payload_is_still_not_proven(monkeypatch, status):
    """A route that answers the payload with a client error rejected that input: as in the retest
    (a control answered, payloads met a client error), that is the application's answer."""
    result = _browser_proof(monkeypatch, status=status)

    assert result.status == "success"
    assert "inconclusive_reason" not in _proof(result)


@pytest.mark.parametrize("status", [503, 404, 500])
def test_a_payload_that_ran_is_proven_whatever_the_page_answered(monkeypatch, status):
    result = _browser_proof(monkeypatch, status=status, runs=True)

    assert result.status == "success"
    assert _proof(result)["proof_state"] == "verified"
    assert "inconclusive_reason" not in _proof(result)


@pytest.mark.parametrize("status, headers, error", [
    (401, {}, "authentication_required:401"),
    (403, {}, "target_refused:403"),
    (403, {"WWW-Authenticate": "Basic realm=app"}, "authentication_required:403"),
])
def test_a_refusal_keeps_its_own_reason(monkeypatch, status, headers, error):
    result = _browser_proof(monkeypatch, status=status, headers=headers)

    assert result.status == "partial"
    assert result.errors == (error,)


def test_a_navigation_sent_to_sign_in_stays_an_authentication_refusal(monkeypatch):
    result = _browser_proof(monkeypatch, final_url="https://app.example.test/login")

    assert result.status == "partial"
    assert result.errors == ("authentication_required:200",)


def test_a_navigation_sent_off_the_origin_stays_a_blocked_attempt(monkeypatch):
    result = _browser_proof(monkeypatch, final_url="https://elsewhere.example.test/landing")

    assert result.status == "blocked"
    assert result.errors == ("final_url_outside_target_origin",)
    assert not any(item.get("kind") == "xss_browser_proof" for item in result.observations)


def test_a_navigation_that_failed_on_the_network_stays_a_failed_attempt(monkeypatch):
    result = _browser_proof(monkeypatch, fail=RuntimeError("net::ERR_CONNECTION_REFUSED"))

    assert result.status == "failed"
    assert result.errors == ("browser_action:RuntimeError",)
    assert not any(item.get("kind") == "xss_browser_proof" for item in result.observations)


def test_a_page_that_never_loaded_stays_a_timed_out_attempt(monkeypatch):
    prepared = _query_proof()
    page, _seen = _install_fake_browser(monkeypatch, requires_auth=False)
    page.fail = sys.modules["playwright.async_api"].TimeoutError("navigation timeout")
    result = asyncio.run(XSSBrowserProofAdapter(prepared).execute(
        heartbeat=_noop, cancelled=lambda: False,
    ))

    assert result.status == "partial" and result.timed_out is True
    assert result.errors == ("browser_action_timeout",)


# --- target-controlled status codes, headers and page output (hostile data) ----------------------


@pytest.mark.parametrize("status, headers", [
    # A challenge on a 503 asks for no credentials the proof could add: the service was down.
    (503, {"WWW-Authenticate": "Basic realm=app"}),
    # A Location on an answer that is not a redirect sends the browser nowhere.
    (503, {"Location": "/login"}),
    # A status outside the registered range is no page that loaded.
    (999, {}),
    (600, {}),
    (429, {"Retry-After": "999999999"}),
], ids=["503-challenge", "503-location", "999", "600", "429-retry-after"])
def test_target_controlled_status_and_headers_cannot_make_an_unserved_page_a_negative(
    monkeypatch, status, headers,
):
    result = _browser_proof(monkeypatch, status=status, headers=headers)

    assert result.status == "partial"
    assert result.errors == (f"target_unavailable:{status}",)
    rendered = json.dumps({"observations": result.observations, "errors": result.errors}, default=str)
    # Nothing the target sent beyond its status reaches the record.
    for value in headers.values():
        assert value not in rendered


def test_page_output_that_is_not_the_marker_neither_proves_nor_settles_an_unserved_page(monkeypatch):
    prepared = _query_proof()
    result = _browser_proof(
        monkeypatch, status=503, marker=f"{prepared.marker} <script>alert(1)</script>",
    )

    assert result.status == "partial"
    proof = _proof(result)
    assert proof["proof_state"] == "not_proven"
    assert proof["inconclusive_reason"] == "target_unavailable"
    assert "<script>" not in json.dumps(result.observations, default=str)


# --- the SQL injection proof ---------------------------------------------------------------------


class PairTransport:
    """The control (the candidate's own value) answers ``control``; every payload answers
    ``payload`` (unit fixture). Bodies hold no database error and reflect nothing."""

    def __init__(self, control, payload, *, body=b'{"products":[]}', headers=None):
        self.control, self.payload, self.body = control, payload, body
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.statuses: list[int] = []

    async def send(self, request, **_kwargs):
        value = urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query).get("q", [""])[0]
        status = self.control if value == "apple" else self.payload
        self.statuses.append(status)
        return ReplayTransportResult(
            status_code=status, connected_address="192.0.2.10", final_url=request.url,
            response_headers=self.headers, response_body=self.body, elapsed_ms=5,
        )


def _sqli_proof(control, payload, **kwargs):
    transport = PairTransport(control, payload, **kwargs)
    adapter = SQLiProofAdapter(
        specification=CAPABILITY_REGISTRY.require("sqli.prove_batch"), target=_target(),
        request=_request(url="https://app.example.test/search?q=apple"),
        candidate={"candidate_id": "b" * 64, "method": "GET", "parameter_name": "q",
                   "request_class": "safe_read"},
        transport=transport,
        requested_budget={"http_requests": 20, "state_changing_requests": 0, "tool_wall_seconds": 20},
    )
    result = asyncio.run(adapter.execute(heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False))
    return result, transport


@pytest.mark.parametrize("control, payload, shown", [
    (503, 503, 503), (502, 502, 502), (504, 504, 504), (408, 408, 408), (429, 429, 429),
    # Answered, then refused by the service: the pairs compare an answer with a refusal.
    (200, 429, 429), (200, 503, 503),
    # The route answered nothing but a missing page or a server error.
    (404, 404, 404), (410, 410, 410), (500, 500, 500), (404, 500, 404),
])
def test_a_sqli_proof_measured_against_an_unavailable_service_is_an_unresolved_attempt(
    control, payload, shown,
):
    result, transport = _sqli_proof(control, payload)

    assert len(transport.statuses) >= 4
    assert result.status == "partial" and result.partial is True
    assert result.errors == (f"target_unavailable:{shown}",)
    proof = result.observations[0]
    assert proof["proof_state"] == "not_proven"
    assert (proof["finding_verdict"], proof["inconclusive_reason"]) == ("inconclusive", "target_unavailable")


@pytest.mark.parametrize("control, payload", [(200, 200), (200, 400), (200, 404), (200, 500)])
def test_a_sqli_proof_whose_route_answered_its_control_is_still_not_proven(control, payload):
    """The route answered its control: a payload answered with an error is the route's answer."""
    result, _transport = _sqli_proof(control, payload)

    assert result.status == "success" and result.errors == ()
    proof = result.observations[0]
    assert (proof["proof_state"], proof["finding_verdict"]) == ("not_proven", "not_proven")
    assert "inconclusive_reason" not in proof


def test_a_sqli_proof_refused_for_credentials_keeps_its_reason():
    result, _transport = _sqli_proof(401, 401)

    assert result.status == "partial"
    assert result.errors == ("authentication_required:401",)
    assert result.observations[0]["inconclusive_reason"] == "authentication_required"


def test_a_body_or_header_that_says_unavailable_does_not_decide_a_sqli_proof():
    """Only the status decides: a 200 whose body and headers announce maintenance is an answer."""
    result, _transport = _sqli_proof(
        200, 200, body=b"<h1>503 Service Unavailable</h1>", headers={"Retry-After": "120"},
    )

    assert result.status == "success"
    assert "inconclusive_reason" not in result.observations[0]


def test_a_sqli_proof_record_of_an_unavailable_service_carries_no_target_text():
    result, _transport = _sqli_proof(
        503, 503, body=b"<p>down for maintenance: token=shakerscan-hostile-body</p>",
        headers={"X-Debug": "shakerscan-hostile-header"},
    )

    assert result.errors == ("target_unavailable:503",)
    rendered = json.dumps({"observations": result.observations, "errors": result.errors}, default=str)
    assert "shakerscan-hostile-body" not in rendered
    assert "shakerscan-hostile-header" not in rendered


def test_the_shared_rule_matches_the_retest():
    from api.runtime.auth_refusal import unavailable_status

    assert unavailable_status(()) is None
    assert unavailable_status((200,)) is None
    assert unavailable_status((200, 400, 500)) is None
    assert unavailable_status((200, 404)) is None
    assert unavailable_status((None, 0, 503)) == 503
    assert unavailable_status((200, 429)) == 429
    assert unavailable_status((404,)) == 404
    assert unavailable_status((404, 500)) == 404
    assert unavailable_status((999,)) == 999
    # Hostile or malformed values are no answer.
    assert unavailable_status((True, "x", -503, 200)) is None
    assert unavailable_status(("503",)) == 503


def test_the_reason_is_a_durable_code_the_coverage_explains():
    from api.scan.explanation import _REASON_LABELS

    assert Reason("target_unavailable") is Reason.TARGET_UNAVAILABLE
    assert "neither proven nor ruled out" in _REASON_LABELS["target_unavailable"]
