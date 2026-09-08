"""No-listing selected-object comparisons: real HTTP fixture plus negative controls.

The fixture intentionally has no collection handler. These tests exercise the
comparison, not the Hunt queue, PostgreSQL or the frozen-address transport.
"""
from __future__ import annotations

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
from capabilities.authz_selected import compare_selected_objects, selected_object_pair

PRIMARY = {"Authorization": "Bearer fixture-a"}
SECONDARY = {"Authorization": "Bearer fixture-b"}
ROOT = "https://app.example.test"
ROUTES = [ROOT + "/objects/101", ROOT + "/objects/202"]


def response(identifier="101", *, status=200, body=None, complete=True, error=None, **extra):
    return {"status_code": status, "body": json.dumps({"id": identifier, "private_note": "private fixture content"}) if body is None else body,
            "headers": {"content-type": "application/json"}, "complete": complete, "error": error, **extra}


def run_case(overrides=None, *, cancelled=lambda: False):
    calls = []
    values = [response("202"), response(), response(), response()]
    for index, item in (overrides or {}).items():
        values[index] = item

    async def fetch(url, *, method, headers, timeout):
        calls.append((url, method, dict(headers), timeout))
        return values[len(calls) - 1]
    result = asyncio.run(compare_selected_objects(ROUTES, fetcher=fetch,
                        primary_headers=PRIMARY, secondary_headers=SECONDARY, cancelled=cancelled))
    return result, calls


def test_exact_selected_object_is_replayed_without_parent_or_enumeration():
    result, calls = run_case()
    assert [(u, h) for u, _, h, _ in calls] == [
        (ROUTES[1], SECONDARY), (ROUTES[0], PRIMARY),
        (ROUTES[0], SECONDARY), (ROUTES[0], PRIMARY),
    ]
    assert all(m == "GET" and timeout == 10 for _, m, _, timeout in calls)
    assert result["cross_access_observed"] is True
    assert result["owner_repeat_stable"] and result["responses_equivalent"]
    assert result["requests_attempted"] == 4 and result["listing_used"] is False
    assert result["proof_state"] == "inconclusive"  # Access alone is not entitlement.
    encoded = json.dumps(result)
    assert "private fixture content" not in encoded and "fixture-a" not in encoded
    assert "absent_from_listing" not in encoded and "findings" not in result


@pytest.mark.parametrize("status", [401, 404, 429, 500, 503, 204, 206, 0])
def test_bad_own_reference_stops_before_the_crossing(status):
    result, calls = run_case({0: response("202", status=status)})
    assert len(calls) == 1 and not result["cross_access_observed"]
    assert not result["selected_request_examined"]


def test_successful_html_baseline_is_not_an_object():
    result, calls = run_case({0: response("202", body="<html>login</html>", headers={"content-type": "text/html"})})
    assert len(calls) == 1 and result["reason"] == "secondary_baseline_response_not_json"


@pytest.mark.parametrize("bad", [
    response("202"), response(status=500), response(complete=False),
    response(complete=None), response(error="timeout"), response(body='{"id":"101"}'),
    response(body='{"id":"101","id":"202","data":1}'),
    response(body='{"id":"101","Id":"101","data":1}'),
    response(body='{"id":"101","value":NaN}'),
    response(body='{"id":true,"data":1}'),
    response(body='{"error":"bad","id":"101"}'),
    response(body='[{"id":"101","data":1}]'),
    response(body='{"a":{"id":"101","x":1},"b":{"id":"101","x":1}}'),
])
def test_invalid_selected_responses_do_not_create_cross_access(bad):
    result, calls = run_case({2: bad})
    assert not result["cross_access_observed"] and len(calls) == 3
    assert result["proof_state"] == "inconclusive"


def test_wrapper_json_and_case_insensitive_id_are_supported():
    body = '{"status":"success","data":{"Id":101,"items":[]}}'
    result, _ = run_case({i: response(body=body) for i in (1, 2, 3)})
    assert result["cross_access_observed"] is True


def test_protected_selected_object_is_not_confirmed_by_another_object():
    # No selection/enumeration from the parent; only this exact object is tested.
    result, calls = run_case({2: response(status=403, body='{"error":"forbidden"}')})
    assert len(calls) == 3 and result["access_denied"]
    assert not result["cross_access_observed"] and result["selected_request_examined"]


@pytest.mark.parametrize("status", [0, 401, 404, 429, 500, 503])
def test_crossing_errors_are_not_enforcement(status):
    result, _ = run_case({2: response(status=status)})
    assert not result["access_denied"] and not result["cross_access_observed"]


def test_partial_or_transport_failed_403_does_not_establish_denial():
    for value in (response(status=403, complete=False), response(status=403, error="timeout")):
        result, _ = run_case({2: value})
        assert not result["access_denied"]


def test_changing_owner_view_prevents_stable_cross_access_claim():
    result, calls = run_case({3: response(body='{"id":"101","private_note":"changed"}')})
    assert len(calls) == 4 and not result["cross_access_observed"]
    assert result["reason"] == "selected_object_changed_during_comparison"


def test_partial_disclosure_is_a_reviewable_difference_not_full_equivalence():
    result, _ = run_case({2: response(body='{"id":"101","private_note":"redacted"}')})
    assert result["reason"] == "selected_object_response_differs_review_fields"
    assert not result["cross_access_observed"]


def test_shared_object_never_becomes_automatic_authorization_proof():
    result, _ = run_case()
    assert result["cross_access_observed"] and result["requires_entitlement_review"]
    assert result["proof_state"] != "verified"


@pytest.mark.parametrize("pair", [
    [ROOT + "/objects", ROUTES[0]], [ROUTES[0]], [*ROUTES, ROOT + "/objects/303"],
    [ROUTES[0], ROUTES[0]], [ROUTES[0], ROOT + "/other/202"],
    [ROUTES[0], "https://other.example.test/objects/202"],
    [ROUTES[0], "http://app.example.test/objects/202"],
    [ROUTES[0], ROOT + "/objects/202/"],
    [ROUTES[0], ROOT + "/objects/202?view=x"],
    [ROUTES[0], ROOT + "/objects/202#x"],
    [ROOT + "/%2e%2e/101", ROOT + "/%2e%2e/202"],
    [ROOT + "/objects/abc", ROOT + "/objects/def"],
    [ROOT + "/objects//101", ROOT + "/objects//202"],
    ["https://user:secret@app.example.test/objects/101", ROUTES[1]],
])
def test_unsupported_or_ambiguous_pairs_are_not_rewritten(pair):
    assert selected_object_pair(pair) is None


def test_cancellation_before_first_get_sends_nothing():
    with pytest.raises(asyncio.CancelledError):
        run_case(cancelled=lambda: True)


def test_cancellation_between_requests_stops_the_sequence():
    calls = []
    async def fetch(url, **kwargs):
        calls.append(url)
        return response("202")
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(compare_selected_objects(ROUTES, fetcher=fetch,
                    primary_headers=PRIMARY, secondary_headers=SECONDARY, cancelled=lambda: bool(calls)))
    assert calls == [ROUTES[1]]


def test_same_auth_context_is_not_cross_principal_evidence():
    async def unexpected(*args, **kwargs):
        raise AssertionError("sent traffic")
    with pytest.raises(ValueError, match="distinct"):
        asyncio.run(compare_selected_objects(ROUTES, fetcher=unexpected,
                    primary_headers=PRIMARY, secondary_headers=PRIMARY))


@pytest.fixture
def no_listing_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            principal = "a" if self.headers.get("Authorization") == PRIMARY["Authorization"] else "b"
            self.server.trace.append((principal, self.path))
            mode, _, identifier = self.path.strip("/").partition("/")
            if not identifier:
                code, value = 500, {"error": "no collection route"}
            elif identifier not in {"101", "102", "202"}:
                code, value = 404, {"error": "not found"}
            elif principal == "b" and identifier != "202" and (mode == "protected" or identifier == "102"):
                code, value = 403, {"error": "forbidden"}
            else:
                code, value = 200, {"data": {"id": identifier, "items": ["fixture-value"],
                                            "visibility": "shared" if mode == "shared" else "private"}}
            encoded = json.dumps(value).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.trace = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown(); server.server_close(); thread.join()


@pytest.mark.parametrize("mode,selected,observed", [
    ("vulnerable", "101", True), ("protected", "101", False),
    ("vulnerable", "102", False), ("shared", "101", True),
])
def test_real_http_no_listing_fixture(no_listing_server, mode, selected, observed):
    server, origin = no_listing_server
    async def fetch(url, *, headers, method="GET", timeout=10):
        req = urllib.request.Request(url, headers=headers, method=method)
        try:
            value = urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            value = exc
        with value:
            return {"status_code": value.code, "headers": dict(value.headers),
                    "body": value.read().decode(), "complete": True, "error": None}
    assert asyncio.run(fetch(origin + "/" + mode, headers=PRIMARY))["status_code"] == 500
    server.trace.clear()
    result = asyncio.run(compare_selected_objects(
        [f"{origin}/{mode}/{selected}", f"{origin}/{mode}/202"], fetcher=fetch,
        primary_headers=PRIMARY, secondary_headers=SECONDARY))
    assert result["cross_access_observed"] is observed
    assert result["proof_state"] == "inconclusive"
    expected = [("b", f"/{mode}/202"), ("a", f"/{mode}/{selected}"), ("b", f"/{mode}/{selected}")]
    if observed:
        expected.append(("a", f"/{mode}/{selected}"))
    assert server.trace == expected
    # Selecting the protected object never probes the vulnerable sibling 101.
    if selected == "102":
        assert all(not path.endswith("/101") for _, path in server.trace)


def test_deadline_retains_partial_observations_without_continuing(monkeypatch):
    import capabilities.authz_selected as selected
    monkeypatch.setattr(selected, "DEADLINE_SECONDS", 0.01)
    calls = []
    async def fetch(url, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            return response("202")
        await asyncio.sleep(10)
    result = asyncio.run(compare_selected_objects(ROUTES, fetcher=fetch,
                        primary_headers=PRIMARY, secondary_headers=SECONDARY))
    assert result["partial"] and result["secondary_baseline_valid"]
    assert result["requests_attempted"] == 2 and len(calls) == 2
    assert result["reason"] == "selected_object_deadline_exceeded"
    assert not result["cross_access_observed"]


def _envelope(identifier="101", *, sibling_id=None):
    """An envelope carrying the requested object beside an unrelated sibling object."""
    sibling = {"transaction_id": "t-1", "amount": 10}
    if sibling_id is not None:
        sibling["id"] = sibling_id
    return json.dumps({"selection": {"id": identifier, "private_note": "private fixture content"},
                       "related": sibling})


def test_a_sibling_object_beside_the_selection_does_not_hide_it():
    """Composite envelopes are ordinary API shape; refusing them left such routes unexaminable."""
    result, _ = run_case({0: response(body=_envelope("202")),
                          **{i: response(body=_envelope()) for i in (1, 2, 3)}})
    assert result["secondary_baseline_valid"] is True
    assert result["cross_access_observed"] is True


def test_the_comparison_covers_the_identified_object_not_the_envelope():
    """Only the selection is compared, so an unrelated sibling cannot mask or fake equivalence."""
    owner = json.dumps({"selection": {"id": "101", "private_note": "private fixture content"},
                        "related": {"amount": 10}})
    crossing = json.dumps({"selection": {"id": "101", "private_note": "private fixture content"},
                           "related": {"amount": 99}})
    result, _ = run_case({0: response(body=_envelope("202")), 1: response(body=owner),
                          2: response(body=crossing), 3: response(body=owner)})
    assert result["responses_equivalent"] is True


def test_two_siblings_claiming_the_identifier_stay_ambiguous():
    body = json.dumps({"a": {"id": "101", "note": "one"}, "b": {"id": "101", "note": "two"}})
    result, _ = run_case({0: response(body=body)})
    assert result["secondary_baseline_valid"] is False


def test_an_envelope_whose_siblings_never_claim_the_identifier_stays_ambiguous():
    result, _ = run_case({0: response(body=_envelope("999", sibling_id="888"))})
    assert result["secondary_baseline_valid"] is False
    assert result["reason"] == "secondary_baseline_response_object_ambiguous"
