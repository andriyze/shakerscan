"""The server_injection batch: what each candidate is sent, and what it is never sent."""
import asyncio
import json
import re
import urllib.parse
import uuid

from scan.auth_endpoint_probe import SignInEndpoint

from tests.test_scan_action_adapter import (
    Backend, TARGET, _action, _dispatcher, _lease, _noop,
    action_adapter_module, build_candidate_manifest, build_endpoint_manifest,
    ReplayTransportResult, ScanActionPlan, ScanPolicy,
)


def _endpoint(method, path, *, query=(), body=()):
    return {
        "method": method, "scheme": "https", "host": "app.example.test", "port": 443,
        "normalized_path": path, "concrete_path": path, "query_keys": list(query),
        "content_type": "application/json" if body else None,
        "body_field_names": list(body), "source": "web.browser_crawl",
    }


def _run(monkeypatch, endpoint, *, allow_state_changing, sign_in=None, budget=None):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={"schema_version": "endpoint-manifest/v2", "status": "complete",
                          "reason": None, "endpoints": [endpoint]},
        source_action_ids=("discover.crawl",))
    candidates = build_candidate_manifest(endpoints, source_action_ids=("discover.crawl",),
                                          maximum=10, allow_state_changing_http=True)
    assert len(candidates.entries) == 1
    action = _action("verify.server_injection.00000", "injection.verify_batch", 0, capability_args={
        "candidate_manifest_ref": candidates.reference().canonical_dict(),
        "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        "slice": {"start": 0, "count": 1}, "profile": "balanced_batch_v1",
        "proof_policy": "verified_only"})
    if budget is not None:
        import dataclasses
        action = dataclasses.replace(action, requested_budget=dict(budget), action_digest=None)
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    backend = Backend(manifests={endpoints.manifest_id: endpoints,
                                 candidates.manifest_id: candidates})
    requests = []

    class Transport:
        async def send(self, request, **_kwargs):
            requests.append(request)
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query)
            value = (query.get("q") or [""])[0]
            # A template rendered from the input: ``{{a*b}}`` is evaluated, the rest echoed.
            rendered = re.sub(r"\{\{(\d+)\*(\d+)\}\}",
                              lambda m: str(int(m.group(1)) * int(m.group(2))), value)
            return ReplayTransportResult(
                status_code=200, connected_address="192.0.2.10", final_url=request.url,
                response_headers={"Content-Type": "text/html"},
                response_body=f"<p>{rendered}</p>".encode(), elapsed_ms=5)

    monkeypatch.setattr(action_adapter_module.DatabaseNeutralScanActionDispatcher,
                        "_scan_replay_transport", lambda *a, **kw: Transport())

    async def endpoints_of_profiles(_self):
        return (sign_in,) if sign_in is not None else ()

    monkeypatch.setattr(action_adapter_module.DatabaseNeutralScanActionDispatcher,
                        "_sign_in_endpoints", endpoints_of_profiles)
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy(
        active_testing=True, allow_state_changing_http=allow_state_changing,
        approval_receipt_id="approval-1"))
    result = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    observations = [item for attempt in backend.attempts.get(action.action_id, {}).values()
                    for item in attempt["observations"]]
    return result, observations, requests


def test_a_query_candidate_is_proven_within_its_reservation(monkeypatch):
    _result, observations, requests = _run(
        monkeypatch, _endpoint("GET", "/render", query=("q",)), allow_state_changing=False)
    proofs = [item for item in observations if item.get("kind") == "injection_proof"]
    verified = [item for item in proofs if item["proof_state"] == "verified"]
    assert [item["injection_class"] for item in verified] == ["template_injection"]
    assert verified[0]["repetitions"] == 2 and verified[0]["method"] == "GET"
    assert all(request.method == "GET" for request in requests)
    # Every class on one candidate fits what a plan reserves for it (action_plan: 40 requests).
    assert 0 < len(requests) <= 40


def test_a_body_candidate_without_state_changing_authority_is_sent_nothing(monkeypatch):
    result, observations, requests = _run(
        monkeypatch, _endpoint("POST", "/notes", body=("title",)), allow_state_changing=False)
    assert requests == [] and observations == []
    # No budget could have tested it: inapplicable with the reason, and the batch is complete,
    # not a partial one that reads as work the budget cut off.
    skipped = [item for item in result.observations if item.get("kind") == "candidate_inapplicable"]
    assert [item["reason"] for item in skipped] == ["state_changing_http_not_allowed"]
    assert result.status == "success" and result.redacted_execution["unattempted_count"] == 0


def test_a_candidate_whose_request_cannot_be_built_fails_alone(monkeypatch):
    """One candidate must never fail the batch: its own attempt fails, with the reason."""
    def refuse(**_kwargs):
        raise ValueError("injection request method differs from candidate")

    monkeypatch.setattr(action_adapter_module, "InjectionVerifyAdapter", refuse)
    result, observations, requests = _run(
        monkeypatch, _endpoint("GET", "/render", query=("q",)), allow_state_changing=False)
    assert requests == []
    assert [item["status"] for item in observations] == ["failed"]
    assert result.errors == ("candidate_request_invalid:ValueError",)
    assert result.redacted_execution["attempted_count"] == 1


def test_the_credential_profiles_sign_in_endpoint_is_sent_nothing(monkeypatch):
    sign_in = SignInEndpoint(scheme="https", host="app.example.test", port=443, path="/login")
    result, _observations, requests = _run(
        monkeypatch, _endpoint("POST", "/login", body=("email",)),
        allow_state_changing=True, sign_in=sign_in)
    assert requests == []
    public = json.dumps(result.public_dict())
    assert "sign_in_endpoint_candidate" in public


def test_a_body_candidate_spends_the_slices_state_changing_hold_and_no_more(monkeypatch):
    """Every request of a body candidate is a write: it is reserved, bounded and settled as one."""
    result, observations, requests = _run(
        monkeypatch, _endpoint("POST", "/notes", body=("title",)), allow_state_changing=True,
        budget={"http_requests": 40, "state_changing_requests": 6, "tool_wall_seconds": 40})
    assert 0 < len(requests) <= 6 and all(request.method == "POST" for request in requests)
    attempt, = [item for item in observations if item.get("kind") == "candidate_attempt"]
    assert attempt["budget_consumed"]["state_changing_requests"] == len(requests)
    assert attempt["budget_consumed"]["http_requests"] == len(requests)
    assert result.public_dict()["budget_consumed"]["state_changing_requests"] == len(requests)


def test_a_body_candidate_in_a_slice_without_a_state_changing_hold_is_sent_nothing(monkeypatch):
    """The authority alone is not a reservation: with no hold the write is left unattempted (a
    partial batch), never sent as a plain request."""
    result, observations, requests = _run(
        monkeypatch, _endpoint("POST", "/notes", body=("title",)), allow_state_changing=True,
        budget={"http_requests": 40, "tool_wall_seconds": 40})
    assert requests == [] and observations == []
    assert result.redacted_execution["unattempted_count"] == 1
    assert result.status != "success"


def test_a_read_candidate_spends_none_of_the_state_changing_hold(monkeypatch):
    result, observations, requests = _run(
        monkeypatch, _endpoint("GET", "/render", query=("q",)), allow_state_changing=True,
        budget={"http_requests": 40, "state_changing_requests": 40, "tool_wall_seconds": 40})
    assert requests and all(request.method == "GET" for request in requests)
    attempt, = [item for item in observations if item.get("kind") == "candidate_attempt"]
    assert "state_changing_requests" not in attempt["budget_consumed"]
    assert result.public_dict()["budget_consumed"].get("state_changing_requests", 0) == 0
