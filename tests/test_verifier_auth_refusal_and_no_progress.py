"""Refused baselines are inconclusive, and a continuation that sent nothing is not repeated.

Lab Scan 13bd3497 (2.11.0 at 24d32428, thorough honey with a /hub/ browser capture) replayed the
captured ``/hub/api/<name>/1*`` routes without the captured session (a capture never keeps
credentials). Each answered 401; sqlmap stopped after one request per technique and every
technique was recorded as a settled negative. Its SQLi continuation then ran seven links in a
row at the same 480-request hold without sending a request. Fixture data below is shaped after
those receipts; nothing here is a live measurement.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import uuid
from types import SimpleNamespace

import agent_tools
import scan.action_adapter as action_adapter_module
from capabilities.nosqli_verify import NoSQLiVerifyAdapter
from capabilities.request_mutation import RequestMutationVerificationAdapter
from hunt.capability_executor import CapabilityAdapterResult
from runtime.auth_refusal import BASELINE_RECORD_KIND, is_login_location, refusal_status
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy
from runtime.request_replay_executor import ReplayTransportResult
from scan.action_adapter import batch_stop_reason
from scan.action_plan import ScanActionPlan
from scan.finalizer import _family_action_reason
from scan.sqli_stages import prior_stages, run_staged_sqli_attempt, stage_attempt_id
from scan.verification_extension import EXTENDS_ARG, plan_verification_extensions
from scan.verifier_refusal import mark_refused
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest
from scanner_tools.request_replay import ReplayRequest

from tests.test_scan_action_adapter import TARGET, Backend, _dispatcher, _lease, _noop
from tests.test_scan_action_adapter import _action as plan_action

SQLMAP_TRAFFIC = (
    "HTTP request [#1]:\nGET /hub/api/tickets/1 HTTP/1.1\nHost: 10.10.10.100:8000\n\n"
    "HTTP response [#1] (401 Unauthorized):\r\nContent-Type: application/json\r\n"
    "Content-Length: 27\r\n\r\n{\"error\":\"login required\"}\n\n" + "#" * 76 + "\n\n"
)


def test_refusal_statuses_and_login_redirects():
    assert refusal_status(401) == 401 and refusal_status(403) == 403
    assert refusal_status(303, {"Location": "/hub/login?next=%2Fhub%2Forders"}) == 303
    assert refusal_status(302, {"location": "https://app.example.test/users/sign_in"}) == 302
    assert refusal_status(302, {"Location": "/hub/orders"}) is None
    assert refusal_status(200) is None and refusal_status(404) is None
    assert is_login_location("/login") and not is_login_location("/blog/login-tips")


def test_the_wire_log_baseline_is_recorded_for_sqlmap_and_dalfox():
    assert agent_tools.sqlmap_traffic_baseline(SQLMAP_TRAFFIC) == {
        "status": 401, "login_redirect": False, "www_authenticate": False,
    }
    har = json.dumps({"log": {"entries": [{"response": {
        "status": 303, "headers": [{"name": "Location", "value": "/hub/login"}],
    }}]}})
    assert agent_tools.har_baseline(har) == {
        "status": 303, "login_redirect": True, "www_authenticate": False,
    }
    parsed = agent_tools.parse_scanner_output(
        "sqlmap", "", wire_log={"actual": 1, "baseline": {"status": 401, "login_redirect": False}},
    )
    assert parsed["records"] == [{
        "kind": BASELINE_RECORD_KIND, "http_status": 401, "login_redirect": False,
        "www_authenticate": False,
    }]
    # Without a traffic log, sqlmap's own refusal of its connection test names the 401.
    stdout = (
        "[CRITICAL] not authorized, try to provide right HTTP authentication type and valid "
        "credentials (401). If this is intended, try to rerun by providing a valid value for "
        "option '--ignore-code'"
    )
    assert agent_tools.parse_scanner_output("sqlmap", stdout)["records"][0]["http_status"] == 401
    assert agent_tools.parse_scanner_output("nuclei", "", wire_log={"baseline": {"status": 401}})[
        "records"
    ] == []


def _run(status=401, **extra):
    return CapabilityAdapterResult(
        status="success", execution_started=True, parser_version="sqlmap-output/v1",
        actual_budget={"http_requests": 1, "tool_wall_seconds": 1},
        observations=(
            {"kind": BASELINE_RECORD_KIND, "http_status": status, "login_redirect": False},
            *extra.get("records", ()),
        ),
    )


def test_a_refused_run_is_partial_for_authentication_never_a_negative():
    refused = mark_refused(_run(), exempt=False)
    assert refused.status == "partial" and refused.partial
    assert refused.errors[0] == "authentication_required:401"
    assert batch_stop_reason(refused.errors, unattempted=0) == "authentication_required"
    # A body candidate (a login form tested with --ignore-code 401/403), an answered baseline,
    # and a run that found something are all left as they are.
    assert mark_refused(_run(), exempt=True).status == "success"
    assert mark_refused(_run(200), exempt=False).status == "success"
    found = _run(records=({"kind": "sqli_finding", "param": "id"},))
    assert mark_refused(found, exempt=False).status == "success"


def test_a_refused_stage_stops_the_candidate_without_a_verdict_or_a_continuation():
    calls, checkpoints = [], []

    async def run_stage(technique, budget, _latency):
        calls.append(technique)
        return mark_refused(_run(), exempt=False)

    async def checkpoint(item):
        checkpoints.append(dict(item))

    def attempt(prior):
        return asyncio.run(run_staged_sqli_attempt(
            candidate_attempt_id="6" * 64, candidate_id="tickets",
            budget={"http_requests": 400, "tool_wall_seconds": 180}, prior=prior,
            own_action_id="verify.sqli.r01", run_stage=run_stage, checkpoint=checkpoint,
            cancelled=lambda: False,
        ))

    outcome = attempt(prior_stages((), "6" * 64))
    assert calls == ["U"], "B, E and T would meet the same refusal"
    assert outcome.status == "partial" and outcome.refusal == "authentication_required:401"
    assert outcome.settled_units == ()
    assert outcome.resume_wall_seconds is None, "no continuation can get past a login wall"
    assert outcome.stages[-1] == {"technique": "U", "outcome": "authentication_required"}
    # A later attempt reads the refusal from the checkpoint and sends nothing again.
    again = attempt(prior_stages((("verify.sqli.r01", tuple(checkpoints)),), "6" * 64))
    assert calls == ["U"] and again.refusal == "authentication_required:401"
    assert checkpoints[0]["attempt_id"] == stage_attempt_id("6" * 64, "U")


def test_a_refused_query_candidate_is_inconclusive_in_the_sqli_batch(monkeypatch):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": "/api/tickets", "concrete_path": "/api/tickets",
                "query_keys": ["id"], "source": "web.crawl",
            }],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=10,
    )
    action = dataclasses.replace(plan_action(
        "verify.sqli.r01", "sqli.verify_batch", 0, capability_args={
            "candidate_manifest_ref": candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
            "slice": {"start": 0, "count": 1},
            "profile": "thorough_batch_v1", "proof_policy": "deterministic_differential_required",
        },
    ), requested_budget={"http_requests": 1_600, "tool_wall_seconds": 720}, action_digest=None)
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    techniques = []

    async def execute(_self, _context, adapter, **_kwargs):
        techniques.append(adapter._process_payload["scanner_options"]["technique"])
        return _run()

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    dispatcher = _dispatcher(
        plan, backend, policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert techniques == ["U"]
    assert receipt.status == "partial"
    assert receipt.errors[0] == "authentication_required"
    head = next(item for item in receipt.observations if item.get("kind") == "candidate_attempt")
    assert head["verdict"] == "inconclusive"
    assert head["inconclusive_reason"] == "authentication_required"
    assert "resume_wall_seconds" not in head


class _Transport:
    def __init__(self, status, headers=None):
        self.status, self.headers, self.sent = status, dict(headers or {}), []

    async def send(self, request, **_kwargs):
        self.sent.append(request)
        return ReplayTransportResult(
            status_code=self.status, connected_address="203.0.113.10",
            final_url=request.url, response_headers=self.headers,
            response_body=b'{"error":"login required"}',
        )


def _request(method="GET", url="https://app.example.test/api/tickets?id=1", body=b""):
    return ReplayRequest(
        request_id="request-1", ordinal=1, name="captured", folder="", method=method, url=url,
        headers=(("Content-Type", "application/json"),) if body else (), body=body,
        body_mode="raw" if body else "none", auth_type="none", has_sensitive_material=False,
    )


async def _noop_heartbeat():
    return None


def test_nosqli_does_not_read_a_refused_control_as_not_proven():
    transport = _Transport(303, {"Location": "/hub/login"})
    adapter = NoSQLiVerifyAdapter(
        specification=CAPABILITY_REGISTRY.require("nosqli.verify_batch"), target=TARGET,
        request=_request(), transport=transport, requested_budget={"http_requests": 8},
        candidate={"candidate_id": "c" * 64, "method": "GET", "parameter_name": "id"},
    )
    result = asyncio.run(adapter.execute(heartbeat=_noop_heartbeat, cancelled=lambda: False))
    assert len(transport.sent) == 1, "the operators would meet the same refusal"
    assert result.status == "partial" and result.errors[0] == "authentication_required:303"
    assert result.observations[0]["inconclusive_reason"] == "authentication_required"


def test_a_request_mutation_whose_control_is_refused_is_not_sent():
    def run(request_class):
        transport = _Transport(401)
        adapter = RequestMutationVerificationAdapter(
            specification=CAPABILITY_REGISTRY.require("sqli.request_verify_batch"), target=TARGET,
            request=_request("POST", "https://app.example.test/api/tickets", b'{"title":"x"}'),
            transport=transport,
            requested_budget={"http_requests": 2, "state_changing_requests": 2, "tool_wall_seconds": 10},
            candidate={
                "candidate_id": "d" * 64, "request_ref_id": "request-1", "method": "POST",
                "family_hints": ["sqli"], "request_class": request_class, "field_path": "title",
            },
        )
        return transport, asyncio.run(
            adapter.execute(heartbeat=_noop_heartbeat, cancelled=lambda: False),
        )

    transport, result = run("confirmed_mutation")
    assert len(transport.sent) == 1
    assert result.status == "partial" and result.errors == ("authentication_required:401",)
    # A login form answers a wrong password with 401: that answer is what it is compared to.
    transport, result = run("safe_authentication")
    assert len(transport.sent) == 2 and result.status == "success"


def test_a_captured_login_form_is_compared_although_it_is_a_confirmed_mutation():
    # Lab Scan 9487605c (2.11.0 candidate 8dcd692b): the browser capture and the seeds replay
    # POST /hub/login as confirmed_mutation, so its 401 for the wrong password was read as a
    # refusal and no payload was sent. The login path and its body identify it.
    def mutation(url):
        transport = _Transport(401)
        adapter = RequestMutationVerificationAdapter(
            specification=CAPABILITY_REGISTRY.require("sqli.request_verify_batch"), target=TARGET,
            request=_request("POST", url, b'{"username":"x","password":"y"}'),
            transport=transport,
            requested_budget={"http_requests": 2, "state_changing_requests": 2, "tool_wall_seconds": 10},
            candidate={
                "candidate_id": "d" * 64, "request_ref_id": "request-1", "method": "POST",
                "family_hints": ["sqli"], "request_class": "confirmed_mutation",
                "field_path": "username",
            },
        )
        return transport, asyncio.run(
            adapter.execute(heartbeat=_noop_heartbeat, cancelled=lambda: False),
        )

    transport, result = mutation("https://app.example.test/hub/login")
    assert len(transport.sent) == 2 and result.status == "success"
    for refused in ("/hub/api/users/1", "/api/auth/change-password", "/api/users/1/token"):
        transport, result = mutation(f"https://app.example.test{refused}")
        assert len(transport.sent) == 1 and result.errors == ("authentication_required:401",)

    def nosqli(url):
        transport = _Transport(401)
        adapter = NoSQLiVerifyAdapter(
            specification=CAPABILITY_REGISTRY.require("nosqli.verify_batch"), target=TARGET,
            request=_request("POST", url, b'{"username":"x","password":"y"}'),
            transport=transport, requested_budget={"http_requests": 8},
            candidate={
                "candidate_id": "e" * 64, "method": "POST", "request_class": "confirmed_mutation",
                "request_ref_id": "request-1", "field_path": "username",
            },
        )
        return transport, asyncio.run(
            adapter.execute(heartbeat=_noop_heartbeat, cancelled=lambda: False),
        )

    transport, result = nosqli("https://app.example.test/hub/login")
    assert len(transport.sent) > 1 and "authentication_required:401" not in result.errors
    transport, result = nosqli("https://app.example.test/hub/api/users/1")
    assert len(transport.sent) == 1 and result.errors[0] == "authentication_required:401"


THOROUGH = {"http_requests": 60_000, "state_changing_requests": 6_000, "tool_wall_seconds": 10_800}


def _link(action_id, extends=None):
    args = {"slice": {"start": 0, "count": 4}, "candidate_manifest_ref": {"kind": "candidate"}}
    if extends:
        args[EXTENDS_ARG] = extends
    return SimpleNamespace(
        action_id=action_id, capability_name="sqli.verify_batch", stage="verify_candidates",
        capability_args=args, dependencies=(),
        requested_budget={"http_requests": 480, "tool_wall_seconds": 1_173},
    )


def _settled(status, reason, consumed, reserved):
    return SimpleNamespace(
        status=SimpleNamespace(value=status), reason_code=SimpleNamespace(value=reason),
        budget_reserved=dict(reserved), budget_consumed=dict(consumed),
    )


def test_a_link_that_sent_nothing_is_not_extended_again_at_the_same_holds():
    first, second = _link("verify.sqli.r01"), _link("verify.sqli.r01.ext.r02", "verify.sqli.r01")
    results = {
        "verify.sqli.r01": _settled(
            "timed_out", "timed_out", {"http_requests": 15, "tool_wall_seconds": 11},
            {"http_requests": 1_600, "tool_wall_seconds": 720},
        ),
        "verify.sqli.r01.ext.r02": _settled(
            "partial", "http_request_budget_exhausted",
            {"http_requests": 0, "tool_wall_seconds": 1},
            {"http_requests": 480, "tool_wall_seconds": 1_173},
        ),
    }
    planned = plan_verification_extensions(
        parent_plan=SimpleNamespace(actions=(first, second)), parent_results=results,
        profile_limits=THOROUGH, residual={"http_requests": 30_000, "tool_wall_seconds": 1_200},
        stage_resume_walls={"verify.sqli.r01.ext.r02": 30},
        stage_remaining_requests={"verify.sqli.r01.ext.r02": 189},
    )
    assert planned == ()
    # The family names why the candidate stayed unverified instead of a budget it never used.
    finalized = SimpleNamespace(
        status=SimpleNamespace(value="partial"),
        reason_code=SimpleNamespace(value="http_request_budget_exhausted"),
        budget_consumed={"http_requests": 0, "tool_wall_seconds": 1},
    )
    assert _family_action_reason(second, finalized) == "insufficient_budget_for_stage"
    assert _family_action_reason(first, finalized) == "http_request_budget_exhausted"
