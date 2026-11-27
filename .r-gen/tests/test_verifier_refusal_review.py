"""Review follow-ups to the refused-baseline rule (b52a18be..ddafdbd1).

* Only an authentication endpoint's 401/403 is its own answer: a captured ``POST /api/orders``
  replayed without its session is refused like any GET, and Dalfox is never exempt.
* A 403 that asks for no credentials (a WAF rejecting sqlmap's user agent, an ownership check)
  is ``target_refused``: the remaining techniques still run, since a payload may get past it,
  but none of their negatives is a verdict.
* The SQLi proof, open-redirect, GraphQL and browser XSS verifiers read a refused control as
  inconclusive too.
* Sign-in detection covers OAuth/OIDC authorization endpoints and ignores static assets.

Fixtures only; nothing here is a live measurement.
"""

from __future__ import annotations

import asyncio
import dataclasses
import urllib.parse

import agent_tools
from capabilities.graphql_probe import TYPENAME_QUERY
from capabilities.open_redirect import probe_candidate
from capabilities.sqli_proof import SQLiProofAdapter
from hunt.capability_executor import CapabilityAdapterResult
from runtime.auth_refusal import BASELINE_RECORD_KIND, is_login_location, refusal
from runtime.capability_registry import CAPABILITY_REGISTRY
from scan.sqli_stages import prior_stages, run_staged_sqli_attempt
from scan.verifier_refusal import mark_refused, refusal_exempt

from tests.test_graphql_verify_batch import _run as run_graphql_batch
from tests.test_scan_action_adapter import TARGET
from tests.test_verifier_auth_refusal_and_no_progress import (
    _noop_heartbeat,
    _request,
    _Transport,
)


def test_sign_in_locations_include_authorization_endpoints_but_not_assets():
    for location in (
        "/hub/login", "/users/sign_in", "/login.php", "/Account/Login.aspx", "/auth",
        "https://idp.example.test/realms/acme/protocol/openid-connect/auth?client_id=x",
        "/oauth2/authorize", "/oauth2/v2.0/authorize", "/connect/authorize", "/authorize",
    ):
        assert is_login_location(location), location
    for location in ("/static/login.css", "/login.js", "/img/sso.png", "/blog/login-tips", "/hub/orders"):
        assert not is_login_location(location), location


def test_a_403_is_a_credential_request_only_when_it_asks_for_one():
    assert refusal(401) == (401, "authentication_required")
    assert refusal(407) == (407, "authentication_required")
    assert refusal(403, {"WWW-Authenticate": 'Bearer realm="api"'}) == (403, "authentication_required")
    assert refusal(403) == (403, "target_refused")
    assert refusal(302, {"Location": "/oauth2/authorize?next=/x"}) == (302, "authentication_required")
    assert refusal(302, {"Location": "/static/login.css"}) is None


def test_authentication_paths_are_whole_segments():
    from runtime.auth_refusal import is_authentication_candidate, is_authentication_path

    for path in ("/hub/login", "/users/sign_in", "/api/v1/auth", "/auth/login", "/session/new",
                 "/oauth/token", "/api/authenticate", "/logon", "/sign-in"):
        assert is_authentication_path(path), path
        assert is_authentication_candidate({"canonical_path": path, "body_field_names": ["a"]})
    for path in ("/api/authors", "/api/sessions/123/notes", "/api/loginhistory",
                 "/api/users/authorization", "/auth/admin/users/1", "/session/1/notes/2"):
        assert not is_authentication_path(path), path
        assert not is_authentication_candidate({"canonical_path": path, "body_field_names": ["a"]})
    # A query candidate is never an authentication endpoint by its path alone.
    assert not is_authentication_candidate({"canonical_path": "/hub/login"})


def test_only_an_authentication_endpoint_is_exempt_and_dalfox_never_is():
    orders = {"canonical_path": "/api/orders", "body_field_names": ["note"], "method": "POST"}
    login = {"canonical_path": "/hub/login", "body_field_names": ["username", "password"]}
    assert refusal_exempt("sqlmap", orders) is False
    assert refusal_exempt("sqlmap", login) is True
    assert refusal_exempt("sqlmap", {"request_class": "safe_authentication"}) is True
    assert refusal_exempt("dalfox", login) is False
    assert refusal_exempt("nuclei", orders) is True


def _baseline(status, **flags):
    return CapabilityAdapterResult(
        status="success", execution_started=True, parser_version="sqlmap-output/v1",
        actual_budget={"http_requests": 20, "tool_wall_seconds": 20},
        observations=({
            "kind": BASELINE_RECORD_KIND, "http_status": status,
            "login_redirect": False, "www_authenticate": False, **flags,
        },),
    )


def _staged(results, *, prior=None):
    calls, checkpoints = [], []

    async def run_stage(technique, _budget, _latency):
        calls.append(technique)
        return mark_refused(results(technique), exempt=False)

    async def checkpoint(item):
        checkpoints.append(dict(item))

    outcome = asyncio.run(run_staged_sqli_attempt(
        candidate_attempt_id="7" * 64, candidate_id="orders",
        budget={"http_requests": 2_000, "tool_wall_seconds": 3_000},
        prior=prior or prior_stages((), "7" * 64), own_action_id="verify.sqli.r01",
        run_stage=run_stage, checkpoint=checkpoint, cancelled=lambda: False,
    ))
    return outcome, calls, checkpoints


def test_a_waf_403_runs_every_technique_but_settles_none():
    # A WAF rejects sqlmap's user agent: every request answers 403 with no challenge.
    outcome, calls, checkpoints = _staged(lambda _technique: _baseline(403))
    assert calls == ["U", "B", "E", "T"]
    assert outcome.status == "partial"
    assert outcome.settled_units == ()
    assert outcome.refusal == "target_refused:403"
    assert outcome.resume_wall_seconds is None
    assert [stage["outcome"] for stage in outcome.stages] == ["target_refused"] * 4
    # A later attempt does not re-send them, and they still settle nothing.
    again, calls_again, _ = _staged(
        lambda _technique: _baseline(403),
        prior=prior_stages((("verify.sqli.r01", tuple(checkpoints)),), "7" * 64),
    )
    assert calls_again == [] and again.settled_units == () and again.status == "partial"


def test_an_ownership_check_403_does_not_hide_a_later_technique_that_proves():
    # GET /api/orders?id=1 answers 403 (not the caller's order); a boolean payload gets past
    # the check. The refused union stage is no verdict, and the proof stands.
    def results(technique):
        if technique == "B":
            return dataclasses.replace(_baseline(403), observations=(
                *_baseline(403).observations,
                {"kind": "sqli_finding", "param": "id", "proof_state": "candidate"},
            ))
        return _baseline(403)

    outcome, calls, _ = _staged(results)
    assert calls == ["U", "B"]
    assert outcome.status == "success" and outcome.refusal is None
    assert any(item.get("kind") == "sqli_finding" for item in outcome.observations)


def test_a_403_challenge_stops_at_once_like_a_401():
    outcome, calls, _ = _staged(lambda _technique: _baseline(403, www_authenticate=True))
    assert calls == ["U"] and outcome.refusal == "authentication_required:403"


def test_the_baseline_record_survives_the_record_cap():
    lines = "\n".join(
        f"[INFO] GET parameter 'id{index}' is vulnerable. Do you want to keep testing?"
        for index in range(agent_tools.MAX_TOOL_RECORDS + 5)
    )
    parsed = agent_tools.parse_scanner_output(
        "sqlmap", lines, wire_log={"baseline": {"status": 401}},
    )
    assert parsed["records"][0]["kind"] == BASELINE_RECORD_KIND
    assert len(parsed["records"]) == agent_tools.MAX_TOOL_RECORDS


def test_the_sqli_proof_reads_a_refused_control_as_inconclusive():
    def run(request_class, status=401):
        transport = _Transport(status)
        adapter = SQLiProofAdapter(
            specification=CAPABILITY_REGISTRY.require("sqli.prove_batch"), target=TARGET,
            request=_request(), transport=transport,
            requested_budget={"http_requests": 12, "tool_wall_seconds": 30},
            candidate={
                "candidate_id": "e" * 64, "method": "GET", "parameter_name": "id",
                "request_class": request_class,
            },
        )
        return asyncio.run(adapter.execute(heartbeat=_noop_heartbeat, cancelled=lambda: False))

    refused = run("safe_read")
    assert refused.status == "partial" and refused.errors[0] == "authentication_required:401"
    assert refused.observations[0]["finding_verdict"] == "inconclusive"
    assert run("safe_read", 403).errors[0] == "target_refused:403"
    login = run("safe_authentication")
    assert "inconclusive_reason" not in login.observations[0]


def test_an_open_redirect_probe_met_by_a_sign_in_redirect_is_inconclusive():
    async def send(_url):
        return 303, {"Location": "/hub/login?next=%2Fhub%2Fgo"}

    proof = asyncio.run(probe_candidate({"url": "https://app.example.test/hub/go?next=x", "parameter": "next"}, send))
    assert proof["proof_state"] == "not_proven"
    assert proof["inconclusive_reason"] == "authentication_required"

    async def answered(_url):
        return 200, {}

    plain = asyncio.run(probe_candidate({"url": "https://app.example.test/go?next=x", "parameter": "next"}, answered))
    assert "inconclusive_reason" not in plain


def test_a_discovered_graphql_route_that_refuses_is_inconclusive_not_absent(monkeypatch):
    def answer(url):
        if urllib.parse.urlsplit(url).path == "/api/hub/graphql":
            return 401, b'{"error":"login required"}'
        return 404, b"<html>Not Found</html>"

    receipt, proofs, transport, *_ = run_graphql_batch(
        monkeypatch, answer, paths=("/api/hub/graphql",),
    )
    assert proofs == []
    assert receipt.status == "partial"
    assert receipt.errors[0] == "authentication_required"
    refused = [
        item for item in receipt.observations
        if item.get("kind") == "candidate_attempt" and item.get("inconclusive_reason")
    ]
    assert len(refused) == 1 and refused[0]["verdict"] == "inconclusive"
    assert any(TYPENAME_QUERY in urllib.parse.unquote(url) for url in transport.sent)


def _body_batch(monkeypatch, path):
    import uuid

    import scan.action_adapter as action_adapter_module
    from runtime.models import ScanPolicy
    from scan.action_plan import ScanActionPlan
    from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest

    from tests.test_scan_action_adapter import Backend, _dispatcher, _lease, _noop
    from tests.test_scan_action_adapter import _action as plan_action

    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "POST", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": path, "concrete_path": path, "query_keys": [],
                "content_type": "application/x-www-form-urlencoded",
                "body_field_names": ["note"], "source": "inputs.custom_endpoints",
            }],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=5,
        allow_state_changing_http=True,
    )
    action = dataclasses.replace(plan_action(
        "verify.sqli.r01", "sqli.verify_batch", 0, capability_args={
            "candidate_manifest_ref": candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
            "slice": {"start": 0, "count": 1},
            "profile": "thorough_batch_v1", "proof_policy": "deterministic_differential_required",
        },
    ), requested_budget={
        "http_requests": 1_600, "state_changing_requests": 1_600, "tool_wall_seconds": 720,
    }, action_digest=None)
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    techniques = []

    async def execute(_self, _context, adapter, **_kwargs):
        techniques.append(adapter._process_payload["scanner_options"]["technique"])
        return _baseline(401)

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    dispatcher = _dispatcher(
        plan, backend, policy=ScanPolicy(
            active_testing=True, allow_state_changing_http=True, approval_receipt_id="approval-1",
        ),
    )
    return asyncio.run(dispatcher(action, _lease(plan, action), _noop)), techniques


def test_a_captured_body_replayed_without_its_session_is_refused_not_negative(monkeypatch):
    receipt, techniques = _body_batch(monkeypatch, "/api/orders")
    assert techniques == ["U"]
    assert receipt.status == "partial" and receipt.errors[0] == "authentication_required"


def test_a_login_form_401_is_still_its_answer(monkeypatch):
    receipt, techniques = _body_batch(monkeypatch, "/hub/login")
    assert techniques == ["U", "B", "E", "T"]
    assert receipt.status == "success"


def test_a_graphql_seed_that_asks_for_credentials_while_the_root_answers_is_inconclusive(monkeypatch):
    import tests.test_graphql_verify_batch as graphql_batch

    class Challenging(graphql_batch._Transport):
        def __init__(self, answer, wall):
            super().__init__(answer)
            self.wall = wall

        async def send(self, request, **kwargs):
            result = await super().send(request, **kwargs)
            path = urllib.parse.urlsplit(request.url).path
            if path == "/graphql" or (self.wall and path == "/"):
                return dataclasses.replace(
                    result, status_code=401, response_headers={"WWW-Authenticate": "Bearer"},
                )
            return result

    # run_graphql_batch builds its transport from _Transport: substitute ours for one run each.
    original = graphql_batch._Transport
    try:
        graphql_batch._Transport = lambda answer: Challenging(answer, False)
        protected = run_graphql_batch(monkeypatch, lambda _url: (200, b"<html>app</html>"), paths=("/app",))[0]
        graphql_batch._Transport = lambda answer: Challenging(answer, True)
        walled = run_graphql_batch(monkeypatch, lambda _url: (200, b"<html>app</html>"), paths=("/app",))[0]
    finally:
        graphql_batch._Transport = original
    assert protected.status == "partial" and protected.errors[0] == "authentication_required"
    assert walled.status == "success", "a site-wide wall keeps the seed 'not GraphQL'"


def test_nosqli_keeps_testing_the_other_fields_after_a_plain_403():
    from capabilities.nosqli_verify import NoSQLiVerifyAdapter

    class PerField(_Transport):
        async def send(self, request, **kwargs):
            result = await super().send(request, **kwargs)
            first = len(self.sent) == 1
            return dataclasses.replace(result, status_code=403 if first else 200, response_headers={})

    transport = PerField(200)
    adapter = NoSQLiVerifyAdapter(
        specification=CAPABILITY_REGISTRY.require("nosqli.verify_batch"), target=TARGET,
        request=_request(url="https://app.example.test/api/orders?id=1&owner=2"),
        transport=transport, requested_budget={"http_requests": 8},
        candidate={"candidate_id": "f" * 64, "method": "GET", "parameter_name": "id",
                   "body_field_names": ["id", "owner"]},
    )
    result = asyncio.run(adapter.execute(heartbeat=_noop_heartbeat, cancelled=lambda: False))
    assert len(transport.sent) == 5, "the second field still gets its four-request differential"
    assert result.observations[0]["inconclusive_reason"] == "target_refused"
    assert "inconclusive_reason" not in result.observations[1]
    assert result.status == "partial" and result.errors[0] == "target_refused:403"
