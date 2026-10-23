"""The in-process checks keep the sign-in endpoint's pace and probe sets too (E1-N6).

Besides sqlmap and Dalfox, five checks send requests to a candidate's endpoint from the worker
itself: the SQLi and XSS request verifiers, the SQLi proof, the NoSQLi check and the XSS browser
proof. On the credential profile's own sign-in endpoint each of their requests waits the
lockout-safe pace, and each check draws from a probe set of its own across the Scan, so what the
endpoint may receive is the sum of the probe sets. The adapters are the real ones over a fake
transport (a unit fixture: a sign-in form that answers every request alike, so nothing proves);
the pace is recorded, not slept; the XSS browser proof's runtime is a stand-in.
"""
from __future__ import annotations

import asyncio
import dataclasses
import re
import types
from pathlib import Path

import pytest
import scan.action_adapter as action_adapter_module
import scan.auth_endpoint_probe as probe_module
from capabilities.nosqli_verify import NoSQLiVerifyAdapter
from capabilities.request_mutation import RequestMutationVerificationAdapter
from capabilities.sqli_proof import SQLiProofAdapter
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy
from runtime.request_replay_executor import ReplayTransportResult
from scan.action_plan import ScanActionPlan
from scan.auth_endpoint_probe import (
    AUTH_ENDPOINT_CHECK_ATTEMPT_REQUESTS,
    AUTH_ENDPOINT_PROBE_LIMITED,
    AUTH_ENDPOINT_PROBE_REQUESTS,
    AUTH_ENDPOINT_SECONDS_PER_REQUEST,
    PacedSignInTransport,
    probe_set_requests,
    sign_in_endpoints,
)
from scan.work_manifests import build_request_candidate_manifest, build_request_manifest

from tests.test_auth_endpoint_probe_limit import LOGIN, ORIGIN, _StoredOnce
from tests.test_form_variant_batch_attempts import BATCHES, _manifests, _signals
from tests.test_scan_action_adapter import TARGET, _action, _dispatcher, _lease, _noop

try:
    from scanner_tools.request_replay import (
        ReplayAuthorization,
        ReplayRequest,
        build_replay_plan,
    )
except ModuleNotFoundError:
    from scanner.scanner_tools.request_replay import (
        ReplayAuthorization,
        ReplayRequest,
        build_replay_plan,
    )

ROOT = Path(__file__).resolve().parents[1]
PACE = AUTH_ENDPOINT_SECONDS_PER_REQUEST
SIGN_IN = {"login_url": LOGIN}
BUDGET = {"http_requests": 600, "state_changing_requests": 600, "tool_wall_seconds": 600}


class _SignInForm:
    """A sign-in form that answers every request alike, so no proof verifies."""

    def __init__(self):
        self.sent: list[tuple[str, str, float]] = []

    async def send(self, request, **kwargs):
        self.sent.append((request.method, request.url, float(kwargs.get("timeout_seconds") or 0)))
        return ReplayTransportResult(
            status_code=200, connected_address="192.0.2.10", final_url=request.url,
            response_headers={"content-type": "text/html"}, response_body=b"<form>sign in</form>",
            elapsed_ms=5,
        )

    def to_sign_in(self):
        return [item for item in self.sent if item[0] == "POST" and item[1].split("?")[0].endswith(LOGIN)]


def _record_pace(monkeypatch):
    waits: list[float] = []

    async def wait(seconds):
        waits.append(seconds)

    monkeypatch.setattr(probe_module, "pace_wait", wait, raising=False)
    return waits


def _fake_target(monkeypatch):
    target = _SignInForm()
    monkeypatch.setattr(
        action_adapter_module.DatabaseNeutralScanActionDispatcher, "_scan_replay_transport",
        lambda _self, _action, **_kwargs: target,
    )
    return target


def _holds(monkeypatch):
    """Every hold an attempt ran with, around the real executor."""
    held: list[dict] = []
    original = action_adapter_module.CapabilityExecutor.execute

    async def execute(self, context, adapter, **kwargs):
        held.append(dict(context.requested_budget))
        return await original(self, context, adapter, **kwargs)

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    return held


def _run(capability, *, options, slices=None, prior=None, budget=BUDGET):
    """The three variants of one sign-in form through ``capability``, one action per slice."""
    _family, verifier = BATCHES[capability]
    scan_id, endpoints, candidates = _manifests()
    refs = {"candidate_manifest_ref": candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoints.reference().canonical_dict()}
    actions, observations = [], {}
    if verifier is not None:
        verify = _action("verify.x.r01", verifier[0], 0,
                         capability_args={**refs, "slice": {"start": 0, "count": 3}})
        actions.append(verify)
        observations[verify.action_id] = _signals(candidates, verifier[1], {0, 1, 2})
    batches = []
    for index, (start, count) in enumerate(slices or [(0, 3)]):
        batch = dataclasses.replace(
            _action(f"batch.x.{index:03d}.r01", capability, len(actions),
                    capability_args={**refs, "slice": {"start": start, "count": count}},
                    dependencies=tuple(item.action_id for item in actions if item.action_id.startswith("verify"))),
            requested_budget={**budget, **({"browser_actions": 30} if capability.startswith("xss.") else {})},
            action_digest=None,
        )
        actions.append(batch)
        batches.append(batch)
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=tuple(actions))
    backend = _StoredOnce(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates},
                          observations=observations)
    for action_id, attempt in prior or ():
        backend.attempts.setdefault(action_id, {})[attempt["attempt_id"]] = attempt
    dispatcher = _dispatcher(plan, backend, options=options, policy=ScanPolicy(
        active_testing=True, allow_state_changing_http=True, approval_receipt_id="approval-1",
    ))
    receipts = [asyncio.run(dispatcher(batch, _lease(plan, batch), _noop)) for batch in batches]
    return receipts, candidates


def _heads(receipts):
    return [item for receipt in receipts for item in receipt.observations
            if item.get("kind") == "candidate_attempt"]


# --- what each check sends at most ---------------------------------------------------------------

def _proof_request(method, url, body=b"", content_type=None):
    headers = (("Content-Type", content_type),) if content_type else ()
    return ReplayRequest(request_id="r1", ordinal=1, name="n", folder="", method=method, url=url,
                         headers=headers, body=body, body_mode="raw" if body else "none",
                         auth_type="none", has_sensitive_material=False)


def _sends(adapter_type, request, candidate, budget):
    target = _SignInForm()
    adapter = adapter_type(specification=CAPABILITY_REGISTRY.require(adapter_type.capability_name),
                           target=TARGET, request=request, candidate=candidate, transport=target,
                           requested_budget=budget)

    async def heartbeat():
        return None

    asyncio.run(adapter.execute(heartbeat=heartbeat, cancelled=lambda: False))
    return len(target.sent)


def test_the_check_attempt_sizes_are_what_the_checks_send():
    """The probe sets are twice these; each is what one attempt sends when nothing proves."""
    ample = {"http_requests": 50, "state_changing_requests": 50, "tool_wall_seconds": 60}
    form = b"username=shakerscan&password=shakerscan"
    query = _proof_request("GET", f"{ORIGIN}/search?q=1")
    assert _sends(SQLiProofAdapter, query, {"candidate_id": "c" * 64, "method": "GET",
                                            "parameter_name": "q", "request_class": "safe_read"},
                  ample) == AUTH_ENDPOINT_CHECK_ATTEMPT_REQUESTS["sqli.prove_batch"] == 14
    sign_in = _proof_request("POST", f"{ORIGIN}{LOGIN}", form, "application/x-www-form-urlencoded")
    assert _sends(SQLiProofAdapter, sign_in, {"candidate_id": "c" * 64, "method": "POST",
                                              "field_path": "username",
                                              "request_class": "safe_authentication"}, ample) == 8
    assert _sends(NoSQLiVerifyAdapter, sign_in, {
        "candidate_id": "c" * 64, "method": "POST", "parameter_name": "username",
        "body_field_names": ["username", "password"],
    }, ample) == 2 * AUTH_ENDPOINT_CHECK_ATTEMPT_REQUESTS["nosqli.verify_batch"]
    for capability in ("sqli.request_verify_batch", "xss.request_verify_batch"):
        target = _SignInForm()
        adapter = RequestMutationVerificationAdapter(
            specification=CAPABILITY_REGISTRY.require(capability), target=TARGET, request=sign_in,
            candidate={"candidate_id": "c" * 64, "request_ref_id": "r1", "method": "POST",
                       "family_hints": ["xss", "sqli"], "field_path": "username",
                       "request_class": "safe_authentication"},
            transport=target, requested_budget=ample,
        )

        async def heartbeat():
            return None

        asyncio.run(adapter.execute(heartbeat=heartbeat, cancelled=lambda: False))
        assert len(target.sent) == AUTH_ENDPOINT_CHECK_ATTEMPT_REQUESTS[capability] == 2
    assert AUTH_ENDPOINT_CHECK_ATTEMPT_REQUESTS["xss.browser_prove_batch"] == 1


def test_the_documented_bound_is_the_sum_of_the_largest_probe_sets():
    sets = {name: probe_set_requests(name, 4) for name in AUTH_ENDPOINT_PROBE_REQUESTS}
    assert sets == {
        "sqli.verify_batch": 3_784, "xss.verify_batch": 256, "sqli.prove_batch": 112,
        "nosqli.verify_batch": 32, "sqli.request_verify_batch": 16, "xss.request_verify_batch": 16,
        "xss.browser_prove_batch": 8,
    }
    assert sum(sets.values()) == 4_224
    # At 20 a minute: 3 h 31 min.
    assert divmod(sum(sets.values()) * PACE // 60, 60) == (3, 31)
    release = (ROOT / "docs/releases/2.11.1.md").read_text(encoding="utf-8")
    docstring = probe_module.__doc__ or ""
    for text in (release, docstring):
        flat = re.sub(r"\s+", " ", text)
        assert "4,224" in flat and "4,040" not in flat


# --- the transport -------------------------------------------------------------------------------

def test_the_paced_transport_waits_before_each_request_to_the_endpoint_only(monkeypatch):
    waits = _record_pace(monkeypatch)
    (endpoint,) = sign_in_endpoints(SIGN_IN, [], base_url=f"{ORIGIN}/")
    inner = _SignInForm()
    paced = PacedSignInTransport(inner, endpoint, pace_seconds=PACE)

    async def run():
        for request in (_proof_request("POST", f"{ORIGIN}{LOGIN}", b"a=1", "application/x-www-form-urlencoded"),
                        _proof_request("GET", f"{ORIGIN}{LOGIN}?next=1"),
                        _proof_request("POST", f"{ORIGIN}/api/feedback", b"a=1", "application/x-www-form-urlencoded"),
                        _proof_request("POST", f"{ORIGIN}/hub/Login/", b"a=1", "application/x-www-form-urlencoded")):
            await paced.send(request, target=TARGET, timeout_seconds=10.0, follow_redirects=False)

    asyncio.run(run())
    assert waits == [PACE, PACE] and paced.sent == 2
    # The wait comes out of the request's own timeout, so the attempt keeps to its wall.
    assert [timeout for _method, _url, timeout in inner.sent] == [10.0 - PACE, 10.0, 10.0, 10.0 - PACE]


# --- the batches ---------------------------------------------------------------------------------

@pytest.mark.parametrize("capability", ["sqli.prove_batch", "nosqli.verify_batch"])
def test_every_request_a_check_sends_the_sign_in_endpoint_waits_the_pace(monkeypatch, capability):
    waits = _record_pace(monkeypatch)
    target = _fake_target(monkeypatch)
    held = _holds(monkeypatch)
    receipts, _candidates = _run(capability, options=SIGN_IN)
    sent = target.to_sign_in()
    assert sent and len(waits) == len(sent) and set(waits) == {PACE}
    heads = [head for head in _heads(receipts) if head.get("sign_in_endpoint")]
    assert {head["sign_in_endpoint"] for head in heads} == {LOGIN}
    assert sum(head["sign_in_endpoint_requests"] for head in heads) == len(sent)
    assert heads[-1]["sign_in_endpoint_received"] == len(sent) <= probe_set_requests(capability, 4)
    # Each attempt holds a pace and a second for every request it may send.
    assert held and all(
        hold["tool_wall_seconds"] >= hold["http_requests"] * (PACE + 1) for hold in held
    )


def test_the_nosqli_check_stops_at_its_probe_set_and_never_reads_negative(monkeypatch):
    """Four requests a field: the declared form sends 8 and the crawled form 16 of the 32 the
    four-field set holds; the JSON variant's two-field set (16) is then spent."""
    _record_pace(monkeypatch)
    target = _fake_target(monkeypatch)
    receipts, _candidates = _run("nosqli.verify_batch", options=SIGN_IN)
    heads = _heads(receipts)
    assert [head["sign_in_endpoint_requests"] for head in heads] == [8, 16, 0]
    assert len(target.to_sign_in()) == 24
    closed = heads[2]
    assert closed["verdict"] == "inconclusive"
    assert closed["inconclusive_reason"] == AUTH_ENDPOINT_PROBE_LIMITED
    assert closed["sign_in_endpoint_received"] == 24


def test_a_later_action_of_the_check_draws_from_what_the_endpoint_already_received(monkeypatch):
    _record_pace(monkeypatch)
    target = _fake_target(monkeypatch)
    receipts, _candidates = _run("sqli.prove_batch", options=SIGN_IN, slices=[(0, 1), (1, 2)])
    first, second = ([head for head in receipt.observations if head.get("kind") == "candidate_attempt"]
                     for receipt in receipts)
    assert [head["sign_in_endpoint_received"] for head in first] == [8]
    assert [head["sign_in_endpoint_received"] for head in second] == [16, 24]
    assert len(target.to_sign_in()) == 24


def test_a_spent_proof_set_closes_every_variant_without_a_request(monkeypatch):
    """An earlier proof action spent the four-field set: nothing more is sent, each variant is
    inconclusive for the limit, and the family names it."""
    from api.scan.action_plan import ScanActionPlan as PackagePlan
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_finalizer import _result_with_observation_count
    from tests.test_scan_orchestrator import SCAN_ID
    from tests.test_scan_orchestrator import _action as plan_action

    _record_pace(monkeypatch)
    target = _fake_target(monkeypatch)
    (endpoint,) = sign_in_endpoints(SIGN_IN, [], base_url=f"{ORIGIN}/")
    spent = {"attempt_id": "e" * 64, "candidate_id": "e" * 64, "status": "success",
             "observations": ({"kind": "candidate_attempt", "sign_in_endpoint_key": endpoint.key,
                               "sign_in_endpoint_requests": probe_set_requests("sqli.prove_batch", 4)},)}
    receipts, _candidates = _run("sqli.prove_batch", options=SIGN_IN, slices=[(0, 3), (0, 3)],
                                 prior=[("batch.x.000.r01", spent)])
    assert target.to_sign_in() == []
    heads = [head for head in receipts[1].observations if head.get("kind") == "candidate_attempt"]
    assert len(heads) == 3 and all(
        head["verdict"] == "inconclusive" and head["inconclusive_reason"] == AUTH_ENDPOINT_PROBE_LIMITED
        for head in heads
    )
    rows = tuple(receipts[1].observations)
    proof = dataclasses.replace(
        plan_action("prove.sqli.r01", 0, capability_name="sqli.prove_batch"),
        capability_args={"slice": {"start": 0, "count": 3}, "manifest_entries": 3},
        output_schema="sqli-proof-batch/v1", action_digest=None,
    )
    final = plan_action("finalize.report", 1, dependencies=(proof.action_id,))
    plan = PackagePlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                       target_binding_digest="a" * 64, actions=(proof, final))
    report = finalize_scan_report(
        plan=plan, target_url=ORIGIN,
        action_results={proof.action_id: _result_with_observation_count(proof, len(rows))},
        observations={proof.action_id: rows},
    )
    family = next(row for row in report["coverage"]["family_coverage"] if row["family"] == "sqli")
    assert family["sign_in_probe_limited"] == {"endpoints": [LOGIN], "candidates": 3}
    assert AUTH_ENDPOINT_PROBE_LIMITED in report["coverage"]["reasons"]


def test_the_browser_proof_waits_the_pace_before_each_submission(monkeypatch):
    waits = _record_pace(monkeypatch)

    async def execute(_self, context, adapter, **_kwargs):
        return types.SimpleNamespace(
            status="success", timed_out=False, errors=(),
            observations=({"kind": "xss_browser_proof", "proof_state": "not_proven"},),
            actual_budget={"browser_actions": 2, "http_requests": 3, "state_changing_requests": 1,
                           "tool_wall_seconds": 2},
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    receipts, _candidates = _run("xss.browser_prove_batch", options=SIGN_IN)
    heads = _heads(receipts)
    assert waits == [PACE] * 3
    assert [head["sign_in_endpoint_requests"] for head in heads] == [1, 1, 1]
    assert [head["sign_in_endpoint_received"] for head in heads] == [1, 2, 3]


@pytest.mark.parametrize("capability", ["sqli.request_verify_batch", "xss.request_verify_batch"])
def test_the_request_verifiers_pace_the_sign_in_request_of_the_profile(monkeypatch, capability):
    """The profile's own sign-in request, mutated field by field: each request waits the pace."""
    waits = _record_pace(monkeypatch)
    target = _fake_target(monkeypatch)
    request = build_replay_plan(
        ({"id": "credential-login:primary", "method": "POST", "url": f"{ORIGIN}{LOGIN}",
          "headers": {"Content-Type": "application/json"},
          "body": '{"username":"unit-fixture","password":"unit-fixture"}',
          "body_mode": "application/json", "auth_type": "none", "has_sensitive_material": True},),
        allowed_origins=TARGET.allowed_origins,
        authorization=ReplayAuthorization(active_testing=True, allow_state_changing_http=True,
                                          approval_receipt_id="credential-workflow"),
    ).requests[0]
    scan_id, _endpoints, _candidates = _manifests()
    request_manifest = build_request_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest, source_action_ids=("inputs.auth_primary",),
        requests=({"request_ref_id": request.request_id, "route_id": "d" * 64, "method": "POST",
                   "auth_lane": "primary", "selected_shard": None, "request_class": "safe_authentication",
                   "content_type": "application/json", "body_field_names": ["username", "password"],
                   "selection_digest": "e" * 64, "body_schema_digest": "f" * 64},),
    )
    candidates = build_request_candidate_manifest((request_manifest,), source_action_ids=("inputs.auth_primary",),
                                                  maximum=10)
    action = dataclasses.replace(_action("verify.request.r01", capability, 0, capability_args={
        "request_candidate_manifest_ref": candidates.reference().canonical_dict(),
        "slice": {"start": 0, "count": 2}, "profile": "balanced_batch_v1",
        "proof_policy": "deterministic_differential_required",
    }), requested_budget=dict(BUDGET), action_digest=None)
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    dispatcher = _dispatcher(plan, _StoredOnce(manifests={candidates.manifest_id: candidates}),
                             options=SIGN_IN, policy=ScanPolicy(active_testing=True,
                                                                approval_receipt_id="approval-1"))
    dispatcher._private_requests[request.request_id] = request
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    heads = [item for item in receipt.observations if item.get("kind") == "candidate_attempt"]
    assert len(target.to_sign_in()) == 4 and waits == [PACE] * 4
    assert [head["sign_in_endpoint_requests"] for head in heads] == [2, 2]
    assert heads[-1]["sign_in_endpoint_received"] == 4


@pytest.mark.parametrize("capability", sorted(BATCHES))
def test_without_a_sign_in_profile_nothing_waits_and_holds_are_unchanged(monkeypatch, capability):
    waits = _record_pace(monkeypatch)
    if capability == "xss.browser_prove_batch":
        async def execute(_self, context, adapter, **_kwargs):
            return types.SimpleNamespace(
                status="success", timed_out=False, errors=(), observations=(),
                actual_budget={"browser_actions": 2, "state_changing_requests": 1, "tool_wall_seconds": 2},
            )

        monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
        held = None
    else:
        _fake_target(monkeypatch)
        held = _holds(monkeypatch)
    receipts, _candidates = _run(capability, options={})
    assert waits == []
    assert not any(head.get("sign_in_endpoint") for head in _heads(receipts))
    if held is not None:
        # The first attempt's share of the slice: a third of it, as before.
        assert held[0]["tool_wall_seconds"] == BUDGET["tool_wall_seconds"] // 3
        assert held[0]["http_requests"] == BUDGET["http_requests"] // 3
