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
import itertools
import re
import sys
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
    AUTH_ENDPOINT_PACE_UNFUNDED,
    AUTH_ENDPOINT_PROBE_LIMITED,
    AUTH_ENDPOINT_PROBE_REQUESTS,
    AUTH_ENDPOINT_SECONDS_PER_REQUEST,
    PacedSignInTransport,
    probe_set_requests,
    sign_in_endpoints,
)
from scan.work_manifests import build_request_candidate_manifest, build_request_manifest

from tests.test_auth_endpoint_probe_limit import (
    LOGIN,
    ORIGIN,
    SIGN_IN_ROUTES,
    _StoredOnce,
)
from tests.test_form_variant_batch_attempts import BATCHES, _manifests, _report, _signals
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
        "nosqli.verify_batch": 96, "sqli.request_verify_batch": 48, "xss.request_verify_batch": 48,
        "xss.browser_prove_batch": 8,
    }
    assert sum(sets.values()) == 4_352
    # At 20 a minute: about 3 h 38 min.
    assert divmod(round(sum(sets.values()) * PACE / 60), 60) == (3, 38)
    release = (ROOT / "docs/releases/2.11.1.md").read_text(encoding="utf-8")
    docstring = probe_module.__doc__ or ""
    for text in (release, docstring):
        flat = re.sub(r"\s+", " ", text)
        assert "4,352" in flat and "3 h 38 min" in flat
        assert "4,224" not in flat and "4,040" not in flat
        # What the bound leaves out is stated: the active templates are not paced or counted.
        assert "default-login" in flat


#: What each check sends to a four-field variant: the proof's longest proof, the NoSQLi check's
#: four a field, a request verifier's control and mutation for each of four field candidates, the
#: browser proof's one submission.
_FOUR_FIELD_ATTEMPT = {"sqli.prove_batch": 14, "nosqli.verify_batch": 16,
                       "sqli.request_verify_batch": 8, "xss.request_verify_batch": 8,
                       "xss.browser_prove_batch": 1}


@pytest.mark.parametrize("capability", sorted(AUTH_ENDPOINT_CHECK_ATTEMPT_REQUESTS))
def test_each_check_set_holds_the_three_variants_of_a_sign_in_form_twice(capability):
    """The declared form, the crawled form with its hidden fields and a JSON variant draw from one
    set: it holds an attempt of each, at four fields, twice over."""
    assert probe_module.AUTH_ENDPOINT_FORM_VARIANTS == 3
    assert probe_set_requests(capability, 4) >= (
        probe_module.AUTH_ENDPOINT_PROBE_HEADROOM * probe_module.AUTH_ENDPOINT_FORM_VARIANTS
        * _FOUR_FIELD_ATTEMPT[capability]
    )


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
    # One before each request, and one after the action's last (_SignInChecks.settle).
    assert sent and len(waits) == len(sent) + 1 and set(waits) == {PACE}
    heads = [head for head in _heads(receipts) if head.get("sign_in_endpoint")]
    assert {head["sign_in_endpoint"] for head in heads} == {LOGIN}
    assert sum(head["sign_in_endpoint_requests"] for head in heads) == len(sent)
    assert heads[-1]["sign_in_endpoint_received"] == len(sent) <= probe_set_requests(capability, 4)
    # Each attempt holds a pace and a second for every request it may send.
    assert held and all(
        hold["tool_wall_seconds"] >= hold["http_requests"] * (PACE + 1) for hold in held
    )


def test_the_nosqli_check_stops_at_its_probe_set_and_never_reads_negative(monkeypatch):
    """Four requests a field: the three variants send 8, 16 and 8 a round, three rounds spend the
    96 the endpoint's set holds, and a fourth closes every variant without a request."""
    _record_pace(monkeypatch)
    target = _fake_target(monkeypatch)
    receipts, _candidates = _run("nosqli.verify_batch", options=SIGN_IN, slices=[(0, 3)] * 4)
    sent = [[head["sign_in_endpoint_requests"] for head in _heads([receipt])] for receipt in receipts]
    assert sent == [[8, 16, 8], [8, 16, 8], [8, 16, 8], [0, 0, 0]]
    assert len(target.to_sign_in()) == 96 == probe_set_requests("nosqli.verify_batch", 4)
    closed = _heads(receipts[3:])
    assert all(head["verdict"] == "inconclusive" for head in closed)
    assert {head["inconclusive_reason"] for head in closed} == {AUTH_ENDPOINT_PROBE_LIMITED}
    assert {head["sign_in_endpoint_received"] for head in closed} == {96}


def test_a_check_its_set_leaves_short_sends_only_what_is_left_and_is_inconclusive(monkeypatch):
    """88 of the 96 the NoSQLi set holds were sent by an earlier action: the crawled form's attempt
    holds the 8 left, tests two of its four fields and is never read negative."""
    _record_pace(monkeypatch)
    target = _fake_target(monkeypatch)
    (endpoint,) = sign_in_endpoints(SIGN_IN, [], base_url=f"{ORIGIN}/")
    earlier = {"attempt_id": "e" * 64, "candidate_id": "e" * 64, "status": "success",
               "observations": ({"kind": "candidate_attempt", "sign_in_endpoint_key": endpoint.key,
                                 "sign_in_endpoint_requests": 88},)}
    receipts, candidates = _run("nosqli.verify_batch", options=SIGN_IN, slices=[(1, 1)],
                                prior=[("batch.x.000.r01", earlier)])
    assert len(candidates.entries[1]["body_field_names"]) == 4
    (head,) = [item for item in receipts[0].observations if item.get("kind") == "candidate_attempt"]
    assert head["sign_in_endpoint_requests"] == 8 and head["sign_in_endpoint_received"] == 96
    assert head["verdict"] == "inconclusive"
    assert head["inconclusive_reason"] == AUTH_ENDPOINT_PROBE_LIMITED
    assert len(target.to_sign_in()) == 8


_VARIANT_SHAPES = ((["password", "username"], "application/x-www-form-urlencoded"),
                   (["csrf_token", "password", "remember", "username"], "application/x-www-form-urlencoded"),
                   (["password", "username"], "application/json"))


@pytest.mark.parametrize("sources", list(itertools.permutations(
    ("inputs.custom_endpoints", "web.crawl", "web.spec_ingest"),
)))
def test_a_fresh_scan_tests_every_variant_of_the_sign_in_form_in_any_order(monkeypatch, sources):
    """The set is the endpoint's, not the variant's: whichever variant the manifest puts first, the
    three send their whole NoSQLi attempts. A two-field variant's own set (16) was spent by the
    crawled form's 16, so on a fresh scan up to two variants were closed without a request."""
    from tests.test_form_variant_batch_attempts import _manifests as variant_manifests

    _record_pace(monkeypatch)
    target = _fake_target(monkeypatch)
    routes = tuple(("POST", LOGIN, fields, content_type, [], source)
                   for (fields, content_type), source in zip(_VARIANT_SHAPES, sources))
    monkeypatch.setattr(sys.modules[__name__], "_manifests", lambda: variant_manifests(routes))
    receipts, candidates = _run("nosqli.verify_batch", options=SIGN_IN)
    heads = _heads(receipts)
    assert [head["sign_in_endpoint_requests"] for head in heads] == [
        4 * len(entry["body_field_names"]) for entry in candidates.entries
    ]
    assert not [head for head in heads if head.get("inconclusive_reason")]
    assert len(target.to_sign_in()) == 32 and receipts[0].status == "success"


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
    family, report = _report(
        "sqli", ("sqli.prove_batch", receipts[1].observations, "success", (0, 3, 3)),
    )
    assert family["sign_in_probe_limited"] == {"endpoints": [LOGIN], "candidates": 3}
    assert AUTH_ENDPOINT_PROBE_LIMITED in report["coverage"]["reasons"]


# --- an attempt the slice's wall cannot pace in full --------------------------------------------

class _PacedClock:
    """The pace consumes wall: each pace wait advances a fake clock by its seconds and each answer
    of the sign-in form by 0.2 s, and the checks read their elapsed wall from that clock."""

    def __init__(self, monkeypatch):
        import capabilities.nosqli_verify as nosqli_module
        import capabilities.sqli_proof as proof_module

        self.now = 1_000.0
        clock = types.SimpleNamespace(monotonic=lambda: self.now)
        for module in (proof_module, nosqli_module):
            monkeypatch.setattr(module, "time", clock)

        async def wait(seconds):
            self.now += float(seconds)

        monkeypatch.setattr(probe_module, "pace_wait", wait, raising=False)
        form = _SignInForm()
        original = form.send

        async def send(request, **kwargs):
            self.now += 0.2
            return await original(request, **kwargs)

        form.send = send
        self.target = form
        monkeypatch.setattr(
            action_adapter_module.DatabaseNeutralScanActionDispatcher, "_scan_replay_transport",
            lambda _self, _action, **_kwargs: form,
        )


def _proof_report(candidates, proof_rows, status):
    """The SQLi family over a verifier that flagged all three variants and the proof action."""
    return _report(
        "sqli", ("sqli.verify_batch", _signals(candidates, "sqli", {0, 1, 2}), "success", (0, 3, 3)),
        ("sqli.prove_batch", proof_rows, status, (0, 3, 3)),
    )


#: A sign-in form's proof is an error pair and a bypass pair (8 requests); a sign-in endpoint
#: whose path names no sign-in runs the error, boolean and timing pairs (14).
NOT_A_SIGN_IN_PATH = "/hub/enter"


def _routes_at(path):
    return tuple((method, path, fields, content_type, query, source)
                 for method, _path, fields, content_type, query, source in SIGN_IN_ROUTES[:3])


@pytest.mark.parametrize(("path", "proof"), [(LOGIN, 8), (NOT_A_SIGN_IN_PATH, 14)])
@pytest.mark.parametrize("short_by", [1, 4])
def test_a_proof_the_wall_cannot_pace_in_full_waits_instead_of_running_short(
    monkeypatch, path, proof, short_by,
):
    """The slice's wall paces fewer requests than the proof sends (one pace and one second each):
    the proof waits, sends nothing, and never reads complete. Cutting a sign-in form's proof to its
    error pair would never send the bypass pair that proves a blind sign-in injection."""
    from tests.test_form_variant_batch_attempts import _manifests as variant_manifests

    _PacedClock(monkeypatch)
    held = _holds(monkeypatch)
    monkeypatch.setattr(sys.modules[__name__], "_manifests",
                        lambda: variant_manifests(_routes_at(path)))
    wall = (proof - short_by) * (PACE + 1) + PACE
    receipts, candidates = _run("sqli.prove_batch", options={"login_url": path}, budget={
        "http_requests": 600, "state_changing_requests": 600, "tool_wall_seconds": wall,
    })
    (receipt,) = receipts
    deferred = [item for item in receipt.observations if item.get("kind") == "candidate_deferred"]
    assert held == [] and _heads(receipts) == []
    assert len(deferred) == 3 and {item["reason"] for item in deferred} == {AUTH_ENDPOINT_PACE_UNFUNDED}
    assert receipt.status == "partial"
    family, report = _proof_report(candidates, receipt.observations, "partial")
    assert family["proof_escalation"]["status"] != "complete"
    assert family["coverage_status"] == "partial"
    assert family["reason"] == AUTH_ENDPOINT_PROBE_LIMITED
    assert family["sign_in_probe_limited"] == {"endpoints": [path], "candidates": 3}
    assert AUTH_ENDPOINT_PROBE_LIMITED in report["coverage"]["reasons"]


@pytest.mark.parametrize(("wall", "sent"), [(48, [8]), (72, [8, 8]), (100, [8, 8, 8])])
def test_the_wall_the_pace_consumes_funds_whole_proofs_and_leaves_the_rest_waiting(
    monkeypatch, wall, sent,
):
    """With the pace taking its seconds from the slice: each proof that runs sends all 8 of its
    requests, the slice's wall funds as many as it can pace, and the others wait. A proof the wall
    cut to its error pair was recorded as a finished proof, and the report read it complete."""
    clock = _PacedClock(monkeypatch)
    held = _holds(monkeypatch)
    receipts, candidates = _run("sqli.prove_batch", options=SIGN_IN, budget={
        "http_requests": 24, "state_changing_requests": 24, "tool_wall_seconds": wall,
    })
    (receipt,) = receipts
    heads = _heads(receipts)
    assert [head["sign_in_endpoint_requests"] for head in heads] == sent
    assert len(clock.target.to_sign_in()) == sum(sent)
    assert all(hold["http_requests"] >= 8 for hold in held)
    deferred = [item for item in receipt.observations if item.get("kind") == "candidate_deferred"]
    assert len(deferred) == 3 - len(sent)
    assert receipt.status == ("success" if len(sent) == 3 else "partial")
    family, _report_ = _proof_report(candidates, receipt.observations, receipt.status)
    if len(sent) == 3:
        assert family["coverage_status"] == "complete"
        assert family["proof_escalation"]["status"] == "complete"
    else:
        assert family["coverage_status"] == "partial"
        assert family["sign_in_probe_limited"]["candidates"] == 3 - len(sent)


@pytest.mark.parametrize("capability", ["sqli.prove_batch", "nosqli.verify_batch"])
@pytest.mark.parametrize("wall", [8, 12, 20, 31, 40])
def test_no_hold_on_the_sign_in_endpoint_outlasts_what_the_slice_has_left(monkeypatch, capability, wall):
    """Every attempt that runs holds no more wall than the slice has left, sends what it needs in
    full (a NoSQLi attempt four a field), and one the slice cannot pace waits."""
    from tests.test_form_variant_batch_attempts import _attempt_ids

    clock = _PacedClock(monkeypatch)
    held = _holds(monkeypatch)
    receipts, candidates = _run(capability, options=SIGN_IN, budget={
        "http_requests": 600, "state_changing_requests": 600, "tool_wall_seconds": wall,
    })
    heads = _heads(receipts)
    deferred = [item for receipt in receipts for item in receipt.observations
                if item.get("kind") == "candidate_deferred"]
    assert len(heads) + len(deferred) == 3
    entry_of = dict(zip(_attempt_ids(candidates, BATCHES[capability][0]), candidates.entries))
    ran = [head for head in heads if head.get("budget_consumed")]
    assert len(ran) == len(held)
    spent = 0
    for hold, head in zip(held, ran):
        assert hold["tool_wall_seconds"] <= wall - spent
        assert hold["tool_wall_seconds"] >= hold["http_requests"] * (PACE + 1)
        # What the attempt needs in full, never fewer: a sign-in form's proof 8, NoSQLi four a field.
        fields = entry_of[head["attempt_id"]]["body_field_names"]
        assert head["sign_in_endpoint_requests"] == (
            8 if capability == "sqli.prove_batch" else 4 * len(fields)
        )
        spent += int(head["budget_consumed"]["tool_wall_seconds"])
    for head in heads:
        if head not in ran:
            assert head["sign_in_endpoint_requests"] == 0
            assert head["inconclusive_reason"] == AUTH_ENDPOINT_PROBE_LIMITED
    assert len(clock.target.to_sign_in()) == sum(head["sign_in_endpoint_requests"] for head in heads)
    if wall < 8 * (PACE + 1):
        assert heads == [] and len(deferred) == 3


def test_the_paced_hold_funds_the_whole_attempt_or_nothing():
    """The slice's request share and its wall at a pace and a second a request must reach the
    attempt's need; the probe set alone may leave it short (the batch then marks it inconclusive)."""
    budget = {"http_requests": 200, "state_changing_requests": 200, "tool_wall_seconds": 60}
    hold = probe_module.paced_check_hold(
        budget, capability_name="sqli.prove_batch", received=0, parameters=4,
        available_wall_seconds=32, need=8,
    )
    assert hold is not None and hold["http_requests"] == 8 and hold["tool_wall_seconds"] == 32
    for available in (16, 28, 31):
        assert probe_module.paced_check_hold(
            budget, capability_name="sqli.prove_batch", received=0, parameters=4,
            available_wall_seconds=available, need=8,
        ) is None
    assert probe_module.paced_check_hold(
        budget, capability_name="sqli.prove_batch", received=0, parameters=4,
        available_wall_seconds=55, need=14,
    ) is None
    # A split Scan paces slower: the same wall funds half as many requests.
    assert probe_module.paced_check_hold(
        budget, capability_name="sqli.prove_batch", received=0, parameters=4, children=2,
        available_wall_seconds=55, need=8,
    ) is None
    # The probe set leaves 5: the attempt runs with them, short of its need.
    left = probe_module.probe_set_requests("sqli.prove_batch", 4) - 5
    short = probe_module.paced_check_hold(
        budget, capability_name="sqli.prove_batch", received=left, parameters=4,
        available_wall_seconds=60, need=8,
    )
    assert short is not None and short["http_requests"] == 5


def test_a_variant_its_verifier_and_its_proof_both_left_limited_is_one_candidate(monkeypatch):
    """Dalfox ends inconclusive on each of the three variants, and the browser proof's spent set
    closes each of them again: three candidates, not six. The verifier's and the proof's attempt
    ids of one variant differ (each names its family), so counting attempt ids counted each
    variant once per check."""
    from tests.test_auth_endpoint_probe_limit import XSS, _slice

    verified, _rounds, _record = _slice(XSS[0], tool=XSS[1], parser=XSS[2], sent=10_000,
                                        options=SIGN_IN, routes=SIGN_IN_ROUTES[:3])
    verifier_rows = verified[0].observations
    assert len([head for head in verifier_rows if head.get("inconclusive_reason")
                == AUTH_ENDPOINT_PROBE_LIMITED]) == 3
    _record_pace(monkeypatch)
    (endpoint,) = sign_in_endpoints(SIGN_IN, [], base_url=f"{ORIGIN}/")
    spent = {"attempt_id": "e" * 64, "candidate_id": "e" * 64, "status": "success",
             "observations": ({"kind": "candidate_attempt", "sign_in_endpoint_key": endpoint.key,
                               "sign_in_endpoint_requests": probe_set_requests("xss.browser_prove_batch", 4)},)}
    receipts, _candidates = _run("xss.browser_prove_batch", options=SIGN_IN,
                                 prior=[("batch.x.000.r01", spent)])
    proof_rows = receipts[0].observations
    assert len([head for head in _heads(receipts) if head.get("inconclusive_reason")
                == AUTH_ENDPOINT_PROBE_LIMITED]) == 3
    family, _report_ = _report(
        "xss", ("xss.verify_batch", verifier_rows, "success", (0, 3, 3)),
        ("xss.browser_prove_batch", proof_rows, "success", (0, 3, 3)),
    )
    assert family["sign_in_probe_limited"] == {"endpoints": [LOGIN], "candidates": 3}


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
    # One before each submission, and one after the action's last.
    assert waits == [PACE] * 4
    assert [head["sign_in_endpoint_requests"] for head in heads] == [1, 1, 1]
    assert [head["sign_in_endpoint_received"] for head in heads] == [1, 2, 3]


def _browser_proof(monkeypatch, *, wall=2):
    """The browser runtime is a stand-in: one submission and ``wall`` seconds an attempt; the
    holds it ran with are recorded."""
    held: list[dict] = []

    async def execute(_self, context, adapter, **_kwargs):
        held.append(dict(context.requested_budget))
        return types.SimpleNamespace(
            status="success", timed_out=False, errors=(),
            observations=({"kind": "xss_browser_proof", "proof_state": "not_proven"},),
            actual_budget={"browser_actions": 2, "http_requests": 3, "state_changing_requests": 1,
                           "tool_wall_seconds": wall},
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    return held


def test_the_browser_proof_pace_comes_out_of_its_wall_and_is_charged(monkeypatch):
    """The wait before the submission ran outside the attempt: neither held against what the slice
    had left nor charged, so each sign-in variant could run a pace past the action's wall."""
    _record_pace(monkeypatch)
    held = _browser_proof(monkeypatch, wall=2)
    budget = {"http_requests": 300, "state_changing_requests": 300, "tool_wall_seconds": 90}
    receipts, _candidates = _run("xss.browser_prove_batch", options=SIGN_IN, budget=budget)
    (receipt,) = receipts
    # Each attempt's share of what the slice has left (2 s and the pace charged per attempt),
    # less the pace it waits first.
    assert [hold["tool_wall_seconds"] for hold in held] == [
        (90 - index * (2 + PACE)) // (3 - index) - PACE for index in range(3)
    ]
    heads = _heads(receipts)
    assert [head["budget_consumed"]["tool_wall_seconds"] for head in heads] == [2 + PACE] * 3
    # And the pace after the last submission.
    assert receipt.budget_consumed["tool_wall_seconds"] == 3 * (2 + PACE) + PACE


def test_a_browser_proof_whose_share_cannot_hold_the_pace_waits(monkeypatch):
    """A slice of one pace: no attempt's share holds the wait and a second of browser time."""
    waits = _record_pace(monkeypatch)
    held = _browser_proof(monkeypatch)
    budget = {"http_requests": 300, "state_changing_requests": 300, "tool_wall_seconds": PACE}
    receipts, candidates = _run("xss.browser_prove_batch", options=SIGN_IN, budget=budget)
    (receipt,) = receipts
    deferred = [item for item in receipt.observations if item.get("kind") == "candidate_deferred"]
    assert held == [] and waits == [] and _heads(receipts) == []
    assert len(deferred) == 3 and {item["reason"] for item in deferred} == {AUTH_ENDPOINT_PACE_UNFUNDED}
    assert receipt.status == "partial"


def test_browser_proofs_over_many_actions_stop_at_the_endpoint_set(monkeypatch):
    """Ten proof actions over the three variants (thirty attempts): the endpoint receives the 8
    submissions its set holds, and every later attempt is closed without one."""
    waits = _record_pace(monkeypatch)
    _browser_proof(monkeypatch)
    receipts, _candidates = _run("xss.browser_prove_batch", options=SIGN_IN, slices=[(0, 3)] * 10)
    heads = _heads(receipts)
    assert len(heads) == 30
    sending = [receipt for receipt in receipts
               if any(head["sign_in_endpoint_requests"] for head in _heads([receipt]))]
    assert sum(head["sign_in_endpoint_requests"] for head in heads) == 8
    assert len(waits) == 8 + len(sending)
    assert probe_set_requests("xss.browser_prove_batch", 4) == 8
    closed = [head for head in heads if not head["sign_in_endpoint_requests"]]
    assert len(closed) == 22 and {head["inconclusive_reason"] for head in closed} == {
        AUTH_ENDPOINT_PROBE_LIMITED,
    }


def _request_verifiers(capability, *, prior=()):
    """The request verifier over the profile's own two-field sign-in request: one action, after
    ``prior`` actions of the same verifier that recorded (attempt id, what they sent there)."""
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
    args = {"request_candidate_manifest_ref": candidates.reference().canonical_dict(),
            "slice": {"start": 0, "count": 2}, "profile": "balanced_batch_v1",
            "proof_policy": "deterministic_differential_required"}
    earlier = [dataclasses.replace(_action(f"verify.request.{index:03d}.r01", capability, index,
                                           capability_args=args),
                                   requested_budget=dict(BUDGET), action_digest=None)
               for index in range(len(prior))]
    action = dataclasses.replace(_action("verify.request.r01", capability, len(earlier),
                                         capability_args=args),
                                 requested_budget=dict(BUDGET), action_digest=None)
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(*earlier, action))
    backend = _StoredOnce(manifests={candidates.manifest_id: candidates})
    (endpoint,) = sign_in_endpoints(SIGN_IN, [], base_url=f"{ORIGIN}/")
    for item, (attempt_id, sent) in zip(earlier, prior):
        backend.attempts.setdefault(item.action_id, {})[attempt_id] = {
            "attempt_id": attempt_id, "candidate_id": attempt_id, "status": "success",
            "observations": ({"kind": "candidate_attempt", "sign_in_endpoint_key": endpoint.key,
                              "sign_in_endpoint_requests": sent},),
        }
    dispatcher = _dispatcher(plan, backend, options=SIGN_IN, policy=ScanPolicy(
        active_testing=True, approval_receipt_id="approval-1",
    ))
    dispatcher._private_requests[request.request_id] = request
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    return receipt


@pytest.mark.parametrize("capability", ["sqli.request_verify_batch", "xss.request_verify_batch"])
def test_the_request_verifiers_pace_the_sign_in_request_of_the_profile(monkeypatch, capability):
    """The profile's own sign-in request, mutated field by field: each request waits the pace."""
    waits = _record_pace(monkeypatch)
    target = _fake_target(monkeypatch)
    receipt = _request_verifiers(capability)
    heads = [item for item in receipt.observations if item.get("kind") == "candidate_attempt"]
    assert len(target.to_sign_in()) == 4 and waits == [PACE] * 5
    assert [head["sign_in_endpoint_requests"] for head in heads] == [2, 2]
    assert heads[-1]["sign_in_endpoint_received"] == 4


@pytest.mark.parametrize("capability", ["sqli.request_verify_batch", "xss.request_verify_batch"])
def test_a_request_verifier_whose_set_is_spent_closes_each_field_inconclusive(monkeypatch, capability):
    """Earlier actions of the verifier spent its set on the endpoint: each field candidate is closed
    for the limit without a request, never left waiting for a wall it does not need."""
    waits = _record_pace(monkeypatch)
    target = _fake_target(monkeypatch)
    spent = probe_set_requests(capability, 4)
    receipt = _request_verifiers(capability, prior=[("a" * 64, spent - 20), ("b" * 64, 20)])
    heads = [item for item in receipt.observations if item.get("kind") == "candidate_attempt"]
    assert target.to_sign_in() == [] and waits == []
    assert len(heads) == 2 and {head["inconclusive_reason"] for head in heads} == {AUTH_ENDPOINT_PROBE_LIMITED}
    assert {head["sign_in_endpoint_received"] for head in heads} == {spent}
    assert not [item for item in receipt.observations if item.get("kind") == "candidate_deferred"]


class _Unanswered:
    """A transport whose requests time out unanswered, or fail before an answer."""

    def __init__(self, *, raises=False):
        self.raises = raises
        self.sent = 0

    async def send(self, request, **kwargs):
        self.sent += 1
        if self.raises:
            raise ConnectionError("reset before an answer")
        return ReplayTransportResult(status_code=None, connected_address=None, error_code="timeout",
                                     timed_out=True, final_url=request.url)


@pytest.mark.parametrize("raises", [False, True])
def test_a_request_to_the_endpoint_counts_whether_or_not_it_was_answered(monkeypatch, raises):
    """A timed-out sign-in attempt still reached the endpoint's throttle: it is counted before it
    is sent, so an unanswered or failed request never leaves the set larger than what was sent."""
    waits = _record_pace(monkeypatch)
    (endpoint,) = sign_in_endpoints(SIGN_IN, [], base_url=f"{ORIGIN}/")
    inner = _Unanswered(raises=raises)
    paced = PacedSignInTransport(inner, endpoint, pace_seconds=PACE)

    async def run():
        for _ in range(3):
            try:
                await paced.send(
                    _proof_request("POST", f"{ORIGIN}{LOGIN}", b"a=1", "application/x-www-form-urlencoded"),
                    target=TARGET, timeout_seconds=10.0, follow_redirects=False,
                )
            except ConnectionError:
                pass

    asyncio.run(run())
    assert inner.sent == paced.sent == 3 and waits == [PACE] * 3


@pytest.mark.parametrize("capability", ["sqli.prove_batch", "nosqli.verify_batch"])
def test_a_check_leaves_the_pace_after_its_last_request_to_the_endpoint(monkeypatch, capability):
    """Each request waits the pace before it, and the action waits it once more after its last
    one, charged from the wall it has left: whatever this scan part sends the endpoint next (a
    verifier process whose first request does not wait its own delay) comes a pace later."""
    clock = _PacedClock(monkeypatch)
    waits: list[tuple[float, int]] = []
    original = probe_module.pace_wait

    async def wait(seconds):
        waits.append((seconds, len(clock.target.to_sign_in())))
        await original(seconds)

    monkeypatch.setattr(probe_module, "pace_wait", wait, raising=False)
    receipts, _candidates = _run(capability, options=SIGN_IN)
    (receipt,) = receipts
    sent = len(clock.target.to_sign_in())
    assert sent and len(waits) == sent + 1
    # The last wait comes after the last request.
    assert waits[-1] == (PACE, sent)
    attempts = sum(int(head["budget_consumed"]["tool_wall_seconds"]) for head in _heads(receipts))
    assert receipt.budget_consumed["tool_wall_seconds"] == attempts + PACE


def test_the_closing_pace_is_waited_only_from_wall_the_action_has_left(monkeypatch):
    waits = _record_pace(monkeypatch)
    (endpoint,) = sign_in_endpoints(SIGN_IN, [], base_url=f"{ORIGIN}/")
    checks = action_adapter_module._SignInChecks("sqli.prove_batch", (endpoint,), {}, 1)

    async def close(consumed, requested):
        await checks.settle(consumed, requested)
        return consumed

    # Nothing sent to the endpoint: nothing to wait.
    assert asyncio.run(close({"tool_wall_seconds": 10}, {"tool_wall_seconds": 60})) == {"tool_wall_seconds": 10}
    checks.record({"kind": "candidate_attempt"}, endpoint, 8, short=False, manifest_index=0)
    assert asyncio.run(close({"tool_wall_seconds": 58}, {"tool_wall_seconds": 60})) == {"tool_wall_seconds": 58}
    assert waits == []
    assert asyncio.run(close({"tool_wall_seconds": 10}, {"tool_wall_seconds": 60})) == {
        "tool_wall_seconds": 10 + PACE,
    }
    assert waits == [PACE]


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
