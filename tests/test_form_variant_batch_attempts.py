"""Each variant of one form is its own attempt in every batch over the candidate manifest.

A body candidate's id is its route, method and the field that anchors the body, so the declared
sign-in form, the crawled form with its hidden fields and a JSON variant are one candidate id with
three bodies. The SQLi and XSS verifiers give each variant its own attempt
(tests/test_auth_endpoint_probe_limit.py); the SQLi proof, the XSS browser proof and the NoSQLi
verifier read the same manifest and must too. Their checkpoints are kept the way the scan
database keeps them (``_StoredOnce``): an attempt id's first row stands and a later row for it with
another status is refused, so variants sharing one attempt id either failed the action or stored one
row for three attempts. The executor is a unit fixture: it reports a status per variant and sends no
request.
"""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import types
import urllib.parse
import uuid

import pytest
import scan.action_adapter as action_adapter_module
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest

from tests.test_auth_endpoint_probe_limit import SIGN_IN_ROUTES, _StoredOnce
from tests.test_scan_action_adapter import TARGET, _action, _dispatcher, _lease, _noop

PROOF_BUDGET = {"http_requests": 600, "state_changing_requests": 600, "tool_wall_seconds": 600}
#: The family each batch names its attempts with, and the verifier whose signals it escalates.
BATCHES = {
    "nosqli.verify_batch": ("nosqli", None),
    "sqli.prove_batch": ("sqli_proof", ("sqli.verify_batch", "sqli")),
    "xss.browser_prove_batch": ("xss_browser_proof", ("xss.verify_batch", "xss")),
}


def _sha(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _manifests(routes=SIGN_IN_ROUTES[:3]):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": method, "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": path, "concrete_path": path, "query_keys": query,
                "content_type": content_type, "body_field_names": fields, "source": source,
            } for method, path, fields, content_type, query, source in routes],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=20,
        allow_state_changing_http=True,
    )
    return scan_id, endpoints, candidates


def _attempt_ids(candidates, family: str) -> list[str]:
    """Each entry's attempt id as the batches derive it: the manifest, the family and the
    candidate id, and the position for an entry whose candidate id an earlier entry has."""
    digest = candidates.reference().manifest_digest
    seen: set[str] = set()
    ids = []
    for index, entry in enumerate(candidates.entries):
        key = f"{digest}:{family}:{entry['candidate_id']}"
        if entry["candidate_id"] in seen:
            key += f":entry:{index}"
        seen.add(entry["candidate_id"])
        ids.append(_sha(key))
    return ids


def _shape(body: bytes, content_type: str) -> tuple:
    """A variant: its body's field names and whether the body is JSON."""
    if "json" in str(content_type or "").lower():
        return tuple(sorted(json.loads(body.decode()))), "json"
    return tuple(sorted(urllib.parse.parse_qs(body.decode(), keep_blank_values=True))), "form"


def _variant_of(adapter) -> tuple:
    prepared = getattr(adapter, "prepared", None)
    if prepared is not None:  # the XSS browser proof
        return _shape(prepared.body, prepared.content_type)
    headers = {str(name).lower(): str(value) for name, value in adapter.request.headers}
    return _shape(adapter.request.body, headers.get("content-type", ""))


def _signals(candidates, verifier_family: str, positions, *, ids=None) -> tuple:
    """What the verifier recorded: every variant's attempt, and a signal from ``positions``."""
    ids = ids or _attempt_ids(candidates, verifier_family)
    kind = {"sqli": "sqli_finding", "xss": "xss_alert"}[verifier_family]
    records = []
    for index, entry in enumerate(candidates.entries):
        signalled = index in positions
        records.append({
            "kind": "candidate_attempt", "attempt_id": ids[index],
            "candidate_id": entry["candidate_id"], "family": verifier_family, "status": "success",
            "proof_state": "suspected" if signalled else "unproven",
        })
        if signalled:
            records.append({"kind": kind, "attempt_id": ids[index],
                            "candidate_id": entry["candidate_id"], "proof_state": "suspected"})
    return tuple(records)


def _run(monkeypatch, capability, *, statuses, signalled=(0, 1, 2), signals=None, rounds=1,
         backend=None, manifests=None, part=None):
    """Run ``capability`` over the three variants of one sign-in form ``rounds`` times (over the
    manifest's ``part``, (start, count), when given)."""
    family, verifier = BATCHES[capability]
    scan_id, endpoints, candidates = manifests or _manifests()
    start, count = part or (0, len(candidates.entries))
    args = {
        "candidate_manifest_ref": candidates.reference().canonical_dict(),
        "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        "slice": {"start": start, "count": count},
    }
    actions = []
    observations = {}
    if verifier is not None:
        verify = _action("verify.x.r01", verifier[0], 0, capability_args=args)
        actions.append(verify)
        observations[verify.action_id] = (
            signals if signals is not None else _signals(candidates, verifier[1], set(signalled))
        )
    budget = {**PROOF_BUDGET, **({"browser_actions": 30} if capability.startswith("xss.") else {})}
    batch = dataclasses.replace(
        _action("batch.x.r01", capability, len(actions), capability_args=args,
                dependencies=tuple(item.action_id for item in actions)),
        requested_budget=budget, action_digest=None,
    )
    actions.append(batch)
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=tuple(actions))
    backend = backend or _StoredOnce(
        manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates},
        observations=observations,
    )
    calls: list[tuple] = []
    pending = iter(statuses)

    async def execute(_self, context, adapter, **_kwargs):
        status = next(pending)
        calls.append((_variant_of(adapter), status))
        proof = {"nosqli.verify_batch": "nosqli_proof", "sqli.prove_batch": "sqli_proof",
                 "xss.browser_prove_batch": "xss_browser_proof"}[capability]
        return types.SimpleNamespace(
            status=status, timed_out=False, errors=(),
            observations=({"kind": proof, "proof_state": "not_proven"},),
            actual_budget={name: min(4, int(amount)) for name, amount in context.requested_budget.items()},
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy(
        active_testing=True, allow_state_changing_http=True, approval_receipt_id="approval-1",
    ))
    receipts = [asyncio.run(dispatcher(batch, _lease(plan, batch), _noop)) for _ in range(rounds)]
    return receipts, calls, backend, candidates, family, batch


def _heads(receipt):
    return [item for item in receipt.observations if item.get("kind") == "candidate_attempt"]


VARIANTS = {(("password", "username"), "form"), (("csrf_token", "password", "remember", "username"), "form"),
            (("password", "username"), "json")}


@pytest.mark.parametrize("capability", sorted(BATCHES))
def test_variants_that_settle_differently_each_keep_their_own_attempt(monkeypatch, capability):
    """Mixed statuses never fail the action, and the receipt names three attempts."""
    receipts, calls, backend, _candidates, _family, batch = _run(
        monkeypatch, capability, statuses=["success", "partial", "success"],
    )
    (receipt,) = receipts
    assert {variant for variant, _status in calls} == VARIANTS, calls
    heads = _heads(receipt)
    assert len(heads) == 3 and len({head["attempt_id"] for head in heads}) == 3, heads
    assert sorted(head["status"] for head in heads) == ["partial", "success", "success"]
    assert len(backend.attempts[batch.action_id]) == 3
    assert receipt.redacted_execution["attempted_count"] == 3


@pytest.mark.parametrize("capability", sorted(BATCHES))
def test_the_first_variant_keeps_the_attempt_id_earlier_builds_checkpointed(monkeypatch, capability):
    receipts, _calls, _backend, candidates, family, _batch = _run(
        monkeypatch, capability, statuses=["success"] * 3,
    )
    digest = candidates.reference().manifest_digest
    first = candidates.entries[0]["candidate_id"]
    assert len({entry["candidate_id"] for entry in candidates.entries}) == 1
    ids = {head["attempt_id"] for head in _heads(receipts[0])}
    assert _sha(f"{digest}:{family}:{first}") in ids
    assert ids == set(_attempt_ids(candidates, family))


@pytest.mark.parametrize("capability", sorted(BATCHES))
def test_a_resumed_action_replays_each_variants_own_record(monkeypatch, capability):
    """A second run resends nothing and each variant keeps the status its own attempt recorded."""
    receipts, calls, _backend, _candidates, _family, _batch = _run(
        monkeypatch, capability, statuses=["success", "partial", "success"], rounds=2,
    )
    assert len(calls) == 3
    first, second = receipts
    assert second.redacted_execution["resumed_count"] == 3
    assert sorted((head["attempt_id"], head["status"]) for head in _heads(second)) == sorted(
        (head["attempt_id"], head["status"]) for head in _heads(first)
    )


@pytest.mark.parametrize("capability", ["sqli.prove_batch", "xss.browser_prove_batch"])
def test_a_verifier_signal_escalates_only_the_variant_that_produced_it(monkeypatch, capability):
    """The crawled form's signal proves the crawled form, not its two siblings."""
    receipts, calls, _backend, candidates, _family, _batch = _run(
        monkeypatch, capability, statuses=["success"], signalled=(1,),
    )
    crawled = candidates.entries[1]
    assert [variant for variant, _status in calls] == [(tuple(sorted(crawled["body_field_names"])), "form")]
    (receipt,) = receipts
    assert len(_heads(receipt)) == 1
    assert receipt.redacted_execution["eligible_count"] == 1
    assert receipt.status == "success"


@pytest.mark.parametrize("capability", ["sqli.prove_batch", "xss.browser_prove_batch"])
def test_the_first_variants_signal_escalates_only_the_first_variant(monkeypatch, capability):
    """The first variant keeps the attempt id an earlier build shared; the verifier recorded its
    siblings under their own ids, so its signal is the first variant's alone."""
    receipts, calls, _backend, candidates, _family, _batch = _run(
        monkeypatch, capability, statuses=["success"], signalled=(0,),
    )
    declared = candidates.entries[0]
    expected = (tuple(sorted(declared["body_field_names"])),
                "json" if "json" in str(declared.get("content_type") or "") else "form")
    assert [variant for variant, _status in calls] == [expected]
    assert receipts[0].redacted_execution["eligible_count"] == 1


@pytest.mark.parametrize("capability", ["sqli.prove_batch", "xss.browser_prove_batch"])
def test_a_signal_recorded_under_the_shared_attempt_of_an_earlier_build_escalates_every_variant(
    monkeypatch, capability,
):
    """An earlier build recorded the three variants under one attempt id, so a signal cannot say
    which variant it came from: every variant with that candidate id is escalated, as before."""
    _manifests_ = _manifests()
    _scan, _endpoints, candidates = _manifests_
    _family, (_verifier, verifier_family) = BATCHES[capability]
    digest = candidates.reference().manifest_digest
    shared = _sha(f"{digest}:{verifier_family}:{candidates.entries[0]['candidate_id']}")
    signals = _signals(candidates, verifier_family, {0}, ids=[shared] * 3)[:2]
    receipts, calls, _backend, _candidates, _family, _batch = _run(
        monkeypatch, capability, statuses=["success"] * 3, signals=signals, manifests=_manifests_,
    )
    assert {variant for variant, _status in calls} == VARIANTS
    assert len({head["attempt_id"] for head in _heads(receipts[0])}) == 3


def test_a_signal_without_an_attempt_id_escalates_every_variant_of_its_candidate(monkeypatch):
    _manifests_ = _manifests()
    candidates = _manifests_[2]
    signals = ({"kind": "sqli_finding", "candidate_id": candidates.entries[0]["candidate_id"],
                "proof_state": "suspected"},)
    _receipts, calls, *_rest = _run(
        monkeypatch, "sqli.prove_batch", statuses=["success"] * 3, signals=signals,
        manifests=_manifests_,
    )
    assert {variant for variant, _status in calls} == VARIANTS


def test_every_nosqli_variant_counts_as_attempted_in_the_report(monkeypatch):
    """The report counts distinct attempt ids: three variants that shared one read as two
    candidates never attempted (``candidates_unattempted``)."""
    from api.scan.action_plan import ScanActionPlan as PackagePlan
    from api.scan.finalizer import finalize_scan_report
    from tests.test_auth_endpoint_probe_coverage import ORIGIN
    from tests.test_scan_finalizer import _result_with_observation_count
    from tests.test_scan_orchestrator import SCAN_ID
    from tests.test_scan_orchestrator import _action as plan_action

    receipts, *_rest = _run(monkeypatch, "nosqli.verify_batch", statuses=["success"] * 3)
    rows = tuple(receipts[0].observations)
    batch = dataclasses.replace(
        plan_action("verify.nosqli.r01", 0, capability_name="nosqli.verify_batch"),
        capability_args={"slice": {"start": 0, "count": 3}, "manifest_entries": 3},
        output_schema="nosqli-batch/v1", action_digest=None,
    )
    final = plan_action("finalize.report", 1, dependencies=(batch.action_id,))
    plan = PackagePlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                       target_binding_digest="a" * 64, actions=(batch, final))
    result = _result_with_observation_count(batch, len(rows))
    report = finalize_scan_report(plan=plan, target_url=ORIGIN, action_results={batch.action_id: result},
                                  observations={batch.action_id: rows})
    family = next(row for row in report["coverage"]["family_coverage"] if row["family"] == "nosqli")
    assert family["attempted_candidates"] == 3, family
    assert family["unattempted_candidates"] == 0
    assert family["reason"] != "candidates_unattempted"



def _authz_surface(routes, *, rounds=1, backend=None, public_route=False):
    """The anonymous-versus-signed-in comparison over the endpoint manifest of ``routes``.

    Every probe answers 401 anonymously and 200 signed in; with ``public_route`` the sign-in path
    without a query answers both alike with a JSON body (an anonymous-access finding there).
    """
    from runtime.request_replay_executor import ReplayTransportResult

    scan_id, endpoints, candidates = _manifests(routes)
    sent: list[tuple[str, str]] = []

    class Transport:
        async def send(self, request, **_kwargs):
            sent.append((request.method, request.url))
            public = public_route and "?" not in request.url
            return ReplayTransportResult(
                status_code=200 if request.headers or public else 401,
                connected_address="192.0.2.10", final_url=request.url,
                response_headers={"Content-Type": "application/json"},
                response_body=b'{"items": ["one", "two", "three", "four"]}' if public else b"{}",
            )

    args = {"endpoint_manifest_ref": endpoints.reference().canonical_dict(),
            "slice": {"start": 0, "count": len(endpoints.entries)}}
    action = dataclasses.replace(
        _action("verify.authz_surface.r01", "authz_surface.verify_batch", 0, capability_args=args),
        action_digest=None,
    )
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    backend = backend or _StoredOnce(manifests={endpoints.manifest_id: endpoints,
                                                candidates.manifest_id: candidates})
    dispatcher = _dispatcher(plan, backend, options={"auth_header": "Bearer unit-fixture"},
                             policy=ScanPolicy(active_testing=True))
    dispatcher._scan_replay_transport = lambda *_args, **_kwargs: Transport()
    receipts = [asyncio.run(dispatcher(action, _lease(plan, action), _noop)) for _ in range(rounds)]
    return receipts, sent, endpoints, action


def test_each_entry_of_a_route_seen_with_two_bodies_is_its_own_comparison_attempt():
    """The sign-in route's three bodies are one route to the GET comparison: it is probed once, and
    each entry is its own attempt, so the report does not read two of them as never attempted."""
    from api.scan.action_plan import ScanActionPlan as PackagePlan
    from api.scan.finalizer import finalize_scan_report
    from tests.test_auth_endpoint_probe_coverage import ORIGIN
    from tests.test_scan_finalizer import _result_with_observation_count
    from tests.test_scan_orchestrator import SCAN_ID
    from tests.test_scan_orchestrator import _action as plan_action

    (receipt,), sent, endpoints, _authz_action = _authz_surface(SIGN_IN_ROUTES)
    assert len(endpoints.entries) == 4
    assert len({entry["route_id"] for entry in endpoints.entries}) == 2
    # Two routes, four GETs each: the second and third body of the sign-in route send nothing.
    assert len(sent) == 8, sent
    heads = _heads(receipt)
    assert len(heads) == 4 and len({head["attempt_id"] for head in heads}) == 4, heads
    digest = endpoints.reference().manifest_digest
    first = endpoints.entries[0]["route_id"]
    assert _sha(f"{digest}:authz_surface:{first}") in {head["attempt_id"] for head in heads}

    rows = tuple(receipt.observations)
    batch = dataclasses.replace(
        plan_action("verify.authz_surface.r01", 0, capability_name="authz_surface.verify_batch"),
        capability_args={"slice": {"start": 0, "count": 4}, "manifest_entries": 4},
        output_schema="authz-surface-batch/v1", action_digest=None,
    )
    final = plan_action("finalize.report", 1, dependencies=(batch.action_id,))
    plan = PackagePlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                       target_binding_digest="a" * 64, actions=(batch, final))
    report = finalize_scan_report(
        plan=plan, target_url=ORIGIN,
        action_results={batch.action_id: _result_with_observation_count(batch, len(rows))},
        observations={batch.action_id: rows},
    )
    family = next(row for row in report["coverage"]["family_coverage"] if row["family"] == "authz_surface")
    assert family["attempted_candidates"] == 4 and family["unattempted_candidates"] == 0, family


def test_a_resumed_comparison_resends_nothing_for_any_entry_of_the_route():
    receipts, sent, *_rest = _authz_surface(SIGN_IN_ROUTES, rounds=2)
    assert len(sent) == 8
    assert receipts[1].redacted_execution["resumed_count"] == 4


def test_a_route_seen_with_several_bodies_yields_one_finding():
    (receipt,), _sent, _endpoints, _authz_action = _authz_surface(SIGN_IN_ROUTES, public_route=True)
    findings = [item for item in receipt.observations if item.get("kind") == "authz_surface_proof"]
    assert len(findings) == 1, findings
    assert sum(head["proof_state"] == "verified" for head in _heads(receipt)) == 3


#: Three candidates of other routes rank before the sign-in form, and a body of another route
#: between them: the form's three variants are positions 4, 5 and 6.
_LEADING_ROUTES = (
    ("GET", "/items", None, None, ["id"], "web.crawl"),
    ("GET", "/search", None, None, ["q"], "web.crawl"),
    ("GET", "/a/b", None, None, ["sort"], "web.crawl"),
    ("POST", "/api/user", ["id", "name"], "application/json", [], "web.spec_ingest"),
)


@pytest.mark.parametrize("capability", sorted(BATCHES))
def test_a_slice_starting_inside_a_forms_variants_names_each_by_its_manifest_position(
    monkeypatch, capability,
):
    """A slice of positions 5 and 6 (the crawled form and the JSON variant): each attempt is named
    by its manifest position, not its place in the slice. Named by the slice's offsets (0, 1), both
    took the first variant's id, and their different statuses failed the action."""
    manifests = _manifests(_LEADING_ROUTES + SIGN_IN_ROUTES[:3])
    candidates = manifests[2]
    form = [index for index, entry in enumerate(candidates.entries)
            if entry.get("canonical_path") == "/hub/login"]
    assert form == [4, 5, 6] and len({candidates.entries[index]["candidate_id"] for index in form}) == 1
    family, _verifier = BATCHES[capability]
    receipts, calls, backend, _candidates, _family, batch = _run(
        monkeypatch, capability, statuses=["success", "partial"], signalled=tuple(form),
        manifests=manifests, part=(5, 2),
    )
    (receipt,) = receipts
    heads = _heads(receipt)
    assert [head["attempt_id"] for head in heads] == _attempt_ids(candidates, family)[5:7]
    assert sorted(head["status"] for head in heads) == ["partial", "success"]
    assert len(calls) == 2 and len(backend.attempts[batch.action_id]) == 2


_PRIVATE_KEY = (b"-----BEGIN RSA PRIVATE KEY-----\n"
                b"MIIEowIBAAKCAQEA7vbqajDw4o6gJy8UtmIbkcpnkO3Kwc4qsEnSZp/TR+fQi62F\n"
                b"-----END RSA PRIVATE KEY-----\n")


def _exposure(routes, *, part, rounds=1, disclosed=False):
    """The exposure sweep over a window of the endpoint manifest of ``routes`` (no seed paths:
    the window does not start the manifest). Every URL answers 404, or, with ``disclosed``, the
    sign-in path without a query serves a private key."""
    from runtime.request_replay_executor import ReplayTransportResult

    scan_id, endpoints, candidates = _manifests(routes)
    sent: list[tuple[str, str]] = []

    class Transport:
        async def send(self, request, **_kwargs):
            sent.append((request.method, request.url))
            served = disclosed and request.url.endswith("/hub/login")
            return ReplayTransportResult(
                status_code=200 if served else 404, connected_address="192.0.2.10",
                final_url=request.url, response_headers={"content-type": "text/plain"},
                response_body=_PRIVATE_KEY if served else b"not found", elapsed_ms=5,
            )

    start, count = part
    action = dataclasses.replace(
        _action("verify.exposure.r01", "exposure.verify_batch", 0, capability_args={
            "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
            "slice": {"start": start, "count": count},
        }),
        requested_budget={"http_requests": 400, "tool_wall_seconds": 400}, action_digest=None,
    )
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    backend = _StoredOnce(manifests={endpoints.manifest_id: endpoints,
                                     candidates.manifest_id: candidates})
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy(active_testing=True))
    dispatcher._scan_replay_transport = lambda *_args, **_kwargs: Transport()
    receipts = [asyncio.run(dispatcher(action, _lease(plan, action), _noop)) for _ in range(rounds)]
    return receipts, sent, endpoints


def test_each_entry_of_a_url_seen_with_several_bodies_is_one_exposure_get_and_its_own_attempt():
    """Two bodies of the sign-in route and its sign-in page: the sign-in URL is read once, and each
    entry is its own attempt. The sweep read the URL once per entry under one attempt id, so it sent
    a duplicate GET and the report counted two of three entries."""
    from api.scan.action_plan import ScanActionPlan as PackagePlan
    from api.scan.finalizer import finalize_scan_report
    from tests.test_auth_endpoint_probe_coverage import ORIGIN
    from tests.test_scan_finalizer import _result_with_observation_count
    from tests.test_scan_orchestrator import SCAN_ID
    from tests.test_scan_orchestrator import _action as plan_action

    (receipt,), sent, endpoints = _exposure(SIGN_IN_ROUTES, part=(1, 3))
    window = endpoints.entries[1:4]
    assert [entry["method"] for entry in window] == ["POST", "POST", "GET"]
    assert sorted(url for _method, url in sent) == [f"{ORIGIN}/hub/login", f"{ORIGIN}/hub/login?next=1"]
    heads = _heads(receipt)
    assert len(heads) == 3 and len({head["attempt_id"] for head in heads}) == 3, heads
    digest = endpoints.reference().manifest_digest
    # The URL's first entry keeps the attempt id earlier builds checkpointed it under.
    assert _sha(f"{digest}:exposure:{ORIGIN}/hub/login") in {head["attempt_id"] for head in heads}
    rows = tuple(receipt.observations)
    batch = dataclasses.replace(
        plan_action("verify.exposure.r01", 0, capability_name="exposure.verify_batch"),
        capability_args={"slice": {"start": 1, "count": 3}, "manifest_entries": 4},
        output_schema="exposure-probe-batch/v1", action_digest=None,
    )
    final = plan_action("finalize.report", 1, dependencies=(batch.action_id,))
    plan = PackagePlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                       target_binding_digest="a" * 64, actions=(batch, final))
    report = finalize_scan_report(
        plan=plan, target_url=ORIGIN,
        action_results={batch.action_id: _result_with_observation_count(batch, len(rows))},
        observations={batch.action_id: rows},
    )
    family = next(row for row in report["coverage"]["family_coverage"]
                  if row["family"] == "sensitive_exposure")
    assert family["attempted_candidates"] == 3 and family["unattempted_candidates"] == 0, family


def test_a_resumed_exposure_sweep_reads_no_url_again_for_any_entry():
    receipts, sent, _endpoints = _exposure(SIGN_IN_ROUTES, part=(1, 3), rounds=2)
    assert len(sent) == 2
    assert len(_heads(receipts[1])) == 3 and len({head["attempt_id"] for head in _heads(receipts[1])}) == 3


def test_a_url_seen_with_several_bodies_yields_one_exposure_finding():
    (receipt,), _sent, _endpoints = _exposure(SIGN_IN_ROUTES, part=(1, 3), disclosed=True)
    proofs = [item for item in receipt.observations if item.get("kind") == "sensitive_exposure_proof"]
    assert len(proofs) == 1, proofs
    assert sum(head["proof_state"] == "verified" for head in _heads(receipt)) == 2
