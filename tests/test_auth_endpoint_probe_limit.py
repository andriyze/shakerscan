"""The credential profile's own sign-in endpoint gets a lockout-safe probe set (E1-N6).

A balanced authenticated lab Scan sent about 1,460 injection POSTs to the Hub login it signed in
with (938 sqlmap, 523 Dalfox). On that one endpoint each active injection verifier now runs a
bounded probe set per parameter, at most 20 requests a minute, and coverage names the limit
(``auth_endpoint_probe_limited``). Every other endpoint keeps its full hold. The batch tests
drive the real batch adapter with a fake process runner; no scanner process runs.
"""
from __future__ import annotations

import asyncio
import dataclasses
from dataclasses import replace
import uuid

import pytest

import agent_tools
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.auth_endpoint_probe import (
    AUTH_ENDPOINT_PROBE_LIMITED, AUTH_ENDPOINT_PROBE_REQUESTS, AUTH_ENDPOINT_SECONDS_PER_REQUEST,
    auth_endpoint_hold, auth_endpoint_keys, auth_endpoint_of,
)
from scan.verification_extension import EXTENDS_ARG
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest
from tests.test_body_attempt_mutation_accounting import _enforcement
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop

ORIGIN = "https://app.example.test"
LOGIN = "/hub/login"


# --- the numbers --------------------------------------------------------------------------------

def test_a_sign_in_parameter_gets_the_bounded_probe_set_at_the_lockout_safe_pace():
    body = {"http_requests": 480, "state_changing_requests": 480, "tool_wall_seconds": 420}
    sqli = auth_endpoint_hold(body, capability_name="sqli.verify_batch", used=0)
    assert sqli == {"http_requests": 60, "state_changing_requests": 60, "tool_wall_seconds": 420}
    xss = auth_endpoint_hold(
        {"http_requests": 240, "state_changing_requests": 240, "tool_wall_seconds": 120},
        capability_name="xss.verify_batch", used=0,
    )
    assert xss["http_requests"] == 32
    # The pace: never more than one request per 3 s of wall for each candidate that runs at once.
    assert AUTH_ENDPOINT_SECONDS_PER_REQUEST == 3
    paced = auth_endpoint_hold({"http_requests": 160, "tool_wall_seconds": 30},
                               capability_name="sqli.verify_batch", used=0)
    assert paced["http_requests"] == 10
    concurrent = auth_endpoint_hold({"http_requests": 160, "tool_wall_seconds": 60},
                                    capability_name="sqli.verify_batch", used=0, concurrency=2)
    assert concurrent["http_requests"] == 10
    # What a parameter already received counts: a spent probe set funds nothing more.
    assert auth_endpoint_hold(body, capability_name="sqli.verify_batch", used=40)["http_requests"] == 20
    assert auth_endpoint_hold(body, capability_name="sqli.verify_batch", used=55) is None


def test_the_sign_in_endpoint_and_its_form_action_are_recognized_and_nothing_else():
    keys = auth_endpoint_keys(
        {"login_url": f"{ORIGIN}{LOGIN}"},
        [{"kind": "credential_session", "endpoint_path": LOGIN, "form_action_path": "/hub/session"}],
        base_url=f"{ORIGIN}/",
    )
    assert auth_endpoint_of(f"{ORIGIN}{LOGIN}", keys) == LOGIN
    assert auth_endpoint_of(f"{ORIGIN}{LOGIN}/", keys) == LOGIN
    assert auth_endpoint_of(f"{ORIGIN}/hub/session?next=1", keys) == "/hub/session"
    assert auth_endpoint_of(f"{ORIGIN}/api/feedback", keys) is None
    assert auth_endpoint_of(f"https://other.example.test{LOGIN}", keys) is None
    relative = auth_endpoint_keys({"login_url": LOGIN}, [], base_url=f"{ORIGIN}/app/")
    assert auth_endpoint_of(f"{ORIGIN}{LOGIN}", relative) == LOGIN
    assert auth_endpoint_keys({}, [], base_url=f"{ORIGIN}/") == frozenset()


@pytest.mark.parametrize("tool,flag", [("sqlmap", "--level"), ("dalfox", "--only-custom-payload")])
def test_the_probe_profile_bounds_the_payloads(tool, flag, tmp_path):
    tmp_path.chmod(0o700)
    runtime = {"sqlmap_output_dir": str(tmp_path)} if tool == "sqlmap" else {}
    options = {"_batch_attempt": True, "method": "POST", "body_field_names": ["username", "password"],
               "injection_field": "username", "probe_profile": "auth_endpoint"}
    plan = agent_tools.build_enforced_scanner_plan(
        tool, f"{ORIGIN}{LOGIN}", options,
        reserved_budget={"http_requests": 60, "state_changing_requests": 60, "tool_wall_seconds": 420},
        pinned_proxy_url="socks5://127.0.0.1:41000", runtime_paths=runtime,
    )
    argv = list(plan.argv)
    if tool == "sqlmap":
        assert argv[argv.index("--level") + 1] == "1" and argv[argv.index("--risk") + 1] == "1"
        assert float(argv[argv.index("--delay") + 1]) >= AUTH_ENDPOINT_SECONDS_PER_REQUEST
    else:
        assert flag in argv and "--custom-payload" in argv
        assert int(argv[argv.index("--delay") + 1]) >= AUTH_ENDPOINT_SECONDS_PER_REQUEST * 1_000
    unbounded = agent_tools.build_enforced_scanner_plan(
        tool, f"{ORIGIN}/api/feedback", {**options, "probe_profile": None},
        reserved_budget={"http_requests": 480, "state_changing_requests": 480, "tool_wall_seconds": 420},
        pinned_proxy_url="socks5://127.0.0.1:41000", runtime_paths=runtime,
    )
    if tool == "sqlmap":
        assert unbounded.argv[list(unbounded.argv).index("--level") + 1] == "2"
    else:
        assert "--only-custom-payload" not in unbounded.argv


# --- the batch ----------------------------------------------------------------------------------

def _runner(tool, parser, *, sent):
    calls: list[dict] = []

    async def process_runner(payload, *, heartbeat):
        reserved = dict(payload["_reserved_budget"])
        calls.append({"target": payload["execution_target"], "reserved": reserved,
                      "options": dict(payload["scanner_options"])})
        count = min(sent, int(reserved["http_requests"]))
        return {
            "status": "success", "elapsed_seconds": 10,
            "typed_output": {"parser": parser, "records": [], "errors": []},
            "settlement": {"mode": "exact", "actual": count, "observed_minimum": count},
            "process_enforcement": _enforcement(tool, parser, {
                name: reserved[name] for name in ("http_requests", "tool_wall_seconds")
            }),
        }

    return process_runner, calls


def _slice(capability, *, tool, parser, sent, options, extends=None, prior=()):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "POST", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": path, "concrete_path": path, "query_keys": [],
                "content_type": "application/x-www-form-urlencoded", "body_field_names": fields,
                "source": "inputs.custom_endpoints",
            } for path, fields in ((LOGIN, ["username", "password"]), ("/api/feedback", ["comment"]))],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=10,
        allow_state_changing_http=True,
    )
    count = len(candidates.entries)
    args = {
        "candidate_manifest_ref": candidates.reference().canonical_dict(),
        "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        "slice": {"start": 0, "count": count}, "profile": "balanced_batch_v1",
        "proof_policy": "deterministic_differential_required",
    }
    first = dataclasses.replace(
        _action("verify.x.r01", capability, 0, capability_args=args),
        requested_budget={"http_requests": 6_000, "state_changing_requests": 6_000,
                          "tool_wall_seconds": 6_000},
        action_digest=None,
    )
    actions = [first]
    action = first
    if extends:
        action = dataclasses.replace(
            _action("verify.x.r02", capability, 1, capability_args={**args, EXTENDS_ARG: first.action_id}),
            requested_budget=dict(first.requested_budget), action_digest=None,
        )
        actions.append(action)
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=tuple(actions))
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    dispatcher = _dispatcher(plan, backend, options=options, policy=ScanPolicy(
        active_testing=True, allow_state_changing_http=True, approval_receipt_id="approval-1",
    ))
    runner, calls = _runner(tool, parser, sent=sent)
    dispatcher.process_runner = runner
    receipt = asyncio.run(dispatcher(first, _lease(plan, first), _noop))
    if extends:
        calls.clear()
        receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    return receipt, calls, candidates


def _sent_to(calls, path):
    return [call for call in calls if call["target"].split("?")[0].endswith(path)]


@pytest.mark.parametrize("capability,tool,parser", [
    ("sqli.verify_batch", "sqlmap", "sqlmap-output/v1"),
    ("xss.verify_batch", "dalfox", "dalfox-jsonl/v1"),
])
def test_the_sign_in_endpoint_gets_the_probe_set_and_other_endpoints_their_full_hold(capability, tool, parser):
    receipt, calls, _candidates = _slice(capability, tool=tool, parser=parser, sent=1_000,
                                         options={"login_url": LOGIN})
    login, other = _sent_to(calls, LOGIN), _sent_to(calls, "/api/feedback")
    assert login and other
    assert sum(call["reserved"]["http_requests"] for call in login) <= 2 * AUTH_ENDPOINT_PROBE_REQUESTS[capability]
    for call in login:
        reserved = call["reserved"]
        assert reserved["tool_wall_seconds"] >= reserved["http_requests"] * AUTH_ENDPOINT_SECONDS_PER_REQUEST
        assert call["options"].get("probe_profile") == "auth_endpoint"
    assert all(call["options"].get("probe_profile") is None for call in other)
    assert max(call["reserved"]["http_requests"] for call in other) > AUTH_ENDPOINT_PROBE_REQUESTS[capability]
    heads = [item for item in receipt.observations
             if item.get("kind") == "candidate_attempt" and item.get("sign_in_endpoint") == LOGIN]
    assert len(heads) == 1  # one body candidate tests both fields (username, password)
    for head in heads:
        assert head["sign_in_endpoint_requests"] <= 2 * AUTH_ENDPOINT_PROBE_REQUESTS[capability]
        assert head["verdict"] == "inconclusive"
        assert head["inconclusive_reason"] == AUTH_ENDPOINT_PROBE_LIMITED
        assert "resume_wall_seconds" not in head


def test_a_continuation_round_sends_the_spent_sign_in_parameters_nothing():
    receipt, calls, _candidates = _slice("sqli.verify_batch", tool="sqlmap", parser="sqlmap-output/v1",
                                         sent=1_000, options={"login_url": LOGIN}, extends=True)
    assert not _sent_to(calls, LOGIN)
    deferred = [item for item in receipt.observations
                if item.get("kind") == "candidate_deferred" and item.get("reason") == AUTH_ENDPOINT_PROBE_LIMITED]
    assert len(deferred) == 1
    assert all(item["verdict"] == "inconclusive" for item in deferred)


def test_without_a_sign_in_profile_the_login_form_keeps_the_full_hold():
    _receipt, calls, _candidates = _slice("sqli.verify_batch", tool="sqlmap", parser="sqlmap-output/v1",
                                          sent=1_000, options={})
    login = _sent_to(calls, LOGIN)
    assert login and all(call["options"].get("probe_profile") is None for call in login)


# --- coverage -----------------------------------------------------------------------------------

def test_coverage_names_the_limited_sign_in_endpoint():
    from api.runtime.observation_manifests import ObservationManifest
    from api.scan.action_plan import ScanActionPlan as PackagePlan
    from api.scan.capability_result import CapabilityResultStatus
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_orchestrator import SCAN_ID, _action as plan_action, _result as settle

    batch = replace(
        plan_action("verify.sqli.r01", 0, capability_name="sqli.verify_batch"),
        capability_args={"slice": {"start": 0, "count": 2}, "manifest_entries": 2},
        output_schema="sqlmap-batch/v1", action_digest=None,
    )
    final = plan_action("finalize.report", 1, dependencies=(batch.action_id,))
    plan = PackagePlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                       target_binding_digest="a" * 64, actions=(batch, final))
    rows = (
        {"kind": "candidate_attempt", "attempt_id": "1" * 64, "candidate_id": "c1", "family": "sqli",
         "status": "success", "proof_state": "unproven", "verdict": "inconclusive",
         "inconclusive_reason": AUTH_ENDPOINT_PROBE_LIMITED, "sign_in_endpoint": LOGIN,
         "sign_in_endpoint_requests": 120},
        {"kind": "candidate_attempt", "attempt_id": "2" * 64, "candidate_id": "c2", "family": "sqli",
         "status": "success", "proof_state": "unproven"},
    )
    result = settle(batch, status=CapabilityResultStatus.SUCCESS)
    result = replace(result, observation_manifest_ref=ObservationManifest(
        manifest_id="00000000-0000-4000-8000-0000000000ad", owner_id=SCAN_ID,
        action_id=batch.action_id, capability_name=batch.capability_name,
        output_schema=batch.output_schema, observation_count=len(rows),
        content_sha256="0" * 64, size_bytes=512, object_key="scans/x.jsonl",
    ).reference(), result_digest=None)
    report = finalize_scan_report(plan=plan, target_url=ORIGIN,
                                  action_results={batch.action_id: result},
                                  observations={batch.action_id: rows})
    coverage = report["coverage"]
    family = next(row for row in coverage["family_coverage"] if row["family"] == "sqli")
    assert family["sign_in_probe_limited"] == {"endpoints": [LOGIN], "candidates": 1}
    assert AUTH_ENDPOINT_PROBE_LIMITED in coverage["reasons"]


def test_the_sign_in_records_where_its_form_posts():
    from tests.test_authenticated_crawl_seeds import _form_login

    observation = _form_login("/hub/")
    assert observation["form_action_path"] == "/hub/login"
    keys = auth_endpoint_keys({}, [observation], base_url=f"{ORIGIN}/")
    assert auth_endpoint_of(f"{ORIGIN}/hub/login", keys) == "/hub/login"
