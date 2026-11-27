"""The credential profile's own sign-in endpoint gets a paced rate and one bounded probe set.

An authenticated balanced Scan of a test application sent about 1,460 injection requests to the
sign-in form it used (938 sqlmap, 523 Dalfox). On that one endpoint the verifiers keep their full
payloads but run at most 20 requests a minute, one attempt at a time, and draw from one probe set
per verifier across every candidate and round of the Scan; coverage names the limit
(``auth_endpoint_probe_limited``). Every other endpoint keeps its full hold. The batch tests drive
the real batch adapter with a fake process runner (``_runner``); no scanner process runs.
"""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import math
import uuid

import pytest

import agent_tools
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.auth_endpoint_probe import (
    AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS, AUTH_ENDPOINT_PACE_UNFUNDED, AUTH_ENDPOINT_PROBE_HEADROOM,
    AUTH_ENDPOINT_PROBE_LIMITED, AUTH_ENDPOINT_PROBE_REQUESTS, AUTH_ENDPOINT_SECONDS_PER_REQUEST,
    auth_endpoint_hold, normalize_path, probe_set_requests, routing_digests, sign_in_endpoint_for,
    sign_in_endpoints,
)
from scan.sqli_concurrency import CANDIDATE_CONCURRENCY_ARG
from scan.sqli_stages import SQLI_TECHNIQUE_NEGATIVE_COST
from scan.verification_extension import EXTENDS_ARG
from scan.work_manifests import ScanWorkManifestKind, build_candidate_manifest, build_endpoint_manifest
from tests.test_body_attempt_mutation_accounting import _enforcement
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop

ORIGIN = "https://app.example.test"
LOGIN = "/hub/login"
FORM = "application/x-www-form-urlencoded"


def _for(url, endpoints, method="POST"):
    found = sign_in_endpoint_for(url, method, endpoints)
    return found.label if found is not None else None


# --- which requests are the sign-in endpoint ----------------------------------------------------

def test_the_probe_sets_hold_twice_the_level_two_ladder_and_a_bounded_xss_set():
    # Twice sqlmap's measured cost to a negative verdict at level 2 / risk 2, per tested field: a
    # real sign-in costs more per unit than the plain fixture the ladder was measured on.
    assert AUTH_ENDPOINT_PROBE_HEADROOM == 2
    assert sum(SQLI_TECHNIQUE_NEGATIVE_COST.values()) == 473
    assert AUTH_ENDPOINT_PROBE_REQUESTS["sqli.verify_batch"] == 2 * 473 == 946
    assert probe_set_requests("sqli.verify_batch", 2) == 1_892
    assert probe_set_requests("xss.verify_batch", 2) == 128
    assert probe_set_requests("xss.verify_batch", 9) == probe_set_requests("xss.verify_batch", 4)


def test_spelling_variants_of_the_sign_in_path_are_the_same_endpoint():
    endpoints = sign_in_endpoints({"login_url": LOGIN}, [], base_url=f"{ORIGIN}/")
    for variant in ("/hub/login", "/hub/login/", "/hub/Login", "/HUB/LOGIN", "/hub//login",
                    "/hub/./login", "/hub/x/../login", "/hub/login;jsessionid=1", "/hub/%6cogin",
                    "/hub/%6Cogin"):
        assert _for(f"{ORIGIN}{variant}", endpoints) == LOGIN, variant
    for other in ("/hub/logins", "/hub/login/extra", "/api/feedback", "/login"):
        assert _for(f"{ORIGIN}{other}", endpoints) is None, other
    assert _for(f"https://other.example.test{LOGIN}", endpoints) is None
    assert _for(f"http://app.example.test{LOGIN}", endpoints) is None
    assert normalize_path("/Account/./Login;x=1") == normalize_path("/account//login/") == "/account/login"
    # Case folding errs toward the endpoint: an IIS-style path is one endpoint in any case.
    iis = sign_in_endpoints({"login_url": "/Account/Login"}, [], base_url=f"{ORIGIN}/")
    assert _for(f"{ORIGIN}/account/login", iis) == "/Account/Login"


def test_only_a_request_with_a_body_attempts_a_sign_in():
    endpoints = sign_in_endpoints({"login_url": LOGIN}, [], base_url=f"{ORIGIN}/")
    for method in ("POST", "PUT", "PATCH", "post"):
        assert _for(f"{ORIGIN}{LOGIN}", endpoints, method) == LOGIN
    for method in ("GET", "HEAD", "OPTIONS", ""):
        assert _for(f"{ORIGIN}{LOGIN}?next=1", endpoints, method) is None
        assert _for(f"{ORIGIN}{LOGIN}?ReturnUrl=%2F", endpoints, method) is None


@pytest.mark.parametrize("login_url,sign_in,others", [
    ("/index.php?r=site/login", "/index.php?r=site/login", ["/index.php?r=product/view&id=1", "/index.php"]),
    ("/?action=login", "/?action=login&x=1", ["/?page=item&id=3", "/"]),
    ("/index.php?route=account/login", "/index.php?route=account%2Flogin",
     ["/index.php?route=product/search&search=x", "/index.php?route=account/register"]),
    ("/index.php?option=com_users&view=login", "/index.php?view=login&option=com_users&Itemid=101",
     ["/index.php?option=com_users&view=registration", "/index.php?option=com_content"]),
    ("/index.php?title=Special:UserLogin", "/index.php?title=Special:UserLogin&returnto=Main",
     ["/index.php?title=Main_Page&action=edit"]),
    ("/ucp.php?mode=login", "/ucp.php?mode=login&sid=1", ["/ucp.php?mode=register", "/posting.php?mode=post"]),
])
def test_a_front_controller_sign_in_is_keyed_on_its_routing_query(login_url, sign_in, others):
    endpoints = sign_in_endpoints({"login_url": login_url}, [], base_url=f"{ORIGIN}/")
    assert _for(f"{ORIGIN}{sign_in}", endpoints) is not None
    for other in others:
        assert _for(f"{ORIGIN}{other}", endpoints) is None, other


def test_a_query_that_says_where_to_go_next_does_not_route():
    endpoints = sign_in_endpoints({"login_url": "/login?next=/dashboard&lang=en"}, [],
                                  base_url=f"{ORIGIN}/")
    assert _for(f"{ORIGIN}/login", endpoints) == "/login"
    assert routing_digests("next=/x&ReturnUrl=/y&redirect_uri=z&token=abc&state=Zx9Qp2Lm7Rt4Wv8Yb3Nc") == frozenset()
    assert routing_digests("route=account/login")


def test_the_page_is_not_the_endpoint_when_its_form_posts_elsewhere():
    """A sign-in box on the home page posts to /session: the site search on / is not limited."""
    observation = {"kind": "credential_session", "auth_kind": "form_login", "status": "established",
                   "endpoint_path": "/", "form_action_path": "/session"}
    endpoints = sign_in_endpoints({"login_url": "/"}, [observation], base_url=f"{ORIGIN}/")
    assert _for(f"{ORIGIN}/session", endpoints) == "/session"
    assert _for(f"{ORIGIN}/?q=shoes", endpoints) is None
    assert _for(f"{ORIGIN}/", endpoints) is None
    # A form that posts back to its own page: the page is the endpoint.
    same = dict(observation, endpoint_path=LOGIN, form_action_path=LOGIN)
    assert _for(f"{ORIGIN}{LOGIN}", sign_in_endpoints({"login_url": LOGIN}, [same], base_url=f"{ORIGIN}/")) == LOGIN


def test_a_form_action_with_a_query_is_still_its_sign_in_endpoint():
    recorded = {"kind": "credential_session", "auth_kind": "form_login", "status": "established",
                "endpoint_path": "/signin", "form_action_path": "/auth", "form_action_has_query": True}
    endpoints = sign_in_endpoints({}, [recorded], base_url=f"{ORIGIN}/")
    assert _for(f"{ORIGIN}/auth", endpoints) == "/auth"
    assert _for(f"{ORIGIN}/auth?step=2", endpoints) == "/auth"
    assert _for(f"{ORIGIN}/signin", endpoints) is None
    # A record from before the action's path was kept apart from its query.
    legacy = dict(recorded, form_action_path="/auth?<redacted-query>")
    legacy.pop("form_action_has_query")
    assert _for(f"{ORIGIN}/auth", sign_in_endpoints({}, [legacy], base_url=f"{ORIGIN}/")) == "/auth"


def test_a_json_sign_in_with_a_routing_query_is_recognized_from_its_record():
    record = {"kind": "credential_session", "auth_kind": "json_login", "status": "established",
              "endpoint_path": "/index.php?<redacted-query>",
              "endpoint_routing": sorted(routing_digests("r=api/login"))}
    endpoints = sign_in_endpoints({}, [record], base_url=f"{ORIGIN}/")
    assert _for(f"{ORIGIN}/index.php?r=api/login", endpoints) == "/index.php"
    assert _for(f"{ORIGIN}/index.php?r=api/orders", endpoints) is None
    # Without its routing the record names nothing: the bare script is not the endpoint.
    unknown = dict(record)
    unknown.pop("endpoint_routing")
    assert sign_in_endpoints({}, [unknown], base_url=f"{ORIGIN}/") == ()


def test_the_sign_in_records_where_its_form_posts():
    from tests.test_authenticated_crawl_seeds import _form_login

    observation = _form_login("/hub/")
    assert observation["form_action_path"] == "/hub/login"
    assert "form_action_has_query" not in observation
    endpoints = sign_in_endpoints({}, [observation], base_url=f"{ORIGIN}/")
    assert _for(f"{ORIGIN}/hub/login", endpoints) == "/hub/login"
    routed = _form_login("/hub/", action="/index.php?route=account/login&token=Zx9Qp2Lm7Rt4Wv8Yb3Nc")
    assert routed["form_action_path"] == "/index.php" and routed["form_action_has_query"] is True
    assert routed["form_action_routing"] == sorted(routing_digests("route=account/login"))
    assert "account" not in str(routed) and "Zx9Qp2" not in str(routed)  # digests only
    endpoints = sign_in_endpoints({}, [routed], base_url=f"{ORIGIN}/")
    assert _for(f"{ORIGIN}/index.php?route=account/login", endpoints) == "/index.php"
    assert _for(f"{ORIGIN}/index.php?route=product/search", endpoints) is None


# --- the hold and the pace ----------------------------------------------------------------------

def test_an_attempt_holds_what_the_probe_set_has_left_at_the_paced_rate():
    body = {"http_requests": 480, "state_changing_requests": 480, "tool_wall_seconds": 420}
    assert AUTH_ENDPOINT_SECONDS_PER_REQUEST == 3
    hold = auth_endpoint_hold(body, capability_name="sqli.verify_batch", received=0, parameters=2)
    assert hold == {"http_requests": 140, "state_changing_requests": 140, "tool_wall_seconds": 420}
    late = auth_endpoint_hold(body, capability_name="sqli.verify_batch", received=1_850, parameters=2)
    assert late["http_requests"] == 42
    # Across parallel children the pace is divided among them.
    split = auth_endpoint_hold(body, capability_name="sqli.verify_batch", received=0, parameters=2, children=2)
    assert split["http_requests"] == 70
    # A wall that cannot pace a probe holds nothing: the candidate waits for a later round.
    assert auth_endpoint_hold({"http_requests": 160, "tool_wall_seconds": 23},
                              capability_name="sqli.verify_batch", received=0) is None
    assert auth_endpoint_hold({"http_requests": 160, "tool_wall_seconds": 24},
                              capability_name="sqli.verify_batch", received=0)["http_requests"] == 8


def _plan_argv(tool, url, options, budget, tmp_path):
    tmp_path.chmod(0o700)
    runtime = {"sqlmap_output_dir": str(tmp_path)} if tool == "sqlmap" else {}
    return list(agent_tools.build_enforced_scanner_plan(
        tool, url, options, reserved_budget=budget, pinned_proxy_url="socks5://127.0.0.1:41000",
        runtime_paths=runtime,
    ).argv)


BODY = {"_batch_attempt": True, "method": "POST", "body_field_names": ["username", "password"],
        "injection_field": "username", "content_type": FORM}


def test_sqlmap_keeps_its_level_two_ladder_on_the_sign_in_endpoint_at_the_pace(tmp_path):
    budget = {"http_requests": 140, "state_changing_requests": 140, "tool_wall_seconds": 420}
    argv = _plan_argv("sqlmap", f"{ORIGIN}{LOGIN}", {**BODY, "probe_profile": "auth_endpoint"}, budget, tmp_path)
    assert argv[argv.index("--level") + 1] == "2" and argv[argv.index("--risk") + 1] == "2"
    assert argv[argv.index("--threads") + 1] == "1"
    assert float(argv[argv.index("--delay") + 1]) >= AUTH_ENDPOINT_SECONDS_PER_REQUEST


def test_a_small_remaining_stage_hold_keeps_the_three_second_floor(tmp_path):
    """A later stage holds less: its own wall/requests pace would be faster than 20 a minute."""
    budget = {"http_requests": 50, "state_changing_requests": 50, "tool_wall_seconds": 100}
    argv = _plan_argv("sqlmap", f"{ORIGIN}{LOGIN}", {**BODY, "probe_profile": "auth_endpoint"}, budget, tmp_path)
    assert float(argv[argv.index("--delay") + 1]) >= AUTH_ENDPOINT_SECONDS_PER_REQUEST
    shard = _plan_argv("sqlmap", f"{ORIGIN}{LOGIN}",
                       {**BODY, "probe_profile": "auth_endpoint", "probe_pace_seconds": 6}, budget, tmp_path)
    assert float(shard[shard.index("--delay") + 1]) >= 6
    dalfox = _plan_argv("dalfox", f"{ORIGIN}{LOGIN}", {**BODY, "probe_profile": "auth_endpoint"},
                        {"http_requests": 30, "state_changing_requests": 30, "tool_wall_seconds": 60}, tmp_path)
    assert int(dalfox[dalfox.index("--delay") + 1]) >= AUTH_ENDPOINT_SECONDS_PER_REQUEST * 1_000


def test_dalfox_tests_the_body_of_the_sign_in_request_and_stops_at_its_first_proof(tmp_path):
    budget = {"http_requests": 128, "state_changing_requests": 128, "tool_wall_seconds": 420}
    argv = _plan_argv("dalfox", f"{ORIGIN}{LOGIN}", {**BODY, "probe_profile": "auth_endpoint"}, budget, tmp_path)
    # Its custom-payload mode puts the payloads in the URL's query and leaves the body alone.
    assert "--only-custom-payload" not in argv and "--custom-payload" not in argv
    assert "--skip-discovery" not in argv
    assert argv[argv.index("-X") + 1] == "POST" and "-d" in argv
    assert argv[argv.index("--worker") + 1] == "1"
    assert int(argv[argv.index("--delay") + 1]) >= AUTH_ENDPOINT_SECONDS_PER_REQUEST * 1_000
    assert argv[argv.index("--limit-result") + 1] == "1"
    assert argv[argv.index("--limit-result-type") + 1] == "v"
    other = _plan_argv("dalfox", f"{ORIGIN}/api/feedback", BODY,
                       {"http_requests": 240, "state_changing_requests": 240, "tool_wall_seconds": 120}, tmp_path)
    assert "--limit-result" not in other and other[other.index("--worker") + 1] == "3"


@pytest.mark.parametrize("profile", [None, "auth_endpoint"])
def test_a_body_candidate_on_a_routed_action_keeps_dalfox_on_its_body(profile, tmp_path):
    """One routing pair in the action's query is not the parameter a body candidate verifies."""
    argv = _plan_argv("dalfox", f"{ORIGIN}/index.php?route=account/login", {**BODY, "probe_profile": profile},
                      {"http_requests": 128, "state_changing_requests": 128, "tool_wall_seconds": 420}, tmp_path)
    assert "--skip-discovery" not in argv and "--only-custom-payload" not in argv
    assert [argv[index + 1] for index, value in enumerate(argv) if value == "-p"] == ["username", "password"]


# --- the batch ----------------------------------------------------------------------------------

def _runner(tool, parser, *, sent, record):
    calls: list[dict] = []

    async def process_runner(payload, *, heartbeat):
        reserved = dict(payload["_reserved_budget"])
        options = dict(payload["scanner_options"])
        call = {"target": payload["execution_target"], "reserved": reserved, "options": options}
        calls.append(call)
        sign_in = bool(options.get("probe_profile"))
        record["running"] += 1
        record["sign_in"] += sign_in
        record["peak"] = max(record["peak"], record["running"])
        record["sign_in_peak"] = max(record["sign_in_peak"], record["sign_in"])
        await asyncio.sleep(0.005)
        record["running"] -= 1
        record["sign_in"] -= sign_in
        count = min(sent, int(reserved["http_requests"]))
        return {
            # A slow target (3.45 s a request), so a concurrent slice keeps its slots open.
            "status": "success",
            "elapsed_seconds": max(1, min(int(reserved["tool_wall_seconds"]), math.ceil(count * 3.45))),
            "typed_output": {"parser": parser, "records": [], "errors": []},
            "settlement": {"mode": "exact", "actual": count, "observed_minimum": count},
            "process_enforcement": _enforcement(tool, parser, {
                name: reserved[name] for name in ("http_requests", "tool_wall_seconds")
            }),
        }

    process_runner.enforces_request_gate = True
    return process_runner, calls


SIGN_IN_ROUTES = (
    ("POST", LOGIN, ["password", "username"], FORM, [], "inputs.custom_endpoints"),
    ("POST", LOGIN, ["csrf_token", "password", "remember", "username"], FORM, [], "web.crawl"),
    ("POST", LOGIN, ["password", "username"], "application/json", [], "web.spec_ingest"),
    ("GET", LOGIN, None, None, ["next"], "web.crawl"),
)
DEFAULT_ROUTES = (
    ("POST", LOGIN, ["username", "password"], FORM, [], "inputs.custom_endpoints"),
    ("POST", "/api/feedback", ["comment"], FORM, [], "inputs.custom_endpoints"),
)
LARGE = {"http_requests": 6_000, "state_changing_requests": 6_000, "tool_wall_seconds": 6_000}


class _StoredOnce(Backend):
    """Checkpoints kept the way the scan database keeps them: an attempt id's first row stands, and
    a later row for it with another candidate or status is refused (the fake above keeps the last)."""

    async def checkpoint_batch_attempt(self, action_id, attempt):
        stored = self.attempts.setdefault(action_id, {})
        prior = stored.get(attempt["attempt_id"])
        if prior is None:
            stored[attempt["attempt_id"]] = dict(attempt)
        elif (prior["candidate_id"], prior["status"]) != (attempt["candidate_id"], attempt["status"]):
            raise RuntimeError("batch attempt checkpoint conflicts with authority")


def _slice(capability, *, tool, parser, sent, options, routes=DEFAULT_ROUTES, rounds=1, budget=None,
           concurrency=None, measured=False, runner=None, budgets=None, backend_type=Backend):
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
    args = {
        "candidate_manifest_ref": candidates.reference().canonical_dict(),
        "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        "slice": {"start": 0, "count": len(candidates.entries)}, "profile": "balanced_batch_v1",
        "proof_policy": "deterministic_differential_required",
        **({CANDIDATE_CONCURRENCY_ARG: concurrency} if concurrency else {}),
    }
    actions = []
    for index in range(rounds):
        actions.append(dataclasses.replace(
            _action(f"verify.x.r0{index + 1}", capability, index, capability_args={
                **args, **({EXTENDS_ARG: actions[-1].action_id} if actions else {}),
            }),
            requested_budget=dict((budgets or {}).get(index) or budget or LARGE), action_digest=None,
        ))
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=tuple(actions))
    backend = backend_type(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    if measured:
        # A stage another candidate finished on this slow target: concurrent slots open at once.
        from tests.test_sqli_concurrent_candidates import _measured_on_target
        _measured_on_target(backend, actions[0].action_id)
    dispatcher = _dispatcher(plan, backend, options=options, policy=ScanPolicy(
        active_testing=True, allow_state_changing_http=True, approval_receipt_id="approval-1",
    ))
    record = {"running": 0, "sign_in": 0, "peak": 0, "sign_in_peak": 0}
    runner, calls = (runner or _runner)(tool, parser, sent=sent, record=record)
    dispatcher.process_runner = runner
    receipts, per_round = [], []
    for action in actions:
        before = len(calls)
        receipts.append(asyncio.run(dispatcher(action, _lease(plan, action), _noop)))
        per_round.append(calls[before:])
    return receipts, per_round, record


def _sent_to(calls, path):
    return [call for call in calls if call["target"].split("?")[0].endswith(path)]


def _sign_in_calls(calls):
    return [call for call in calls if call["options"].get("probe_profile")]


def _heads(receipt):
    return [item for item in receipt.observations
            if item.get("kind") == "candidate_attempt" and item.get("sign_in_endpoint")]


SQLI = ("sqli.verify_batch", "sqlmap", "sqlmap-output/v1")
XSS = ("xss.verify_batch", "dalfox", "dalfox-jsonl/v1")


@pytest.mark.parametrize("capability,tool,parser", [SQLI, XSS])
def test_the_sign_in_endpoint_gets_its_pace_and_other_endpoints_their_full_hold(capability, tool, parser):
    receipts, (calls,), _record = _slice(capability, tool=tool, parser=parser, sent=10_000,
                                         options={"login_url": LOGIN})
    login, other = _sent_to(calls, LOGIN), _sent_to(calls, "/api/feedback")
    assert login and other
    for call in login:
        reserved = call["reserved"]
        assert reserved["tool_wall_seconds"] >= reserved["http_requests"] * AUTH_ENDPOINT_SECONDS_PER_REQUEST
        assert call["options"].get("probe_profile") == "auth_endpoint"
    assert sum(call["reserved"]["http_requests"] for call in login) <= probe_set_requests(capability, 2)
    assert all(call["options"].get("probe_profile") is None for call in other)
    # The other endpoint keeps the batch's own pace, faster than the sign-in pace.
    assert any(call["reserved"]["tool_wall_seconds"] < call["reserved"]["http_requests"] * 3 for call in other)
    heads = _heads(receipts[0])
    assert {head["sign_in_endpoint"] for head in heads} == {LOGIN}
    assert all(head["sign_in_endpoint_requests"] > 0 for head in heads)


@pytest.mark.parametrize("capability,tool,parser", [SQLI, XSS])
def test_one_probe_set_is_shared_by_every_candidate_on_the_endpoint(capability, tool, parser):
    """The declared form, the crawled form with hidden fields and a JSON variant: one endpoint."""
    receipts, (calls,), _record = _slice(capability, tool=tool, parser=parser, sent=10_000,
                                         options={"login_url": LOGIN}, routes=SIGN_IN_ROUTES)
    sign_in = _sign_in_calls(calls)
    assert len({tuple(call["options"]["body_field_names"]) for call in sign_in}) >= 2
    total = sum(call["reserved"]["http_requests"] for call in sign_in)
    # At most the largest candidate's probe set (four fields), not one probe set per candidate.
    assert total <= probe_set_requests(capability, 4), total
    # The query candidate on the sign-in page attempts no sign-in: its own full hold.
    page = [call for call in _sent_to(calls, LOGIN) if "next=" in call["target"]]
    assert page and all(call["options"].get("probe_profile") is None for call in page)
    received = [head["sign_in_endpoint_received"] for head in _heads(receipts[0])]
    assert len(received) == 3 and received == sorted(received) and received[-1] == total


def test_continuation_rounds_draw_from_the_same_probe_set_and_stop_when_it_is_spent():
    capability, tool, parser = SQLI
    receipts, rounds, _record = _slice(capability, tool=tool, parser=parser, sent=10_000,
                                       options={"login_url": LOGIN}, rounds=8, routes=DEFAULT_ROUTES[:1],
                                       budget={"http_requests": 6_000, "state_changing_requests": 6_000,
                                               "tool_wall_seconds": 900})
    sent = [sum(call["reserved"]["http_requests"] for call in _sent_to(calls, LOGIN)) for calls in rounds]
    # The fake spends each unit's whole hold: 1,800 of 1,892 after six rounds (union, boolean and
    # error on both fields), and what is left cannot conclude the next unit (time-based over one
    # field, 189), so the candidate is closed.
    assert sent == [300] * 6 + [0, 0]
    assert sum(sent) <= probe_set_requests(capability, 2)
    for receipt in receipts[6:]:
        (closed,) = [item for item in receipt.observations if item.get("kind") == "candidate_attempt"]
        assert closed["verdict"] == "inconclusive"
        assert closed["inconclusive_reason"] == AUTH_ENDPOINT_PROBE_LIMITED
        assert closed["sign_in_endpoint_received"] == 1_800
        assert "resume_wall_seconds" not in closed
        assert receipt.status == "success"


def _overspending(overspend, *, content_types=None):
    """A fake sqlmap whose every unit settles negative after ``overspend`` times its measured cost
    (``content_types`` names another multiple for a body of that content type)."""

    def factory(tool, parser, *, sent, record):
        calls: list[dict] = []

        async def process_runner(payload, *, heartbeat):
            reserved = dict(payload["_reserved_budget"])
            options = dict(payload["scanner_options"])
            calls.append({"target": payload["execution_target"], "reserved": reserved, "options": options,
                          "job": payload["job_id"]})
            await asyncio.sleep(0)
            cost = SQLI_TECHNIQUE_NEGATIVE_COST[str(options["technique"])]
            factor = (content_types or {}).get(options.get("content_type"), overspend)
            count = min(math.ceil(cost * factor), int(reserved["http_requests"]))
            return {
                "status": "success",
                "elapsed_seconds": max(1, min(int(reserved["tool_wall_seconds"]), math.ceil(count * 3.45))),
                "typed_output": {"parser": parser, "records": [], "errors": []},
                "settlement": {"mode": "exact", "actual": count, "observed_minimum": count},
                "process_enforcement": _enforcement(tool, parser, {
                    name: reserved[name] for name in ("http_requests", "tool_wall_seconds")
                }),
            }

        process_runner.enforces_request_gate = True
        return process_runner, calls

    return factory


def test_a_sign_in_form_whose_units_cost_more_than_measured_still_runs_every_unit():
    """Real sign-in pages cost more per unit than the plain fixture the ladder was measured on.

    A two-field form whose second field is injectable only by time-based blind: with every unit
    10% over its measured cost, the probe set (2x the measured ladder) still funds T on it.
    """
    capability, tool, parser = SQLI
    receipts, (calls,), _record = _slice(capability, tool=tool, parser=parser, sent=0,
                                         options={"login_url": LOGIN}, routes=DEFAULT_ROUTES[:1],
                                         runner=_overspending(1.1))
    units = [(call["options"]["technique"], tuple(call["options"].get("injection_fields") or ()))
             for call in _sign_in_calls(calls)]
    assert ("T", ("password",)) in units and ("T", ("username",)) in units, units
    assert len(units) == 8
    (head,) = _heads(receipts[0])
    assert head.get("inconclusive_reason") != AUTH_ENDPOINT_PROBE_LIMITED
    assert head["sign_in_endpoint_received"] == 2 * sum(
        math.ceil(cost * 1.1) for cost in SQLI_TECHNIQUE_NEGATIVE_COST.values()
    )


def _units_by_attempt(rounds):
    """Each candidate attempt's body fields and the (technique, field) units dispatched for it.

    A stage's job id carries its candidate attempt's id: ``<job>:<action>:<attempt[:16]>:<unit>``.
    """
    fields: dict[str, set] = {}
    units: dict[str, set] = {}
    for calls in rounds:
        for call in _sign_in_calls(calls):
            attempt = call["job"].split(":")[2]
            fields.setdefault(attempt, set()).update(call["options"]["body_field_names"])
            units.setdefault(attempt, set()).update(
                (call["options"]["technique"], field)
                for field in call["options"].get("injection_fields") or ()
            )
    return fields, units


def test_variants_of_one_sign_in_form_draw_from_one_probe_set_across_rounds():
    """The declared form, the crawled form with hidden fields and a JSON variant share one
    candidate identity (route, method, the field that anchors it); each is still its own attempt.

    Every unit settles negative at 1.5 times its measured cost, so the three cannot all finish
    inside the probe set: over eight rounds the endpoint receives at most the largest candidate's
    set, and every candidate either ran each of its units or is inconclusive for the limit.
    """
    capability, tool, parser = SQLI
    over = 1.5
    receipts, rounds, _record = _slice(capability, tool=tool, parser=parser, sent=0,
                                       options={"login_url": LOGIN}, routes=SIGN_IN_ROUTES, rounds=8,
                                       runner=_overspending(over), backend_type=_StoredOnce)
    sent = sum(
        min(math.ceil(SQLI_TECHNIQUE_NEGATIVE_COST[str(call["options"]["technique"])] * over),
            int(call["reserved"]["http_requests"]))
        for calls in rounds for call in _sign_in_calls(calls)
    )
    assert sent <= probe_set_requests(capability, 4), sent
    # What each round starts from is what the endpoint already received.
    for receipt, calls in zip(receipts[1:], rounds[1:]):
        heads = [head for head in _heads(receipt) if not head.get("carried_from")]
        if heads:
            first = min(head["sign_in_endpoint_received"] - head["sign_in_endpoint_requests"]
                        for head in heads)
            assert first >= sum(
                min(math.ceil(SQLI_TECHNIQUE_NEGATIVE_COST[str(call["options"]["technique"])] * over),
                    int(call["reserved"]["http_requests"]))
                for earlier in rounds[:rounds.index(calls)] for call in _sign_in_calls(earlier)
            )
    fields, units = _units_by_attempt(rounds)
    final = {head["attempt_id"]: head for head in _heads(receipts[-1])}
    assert len(final) == 3, final
    for attempt_id, head in final.items():
        own = fields.get(attempt_id[:16], set())
        every_unit = {(technique, field) for technique in "UBET" for field in own}
        if own and units[attempt_id[:16]] == every_unit:
            continue
        assert head.get("verdict") == "inconclusive", (sorted(units.get(attempt_id[:16], ())), head)
        assert head.get("inconclusive_reason") == AUTH_ENDPOINT_PROBE_LIMITED


def test_variants_of_one_form_keep_their_own_units_without_a_sign_in_profile():
    """With no sign-in profile the same three variants are ordinary body candidates: each runs
    every unit over its own fields, none takes another's settled unit as its own."""
    capability, tool, parser = SQLI
    _receipts, rounds, _record = _slice(capability, tool=tool, parser=parser, sent=0, options={},
                                        routes=SIGN_IN_ROUTES, rounds=4, runner=_overspending(1.0),
                                        backend_type=_StoredOnce)
    ran: dict[tuple, set] = {}
    for calls in rounds:
        for call in calls:
            names = tuple(call["options"].get("body_field_names") or ())
            if names:
                key = (names, call["options"].get("content_type"))
                ran.setdefault(key, set()).update(
                    (call["options"]["technique"], field)
                    for field in call["options"].get("injection_fields") or ()
                )
    assert len(ran) == 3, sorted(ran)
    for (names, _content_type), done in ran.items():
        assert done == {(technique, field) for technique in "UBET" for field in names}, (names, done)


def test_a_variant_whose_sibling_concluded_still_shares_the_next_round_with_the_others():
    """Round 0 concludes the JSON variant (its units settle in a few requests) and leaves both form
    variants unfinished. Round 1 carries the JSON one and splits its hold between the two forms: the
    first form is not handed the whole round because the one after it has the concluded variant's
    candidate id."""
    capability, tool, parser = SQLI
    budgets = {
        0: {"http_requests": 6_000, "state_changing_requests": 6_000, "tool_wall_seconds": 3_000},
        1: {"http_requests": 6_000, "state_changing_requests": 6_000, "tool_wall_seconds": 900},
    }
    receipts, (_first, later), _record = _slice(
        capability, tool=tool, parser=parser, sent=0, options={}, routes=SIGN_IN_ROUTES[:3], rounds=2,
        budgets=budgets, backend_type=_StoredOnce,
        runner=_overspending(1.0, content_types={"application/json": 0.02}),
    )
    carried = [item for item in receipts[1].observations
               if item.get("kind") == "candidate_attempt" and item.get("carried_from")]
    assert len(carried) == 1, carried
    assert {len(call["options"]["body_field_names"]) for call in later} == {2, 4}, later
    assert later[0]["reserved"]["http_requests"] <= 6_000 // 2
    assert later[0]["reserved"]["tool_wall_seconds"] <= 900 // 2


def test_the_first_entry_of_a_candidate_id_keeps_the_attempt_id_earlier_builds_checkpointed():
    """An attempt a worker of an earlier build checkpointed is named by the manifest, the family
    and the candidate id alone; the first entry with that id still is, so it resumes instead of
    being re-sent, and only the later variants get attempt ids of their own."""
    backends = []

    class Kept(_StoredOnce):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            backends.append(self)

    receipts, _rounds, _record = _slice(*SQLI[:1], tool="sqlmap", parser="sqlmap-output/v1", sent=0,
                                        options={}, routes=SIGN_IN_ROUTES,
                                        runner=_overspending(1.0), backend_type=Kept)
    (manifest,) = [item for item in backends[0].manifests.values()
                   if item.kind is ScanWorkManifestKind.CANDIDATE]
    digest = manifest.reference().manifest_digest
    earlier = {
        hashlib.sha256(f"{digest}:sqli:{candidate_id}".encode()).hexdigest()
        for candidate_id in {entry["candidate_id"] for entry in manifest.entries}
    }
    attempts = {item["attempt_id"] for item in receipts[0].observations
                if item.get("kind") == "candidate_attempt"}
    assert len(manifest.entries) == 4 and len(earlier) == 2
    assert earlier <= attempts and len(attempts) == 4, (earlier, attempts)


def _answering_in(latency, *, sent):
    """A fake sqlmap on a target answering in ``latency`` s, paced by the delay its argv gets."""

    def factory(tool, parser, *, sent=sent, record):
        calls: list[dict] = []

        async def process_runner(payload, *, heartbeat):
            reserved = dict(payload["_reserved_budget"])
            options = dict(payload["scanner_options"])
            # The delay the worker's sqlmap argv gets (build_enforced_scanner_plan).
            delay, _ = agent_tools._batch_attempt_pacing(
                int(reserved["http_requests"]), int(reserved["tool_wall_seconds"]),
                minimum_seconds=agent_tools._auth_probe_minimum(options, 0.05),
                latency_seconds=float(options.get("_measured_latency_seconds") or 0.0),
            )
            calls.append({"target": payload["execution_target"], "reserved": reserved,
                          "options": options, "delay": delay})
            await asyncio.sleep(0)
            count = min(sent, int(reserved["http_requests"]))
            return {
                "status": "success",
                "elapsed_seconds": max(1, min(int(reserved["tool_wall_seconds"]),
                                              round(count * (delay + latency)))),
                "typed_output": {"parser": parser, "records": [], "errors": []},
                "settlement": {"mode": "exact", "actual": count, "observed_minimum": count},
                "process_enforcement": _enforcement(tool, parser, {
                    name: reserved[name] for name in ("http_requests", "tool_wall_seconds")
                }),
            }

        process_runner.enforces_request_gate = True
        return process_runner, calls

    return factory


def test_a_sign_in_candidate_measures_the_targets_latency_at_the_pace_it_ran():
    """The sign-in pace (3 s) binds where the batch pace would be faster: the stage records that
    delay, so what it measures is the target's latency (1 s here), not the gap between the two
    delays, and the next stage is paced from the true latency."""
    capability, tool, parser = SQLI
    receipts, (calls,), _record = _slice(
        capability, tool=tool, parser=parser, sent=40, options={"login_url": LOGIN},
        routes=DEFAULT_ROUTES[:1], runner=_answering_in(1.0, sent=40),
        # A wall that paces the hold a little slower than the floor (about 3.3 s a request).
        budget={"http_requests": 6_000, "state_changing_requests": 6_000, "tool_wall_seconds": 2_880},
    )
    sign_in = _sign_in_calls(calls)
    assert len(sign_in) == 8
    # The first stage is paced slower than the floor; the latency credit then reaches it.
    assert sign_in[0]["delay"] > AUTH_ENDPOINT_SECONDS_PER_REQUEST
    assert any(call["delay"] == AUTH_ENDPOINT_SECONDS_PER_REQUEST for call in sign_in[1:])
    stages = [item for item in receipts[0].observations if item.get("kind") == "sqli_technique_stage"]
    assert len(stages) == 8
    for stage, call in zip(stages, sign_in):
        assert call["delay"] >= AUTH_ENDPOINT_SECONDS_PER_REQUEST
        assert stage["delay_ms"] == round(call["delay"] * 1_000)
        assert 950 <= stage["measured_latency_ms"] <= 1_050, stages
        # Marked, so what it measured paces this candidate only (prior_stages).
        assert stage["paced_floor_ms"] == AUTH_ENDPOINT_SECONDS_PER_REQUEST * 1_000
    for call in sign_in[1:]:
        assert abs(call["options"]["_measured_latency_seconds"] - 1.0) <= 0.05


def test_a_scan_split_in_two_records_the_pace_its_stages_ran_at():
    """Two parallel parts pace the endpoint at one request per 6 s: each stage records that floor
    and the delay its argv ran at, so it measures the target's latency (1 s), not the 3 s gap
    between a floor of one part and the pace of two."""
    capability, tool, parser = SQLI
    shard = {"canonical_shard_authority": {"shard_index": 0, "shard_count": 2}}
    receipts, (calls,), _record = _slice(
        capability, tool=tool, parser=parser, sent=40, options={"login_url": LOGIN, **shard},
        routes=DEFAULT_ROUTES[:1], runner=_answering_in(1.0, sent=40),
        budget={"http_requests": 6_000, "state_changing_requests": 6_000, "tool_wall_seconds": 5_760},
    )
    sign_in = _sign_in_calls(calls)
    assert len(sign_in) == 8
    stages = [item for item in receipts[0].observations if item.get("kind") == "sqli_technique_stage"]
    assert len(stages) == 8
    for stage, call in zip(stages, sign_in):
        assert call["delay"] >= 2 * AUTH_ENDPOINT_SECONDS_PER_REQUEST
        assert stage["paced_floor_ms"] == 2 * AUTH_ENDPOINT_SECONDS_PER_REQUEST * 1_000
        assert stage["delay_ms"] == round(call["delay"] * 1_000)
        assert 950 <= stage["measured_latency_ms"] <= 1_050, stages
    for call in sign_in[1:]:
        assert abs(call["options"]["_measured_latency_seconds"] - 1.0) <= 0.05


def test_a_stage_paced_at_its_endpoints_floor_does_not_size_the_slices_slots():
    """The slice sizes its concurrent slots from the target's latency; a stage paced at the sign-in
    floor measured that one endpoint and is not reported to it. A stage of any other candidate is."""
    from types import SimpleNamespace

    from scan.sqli_stages import PriorStages, run_staged_sqli_attempt

    async def run_stage(technique, budget, latency, field_name=None):
        return SimpleNamespace(status="success", timed_out=False, observations=(), errors=(),
                               actual_budget={"http_requests": 40, "tool_wall_seconds": 160})

    async def checkpoint(_stage):
        return None

    def attempt(floor):
        seen: list[float] = []
        result = asyncio.run(run_staged_sqli_attempt(
            candidate_attempt_id="a" * 64, candidate_id="c1",
            budget={"http_requests": 900, "tool_wall_seconds": 6_000}, prior=PriorStages(),
            own_action_id="verify.x.r01", run_stage=run_stage, checkpoint=checkpoint,
            cancelled=lambda: False, measured=seen.append, minimum_delay_seconds=floor,
        ))
        assert result.status == "success"
        return seen

    assert attempt(float(AUTH_ENDPOINT_SECONDS_PER_REQUEST)) == []
    assert len(attempt(None)) == 4


def test_a_sign_in_candidates_latency_is_not_the_targets():
    """Another candidate on the target is not paced from what the sign-in endpoint measured."""
    from scan.sqli_stages import STAGE_RECORD_KIND, prior_stages, stage_attempt_id

    def stage(candidate, technique, *, wall, extra):
        return {
            "attempt_id": stage_attempt_id(candidate, technique), "candidate_id": candidate,
            "status": "success", "timed_out": False,
            "budget_consumed": {"http_requests": 40, "tool_wall_seconds": wall},
            "observations": ({"kind": STAGE_RECORD_KIND, "technique": technique, "delay_ms": 3_000,
                              **extra},),
        }

    sign_in = stage("a" * 64, "U", wall=200, extra={"paced_floor_ms": 3_000})
    assert prior_stages([("verify.x.r01", [sign_in])], "b" * 64).latency_seconds is None
    # Its own next stage is paced from it.
    assert prior_stages([("verify.x.r01", [sign_in])], "a" * 64).latency_seconds == pytest.approx(2.0)
    # A stage of any other candidate still gives the target's latency.
    other = stage("c" * 64, "U", wall=160, extra={})
    assert prior_stages([("verify.x.r01", [sign_in, other])], "b" * 64).latency_seconds == pytest.approx(1.0)


def test_a_wall_too_short_to_pace_a_probe_leaves_the_candidate_for_a_later_round():
    """Eight parallel children pace the endpoint at one request per 24 s; a 120 s hold paces 5."""
    capability, tool, parser = XSS
    shard = {"canonical_shard_authority": {"shard_index": 0, "shard_count": 8}}
    receipts, (calls,), _record = _slice(
        capability, tool=tool, parser=parser, sent=10_000, options={"login_url": LOGIN, **shard},
        routes=DEFAULT_ROUTES[:1],
        budget={"http_requests": 240, "state_changing_requests": 240, "tool_wall_seconds": 120},
    )
    assert not _sent_to(calls, LOGIN)
    deferred = [item for item in receipts[0].observations if item.get("kind") == "candidate_deferred"]
    assert len(deferred) == 1
    assert deferred[0]["reason"] == AUTH_ENDPOINT_PACE_UNFUNDED
    assert "verdict" not in deferred[0] and deferred[0].get("inconclusive_reason") is None
    assert deferred[0]["resume_wall_seconds"] == AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS * AUTH_ENDPOINT_SECONDS_PER_REQUEST * 8
    assert receipts[0].status == "partial"
    assert not any(item.get("inconclusive_reason") == AUTH_ENDPOINT_PROBE_LIMITED
                   for item in receipts[0].observations)


def test_a_pace_unfunded_slice_says_its_wall_stopped_it_and_a_later_round_funds_it():
    """The slice's wall is what could not pace the candidate: it states a timeout (never an
    unfunded plan or an adapter failure), and a round with the wall it asked for runs it."""
    capability, tool, parser = XSS
    shard = {"canonical_shard_authority": {"shard_index": 0, "shard_count": 8}}
    short = {"http_requests": 240, "state_changing_requests": 240, "tool_wall_seconds": 120}
    funded = {"http_requests": 240, "state_changing_requests": 240,
              "tool_wall_seconds": AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS * AUTH_ENDPOINT_SECONDS_PER_REQUEST * 8}
    receipts, (first, later), _record = _slice(
        capability, tool=tool, parser=parser, sent=3, options={"login_url": LOGIN, **shard},
        routes=DEFAULT_ROUTES[:1], rounds=2, budgets={0: short, 1: funded},
    )
    assert not _sent_to(first, LOGIN)
    assert receipts[0].status == "partial"
    assert receipts[0].errors[0] == "timed_out"
    assert receipts[0].timed_out is True
    (call,) = _sent_to(later, LOGIN)
    assert call["options"]["probe_profile"] == "auth_endpoint"
    assert call["reserved"]["http_requests"] == AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS
    (head,) = _heads(receipts[1])
    assert head["sign_in_endpoint_requests"] == 3


def test_a_dalfox_attempt_that_verified_nothing_is_inconclusive_never_negative():
    capability, tool, parser = XSS
    receipts, (_calls,), _record = _slice(capability, tool=tool, parser=parser, sent=3,
                                          options={"login_url": LOGIN}, routes=DEFAULT_ROUTES[:1])
    (head,) = _heads(receipts[0])
    assert head["sign_in_endpoint_requests"] == 3
    assert head["verdict"] == "inconclusive" and head["inconclusive_reason"] == AUTH_ENDPOINT_PROBE_LIMITED


def test_sign_in_candidates_of_a_concurrent_slice_run_one_at_a_time_at_the_pace():
    """Two candidates on the endpoint never overlap, so the endpoint sees one attempt's pace."""
    capability, tool, parser = SQLI
    routes = SIGN_IN_ROUTES[:2] + (("GET", "/search", None, None, ["q"], "web.crawl"),
                                   ("GET", "/items", None, None, ["id"], "web.crawl"))
    # Each fake stage settles in 20 requests, so both sign-in candidates fit the probe set.
    receipts, (calls,), record = _slice(capability, tool=tool, parser=parser, sent=20,
                                        options={"login_url": LOGIN}, routes=routes, concurrency=2,
                                        measured=True)
    assert record["peak"] == 2, "the slice runs candidates concurrently"
    assert len({call["target"] + str(call["options"].get("body_field_names")) for call in _sign_in_calls(calls)}) == 2
    assert record["sign_in_peak"] == 1
    for call in _sign_in_calls(calls):
        reserved = call["reserved"]
        assert reserved["http_requests"] * AUTH_ENDPOINT_SECONDS_PER_REQUEST <= reserved["tool_wall_seconds"]
    assert receipts[0].redacted_execution["candidate_concurrency"]["bound"] == 2


def test_a_parallel_child_divides_the_pace_by_its_siblings():
    capability, tool, parser = SQLI
    shard = {"canonical_shard_authority": {"shard_index": 0, "shard_count": 2}}
    _receipts, (calls,), _record = _slice(capability, tool=tool, parser=parser, sent=10_000,
                                          options={"login_url": LOGIN, **shard}, routes=DEFAULT_ROUTES[:1])
    assert _sent_to(calls, LOGIN)
    for call in _sent_to(calls, LOGIN):
        reserved = call["reserved"]
        assert reserved["http_requests"] * 2 * AUTH_ENDPOINT_SECONDS_PER_REQUEST <= reserved["tool_wall_seconds"]
        assert call["options"]["probe_pace_seconds"] == 2 * AUTH_ENDPOINT_SECONDS_PER_REQUEST


def test_without_a_sign_in_profile_the_login_form_keeps_the_full_hold():
    receipts, (calls,), _record = _slice("sqli.verify_batch", tool="sqlmap", parser="sqlmap-output/v1",
                                         sent=1_000, options={})
    login = _sent_to(calls, LOGIN)
    assert login and all(call["options"].get("probe_profile") is None for call in login)
    assert not _heads(receipts[0])
