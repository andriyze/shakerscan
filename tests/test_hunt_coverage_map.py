"""Open Hunt coverage: classification, what closes a pair, the finish guard and the debrief."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

from api.hunt import coverage_map
from api.hunt.coverage_map import (
    build_coverage,
    classify,
    compact_open_coverage,
    coverage_page,
    debrief_coverage,
    family_classes,
    finish_guard,
    normalize_path,
)

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)


def _action(capability, status="completed", http_status=200, key_digest=None, **values):
    return {"capability_name": capability, "status": status, "input": json.dumps(values),
            "http_status": None if http_status is None else str(http_status), "content_type": "",
            "idempotency_key_sha256": key_digest}


def _endpoint(path, method="GET", params="", source="hunt_discovery"):
    return {"method": method, "path": path, "param_shape": params, "content_type": None, "source": source}


def _run(**extra):
    return {"id": "11111111-1111-4111-8111-111111111111", "target_kind": "web", "status": "active",
            "created_at": NOW - timedelta(minutes=5),
            "budget_json": {"max_duration_seconds": 5400, "max_http_requests": 1000},
            "budget_used_json": {"http_requests": 10}, **extra}


def test_normalize_path_templates_ids_and_drops_query():
    assert normalize_path("/hub/api/users/12?x=1") == "/hub/api/users/{id}"
    assert normalize_path("http://h:8000/a/0f8fad5b-d9cb-469f-a165-70867728950e/b") == "/a/{id}/b"
    assert normalize_path("/api/items/{itemId}") == "/api/items/{id}"
    assert normalize_path("relative") is None and normalize_path("") is None


def test_classify_names_the_checks_a_route_takes():
    assert "default_credentials" in classify("POST", "/hub/api/login")
    assert "default_credentials" in classify("POST", "/login")
    assert "default_credentials" not in classify("POST", "/api/auth/logout")
    assert {"object_authz", "unauthenticated_api"} <= classify("GET", "/hub/api/users/{id}")
    assert "function_authz" in classify("GET", "/hub/api/admin/payroll/export")
    assert "exposure" in classify("GET", "/backup/wp-config.php.bak")
    assert "exposure" in classify("GET", "/.git/config")
    assert {"sqli", "xss"} <= classify("GET", "/search", ["q"])
    assert {"sqli", "xss"} <= classify("GET", "/search")  # a search route takes them without a seen param
    assert "injection" in classify("GET", "/fetch", ["url"])
    assert "injection" in classify("POST", "/api/tools/dns-lookup")
    assert "graphql" in classify("POST", "/graphql") and "sqli" not in classify("POST", "/graphql")
    assert classify("GET", "/static/app.js") == {"review"}


def test_family_classes_maps_candidate_and_angle_families():
    assert family_classes("bola") == {"object_authz"}
    assert "default_credentials" in family_classes("default_credentials")
    assert "sqli" in family_classes("sql_injection")
    assert "exposure" in family_classes("data_exposure")
    assert family_classes("xss") == {"xss"}
    assert family_classes("sqli") == {"sqli"}


def test_unrequested_inventory_is_open_and_listed_before_requested_routes():
    report = build_coverage(
        actions=[_action("http.request", path="/hub/api/users/1", method="GET")],
        endpoints=[_endpoint("/.env"), _endpoint("/hub/api/users/2"), _endpoint("/search", params="q")],
    )
    open_routes = {item["endpoint"]: item for item in report["open"]}
    assert set(open_routes) == {"GET /.env", "GET /hub/api/users/{id}", "GET /search"}
    # Requested and answered 200: only review closes; authorization and the anonymous-access
    # judgement stay open until a check, a candidate or a settled angle closes them.
    assert open_routes["GET /hub/api/users/{id}"]["untested"] == ["object_authz", "unauthenticated_api"]
    assert open_routes["GET /hub/api/users/{id}"]["requested"] is True
    assert open_routes["GET /search"]["untested"][:2] == ["sqli", "xss"]
    assert report["open"][-1]["endpoint"] == "GET /hub/api/users/{id}"  # never-requested first
    assert report["endpoints"] == 3 and report["endpoints_requested"] == 1
    assert report["pairs_open"] == sum(len(item["untested"]) for item in report["open"])


def test_verifiers_candidates_and_settled_angles_close_pairs():
    report = build_coverage(
        actions=[
            _action("sqli.verify", path="/search?q=1"),
            _action("xss.verify", path="/search", parameter="q"),
            _action("authz.verify", routes=["GET /hub/api/orders/1001"]),
            _action("authz.verify", mode="function", routes=["/hub/api/admin/audit"]),
            _action("http.request", method="POST", path="/hub/api/login",
                    request_bindings=[{"default_credential": "dc-01", "credential_field": "username"}]),
            _action("http.request", path="/fetch?url=http://x"),
        ],
        endpoints=[_endpoint("/search", params="q"), _endpoint("/hub/api/orders/1001"),
                   _endpoint("/hub/api/admin/audit"), _endpoint("/hub/api/login", method="POST"),
                   _endpoint("/fetch", params="url"), _endpoint("/graphql", method="POST"),
                   _endpoint("/backup/")],
        candidates=[{"family": "data_exposure", "canonical_locus": {"path": "/backup/"}}],
        angles=[{"family": "graphql", "locus": {"route": "/graphql"}, "status": "negative"},
                {"family": "upload", "locus": {"route": "/backup/"}, "status": "planned"}],
    )
    open_routes = {item["endpoint"]: item["untested"] for item in report["open"]}
    assert "GET /search" not in open_routes
    assert "GET /hub/api/orders/{id}" not in open_routes
    assert "GET /hub/api/admin/audit" not in open_routes
    assert "POST /graphql" not in open_routes
    assert "GET /backup/" not in open_routes
    # The default-credential attempt closed that class; the login was requested with a body.
    assert "POST /hub/api/login" not in open_routes
    # An ordinary parameterized read is mapping, not an injection check.
    assert set(open_routes["GET /fetch"]) == {"sqli", "xss", "injection"}


def test_engine_probes_are_discovery_not_testing_and_misses_add_no_route():
    probe_digest = "a" * 64
    report = build_coverage(
        actions=[
            _action("http.request", path="/jenkins/api/json", key_digest=probe_digest),
            _action("http.request", path="/nothing-here", http_status=404),
            _action("http.request", path="/hub/orders", http_status=200),
        ],
        endpoints=[_endpoint("/jenkins/api/json", source="hunt_probe")],
        probe_key_digests={probe_digest},
    )
    routes = {item["endpoint"] for item in report["open"]}
    assert "GET /jenkins/api/json" in routes  # still open: the agent has not looked at it
    assert "GET /nothing-here" not in routes
    assert report["endpoints"] == 2  # the inventory hit plus the route the Hunt saw answer


def test_discovery_steps_pending_until_run_and_not_allowed_is_not_pending():
    report = build_coverage(actions=[], endpoints=[], allowed=["web.crawl", "http.request"])
    assert report["discovery"]["steps"] == {"crawl": "not_run", "content_discovery": "not_allowed"}
    assert report["discovery"]["pending"] == [] and report["discovery"]["not_run"] == ["crawl"]
    assert report["discovery"]["run_with"] == {"crawl": "web.crawl"}
    report = build_coverage(actions=[_action("web.crawl", status="running")], endpoints=[],
                            allowed=["web.crawl", "web.content_discover"])
    assert report["discovery"]["steps"]["crawl"] == "running" and report["discovery"]["pending"] == ["crawl"]
    done = build_coverage(actions=[_action("web.crawl"), _action("web.content_discover", wordlist="api")],
                          endpoints=[], allowed=["web.crawl", "web.content_discover"],
                          discovery={"running": False, "products": ["jenkins"], "notes": ["x"]})
    assert done["discovery"]["pending"] == [] and done["discovery"]["products"] == ["jenkins"]
    running = build_coverage(actions=[], endpoints=[], discovery={"running": True, "crawl": "done",
                                                                  "content_discovery": "done"})
    assert "auto_discovery" in running["discovery"]["pending"]


def test_page_compact_and_debrief_are_bounded():
    endpoints = [_endpoint(f"/api/item{index}/{index}") for index in range(30)]
    report = build_coverage(actions=[], endpoints=endpoints)
    page = coverage_page(report, limit=10, offset=0)
    assert page["returned"] == 10 and page["has_more"] and page["next_offset"] == 10
    last = coverage_page(report, limit=10, offset=20)
    assert last["returned"] == 10 and not last["has_more"] and last["next_offset"] is None
    narrowed = coverage_page(report, class_filter="object_authz")
    assert all("object_authz" in item["untested"] for item in narrowed["open"])
    compact = compact_open_coverage(report, "h1")
    assert len(compact["next"]) == coverage_map.COMPACT_ITEMS and "kind=coverage" in compact["list"]
    assert len(json.dumps(compact)) < 2_000
    debrief = debrief_coverage(report, forced=True, reason="out of scope for this objective")
    assert debrief["forced"] is True and debrief["force_reason"] == "out of scope for this objective"
    assert debrief["pairs_open"] == report["pairs_open"] and len(debrief["open_sample"]) == 20


def test_finish_guard_refuses_open_coverage_with_time_left_and_names_it():
    report = build_coverage(actions=[_action("web.crawl", status="running")],
                            endpoints=[_endpoint("/search", params="q")], allowed=["web.crawl"])
    refusal = finish_guard(_run(), report, force=False, force_reason=None, now=NOW)
    assert refusal and "coverage is open" in refusal and "GET /search (q): sqli, xss" in refusal
    assert "discovery not finished: crawl" in refusal and "force=true" in refusal
    assert "kind=coverage" in refusal
    # Discovery that never ran is named in the report but does not hold a finish on its own.
    nothing_known = build_coverage(actions=[], endpoints=[], allowed=["web.crawl"])
    assert finish_guard(_run(), nothing_known, force=False, force_reason=None, now=NOW) is None


def test_finish_guard_lets_the_hunt_finish_when_it_should():
    report = build_coverage(actions=[], endpoints=[_endpoint("/search", params="q")])
    # Forced with a reason once a third of the wall has passed; refused when forced without one.
    later = _run(created_at=NOW - timedelta(minutes=40))
    assert finish_guard(later, report, force=True, force_reason="the person asked to stop now", now=NOW) is None
    assert "force_reason" in finish_guard(_run(), report, force=True, force_reason=" ", now=NOW)
    # Wall nearly spent, HTTP budget spent, budget exhausted, not a web Hunt, nothing open.
    late = _run(created_at=NOW - timedelta(seconds=5400 - 30))
    assert finish_guard(late, report, force=False, force_reason=None, now=NOW) is None
    spent = _run(budget_used_json={"http_requests": 1000})
    assert finish_guard(spent, report, force=False, force_reason=None, now=NOW) is None
    assert finish_guard(_run(status="budget_exhausted"), report, force=False, force_reason=None, now=NOW) is None
    assert finish_guard(_run(target_kind="device"), report, force=False, force_reason=None, now=NOW) is None
    closed = build_coverage(actions=[_action("web.crawl"), _action("web.content_discover")], endpoints=[],
                            allowed=["web.crawl", "web.content_discover"])
    assert finish_guard(_run(), closed, force=False, force_reason=None, now=NOW) is None
    assert finish_guard(_run(), None, force=False, force_reason=None, now=NOW) is None


def test_an_exposure_closes_by_judgement_or_a_refusal_not_by_a_bare_request():
    endpoints = [_endpoint("/.env"), _endpoint("/backup/db.sql"), _endpoint("/api/v1/keys")]
    report = build_coverage(actions=[
        _action("http.request", path="/.env", http_status=200),
        _action("http.request", path="/backup/db.sql", http_status=403),
        _action("http.request", path="/api/v1/keys", http_status=200),
    ], endpoints=endpoints, angles=[{"family": "data_exposure", "locus": {"path": "/api/v1/keys"},
                                     "status": "negative"}])
    open_routes = {item["endpoint"]: item["untested"] for item in report["open"]}
    assert open_routes == {"GET /.env": ["exposure"]}


def test_the_inputs_a_hunt_request_carried_become_the_routes_inputs():
    report = build_coverage(endpoints=[], actions=[
        _action("http.request", method="GET", path="/rest/track", query={"id": "1", "bad name!": "x"}),
        _action("http.request", method="POST", path="/api/feedback", json_body={"comment": "x", "rating": 1}),
        _action("http.request", method="POST", path="/profile", form_body={"bio": "x"}),
        # A default-credential attempt names a sign-in's fields, which the sign-in checks cover.
        _action("http.request", method="POST", path="/api/login", json_body={"username": "", "password": ""},
                request_bindings=[{"default_credential": "dc-01", "credential_field": "username",
                                   "body_pointer": "/username"}]),
    ])
    params = {item["endpoint"]: item["params"] for item in report["open"]}
    assert params["GET /rest/track"] == ["id"]
    assert params["POST /api/feedback"] == ["comment", "rating"]
    assert params["POST /profile"] == ["bio"]
    assert params.get("POST /api/login", []) == []
    track = next(item for item in report["open"] if item["endpoint"] == "GET /rest/track")
    assert {"sqli", "xss"} <= set(track["untested"])


def test_a_following_sweep_is_not_pending_discovery():
    running = build_coverage(endpoints=[], actions=[], discovery={"running": True, "sweep": "running"})
    following = build_coverage(endpoints=[], actions=[], discovery={"running": True, "sweep": "following"})
    assert "auto_discovery" in running["discovery"]["pending"]
    assert following["discovery"]["pending"] == []
    assert following["discovery"]["steps"]["sweep"] == "following"


def test_a_request_check_closes_the_class_its_proof_covers():
    endpoints = [_endpoint("/rest/user/security-question", params="email"), _endpoint("/backup/db.sql")]
    before = build_coverage(endpoints=endpoints, actions=[])
    opened = {item["endpoint"]: set(item["untested"]) for item in before["open"]}
    assert "sqli" in opened["GET /rest/user/security-question"] and "exposure" in opened["GET /backup/db.sql"]
    after = build_coverage(endpoints=endpoints, actions=[
        _action("request.verify", check="sql_injection", method="GET", path="/rest/user/security-question",
                query={"email": "1"}, parameter="email"),
        _action("request.verify", check="exposure", method="GET", path="/backup/db.sql"),
        _action("request.verify", check="cors", method="GET", path="/backup/db.sql"),
    ])
    closed = {item["endpoint"]: set(item["untested"]) for item in after["open"]}
    assert "sqli" not in closed.get("GET /rest/user/security-question", set())
    assert "xss" in closed["GET /rest/user/security-question"]  # only xss.verify settles it
    assert "exposure" not in closed.get("GET /backup/db.sql", set())


def test_a_route_reached_with_the_hunts_own_login_carries_that_identity_by_reference():
    login = [{"source_action_id": "11111111-1111-4111-8111-111111111111", "capture_name": "token",
              "header": "Authorization", "prefix": "Bearer "}]
    report = build_coverage(endpoints=[], actions=[
        _action("http.request", method="GET", path="/rest/basket/1", request_bindings=login),
        _action("http.request", method="GET", path="/rest/refused/1", http_status=401, request_bindings=login),
        # A managed credential or a default pair is not a captured login.
        _action("http.request", method="GET", path="/rest/other/1",
                request_bindings=[{"principal": "primary", "credential_field": "secret", "header": "X-Key"}]),
    ])
    items = {item["endpoint"]: item for item in report["open"]}
    assert items["GET /rest/basket/{id}"]["identity"] == login
    assert "identity" not in items["GET /rest/refused/{id}"] and "identity" not in items["GET /rest/other/{id}"]


def test_a_signed_in_route_with_nothing_open_is_still_listed_for_the_sweep():
    login = [{"withheld_ref": "withheld://hunt/11111111-1111-4111-8111-111111111111/1",
              "header": "Authorization", "prefix": "Bearer "}]
    report = build_coverage(endpoints=[], actions=[
        _action("http.request", method="GET", path="/static/app.css", request_bindings=login),
        _action("http.request", method="GET", path="/rest/basket/1", request_bindings=login),
    ], candidates=[{"family": "bola", "canonical_locus": {"path": "/rest/basket/1", "method": "GET"}}])
    opened = {item["endpoint"] for item in report["open"]}
    signed = {item["endpoint"]: item for item in report.get("signed_in", [])}
    assert set(signed) | opened >= {"GET /rest/basket/{id}", "GET /static/app.css"}
    assert all(item["identity"] == login and item["untested"] == [] for item in signed.values())
    assert report["pairs_open"] == sum(len(item["untested"]) for item in report["open"])


def test_every_answer_names_ready_calls_and_an_objective_can_finish_early():
    report = build_coverage(actions=[], endpoints=[_endpoint("/search", params="q"), _endpoint("/.env"),
                                                   _endpoint("/api/login", method="POST")])
    calls = coverage_map.next_calls(report)
    assert calls and len(calls) <= coverage_map.NEXT_CALLS
    by_capability = {call["capability"] for call in calls}
    assert by_capability <= {"request.verify", "xss.verify", "http.request"} and all(call["input"] for call in calls)
    search = next(call for call in calls if "/search" in json.dumps(call))
    assert search["input"]["parameter"] == "q" or search["capability"] == "xss.verify"
    assert compact_open_coverage(report, "h1")["next_calls"] == calls
    # Five minutes into a 90-minute Hunt the objective may already be answered. Keep the
    # concrete calls available, but a resource ceiling does not require more work.
    early = finish_guard(_run(), report, force=True, force_reason="I think I am done here", now=NOW)
    assert early is None
    assert finish_guard(_run(created_at=NOW - timedelta(minutes=31)), report, force=True,
                        force_reason="I think I am done here", now=NOW) is None
    assert finish_guard(_run(status="budget_exhausted"), report, force=True, force_reason="spent, stopping", now=NOW) is None
    nothing = build_coverage(actions=[], endpoints=[])
    assert finish_guard(_run(), nothing, force=True, force_reason="nothing left to do", now=NOW) is None
    # The unforced refusal hands the same calls over.
    assert "Send next (ready to send)" in finish_guard(_run(), report, force=False, force_reason=None, now=NOW)


def test_next_calls_name_only_capabilities_the_hunt_may_run():
    endpoints = [_endpoint("/search", params="q"), _endpoint("/.env")]
    narrow = build_coverage(actions=[], endpoints=endpoints, allowed=["http.request"])
    assert narrow["allowed"] == ["http.request"]
    assert all(call["capability"] == "http.request" for call in coverage_map.next_calls(narrow))
    # Nothing it may run is open: a forced finish is not held early.
    none = build_coverage(actions=[], endpoints=endpoints, allowed=["web.crawl"])
    assert coverage_map.next_calls(none) == []
    assert finish_guard(_run(), none, force=True, force_reason="nothing I may run is left", now=NOW) is None


def test_default_credential_calls_are_not_offered_when_the_check_is_off(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS", "false")
    report = build_coverage(actions=[], endpoints=[_endpoint("/api/login", method="POST")])
    assert not any("default credentials" in call["why"] for call in coverage_map.next_calls(report))


def test_a_request_check_never_closes_a_class_it_does_not_prove():
    endpoints = [_endpoint("/convert", params="file")]
    report = build_coverage(endpoints=endpoints, actions=[
        _action("request.verify", check="crlf_injection", method="GET", path="/convert", parameter="file")])
    left = {k for item in report["open"] for k in item["untested"]}
    assert {"sqli", "xss"} <= left  # only sql_injection (sqli) and xss.verify (xss) settle those


def test_coverage_reads_every_action_however_many_the_hunt_ran():
    """Review of 2.14.1: the read kept the first 5,000 actions, and one sweep runs more, after
    which a later request never closed a class or mapped a route and the finish guard named pairs
    that had been tested."""
    from api.hunt.coverage_map import CoverageFold

    endpoints = [_endpoint("/search", params="q")]
    early = [_action("http.request", method="GET", path=f"/static/file{index % 40}.css") for index in range(6_000)]
    late = [_action("sqli.verify", path="/search", parameter="q"),
            _action("xss.verify", path="/search?q=1"),
            _action("http.request", method="GET", path="/api/late/7")]
    before = build_coverage(actions=early, endpoints=endpoints)
    assert {"sqli", "xss"} <= set(next(item for item in before["open"] if item["endpoint"] == "GET /search")["untested"])
    after = build_coverage(actions=early + late, endpoints=endpoints)
    assert not any(item["endpoint"] == "GET /search" for item in after["open"])  # closed by action 6,001 and 6,002
    assert any(item["endpoint"] == "GET /api/late/{id}" for item in after["open"])  # mapped by action 6,003
    # The fold keeps routes, not rows: any iterable is read once, a row at a time.
    fold = CoverageFold(endpoints=endpoints)
    for row in (_action("http.request", method="GET", path=f"/item/{index}") for index in range(20_000)):
        fold.add_action(row)
    assert fold.actions == 20_000 and len(fold.known) == 2 and len(fold.ledger.requested) == 1
    assert fold.report()["endpoints"] == 2


def test_the_open_coverage_refusal_does_not_claim_every_route_was_probed():
    report = build_coverage(actions=[], endpoints=[_endpoint("/from-a-sitemap", source="hunt_sweep")])
    refusal = finish_guard(_run(), report, force=False, force_reason=None, now=NOW)
    assert "coverage is open" in refusal
    assert "Every listed endpoint answered" not in refusal
    assert "sources say which" in refusal


def test_an_explained_finish_or_server_deferred_finish_can_leave_coverage_open():
    report = build_coverage(actions=[], endpoints=[_endpoint("/search", params="q")],
                            allowed=["request.verify", "xss.verify", "http.request"])
    assert finish_guard(_run(), report, force=True, force_reason="I think I am done here", now=NOW) is None
    assert "coverage is open" in finish_guard(_run(), report, force=False, force_reason=None, now=NOW)
    assert finish_guard(_run(), report, force=False, force_reason=None, now=NOW, engine_deferred=True) is None
    debrief = debrief_coverage(report, forced=False, reason=None, engine_deferred=True)
    assert debrief["engine_deferred"] is True and debrief["forced"] is False and "force_reason" not in debrief
    assert "engine_deferred" not in debrief_coverage(report, forced=False, reason=None)
