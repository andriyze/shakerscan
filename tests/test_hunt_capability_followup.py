"""Behavioral regressions for the Hunt capability follow-up to PR 558."""
import asyncio

import pytest

from api.capabilities import authz_modes
from api.hunt import agent_job_concurrency as concurrency
from api.hunt.auto_discovery import DiscoveryRunner
from api.hunt.coverage_map import build_coverage, next_calls
from api.hunt.engine_context import is_engine_work
from scripts import shakerscan_mcp as mcp


def _action(method="GET", status="completed", parameter="q", check="sql_injection"):
    return {"capability_name": "request.verify", "status": status, "input": {
        "method": method, "path": "/search", "check": check, "parameter": parameter,
        "query": {parameter: "1"}}, "http_status": 200}


def _open(actions, *, params=("q",)):
    report = build_coverage(actions=actions, endpoints=[
        {"method": method, "path": "/search", "param_shape": list(params)} for method in ("GET", "POST")])
    return {item["endpoint"]: set(item["untested"]) for item in report["open"]}


def test_a_query_check_never_closes_the_body_handler_at_the_same_path():
    opened = _open([_action()])
    assert "sqli" not in opened["GET /search"]
    assert "sqli" in opened["POST /search"]


def test_every_known_input_needs_its_own_check_and_new_inputs_reopen_coverage():
    assert "sqli" in _open([_action()], params=("q", "sort"))["GET /search"]
    assert "sqli" not in _open([_action(), _action(parameter="sort")], params=("q", "sort"))["GET /search"]
    report = build_coverage(actions=[_action()], endpoints=[{
        "method": "GET", "path": "/search", "param_shape": ["q", "sort"]}])
    sql = next(call for call in next_calls(report) if call["capability"] == "request.verify")
    assert sql["input"]["parameter"] == "sort"


def test_a_partial_or_failed_check_leaves_its_input_open():
    for status in ("partial", "failed", "running", "reserved"):
        assert "sqli" in _open([_action(status=status)])["GET /search"]


def test_a_candidate_on_one_input_does_not_close_its_neighbours_or_another_method():
    report = build_coverage(actions=[], endpoints=[
        {"method": method, "path": "/search", "param_shape": ["q", "sort"]}
        for method in ("GET", "POST")], candidates=[{
            "family": "sqli", "canonical_locus": {"method": "GET", "path": "/search", "parameter": "q"}}])
    assert all("sqli" in item["untested"] for item in report["open"])
    sql = next(call for call in next_calls(report) if call["capability"] == "request.verify")
    assert sql["input"]["parameter"] in sql["input"].get("query", sql["input"].get("json_body", {}))


def test_next_call_keeps_an_unchecked_input_beyond_the_short_parameter_window():
    names = [f"p{i:02}" for i in range(12)]
    report = build_coverage(actions=[_action(parameter=name) for name in names[:8]], endpoints=[{
        "method": "GET", "path": "/search", "param_shape": names}])
    sql = next(call for call in next_calls(report) if call["capability"] == "request.verify")
    assert sql["input"]["parameter"] == "p08" and "p08" in sql["input"]["query"]


def test_next_injection_call_advances_from_command_to_template_instead_of_repeating():
    actions = [{**_action(parameter="url", check=check), "input": {
        **_action(parameter="url", check=check)["input"], "path": "/fetch"}}
        for check in ("sql_injection", "command_injection")]
    actions.append({"capability_name": "xss.verify", "status": "completed",
                    "input": {"path": "/fetch?url=1"}})
    report = build_coverage(actions=actions, endpoints=[{
        "method": "GET", "path": "/fetch", "param_shape": ["url"]}])
    call = next_calls(report)[0]
    assert call["input"]["check"] == "template_injection" and call["input"]["parameter"] == "url"


def test_a_bare_write_does_not_examine_upload_or_graphql_security():
    for path, klass in (("/upload", "upload"), ("/graphql", "graphql")):
        report = build_coverage(endpoints=[{"method": "POST", "path": path}], actions=[
            {"capability_name": "http.request", "status": "completed", "input": {
                "method": "POST", "path": path, "json_body": {"x": "1"}}, "http_status": 200}])
        assert klass in report["open_by_class"]


class _Holds:
    def __init__(self, rows): self.rows = rows
    async def fetch(self, *args): return self.rows


def _hold(engine=False):
    return {"capability_name": "sqli.verify", "action_id": "a", "engine_work": "true" if engine else None}


def test_the_sweep_keeps_a_long_slot_for_the_planner_without_lowering_total_capacity():
    async def scenario():
        holds = _Holds([_hold(True)])
        with pytest.raises(Exception) as refused:
            await concurrency.require_long_action_slot(holds, {"id": "h"}, "web.crawl", 605, engine_work=True)
        assert refused.value.detail["reason_code"] == "long_actions_in_flight"
        await concurrency.require_long_action_slot(holds, {"id": "h"}, "web.crawl", 605)
        # The planner and engine can share both slots in either admission order.
        await concurrency.require_long_action_slot(_Holds([_hold()]), {"id": "h"}, "web.crawl", 605, engine_work=True)
        with pytest.raises(Exception):
            await concurrency.require_long_action_slot(_Holds([_hold(), _hold(True)]), {"id": "h"}, "web.crawl", 605)
        # Multiple workers keep all but one of their slots available to automation.
        await concurrency.require_long_action_slot(_Holds([_hold(True)] * 2), {"id": "h"}, "web.crawl", 605,
                                                  workers=2, engine_work=True)
    asyncio.run(scenario())


def test_engine_provenance_is_server_owned_and_scoped_to_its_async_call():
    async def scenario():
        observed = []
        async def execute(*args): observed.append(is_engine_work()); return {}
        runner = DiscoveryRunner("provenance", execute=execute)
        assert not is_engine_work()
        await runner._call("http.request", {}, "untrusted-key")
        assert observed == [True] and not is_engine_work()
        # Choosing an automatic-looking key outside the engine grants no provenance.
        await execute("h", "http.request", {}, "auto-discovery:crawl")
        assert observed == [True, False]
    asyncio.run(scenario())


def test_mcp_keeps_security_signals_after_the_old_two_thousand_character_cut():
    body = "a" * 9_000 + "AUDIT_SECURITY_SIGNAL" + "b" * 6_900
    result = mcp._compact_capability_answer({"capability": "http.request", "action_result": {
        "observations": [{"kind": "http_observation", "response": {"status": 200, "body_sample": body}}]}},
        idempotency_key="visibility")
    assert result["action_result"]["observations"][0]["response"]["body_sample"] == body


def test_function_authorization_executes_all_fifty_routes_with_six_probes_each(monkeypatch):
    calls = []
    clock = [0.0]
    def normalized(base, routes, **kwargs): return [base + route for route in routes]
    async def send(base, values, **kwargs):
        calls.append((values["path"], kwargs["principal_slot"]))
        clock[0] += .5
        return {"ok": True, "request": {}}
    monkeypatch.setattr(authz_modes.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(authz_modes, "_normalized_routes", normalized)
    monkeypatch.setattr(authz_modes, "execute_bound_http_request", send)
    result = asyncio.run(authz_modes.verify_function_authorization(
        "https://app.example.test", [f"/admin/{i}" for i in range(50)], target=object(),
        primary_headers={"Authorization": "a"}, secondary_headers={"Authorization": "b"}))
    assert len(calls) == 300 and len({path for path, slot in calls}) == 50
    assert result["budget_consumed"]["http_requests"] == 300
    assert result["status"] == "partial"  # absent private response evidence cannot become proof
