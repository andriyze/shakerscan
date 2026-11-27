"""Start-of-Hunt discovery: what it plans, how probes are judged, and how it runs."""
from __future__ import annotations

import asyncio
import json

import pytest

from api.hunt import auto_discovery
from api.hunt.auto_discovery import (
    DiscoveryRunner,
    answer_of,
    plan_steps,
    present,
    probe_key_digests,
    signed_in_slots,
)
from api.hunt.coverage_map import key_digest

HUNT = "22222222-2222-4222-8222-222222222222"
ORIGIN = "http://app.example.test:8000"
ALL = ["web.crawl", "web.content_discover", "templates.scan", "http.request", "sqli.verify"]


@pytest.fixture(autouse=True)
def _unpaced(monkeypatch):
    # The wire pace is tested on its own; these tests check what is sent, not how fast.
    from api.hunt import budget_pace
    monkeypatch.setattr(budget_pace, "wire_requests_per_second", lambda: 100_000)


@pytest.fixture(autouse=True)
def _fresh_state():
    auto_discovery._STATE.clear()
    yield
    auto_discovery._STATE.clear()


def _run(*, allowed=ALL, approval=True, credential_access=True, slots=("primary", "secondary"),
         target_kind="web", status="active"):
    return {
        "id": HUNT, "target_id": "33333333-3333-4333-8333-333333333333", "target_kind": target_kind,
        "status": status, "completed_at": None,
        "policy_json": json.dumps({
            "allowed_capabilities": list(allowed), "active_testing": True,
            "credential_access": credential_access,
            **({"approval_receipt_id": "44444444-4444-4444-8444-444444444444"} if approval else {}),
        }),
        "context_pack": json.dumps({
            "target": {"url": ORIGIN},
            "credential_refs": [{"source": "credential_profiles", "principal_slot": slot, "profile_id": slot}
                                for slot in slots] + [{"source": "other", "principal_slot": "primary"}],
        }),
    }


def _response(status, body="", *, title="", json_keys=(), length=None, content_type="text/html"):
    return {"action_result": {"status": "success", "observations": [{
        "kind": "http_observation",
        "response": {"status": status, "body_sample": body, "bytes_observed": len(body) if length is None else length,
                     "body_digest_scope": "complete", "truncated": False, "content_type": content_type,
                     "html": {"title": title}, "json_keys": list(json_keys)},
    }]}}


def test_plan_runs_mapping_signed_in_crawls_and_templates_only_with_authority():
    steps, skipped = plan_steps(_run())
    assert [step.name for step in steps] == [
        "crawl", "content:corporate", "content:api", "content:admin", "crawl:primary", "crawl:secondary",
        "content:corporate:primary", "content:api:primary", "content:corporate:secondary",
        "content:api:secondary", "templates"]
    assert steps[6].input == {"wordlist": "corporate", "as_principal": "primary"}
    assert steps[4].input == {"as_principal": "primary"} and steps[1].input == {"wordlist": "corporate"}
    assert all(step.key.startswith("auto-discovery:") for step in steps) and not skipped
    steps, skipped = plan_steps(_run(approval=False))
    assert [step.name for step in steps] == ["crawl", "content:corporate", "content:api", "content:admin"]
    assert any(reason.startswith("templates:") for reason in skipped)
    assert signed_in_slots(_run(credential_access=False)) == []
    steps, skipped = plan_steps(_run(allowed=["http.request"]))
    assert steps == [] and len(skipped) == 2
    assert plan_steps(_run(target_kind="device")) == ([], [])


def test_present_compares_with_the_negative_control():
    absent = answer_of(_response(404, "nope"))
    assert not present(absent, absent)
    control = answer_of(_response(200, "x" * 500))  # a catch-all that answers 200 everywhere
    assert not present(answer_of(_response(200, "y" * 505)), control)
    assert present(answer_of(_response(200, "y" * 2000)), control)
    assert present(answer_of(_response(401, "denied")), answer_of(_response(404, "")))
    assert not present(answer_of(_response(302, "")), answer_of(_response(302, "")))
    assert not present(answer_of(_response(503, "down")), absent)
    assert not present(None, absent)


class _Fake:
    def __init__(self, answers, *, refuse=(), end_after=None, hunt=HUNT):
        self.hunt = hunt
        self.answers = answers
        self.refuse = set(refuse)
        self.calls: list[tuple[str, dict, str]] = []
        self.recorded: list[tuple[str, list[str], str]] = []
        self.end_after = end_after
        self.run = _run()

    async def execute(self, hunt_id, capability, values, key):
        assert hunt_id == self.hunt
        self.calls.append((capability, dict(values), key))
        if capability in self.refuse or key in self.refuse:
            raise RuntimeError("refused")
        if capability != "http.request":
            await asyncio.sleep(0)
            return {"action_result": {"status": "success", "observations": []}}
        return self.answers.get(values["path"], _response(404, "Not Found"))

    async def record(self, target_id, worklist, source):
        self.recorded.append((target_id, list(worklist), source))
        return len(worklist)

    async def load_run(self, hunt_id):
        if self.end_after is not None and len(self.calls) >= self.end_after:
            return {**self.run, "status": "completed"}
        return self.run


def _runner(fake):
    return DiscoveryRunner(HUNT, execute=fake.execute, record=fake.record, load_run=fake.load_run)


def test_runner_maps_probes_products_and_a_small_api_description():
    spec = json.dumps({"openapi": "3.0.0", "paths": {
        "/api/users": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
        "/internal/admin": {"post": {}},
        "/api/login": {"post": {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {"username": {"type": "string"}, "password": {"type": "string"}}}}}}}}}})
    fake = _Fake({
        "/": _response(200, "<html><script src='/_next/static/x.js'></script></html>"),
        "/openapi.json": _response(200, spec, content_type="application/json"),
        "/graphql": _response(400, '{"errors":[{"message":"Must provide query string."}]}'),
        "/jenkins/api/json": _response(200, '{"_class":"hudson.model.Hudson"}'),
        "/jenkins/script": _response(403, "Forbidden"),
        "/api/version": _response(200, "plain page without the product's words"),  # no ollama marker
        "/manager/html": _response(401, "Unauthorized"),  # tomcat has no marker: any distinct answer
    })
    state = asyncio.run(_runner(fake).run())
    keys = [key for _cap, _values, key in fake.calls]
    assert len(keys) == len(set(keys)), "every call has its own fixed idempotency key"
    assert all(key.startswith("auto-discovery:") for key in keys)
    http_calls = [values for cap, values, _key in fake.calls if cap == "http.request"]
    assert all(values["method"] == "GET" and values["follow_redirects"] is False for values in http_calls)
    assert http_calls[0]["path"].startswith("/.shakerscan-absent-")
    probed = {values["path"] for values in http_calls}
    assert "/jenkins/whoAmI/api/json" in probed  # jenkins answered with its marker: its routes follow
    assert "/api/ps" not in probed  # the ollama identity answer lacked the marker
    assert "/manager/status" in probed and "/api/auth/session" in probed  # tomcat, and Next.js from the root page
    assert set(state["products"]) >= {"jenkins", "tomcat", "nextjs"} and "ollama" not in state["products"]
    (target_id, worklist, source), = fake.recorded
    assert source == "hunt_probe" and target_id == _run()["target_id"]
    assert {"GET /openapi.json", "GET /graphql", "POST /graphql", "GET /jenkins/api/json",
            "GET /jenkins/script", "GET /manager/html"} <= set(worklist)
    assert "GET /api/users?q=1" in worklist and "POST /internal/admin" in worklist
    assert 'POST /api/login json:{"username":"","password":""}' in worklist
    assert "GET /api/version" not in worklist
    long_steps = [cap for cap, _values, _key in fake.calls if cap != "http.request"]
    assert long_steps == ["web.crawl", "web.content_discover", "web.content_discover", "web.content_discover",
                          "web.crawl", "web.crawl", *["web.content_discover"] * 4, "templates.scan"]
    assert state["running"] is False and state["probes"] == "done" and state["crawl"] == "done"
    assert len(http_calls) <= auto_discovery.MAX_PROBES
    assert {key_digest(key) for cap, _v, key in fake.calls if cap == "http.request"} <= probe_key_digests()


def test_a_refused_step_is_skipped_and_named_and_the_rest_runs():
    fake = _Fake({}, refuse={"templates.scan", "auto-discovery:content:api"})
    state = asyncio.run(_runner(fake).run())
    assert state["templates"] == "skipped" and state["content:api"] == "skipped"
    assert state["content:admin"] == "done" and state["crawl:secondary"] == "done"
    assert any(note.startswith("templates:") for note in state["notes"])
    assert fake.recorded == []  # nothing answered: nothing enters the inventory


def test_discovery_stops_when_the_hunt_ends_and_skips_non_web_hunts():
    fake = _Fake({}, end_after=3)
    state = asyncio.run(_runner(fake).run())
    assert state["running"] is False
    assert len(fake.calls) < 10
    assert any("Hunt ended" in note for note in state.get("notes", [])) or state.get("probes") in {"done", "not_run"}
    auto_discovery._STATE.clear()
    device = _Fake({})
    device.run = _run(target_kind="device")
    assert asyncio.run(_runner(device).run()) == {} and device.calls == []


def test_start_is_switchable_and_never_raises(monkeypatch):
    monkeypatch.setenv(auto_discovery.SETTING, "false")
    assert auto_discovery.start(HUNT) is None
    monkeypatch.setenv(auto_discovery.SETTING, "true")
    assert auto_discovery.start(HUNT) is None  # no running loop: nothing scheduled

    async def scheduled():
        fake = _Fake({}, hunt="55555555-5555-4555-8555-555555555555")
        task = auto_discovery.start("55555555-5555-4555-8555-555555555555", runner=DiscoveryRunner(
            "55555555-5555-4555-8555-555555555555", execute=fake.execute, record=fake.record,
            load_run=fake.load_run))
        assert task is not None
        await task
        return fake

    fake = asyncio.run(scheduled())
    assert fake.calls  # it ran through the injected executor


@pytest.mark.parametrize("path", ["/openapi.json", "/graphql", "/jenkins/api/json", "/v1/models"])
def test_probe_catalogue_is_bounded_read_only_and_digested(path):
    paths = auto_discovery.probe_paths()
    assert path in paths and len(paths) == len(set(paths))
    assert all(item.startswith("/") and "://" not in item for item in paths)
    assert key_digest(auto_discovery._probe_key(path)) in probe_key_digests()


def test_a_hunt_without_testing_authority_gets_no_engine_traffic():
    # A passive Hunt (or one without its approval) keeps its zero authority: nothing is sent.
    for run in (_run(approval=False), {**_run(), "policy_json": json.dumps({"active_testing": False})}):
        fake = _Fake({})
        fake.run = run
        state = asyncio.run(_runner(fake).run())
        assert fake.calls == [] and not state.get("running")
        assert any("active testing authority" in note for note in state.get("notes", []))
        auto_discovery._STATE.clear()
    assert auto_discovery.testing_authority({"policy": {"active_testing": True, "approval_receipt_id": "a"}})
    assert not auto_discovery.testing_authority({"policy": {"active_testing": True}})
    assert not auto_discovery.testing_authority(None)


def test_stop_cancels_the_running_discovery_and_drops_a_deferred_finish():
    async def scenario():
        fake = _Fake({})

        async def slow(hunt_id, capability, values, key):
            fake.calls.append(capability)
            await asyncio.sleep(3600)

        fake.execute = slow
        hunt = str(HUNT)
        task = auto_discovery.start(hunt, runner=DiscoveryRunner(
            HUNT, execute=fake.execute, record=fake.record, load_run=fake.load_run))
        for _ in range(20):
            await asyncio.sleep(0)
        assert auto_discovery.sweep_running(hunt)
        auto_discovery.defer_finish(hunt, summary="s", next_actions=[], reason=None)
        assert auto_discovery.stop(hunt) is True
        assert await auto_discovery.wait_stopped(hunt, timeout=5)
        assert task.done() and not auto_discovery.sweep_running(hunt)
        assert "deferred_finish" not in auto_discovery._STATE[hunt]
        assert auto_discovery.stop(hunt) is False  # nothing left to stop
        return fake

    assert asyncio.run(scenario()).calls



def test_an_api_description_longer_than_the_answer_sample_is_parsed_whole_and_ingested():
    """VAmPI's 29 KB spec answered complete, but http.request returns a 16 KB sample and Werkzeug
    ignores byte ranges: the routes it declares were never mapped, only noted for the planner.
    Discovery has the worker parse the whole document (javascript.analyze) and ingests its routes."""
    spec = json.dumps({"openapi": "3.0.0", "paths": {"/users/v1/{username}": {"delete": {}}}})

    class Worker(_Fake):
        async def execute(self, hunt_id, capability, values, key):
            if capability == "javascript.analyze":
                self.calls.append((capability, dict(values), key))
                return {"action_result": {"status": "success", "observations": [{
                    "kind": "javascript_analysis", "api_description_routes": [
                        {"method": "GET", "path": "/api/v1/thing0", "body_field_names": [], "content_type": ""},
                        {"method": "POST", "path": "/users/v1/register", "content_type": "application/json",
                         "body_field_names": ["username", "password", "email"]},
                        {"method": "DELETE", "path": "/users/v1/{username}", "body_field_names": [],
                         "content_type": ""}]}]}}
            return await super().execute(hunt_id, capability, values, key)

    fake = Worker({"/openapi.json": _response(200, spec[:40], length=29_537, content_type="application/json")})
    state = asyncio.run(_runner(fake).run())
    (_target, worklist, _source), = fake.recorded
    assert "GET /api/v1/thing0" in worklist and "DELETE /users/v1/{username}" in worklist
    assert 'POST /users/v1/register json:{"username":"","password":"","email":""}' in worklist
    assert [values["path"] for cap, values, _key in fake.calls if cap == "javascript.analyze"].count("/openapi.json") == 1
    assert not any("API description at /openapi.json" in note for note in state.get("notes", []))
