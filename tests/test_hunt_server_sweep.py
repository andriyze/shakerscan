"""The engine's own sweep: what it runs on a mapped surface, and the deferred finish."""
from __future__ import annotations

import asyncio
import json

import pytest

from api.hunt import auto_discovery, server_sweep
from api.hunt.server_sweep import Refused, Sweep, concrete, exposure_signal, login_form, sweep_key

@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch):
    monkeypatch.setattr(server_sweep, "DEFAULT_CREDENTIAL_PACE_SECONDS", 0)


ALL = ["http.request", "javascript.analyze", "candidate.verify", "authz.verify", "sqli.verify", "xss.verify",
       "web.crawl", "web.content_discover"]


def _run(*, allowed=ALL, writes=True, slots=("primary", "secondary")):
    return {"id": "h1", "target_id": "t1", "target_kind": "web", "status": "active", "completed_at": None,
            "policy_json": json.dumps({"allowed_capabilities": allowed, "allow_state_changing_http": writes,
                                       "credential_access": True, "approval_receipt_id": "r1",
                                       "active_testing": True}),
            "context_pack": json.dumps({"credential_refs": [
                {"source": "credential_profiles", "principal_slot": slot} for slot in slots]})}


def _answer(status, body="", *, forms=None, login_attempt=None, action="a"):
    response = {"status": status, "body_sample": body, "html": {"forms": forms or []}}
    if login_attempt:
        response["login_attempt"] = {"verdict": login_attempt}
    return {"action_id": action, "action_result": {"status": "success", "observations": [{"response": response}]}}


REPORT = {"open": [
    {"endpoint": "GET /.env", "untested": ["exposure", "review"], "params": []},
    {"endpoint": "GET /backup/", "untested": ["exposure", "review"], "params": []},
    {"endpoint": "GET /hub/login", "untested": ["default_credentials", "review"], "params": []},
    {"endpoint": "POST /api/auth/login", "untested": ["default_credentials"], "params": []},
    {"endpoint": "GET /hub/api/admin/payroll/export", "untested": ["function_authz"], "params": []},
    {"endpoint": "GET /search", "untested": ["sqli", "xss", "review"], "params": ["q"]},
    {"endpoint": "POST /api/comment", "untested": ["sqli", "xss"], "params": ["body", "author"]},
    {"endpoint": "GET /orders/{id}", "untested": ["object_authz", "sqli"], "params": ["sort"]},
]}


class _Engine:
    def __init__(self, *, refuse=(), accept_pair="dc-03"):
        self.calls = []
        self.candidates = []
        self.refuse = set(refuse)
        self.accept_pair = accept_pair
        self.alive = True

    async def call(self, capability, values, key):
        self.calls.append((capability, dict(values), key))
        if capability in self.refuse:
            raise Refused("not in this Hunt's capabilities")
        if capability != "http.request":
            return {"action_id": f"x{len(self.calls)}", "action_result": {"status": "success", "observations": []}}
        if values["method"] == "POST":
            pair = values["request_bindings"][0]["default_credential"]
            return _answer(303, login_attempt="accepted" if pair == self.accept_pair else "rejected",
                           action=f"login-{pair}")
        path = values["path"]
        if path == "/.env":
            return _answer(200, "DB_PASSWORD=[withheld:1]", action="env")
        if path == "/backup/":
            return _answer(200, "<html><title>Index of /backup</title>", action="listing")
        if path == "/hub/login":
            return _answer(200, "", forms=[{"method": "POST", "action": "/hub/login", "fields": [
                {"name": "username", "type": "text"}, {"name": "password", "type": "password"}]}])
        return _answer(404, "Not Found")

    async def create(self, values):
        self.candidates.append(dict(values))
        return {"candidate": {"id": f"c{len(self.candidates)}"}}

    async def live(self):
        return self.alive


def test_helpers():
    assert concrete("/orders/{id}/items/{itemId}") == "/orders/1/items/1"
    assert exposure_signal({"status": 200, "body_sample": "x [withheld:2] y"}) == "credential-shaped values"
    assert exposure_signal({"status": 200, "body_sample": "-----BEGIN RSA PRIVATE KEY-----"}) == "a private key"
    assert exposure_signal({"status": 403, "body_sample": "[withheld:1]"}) is None
    assert exposure_signal({"status": 200, "body_sample": "DB_PASSWORD=hunter22\nDB_HOST=db"}) == "secret-named fields"
    assert exposure_signal({"status": 200, "body_sample": '{"api_key": "sk_live_x1y2"}'}) == "secret-named fields"
    assert exposure_signal({"status": 200, "body_sample": '[{"username":"a","id":1},{"username":"b"}]'}) == "account records"
    assert exposure_signal({"status": 200, "body_sample": "<p>Forgot your password? Contact IT</p>",
                            "html": {"title": "Sign in"}}) is None
    assert exposure_signal({"status": 200, "body_sample": '{"status": "ok", "version": "1.2"}'}) is None
    assert login_form({"html": {"forms": [{"method": "POST", "action": "/login", "fields": [
        {"name": "email", "type": "email"}, {"name": "pw", "type": "password"}]}]}}) == ("/login", "email", "pw")
    assert sweep_key("read", "/a") == sweep_key("read", "/a") != sweep_key("read", "/b")


def test_the_sweep_reads_proves_logs_in_checks_authz_and_runs_injection_verifiers():
    engine = _Engine()
    state = {}
    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state=state, live=engine.live)
                .run(_run(), REPORT))
    families = [(c["family"], c["locus"]["path"]) for c in engine.candidates]
    assert ("data_exposure", "/.env") in families and ("data_exposure", "/backup/") in families
    assert ("default_credentials", "/hub/login") in families
    exposure = next(c for c in engine.candidates if c["locus"]["path"] == "/.env")
    assert exposure["evidence_refs"] == ["action:env"]
    verified = [values["candidate_id"] for cap, values, _ in engine.calls if cap == "candidate.verify"]
    assert len(verified) == len(engine.candidates)
    # Default credentials: the form's own fields, pairs in order, stopping at the accepted one.
    form_pairs = [v["request_bindings"][0]["default_credential"] for cap, v, _ in engine.calls
                  if cap == "http.request" and v["method"] == "POST" and v["path"] == "/hub/login"]
    assert form_pairs == ["dc-01", "dc-02", "dc-03"]
    form_call = next(v for cap, v, _ in engine.calls
                     if cap == "http.request" and v["method"] == "POST" and v["path"] == "/hub/login")
    assert form_call["form_body"] == {"username": "", "password": ""}
    json_login = [v for cap, v, _ in engine.calls if cap == "http.request" and v.get("path") == "/api/auth/login"]
    assert json_login and "json_body" in json_login[0]
    authz = [v for cap, v, _ in engine.calls if cap == "authz.verify"]
    assert authz == [{"mode": "function", "primary_principal": "primary", "secondary_principal": "secondary",
                      "routes": ["/hub/api/admin/payroll/export"]}]
    injections = [(cap, v) for cap, v, _ in engine.calls if cap in {"sqli.verify", "xss.verify"}]
    assert ("sqli.verify", {"path": "/search?q=1"}) in injections
    assert ("xss.verify", {"path": "/search?q=1"}) in injections
    assert ("sqli.verify", {"path": "/orders/1?sort=1"}) in injections
    assert ("sqli.verify", {"path": "/api/comment", "method": "POST", "body_field_names": ["body", "author"],
                            "injection_field": "body"}) in injections
    order = [cap for cap, _ in injections]
    assert order.index("xss.verify") >= order.count("sqli.verify") - 1  # SQL injection first
    keys = [key for _cap, _v, key in engine.calls]
    assert len(keys) == len(set(keys)) and all(key.startswith("auto-sweep:") for key in keys)
    assert state["sweep"] == "done" and state["sweep_counts"]["sqli.verify"] >= 3


def test_the_sweep_respects_authority_and_skips_what_is_refused():
    engine = _Engine(refuse={"sqli.verify"})
    state = {}
    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state=state, live=engine.live)
                .run(_run(writes=False, slots=("primary",)), REPORT))
    caps = [cap for cap, _v, _k in engine.calls]
    assert "authz.verify" not in caps  # one principal only
    assert not any(cap == "http.request" and v["method"] == "POST" for cap, v, _ in engine.calls)  # no writes
    assert not any(v.get("method") == "POST" for cap, v, _ in engine.calls if cap == "xss.verify")
    assert state["sweep_counts"]["sqli.verify:refused"] >= 1 and "xss.verify" in caps
    assert any(note.startswith("sqli.verify:") for note in state["notes"])


def test_the_sweep_stops_when_the_hunt_ends():
    engine = _Engine()
    engine.alive = False
    state = {}
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state=state, live=engine.live)
                    .run(_run(), REPORT))
    assert engine.calls == [] and state["sweep"] == "stopped"


def test_the_runner_sweeps_after_discovery_and_finishes_with_the_planners_debrief():
    auto_discovery._STATE.clear()
    engine = _Engine()
    finished = []
    run = {**_run(), "id": "h2", "target_id": "t2"}

    async def execute(hunt_id, capability, values, key):
        return await engine.call(capability, values, key)

    async def record(*_args):
        return 0

    async def load_run(_hunt_id):
        return {**run, "status": "completed"} if finished else run

    async def load_report(_hunt_id):
        return REPORT

    async def create(_hunt_id, values):
        return await engine.create(values)

    async def finish(hunt_id, **values):
        finished.append((hunt_id, values))

    runner = auto_discovery.DiscoveryRunner("h2", execute=execute, record=record, load_run=load_run,
                                            load_report=load_report, create_candidate=create, finish=finish)
    auto_discovery.defer_finish("h2", summary="Done", next_actions=["n"], reason="handing the rest to the engine")
    assert auto_discovery.sweep_running("h2") is False
    state = asyncio.run(runner.run())
    assert state["sweep"] == "done" and state["running"] is False
    assert finished == [("h2", {"summary": "Done", "next_actions": ["n"], "force": True,
                                "force_reason": "handing the rest to the engine"})]
    sweep_calls = [key for _c, _v, key in engine.calls if key.startswith("auto-sweep:")]
    assert sweep_calls  # the sweep ran after discovery
    auto_discovery._STATE.clear()


class _RoundEngine(_Engine):
    async def call(self, capability, values, key):
        if capability == "http.request" and values.get("method") == "GET":
            self.calls.append((capability, dict(values), key))
            path, who = values["path"], values.get("as_principal")
            if path == "/":
                return {"action_id": "root", "action_result": {"observations": [{"response": {
                    "status": 200, "body_sample": "", "html": {"links": ["/new-page", "//evil.test/x", "/app.js"]}}}]}}
            if path == "/hub/api/users/1":
                if who is None:
                    return _answer(401, '{"error":"Unauthorized"}', action="anon")
                return _answer(200, '{"id":1,"password_hash":"$2b$12$abcdefghijk"}', action=f"as-{who}")
            return _answer(404, "Not Found")
        if capability == "javascript.analyze":
            self.calls.append((capability, dict(values), key))
            return {"action_id": "js", "action_result": {"observations": [
                {"kind": "javascript_analysis", "routes": ["/api/hidden", "https://x.test/y", "/api/[withheld:1]"]}]}}
        return await super().call(capability, values, key)


def test_rounds_record_what_reads_reveal_read_signed_in_and_never_repeat_a_check():
    engine = _RoundEngine()
    state = {}
    recorded = []
    reports = [
        {"endpoints": 3, "open": [
            {"endpoint": "GET /", "untested": ["review"], "params": []},
            {"endpoint": "GET /app.js", "untested": ["review"], "params": []},
            {"endpoint": "GET /hub/api/users/{id}", "untested": ["object_authz", "unauthenticated_api", "sqli"],
             "params": ["fields"]}]},
    ]

    async def load_report():
        # The second read lists what the first round recorded, plus everything still open.
        return {"endpoints": 5, "open": reports[0]["open"] + [
            {"endpoint": "GET /new-page", "untested": ["review"], "params": []},
            {"endpoint": "GET /api/hidden", "untested": ["review", "unauthenticated_api"], "params": []}]}

    async def record(worklist):
        recorded.append(list(worklist))

    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state=state, live=engine.live)
                .run(_run(), reports[0], load_report=load_report, record=record))
    assert recorded and set(recorded[0]) == {"GET /new-page", "GET /app.js", "GET /api/hidden"}
    reads = [(v["path"], v.get("as_principal")) for cap, v, _ in engine.calls if cap == "http.request"
             and v.get("method") == "GET"]
    assert ("/hub/api/users/1", None) in reads and ("/hub/api/users/1", "primary") in reads
    assert ("/hub/api/users/1", "secondary") in reads and ("/new-page", None) in reads
    assert reads.count(("/", None)) == 1  # never repeated across rounds
    exposure = [c for c in engine.candidates if c["locus"].get("principal") == "primary"]
    assert exposure and exposure[0]["evidence_refs"] == ["action:as-primary"]
    sqli = [v for cap, v, _ in engine.calls if cap == "sqli.verify"]
    assert sqli == [{"path": "/hub/api/users/1?fields=1", "as_principal": "primary"}]
    stats = state["sweep_stats"]
    assert stats["rounds"] == 2 and stats["pairs_tested"] >= 5 and stats["endpoints_seen"] == 3
    assert "seconds" in stats and state["sweep"] == "done"
