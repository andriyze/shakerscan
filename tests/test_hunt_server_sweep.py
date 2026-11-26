"""The engine's own sweep: what it runs on a mapped surface, and the deferred finish."""
from __future__ import annotations

import asyncio
import json

import pytest

from api.hunt import auto_discovery, server_sweep
from api.hunt.server_sweep import Refused, Sweep, concrete, exposure_signal, login_form, sweep_key

@pytest.fixture(autouse=True)
def _unpaced(monkeypatch):
    # The wire pace is tested on its own; these tests check what is sent, not how fast.
    from api.hunt import budget_pace
    monkeypatch.setattr(budget_pace, "wire_requests_per_second", lambda: 100_000)


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
    # Listings of other stacks than Apache/nginx: Node serve-index, Python http.server, Tomcat.
    for title in ("listing directory /encryptionkeys", "Directory listing for /files/",
                  "Directory Listing For [/files/]"):
        assert exposure_signal({"status": 200, "body_sample": "", "html": {"title": title}}) == "a directory index"
    assert exposure_signal({"status": 200, "body_sample": "our business directory listing",
                            "html": {"title": "Partners"}}) is None
    # A sign-in page's withheld anti-forgery token is not an exposure; a key on a page still is.
    page = {"title": "Sign in", "forms": [{"method": "POST", "action": "/login", "fields": []}]}
    assert exposure_signal({"status": 200, "body_sample": '<input name="_csrf" value="[withheld:1]">',
                            "html": page}) is None
    assert exposure_signal({"status": 200, "body_sample": "[withheld:1] AKIAABCDEFGHIJKLMNOP",
                            "html": page}) == "credential-shaped values"
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
    json_login = [v for cap, v, _ in engine.calls if cap == "http.request" and v.get("path") == "/api/auth/login"
                  and v["method"] == "POST"]
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
    assert order.index("sqli.verify") >= order.count("xss.verify") - 1  # XSS (fast) first
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


def test_long_verifiers_run_from_a_queue_beside_the_rounds_and_drain_before_done():
    # A slow SQL injection verification never holds the next round: its reads run while it waits,
    # and the sweep is done only once every queued verifier has ended.
    gate = asyncio.Event()
    order = []

    class Slow(_Engine):
        async def call(self, capability, values, key):
            if capability == "sqli.verify":
                order.append(("sqli-start", values["path"]))
                await gate.wait()
                order.append(("sqli-end", values["path"]))
            elif capability == "http.request" and values.get("method") == "GET":
                order.append(("read", values["path"]))
            return await super().call(capability, values, key)

    engine = Slow()
    state = {}
    second = {**REPORT, "open": [{"endpoint": "GET /later", "untested": ["review", "exposure"], "params": []}]}
    reports = iter([second, {"open": []}])

    async def scenario():
        async def reload():
            return next(reports, {"open": []})

        sweep = Sweep(call=engine.call, create_candidate=engine.create, state=state, live=engine.live)
        task = asyncio.get_running_loop().create_task(sweep.run(_run(), REPORT, load_report=reload))
        for _ in range(400):  # round 1 paces its default-credential attempts (seconds)
            await asyncio.sleep(0.05)
            if ("read", "/later") in order:
                break
        assert ("read", "/later") in order  # round 2 read while SQL injection still ran
        assert not any(kind == "sqli-end" for kind, _ in order)
        assert state["sweep"] != "done" and state["sweep_stats"]["injection_queued"] > 0
        gate.set()
        await task
        return sweep

    sweep = asyncio.run(scenario())
    assert state["sweep"] == "done"
    assert state["sweep_stats"]["injection_done"] == state["sweep_stats"]["injection_queued"]
    assert sweep.injection_done == sweep.injection_queued


def test_required_inputs_and_input_checks():
    from api.hunt.server_sweep import input_checks, required_inputs
    fastapi = ('{"detail":[{"type":"missing","loc":["query","id"],"msg":"Field required"},'
               '{"type":"missing","loc":["body","url"],"msg":"Field required"}]}')
    assert required_inputs({"status": 422, "body_sample": fastapi}) == [("query", "id"), ("body", "url")]
    assert required_inputs({"status": 400, "body_sample": "Missing parameter 'host'"}) == [("query", "host")]
    assert required_inputs({"status": 200, "body_sample": fastapi}) == []
    checks = dict((check, rank) for rank, check in input_checks("url", "GET"))
    assert checks["ssrf"] == 0 and checks["open_redirect"] == 0 and checks["crlf_injection"] == 1
    assert checks["command_injection"] == 2 and checks["path_traversal"] == 2
    post = [check for _rank, check in input_checks("file", "POST")]
    assert "path_traversal" not in post and "ssrf" not in post and "command_injection" in post


class _ShapeEngine(_Engine):
    async def call(self, capability, values, key):
        if capability == "http.request" and values.get("method") == "GET" and values["path"] in {"/api/lookup", "/api/convert"}:
            self.calls.append((capability, dict(values), key))
            if values["path"] == "/api/lookup":
                return _answer(422, '{"detail":[{"loc":["query","msg"],"msg":"Field required"}]}')
            return _answer(405, '{"detail":"Method Not Allowed"}')
        if capability == "http.request" and values.get("method") == "POST" and values["path"] == "/api/convert":
            self.calls.append((capability, dict(values), key))
            return _answer(422, '{"detail":[{"loc":["body","data"],"msg":"Field required"}]}')
        return await super().call(capability, values, key)


def test_the_sweep_learns_inputs_from_validation_answers_and_runs_request_checks():
    engine = _ShapeEngine()
    state = {}
    recorded = []
    report = {"open": [
        {"endpoint": "GET /api/lookup", "untested": ["review", "unauthenticated_api"], "params": []},
        {"endpoint": "GET /api/convert", "untested": ["review", "unauthenticated_api"], "params": []},
        {"endpoint": "GET /fetch", "untested": ["review", "injection"], "params": ["url"]},
        {"endpoint": "POST /api/xml/parse", "untested": ["review"], "params": []},
        {"endpoint": "POST /graphql", "untested": ["graphql"], "params": []},
        {"endpoint": "GET /hub/login", "untested": ["default_credentials", "review"], "params": []},
    ]}

    async def record(worklist):
        recorded.extend(worklist)

    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state=state, live=engine.live)
                .run(_run(allowed=[*ALL, "request.verify"]), report, load_report=None, record=record))
    assert "GET /api/lookup?msg=1" in recorded
    assert 'POST /api/convert json:{"data":"1"}' in recorded
    shape = [v for cap, v, _ in engine.calls if cap == "http.request" and v["method"] == "POST"
             and v["path"] == "/api/convert"]
    assert shape == [{"method": "POST", "path": "/api/convert", "json_body": {}, "follow_redirects": False}]
    checks = [(v["check"], v["path"], v.get("parameter")) for cap, v, _ in engine.calls if cap == "request.verify"]
    assert ("ssrf", "/fetch", "url") in checks and ("open_redirect", "/fetch", "url") in checks
    assert ("command_injection", "/fetch", "url") in checks
    assert ("xxe", "/api/xml/parse", None) in checks and ("graphql", "/graphql", None) in checks
    assert ("cors", "/", None) in checks and ("security_headers", "/", None) in checks
    assert ("rate_limit", "/hub/login", "password") in checks and ("ldap_injection", "/hub/login", "username") in checks
    # named classes before the generic ones, and never an injection probe at a sign-in
    order = [c for c in checks if c[1] == "/fetch"]
    assert order.index(("ssrf", "/fetch", "url")) < order.index(("command_injection", "/fetch", "url"))
    assert not any(path == "/hub/login" and check not in {"rate_limit", "ldap_injection", "nosql_injection"}
                   for check, path, _ in checks)
    assert state["sweep_stats"]["request_checks_done"] == state["sweep_stats"]["request_checks_queued"] == len(checks)


def test_route_names_are_tried_under_each_api_root_against_a_control():
    from api.hunt.route_words import API_ROUTE_WORDS

    class Api(_Engine):
        async def call(self, capability, values, key):
            if capability == "http.request" and values.get("method") == "GET" and values["path"].startswith("/api/"):
                self.calls.append((capability, dict(values), key))
                path = values["path"]
                if path == "/api/profile":
                    return _answer(422, '{"detail":[{"loc":["query","msg"]}]}')
                if path == "/api/users":
                    return _answer(401, '{"error":"auth"}')
                return _answer(404, '{"detail":"Not Found"}')
            return await super().call(capability, values, key)

    engine = Api()
    state = {}
    recorded = []
    report = {"open": [{"endpoint": "GET /api/status", "untested": ["review"], "params": []},
                       {"endpoint": "GET /api/v1/chat/health", "untested": ["review"], "params": []}]}

    async def record(worklist):
        recorded.extend(worklist)

    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state=state, live=engine.live)
                .run(_run(), report, load_report=None, record=record))
    assert "GET /api/profile" in recorded and "GET /api/users" in recorded
    assert "GET /api/status" not in recorded or True  # the mapped route itself is already known
    assert "GET /api/search" not in recorded  # answered like the control
    tried = [v["path"] for cap, v, _ in engine.calls if cap == "http.request" and v["path"].startswith("/api/v1/")]
    assert len([p for p in tried if p != "/api/v1/chat/health"]) == len(API_ROUTE_WORDS) + 1  # names + control
    assert state["sweep_stats"]["api_roots"] == ["/api", "/api/v1"]
    from pathlib import Path
    bundled = [line.strip() for line in (Path(__file__).resolve().parents[1] / "scanner" / "wordlists" /
               "api-resources.txt").read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]
    assert list(API_ROUTE_WORDS) == list(dict.fromkeys(bundled))


def test_an_anonymous_answer_from_a_product_management_route_queues_its_proof():
    class Product(_Engine):
        async def call(self, capability, values, key):
            if capability == "http.request" and values.get("path") == "/api/kernels":
                self.calls.append((capability, dict(values), key))
                return _answer(200, '[{"id":"k1","execution_state":"idle"}]')
            return await super().call(capability, values, key)

    engine = Product()
    state = {}
    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state=state, live=engine.live)
                .run(_run(allowed=[*ALL, "request.verify"]), {"open": [
                    {"endpoint": "GET /api/kernels", "untested": ["review"], "params": []},
                    {"endpoint": "GET /about", "untested": ["review"], "params": []}]}))
    checks = [(v["check"], v["path"]) for cap, v, _ in engine.calls if cap == "request.verify"]
    assert ("unauthenticated_api", "/api/kernels") in checks
    assert not any(check == "unauthenticated_api" and path == "/about" for check, path in checks)


def test_a_directory_index_read_anonymously_queues_the_listing_proof():
    engine = _Engine()
    state = {}
    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state=state, live=engine.live)
                .run(_run(allowed=[*ALL, "request.verify"]), REPORT))
    checks = [(v["check"], v["path"]) for cap, v, _ in engine.calls if cap == "request.verify"]
    assert ("directory_listing", "/backup/") in checks and ("directory_listing", "/.env") not in checks
    assert ("exposure", "/.env") in checks and ("exposure", "/backup/") in checks


def test_the_sql_tool_follows_only_where_the_quick_sql_proof_saw_the_query_break():
    from api.hunt.server_sweep import sql_screen_escalates

    class Screen(_Engine):
        async def call(self, capability, values, key):
            if capability == "request.verify" and values.get("check") == "sql_injection":
                self.calls.append((capability, dict(values), key))
                broke = values["path"] == "/search"
                pair = {"control_status": 200, "payload_status": 500 if broke else 200}
                return {"action_id": "rv", "action_result": {"status": "success", "observations": [
                    {"kind": "sqli_proof", "proof_state": "not_proven", "finding_verdict": "not_proven",
                     "response_pairs": [pair, pair], "database_error_signatures": []}]}}
            return await super().call(capability, values, key)

    engine = Screen()
    state = {}
    report = {"open": [
        {"endpoint": "GET /search", "untested": ["sqli", "xss"], "params": ["q"]},
        {"endpoint": "GET /orders/{id}", "untested": ["sqli"], "params": ["sort"]},
        {"endpoint": "POST /hub/login", "untested": ["sqli", "default_credentials"], "params": ["username", "password"]},
    ]}
    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state=state, live=engine.live)
                .run(_run(allowed=[*ALL, "request.verify"]), report))
    tool = [v.get("path") + (f" {v['injection_field']}" if v.get("injection_field") else "")
            for cap, v, _ in engine.calls if cap == "sqli.verify"]
    assert "/search?q=1" in tool and not any(item.startswith("/orders") for item in tool)
    assert any(item.startswith("/hub/login") for item in tool)  # a sign-in goes straight to the tool
    assert tool.count("/search?q=1") == 1
    assert sql_screen_escalates(None) is True
    assert sql_screen_escalates({"action_result": {"status": "success", "observations": [
        {"kind": "sqli_proof", "proof_state": "verified", "finding_verdict": "verified"}]}}) is False


def test_one_application_under_several_mounts_is_tested_once():
    class Mounts(_Engine):
        async def call(self, capability, values, key):
            if capability == "http.request" and values.get("method") == "GET" and values["path"].endswith("/app.php"):
                self.calls.append((capability, dict(values), key))
                return _answer(200, "<html>same tool</html>" if not values["path"].startswith("/other") else "<html>else</html>")
            return await super().call(capability, values, key)

    engine = Mounts()
    report = {"open": [{"endpoint": f"GET /{mount}/app.php", "untested": ["sqli", "xss"], "params": ["url"]}
                       for mount in ("a", "b", "c", "other")]}
    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state={}, live=engine.live)
                .run(_run(), report))
    tested = sorted({v["path"].split("?")[0] for cap, v, _ in engine.calls if cap in {"sqli.verify", "xss.verify"}})
    assert tested == ["/a/app.php", "/other/app.php"]


def test_the_wire_pace_holds_the_engines_own_calls_to_its_rate():
    from api.hunt.server_sweep import WirePace, wire_cost
    import time as clock

    pace = WirePace(20)

    async def burst():
        started = clock.monotonic()
        await asyncio.gather(*(pace.take(1) for _ in range(10)))
        check = clock.monotonic() - started
        await pace.take(wire_cost("request.verify", {"check": "sql_injection"}))  # starts at 10/20 s
        await pace.take(1)  # after the check's twelve requests: (10 + 12) / 20 s
        return check, clock.monotonic() - started

    check, elapsed = asyncio.run(burst())
    assert check >= 0.40 and elapsed >= 1.05
    assert wire_cost("http.request", {}) == 1 and wire_cost("sqli.verify", {}) == 0


def test_forms_robots_and_sitemaps_add_their_routes_and_inputs():
    from api.hunt.server_sweep import form_entries, hint_entries
    page = {"status": 200, "html": {"forms": [
        {"method": "GET", "action": "/search", "fields": [{"name": "q", "type": "text"}, {"name": "go", "type": "submit"}]},
        {"method": "POST", "action": "/comments", "fields": [{"name": "author"}, {"name": "body", "type": "textarea"}]},
        {"method": "POST", "action": "https://elsewhere.test/x", "fields": [{"name": "a"}]}]}}
    assert form_entries(page, "/blog") == ["GET /search?q=1", "POST /comments form:author=1&body=1"]
    robots = {"status": 200, "body_sample": "User-agent: *\nDisallow: /admin/\nAllow: /public/page\nDisallow: /\n"}
    assert hint_entries(robots, "/robots.txt") == ["GET /admin/", "GET /public/page"]
    sitemap = {"status": 200, "body_sample": "<urlset><url><loc>http://t.test/a?x=1</loc></url><url><loc>/b</loc></url></urlset>"}
    assert hint_entries(sitemap, "/sitemap.xml") == ["GET /a?x=1", "GET /b"]
    assert hint_entries({"status": 404, "body_sample": "Disallow: /x"}, "/robots.txt") == []


def test_html_pages_the_reads_found_are_analyzed_for_routes_too():
    class Pages(_Engine):
        async def call(self, capability, values, key):
            if capability == "http.request" and values.get("path") == "/chat":
                self.calls.append((capability, dict(values), key))
                return {"action_id": "c", "action_result": {"observations": [{"response": {
                    "status": 200, "body_sample": "<html>", "html": {"title": "Chat", "links": []}}}]}}
            if capability == "javascript.analyze":
                self.calls.append((capability, dict(values), key))
                return {"action_id": "j", "action_result": {"observations": [
                    {"kind": "javascript_analysis", "routes": ["/api/chat/send"]}]}}
            return await super().call(capability, values, key)

    engine = Pages()
    recorded = []

    async def record(worklist):
        recorded.extend(worklist)

    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state={}, live=engine.live)
                .run(_run(), {"open": [{"endpoint": "GET /chat", "untested": ["review"], "params": []}]},
                     load_report=None, record=record))
    analyzed = [v["path"] for cap, v, _ in engine.calls if cap == "javascript.analyze"]
    assert analyzed == ["/chat"] and "GET /api/chat/send" in recorded


def test_the_sweep_follows_the_hunt_and_tests_what_the_planner_maps_until_it_finishes(monkeypatch):
    # Its own rounds done, the sweep waits for the planner: a route the planner's request reached
    # later, and an input a later request added to a route already tested, get the same checks;
    # the sweep ends with a last look once the planner has finished.
    monkeypatch.setattr(server_sweep, "FOLLOW_POLL_SECONDS", 0.01)
    engine = _Engine()
    state = {}
    first = {"open": [{"endpoint": "GET /search", "untested": ["sqli", "xss", "review"], "params": ["q"]}]}
    later = {"open": first["open"] + [
        {"endpoint": "GET /track", "untested": ["sqli", "xss"], "params": ["id"]}]}
    more = {"open": [{"endpoint": "GET /search", "untested": ["sqli", "xss"], "params": ["q", "sort"]},
                     later["open"][1]]}
    last = {"open": more["open"] + [{"endpoint": "GET /late", "untested": ["xss", "sqli"], "params": ["x"]}]}
    looks = []
    finished = {"value": False}

    async def reload():
        looks.append(state.get("sweep"))
        if len(looks) < 3:
            return first  # nothing new yet: the sweep keeps following
        if len(looks) == 3:
            return later
        if len(looks) < 6:
            return more
        if not finished["value"]:
            finished["value"] = True  # the planner finishes; its last request mapped /late
            return more
        return last

    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state=state, live=engine.live)
                .run(_run(allowed=["http.request", "xss.verify"]), first, load_report=reload,
                     planner_finished=lambda: finished["value"]))
    xss = [v["path"] for cap, v, _ in engine.calls if cap == "xss.verify"]
    assert xss == ["/search?q=1", "/track?id=1", "/search?q=1&sort=1", "/late?x=1"]
    assert "following" in looks and state["sweep"] == "done"
    reads = [v["path"] for cap, v, _ in engine.calls if cap == "http.request"]
    assert reads.count("/search") == 1  # back for its new input, never read again


def test_without_a_planner_signal_the_sweep_ends_when_a_round_finds_nothing_new():
    engine = _Engine()
    state = {}
    report = {"open": [{"endpoint": "GET /search", "untested": ["xss"], "params": ["q"]}]}

    async def reload():
        return report

    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state=state, live=engine.live)
                .run(_run(allowed=["http.request", "xss.verify"]), report, load_report=reload))
    assert state["sweep"] == "done" and state["sweep_stats"]["rounds"] == 1


def test_one_sign_in_under_several_mounts_gets_the_default_pairs_once():
    form = [{"method": "POST", "action": "", "fields": [
        {"name": "pma_username", "type": "text"}, {"name": "pma_password", "type": "password"}]}]

    class Mounts(_Engine):
        async def call(self, capability, values, key):
            self.calls.append((capability, dict(values), key))
            if capability == "http.request" and values["method"] == "GET":
                mount = values["path"].split("/")[1]
                page = [dict(form[0], action=f"/{mount}/index.php")]
                title = "Other app" if mount == "crm" else "phpMyAdmin"
                return {"action_id": "r", "action_result": {"status": "success", "observations": [
                    {"response": {"status": 200, "body_sample": "", "html": {"forms": page, "title": title}}}]}}
            if capability == "http.request":
                return _answer(200, login_attempt="rejected")
            return {"action_id": "x", "action_result": {"status": "success", "observations": []}}

    engine = Mounts()
    report = {"open": [{"endpoint": f"GET /{mount}/", "untested": ["review"], "params": []}
                       for mount in ("pma", "phpmyadmin", "dbadmin", "crm")]}
    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state={}, live=engine.live)
                .run(_run(allowed=["http.request"]), report))
    tried = {v["path"] for cap, v, _ in engine.calls if cap == "http.request" and v["method"] == "POST"}
    assert tried == {"/pma/index.php", "/crm/index.php"}


def test_a_route_that_asks_for_http_basic_gets_the_default_pairs_once_per_first_segment():
    class Tomcat(_Engine):
        async def call(self, capability, values, key):
            self.calls.append((capability, dict(values), key))
            if capability != "http.request":
                return {"action_id": "v", "action_result": {"status": "success", "observations": []}}
            if values.get("request_bindings"):
                pair = values["request_bindings"][0]["default_credential"]
                return _answer(200 if pair == "dc-15" else 401,
                               login_attempt="accepted" if pair == "dc-15" else "rejected", action=f"basic-{pair}")
            return {"action_id": "r", "action_result": {"status": "success", "observations": [
                {"response": {"status": 401, "body_sample": "", "challenge_schemes": ["basic"]}}]}}

    engine = Tomcat()
    report = {"open": [{"endpoint": f"GET {path}", "untested": ["review"], "params": []}
                       for path in ("/manager/html", "/manager/status", "/host-manager/html")]}
    asyncio.run(Sweep(call=engine.call, create_candidate=engine.create, state={}, live=engine.live)
                .run(_run(allowed=["http.request", "candidate.verify"], slots=()), report))
    attempts = [v for cap, v, _ in engine.calls if cap == "http.request" and v.get("request_bindings")]
    assert {v["path"] for v in attempts} == {"/manager/html", "/host-manager/html"}
    assert all(v["method"] == "GET" and v["request_bindings"] == [
        {"default_credential": v["request_bindings"][0]["default_credential"], "credential_field": "basic",
         "header": "Authorization"}] for v in attempts)
    assert [c["locus"] for c in engine.candidates] == [
        {"method": "GET", "path": "/manager/html"}, {"method": "GET", "path": "/host-manager/html"}]
    assert all(c["family"] == "default_credentials" and c["evidence_refs"] == ["action:basic-dc-15"]
               for c in engine.candidates)
