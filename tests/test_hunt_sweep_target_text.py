"""The engine's sweep reads text the target chose: no body may stall it, end it, or steer it.

Review of 2.14.1:

* ``exposure_signal`` searched each read's body with a pattern quadratic on a long run of name
  characters (4.7 s on 16,000 characters of ``a.a.a.``, on the API's event loop, up to 800 reads
  a sweep). The patterns that run on target text are linear; the counts below are the engine's
  own work on inputs of doubling size, in the style of ``test_archive_masking_linear``.
* One malformed document (a sitemap ``<loc>http://[</loc>``, an introspection answer whose
  ``fields`` is a number) raised out of the sweep, which ended with its state still ``running``
  and its queued checks orphaned. A failure is now counted and named and the batch goes on.
* The XSS reflection screen sent the inventory route's own method, so ``DELETE /api/users/{id}``
  got a DELETE with a form body. The engine's own requests are GET, HEAD, POST, PUT or PATCH.
* The sign-in rate-limit check named a user that does not exist; it is not queued.
* ``allow_account_creation`` was read once at the sweep's start; it is read again before use.
"""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from api.hunt import graphql_sweep, server_sweep
from api.hunt.server_sweep import Sweep, exposure_signal, hint_entries, required_inputs
from api.runtime import form_prefetch


@pytest.fixture(autouse=True)
def _unpaced(monkeypatch):
    from api.hunt import budget_pace
    monkeypatch.setattr(budget_pace, "wire_requests_per_second", lambda: 100_000)
    monkeypatch.setattr(server_sweep, "DEFAULT_CREDENTIAL_PACE_SECONDS", 0)


# --- linear on target text ----------------------------------------------------------------------

# Bodies built to make a backtracking pattern do the most work: long runs of the characters a
# pattern's unbounded part accepts, with nothing after them that lets it match.
ADVERSARIAL = {
    "name characters": lambda n: "a." * (n // 2),
    "name characters, dashed": lambda n: "a-b_" * (n // 4),
    "words": lambda n: "pass " * (n // 5),
    "quoted names": lambda n: '"a.a.a.a":1,' * (n // 12),
    "blank lines": lambda n: "\n" * n,
    "blanks after a required word": lambda n: "missing parameter" + " " * n + "1",
    "blanks after a secret name": lambda n: "token" + " " * n,
    "sitemap entries": lambda n: "<loc>" * (n // 5),
    "robots lines": lambda n: "Allow:" + " " * n,
    "records": lambda n: '"email":"' * (n // 9),
}


def _seconds(function, *args) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        function(*args)
        best = min(best, time.perf_counter() - started)
    return best


def _readers():
    def exposure(text):
        exposure_signal({"status": 200, "body_sample": text, "json_keys": [text[:4000]]})

    def robots(text):
        hint_entries({"status": 200, "body_sample": text}, "/robots.txt")

    def sitemap(text):
        hint_entries({"status": 200, "body_sample": text}, "/sitemap.xml")

    def required(text):
        required_inputs({"status": 422, "body_sample": text})

    def schema(text):
        graphql_sweep.argument_loci(text, "/graphql")

    def form(text):
        form_prefetch.hidden_fields(text, page_url="http://t.example/login", post_url="http://t.example/login")

    return {"exposure_signal": exposure, "robots": robots, "sitemap": sitemap, "required_inputs": required,
            "graphql schema": schema, "form_prefetch": form}


@pytest.mark.parametrize("reader", sorted(_readers()))
@pytest.mark.parametrize("shape", sorted(ADVERSARIAL))
def test_a_body_the_target_chose_is_read_in_linear_time(reader, shape):
    """Quadratic work on 128,000 characters is seconds (the old secret-field pattern: minutes);
    linear work is milliseconds. The bound is loose enough for a loaded machine and far below
    what any quadratic pattern needs."""
    read, make = _readers()[reader], ADVERSARIAL[shape]
    small, large = _seconds(read, make(16_000)), _seconds(read, make(128_000))
    assert large < 1.0, f"{reader} on {shape}: {large:.2f}s for 128,000 characters"
    # Eight times the input: linear is about 8x, quadratic about 64x.
    assert large < max(0.05, 24 * small), f"{reader} on {shape}: {small:.4f}s -> {large:.4f}s"


def test_the_secret_field_search_measured_in_the_review_is_fast_and_finds_what_it_found():
    body = "a." * 8_000  # the measured case: 16,000 characters, 4.7 s
    assert _seconds(exposure_signal, {"status": 200, "body_sample": body}) < 0.25
    # Unchanged verdicts: a name ending in a secret word, quoted or not, dotted or dashed.
    for text in ("DB_PASSWORD=hunter22", '{"api_key": "sk_live_x1y2"}', "spring.datasource.password: s3cret!",
                 "aws-secret = abcdef", "'client_secret' : 'abcd'", 'x "password_hash":"$2b$12$abc"',
                 "a." * 4_000 + "db.password=hunter22"):
        assert exposure_signal({"status": 200, "body_sample": text}) == "secret-named fields", text
    for text in ("the password policy", "token", '{"status": "ok"}', "passwords are hashed", "secret:"):
        assert exposure_signal({"status": 200, "body_sample": text}) is None, text


def test_robots_and_validation_answers_still_parse():
    robots = "User-agent: *\nDisallow: /admin\n  allow : /public/x\nDisallow:\n/not-a-rule\nAllow: /a?b\n"
    assert hint_entries({"status": 200, "body_sample": robots}, "/robots.txt") == [
        "GET /admin", "GET /public/x", "GET /a"]
    assert required_inputs({"status": 400, "body_sample": "Missing required parameter: 'name'"}) == [("query", "name")]
    assert required_inputs({"status": 400, "body_sample": "missing field = email"}) == [("query", "email")]
    assert required_inputs({"status": 400, "body_sample": "required argument `q`"}) == [("query", "q")]


# --- one malformed document never ends the sweep ------------------------------------------------

def test_malformed_target_text_is_no_entry_and_no_error():
    sitemap = "<urlset><loc>http://[</loc><loc>/ok</loc><loc>http://t.example/a?b=1</loc></urlset>"
    assert hint_entries({"status": 200, "body_sample": sitemap}, "/sitemap.xml") == ["GET /ok", "GET /a?b=1"]
    for answer in ({"data": {"__schema": {"queryType": {"fields": 5}}}},
                   {"data": {"__schema": {"queryType": {"fields": {"a": 1}}}}},
                   {"data": {"__schema": {"queryType": {"fields": [{"name": "pastes", "args": 5}]}}}},
                   {"data": {"__schema": {"queryType": {"fields": [
                       {"name": "pastes", "type": {"kind": ["LIST"]}, "args": [{"name": "q", "type": {"kind": {}}}]}]}}}},
                   {"data": 5}, [], "[1, 2", 7):
        text = answer if isinstance(answer, str) else json.dumps(answer)
        assert graphql_sweep.argument_loci(text, "/graphql") == []
    page = '<form method="post" action="http://[/x"><input type="hidden" name="t" value="1"></form>'
    assert form_prefetch.hidden_fields(page, page_url="http://t.example/login",
                                       post_url="http://t.example/login") == {}
    # The page's other form still posts where the request does.
    both = page + '<form method="post" action="/login"><input type="hidden" name="csrf" value="v"></form>'
    assert form_prefetch.hidden_fields(both, page_url="http://t.example/login",
                                       post_url="http://t.example/login") == {"csrf": "v"}


ALL = ["http.request", "javascript.analyze", "candidate.verify", "request.verify", "xss.verify", "sqli.verify"]


def _run(*, allowed=ALL, writes=True, **policy):
    return {"id": "h1", "target_id": "t1", "target_kind": "web", "status": "active", "completed_at": None,
            "policy_json": json.dumps({"allowed_capabilities": allowed, "allow_state_changing_http": writes,
                                       "active_testing": True, "approval_receipt_id": "r1", **policy}),
            "context_pack": "{}"}


def _answer(status, body="", *, action="a"):
    return {"action_id": action, "action_result": {"status": "success", "observations": [
        {"response": {"status": status, "body_sample": body, "html": {}}}]}}


class _Target:
    """An application whose documents are malformed in the ways the review named."""

    def __init__(self, pages):
        self.pages = pages
        self.calls: list[tuple[str, dict, str]] = []
        self.candidates: list[dict] = []

    async def call(self, capability, values, key):
        self.calls.append((capability, dict(values), key))
        if capability != "http.request":
            return {"action_id": f"x{len(self.calls)}", "action_result": {"status": "success", "observations": []}}
        path = values["path"].split("?", 1)[0]
        if values["method"] != "GET" and path not in self.pages:
            return _answer(200, " ".join(str(v) for v in (values.get("form_body") or values.get("json_body") or {}).values()))
        if "zsk" in values["path"]:
            import urllib.parse
            return _answer(200, urllib.parse.unquote_plus(values["path"].split("?", 1)[1]))
        page = self.pages.get(path)
        return _answer(200, page, action=f"read{len(self.calls)}") if page is not None else _answer(404, "Not Found")

    async def create(self, values):
        self.candidates.append(dict(values))
        return {"candidate": {"id": f"c{len(self.candidates)}"}}

    async def live(self):
        return True


def test_a_sitemap_and_a_graphql_schema_that_do_not_parse_leave_the_sweep_running_its_checks():
    target = _Target({
        "/sitemap.xml": "<urlset><loc>http://[</loc><loc>/shop</loc></urlset>",
        "/graphql": json.dumps({"data": {"__schema": {"queryType": {"fields": 5}}}}),
        "/search": "results",
    })
    state: dict = {}
    recorded: list[str] = []
    report = {"open": [
        {"endpoint": "GET /sitemap.xml", "untested": ["review"], "params": []},
        {"endpoint": "POST /graphql", "untested": ["graphql"], "params": []},
        {"endpoint": "GET /search", "untested": ["sqli", "xss", "review"], "params": ["q"]},
    ]}

    async def record(worklist):
        recorded.extend(worklist)

    asyncio.run(Sweep(call=target.call, create_candidate=target.create, state=state, live=target.live)
                .run(_run(), report, load_report=None, record=record))
    assert state["sweep"] == "done"
    assert "GET /shop" in recorded  # the entry that parses is still mapped
    checks = {(v["check"], v["path"], v.get("parameter")) for cap, v, _ in target.calls if cap == "request.verify"}
    assert ("sql_injection", "/search", "q") in checks and ("graphql", "/graphql", None) in checks
    assert any(cap == "xss.verify" for cap, _v, _k in target.calls)  # the reflection screen and its tool ran
    assert state["sweep_stats"]["request_checks_done"] == state["sweep_stats"]["request_checks_queued"] > 0
    assert not target.candidates  # a schema with no fields names no argument


def test_a_step_that_raises_is_counted_and_named_and_the_rest_of_the_batch_runs(monkeypatch):
    """Whatever else target text breaks (here: one route's parse and one whole phase), a route's
    failure costs that route and a phase's failure that phase; the sweep still ends ``done``."""
    real = server_sweep.hint_entries

    def hints(response, page):
        if page == "/boom":
            raise ValueError("a document nobody anticipated")
        return real(response, page)

    async def no_javascript(self, _items):
        raise TypeError("a phase that fails outright")

    monkeypatch.setattr(server_sweep, "hint_entries", hints)
    monkeypatch.setattr(Sweep, "_javascript", no_javascript)
    target = _Target({"/boom": "x", "/search": "results", "/robots.txt": "Disallow: /private"})
    state: dict = {}
    recorded: list[str] = []
    report = {"open": [
        {"endpoint": "GET /boom", "untested": ["review"], "params": []},
        {"endpoint": "GET /robots.txt", "untested": ["review"], "params": []},
        {"endpoint": "GET /search", "untested": ["sqli", "xss", "review"], "params": ["q"]},
    ]}

    async def record(worklist):
        recorded.extend(worklist)

    asyncio.run(Sweep(call=target.call, create_candidate=target.create, state=state, live=target.live)
                .run(_run(), report, load_report=None, record=record))
    assert state["sweep"] == "done"
    assert state["sweep_counts"]["read:failed"] == 1 and state["sweep_counts"]["javascript:failed"] == 1
    assert any("read: ValueError" in note for note in state["notes"])
    assert any("javascript: TypeError" in note for note in state["notes"])
    assert "GET /private" in recorded  # the other routes of the batch were read and mapped
    assert any(cap == "request.verify" and v.get("path") == "/search" for cap, v, _ in target.calls)


def test_a_sweep_that_dies_says_so_and_cancels_what_it_queued():
    """What no guard contains (the coverage read failing between rounds): the state is ``failed``,
    never left ``running``, and the queued checks are cancelled, not orphaned."""
    started = asyncio.Event()
    cancelled: list[str] = []

    class Slow(_Target):
        async def call(self, capability, values, key):
            if capability == "request.verify":
                started.set()
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    cancelled.append(values["check"])
                    raise
            return await super().call(capability, values, key)

    target = Slow({"/search": "results"})
    state: dict = {}
    report = {"open": [{"endpoint": "GET /search", "untested": ["sqli", "review"], "params": ["q"]}]}

    async def reload():
        await started.wait()
        raise RuntimeError("the coverage read failed")

    async def scenario():
        sweep = Sweep(call=target.call, create_candidate=target.create, state=state, live=target.live)
        await asyncio.wait_for(sweep.run(_run(allowed=["http.request", "request.verify"]), report,
                                         load_report=reload), 10)
        return sweep

    sweep = asyncio.run(scenario())
    assert state["sweep"] == "failed" and state["sweep_counts"]["sweep:failed"] == 1
    assert any("sweep ended early: RuntimeError" in note for note in state["notes"])
    assert cancelled and not sweep._long_jobs


# --- the engine's own requests never use DELETE ---------------------------------------------------

def test_an_object_route_mapped_as_delete_gets_no_delete_from_the_engine():
    target = _Target({"/api/users/1": '{"id": 1}'})
    state: dict = {}
    report = {"open": [
        {"endpoint": "DELETE /api/users/{id}", "untested": ["object_authz", "sqli", "xss"], "params": ["reason", "id"]},
        {"endpoint": "PUT /api/users/{id}", "untested": ["sqli", "xss"], "params": ["name"]},
        {"endpoint": "OPTIONS /api/users/{id}", "untested": ["xss"], "params": ["name"]},
    ]}
    asyncio.run(Sweep(call=target.call, create_candidate=target.create, state=state, live=target.live)
                .run(_run(), report))
    assert state["sweep"] == "done"
    methods = {str(v.get("method") or "").upper() for _cap, v, _k in target.calls if v.get("method")}
    assert methods <= {"GET", "POST", "PUT", "PATCH"}, methods
    assert not any("DELETE" in json.dumps(v) for _cap, v, _k in target.calls)
    # The write the Hunt may send is still screened and tested.
    assert any(cap == "http.request" and v["method"] == "PUT" and v.get("form_body") for cap, v, _ in target.calls)


def test_the_engine_call_gate_refuses_a_delete_whoever_builds_it():
    target = _Target({})
    state: dict = {}
    sweep = Sweep(call=target.call, create_candidate=target.create, state=state, live=target.live)

    async def scenario():
        sent = [await sweep._safe("http.request", {"method": "DELETE", "path": "/api/users/1"}, "k1"),
                await sweep._safe("xss.verify", {"method": "delete", "path": "/api/users/1",
                                                 "injection_field": "x"}, "k2"),
                await sweep._safe("request.verify", {"check": "sql_injection", "method": "TRACE", "path": "/x"}, "k3")]
        kept = await sweep._safe("http.request", {"method": "GET", "path": "/api/users/1"}, "k4")
        return sent, kept

    sent, kept = asyncio.run(scenario())
    assert sent == [None, None, None] and kept is not None
    assert [v["method"] for _cap, v, _k in target.calls] == ["GET"]
    assert state["sweep_counts"]["http.request:method_skipped"] == 1
    assert state["sweep_counts"]["xss.verify:method_skipped"] == 1


# --- no rate-limit check for a made-up user -------------------------------------------------------

def test_the_sweep_queues_no_rate_limit_check_for_a_user_that_does_not_exist():
    target = _Target({})
    state: dict = {}
    sweep = Sweep(call=target.call, create_candidate=target.create, state=state, live=target.live)

    async def scenario():
        await sweep._signin_checks("/api/login", "username", "password", True)
        await asyncio.gather(*list(sweep._long_jobs))

    asyncio.run(scenario())
    checks = [v["check"] for cap, v, _ in target.calls if cap == "request.verify"]
    assert sorted(checks) == ["ldap_injection", "nosql_injection"]
    assert state["sweep_counts"]["rate_limit:skipped_no_account"] == 1


# --- allow_account_creation is read when it is used -----------------------------------------------

def test_account_creation_revoked_while_the_hunt_runs_stops_the_next_sign_up():
    target = _Target({})
    made: list[int] = []
    policy = {"allow_account_creation": True}
    loads: list[bool] = []

    async def load_policy():
        loads.append(policy["allow_account_creation"])
        return dict(policy)

    class Counting(Sweep):
        async def _make_accounts(self, items):
            made.append(len(made) + 1)
            policy["allow_account_creation"] = False  # the operator revokes it after the first round

    first = {"open": [{"endpoint": "POST /api/Users", "untested": ["sqli"], "params": ["email", "password"]}]}
    second = {"open": first["open"] + [{"endpoint": "GET /late", "untested": ["review"], "params": []}]}
    reports = [second, second]

    async def reload():
        return reports.pop(0) if reports else second

    state: dict = {}
    asyncio.run(Counting(call=target.call, create_candidate=target.create, state=state, live=target.live,
                         load_policy=load_policy)
                .run(_run(allowed=["http.request"], allow_account_creation=True), first, load_report=reload))
    assert state["sweep_stats"]["rounds"] == 2
    assert made == [1] and loads == [True, False]


def test_an_unreadable_policy_allows_no_account():
    target = _Target({})

    async def load_policy():
        raise RuntimeError("database away")

    state: dict = {}
    sweep = Sweep(call=target.call, create_candidate=target.create, state=state, live=target.live,
                  load_policy=load_policy)
    assert asyncio.run(sweep._accounts_allowed({"allow_account_creation": True})) is False
    # Without a loader (a caller that has none) the policy at the sweep's start still decides.
    plain = Sweep(call=target.call, create_candidate=target.create, state={}, live=target.live)
    assert asyncio.run(plain._accounts_allowed({"allow_account_creation": True})) is True


# --- a hold the target asked for is waited out between calls, not inside one -----------------------

def test_a_call_refused_for_a_target_hold_is_sent_again_after_the_hold(monkeypatch):
    sleeps: list[float] = []

    async def sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(server_sweep.asyncio, "sleep", sleep)
    held = {"action_id": "h", "error": "target_hold: the target is held for another 45 s (429 from the target); "
                                       "nothing was sent, retry after it",
            "action_result": {"status": "failed", "observations": []}}

    class Held(_Target):
        def __init__(self, refusals):
            super().__init__({"/a": "ok"})
            self.refusals = refusals

        async def call(self, capability, values, key):
            if self.refusals > 0:
                self.refusals -= 1
                self.calls.append((capability, dict(values), key))
                return held
            return await super().call(capability, values, key)

    target = Held(2)
    state: dict = {}
    sweep = Sweep(call=target.call, create_candidate=target.create, state=state, live=target.live)
    result = asyncio.run(sweep._safe("http.request", {"method": "GET", "path": "/a"}, "k"))
    assert server_sweep._response(result)["status"] == 200
    assert sleeps == [46.0, 46.0] and [key for _c, _v, key in target.calls] == ["k", "k:held1", "k:held1:held2"]
    assert state["sweep_counts"]["http.request:target_hold_waited"] == 2
    # Bounded: a target that stays held is given up on, and the answer says why.
    stuck = Held(99)
    sweep = Sweep(call=stuck.call, create_candidate=stuck.create, state={}, live=stuck.live)
    result = asyncio.run(sweep._safe("http.request", {"method": "GET", "path": "/a"}, "k"))
    assert len(stuck.calls) == server_sweep.MAX_TARGET_HOLD_WAITS + 1
    assert server_sweep._error_of(result).startswith("target_hold:")
