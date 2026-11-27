"""Accounts the engine makes itself: sign-up, sign-in, the app used as each login, two compared."""
from __future__ import annotations

import asyncio
import json

import pytest

from api.hunt import engine_accounts as ea
from api.hunt import server_sweep
from api.hunt.server_sweep import Sweep


@pytest.fixture(autouse=True)
def _unpaced(monkeypatch):
    from api.hunt import budget_pace
    monkeypatch.setattr(budget_pace, "wire_requests_per_second", lambda: 100_000)
    monkeypatch.setattr(server_sweep, "DEFAULT_CREDENTIAL_PACE_SECONDS", 0)


def test_signup_routes_bodies_values_and_tokens():
    items = [{"endpoint": "POST /api/Users", "params": []},
             {"endpoint": "POST /account/register", "params": ["email", "pass", "pass_confirm"]},
             {"endpoint": "POST /api/feedback", "params": ["comment"]},
             {"endpoint": "POST /settings", "params": ["new_password", "repeat_password"]}]
    assert [path for path, _ in ea.signup_routes(items)] == ["/account/register", "/settings", "/api/Users"]
    account = {"email": "a@example.invalid", "username": "a1", "name": "A", "password": "Ss-x9!"}
    assert ea.signup_body(["email", "pass", "pass_confirm"], account) == {
        "email": "a@example.invalid", "pass": "Ss-x9!", "pass_confirm": "Ss-x9!"}
    assert set(ea.signup_body([], account)) >= {"email", "username", "password", "passwordRepeat"}
    assert ea.field_value("ProductId", account, {"ProductId": "7"}) == 7
    assert ea.field_value("quantity", account) == 1 and ea.field_value("imageUrl", account).startswith("https://")
    response = {"body_sample": '{"authentication":{"token":"[withheld:2]","bid":6,"umail":"a@x"}}',
                "withheld_values": [{"marker": "[withheld:1]", "ref": "withheld://hunt/x/1"},
                                    {"marker": "[withheld:2]", "ref": "withheld://hunt/x/2"}]}
    assert ea.token_ref(response) == "withheld://hunt/x/2"
    assert ea.own_refs(response) == {"bid": "6"}
    assert ea.own_id("/rest/basket/{id}", {"bid": "6"}) == "6"
    assert ea.own_id("/api/Users/{id}", {"id": "22"}) == "22"
    assert ea.concrete_for("/rest/basket/{id}/items/{itemId}", {"bid": "6"}) == "/rest/basket/6/items/6"
    assert ea.feature_writes([{"endpoint": "POST /api/BasketItems", "params": ["ProductId", "quantity"]},
                              {"endpoint": "DELETE /api/BasketItems/{id}", "params": ["x"]},
                              {"endpoint": "POST /rest/user/reset-password", "params": ["new"]},
                              {"endpoint": "POST /api/Feedbacks", "params": []}]) == [
        ("POST", "/api/BasketItems", ["ProductId", "quantity"])]


class _Shop:
    """A shop with self-registration, a JSON sign-in answering a token, and baskets."""

    def __init__(self):
        self.calls = []
        self.users = {}
        self.candidates = []

    async def call(self, capability, values, key):
        self.calls.append((capability, json.loads(json.dumps(values)), key))
        if capability != "http.request":
            return {"action_id": f"a{len(self.calls)}", "action_result": {"status": "success", "observations": []}}
        method, path = values["method"], values["path"]
        body = values.get("json_body") or {}
        if (method, path) == ("POST", "/api/Users"):
            if "json_body" not in values:
                return self._answer(415, "")
            self.users[body["email"]] = (len(self.users) + 1, body["password"])
            return self._answer(201, json.dumps({"status": "success", "data": {"id": len(self.users)}}))
        if (method, path) == ("POST", "/rest/user/login"):
            uid, password = self.users.get(body.get("email"), (None, None))
            if uid is None or body.get("password") != password:
                return self._answer(401, "Invalid email or password.")
            n = len([c for c in self.calls if c[1].get("path") == "/rest/user/login"])
            return self._answer(200, json.dumps({"authentication": {"token": f"[withheld:{n}]", "bid": 10 + uid}}),
                                withheld=[{"marker": f"[withheld:{n}]", "ref": f"withheld://hunt/{uid}/{n}"}])
        if values.get("request_bindings") or path.startswith("/rest/user/login"):
            return self._answer(200, '{"data":[]}')
        if path == "/rest/user/login" or path.startswith("/rest/basket"):
            return self._answer(401, "")
        return self._answer(200, "{}")

    @staticmethod
    def _answer(status, body, withheld=None):
        response = {"status": status, "body_sample": body, "html": {}}
        if withheld:
            response["withheld_values"] = withheld
        return {"action_id": f"r{status}", "action_result": {"status": "success", "observations": [{"response": response}]}}

    async def create(self, values):
        self.candidates.append(values)
        return {"candidate": {"id": f"c{len(self.candidates)}"}}

    async def live(self):
        return True


def _run(allowed, writes=True, accounts=True):
    return {"id": "h1", "target_id": "t1", "target_kind": "web", "status": "active", "completed_at": None,
            "policy_json": json.dumps({"allowed_capabilities": allowed, "allow_state_changing_http": writes,
                                       "allow_account_creation": accounts,
                                       "active_testing": True, "approval_receipt_id": "r1"}),
            "context_pack": "{}"}


REPORT = {"open": [
    {"endpoint": "POST /api/Users", "untested": ["sqli"], "params": []},
    {"endpoint": "POST /rest/user/login", "untested": ["default_credentials"], "params": []},
    {"endpoint": "GET /rest/basket/{id}", "untested": ["object_authz"], "params": []},
    {"endpoint": "POST /api/BasketItems", "untested": ["sqli"], "params": ["ProductId", "BasketId", "quantity"]},
]}


def test_the_engine_signs_up_twice_signs_in_uses_the_app_as_each_and_compares_them():
    shop = _Shop()
    state = {}
    asyncio.run(Sweep(call=shop.call, create_candidate=shop.create, state=state, live=shop.live)
                .run(_run(["http.request", "authz.verify"]), REPORT))
    signups = [v for cap, v, _ in shop.calls if v.get("path") == "/api/Users" and v.get("method") == "POST"
               and "json_body" in v and "request_bindings" not in v]
    assert len(shop.users) == 2 and len(signups) == 2
    assert signups[0]["json_body"]["email"] != signups[1]["json_body"]["email"]
    logins = state["sweep_stats"]["engine_logins"]
    assert len(logins) == 2 and all(label.startswith("account") for label in logins)
    as_login = [v for cap, v, _ in shop.calls if cap == "http.request" and v.get("request_bindings")]
    baskets = sorted(v["path"] for v in as_login if v["path"].startswith("/rest/basket/"))
    assert baskets == ["/rest/basket/11", "/rest/basket/12"]  # each account reads its own basket
    items = [v for v in as_login if v["path"] == "/api/BasketItems"]
    assert len(items) == 2 and {v["json_body"]["BasketId"] for v in items} == {11, 12}
    assert all(v["json_body"]["quantity"] == 1 for v in items)
    authz = [v for cap, v, _ in shop.calls if cap == "authz.verify"]
    assert len(authz) == 1 and authz[0]["routes"] == ["/rest/basket/11"]
    assert authz[0]["primary_bindings"] != authz[0]["secondary_bindings"]
    assert all(b[0]["header"] == "Authorization" and b[0]["prefix"] == "Bearer "
               for b in (authz[0]["primary_bindings"], authz[0]["secondary_bindings"]))
    # The operator's clean-up list: each account (never its password) and each write it sent.
    made = state["engine_accounts"]
    assert [entry["signup_route"] for entry in made] == ["POST /api/Users"] * 2
    assert {entry["email"] for entry in made} == set(shop.users) and all("password" not in entry for entry in made)
    assert {entry["request"] for entry in state["engine_writes"]} == {"POST /api/BasketItems"}


def test_without_the_state_changing_permission_no_account_is_made():
    shop = _Shop()
    asyncio.run(Sweep(call=shop.call, create_candidate=shop.create, state={}, live=shop.live)
                .run(_run(["http.request", "authz.verify"], writes=False), REPORT))
    assert not shop.users and not any(v.get("request_bindings") for _, v, _ in shop.calls)


def test_an_accepted_default_pair_becomes_a_login_the_sweep_uses():
    class Admin(_Shop):
        async def call(self, capability, values, key):
            if capability == "http.request" and values.get("request_bindings") and \
                    values["request_bindings"][0].get("default_credential"):
                self.calls.append((capability, json.loads(json.dumps(values)), key))
                pair = values["request_bindings"][0]["default_credential"]
                if pair != "dc-01":
                    return {"action_id": f"x{pair}", "action_result": {"status": "success", "observations": [
                        {"response": {"status": 401, "body_sample": "", "login_attempt": {"verdict": "rejected"}}}]}}
                return {"action_id": "accepted", "action_result": {"status": "success", "observations": [{"response": {
                    "status": 200, "body_sample": '{"token":"[withheld:1]","user":{"id":1}}',
                    "withheld_values": [{"marker": "[withheld:1]", "ref": "withheld://hunt/accepted/1"}],
                    "login_attempt": {"verdict": "accepted"}}}]}}
            return await super().call(capability, values, key)

    admin = Admin()
    state = {}
    report = {"open": [{"endpoint": "POST /api/login", "untested": ["default_credentials"], "params": []},
                       {"endpoint": "GET /api/admin/users", "untested": ["function_authz"], "params": []}]}
    asyncio.run(Sweep(call=admin.call, create_candidate=admin.create, state=state, live=admin.live)
                .run(_run(["http.request"]), report))
    assert state["sweep_stats"]["engine_logins"] == ["default dc-01 (/api/login)"]
    reads = [v for cap, v, _ in admin.calls if v.get("path") == "/api/admin/users" and v.get("request_bindings")]
    assert reads and reads[0]["request_bindings"] == [
        {"withheld_ref": "withheld://hunt/accepted/1", "header": "Authorization", "prefix": "Bearer "}]


def test_writes_go_only_to_the_accounts_own_objects_and_never_touch_secrets_or_roles():
    assert ea.own_path("/api/BasketItems", {}) == "/api/BasketItems"
    assert ea.own_path("/rest/basket/{id}", {"bid": "6"}) == "/rest/basket/6"
    assert ea.own_path("/api/Products/{id}", {"bid": "6"}) is None  # not this account's object
    items = [{"endpoint": "PUT /api/users/{id}", "params": ["email", "password"]},
             {"endpoint": "PATCH /api/profile", "params": ["role"]},
             {"endpoint": "POST /api/Feedbacks", "params": ["comment", "rating"]}]
    assert ea.feature_writes(items) == [("POST", "/api/Feedbacks", ["comment", "rating"])]


def test_a_default_credential_login_reads_but_never_writes():
    class Admin(_Shop):
        async def call(self, capability, values, key):
            bindings = values.get("request_bindings") or []
            if capability == "http.request" and bindings and bindings[0].get("default_credential"):
                self.calls.append((capability, json.loads(json.dumps(values)), key))
                ok = bindings[0]["default_credential"] == "dc-01"
                return {"action_id": "acc" if ok else "rej", "action_result": {"status": "success", "observations": [{"response": {
                    "status": 200 if ok else 401, "body_sample": '{"token":"[withheld:1]"}' if ok else "",
                    "withheld_values": [{"marker": "[withheld:1]", "ref": "withheld://hunt/acc/1"}] if ok else [],
                    "login_attempt": {"verdict": "accepted" if ok else "rejected"}}}]}}
            return await super().call(capability, values, key)

    admin = Admin()
    report = {"open": [{"endpoint": "POST /api/login", "untested": ["default_credentials"], "params": []},
                       {"endpoint": "POST /api/Feedbacks", "untested": ["sqli"], "params": ["comment"]},
                       {"endpoint": "GET /api/admin/users", "untested": ["function_authz"], "params": []}]}
    asyncio.run(Sweep(call=admin.call, create_candidate=admin.create, state={}, live=admin.live)
                .run(_run(["http.request"]), report))
    as_admin = [v for _, v, _ in admin.calls if v.get("request_bindings") and
                v["request_bindings"][0].get("withheld_ref") == "withheld://hunt/acc/1"]
    assert as_admin and all(v["method"] == "GET" for v in as_admin)


def test_accounts_are_made_only_with_the_operators_explicit_account_creation_permission():
    shop = _Shop()
    state = {}
    asyncio.run(Sweep(call=shop.call, create_candidate=shop.create, state=state, live=shop.live)
                .run(_run(["http.request", "authz.verify"], accounts=False), REPORT))
    assert not shop.users and "engine_accounts" not in state and "engine_writes" not in state


def test_the_debrief_lists_what_the_engine_made_on_the_target():
    from api.hunt.coverage_map import build_coverage, debrief_coverage
    discovery = {"engine_accounts": [{"label": "account a (/api/Users)", "signup_route": "POST /api/Users",
                                      "email": "shakerscan-x@example.invalid", "username": "shakerscanx"}],
                 "engine_writes": [{"login": "account a (/api/Users)", "request": "POST /api/BasketItems",
                                    "fields": ["ProductId"]}]}
    report = build_coverage(actions=[], endpoints=[], discovery=discovery)
    debrief = debrief_coverage(report, forced=False, reason=None)
    assert debrief["discovery"]["engine_accounts"] == discovery["engine_accounts"]
    assert debrief["discovery"]["engine_writes"] == discovery["engine_writes"]


@pytest.mark.parametrize("answer, accounts", [("pending", 0), ("unavailable", 0), ("granted", 2)])
def test_without_the_flag_the_engine_asks_and_makes_accounts_only_when_granted(answer, accounts):
    asked = []

    async def ask(flag, routes):
        asked.append((flag, list(routes)))
        return answer

    shop = _Shop()
    state = {}
    asyncio.run(Sweep(call=shop.call, create_candidate=shop.create, state=state, live=shop.live,
                      request_permission=ask).run(_run(["http.request"], accounts=False), REPORT))
    assert asked == [("account-creation", ["/api/Users"])]
    assert len(shop.users) == accounts
    assert ("engine_accounts" in state) == bool(accounts)


def test_a_users_collection_seen_only_as_a_read_is_tried_as_a_sign_up():
    assert [path for path, _ in ea.signup_routes([{"endpoint": "GET /api/Users", "params": []},
                                                  {"endpoint": "GET /api/Products", "params": []}])] == ["/api/Users"]
