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


def _run(allowed, writes=True):
    return {"id": "h1", "target_id": "t1", "target_kind": "web", "status": "active", "completed_at": None,
            "policy_json": json.dumps({"allowed_capabilities": allowed, "allow_state_changing_http": writes,
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
    assert len(items) == 2 and items[0]["json_body"]["BasketId"] == 11 and items[0]["json_body"]["quantity"] == 1
    authz = [v for cap, v, _ in shop.calls if cap == "authz.verify"]
    assert len(authz) == 1 and authz[0]["routes"] == ["/rest/basket/11"]
    assert authz[0]["primary_bindings"] != authz[0]["secondary_bindings"]
    assert all(b[0]["header"] == "Authorization" and b[0]["prefix"] == "Bearer "
               for b in (authz[0]["primary_bindings"], authz[0]["secondary_bindings"]))


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
