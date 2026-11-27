"""request.verify mass_assignment: a sign-up that stores a privileged field (driven VAmPI, 2026-11)."""
from __future__ import annotations

import asyncio
import json
import secrets
import urllib.parse


from api.capabilities.request_verify import RequestVerifier
from api.hunt.request_verification import admission_refusal
from api.runtime.request_replay_executor import ReplayTransportResult
from scanner.scanner_tools.request_replay import ReplayRequest

ORIGIN = "http://vampi.test"
SIGN_UP = ReplayRequest(
    request_id="r", ordinal=0, name="n", folder="", method="POST", url=ORIGIN + "/users/v1/register",
    headers=(("Content-Type", "application/json"),),
    body=json.dumps({"username": "x", "password": "x", "email": "x@x"}).encode(), body_mode="raw",
    auth_type="none", has_sensitive_material=False)


class App:
    def __init__(self, *, stores_admin: bool):
        self.stores_admin, self.users, self.tokens, self.sent = stores_admin, {}, {}, []

    async def send(self, request: ReplayRequest) -> ReplayTransportResult:
        self.sent.append(request)
        path = urllib.parse.urlsplit(request.url).path
        headers = dict(request.headers)
        status, body, out_headers = 404, {}, {"Content-Type": "application/json"}
        if path == "/users/v1/register":
            data = json.loads(request.body)
            self.users[data["username"]] = {"username": data["username"], "email": data["email"],
                                            "password": data["password"],
                                            "admin": bool(data.get("admin")) if self.stores_admin else False}
            status, body = 200, {"message": "Successfully registered", "status": "success"}
        elif path == "/users/v1/login":
            data = json.loads(request.body)
            user = self.users.get(data.get("username"))
            if user and user["password"] == data.get("password"):
                token = secrets.token_hex(16)
                self.tokens[token] = user["username"]
                status, body = 200, {"auth_token": token, "status": "success"}
            else:
                status, body = 200, {"status": "fail", "message": "Password is not correct for the given username."}
        elif path.startswith("/users/v1/"):
            token = str(headers.get("Authorization", "")).removeprefix("Bearer ")
            name = urllib.parse.unquote(path.rsplit("/", 1)[1])
            if self.tokens.get(token) == name:
                user = self.users[name]
                status, body = 200, {"username": name, "email": user["email"], "admin": user["admin"]}
            else:
                status, body = 401, {"status": "fail"}
        return ReplayTransportResult(status_code=status, connected_address="192.0.2.1", final_url=request.url,
                                     response_headers=out_headers, response_body=json.dumps(body).encode(),
                                     elapsed_ms=5)


def _prove(app):
    verifier = RequestVerifier(
        check="mass_assignment", request=SIGN_UP, field="admin", seed="s", send=app.send, left=lambda: 48,
        options={"login_path": "/users/v1/login", "profile_path": "/users/v1/{username}", "privilege_value": "true"})
    return asyncio.run(verifier.run(None))[0]


def test_a_sign_up_that_stores_a_chosen_privilege_is_verified():
    app = App(stores_admin=True)
    observation = _prove(app)
    assert observation["proof_state"] == "verified", observation
    assert observation["proof_contract"] == "request_registration_privilege_readback/v1"
    assert observation["control_value"] == "False" and observation["accounts_created"] == 3
    sign_ups = [json.loads(r.body) for r in app.sent if r.url.endswith("/register")]
    assert len(sign_ups) == 3 and "admin" not in sign_ups[0] and all(s["admin"] is True for s in sign_ups[1:])
    assert len({s["username"] for s in sign_ups}) == 3  # fresh accounts, never the planner's values


def test_a_sign_up_that_ignores_the_field_is_not_proven():
    observation = _prove(App(stores_admin=False))
    assert observation["proof_state"] == "not_proven" and observation["not_proven_reason"] == "field_not_stored"


def test_the_check_needs_account_creation_and_its_paths():
    values = {"check": "mass_assignment", "method": "POST", "path": "/users/v1/register", "parameter": "admin",
              "json_body": {"username": "x", "password": "x"}, "login_path": "/users/v1/login",
              "profile_path": "/users/v1/{username}"}
    policy = {"active_testing": True, "allow_state_changing_http": True}
    assert "allow_account_creation" in admission_refusal(values, policy)
    assert admission_refusal(values, {**policy, "allow_account_creation": True}) is None
    assert "login_path" in admission_refusal({**values, "login_path": None}, {**policy, "allow_account_creation": True})
