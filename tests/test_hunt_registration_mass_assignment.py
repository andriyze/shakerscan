"""request.verify mass_assignment: a sign-up that stores a privileged field (driven VAmPI, 2026-11)."""
from __future__ import annotations

import asyncio
import json
import secrets
import urllib.parse

import pytest

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
    def __init__(self, *, stores_admin: bool, stores: tuple[str, ...] = ()):
        self.stores_admin, self.users, self.tokens, self.sent = stores_admin, {}, {}, []
        self.stores = stores  # ordinary profile fields a sign-up is meant to set

    async def send(self, request: ReplayRequest) -> ReplayTransportResult:
        self.sent.append(request)
        path = urllib.parse.urlsplit(request.url).path
        headers = dict(request.headers)
        status, body, out_headers = 404, {}, {"Content-Type": "application/json"}
        if path == "/users/v1/register":
            data = json.loads(request.body)
            self.users[data["username"]] = {"username": data["username"], "email": data["email"],
                                            "password": data["password"],
                                            "admin": bool(data.get("admin")) if self.stores_admin else False,
                                            **{name: data.get(name, False) for name in self.stores}}
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
                status, body = 200, {key: value for key, value in user.items() if key != "password"}
            else:
                status, body = 401, {"status": "fail"}
        return ReplayTransportResult(status_code=status, connected_address="192.0.2.1", final_url=request.url,
                                     response_headers=out_headers, response_body=json.dumps(body).encode(),
                                     elapsed_ms=5)


def _prove(app, field="admin", value="true"):
    verifier = RequestVerifier(
        check="mass_assignment", request=SIGN_UP, field=field, seed="s", send=app.send, left=lambda: 48,
        options={"login_path": "/users/v1/login", "profile_path": "/users/v1/{username}", "privilege_value": value})
    return asyncio.run(verifier.run(None))[0]


def test_a_sign_up_that_stores_a_chosen_privilege_is_verified():
    app = App(stores_admin=True)
    observation = _prove(app)
    assert observation["proof_state"] == "verified", observation
    assert observation["proof_contract"] == "request_registration_privilege_readback/v1"
    assert observation["accounts_created"] == 3 and observation["privilege_kind"] == "administrator_flag"
    # The control's profile value is described, not carried.
    assert "control_value" not in observation and observation["control_value_type"] == "bool"
    assert observation["control_value_chars"] == 5 and "False" not in json.dumps(observation)
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


@pytest.mark.parametrize("field,value", [("newsletter", "true"), ("marketing_opt_in", "true"),
                                         ("theme", '"dark"'), ("admin_notes", '"hello"')])
def test_a_stored_field_that_is_no_privilege_is_never_a_verified_mass_assignment(field, value):
    """The application stores it, the control differs, both repeats read it back: the differential
    holds, and it is the sign-up working as designed."""
    app = App(stores_admin=False, stores=(field,))
    observation = _prove(app, field=field, value=value)
    assert observation["proof_state"] == "not_proven" and observation["proof_contract"] is None
    assert observation["not_proven_reason"] == "field_is_not_a_privilege"
    assert app.sent == []  # no account is created for a claim that cannot be proved
    values = {"check": "mass_assignment", "method": "POST", "path": "/users/v1/register", "parameter": field,
              "privilege_value": value, "json_body": {"username": "x", "password": "x"},
              "login_path": "/users/v1/login", "profile_path": "/users/v1/{username}"}
    refusal = admission_refusal(values, {"active_testing": True, "allow_state_changing_http": True,
                                         "allow_account_creation": True})
    # The refusal says what is accepted, so the planner can name the right field or move on.
    assert refusal and "administrator flag" in refusal and "role" in refusal and field in refusal


def test_the_privilege_vocabulary_matches_whole_field_names():
    from api.capabilities.registration_mass_assignment import privilege_kind, privilege_refusal
    for name, kind in {
        "admin": "administrator_flag", "is_admin": "administrator_flag", "isAdmin": "administrator_flag",
        "IsAdmin": "administrator_flag", "is_staff": "administrator_flag", "is_superuser": "administrator_flag",
        "superUser": "administrator_flag", "user_role": "role", "role": "role", "roles": "role",
        "roleId": "role", "permissions": "role", "scopes": "role", "email_verified": "account_gate",
        "isVerified": "account_gate", "approved": "account_gate", "is_active": "account_gate",
        "balance": "balance", "account_balance": "balance", "credits": "balance",
    }.items():
        assert privilege_kind(name) == kind, name
    for name in ("newsletter", "administration_area", "admin_notes", "role_description", "newsletter_active",
                 "roleplay", "scopes_seen", "unbalanced", "credit_card", "plan", "tier", "group", "verified_by",
                 "username", "", "is"):
        assert privilege_kind(name) is None, name
    # The value must claim the privilege: a flag is sent true, an amount positive, a role named.
    assert privilege_refusal("admin", "true") is None and privilege_refusal("admin", None) is None
    assert privilege_refusal("role", '"admin"') is None and privilege_refusal("balance", "1000") is None
    assert "must be true" in privilege_refusal("admin", "false")
    assert "positive" in privilege_refusal("balance", "0")
    assert "role name" in privilege_refusal("role", "true")


def test_a_stored_role_the_user_chose_is_verified():
    app = App(stores_admin=False, stores=("role",))
    observation = _prove(app, field="role", value='"admin"')
    assert observation["proof_state"] == "verified" and observation["privilege_kind"] == "role"
