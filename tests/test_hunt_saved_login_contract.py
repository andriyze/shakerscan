"""Saved-login request shape, its write authority, and unreferenced withholding (no database)."""
from __future__ import annotations

import uuid

import pytest

from hunt.saved_logins import login_url, request_login_url, validate_login_request_shape
from runtime.archive_body_masking import WithheldValues, collecting_withheld_values, mask_body_text
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.hunt_http_contract import HttpAuthorityWithdrawn, require_http_request_authority
from runtime.hunt_http_exchange_contract import validate_exchange_input

PROFILE = str(uuid.UUID(int=5))
SECRET = "Fixture-Saved-Secret-77"


def login(**changes):
    values = {"method": "POST", "path": "/login", "form_body": {"u": "", "p": ""},
              "request_bindings": [
                  {"saved_login": PROFILE, "credential_field": "username", "body_pointer": "/u"},
                  {"saved_login": PROFILE, "credential_field": "secret", "body_pointer": "/p"}]}
    values.update(changes)
    return values


def test_a_saved_login_request_validates_and_needs_active_testing_but_not_state_changing():
    CAPABILITY_REGISTRY.validate_hunt_input("http.request", login())
    budget = {"http_requests": 1, "active_actions": 1, "agent_actions": 1}
    # Not charged as a state-changing write, and allowed without that permission.
    assert require_http_request_authority(login(), {"active_testing": True}, requested_budget=budget) is False
    with pytest.raises(HttpAuthorityWithdrawn):
        require_http_request_authority(login(), {"active_testing": False, "allow_state_changing_http": True})
    # The same POST without the saved login is an ordinary write and still needs the permission.
    plain = {"method": "POST", "path": "/login", "form_body": {"u": "x"}}
    with pytest.raises(HttpAuthorityWithdrawn):
        require_http_request_authority(plain, {"active_testing": True})


@pytest.mark.parametrize("binding", [
    {"saved_login": "not-a-profile", "credential_field": "secret", "body_pointer": "/p"},
    {"saved_login": PROFILE, "credential_field": "client_id", "body_pointer": "/p"},
    {"saved_login": PROFILE, "credential_field": "secret", "header": "X-Password"},
    {"saved_login": PROFILE, "credential_field": "secret", "body_pointer": "/p", "profile_version": 1},
])
def test_a_saved_login_binds_only_its_username_or_secret_into_the_body(binding):
    with pytest.raises(ValueError):
        validate_exchange_input({"method": "POST", "form_body": {"p": ""}, "request_bindings": [binding]})


@pytest.mark.parametrize("changes,message", [
    ({"method": "PUT"}, "POST"),
    ({"as_principal": "primary"}, "no other identity"),
    ({"session_ref": str(uuid.uuid4())}, "no other identity"),
    ({"request_bindings": [{"saved_login": PROFILE, "credential_field": "secret", "body_pointer": "/p"},
                           {"saved_login": str(uuid.UUID(int=6)), "credential_field": "secret", "body_pointer": "/u"}]},
     "one saved login"),
    ({"request_bindings": [{"saved_login": PROFILE, "credential_field": "secret", "body_pointer": "/p"},
                           {"secret_ref": f"secret://{uuid.uuid4()}", "body_pointer": "/u"}]}, "only its saved login"),
])
def test_a_login_request_carries_nothing_else(changes, message):
    with pytest.raises(ValueError) as refused:
        validate_login_request_shape(login(**changes))
    assert message in str(refused.value)


def test_login_urls_compare_scheme_host_port_and_path():
    assert login_url("https://Hub.Example.test/hub/login?next=/x#f") == "https://hub.example.test:443/hub/login"
    assert login_url("http://u:p@hub.example.test:8080/login") == "http://hub.example.test:8080/login"
    assert request_login_url({"path": "/hub/login?x=1"}, "https://hub.example.test") == "https://hub.example.test:443/hub/login"
    assert request_login_url({"path": "/hub/login", "origin": "http://hub.example.test"},
                             "https://hub.example.test") == "http://hub.example.test:80/hub/login"
    assert login_url("ftp://hub.example.test/login") is None


def test_an_unreferenced_value_is_masked_in_every_encoding_and_never_numbered():
    import base64
    import html
    import urllib.parse
    collector = WithheldValues(str(uuid.uuid4()))
    collector.bind_unreferenced([SECRET])
    # A later pass that finds or sends the same value cannot make it referenceable.
    collector.bind_known([SECRET], found=True)
    collector.bind_known([SECRET])
    page = (f"pw={SECRET} {SECRET.upper()} {urllib.parse.quote(SECRET)} {html.escape(SECRET)} "
            f"{base64.b64encode(SECRET.encode()).decode()} password: {SECRET}")
    with collecting_withheld_values(collector):
        masked = mask_body_text(page)
    assert SECRET.lower() not in masked.lower() and base64.b64encode(SECRET.encode()).decode() not in masked
    assert collector.values == [] and "[withheld:" not in masked


def test_a_login_request_is_built_from_the_forms_own_field_names_only():
    from hunt.saved_logins import login_request_for_form
    form = {"sign_in": True, "method": "POST", "action": "/account/session",
            "fields": [{"name": "csrf", "type": "hidden"}, {"name": "email", "type": "email"},
                       {"name": "pass", "type": "password"}]}
    request = login_request_for_form(form, PROFILE, "/account/login")
    assert request["path"] == "/account/session" and request["form_body"] == {"email": "", "pass": ""}
    assert [b["body_pointer"] for b in request["request_bindings"]] == ["/email", "/pass"]
    validate_login_request_shape(request)
    # A form posting off the origin, or without a password field, gets no suggestion.
    assert login_request_for_form({**form, "action": "https://evil.example/x"}, PROFILE, "/") is None
    assert login_request_for_form({"fields": [{"name": "q", "type": "text"}]}, PROFILE, "/") is None
