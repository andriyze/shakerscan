"""Scan/Hunt managed login and refresh must honor the response's login verdict."""
from __future__ import annotations

import asyncio
from functools import partial
import json

import pytest

from tests.test_authentication_challenge_completion import CLEARED, UNFINISHED
from capabilities.auth import TargetBoundSessionCredential, establish_target_bound_http_session
from capabilities.session_reuse import reuse_or_establish_session
from tests.test_auth_session_capability import TARGET, _private_response


TOKEN = "managed-login-private-token-canary"
SECRET = "managed-login-private-password-canary"
REFRESH_REF = "3198cda5-cf57-4124-8010-b0f90aa6a294"


def _login(document, *, phase, auth_kind="json_login", headers=None, cookies=None):
    calls = []

    async def request_executor(origin, args, **kwargs):
        calls.append(args)
        if args["method"] == "GET":
            response = _private_response(200, body=(
                '<form action="/login" method="post">'
                '<input name="username"><input type="password" name="password">'
                '</form>'
            ))
        else:
            response = _private_response(
                200, body=json.dumps(document),
                headers={"content-type": "application/json", **(headers or {})},
                cookies=cookies,
            )
        kwargs["private_response_sink"](response)
        return {"ok": True, "request": {"method": args["method"], "path": args["path"]}}

    credential = TargetBoundSessionCredential(
        lane="primary", auth_kind=auth_kind, endpoint_url="/login",
        binding_digest="a" * 64, username="operator@example.test", secret=SECRET,
        client_id="managed-client",
    )
    establish = partial(establish_target_bound_http_session, request_executor=request_executor)
    if phase == "initial":
        # Both Scan and Hunt start via this same reuse-or-establish path.
        session = asyncio.run(reuse_or_establish_session(
            None, credential, target=TARGET, establish=establish,
        ))
    else:
        # Refresh reuses the same exchange, passing the existing session reference.
        session = asyncio.run(establish(credential, target=TARGET, session_ref=REFRESH_REF))
    return session, calls


@pytest.mark.parametrize("phase", ["initial", "refresh"])
@pytest.mark.parametrize("auth_kind,document,headers,cookies", [
    ("json_login", {"access_token": TOKEN, "authenticated": False}, {}, {}),
    ("json_login", {"authentication": {"token": TOKEN, "requiresMfa": True}}, {}, {}),
    ("oauth_client_credentials", {"access_token": TOKEN, "error": "invalid_credentials"}, {}, {}),
    ("json_login", {"loginResult": {"authenticated": False, "requiresMfa": True}},
     {"authorization": "Bearer " + TOKEN}, {}),
    ("json_login", {"access_token": TOKEN, "challenge": {"type": "totp"}}, {}, {}),
    ("form_login", {"loginResult": {"status": "mfa_required"}}, {}, {"session": TOKEN}),
])
def test_failed_or_unfinished_login_has_no_session_identity(phase, auth_kind, document, headers, cookies):
    session, calls = _login(document, phase=phase, auth_kind=auth_kind, headers=headers, cookies=cookies)
    assert session.established is False
    assert session.headers() == {}
    assert session.session_ref is None
    assert len(calls) == (2 if auth_kind == "form_login" else 1)
    public = session.execution_result()
    assert public["ok"] is False
    assert public["status"] == "failed"
    assert public["observation"]["status"] == "failed"
    assert public["observation"]["cookie_names"] == []
    assert not public["observation"].get("session_ref")
    assert TOKEN not in json.dumps(public)
    assert SECRET not in json.dumps(public)
    assert TOKEN not in repr(session)


@pytest.mark.parametrize("document", UNFINISHED)
def test_managed_login_shares_the_canonical_unfinished_verdict(document):
    session, _calls = _login(document, phase="initial", headers={"authorization": "Bearer " + TOKEN})
    assert session.established is False
    assert session.headers() == {}
    assert session.session_ref is None


@pytest.mark.parametrize("phase", ["initial", "refresh"])
@pytest.mark.parametrize("nested_auth", [False, True])
def test_body_token_honors_an_unknown_wrappers_failed_login_verdict(phase, nested_auth):
    verdict = {"authenticated": False, "status": "failed"}
    if nested_auth:
        verdict["authentication"] = {"access_token": TOKEN}
    session, _calls = _login(
        {"access_token": TOKEN, "vendorReply": verdict}, phase=phase,
    )
    assert session.established is False
    assert session.headers() == {}
    assert session.session_ref is None
    assert TOKEN not in json.dumps(session.execution_result())


@pytest.mark.parametrize("phase", ["initial", "refresh"])
@pytest.mark.parametrize("key", ["access_token", "token", "jwt", "id_token", "authToken"])
@pytest.mark.parametrize("holder", [None, "authentication", "data", "result", "auth"])
def test_existing_managed_token_aliases_do_not_need_injection_proof(phase, key, holder):
    document = {key: TOKEN}
    if holder:
        document = {holder: document}
    session, calls = _login(document, phase=phase)
    assert session.established is True
    assert session.headers() == {"Authorization": "Bearer " + TOKEN}
    if phase == "refresh":
        assert session.session_ref == REFRESH_REF
    else:
        assert session.session_ref
    assert len(calls) == 1
    assert TOKEN not in json.dumps(session.execution_result())


@pytest.mark.parametrize("extra", CLEARED)
@pytest.mark.parametrize("identity", ["json", "header", "cookie"])
def test_completed_challenges_and_unrelated_metadata_keep_managed_login(extra, identity):
    session, _calls = _login(
        {**extra, **({"access_token": TOKEN} if identity == "json" else {})},
        phase="initial",
        headers={"authorization": "Bearer " + TOKEN} if identity == "header" else {},
        cookies={"session": TOKEN} if identity == "cookie" else {},
    )
    assert session.established is True
    assert session.session_ref
    assert session.headers() == (
        {"Cookie": "session=" + TOKEN} if identity == "cookie"
        else {"Authorization": "Bearer " + TOKEN}
    )
    assert TOKEN not in json.dumps(session.execution_result())


@pytest.mark.parametrize("identity", ["json", "header", "cookie"])
def test_login_preserves_unrelated_metadata_below_an_unknown_wrapper(identity):
    session, _calls = _login({
        **({"access_token": TOKEN} if identity == "json" else {}),
        "vendorReply": {"authenticated": True, "status": "success"},
        "user": {"email_verification": {"status": "pending"},
                 "verification": {"required": True}},
        "subscription": {"status": "failed", "error": "card declined"},
    }, phase="initial",
        headers={"authorization": "Bearer " + TOKEN} if identity == "header" else {},
        cookies={"session": TOKEN} if identity == "cookie" else {},
    )
    assert session.established is True
