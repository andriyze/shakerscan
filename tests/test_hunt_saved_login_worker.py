"""A saved login by reference through the real admission and worker, against a hostile target.

The unchanged production admission and ``process_canonical_http_capability_job`` run over the
in-memory store doubles of test_hunt_http_pairing_workflow (labelled: database and Redis I/O);
the credential resolver, the vault encryption, the HTTP transport (pinned loopback) and every
masking pass are real. The target is a fixture that echoes the saved login's secret back in
every encoding it can: in the login's answer (redirect, header, body) and on later signed-in
pages, so the tests show the secret never reaches the planner's answer, the receipts, the Hunt
record, a withheld reference or a scanner's observations. Values are synthetic.
"""
from __future__ import annotations

import asyncio
import base64
from copy import deepcopy
from datetime import datetime, timezone
import html
import json
import re
import urllib.parse
import uuid

import pytest

import secret_store
from runtime.credentials import build_credential_secret, parse_credential_secret, public_credential_configuration
from runtime.hunt_http_exchange import (
    KNOWN_VALUES_KEY, WITHHELD_SCHEMA_KEY, saved_login_known_values, sealed_hunt_knowledge,
)
from runtime.public_secrecy import PublicSecrecy
from tests.test_hunt_authz_verification_limit import HUNT, TARGET
from tests.test_hunt_http_pairing_workflow import admit, execute, worker  # noqa: F401 - harness
from tests.test_hunt_replay_worker_lifecycle import Connection as ReplayConnection

# "~" and "|" are in no hex, UUID or base64url alphabet: a match is always a real leak.
SECRET = "Sv3n~Login|Pass<42>&\"q"
USERNAME = "fixture-hub-operator"
SESSION = "hubsession0123456789abcdefABCDEF"
PROFILE_ID = uuid.UUID(int=77)
GRANT_ID = uuid.UUID(int=78)


@pytest.fixture(autouse=True)
def encrypted_vault(monkeypatch, tmp_path):
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.delenv("AI_CREDENTIAL_ENC_KEY", raising=False)
    monkeypatch.setattr(secret_store, "_loaded", False)
    monkeypatch.setattr(secret_store, "_fernet", None)


def encodings(value: str) -> set[str]:
    """Every spelling of ``value`` a hostile target uses below, and that a leak would take."""
    raw = value.encode()
    return {
        value, value.lower(), value.upper(), urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value),
        html.escape(value), "".join(f"&#x{ord(char):x};" for char in value), json.dumps(value)[1:-1],
        base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode().rstrip("="),
        raw.hex(),
    }


def assert_no_secret(text: str, where: str) -> None:
    for form in encodings(SECRET) - {SECRET.encode().hex()}:  # hex is not an echo the target makes
        assert form not in text, f"{where} carries the saved login's secret ({form[:4]}...)"


def hostile_page(extra: str = "") -> bytes:
    raw = SECRET.encode()
    return ("<html><body><h1>Orders</h1><p>Order 1001 shipped</p>"
            f"<p>Your password is {SECRET}</p><p>{html.escape(SECRET)}</p>"
            f"<a href='/hub/x?p={urllib.parse.quote(SECRET, safe='')}'>x</a>"
            f"<script>var p = \"{json.dumps(SECRET)[1:-1]}\"; var b = '{base64.b64encode(raw).decode()}';</script>"
            f"<p>{SECRET.upper()}</p><input type=password value='{SECRET}'>"
            f"<p>signed in as {USERNAME}</p>{extra}</body></html>").encode()


class LoginConnection(ReplayConnection):
    """A web Hunt with active testing and NO state-changing permission, one saved login attached."""

    def __init__(self, origin: str):
        super().__init__(kind="web", origin=origin, registered_origin=origin, active_limit=100)
        self.run["policy_json"].update(allow_state_changing_http=False, allowed_capabilities=["http.request"])
        self.run["budget_json"].update(max_state_changing_requests=0)
        self.run["completed_at"] = None
        self.raw_archive = []
        self.revoked = False
        self.grant_live = True
        self.login_url = f"{origin}/hub/login"
        now = datetime.now(timezone.utc)
        secret = build_credential_secret("form_login", secret=SECRET, username=USERNAME, endpoint_url=self.login_url)
        self.profile = {
            "id": PROFILE_ID, "target_id": TARGET, "target_kind": "web", "name": "hub operator",
            "auth_kind": "form_login", "principal_slot": "primary", "principal_label": "Hub operator",
            "configuration_json": public_credential_configuration(parse_credential_secret("form_login", secret)),
            "current_version": 1, "record_version": 1, "is_active": True, "expires_at": None,
            "rotated_at": now, "created_at": now, "updated_at": now, "allowed_capabilities": ["http.request"],
            "encrypted_secret": secret_store.encrypt_secret(secret),
            "encrypted_metadata": secret_store.encrypt_secret(json.dumps({"schema_version": "credential-private-metadata/v1"})),
            "home_target_id": TARGET,
        }

    def grants(self):
        if not self.grant_live:
            return []
        return [{"id": GRANT_ID, "preauthorization_id": None, "created_by": "alice@example.test",
                 "created_at": datetime.now(timezone.utc),
                 "subject_json": json.dumps({"profile_id": str(PROFILE_ID), "profile_version": 1,
                                             "auth_kind": "form_login", "consuming_target_id": str(TARGET)}),
                 "effect_json": json.dumps({"profile_id": str(PROFILE_ID), "profile_version": 1,
                                            "login_url": _login_url(self.login_url), "max_logins": 2})}]

    async def fetchrow(self, sql, *args):
        if "FROM credential_profiles p" in sql and "credential_profile_versions" in sql:
            # The worker's target-bound lookup (load_for_worker).
            if args != (PROFILE_ID, "web", str(TARGET)) or not self.profile["is_active"]:
                return None
            return dict(self.profile)
        if "FROM credential_profiles p" in sql and "p.id=$1" in sql:
            # The saved login attached to the consuming target (saved_logins.attached_profile).
            return dict(self.profile) if args[0] == PROFILE_ID and args[1] == str(TARGET) else None
        if "SELECT private_http_result" in sql:
            action = self.actions.get(str(args[0]))
            return action if args[1] == HUNT and action and action["status"] == "completed" else None
        if "FROM approval_receipts" in sql:
            row = await super().fetchrow(sql, *args)
            row.update(target_id=TARGET, verdict="allowed", status="revoked" if self.revoked else "active",
                       revoked_at=None)
            return row
        return await super().fetchrow(sql, *args)

    async def fetch(self, sql, *args):
        if "FROM hunt_permission_grants" in sql:
            assert args[1] == "login.use"
            return [grant for grant in self.grants()
                    if args[2] is None or json.loads(grant["subject_json"])["profile_id"] == args[2]]
        if "private_http_result IS NOT NULL" in sql:
            return [action for action in self.actions.values() if action.get("private_http_result")]
        return await super().fetch(sql, *args)

    async def fetchval(self, sql, *args):
        if "FROM hunt_credential_uses" in sql:
            return sum(1 for use in self.credential_uses if use[2] == args[1] and use[5] == args[2])
        raise AssertionError(sql)

    async def execute(self, sql, *args):
        if "SET private_http_result=$3" in sql:
            self.actions[str(args[0])]["private_http_result"] = args[2]
            return "UPDATE 1"
        return await super().execute(sql, *args)


def _login_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.hostname}:{parts.port}{parts.path}"


async def hostile_target(wire):
    async def serve(reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            length = re.search(rb"(?im)^content-length: (\d+)", head)
            body = await reader.readexactly(int(length[1])) if length else b""
            wire.append((head, body))
            raw = SECRET.encode()
            if head.startswith(b"POST /hub/echo-login "):
                # A login answer that hands the password back in a header and a JSON body.
                page = json.dumps({"ok": True, "password": SECRET}).encode()
                response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Pass: "
                            + base64.b64encode(raw) + b"\r\nConnection: close\r\nContent-Length: "
                            + str(len(page)).encode() + b"\r\n\r\n" + page)
            elif head.startswith(b"POST /hub/login "):
                form = urllib.parse.parse_qs(body.decode())
                ok = form == {"username": [USERNAME], "password": [SECRET]}
                location = "/hub/?welcome=" + urllib.parse.quote(SECRET, safe="")
                page = f"<p>Welcome {USERNAME}, your password {SECRET} / {base64.b64encode(raw).decode()}</p>".encode()
                response = ((b"HTTP/1.1 303 See Other\r\n" if ok else b"HTTP/1.1 401 Unauthorized\r\n")
                            + f"Location: {location}\r\nX-Debug: {base64.b64encode(raw).decode()}\r\n".encode()
                            + (f"Set-Cookie: hub_session={SESSION}; Path=/hub; HttpOnly\r\n".encode() if ok else b"")
                            + b"Content-Type: text/html\r\nConnection: close\r\nContent-Length: "
                            + str(len(page)).encode() + b"\r\n\r\n" + page)
            elif f"hub_session={SESSION}".encode() in head:
                page = hostile_page()
                response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Echo: "
                            + urllib.parse.quote(SECRET, safe="").encode()
                            + b"\r\nConnection: close\r\nContent-Length: " + str(len(page)).encode() + b"\r\n\r\n" + page)
            else:
                response = b"HTTP/1.1 303 See Other\r\nLocation: /hub/login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            writer.write(response)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    return await asyncio.start_server(serve, "127.0.0.1", 0)


def login_input(path="/hub/login"):
    return {"method": "POST", "path": path, "form_body": {"username": "", "password": ""},
            "request_bindings": [
                {"saved_login": str(PROFILE_ID), "credential_field": "username", "body_pointer": "/username"},
                {"saved_login": str(PROFILE_ID), "credential_field": "secret", "body_pointer": "/password"}],
            "capture": [{"name": "session", "header": "Set-Cookie"}]}


def test_a_saved_login_signs_in_by_reference_and_its_secret_never_reaches_the_planner_or_records():
    async def scenario():
        wire = []
        server = await hostile_target(wire)
        async with server:
            conn = LoginConnection(f"http://fixture.test:{server.sockets[0].getsockname()[1]}")
            login, _ = await execute(conn, login_input(), "saved-login-1")
            assert login["status"] == "success", login
            head, body = wire[0]
            # The worker sent the saved values, only in the login's own POST.
            assert head.startswith(b"POST /hub/login ") and urllib.parse.parse_qs(body.decode()) == {
                "username": [USERNAME], "password": [SECRET]}
            # The login answer is its status and cookie names; the session is a reference.
            [capture] = login["captures"]
            assert capture["header"] == "Cookie" and capture["capture_name"] == "session"
            # No state-changing permission was needed and none was charged; one login was counted.
            assert conn.run["budget_used_json"].get("state_changing_requests", 0) == 0
            assert [use[5] for use in conn.credential_uses] == ["login"]

            # The login's own records never hold the username either (the target may show it
            # on a signed-in page: an account name is not a secret there).
            assert USERNAME not in json.dumps([login, conn.actions], default=str)
            orders, _ = await execute(conn, {"method": "GET", "path": "/hub/orders",
                                             "request_bindings": [{**capture}]}, "signed-in-orders")
            assert orders["status"] == "success", orders
            assert len(wire) == 2 and f"hub_session={SESSION}".encode() in wire[1][0]
            public = json.dumps(orders)
            assert "Order 1001" in public, "the signed-in page itself reaches the planner"
            for where, value in (("login answer", login), ("signed-in answer", orders), ("Hunt actions", conn.actions),
                                 ("job result", conn.result), ("run", conn.run)):
                text = json.dumps(value, default=str)
                assert_no_secret(text, where)
                assert SESSION not in text, f"{where} carries the session cookie"
            # The secret was sealed for the rest of the Hunt as an unreferenced known value: never
            # under a withheld:// reference, never in clear.
            for action in conn.actions.values():
                ciphertext = action.get("private_http_result") or ""
                assert SECRET not in ciphertext
                if ciphertext:
                    private = json.loads(secret_store.decrypt_secret(ciphertext))
                    assert SECRET not in json.dumps(private.get(WITHHELD_SCHEMA_KEY) or {})
            sealed = [json.loads(secret_store.decrypt_secret(a["private_http_result"]))
                      for a in conn.actions.values() if a.get("private_http_result")]
            assert any(SECRET in (item.get(KNOWN_VALUES_KEY) or ()) for item in sealed)
            assert "withheld://" not in json.dumps(orders.get("typed_output", {}).get("withheld_values") or [])
            # The raw request body exists only in the private archive, marked so every public view
            # omits it (the harness keeps the recorder's captured calls).
            login_rows = [row for row in conn.raw_archive if row.get("method") == "POST"]
            assert login_rows and all(row.get("workflow_values_private") is True for row in login_rows)

            # A scanner action's secrecy boundary is given the same value.
            async with conn.acquire() as reader:
                knowledge = await sealed_hunt_knowledge(reader, run_id=HUNT, target=_target(conn))
            assert SECRET in knowledge["unreferenced"] and SECRET not in knowledge["values"]
            extra = await saved_login_known_values(conn, HUNT, _target(conn))
            scrubbed = PublicSecrecy.for_headers({"Cookie": f"hub_session={SESSION}"}, extra).observations([
                {"kind": "nuclei", "matched": hostile_page().decode(), "extracted_results": [SECRET.upper()],
                 "evidence": base64.b64encode(SECRET.encode()).decode()}])
            assert_no_secret(json.dumps(scrubbed), "scanner observations")
    asyncio.run(scenario())


def _target(conn):
    from hunt.target_binding import web_hunt_target
    policy = conn.run["policy_json"]
    return web_hunt_target(conn.run, conn.run["context_pack"], policy)[0]


@pytest.mark.parametrize("problem", ["other-path", "revoked-grant", "rotated", "revoked-approval", "second-profile-binding"])
def test_a_saved_login_is_never_sent_anywhere_else_or_after_its_authority_changed(problem):
    async def scenario():
        from fastapi import HTTPException
        wire = []
        server = await hostile_target(wire)
        async with server:
            conn = LoginConnection(f"http://fixture.test:{server.sockets[0].getsockname()[1]}")
            values = login_input()
            if problem == "other-path":
                with pytest.raises(HTTPException) as refused:
                    await admit(conn, login_input(path="/hub/profile"), "elsewhere")
                assert refused.value.detail["reason_code"] == "saved_login_destination"
                assert not wire and not conn.credential_uses
                return
            if problem == "second-profile-binding":
                values["request_bindings"].append({"profile_id": str(uuid.UUID(int=79)), "profile_version": 1,
                                                   "credential_field": "secret", "body_pointer": "/other"})
                values["form_body"]["other"] = ""
                with pytest.raises(HTTPException) as refused:
                    await admit(conn, values, "two-credentials")
                assert refused.value.detail["reason_code"] == "saved_login_invalid"
                assert not wire
                return
            admitted = await admit(conn, values, "changed-after-admission")
            if problem == "revoked-grant":
                conn.grant_live = False
            elif problem == "rotated":
                conn.profile["current_version"] = 2
            elif problem == "revoked-approval":
                conn.revoked = True
            stored = next(row for row in conn.store.rows.values() if row.action_id == admitted["action_id"])
            job = {"job_id": str(uuid.uuid4()), "hunt_id": str(HUNT), "action_id": admitted["action_id"],
                   "budget_reservation_id": stored.record.reservation_id, "action_digest": stored.action_digest,
                   "capability_name": "http.request", "capability_input": values,
                   "expected_budget": dict(stored.record.requested)}
            await worker(conn)(job)
            result = deepcopy(conn.result)
            assert result["status"] in {"failed", "blocked"}, result
            assert not wire, "nothing was sent"
            assert_no_secret(json.dumps(result, default=str), "refused result")
    asyncio.run(scenario())


def test_a_capture_that_carries_the_secret_is_never_kept_so_it_cannot_be_sent_on():
    async def scenario():
        wire = []
        server = await hostile_target(wire)
        async with server:
            conn = LoginConnection(f"http://fixture.test:{server.sockets[0].getsockname()[1]}")
            conn.login_url = conn.login_url.replace("/hub/login", "/hub/echo-login")
            conn.profile["encrypted_secret"] = secret_store.encrypt_secret(build_credential_secret(
                "form_login", secret=SECRET, username=USERNAME, endpoint_url=conn.login_url))
            values = login_input(path="/hub/echo-login")
            values["capture"] = [{"name": "pass_header", "header": "X-Pass"},
                                 {"name": "pass_json", "json_pointer": "/password"},
                                 {"name": "ok", "json_pointer": "/ok"}]
            result, _ = await execute(conn, values, "echo-login")
            assert result["status"] == "success", result
            # Only the capture without the secret is a reference; the others are reported missing.
            assert [item["capture_name"] for item in result["captures"]] == ["ok"]
            assert sorted(result["typed_output"]["records"][0]["response"]["captures_missing"]) == ["pass_header", "pass_json"]
            for action in conn.actions.values():
                if action.get("private_http_result"):
                    private = json.loads(secret_store.decrypt_secret(action["private_http_result"]))
                    assert SECRET not in json.dumps(private.get("values") or {})
                    assert base64.b64encode(SECRET.encode()).decode() not in json.dumps(private.get("values") or {})
            assert_no_secret(json.dumps(result, default=str), "echo-login answer")
    asyncio.run(scenario())


def test_the_worker_refuses_a_login_request_for_another_url_even_with_a_live_grant():
    """Defence in depth: admission refuses another URL first; the worker checks again after
    decryption, against the profile's own endpoint, before any value is placed in a request."""
    from runtime.hunt_http_exchange import prepare_http_exchange

    async def scenario():
        conn = LoginConnection("http://fixture.test:7345")
        target = _target(conn)
        for path in ("/hub/other", "/hub/login/../admin"):
            with pytest.raises(ValueError, match="saved_login_destination"):
                await prepare_http_exchange(
                    conn, run=conn.run, action_id=uuid.uuid4(), target=target, context=conn.run["context_pack"],
                    policy=conn.run["policy_json"], values=login_input(path=path), trusted_headers={},
                    destination="http://fixture.test:7345")
        inputs, _headers, exchange = await prepare_http_exchange(
            conn, run=conn.run, action_id=uuid.uuid4(), target=target, context=conn.run["context_pack"],
            policy=conn.run["policy_json"], values=login_input(), trusted_headers={},
            destination="http://fixture.test:7345")
        assert inputs["form_body"] == {"username": USERNAME, "password": SECRET}
        assert exchange.opaque_binding and exchange.known_secrets == [SECRET]
        assert SECRET not in repr(exchange)
    asyncio.run(scenario())
