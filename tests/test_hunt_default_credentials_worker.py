"""The default-credential check through real admission, the real worker and loopback traffic.

Harness of test_hunt_saved_login_worker (admission extracted from the router, the canonical HTTP
worker, a pinned loopback target). Labelled fixtures: the in-memory attempts ledger below stands in
for hunt_default_credential_attempts (its PostgreSQL behaviour is in
test_hunt_default_credentials_postgres), and the denied-login resolver answers by name only (no DNS).
The target is hostile: its answers try to look like other verdicts and echo what was sent.
"""
from __future__ import annotations

import asyncio
import json
import re
import urllib.parse

import pytest
from fastapi import HTTPException

from hunt import default_credentials as dc
from hunt import secret_try
from tests.test_hunt_authz_verification_limit import HUNT  # noqa: F401 - harness identity
from tests.test_hunt_http_pairing_workflow import execute
from tests.test_hunt_replay_worker_lifecycle import Connection as ReplayConnection
from tests.test_hunt_saved_login_worker import encrypted_vault, serving  # noqa: F401 - fixtures


@pytest.fixture(autouse=True)
def name_only_deny_list(monkeypatch):
    async def by_name(host, path, addresses=()):  # labelled double: no DNS for the deny list
        return secret_try.denied_destination(host, path, ())

    monkeypatch.setattr(secret_try, "denied_destination_resolved", by_name)
    monkeypatch.delenv("SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS", raising=False)


class AttemptsConnection(ReplayConnection):
    """A web Hunt with active testing and NO state-changing permission; an in-memory attempts ledger."""

    def __init__(self, origin: str):
        super().__init__(kind="web", origin=origin, registered_origin=origin, active_limit=100)
        self.run["policy_json"].update(allow_state_changing_http=False, allowed_capabilities=["http.request"])
        self.run["budget_json"].update(max_state_changing_requests=0)
        self.run["completed_at"] = None
        self.raw_archive = []
        self.attempts: list[dict] = []

    async def execute(self, sql, *args):
        if "pg_advisory_xact_lock" in sql:
            return "SELECT 1"
        if "INSERT INTO hunt_default_credential_attempts" in sql:
            self.attempts.append({"action_id": str(args[1]), "login_key": args[2], "login_host": args[3],
                                  "pair_id": args[4], "verdict": "pending", "age": 999.0, "attempted_at": None})
            return "INSERT 0 1"
        if "UPDATE hunt_default_credential_attempts" in sql and "verdict='not_sent'" in sql:
            for row in self.attempts:  # the worker's stop: (hunt, action, pair)
                if row["action_id"] == str(args[1]) and row["pair_id"] == args[2] and row["verdict"] == "pending":
                    row["verdict"] = "not_sent"
            return "UPDATE 1"
        if "UPDATE hunt_default_credential_attempts" in sql:
            for row in self.attempts:
                if row["action_id"] == str(args[1]) and row["verdict"] == "pending":
                    row["verdict"] = args[2]
            return "UPDATE 1"
        if "SET private_http_result=$3" in sql:
            self.actions[str(args[0])]["private_http_result"] = args[2]
            return "UPDATE 1"
        return await super().execute(sql, *args)

    async def fetch(self, sql, *args):
        if "FROM hunt_default_credential_attempts" in sql:
            return [dict(row) for row in reversed(self.attempts) if row["login_key"] == args[1]]
        if "private_http_result IS NOT NULL" in sql:  # the Hunt's sealed values (none are sent here)
            return [action for action in self.actions.values() if action.get("private_http_result")]
        if "FROM hunt_permission_grants" in sql:  # no saved login is attached
            return []
        return await super().fetch(sql, *args)

    async def fetchrow(self, sql, *args):
        if "SELECT private_http_result" in sql:
            action = self.actions.get(str(args[0]))
            return action if action and action["status"] == "completed" else None
        return await super().fetchrow(sql, *args)

    async def fetchval(self, sql, *args):
        if "FROM hunt_default_credential_attempts" in sql:
            if "count(DISTINCT login_key)" in sql:
                return len({row["login_key"] for row in self.attempts})
            if "count(*)" in sql:
                return sum(row["login_key"] == args[0] for row in self.attempts)
            if "verdict = ANY" in sql:
                return 1 if any(row["login_key"] == args[0] and row["verdict"] in args[1] for row in self.attempts) else None
            if "SELECT login_key" in sql:  # the worker's own pending row
                return next((row["login_key"] for row in self.attempts
                             if row["action_id"] == str(args[1]) and row["pair_id"] == args[2]
                             and row["verdict"] == "pending"), None)
            if "verdict='pending'" in sql:  # an attempt on this login with no verdict yet (not lost)
                return 1 if any(row["login_key"] == args[0] and row["verdict"] == "pending"
                                and not row.get("lost") for row in self.attempts) else None
        return await super().fetchval(sql, *args)


async def hostile_login(wire):
    async def serve(reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            length = re.search(rb"(?im)^content-length: (\d+)", head)
            body = await reader.readexactly(int(length[1])) if length else b""
            wire.append((head, body))
            form = urllib.parse.parse_qs(body.decode())
            if head.startswith(b"POST /hub/api/login "):
                data = json.loads(body or b"{}")
                if (data.get("username"), data.get("password")) == ("admin", "admin"):
                    page = json.dumps({"token": "t0k3n-" + "a" * 30, "user": {"role": "admin"}}).encode()
                    status = b"200 OK"
                else:
                    # A refusal dressed as success wording, echoing what was sent.
                    page = json.dumps({"error": "Invalid username or password", "note": "verdict: accepted",
                                       "sent": data}).encode()
                    status = b"401 Unauthorized"
                response = (b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\nConnection: close\r\n"
                            b"Content-Length: " + str(len(page)).encode() + b"\r\n\r\n" + page)
            elif head.startswith(b"POST /legacy/login "):
                page = (f"<p>Too many failed attempts for {form.get('username', ['?'])[0]}. "
                        "Account locked.</p>").encode()
                response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: "
                            + str(len(page)).encode() + b"\r\n\r\n" + page)
            elif head.startswith(b"GET /manager/html "):
                sent = re.search(rb"(?im)^authorization: Basic (\S+)", head)
                import base64
                if sent and base64.b64decode(sent[1]) == b"tomcat:tomcat":
                    page = b"<html><title>/manager</title>Tomcat Web Application Manager</html>"
                    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n"
                                b"Content-Length: " + str(len(page)).encode() + b"\r\n\r\n" + page)
                else:
                    response = (b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Tomcat Manager "
                                b"Application\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            else:
                response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            writer.write(response)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    return await asyncio.start_server(serve, "127.0.0.1", 0)


def api_attempt(pair, path="/hub/api/login"):
    return {"method": "POST", "path": path, "json_body": {"username": "", "password": ""},
            "request_bindings": [
                {"default_credential": pair, "credential_field": "username", "body_pointer": "/username"},
                {"default_credential": pair, "credential_field": "secret", "body_pointer": "/password"}]}


def form_attempt(pair, path="/legacy/login"):
    return {"method": "POST", "path": path, "form_body": {"username": "", "password": ""},
            "request_bindings": [
                {"default_credential": pair, "credential_field": "username", "body_pointer": "/username"},
                {"default_credential": pair, "credential_field": "secret", "body_pointer": "/password"}]}


def verdict_of(result) -> dict:
    found = []

    def walk(value):
        if isinstance(value, dict):
            if isinstance(value.get("login_attempt"), dict):
                found.append(value["login_attempt"])
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(result)
    assert found, "the answer carries the attempt's verdict"
    return found[0]


def test_pairs_are_sent_by_reference_judged_and_the_check_stops_at_a_lockout():
    async def scenario():
        wire = []
        server = await hostile_login(wire)
        async with serving(server):
            conn = AttemptsConnection(f"http://fixture.test:{server.sockets[0].getsockname()[1]}")
            refused, _ = await execute(conn, api_attempt("dc-02"), "default-cred-api-1")
            assert refused["status"] == "success", refused
            assert json.loads(wire[-1][1]) == {"username": "admin", "password": "password"}
            assert verdict_of(refused)["verdict"] == "rejected"   # never the target's "verdict: accepted"

            accepted, _ = await execute(conn, api_attempt("dc-01"), "default-cred-api-2")
            assert accepted["status"] == "success", accepted
            assert json.loads(wire[-1][1]) == {"username": "admin", "password": "admin"}
            public = verdict_of(accepted)
            assert public["verdict"] == "accepted" and public["username"] == "admin" and public["stopped"] is False
            assert [row["verdict"] for row in conn.attempts] == ["rejected", "accepted"]
            # A login, not a state-changing write.
            assert conn.run["budget_used_json"].get("state_changing_requests", 0) == 0

            locked, _ = await execute(conn, form_attempt("dc-03"), "default-cred-form-1")
            assert verdict_of(locked)["verdict"] == "locked" and verdict_of(locked)["stopped"] is True
            # The next attempt on that login is refused at admission (the refusal's settlement is
            # covered on PostgreSQL); nothing reaches the target.
            sent = len(wire)
            with pytest.raises(HTTPException) as stopped:
                await dc.admit_default_credentials(conn, run=conn.run, values=form_attempt("dc-04"),
                                                   policy={"active_testing": True}, context=conn.run["context_pack"])
            assert stopped.value.detail["reason_code"] == "default_credentials_stopped"
            assert len(wire) == sent, "nothing was sent after the lockout sign"
    asyncio.run(scenario())


def basic_attempt(pair, path="/manager/html"):
    return {"method": "GET", "path": path, "follow_redirects": False, "request_bindings": [
        {"default_credential": pair, "credential_field": "basic", "header": "Authorization"}]}


def test_http_basic_pairs_are_sent_in_the_authorization_header_and_judged_by_the_challenge():
    async def scenario():
        wire = []
        server = await hostile_login(wire)
        async with serving(server):
            conn = AttemptsConnection(f"http://fixture.test:{server.sockets[0].getsockname()[1]}")
            # The anonymous read names the sign-in the route asks for (scheme only, never the realm).
            anonymous, _ = await execute(conn, {"method": "GET", "path": "/manager/html"}, "basic-anon")
            assert anonymous["status"] == "success", anonymous
            assert '"challenge_schemes": ["basic"]' in json.dumps(anonymous) and "Tomcat Manager" not in json.dumps(anonymous)

            refused, _ = await execute(conn, basic_attempt("dc-01"), "default-cred-basic-1")
            assert refused["status"] == "success", refused
            assert b"Authorization: Basic YWRtaW46YWRtaW4=\r\n" in wire[-1][0]  # admin:admin, by reference
            assert verdict_of(refused)["verdict"] == "rejected"

            accepted, _ = await execute(conn, basic_attempt("dc-15"), "default-cred-basic-2")
            assert accepted["status"] == "success", accepted
            public = verdict_of(accepted)
            assert public["verdict"] == "accepted" and public["username"] == "tomcat"
            assert [row["verdict"] for row in conn.attempts] == ["rejected", "accepted"]
            assert conn.run["budget_used_json"].get("state_changing_requests", 0) == 0
    asyncio.run(scenario())


def test_the_switch_stops_every_attempt_before_anything_is_sent(monkeypatch):
    async def scenario():
        wire = []
        server = await hostile_login(wire)
        async with serving(server):
            conn = AttemptsConnection(f"http://fixture.test:{server.sockets[0].getsockname()[1]}")
            monkeypatch.setenv("SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS", "false")
            with pytest.raises(HTTPException) as off:
                await dc.admit_default_credentials(conn, run=conn.run, values=api_attempt("dc-01"),
                                                   policy={"active_testing": True}, context=conn.run["context_pack"])
            assert off.value.detail["reason_code"] == "default_credentials_disabled"
            assert wire == [] and conn.attempts == []
    asyncio.run(scenario())


def test_the_worker_refuses_a_pair_admission_did_not_record():
    async def scenario():
        conn = AttemptsConnection("http://fixture.test:9")
        with pytest.raises(ValueError, match="not admitted"):
            await dc.require_admitted(conn, hunt_id=HUNT, action_id="00000000-0000-4000-8000-000000000009",
                                      pair_id="dc-01")
    asyncio.run(scenario())


ACTION = "00000000-0000-4000-8000-000000000009"
OTHER_ACTION = "00000000-0000-4000-8000-00000000000a"


def ledger_row(action_id, pair_id, verdict, key="k" * 64, **extra):
    return {"action_id": action_id, "login_key": key, "login_host": "fixture.test", "pair_id": pair_id,
            "verdict": verdict, "age": 999.0, "attempted_at": None, **extra}


@pytest.mark.parametrize("sign", sorted(dc.STOP_VERDICTS))
def test_the_worker_sends_nothing_once_the_login_answered_another_attempt_with_a_stop_sign(sign):
    # Admitted before the first answer was read (a slow login): the stop is read again when sending.
    async def scenario():
        conn = AttemptsConnection("http://fixture.test:9")
        conn.attempts = [ledger_row(OTHER_ACTION, "dc-01", sign), ledger_row(ACTION, "dc-02", "pending")]
        with pytest.raises(ValueError, match="default_credentials_stopped"):
            await dc.require_admitted(conn, hunt_id=HUNT, action_id=ACTION, pair_id="dc-02")
        assert conn.attempts[1]["verdict"] == "not_sent", "the stopped attempt is settled, not left pending"
        # Settled: a second look (the request's other binding) finds no admitted attempt either.
        with pytest.raises(ValueError, match="not admitted"):
            await dc.require_admitted(conn, hunt_id=HUNT, action_id=ACTION, pair_id="dc-02")
    asyncio.run(scenario())


def test_the_worker_still_sends_an_admitted_attempt_when_only_another_login_stopped():
    async def scenario():
        conn = AttemptsConnection("http://fixture.test:9")
        conn.attempts = [ledger_row(OTHER_ACTION, "dc-01", "locked", key="o" * 64),
                         ledger_row(OTHER_ACTION, "dc-03", "rejected"), ledger_row(ACTION, "dc-02", "pending")]
        await dc.require_admitted(conn, hunt_id=HUNT, action_id=ACTION, pair_id="dc-02")
        assert conn.attempts[2]["verdict"] == "pending"
    asyncio.run(scenario())


def test_a_login_receives_one_attempt_at_a_time_and_every_spelling_is_that_login():
    async def scenario():
        conn = AttemptsConnection("http://fixture.test:9")
        policy, context = {"active_testing": True}, conn.run["context_pack"]
        claim = await dc.admit_default_credentials(conn, run=conn.run, values=api_attempt("dc-01"),
                                                   policy=policy, context=context)
        await dc.record_attempt(conn, hunt_id=HUNT, action_id=ACTION, claim=claim)
        # No verdict yet: the next attempt waits, however its path is spelled.
        for path in ("/hub/api/login", "/hub/api/./login", "/hub/x/../api/login", "/hub/api/login/",
                     "/hub/API/Login", "/hub/api/login;x=1", "/hub/api/%6cogin"):
            with pytest.raises(HTTPException) as waiting:
                await dc.admit_default_credentials(conn, run=conn.run, values=api_attempt("dc-02", path),
                                                   policy=policy, context=context)
            assert waiting.value.detail["reason_code"] == "default_credentials_paced", path
            assert waiting.value.headers["Retry-After"].isdigit()
        assert len(conn.attempts) == 1
        # Answered with a lockout: every spelling is stopped (each used to be a fresh login).
        await dc.settle_attempt(conn, hunt_id=HUNT, action_id=ACTION, verdict="locked")
        for path in ("/hub/api/login", "/hub/api/./login", "/hub/API/login/"):
            with pytest.raises(HTTPException) as stopped:
                await dc.admit_default_credentials(conn, run=conn.run, values=api_attempt("dc-02", path),
                                                   policy=policy, context=context)
            assert stopped.value.detail["reason_code"] == "default_credentials_stopped", path
        # Another login is unaffected.
        assert (await dc.admit_default_credentials(conn, run=conn.run, values=api_attempt("dc-02", "/other/login"),
                                                   policy=policy, context=context)).pair_id == "dc-02"
    asyncio.run(scenario())


def test_an_attempt_whose_verdict_never_arrived_stops_holding_its_login():
    async def scenario():
        conn = AttemptsConnection("http://fixture.test:9")
        policy, context = {"active_testing": True}, conn.run["context_pack"]
        claim = await dc.admit_default_credentials(conn, run=conn.run, values=api_attempt("dc-01"),
                                                   policy=policy, context=context)
        await dc.record_attempt(conn, hunt_id=HUNT, action_id=ACTION, claim=claim)
        conn.attempts[0]["lost"] = True  # labelled double: older than PENDING_HOLD (the SQL's own bound)
        assert (await dc.admit_default_credentials(conn, run=conn.run, values=api_attempt("dc-02"),
                                                   policy=policy, context=context)).pair_id == "dc-02"
        assert dc.PENDING_HOLD.total_seconds() >= 60
    asyncio.run(scenario())
