"""The default-credential check against the worker harness's connection and a loopback login.

Harness of test_hunt_saved_login_worker (admission extracted from the router, the canonical HTTP
worker, a pinned loopback target). Labelled fixtures: the in-memory attempts ledger below stands in
for hunt_default_credential_attempts (its PostgreSQL behaviour is in
test_hunt_default_credentials_postgres), and the denied-login resolver answers by name only (no DNS).
The target is hostile: its answers try to look like other verdicts and echo what was sent.
(A full admission-plus-worker scenario on this harness does not finish yet; the worker path is
covered by the lab's live run, where a pair was sent by reference and the login answered 303.)
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
from tests.test_hunt_replay_worker_lifecycle import Connection as ReplayConnection
from tests.test_hunt_saved_login_worker import encrypted_vault, serving  # noqa: F401 - fixtures


@pytest.fixture(autouse=True)
def name_only_deny_list(monkeypatch):
    async def by_name(host, path, addresses=()):  # labelled double: no DNS for the deny list
        return secret_try.denied_destination(host, path, ())

    monkeypatch.setattr(secret_try, "denied_destination_resolved", by_name)
    import importlib
    try:  # the package layout imports the same module under its package name
        monkeypatch.setattr(importlib.import_module("api.hunt.secret_try"), "denied_destination_resolved", by_name)
    except ModuleNotFoundError:
        pass
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
            if "verdict='pending'" in sql:
                return 1 if any(row["action_id"] == str(args[1]) and row["pair_id"] == args[2]
                                and row["verdict"] == "pending" for row in self.attempts) else None
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


async def step(name, awaitable, seconds=60):
    """A step that must finish: a hang fails with the step's name instead of stalling the suite."""
    try:
        return await asyncio.wait_for(awaitable, seconds)
    except asyncio.TimeoutError:
        pytest.fail(f"step {name} did not finish in {seconds} s", pytrace=False)


def test_the_switch_stops_every_attempt_before_anything_is_sent(monkeypatch):
    async def scenario():
        wire = []
        server = await hostile_login(wire)
        async with serving(server):
            conn = AttemptsConnection(f"http://fixture.test:{server.sockets[0].getsockname()[1]}")
            monkeypatch.setenv("SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS", "false")
            with pytest.raises(HTTPException) as off:
                await step("off", dc.admit_default_credentials(conn, run=conn.run, values=api_attempt("dc-01"),
                                                   policy={"active_testing": True}, context=conn.run["context_pack"]))
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
