"""authz.verify planted_object: another user reads a private value one principal planted (VAmPI, 2026-11).

Driven by hand on VAmPI: user B read user A's book secret (GET /books/v1/<title>), but the object
mode skipped every book because B's own listing (/books/v1) shows all books.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from uuid import UUID

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from capabilities.authz_planted import verify_planted_object  # noqa: E402
from hunt import authz_planted  # noqa: E402

SECRET = "pl4nted-Secret-7f3a9c"
A = {"Authorization": "Bearer token-of-user-a"}
B = {"Authorization": "Bearer token-of-user-b"}


def test_the_planted_field_value_and_creator_come_from_the_create_request():
    assert authz_planted.private_field("secret") and authz_planted.private_field("private_note")
    assert not authz_planted.private_field("book_title") and not authz_planted.private_field("title")
    assert authz_planted.distinctive(SECRET) and not authz_planted.distinctive("password")
    assert not authz_planted.distinctive("123456789012345")
    body = json.dumps({"book_title": "t1", "secret": SECRET}).encode()
    assert authz_planted._body_value(body, "application/json", "secret") == SECRET
    assert authz_planted._body_value(b"secret=" + SECRET.encode() + b"&x=1", "application/x-www-form-urlencoded",
                                     "secret") == SECRET
    values = {"primary_bindings": [{"source_action_id": "login-a"}],
              "secondary_bindings": [{"source_action_id": "login-b"}]}
    assert authz_planted.creator_slot({"request_bindings": [{"source_action_id": "login-b"}]}, values) == "secondary"
    assert authz_planted.creator_slot({"request_bindings": [{"source_action_id": "login-c"}]}, values) is None
    assert authz_planted.creator_slot({"as_principal": "primary"}, {"primary_principal": "primary"}) == "primary"
    assert authz_planted.creator_slot({"as_principal": "primary"}, values) is None  # not this proof's principals


def _app(*, owner_check=False, listing_shows_secret=False, anonymous_reads=False):
    async def app(reader, writer):
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            chunk = await reader.read(1)
            if not chunk:
                break
            head += chunk
        text = head.decode()
        path = text.split(" ", 2)[1]
        who = "a" if "user-a" in text else "b" if "user-b" in text else None
        if who is None and not anonymous_reads:
            status, body = 401, {"error": "token missing"}
        elif path == "/books/v1":
            row = {"book_title": "t1", "user": "a", **({"secret": SECRET} if listing_shows_secret else {})}
            status, body = 200, {"Books": [row, {"book_title": "t2", "user": "b"}]}
        elif path == "/books/v1/t1":
            if owner_check and who != "a":
                status, body = 404, {"error": "not found"}
            else:
                status, body = 200, {"book_title": "t1", "owner": "a", "secret": SECRET}
        else:
            status, body = 404, {}
        data = json.dumps(body).encode()
        writer.write(b"HTTP/1.1 %d X\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                     % (status, len(data)) + data)
        await writer.drain()
        writer.close()
    return app


def _prove(**app_options):
    from runtime.models import TargetBinding

    async def scenario():
        try:
            server = await asyncio.start_server(_app(**app_options), "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("the unit-test sandbox forbids loopback listeners")
        base = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        target = TargetBinding(target_id=str(UUID(int=2)), target_kind="web", canonical_host="127.0.0.1",
                               allowed_origins=(base,), allowed_addresses=("127.0.0.1",),
                               allowed_root_domains=("127.0.0.1",), environment="lab", scope_receipt_id=str(UUID(int=3)))
        result = await verify_planted_object(
            base, [f"{base}/books/v1/t1", f"{base}/books/v1"], target=target, primary_headers=A,
            secondary_headers=B, creator="primary", planted_field="secret", planted_value=SECRET)
        server.close()
        await server.wait_closed()
        return result

    return asyncio.run(scenario())


def test_another_user_reading_a_planted_private_value_is_verified():
    result = _prove()
    observation = result["observation"]
    assert observation["proof_state"] == "verified", observation
    assert observation["proof_type"] == "planted_private_field_cross_read"
    assert observation["creator_principal"] == "primary" and observation["reader_principal"] == "secondary"
    assert SECRET not in json.dumps(result)
    assert result["budget_consumed"]["http_requests"] == 5

    from scan.finalizer import canonical_authz_findings
    findings = canonical_authz_findings([observation], receipt={"receipt_id": "r"})
    assert len(findings) == 1 and findings[0]["cwe"] == "CWE-639" and findings[0]["severity"] == "high"
    assert findings[0]["evidence"]["listing_withholds_value"] is True


@pytest.mark.parametrize(("options", "reason"), [
    ({"owner_check": True}, "other_principal_denied_or_value_absent"),
    ({"listing_shows_secret": True}, "listing_shows_planted_value"),
    ({"anonymous_reads": True}, "anonymous_reads_planted_value"),
])
def test_an_owner_check_a_public_field_or_an_open_object_is_not_this_proof(options, reason):
    observation = _prove(**options)["observation"]
    assert observation["proof_state"] == "inconclusive" and observation["reason"] == reason
    from scan.finalizer import canonical_authz_findings
    assert canonical_authz_findings([observation], receipt={"receipt_id": "r"}) == []
