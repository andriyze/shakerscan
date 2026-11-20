"""A signed-in Scan's or a Hunt's credential secret never appears in its masked archive export.

A Scan signed in with a credential profile, and the target echoed the password back: sqlmap reading
the accounts table returned it in 38 wire-log rows, and 12 other rows carried it too. The payload
redaction keys on secret-named fields, so an echo in a response body survived, and the export
(``GET /scans/{id}/http-transactions``) showed it in clear. A Hunt's export already withheld its
saved-login secrets in the whole document; a Scan's now withholds every secret of the credential
profile versions it was admitted with, in every encoding the scrubber knows. Synthetic values only.
"""
from __future__ import annotations

import asyncio
import base64
import json
import urllib.parse
import uuid
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from runtime import http_archive_router as router  # noqa: E402
from runtime import scan_archive_secrets as secrets  # noqa: E402
from runtime.archive_body_masking import withhold_in_document  # noqa: E402
from runtime.credentials import build_credential_secret  # noqa: E402

PASSWORD = "Hub-Pass_7741!x"
USER = "hub.operator"
PROFILE = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
OTHER = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
SCAN = uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")


def envelope(kind: str, **fields) -> str:
    return "plain:" + build_credential_secret(kind, **fields)


class Conn:
    """Scans' options and credential profile versions, as asyncpg would return them."""

    def __init__(self, refs, versions):
        self.refs = refs
        self.versions = versions  # {(profile, version): (auth_kind, ciphertext)}
        self.queries = []

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        if "FROM scans" in query:
            return [{"options": json.dumps({"credential_profile_refs": self.refs})}]
        profile, every, exact = args
        return [{"auth_kind": kind, "encrypted_secret": cipher}
                for (pid, version), (kind, cipher) in self.versions.items()
                if pid == profile and (every or version in exact)]


@pytest.fixture(autouse=True)
def plain_secrets(monkeypatch):
    def decrypt(value):
        if not str(value).startswith("plain:"):
            raise ValueError("not decryptable")
        return str(value)[len("plain:"):]
    monkeypatch.setattr(secrets, "decrypt_secret", decrypt)


def test_a_scans_profile_secrets_are_read_for_its_export_not_its_user_name():
    conn = Conn(
        [{"profile_id": str(PROFILE), "profile_version": 2}, {"profile_id": str(OTHER)}, {"profile_id": "junk"}],
        {
            (PROFILE, 1): ("form_login", envelope("form_login", secret="old-version-pass", username=USER,
                                                  endpoint_url="http://10.0.0.5/hub/login")),
            (PROFILE, 2): ("form_login", envelope("form_login", secret=PASSWORD, username=USER,
                                                  endpoint_url="http://10.0.0.5/hub/login")),
            (OTHER, 1): ("bearer_token", envelope("bearer_token", secret="tok_abcdef123456")),
            (OTHER, 2): ("bearer_token", "enc:fernet:unreadable"),
        },
    )
    found = asyncio.run(secrets.scan_credential_secrets(conn, [SCAN, "not-a-uuid"]))
    # The exact version a ref names; every readable version of a ref without one; never the user.
    assert found == [PASSWORD, "tok_abcdef123456"]
    assert USER not in found and "old-version-pass" not in found


def test_short_secrets_and_scans_without_profiles_add_nothing():
    conn = Conn([{"profile_id": str(PROFILE), "profile_version": 1}],
                {(PROFILE, 1): ("cookie", envelope("cookie", secret="a=1"))})
    assert asyncio.run(secrets.scan_credential_secrets(conn, [SCAN])) == []
    assert asyncio.run(secrets.scan_credential_secrets(Conn([], {}), [])) == []


def test_custom_header_values_are_secrets():
    material = json.loads(build_credential_secret("custom_headers", custom_headers={"X-Api-Key": "key-998877665544"}))
    assert secrets.secret_values(material) == ["key-998877665544"]


HOSTILE_ECHOES = [
    f"id,username,password\n1,{USER},{PASSWORD}\n",                       # sqlmap's table dump
    f"<td>{PASSWORD}</td>",                                               # an account page
    json.dumps({"note": f"password was {PASSWORD}"}),                     # JSON-escaped inside a body
    "password=" + urllib.parse.quote(PASSWORD, safe=""),                  # a reflected form, percent-encoded
    "password=" + urllib.parse.quote_plus(PASSWORD),                      # plus-encoded
    "Authorization: Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode(),
]


@pytest.mark.parametrize("echo", HOSTILE_ECHOES)
def test_every_echo_of_the_secret_is_withheld_from_the_rendered_document(echo):
    document = json.dumps({"transactions": [{"adapter": "tool_wire_log",
                                             "response": {"body": echo}}]}).encode()
    masked = withhold_in_document(document, [PASSWORD])
    text = masked.decode()
    json.loads(text)  # still a valid document
    for form in (PASSWORD, urllib.parse.quote(PASSWORD, safe=""), urllib.parse.quote_plus(PASSWORD),
                 json.dumps(PASSWORD)[1:-1]):
        assert form not in text
    assert base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode() not in text


def test_a_scan_export_withholds_its_profile_secret_and_a_raw_export_is_untouched(monkeypatch):
    body = f"1,{USER},{PASSWORD}"

    class Pool:
        def acquire(self):
            return self

        async def __aenter__(self):
            return object()

        async def __aexit__(self, *exc):
            return False

    class Encoded:
        document = {}

        def render(self):
            return json.dumps({"transactions": [{"response": {"body": body}}]}).encode()

    async def none(*_a, **_k):
        return None

    async def zero(*_a, **_k):
        return 0

    async def rows(*_a, **_k):
        return []

    async def export(*_a, **_k):
        return Encoded()

    seen = []

    async def scan_secrets(_conn, scan_ids):
        seen.append(list(scan_ids))
        return [PASSWORD]

    monkeypatch.setattr(router, "_pool", lambda: Pool())
    monkeypatch.setattr(router, "_scan_archive_ids", none)
    monkeypatch.setattr(router, "count_transactions", zero)
    monkeypatch.setattr(router, "read_archive_stats", none)
    monkeypatch.setattr(router, "read_transactions", rows)
    monkeypatch.setattr(router, "build_export", export)
    monkeypatch.setattr(secrets, "scan_credential_secrets", scan_secrets)

    def run(redaction):
        content, _total = asyncio.run(router._build_export_bytes(
            scan_id=str(SCAN), hunt_run_id=None, export_format="transactions", redaction=redaction,
            method=None, status_code=None, search=None, limit=10, offset=0, raw_har=False))
        return content.decode()

    assert PASSWORD not in run("redacted")
    assert seen == [[str(SCAN)]]
    assert PASSWORD in run("raw")  # the raw view is the separate, deployment-gated choice


HUNT = uuid.UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")


class HuntConn(Conn):
    """A Hunt's context refs, its recorded credential uses and its sign-in sessions."""

    def __init__(self, context, uses, versions):
        super().__init__([], versions)
        self.context = context
        self.uses = uses

    async def fetchval(self, query, *args):
        assert "context_pack" in query and args == (HUNT,)
        return json.dumps(self.context)

    async def fetch(self, query, *args):
        if "hunt_credential_uses" in query:
            return [{"profile_id": p, "profile_version": v} for p, v in self.uses]
        return await super().fetch(query, *args)


def test_a_hunts_admitted_and_used_profile_secrets_are_read_for_its_export():
    conn = HuntConn(
        context=[{"profile_id": str(PROFILE), "profile_version": 2, "source": "credential_profiles"}],
        uses=[(OTHER, 1)],
        versions={
            (PROFILE, 1): ("form_login", envelope("form_login", secret="old-version-pass", username=USER,
                                                  endpoint_url="http://10.0.0.5/hub/login")),
            (PROFILE, 2): ("form_login", envelope("form_login", secret=PASSWORD, username=USER,
                                                  endpoint_url="http://10.0.0.5/hub/login")),
            (OTHER, 1): ("api_key_header", envelope("api_key_header", secret="hdr-secret-4455", header_name="X-Key")),
        },
    )
    found = asyncio.run(secrets.hunt_credential_secrets(conn, str(HUNT)))
    assert found == [PASSWORD, "hdr-secret-4455"]
    assert asyncio.run(secrets.hunt_credential_secrets(conn, "not-a-uuid")) == []


def test_a_hunt_export_withholds_its_profile_and_saved_login_secrets(monkeypatch):
    from runtime import hunt_http_exchange

    body = f"1,{USER},{PASSWORD} saved=login-secret-0099"

    class Pool:
        def acquire(self):
            return self

        async def __aenter__(self):
            return object()

        async def __aexit__(self, *exc):
            return False

    class Encoded:
        document = {}

        def render(self):
            return json.dumps({"transactions": [{"response": {"body": body}}]}).encode()

    async def none(*_a, **_k):
        return None

    async def zero(*_a, **_k):
        return 0

    async def rows(*_a, **_k):
        return []

    async def export(*_a, **_k):
        return Encoded()

    async def saved(_conn, _hunt):
        return ["login-secret-0099"]

    async def profiles(_conn, hunt):
        assert hunt == str(HUNT)
        return [PASSWORD]

    monkeypatch.setattr(router, "_pool", lambda: Pool())
    monkeypatch.setattr(router, "count_transactions", zero)
    monkeypatch.setattr(router, "read_archive_stats", none)
    monkeypatch.setattr(router, "read_transactions", rows)
    monkeypatch.setattr(router, "build_export", export)
    monkeypatch.setattr(hunt_http_exchange, "hunt_saved_login_secrets", saved)
    monkeypatch.setattr(secrets, "hunt_credential_secrets", profiles)
    content, _total = asyncio.run(router._build_export_bytes(
        scan_id=None, hunt_run_id=str(HUNT), export_format="transactions", redaction="redacted",
        method=None, status_code=None, search=None, limit=10, offset=0, raw_har=False))
    text = content.decode()
    assert PASSWORD not in text and "login-secret-0099" not in text
